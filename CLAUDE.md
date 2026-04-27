# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project context

DieHard is an authorized Red Team exercise implant. Its goal is to be **findable but annoying to remove** so Blue Team burns time on it during a drill. It is **not** real-world malware tradecraft.

Scope boundaries — do not cross without explicit user approval:
- Lab/exercise targets only. **Never** target real systems or leave the lab box.
- The `/tmp/diehard.stop` sentinel kill switch is **required**, not optional. Always preserve it — it is the non-negotiable safety mechanism.
- `SIGKILL` is not blockable; do not pretend otherwise.
- **Anti-forensics / detection evasion targeting the implant's own fingerprint is in scope** (expanded 2026-04-27 — BT proved capable of trivially identifying cluster members via `/proc/<pid>/exe` despite the comm masquerade). Techniques like `prctl(PR_SET_MM_EXE_FILE)` to repoint the exe symlink, `memfd_create` + `execveat` for fileless re-exec, on-disk binary deletion/relocation, and similar are now permitted. The implant should still be *defeatable* — it must remain a finite challenge, not a permanent infestation.
- Still out of scope without further explicit approval: anti-recovery (attacking BT's tooling or host), persistence across reboot (autostart units, cron, systemd, rootkit hooks for survival), mass-targeting / network propagation / supply chain, syscall hooking against other processes.

Earlier expansions still in effect:
- Process-name masquerade (each generation samples a random `comm` from `/proc`, applied via `prctl(PR_SET_NAME)` and argv[0] rewrite).
- argv block extension via `prctl(PR_SET_MM_ARG_END)` for full-length cmdline display (needs CAP_SYS_RESOURCE).

## Build / run / stop

```sh
./run.sh                  # builds and execs (sudo if not root); idempotent
touch /tmp/diehard.stop   # graceful shutdown for all members
```

`run.sh` exists specifically because one of the evasion techniques (`tech_delete`) unlinks the on-disk binary, so subsequent runs need a rebuild. Manual build still works: `gcc -O2 -Wall -Wextra -o diehard diehard.c && ./diehard`.

Filesystem footprint:
- `/tmp/diehard.stop` — sentinel; presence triggers graceful exit. Kept as a file so `touch` is the kill-switch UX.
- `/tmp/diehard.txt` — the "work" the leader maintains (appends `DIE HARD WAS HERE` if missing). Visible by design.
- `/var/lib/.systemd-state-cache` — bind-mount cleanup list (one path per line) used by `run.sh` on the next launch. Path is deliberately innocuous-looking; doesn't contain "diehard". Defined as `BIND_CLEANUP_FILE` in `diehard.c`.

All cluster coordination (leader, heartbeats, peer slots) lives in an **anonymous `MAP_SHARED` mmap** allocated by `main` and inherited by every fork descendant. No file backing, no `/dev/shm` entry — only an unnamed entry in `/proc/<pid>/maps`.

## Architecture

Single source file (`diehard.c`). The design rests on a few interacting invariants — read these before changing anything load-bearing:

**Cluster of 32 peers, one leader, all coordinating via memfd-backed shared memory.** `main()` creates a memfd with an **empty name** (`memfd_create("", 0)`), `ftruncate`s it to `sizeof(struct shared_state)`, mmaps `MAP_SHARED` over it, and *then* forks 32 members. The empty name appears as `/memfd: (deleted)` in `/proc/<pid>/maps`, indistinguishable from anonymous memfds that systemd, snapd, dbus etc. create — there's no recognizable string for `grep` to anchor on. The fd is non-CLOEXEC and propagates across `execve` via `DIEHARD_SHM_FD`, which is why per-child `tech_memfd` / `tech_bind_mount` (both of which re-exec the member) don't lose the cluster's coordination state. (`CLUSTER_SIZE` is the knob — bumping it makes the kill-by-rotation race correspondingly worse for BT.)

**cwd detached at startup.** `main` calls `chdir("/")` before forking the cluster, so `/proc/<pid>/cwd` for every member resolves to `/` (typical for daemons) rather than to the launch directory. Inheritance carries it across fork; cwd is preserved across `execve`, so re-exec'd members keep it too. Defeats `ls -la /proc/*/cwd | grep diehard`.

**Per-slot rotation bands.** PID rotation refreshes a member's start time, so a uniform fast rotation across the whole cluster makes every live member match `ps aux | grep $(date +%H:%M)`. To break that fingerprint, slots are divided into four bands by index:

| Slot range | Rotation interval | Role |
|---|---|---|
| `[0, BAND_SIZE)` (0–7) | 200–800 ms | Fast — defeats per-pid kill loops |
| `[8, 16)` | 5–30 s | Medium-fast — survives within-minute attacks |
| `[16, 24)` | 60–300 s | Medium-slow — survives single-minute time-grep |
| `[24, 32)` | 5–30 min | Slow — survives sustained time-based attacks |
| `[32, 128)` (threat-only) | 200–800 ms (or 50–200 ms under threat) | Fast extras spawned only under attack |

`jittered_rotation_ms()` reads `g_slot_idx` and returns an interval in the appropriate band. Threat-mode boost (50–200 ms) applies *only to the fast band*; the slower bands keep their cadence so they keep their old start times even under attack — which is the whole point. The slow-band members are the cluster's persistence anchor: they survive attacks the fast band can't, and they hold the shm coordination state until fresh members can be spawned.

**Defensive mode (threat detection + cluster growth).** Members that exit gracefully call `release_slot()`, which sets `slots[i].pid = 0`. Members killed externally (SIGKILL) never run that code, leaving their slot with `(pid=X, hb=stale)` until the leader's `maintain_membership` sweep notices. That signature is a clean attack indicator with no startup false positives.

When ≥`THREAT_KILLED_THRESHOLD` (= 1, any abrupt death) slots show that pattern in one sweep, the leader sets `g_shm->threat_until_ms = now + THREAT_DURATION_MS` (= 30 s). Two effects flip simultaneously:

1. **Rotation accelerates**: every member's `jittered_rotation_ms` returns 50–200 ms instead of 200–800 ms. Each kill volley's PID snapshot decays in tens of ms.
2. **Cluster grows**: `target_size_now()` returns `CLUSTER_THREAT_SIZE` (= 128) instead of `CLUSTER_BASE_SIZE` (= 32). The leader's next sweep spawns up to 96 extra members. Each kill volley now races 4× more bodies and the leader's tighter `MEMBERSHIP_CHECK_MS` (= 30 ms) refills missing slots between volleys.

The slot array is sized to `CLUSTER_MAX_SIZE` (= 128) up front; threat mode just changes which range is "live". Any kill within 30 s of the last attack refreshes the timer, so sustained pressure keeps the cluster in threat mode indefinitely. Detection latency is bounded by `STALE_MS` (= 300 ms) plus `MEMBERSHIP_CHECK_MS` (= 30 ms) — about 330 ms from kill to threat declaration. The shm holds: `leader` (atomic pid), `leader_hb_ms`, and `slots[CLUSTER_SIZE] = {pid, hb_ms}`. Critical invariant: **`shm_init()` must run before the cluster fork** — children of fork inherit the mapping, but unrelated `./diehard` invocations get separate regions.

**Leader election = CAS on a shared word.** `try_become_leader()` tries `CAS(leader, 0, self)`. If that fails, it inspects `leader_hb_ms`: if the incumbent's heartbeat is older than `STALE_MS`, attempt `CAS(leader, incumbent, self)` to take over. The leader writes `leader_hb_ms = monotonic_ms()` every `HEARTBEAT_MS`. This replaces the old flock-via-OFD-inheritance trick — leadership is now an explicit shared-memory state, not file-locking magic.

**PID rotation = parent forks, child takes the same slot, parent exits.** `rotate_self()` records `old_pid`, forks, the child overwrites `slots[g_slot_idx].pid` with its new pid, and (if leader) attempts `CAS(leader, old_pid, new_pid)`. If that CAS loses (someone else took over during the brief gap), the rotated child becomes a follower — system self-heals. Rotation interval is `ROTATION_MIN_MS..ROTATION_MAX_MS`, jittered.

**Comm masquerade.** On every fresh process (initial spawn, rotation, replacement) the new process samples a `comm` from `/proc/*/comm` (skipping kernel threads via `is_userland_pid` and anything containing "diehard") and applies it via `prctl(PR_SET_NAME)` and `argv[0]` rewrite. With CAP_SYS_RESOURCE (`sudo`), `capture_argv` also extends `arg_end` via `prctl(PR_SET_MM_ARG_END)` so `/proc/<pid>/cmdline` shows the full masqueraded name in `ps aux` instead of being truncated to the original argv length. Defeats `pkill diehard` / `pgrep -f diehard`.

**Exe-link evasion (per-child).** Comm masquerade alone leaves `/proc/<pid>/exe` resolving to the real binary path — trivial for BT to grep. `apply_random_evasion()` runs **independently in each cluster member** post-fork (after `claim_slot`), so the 16 members end up with 16 different exe-link patterns instead of all sharing one. Picker selects from techniques feasible at current privilege:

- `tech_repoint` — `prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd)` repoints `mm->exe_file` to a random binary from `legit_binaries[]`. **Root only.** *Kernel limitation:* on Linux ≤ 5.17 the kernel returns `EBUSY` whenever any VMA still maps the old `exe_file` — which is always true for a running process (its `.text` section). The check was relaxed in ~5.18; on older kernels this technique always falls through to the next pick. Per-generation rotation of the impersonated binary is not feasible on those kernels for the same reason.
- `tech_memfd` — copy `/proc/self/exe` into a `memfd_create`'d anonymous fd, `execveat` from it. **Any user.** Re-execs the process; on success, never returns. The new process re-enters `main`, sees `DIEHARD_REEXECED`, and goes through `run_reexec_member()` to resume the member loop with the inherited slot index and shm fd. `/proc/<pid>/exe` becomes `/memfd:<rand> (deleted)` — different `<rand>` per member.
- `tech_bind_mount` — copy our binary to a randomly-chosen throwaway path, re-exec from there, then `mount(MS_BIND)` a legit binary over the throwaway. **Root only.** The throwaway path is randomized across 8 directories (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/lock`, `/var/cache`, `/var/lib`, `/run/user`, `/run`) × 6 prefixes (`.`, `.X11-unix-`, `.cache-`, `.systemd-`, `lock-`, `session-`) so no single `grep` over `/proc/*/maps` catches all bind-mount members. The first writable directory in random order is picked. Cleanup paths accumulate in `/tmp/diehard.bind` for `run.sh` to undo on the next launch.
- `tech_delete` — `unlink` the on-disk binary. **Any user (with write perm).** Conspicuous: exe link gains `(deleted)` suffix. Requires `run.sh` to rebuild before the next run.

The picker shuffles the feasible pool and tries each technique in order until one succeeds. Inheritance does the rest — fork descendants get the same exe link without needing to re-apply.

**Membership = atomic heartbeat in shm slots.** Each peer writes `monotonic_ms()` to `slots[g_slot_idx].hb_ms` every `HEARTBEAT_MS`. Leader sweeps every `MEMBERSHIP_CHECK_MS`, sets `slots[i].pid = 0` for any slot whose heartbeat is older than `STALE_MS`, and forks replacements to refill empty slots. Slot claim is `CAS(slots[i].pid, 0, self)` — first empty slot wins. `g_slot_idx` is cached after claim and inherited across rotation, so a rotating child stays in its slot without re-claiming.

**Single-threaded by design.** The main loop is `poll`-style with millisecond timers. Do **not** introduce threads — `fork()` in a multithreaded process leaves libc lock state undefined in the child and deadlocks. This is fundamental to the architecture, not a temporary limitation.

**Per-generation `setsid()`.** Every fresh process (initial spawn, rotation, replacement) calls `setsid()` so each generation has its own session/pgid. This means session-wide signals (e.g. terminal HUP) don't take down the cluster.

**Soft signals ignored.** `SIGTERM/HUP/INT/USR1/USR2/PIPE` are SIG_IGN. `SIGCHLD` is SIG_IGN so zombies auto-reap on Linux. `SIGKILL`/`SIGSTOP` are kernel-enforced and not handled (by design — see scope).

## When changing timer constants

The timing constants near the top (`TICK_MS`, `HEARTBEAT_MS`, `STALE_MS`, `ROTATION_MIN/MAX_MS`, etc.) are interrelated. `STALE_MS` must comfortably exceed `HEARTBEAT_MS` or live peers get reaped. `ROTATION_*` should be longer than `MEMBERSHIP_CHECK_MS` or the leader spends most of its time forking instead of working.
