# DieHard

A self-defending process cluster for authorized Red Team exercises on Linux. The implant is designed to be findable in principle but frustrating to remove in practice, so Blue Team has a worthy adversary during cyber drills without the engagement turning into a real malware investigation.

## Status

- **Authorized lab/exercise use only.** Not for real systems.
- Includes a non-negotiable kill switch (`touch /tmp/diehard.stop`) so the drill always ends cleanly.
- Single source file (`diehard.c`), no dependencies beyond libc.

## Quick start

```sh
./run.sh                  # build (root or sudo) and launch
touch /tmp/diehard.stop   # graceful shutdown for all members
```

Manual build:

```sh
gcc -O2 -Wall -Wextra -o diehard diehard.c
sudo ./diehard
```

## What it does

A cluster of 32 cooperating processes (up to 128 under attack) shares state through an unnamed memfd-backed mmap region. Each member rotates its PID on a jittered timer, picks a random `comm` from `/proc` to masquerade as, and uses one of four techniques to disguise its `/proc/<pid>/exe` link. When the cluster detects abrupt member deaths (the signature of an external `kill -9`), it shifts into threat mode: rotation accelerates 4× and the live cluster grows to 128 members.

## Defenses, in layered order

| Layer | Defeats |
|---|---|
| PID rotation (200–800 ms baseline, 50–200 ms under attack) | `kill <pid>` |
| Comm masquerade (sampled from `/proc/*/comm` per fork) | `pkill diehard`, `pgrep -f diehard` |
| Per-child exe-link evasion (memfd / bind-mount / delete / repoint) | `readlink /proc/*/exe \| grep diehard` |
| Empty-named memfd shm (`memfd_create("", 0)`) | `grep diehard-shm /proc/*/maps` |
| `chdir("/")` at startup | `ls /proc/*/cwd \| grep diehard` |
| Per-slot rotation bands (200 ms → 30 min) | `ps aux \| grep $(date +%H:%M)` |
| Threat-mode cluster growth (32 → 128) + faster rotation | sustained kill-loop attacks |
| Process group per member (`setpgid`) without session leadership | `ps aux \| grep Ss \| xargs kill` |
| Randomized bind-mount throwaway paths (8 dirs × 6 prefixes) | path-pattern grep |
| Innocuous-named bind cleanup file (`/var/lib/.systemd-state-cache`) | `find / -name 'diehard*'` |

The kill switch (`/tmp/diehard.stop`) and visible work file (`/tmp/diehard.txt`) remain observable on purpose — they are the project's training-wheels and proof-of-life respectively.

## Scope

In scope (current):
- Detection evasion and anti-forensics targeting the implant's own fingerprint.
- Process-name masquerade and exe-link disguise.
- Memfd-backed fileless re-exec.

Out of scope (do not extend without explicit approval):
- Persistence across reboot (autostart, cron, systemd units, rootkit hooks).
- Anti-recovery (attacking Blue Team tooling, host hardening, or detection infrastructure).
- Mass-targeting, network propagation, supply-chain compromise.
- Syscall hooking against other processes.

## Files at runtime

- `/tmp/diehard.stop` — sentinel kill switch.
- `/tmp/diehard.txt` — visible "work" output (the leader appends `DIE HARD WAS HERE` if missing).
- `/var/lib/.systemd-state-cache` — bind-mount cleanup list, consumed by `run.sh` on the next launch.

The on-disk binary may also be unlinked at runtime if the `tech_delete` evasion technique was selected — `run.sh` rebuilds it before each launch.

## See also

- `CLAUDE.md` — architectural notes and design invariants for code reviewers and future work.
- `find-diehard.sh` — Blue Team's reference cluster-finder + killer (kept in-tree as a regression target; current defenses make it largely ineffective).
