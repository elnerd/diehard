#!/bin/bash
#
# find-diehard.sh — locate (and optionally kill) DieHard cluster members.
#
# Fingerprint: every cluster member has the "diehard-shm" memfd mapped
# MAP_SHARED in its address space, and the name shows up plainly in
# /proc/<pid>/maps. This bypasses the comm masquerade, the per-child exe
# evasion, and PID rotation — it's a structural property of the cluster.
#
# Usage:
#   find-diehard.sh        # list cluster member PIDs
#   find-diehard.sh -k     # kill them (loops until none seen for ~0.5s)
#
set -uo pipefail

KILL=0
for arg in "$@"; do
    case "$arg" in
        -k|--kill) KILL=1 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    exec sudo "$0" "$@"
fi

scan_pids() {
    # Single grep across all maps files — much faster than a per-pid loop,
    # which races against rapid PID rotation when the cluster is in
    # threat mode. Output: one pid per line.
    grep -lar diehard-shm /proc/[0-9]*/maps 2>/dev/null \
        | sed -E 's|^/proc/([0-9]+)/maps$|\1|'
}

if [[ $KILL -eq 0 ]]; then
    mapfile -t pids < <(scan_pids)
    if [[ ${#pids[@]} -eq 0 ]]; then
        echo "no diehard cluster members found"
        exit 0
    fi
    printf '%-8s  %-16s  %s\n' PID COMM EXE
    for pid in "${pids[@]}"; do
        comm=$(cat "/proc/$pid/comm" 2>/dev/null || echo '?')
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null || echo '?')
        printf '%-8s  %-16s  %s\n' "$pid" "$comm" "$exe"
    done
    echo
    echo "found ${#pids[@]} member(s)"
else
    # Race the cluster's respawn loop. Keep killing until five consecutive
    # passes find no members, which means the leader itself died and
    # nothing is left to fork replacements.
    empty_passes=0
    total=0
    while (( empty_passes < 5 )); do
        mapfile -t pids < <(scan_pids)
        if [[ ${#pids[@]} -eq 0 ]]; then
            (( empty_passes++ ))
            sleep 0.1
            continue
        fi
        empty_passes=0
        kill -KILL "${pids[@]}" 2>/dev/null || true
        (( total += ${#pids[@]} ))
        sleep 0.05
    done
    echo "cluster gone — issued $total SIGKILL(s) across the kill loop"
fi
