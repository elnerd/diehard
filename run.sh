#!/bin/bash
#
# Build and run diehard. Required after a run with the binary-delete
# evasion technique (which removes the on-disk binary). Idempotent:
# safe to run from any state.
#
# Most evasion techniques (PR_SET_MM_EXE_FILE, bind-mount over
# /proc/self/exe) need root. memfd_create + execveat and the delete
# technique work as any user.
#
set -euo pipefail
cd "$(dirname "$0")"

# Best-effort cleanup of the previous run's bind-mount technique, if any.
# Path matches BIND_CLEANUP_FILE in diehard.c — looks like a systemd
# state-cache file rather than anything tied to "diehard".
BIND_CLEANUP=/var/lib/.systemd-state-cache
if sudo test -f "$BIND_CLEANUP"; then
    sudo cat "$BIND_CLEANUP" | while read -r p; do
        [[ -z "$p" ]] && continue
        sudo umount "$p" 2>/dev/null || true
        sudo rm -f "$p" 2>/dev/null || true
    done
    sudo rm -f "$BIND_CLEANUP"
fi

gcc -O2 -Wall -Wextra -o diehard diehard.c

if [[ $EUID -eq 0 ]]; then
    exec ./diehard "$@"
else
    exec sudo ./diehard "$@"
fi
