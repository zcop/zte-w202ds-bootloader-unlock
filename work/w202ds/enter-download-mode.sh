#!/usr/bin/env bash
# Canonical download-mode entry for the W202DS (ZTE W202DS / CN_P720P01).
#
# Rule (learned the hard way, re-confirmed 2026-10-19):
#   ZTE spelling is `adb reboot autodloader` — WITH the "d".
#   Plain `adb reboot autoloader` is a different string and only reboots
#   Android (the device never enumerates 1782:4d00; wastes a full boot).
#
# Usage:  ./enter-download-mode.sh [wait_seconds]      (default 120)
# Exit:   0 = 1782:4d00 node is up (proceed with spd_dump / phase1)
#         1 = adb reboot failed (device not in adb)
#         2 = no node within the wait; if Android is back, the applied
#             boot reason is printed for diagnosis.
#
# Requires: adb (authorized) + lsusb.  Run the root watcher
# (`sudo ./fix-node.sh 600`) in this directory first so the new node
# gets group access for the reader.
set -u
SER="${ADB_SERIAL:-${SERIAL:-}}"
if [ -z "$SER" ]; then
    echo "[entry] ERROR: set ADB_SERIAL=<serial> (or SERIAL=<serial>)" >&2
    exit 1
fi
WAIT="${1:-120}"

a() { command adb -s "$SER" "$@"; }

echo "[entry] serial=$SER  wait=${WAIT}s"
a reboot autodloader || { echo "[entry] ERROR: adb reboot failed (no adb device?)"; exit 1; }
echo "[entry] 'adb reboot autodloader' issued $(date -Is) (ZTE spelling, with the d)"

i=0
while [ "$i" -lt "$((WAIT / 2))" ]; do
    if lsusb -d 1782:4d00 | grep -q .; then
        echo "[entry] download node up after $((i * 2))s:"
        lsusb -d 1782:4d00
        exit 0
    fi
    i=$((i + 1))
    sleep 2
done

echo "[entry] !! no 1782:4d00 node after ${WAIT}s"
if a get-state >/dev/null 2>&1; then
    echo "[entry] !! Android is back — the entry did not reach download mode."
    echo "[entry] !! bootreason now: $(a shell getprop ro.boot.bootreason 2>/dev/null | tr -d '\r')"
    echo "[entry] !! if it shows 'reboot,autoloader' the plain spelling was used by mistake;"
    echo "[entry] !! this helper always sends 'autodloader' (with the d)."
fi
exit 2
