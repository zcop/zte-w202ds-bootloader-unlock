#!/bin/bash
# magic-b500-recover.sh — armed recovery for the corrected magic64 carrier test.
#
# Waits for BROM (key combo), then:
#   1. reads the failed boot's uboot_log into magic-b500-out/
#   2. restores uboot_b-unlock.bin and reads it back (expects d2210425...)
#   3. erases splloader, resets -> automatic BROM fallback
#   4. runs b2p14b-cmd.txt (host spl-unlock) -> patched SPL -> patched LK
#   5. waits for Android and prints the boot props
#
# The fix-node.sh watcher must already be live. This script does not start it.
# It never overwrites the older preverify/r37 evidence directories.
set -u
cd "$(dirname "$0")" || exit 1

SPD=../../../tools/spreadtrum_flash/spd_dump
# Required: the tablet's adb serial. Example: SERIAL=0123456789ABCDEF ./magic-b500-recover.sh
: "${SERIAL:?set SERIAL to the tablet adb serial}"
RESTORE_SHA=d221042556e13fe52d6093036c14ab8bac4fe9de40ba89cc4da516de9efac37e
LOG=logs/magic-b500-recover.log
OUT=magic-b500-out

mkdir -p "$OUT" logs
: > "$LOG"
say() { echo "[b500-rec] $*" | tee -a "$LOG"; }

say "=== corrected-carrier recovery $(date -Is) ==="
pgrep -f '[f]ix-node\.sh' >/dev/null 2>&1 \
    || { say "NO fix-node.sh WATCHER; start it first"; exit 1; }
say "watcher live"

node_of() {
    local line bus dev
    line=$(lsusb -d 1782:4d00 2>/dev/null | head -1)
    [ -z "$line" ] && return 1
    bus=$(echo "$line" | sed -n 's/^Bus \([0-9]*\) Device \([0-9]*\):.*/\1/p')
    dev=$(echo "$line" | sed -n 's/^Bus \([0-9]*\) Device \([0-9]*\):.*/\2/p')
    [ -n "$bus" ] && [ -n "$dev" ] || return 1
    printf '/dev/bus/usb/%s/%s\n' "$bus" "$dev"
}
wait_node() {  # label timeout
    local label=$1 deadline=$((SECONDS + $2)) n
    while [ $SECONDS -lt $deadline ]; do
        if n=$(node_of) && [ -w "$n" ]; then say "$label: node $n"; return 0; fi
        sleep 0.3
    done
    say "$label: TIMEOUT"; return 1
}
wait_absent() {  # label timeout
    local label=$1 deadline=$((SECONDS + $2)) gone=0
    while [ $SECONDS -lt $deadline ]; do
        if node_of >/dev/null; then gone=0; else gone=$((gone + 1)); fi
        [ $gone -ge 10 ] && { say "$label: node absent"; return 0; }
        sleep 0.3
    done
    say "$label: node never left"; return 1
}
load_cmd() {
    local line
    line=$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$1" | tr '\n' ' ')
    read -r -a TOKENS <<< "$line"
    [ ${#TOKENS[@]} -ge 2 ]
}

say "waiting for BROM: hold POWER+VOL_DOWN 7-10 s on the tablet"
wait_node "BROM (recovery)" 900 || { say "no BROM; nothing written"; exit 2; }

# ---- recovery session -----------------------------------------------------
load_cmd magic-b500-recover-cmd.txt || { say "bad recover cmd"; exit 1; }
say "spd_dump: ${TOKENS[*]}"
"$SPD" --wait 300 "${TOKENS[@]}" </dev/null 2>&1 | tee -a "$LOG"
say "recovery spd_dump exit=${PIPESTATUS[0]}"

rb=$OUT/uboot_b-restored-readback.bin
if [ ! -s "$rb" ]; then
    say "NO RESTORE READBACK; stop"
    exit 3
fi
sha=$(sha256sum "$rb" | awk '{print $1}')
say "restored uboot_b readback ${sha:0:16}... ($(stat -c %s "$rb") bytes)"
[ "$sha" = "$RESTORE_SHA" ] || { say "RESTORE MISMATCH; do not boot"; exit 3; }
say "restore readback PASS"

# ---- automatic fallback (splloader erased) -------------------------------
# The recovery reset can re-enumerate before this point. If the BROM node is
# already present and writable it IS the fallback; do not wait for it to leave.
if n=$(node_of) && [ -w "$n" ]; then
    say "fallback BROM already present: $n (skipped absent gate)"
else
    wait_absent "post-recovery reset" 20 || { say "node stayed; check tablet"; exit 4; }
    wait_node "fallback BROM" 240 \
        || { say "no fallback BROM; hold POWER+VOL_DOWN and rerun"; exit 4; }
fi

# ---- host spl-unlock -> patched LK ---------------------------------------
load_cmd b2p14b-cmd.txt || { say "bad b2p14b cmd"; exit 1; }
say "spd_dump: ${TOKENS[*]}"
"$SPD" --wait 300 "${TOKENS[@]}" </dev/null 2>&1 | tee -a "$LOG"
say "spl-unlock exit=${PIPESTATUS[0]} (non-zero expected when the LK boots)"

# ---- wait for Android -----------------------------------------------------
deadline=$((SECONDS + 180))
while [ $SECONDS -lt $deadline ]; do
    if adb devices 2>/dev/null | grep -q "^$SERIAL[[:space:]]*device$"; then
        say "ANDROID UP: current tethered state restored"
        for p in ro.boot.flash.locked ro.boot.verifiedbootstate ro.boot.veritymode \
                 sys.boot_completed ro.build.fingerprint; do
            printf '  %s = %s\n' "$p" \
                "$(adb -s "$SERIAL" shell getprop "$p" 2>/dev/null | tr -d '\r')" \
                | tee -a "$LOG"
        done
        say "post-failure uboot_log saved: $OUT/uboot_log-post.bin"
        say "=== recovery PASS $(date -Is) ==="
        exit 0
    fi
    sleep 2
done
say "no adb after 180 s; re-run b2p14b-cmd.txt or hold POWER+VOL_DOWN and retry"
exit 5
