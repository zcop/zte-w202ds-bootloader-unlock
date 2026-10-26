#!/bin/bash
# magic-b500-run.sh — corrected post-verification magic64 carrier test.
#
# Difference from r37: the runtime patch target is 0xB50629B4, derived from the
# stock SPL's own load call (VA 0x6500AFAC, x2=0xB5000000), not the generic
# 0x9F000000 example used by the magic64 documentation.  The on-flash carrier
# is byte-identical to r37 except for one byte in the patch-list address.
#
# Writes the corrected carrier + stock SPL, reads both back, resets, and does
# NOT run spl-unlock.  Success means the stock SPL verified the unchanged stock
# LK payload, the magic64 shellcode applied the B2^12 patch in RAM, and Android
# booted.  A second boot proves persistence.
#
# Preconditions:
#   * `sudo ./fix-node.sh 3600` running in another terminal (watcher live)
#   * explicit user go (B500_GO=GO or type GO at the prompt)
#   * tablet on Android with adb, or already in BROM
#
# On failure: hold POWER+VOL_DOWN 7-10 s, then run ./magic-b500-recover.sh.
# That restores uboot_b-unlock.bin, erases splloader, and runs the normal host
# spl-unlock flow to return to the current tethered Android state.
set -u
cd "$(dirname "$0")" || exit 1

SPD=../../../tools/spreadtrum_flash/spd_dump
# Required: the tablet's adb serial. Example: SERIAL=0123456789ABCDEF ./magic-b500-run.sh
: "${SERIAL:?set SERIAL to the tablet adb serial}"
ART=../persistent-magic-b500/uboot_b-magic64-b500.bin
SPL=../../../tools/spreadtrum_flash/backups/2026-10-17-full/splloader.bin
ART_SHA=c37d0a4c63ff5d1f9ce1782838435c2c0437224ec4731deb3e5a3242909174b0
SPL_SHA=77a4fa3d739dfd6b333ed3c81301d59397445c246cd6def8ec9d4151c217a47d
ART_SIZE=1130520
LOG=logs/magic-b500-run.log
OUT=magic-b500-out

mkdir -p "$OUT" logs
: > "$LOG"
say() { echo "[b500] $*" | tee -a "$LOG"; }

say "=== corrected magic64 carrier test (target 0xB50629B4) $(date -Is) ==="

# ---- guard: artifact hashes and sizes -------------------------------------
[ "$(sha256sum "$ART" 2>/dev/null | awk '{print $1}')" = "$ART_SHA" ] \
    || { say "GUARD FAIL: corrected carrier hash mismatch"; exit 1; }
[ "$(stat -c %s "$ART" 2>/dev/null)" = "$ART_SIZE" ] \
    || { say "GUARD FAIL: carrier size != 0x114018"; exit 1; }
[ "$(sha256sum "$SPL" 2>/dev/null | awk '{print $1}')" = "$SPL_SHA" ] \
    || { say "GUARD FAIL: stock SPL hash mismatch"; exit 1; }
[ "$(stat -c %s "$SPL" 2>/dev/null)" = "262144" ] \
    || { say "GUARD FAIL: stock SPL size != 0x40000"; exit 1; }
[ -x "$SPD" ] || { say "GUARD FAIL: spd_dump missing"; exit 1; }
[ -f fdl1-dl.bin ] && [ -f fdl2-dl.bin ] \
    || { say "GUARD FAIL: FDL files missing"; exit 1; }
[ -f magic-b500-cmd.txt ] && [ -f magic-b500-postread-cmd.txt ] \
    || { say "GUARD FAIL: command files missing"; exit 1; }
[ -x ./magic-b500-recover.sh ] \
    || { say "GUARD FAIL: armed recovery magic-b500-recover.sh missing"; exit 1; }
say "guard: carrier 0x114018 sha ${ART_SHA:0:16}...; stock SPL 0x40000 sha ${SPL_SHA:0:16}..."

# ---- guard: watcher must already be live ----------------------------------
if ! pgrep -f '[f]ix-node\.sh' >/dev/null 2>&1; then
    say "GUARD FAIL: no fix-node.sh watcher."
    say "  run in another terminal:  cd $(pwd) && sudo ./fix-node.sh 3600"
    exit 2
fi
say "guard: fix-node.sh watcher is live"

# ---- guard: battery via adb, if Android is still up ------------------------
if adb devices 2>/dev/null | grep -q "^$SERIAL[[:space:]]*device$"; then
    level=$(adb -s "$SERIAL" shell dumpsys battery 2>/dev/null | tr -d '\r' \
            | awk '/level:/{print $2; exit}')
    say "guard: battery level ${level:-unknown}%"
    case "${level:-}" in
        ''|*[!0-9]*) say "GUARD FAIL: battery level not readable"; exit 3 ;;
    esac
    [ "$level" -ge 50 ] || { say "GUARD FAIL: battery <50%"; exit 3; }
else
    say "guard: adb tablet not present; assuming BROM/key-combo entry"
fi

# ---- explicit user go ------------------------------------------------------
if [ "${B500_GO:-}" != "GO" ]; then
    printf 'Type GO to confirm the corrected bootloader write: '
    read -r go_answer || go_answer=""
    [ "$go_answer" = "GO" ] || { say "no GO: abort, nothing written"; exit 2; }
fi
say "explicit GO received"

# ---- enter BROM ------------------------------------------------------------
if adb devices 2>/dev/null | grep -q "^$SERIAL[[:space:]]*device$"; then
    say "rebooting tablet to autoloader (BROM)"
    adb -s "$SERIAL" reboot autoloader >/dev/null 2>&1 || true
fi

node_of() {
    local line bus dev
    line=$(lsusb -d 1782:4d00 2>/dev/null | head -1)
    [ -z "$line" ] && return 1
    bus=$(echo "$line" | sed -n 's/^Bus \([0-9]*\) Device \([0-9]*\):.*/\1/p')
    dev=$(echo "$line" | sed -n 's/^Bus \([0-9]*\) Device \([0-9]*\):.*/\2/p')
    [ -n "$bus" ] && [ -n "$dev" ] || return 1
    printf '/dev/bus/usb/%s/%s\n' "$bus" "$dev"
}
wait_node() {
    local label=$1 deadline=$((SECONDS + $2)) n
    while [ $SECONDS -lt $deadline ]; do
        if n=$(node_of) && [ -w "$n" ]; then
            say "$label: node $n"
            return 0
        fi
        sleep 0.3
    done
    say "$label: TIMEOUT"
    return 1
}

if ! wait_node "BROM (automatic)" 150; then
    say "no automatic BROM: hold POWER+VOL_DOWN 7-10 s on the tablet"
    wait_node "BROM (manual)" 300 || { say "no BROM; abort (no writes)"; exit 4; }
fi

load_cmd() {
    local line
    line=$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$1" | tr '\n' ' ')
    read -r -a TOKENS <<< "$line"
    [ ${#TOKENS[@]} -ge 2 ]
}

# ---- write corrected carrier + stock SPL, read back, reset ----------------
load_cmd magic-b500-cmd.txt || { say "bad magic-b500-cmd.txt"; exit 1; }
say "spd_dump: ${TOKENS[*]}"
"$SPD" --wait 300 "${TOKENS[@]}" </dev/null 2>&1 | tee -a "$LOG"
say "spd_dump exit=${PIPESTATUS[0]}"

# ---- readback gate --------------------------------------------------------
ub=$OUT/uboot_b-readback.bin
sp=$OUT/splloader-readback.bin
if [ ! -s "$ub" ] || [ ! -s "$sp" ]; then
    say "READBACK MISSING: $ub / $sp"
    say "recover: hold POWER+VOL_DOWN 7-10 s, run ./magic-b500-recover.sh"
    exit 5
fi
ub_sha=$(sha256sum "$ub" | awk '{print $1}')
sp_sha=$(sha256sum "$sp" | awk '{print $1}')
say "readback uboot_b: $(stat -c %s "$ub") bytes sha ${ub_sha:0:16}..."
say "readback splloader: $(stat -c %s "$sp") bytes sha ${sp_sha:0:16}..."
[ "$ub_sha" = "$ART_SHA" ] || {
    say "UBOOT READBACK MISMATCH (expected ${ART_SHA:0:16}...)"
    say "recover: hold POWER+VOL_DOWN 7-10 s, run ./magic-b500-recover.sh"
    exit 5
}
[ "$sp_sha" = "$SPL_SHA" ] || {
    say "SPL READBACK MISMATCH (expected ${SPL_SHA:0:16}...)"
    say "recover: hold POWER+VOL_DOWN 7-10 s, run ./magic-b500-recover.sh"
    exit 5
}
say "readback gate: PASS"

# ---- wait for first corrected-carrier boot -------------------------------
wait_android() {
    local deadline=$((SECONDS + $1))
    while [ $SECONDS -lt $deadline ]; do
        if adb devices 2>/dev/null | grep -q "^$SERIAL[[:space:]]*device$"; then
            return 0
        fi
        sleep 2
    done
    return 1
}
props() {
    local p
    for p in ro.boot.flash.locked ro.boot.verifiedbootstate ro.boot.veritymode \
             sys.boot_completed ro.build.fingerprint; do
        printf '  %s = %s\n' "$p" \
            "$(adb -s "$SERIAL" shell getprop "$p" 2>/dev/null | tr -d '\r')" \
            | tee -a "$LOG"
    done
}

say "waiting for Android after corrected carrier boot (no spl-unlock)..."
if ! wait_android 180; then
    say "NO ADB after 180 s: stock SPL did not boot the corrected carrier, or boot is stuck."
    say "recover: hold POWER+VOL_DOWN 7-10 s; watcher live;"
    say "         run ./magic-b500-recover.sh  (restores B2 LK + host spl-unlock)"
    exit 6
fi
say "ANDROID UP after corrected carrier boot"
props

# ---- second boot: proves no host spl-unlock is needed ---------------------
say "rebooting again to prove persistence (no host action)..."
adb -s "$SERIAL" reboot >/dev/null 2>&1 || true
if ! wait_android 180; then
    say "SECOND BOOT FAILED: corrected carrier booted once but not again."
    say "recover: hold POWER+VOL_DOWN 7-10 s; run ./magic-b500-recover.sh"
    exit 7
fi
say "PERSISTENT: second boot reached Android with no host spl-unlock"
props

# ---- read-only post-run uboot_log capture --------------------------------
say "post-run uboot_log read (read-only): rebooting to BROM"
adb -s "$SERIAL" reboot autoloader >/dev/null 2>&1 || true
if ! wait_node "BROM (post-read)" 300; then
    say "no BROM for post-read. Device remains persistent; rerun magic-b500-postread-cmd.txt later."
    exit 8
fi
load_cmd magic-b500-postread-cmd.txt || { say "bad magic-b500-postread-cmd.txt"; exit 1; }
say "spd_dump: ${TOKENS[*]}"
"$SPD" --wait 300 "${TOKENS[@]}" </dev/null 2>&1 | tee -a "$LOG"
say "post-read spd_dump exit=${PIPESTATUS[0]}"
if [ ! -s "$OUT/uboot_log-post.bin" ]; then
    say "POST LOG MISSING. Device remains persistent; rerun magic-b500-postread-cmd.txt later."
    exit 8
fi
say "post-run log: $OUT/uboot_log-post.bin ($(stat -c %s "$OUT/uboot_log-post.bin") bytes)"
if ! wait_android 180; then
    say "post-read reset did not reach Android. The carrier is still in flash; hold POWER and retry."
    exit 8
fi
say "post-read Android up"
props
say "=== corrected magic64 carrier test PASS $(date -Is) ==="
exit 0
