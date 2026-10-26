#!/bin/sh
# fix-node.sh — per-session USB access for the download mode (1782:4d00).
# No udev rule: run this as root BEFORE the key combo; it keeps watching for
# the BootROM node and grants group `plugdev` rw on each one that appears
# (first enumeration and any re-enumeration). If the device arrives while
# spd_dump is already waiting, its single hotplug open attempt fails fatally
# ("Connection failed") — hence: enumerate first, then start the tool.
# Ctrl-C when you are done.
#
#   sudo ./fix-node.sh [seconds]        (default 600, minimum is 1)
#
# Exit status: 0 if at least one node was granted access (the watcher keeps
# running until the timeout); 1 if no 1782:4d00 node showed up in time.
set -u

[ "$(id -u)" -eq 0 ] || { echo "fix-node: run as root (sudo $0)" >&2; exit 1; }
secs="${1:-600}"
end=$(( $(date +%s) + secs ))
fixed=0

while [ "$(date +%s)" -lt "$end" ]; do
  for d in /sys/bus/usb/devices/*/; do
    [ -f "${d}idVendor" ] && [ -f "${d}devnum" ] || continue
    [ "$(cat "${d}idVendor")" = "1782" ] || continue
    # 4d00 = ROM download (BROM); d001 = the running Android/recovery adb node
    case "$(cat "${d}idProduct" 2>/dev/null)" in 4d00|d001) ;; *) continue ;; esac
    # USB node paths are zero-padded: bus 3, dev 36 -> /dev/bus/usb/003/036
    node=$(printf '/dev/bus/usb/%03d/%03d' \
      "$(cat "${d}busnum" 2>/dev/null)" "$(cat "${d}devnum" 2>/dev/null)")
    [ -c "$node" ] || continue
    grp=$(stat -c %G "$node" 2>/dev/null)
    mode=$(stat -c %a "$node" 2>/dev/null)
    if [ "$grp" = "plugdev" ]; then
      case "$(printf '%s' "$mode" | cut -c2)" in 6|7) continue ;; esac
    fi
    if chgrp plugdev "$node" && chmod g+rw "$node"; then
      echo "fix-node: granted plugdev rw on $node"
      fixed=1
    else
      echo "fix-node: chgrp/chmod failed on $node" >&2
    fi
  done
  sleep 0.2
done

if [ "$fixed" -eq 0 ]; then
  echo "fix-node: no 1782:4d00 node appeared within ${secs}s" >&2
  exit 1
fi
exit 0
