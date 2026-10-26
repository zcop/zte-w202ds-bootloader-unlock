#!/bin/sh
# Create the Android-named AArch64 binutils links that magic64 expects.
#
# magic64 assembles and links a tiny AArch64 payload, then looks for
#   aarch64-linux-android-as
#   aarch64-linux-android-ld
#   aarch64-linux-android-objcopy
# in its own directory. Most Linux hosts have the GNU-named tools instead.
#
# Run once after cloning:
#   ./setup-build-tools.sh

set -eu
cd "$(dirname "$0")"

missing=0
for tool in as ld objcopy; do
    if command -v "aarch64-linux-android-$tool" >/dev/null 2>&1; then
        src=$(command -v "aarch64-linux-android-$tool")
    elif command -v "aarch64-linux-gnu-$tool" >/dev/null 2>&1; then
        src=$(command -v "aarch64-linux-gnu-$tool")
    else
        echo "missing: aarch64-linux-android-$tool or aarch64-linux-gnu-$tool" >&2
        missing=1
        continue
    fi
    ln -sf "$src" "aarch64-linux-android-$tool"
    echo "linked aarch64-linux-android-$tool -> $src"
done

if [ "$missing" -ne 0 ]; then
    echo "install the AArch64 binutils package and rerun this script" >&2
    exit 1
fi
