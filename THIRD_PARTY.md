# Third-party code and firmware

This repository is a personal, private snapshot of a device-specific unlock.
It includes code and binaries from upstream research projects so the exact
tested procedure can be reproduced. No upstream license file was present in
the copies used here. Check the upstream repositories and their terms before
making this repository public or redistributing the binaries.

## Spreadtrum download tool and payloads

- `tools/spreadtrum_flash/spd_dump`
- `tools/spreadtrum_flash/README.md`
- `work/w202ds/stage2b-run/fdl1-dl.bin`
- `work/w202ds/stage2b-run/fdl2-dl.bin`
- `work/w202ds/stage2b-run/spl-unlock.bin`
- `work/w202ds/stage2b-run/custom_exec_no_verify_65012f48.bin`

Upstream:

- <https://github.com/TomKing062/spreadtrum_flash>
- <https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader>

`spd_dump` is the Linux build used by the scripts. It speaks to the Unisoc
BROM/FDL protocol over USB and requires libusb.

## magic64 / difftool

- `work/w202ds/persistent-magic/magic64-linux.cpp`
- `work/w202ds/persistent-magic/difftool-linux.c`
- `work/w202ds/persistent-magic/magic64`
- `work/w202ds/persistent-magic/difftool`

These are the Linux ports of the `magic64` and `difftool` utilities used by
the TomKing062 unlock research. The local sources are included so the binaries
can be rebuilt. The prebuilt binaries are x86-64 Linux.

## Stock firmware images

- `tools/spreadtrum_flash/backups/2026-10-17-full/uboot_b.bin`
- `tools/spreadtrum_flash/backups/2026-10-17-full/splloader.bin`
- `work/w202ds/persistent/uboot_b-unlock.bin`
- `work/w202ds/persistent-magic-b500/uboot_b-magic64-b500.bin`

These are device firmware and patched firmware from the test W202DS. They are
included only for this exact build. They are not a generic firmware pack and
should not be flashed to another device.

## No license grant

Nothing in this repository grants a license to the third-party components.
The local notes and scripts are provided as-is for personal repair and
research use, with no warranty. Flashing a bootloader can brick the device.
