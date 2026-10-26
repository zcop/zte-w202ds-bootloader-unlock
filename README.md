# ZTE W202DS persistent bootloader unlock

This repository is a cleaned, self-contained snapshot of the **verified
persistent AP-side bootloader unlock** for the ZTE W202DS.

It contains the human-readable procedure, the build inputs, the working
carrier, the flashing script, and the recovery path used on the test device.

> **Status:** verified on 2026-10-21. The tablet booted Android three times
> with **no host `spl-unlock`**, and reported `ro.boot.flash.locked=0` and
> `ro.boot.verifiedbootstate=orange`.

> **This is not a generic Unisoc unlock.** It is specific to the W202DS
> (`P720P01` / `CN_P720P01`, UMS9620-AB, Android 13) and to the tested build
> and slot B. The addresses and offsets below come from that exact build.
> Do not use them on another model, build, or slot.

---

## Start here

Read the plain-language guide **before** running anything:

- **[Persistent unlock guide](docs/persistent-unlock-W202DS-guide.md)** —
  what to dump, what to patch, what to flash, how to verify, and how to
  recover.
- **[Technical procedure](docs/persistent-unlock-W202DS.md)** — the full
  reasoning, offsets, hashes, and evidence.
- **[Device result](analysis/r44-magic-b500-result-2026-10-21.md)** — the
  readbacks and three-boot persistence test.
- **[Public issue update](reports/public-update-2026-10-21.md)** — the
  short report posted to the upstream issue.

If you only read one file, read the guide.

---

## What is in the box

| Path | What it is |
|---|---|
| `docs/persistent-unlock-W202DS-guide.md` | Human step-by-step guide. Start here. |
| `docs/persistent-unlock-W202DS.md` | Canonical technical procedure. |
| `docs/unlock-bootloader-W202DS.md` | Older tethered-unlock research (historical). |
| `analysis/patch-lk-verdict-stub.py` | Builds the B2 reference LK from the stock LK. |
| `work/w202ds/persistent/uboot_b-unlock.bin` | B2 reference LK (patched verdict). |
| `work/w202ds/persistent-magic/magic64` | Adds the small post-verification loader. |
| `work/w202ds/persistent-magic/difftool` | Injects the B2 runtime patch at `0xB5000000`. |
| `work/w202ds/persistent-magic-b500/uboot_b-magic64-b500.bin` | Final verified carrier. |
| `work/w202ds/persistent-magic-b500/verify-magic64-b500.py` | 28-check offline verifier. |
| `work/w202ds/stage2b-run/magic-b500-run.sh` | Flash, read back, reboot, and check props. |
| `work/w202ds/stage2b-run/magic-b500-recover.sh` | Return to the tethered state (erases `splloader`). |
| `work/w202ds/stage2b-run/fix-node.sh` | USB/BROM node access helper. |
| `tools/spreadtrum_flash/spd_dump` | Spreadtrum download tool used by the scripts. |
| `tools/spreadtrum_flash/backups/2026-10-17-full/` | Stock `uboot_b` and `splloader` for this build. |
| `SHA256SUMS` | Hashes for every tracked file. |

The stock images and the final carrier are included so the exact build can be
reproduced and restored. They are device- and build-specific; they are not a
generic firmware pack.

---

## Quick start (only for this exact build)

### 1. Check the files

```sh
sha256sum -c SHA256SUMS
```

Every line should say `OK`.

### 2. Verify the carrier offline

```sh
python3 work/w202ds/persistent-magic-b500/verify-magic64-b500.py
```

Expected final line:

```text
ALL 28 CHECKS PASS
```

### 3. Read the guide, then flash

Do not skip the guide. The short version is:

```sh
export SERIAL=<your-adb-serial>
export ADB_SERIAL="$SERIAL"

cd work/w202ds/stage2b-run
sudo ./fix-node.sh 3600       # leave running in another terminal
./magic-b500-run.sh
```

No serial number is stored in this repository. Find yours with `adb devices`.
The script asks you to type `GO`. It writes the carrier and the stock SPL,
reads both back, resets, and checks the device. Success means the tablet
boots without a host-side `spl-unlock`.

### 4. Recovery

If the tablet does not boot, hold **POWER + VOL_DOWN** for 7–10 seconds to
reach BROM, then run:

```sh
cd work/w202ds/stage2b-run
./magic-b500-recover.sh
```

This restores `uboot_b-unlock.bin`, erases `splloader`, and runs the normal
host `spl-unlock` flow to return to the **tethered** state. Do not run it
unless you intend to give up the persistent unlock.

---

## Rebuilding the carrier

The prebuilt binaries are included. To rebuild `magic64` or `difftool`, use a
Linux host with `g++` (or `gcc`) and the AArch64 binutils. `magic64` looks for
the Android-named assembler tools in its own folder:

```sh
cd work/w202ds/persistent-magic
./setup-build-tools.sh
```

The script links `aarch64-linux-android-{as,ld,objcopy}` to the host's
`aarch64-linux-gnu-*` tools. Then follow sections 3.1–3.4 of the guide.

The final carrier hash must be:

```text
c37d0a4c63ff5d1f9ce1782838435c2c0437224ec4731deb3e5a3242909174b0
```

---

## Important limits

- **AP-side only.** This does not unlock TEE or the secure world. The expected
  state is `orange`, not `green`.
- **Slot B and build specific.** The procedure assumes `ro.boot.slot_suffix=_b`
  and fingerprint
  `zte/CN_P720P01/P720P01:13/TP1A.220624.014/20260709.232156:user/release-keys`.
- **An OTA can undo it.** A firmware update can overwrite `uboot_b` and
  re-lock the device.
- **No Magisk here.** This repository does not write `boot` or `init_boot`.
- **Recovery is destructive to the persistent state.** `magic-b500-recover.sh`
  erases `splloader` on purpose.
- **Keep a full backup.** The repository includes only the two images needed
  for this unlock. Keep the original full partition dump somewhere safe.

---

## Third-party code and firmware

See [`THIRD_PARTY.md`](THIRD_PARTY.md). The download tool and the FDL/SPL
payloads come from the upstream Unisoc research project. No license file was
present in the upstream snapshot used here. This repository is private by
default; check the upstream terms before making it public or redistributing
the binaries.
