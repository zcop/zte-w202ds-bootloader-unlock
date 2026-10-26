# ZTE W202DS — Persistent Bootloader Unlock (verified)

Status: **verified on hardware, 2026-10-21.** The tablet booted Android three
times without a host `spl-unlock`; the third boot used a changed boot ID.
This is the current procedure. The older
`docs/unlock-bootloader-W202DS.md` is historical research and is superseded by
this document.

> For a plain-language, step-by-step walkthrough, see
> [`persistent-unlock-W202DS-guide.md`](persistent-unlock-W202DS-guide.md).
> It explains which script to run at each step and what result to check for.

Scope: ZTE W202DS (`P720P01`, product `CN_P720P01`), Unisoc **UMS9620-AB**,
A/B, Android 13, firmware `TP1A.220624.014` / `20260709.232156`, active slot
`_b`, LK build `2026-07-09-23:28:18_LOCAL`.

> **This is an AP-side unlock only.** It changes the LK lock verdict seen by
> Android/AVB. It does **not** change the TEE/secure-world state or create a
> valid `miscdata` unlock token. `ro.boot.verifiedbootstate` is `orange`, not
> `green`.

---

## 1. Result

Final verified state:

```text
sys.boot_completed          = 1
ro.boot.flash.locked        = 0
ro.boot.verifiedbootstate   = orange
ro.boot.veritymode          = disabled
ro.boot.slot_suffix         = _b
ro.boot.vbmeta.device_state = unlocked
```

The chain is:

```text
stock BROM
  -> stock splloader (unchanged, 262,144 B)
  -> magic64 carrier in uboot_b
       - stock LK payload, stock header hash, stock certificate
       - post-verification shellcode
       - runtime B2 patch at 0xB50629B4
  -> stock LK (unlocked verdict)
  -> Android
```

No `spl-unlock` is sent after the reset. The stock SPL verifies the unchanged
stock LK payload; the carrier applies the lock-verdict patch in RAM after that
verification.

The earlier magic64 failure used patch address `0x9F0629B4` (the generic
`0x9F000000` example base). The W202DS stock SPL loads the LK payload at
`0xB5000000` (load call at SPL VA `0x6500AFAC`), so the correct target is:

```text
0xB5000000 + 0x629B4 = 0xB50629B4
```

That was the only functional difference between the failed carrier and the
carrier that now persists.

## 2. Warnings and scope

- **Back up every partition first.** Keep stock `splloader`, `uboot_b`,
  `vbmeta_b`, `super`, `boot_b`, `init_boot_b`, `misc`, and `userdata` as
  applicable. No backup means no rollback.
- **Build-specific.** The B2/LK file offset and the `0xB50629B4` target are for
  this W202DS build and slot B. Do not reuse them on `uboot_a`, another
  firmware, or another SoC.
- **A/B:** only `uboot_b` is patched. Do not switch to slot A and expect the
  same result; `uboot_a` is a different build and was not patched.
- **The stock SPL remains in flash.** The unlock depends on the carrier
  applying the patch at every boot. Do not replace `uboot_b` with stock and
  expect the unlock to remain.
- **OTA risk.** A future OTA can overwrite `uboot_b` and return the device to
  the locked state. Re-check the hashes and props after any update.
- **No TEE unlock.** Banking/DRM/Play Integrity checks that require a locked
  green device or strong integrity will not see one. This procedure was chosen
  with that limitation accepted.
- **Verity is separate.** `ro.boot.veritymode=disabled` in this device's
  current state comes from the modified flag-1 `vbmeta_b` used for the custom
  `super`/GApps image. The magic64 carrier only supplies the unlock verdict.
  Flashing a stock `vbmeta_b` will change verity behavior independently.

## 3. Verified inputs

| item | size | sha256 |
|---|---:|---|
| stock `splloader.bin` | 262,144 (`0x40000`) | `77a4fa3d739dfd6b333ed3c81301d59397445c246cd6def8ec9d4151c217a47d` |
| stock `uboot_b.bin` | 5,242,880 (`0x500000`) | `0ae123503d1fedb4d9cdf7b6bdab1ad9f5f9cf1aa5077605c4bf79a26050ad70` |
| B2 LK, `uboot_b-unlock.bin` | 5,242,880 (`0x500000`) | `d221042556e13fe52d6093036c14ab8bac4fe9de40ba89cc4da516de9efac37e` |
| magic64 carrier, `uboot_b-magic64-b500.bin` | 1,130,520 (`0x114018`) | `c37d0a4c63ff5d1f9ce1782838435c2c0437224ec4731deb3e5a3242909174b0` |
| B2 LK file offset | — | `0x62BB4` (VA `0xB50629B4`) |
| carrier patch entry | — | `addr=0xB50629B4`, 4 words, `F00005C1 52800020 B908C820 D65F03C0` |

The stock `splloader.bin` is the full 256 KiB partition read. The 65,480-byte
file is the **patched** `spl-unlock.bin` produced by `gen_spl-unlock`, not the
stock image. (The earlier public issue's table gave 65,480 B for the stock
image; that is the patched image's size. The hash above is for the full
262,144-byte stock image.)

After the device test, the carrier was rebuilt independently from the stock
image and the B2 LK and compared byte-for-byte with the tested artifact:
identical hash `c37d0a4c…74b0`.

## 4. Build the carrier (offline)

All steps are offline. Use a copy of the stock images; never overwrite the only
backup.

### 4.1 Build the B2 LK

Use the checked script in this tree:

```sh
python3 analysis/patch-lk-verdict-stub.py \
  -i /path/to/stock/uboot_b.bin \
  -o work/w202ds/persistent/uboot_b-unlock.bin
```

Expected output hash is `d2210425…c37e`. The script validates the 16 stock
bytes at file offset `0x62BB4`, writes the four-word `get_lock_status()` stub,
and recomputes the DHTB header hash. The stub makes the function return `1`
without touching storage or TEE.

Reproducer if the checked script is unavailable:

```python
import hashlib

d = bytearray(open("uboot_b.bin", "rb").read())
assert len(d) == 5 * 1024 * 1024 and d[:4] == b"DHTB"
assert d[0x62BB4:0x62BC4] == bytes.fromhex("fd7bbea9803b80d2fd030091f35301a9")
d[0x62BB4:0x62BC4] = bytes.fromhex("c10500f02000805220c808b9c0035fd6")
d[0x08:0x28] = hashlib.sha256(bytes(d[0x200:0x113A60])).digest()
open("uboot_b-unlock.bin", "wb").write(d)
```

### 4.2 Trim the stock image

`magic64` expects the real end of the DHTB image, not the 5 MiB partition
padding. The real end here is `0x113F18`.

```sh
python3 - <<'PY'
from pathlib import Path
p = Path("uboot_b.bin").read_bytes()
assert len(p) == 0x500000 and p[:4] == b"DHTB"
Path("uboot_b-stock-trimmed.bin").write_bytes(p[:0x113F18])
PY
```

The trimmed stock image used here had sha256
`015b660448597817ca241036ef09a51467b60a40ede711c9d1bbe09a4f5baa51`.

### 4.3 Add the magic64 shellcode

Use the public `magic64` tool from
`unisoc_chipram_signcheck_exploit` (or the equivalent Linux port). Run it in a
scratch build directory because it writes `patched.bin` in the current
directory.

```sh
./magic64 uboot_b-stock-trimmed.bin
# output: patched.bin (0x114018 bytes), with an empty patch list
```

The shellcode is added after the stock payload. The stock payload, header
hash, and certificate remain unchanged.

### 4.4 Inject the runtime patch with `difftool`

`difftool` compares the B2 LK with the magic64-prepared stock image and writes
the patch list. The load address **must** be `0xB5000000` for this device.

```sh
./difftool \
  uboot_b-unlock.bin \
  patched.bin \
  0xB5000000 \
  uboot_b-magic64-b500.bin
```

Expected output:

```text
Patched file saved to: uboot_b-magic64-b500.bin (1130520 bytes)
Patch entries: 1
[0] addr=0xB50629B4 len=4 words
    data: 0xF00005C1 0x52800020 0xB908C820 0xD65F03C0
```

Verify before touching the tablet:

```sh
sha256sum uboot_b-magic64-b500.bin
# c37d0a4c63ff5d1f9ce1782838435c2c0437224ec4731deb3e5a3242909174b0
```

The offline verifier `work/w202ds/persistent-magic-b500/verify-magic64-b500.py`
checks the stock payload, stock header hash, stock certificate, jump target,
patch address/data, and the on-flash-stock property. It reports **28/28
checks pass**.

## 5. Flash the persistent pair

### 5.1 Preconditions

- Full backup, including `splloader`, `uboot_b`, `vbmeta_b`, and `super`.
- Battery at least 50%.
- BROM access (`1782:4d00`) and the FDL1/FDL2 files.
- A working USB node permission setup. On this host a watcher (`fix-node.sh`)
  made the BROM node writable; a udev rule is the normal alternative.
- Tablet on Android with ADB, or already in BROM.
- **Explicit confirmation**: this writes the bootloader. Do not run it
  unattended or on a guess.

### 5.2 Exact session

The tested command read the old `uboot_log`, wrote the carrier and stock SPL,
read both back, and reset:

```sh
spd_dump --wait 300 exec_addr 0x65012f48 \
  fdl fdl1-dl.bin 0x65000800 \
  fdl fdl2-dl.bin 0xb4fffe00 exec \
  read_part uboot_log 0 0x1000000 uboot_log-pre.bin \
  w uboot_b uboot_b-magic64-b500.bin \
  w splloader splloader.bin \
  read_part uboot_b 0 0x114018 uboot_b-readback.bin \
  read_part splloader 0 0x40000 splloader-readback.bin \
  reset
```

Use the stock `splloader.bin` (262,144 B), **not** `spl-unlock.bin`.

### 5.3 Gate on readback

Both readbacks must match exactly:

```text
uboot_b   1,130,520 B  sha256 c37d0a4c…74b0
splloader   262,144 B  sha256 77a4fa3d…a47d
```

If either mismatches, do not boot. Treat it as a failed write and use the
recovery path in section 7.

### 5.4 Reset

After the reset the stock SPL loads the carrier from flash. **Do not send
`spl-unlock`.** That is the entire point of this procedure.

## 6. Verify persistence

ADB can enumerate before Android has finished booting. Poll
`sys.boot_completed` until it is `1`; do not treat an early ADB connection as
success.

First boot:

```sh
adb -s <serial> shell \
  'getprop sys.boot_completed; getprop ro.boot.flash.locked; \
   getprop ro.boot.verifiedbootstate; getprop ro.boot.veritymode; \
   getprop ro.boot.slot_suffix; getprop ro.boot.vbmeta.device_state'
```

Expected:

```text
1
0
orange
disabled
_b
unlocked
```

Then reboot normally and verify again:

```sh
adb -s <serial> reboot
# wait for ADB, then poll sys.boot_completed == 1
```

A changed `boot_id` and a fresh `uptime` prove it was a real boot, not a stale
ADB session. On this device the third boot's `boot_id` changed from
`eb0ef000…` to `7ff7c7e1…`.

The optional post-run `uboot_log` capture is read-only. The successful test was
interrupted before that capture, so `uboot_log-post.bin` is absent from the
record; the three boots and runtime props are the persistence evidence.

## 7. Recovery and rollback

### 7.1 Return to the known tethered state

This is the state used before the persistent test: B2 LK in `uboot_b`, erased
`splloader`, and the host `spl-unlock` on every boot.

1. Force BROM with `POWER+VOL_DOWN` for 7–10 seconds.
2. Restore the B2 LK and read it back:

```sh
spd_dump --wait 300 exec_addr 0x65012f48 \
  fdl fdl1-dl.bin 0x65000800 \
  fdl fdl2-dl.bin 0xb4fffe00 exec \
  w uboot_b uboot_b-unlock.bin \
  read_part uboot_b 0 0x500000 uboot_b-restored-readback.bin \
  e splloader \
  reset
```

Gate on `d2210425…c37e`. The erase leaves no SPL, so the next normal power-on
falls back to BROM. Run the host `gen_spl-unlock`/`spl-unlock` flow to boot the
B2 LK. Expect `flash.locked=0`, `orange`, and the same custom system.

The armed script `work/w202ds/stage2b-run/magic-b500-recover.sh` automates this
path and also captures the failed boot log. It intentionally returns to the
**tethered** state, not to stock.

### 7.2 Full stock restore

Write the stock `splloader.bin` and stock `uboot_b.bin` back, read back both,
and reset. With the stock `vbmeta_b`/`super`, expect the locked/green state.
This discards the persistent unlock; it is the correct rollback if the device
must be returned to stock.

Never leave a stock `uboot_b` paired with an erased `splloader` as a permanent
state; that is a BROM-only recovery state.

## 8. Custom system and Magisk

The persistent unlock is independent of the custom `super` and modified
`vbmeta_b`. On this device those were installed earlier:

```text
super     custom debloat+GApps   sha256 7911dfa7…a0e2
vbmeta_b  flag 1 (verity off)    sha256 99f74c8d…38d8
```

The persistent test did **not** write `super`, `vbmeta_b`, `boot`, `init_boot`,
or `userdata`; the GApps packages and Play Store data remained present.

Magisk is a separate operation. With the device persistently unlocked, patch
`boot_b` or `init_boot_b` as appropriate, read back the image, and keep a stock
copy. Do not assume that `verity` flag 1 unlocks `boot`; the verity flag and the
bootloader verdict are separate controls. A Magisk write needs its own explicit
confirmation and recovery plan.

## 9. Evidence

- `analysis/r42-magic64-base-fix-2026-10-21.md` — address error and corrected
  carrier derivation.
- `analysis/r44-magic-b500-result-2026-10-21.md` — device result, readbacks,
  three boots, and caveats.
- `work/w202ds/stage2b-run/logs/magic-b500-run.log` — full write/readback/boot
  log.
- `work/w202ds/stage2b-run/magic-b500-out/` — readbacks and pre-run log.
- `work/w202ds/persistent-magic-b500/verify-magic64-b500.log` — 28/28 offline
  checks.
- `work/w202ds/persistent-magic-b500/build-check/` — independent rebuild of
  the carrier from stock + B2; output hash matches the tested carrier.
- Public issue update:
  https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader/issues/337#issuecomment-6309209181

## 10. Short version

```text
1. Back up.
2. Build B2 LK; build magic64 carrier with load base 0xB5000000.
3. Flash carrier to uboot_b and stock splloader to splloader.
4. Read both back; require exact hashes.
5. Reset; do not run spl-unlock.
6. Check flash.locked=0 / orange / boot_completed=1.
7. Reboot twice; check again.
8. If anything fails: POWER+VOL_DOWN -> BROM -> restore B2 LK,
   erase splloader, host spl-unlock.
```

The persistent unlock is real for this build, but it is an AP-side patch, not a
secure-world unlock. Keep the stock backups and do not accept an OTA without
re-checking `uboot_b`, `splloader`, and the boot properties.
