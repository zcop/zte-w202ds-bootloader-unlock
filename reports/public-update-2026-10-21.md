## Update 2026-10-21 — persistent unlock achieved (answers Q3)

The W202DS is now **persistent**: it boots Android with no host `spl-unlock`,
using the **stock SPL** plus a corrected post-verification **magic64** carrier
in `uboot_b`.

This is the same device/firmware as the report above: ZTE W202DS (`P720P01`),
UMS9620-AB, A/B, firmware `TP1A.220624.014` / `20260709.232156`, active slot
`_b`, LK build `2026-07-09-23:28:18_LOCAL`.

### Result

After writing the carrier + stock SPL and resetting:

```text
sys.boot_completed          = 1
ro.boot.flash.locked        = 0
ro.boot.verifiedbootstate   = orange
ro.boot.veritymode          = disabled
ro.boot.slot_suffix         = _b
ro.boot.vbmeta.device_state = unlocked
```

No `spl-unlock` was sent after the reset. The tablet booted a second and third
time normally; the third boot had a new `boot_id`
(`eb0ef000…` -> `7ff7c7e1…`) and `sys.boot_completed=1`. GApps remained present
(`com.android.vending`, `com.google.android.gms`, `com.google.android.gsf`,
`com.google.android.partnersetup`).

This is still an **AP-side** unlock: `flash.locked=0` / `orange` comes from the
LK verdict. The TEE/secure-world state was not changed, so this is not a
green/strong-integrity unlock.

### Why the earlier magic64 attempt stayed locked

The carrier used the generic magic64 example load base `0x9F000000`, so it
patched `0x9F0629B4`. This W202DS stock SPL loads the LK payload at
`0xB5000000` (load call at SPL VA `0x6500AFAC`, `mov x2, #0xB5000000`), and the
LK runs at that base. The correct patch target is therefore:

```text
0xB5000000 + 0x629B4 = 0xB50629B4
```

The only functional difference between the failed carrier and the working one
is one byte in the patch-entry address. The stock LK payload, stock header
hash, and stock certificate are unchanged; magic64 copies the stock payload and
applies the 16-byte `get_lock_status()` verdict stub in RAM after SPL
verification. The stock SPL therefore still sees the stock payload it verified.

Working carrier:

```text
uboot_b-magic64-b500.bin
size    1,130,520 (0x114018)
sha256  c37d0a4c63ff5d1f9ce1782838435c2c0437224ec4731deb3e5a3242909174b0
patch   addr=0xB50629B4 len=4 words
        F00005C1 52800020 B908C820 D65F03C0
```

Inputs used:

```text
stock splloader.bin  262,144 B  sha256 77a4fa3d739dfd6b333ed3c81301d59397445c246cd6def8ec9d4151c217a47d
stock uboot_b.bin  5,242,880 B  sha256 0ae123503d1fedb4d9cdf7b6bdab1ad9f5f9cf1aa5077605c4bf79a26050ad70
B2 LK              5,242,880 B  sha256 d221042556e13fe52d6093036c14ab8bac4fe9de40ba89cc4da516de9efac37e
```

Small correction to the reproducibility table in the report above: the stock
`splloader.bin` hash `77a4fa3d…` is the **262,144-byte** full partition image.
The 65,480-byte size belongs to the patched `spl-unlock.bin`. The hash and the
size in that row do not describe the same file.

### Build

The public `magic64`/`difftool` path works. The B2 LK reproducer is already in
Appendix A.2; the remaining carrier steps are:

```sh
# 1. Trim the 5 MiB partition image to its real end (0x113F18)
python3 - <<'PY'
from pathlib import Path
p = Path("uboot_b.bin").read_bytes()
assert len(p) == 0x500000 and p[:4] == b"DHTB"
Path("uboot_b-stock-trimmed.bin").write_bytes(p[:0x113F18])
PY

# 2. magic64 adds its shellcode; it writes "patched.bin"
./magic64 uboot_b-stock-trimmed.bin

# 3. difftool injects the B2 diff at the real LK base
./difftool uboot_b-unlock.bin patched.bin 0xB5000000 uboot_b-magic64-b500.bin
```

The important reproducible values are the hashes and the `0xB5000000` load
address. A rebuild from the stock image + B2 LK produced byte-for-byte the same
carrier hash.

### Flash and verify

This was the write session (both writes + readbacks in one BROM session; the
`reset` boots the carrier):

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

Readback gate (both exact):

```text
uboot_b   1,130,520 B  c37d0a4c…74b0
splloader   262,144 B  77a4fa3d…a47d
```

After reset, **do not run `spl-unlock`**. ADB may enumerate before Android is
finished; poll `sys.boot_completed=1` before declaring success. Then reboot
normally and check again.

### Recovery

To return to the known tethered state: force BROM with `POWER+VOL_DOWN` (7–10 s),
restore the B2 LK (`d2210425…c37e`), read it back, erase `splloader`, reset, and
run the host `spl-unlock` flow. To return to full stock, write stock
`splloader.bin` and stock `uboot_b.bin` back and restore stock `vbmeta_b` /
`super` as needed.

Do not leave stock `uboot_b` paired with an erased `splloader` as a permanent
state; that is only a BROM recovery state.

### Limits

- Build-specific: `0xB50629B4`, the 16-byte LK offset, and slot B are for this
  W202DS build. Do not reuse on `uboot_a` or another firmware.
- The stock SPL remains in flash; a future OTA that overwrites `uboot_b` will
  remove the unlock.
- `veritymode=disabled` here is from the separate flag-1 `vbmeta_b` used for
  the custom `super`/GApps image. The magic64 carrier only supplies the unlock
  verdict; verity and unlock are separate controls.
- The optional post-run `uboot_log` read was interrupted, so no
  `uboot_log-post.bin` was captured. The result is based on the exact readbacks
  and three real cold boots. No write occurred after the readback gate.

This answers Q3: a persistent route exists for this 9620 A/B build without a
valid `miscdata` token or an SMC call, by keeping the stock SPL and applying the
verdict patch after verification. It is not a secure-world unlock.
