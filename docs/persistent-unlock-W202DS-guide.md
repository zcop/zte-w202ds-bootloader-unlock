# ZTE W202DS — Persistent Bootloader Unlock

## A plain-language, step-by-step guide

**Applies to:** ZTE W202DS (`P720P01` / `CN_P720P01`), Unisoc **UMS9620-AB**,
Android 13, firmware `TP1A.220624.014` / `20260709.232156`, active slot **B**
(`_b`), LK build `2026-07-09-23:28:18_LOCAL`.

**What you get:** the tablet boots Android with
`ro.boot.flash.locked=0` and `ro.boot.verifiedbootstate=orange` **without**
running a host unlock command on every boot. The stock SPL stays in flash.

**What you do not get:** a TEE/secure-world unlock, a green device, or strong
Play Integrity. Banking, DRM and some Google checks may still fail. See
[Limits and rules](#7-limits-and-rules).

> **Already done?** The reference tablet was left in this state on 2026-10-21.
> If its props already show `flash.locked=0` and `verifiedbootstate=orange`
> after a normal reboot, do not reflash it. Just verify it with Part 5.

> **Stop if your device is different.** The addresses and offsets in this guide
> are tied to this exact firmware and slot B. Do not use them on `uboot_a`,
> another firmware, or another model. If you are unsure, stop and compare the
> hashes in this guide with your files.

> **Flash gate:** do not write to the tablet until the carrier hash is
> `c37d0a4c…74b0` and the offline verifier says **ALL 28 CHECKS PASS**. If
> either one is different, stop.

## Quick path

Only if you already have a full backup and the verified carrier
`c37d0a4c…74b0`:

1. Check the tablet ([Part 1](#1-check-the-tablet)).
2. Start the USB helper ([step 2.1](#21-start-the-usb-access-helper)).
3. Run the offline verifier ([step 3.5](#35-verify-the-finished-carrier)),
   then run `work/w202ds/stage2b-run/magic-b500-run.sh` and type `GO`
   ([Part 4](#4-flash-the-unlock)).
4. Confirm `readback gate: PASS` and `PERSISTENT`.
5. Check the props ([Part 5](#5-confirm-it-is-persistent)).

If anything fails, use `magic-b500-recover.sh` ([Part 6](#6-recovery)).
Read the full guide before flashing.

---

## Contents

1. [Check the tablet](#1-check-the-tablet)
2. [Back up the partitions](#2-back-up-the-partitions)
3. [Build the unlock files](#3-build-the-unlock-files)
4. [Flash the unlock](#4-flash-the-unlock)
5. [Confirm it is persistent](#5-confirm-it-is-persistent)
6. [Recovery](#6-recovery)
7. [Limits and rules](#7-limits-and-rules)
8. [File map](#appendix-a--file-map)
9. [Exact flash command](#appendix-b--exact-flash-command)
10. [Why `0xB5000000`](#appendix-c--why-0xb5000000)

---

## Words used in this guide

| Word | What it means here |
|---|---|
| **BROM** / download mode | The lowest-level USB mode of the tablet. `spd_dump` talks to it. |
| **SPL** / `splloader` | The small first-stage loader. It checks the LK before running it. |
| **LK** / `uboot` | The bootloader that decides locked/unlocked and starts Android. |
| **B2** | Our unlocked copy of the LK. It is used only as a reference to build the carrier. |
| **Carrier** | The stock LK plus a small loader that changes the lock verdict in RAM after the SPL check. |
| **Readback** | Reading a partition back after writing it, to prove the bytes really landed. |
| **Tethered** | The old state: the tablet needs a host `spl-unlock` command on every boot. |
| **AP-side** | The Android/application-processor side. It is not the protected secure world. |
| **TEE / secure world** | The protected part of the SoC that handles keys, DRM and strong integrity. This guide does not change it. |
| **FDL1 / FDL2** | Small download helpers that `spd_dump` sends before it can read or write. |

## What this guide does

```text
1. Dump the stock LK and SPL from the tablet.
2. Patch the stock LK to make the B2 reference.
3. Wrap the stock LK with the magic64 loader.
4. Put the B2 change into the loader's patch list.
5. Verify the finished carrier offline.
6. Write the carrier to uboot_b and the stock SPL to splloader.
7. Reboot twice and check the props.
```

**Why it works, in one paragraph:** the stock SPL verifies the stock LK and
finds it valid. The added loader then changes the lock function in RAM, after
the check. Android sees `unlocked`; the SPL still sees the stock image it
verified.

### Scripts at a glance

| Step | Script | What it does for you |
|---|---|---|
| Read/write flash | `tools/spreadtrum_flash/spd_dump` | Dumps partitions, writes them back, reads them back. |
| Make the B2 LK | `analysis/patch-lk-verdict-stub.py` | Copies the stock LK and changes the lock verdict. |
| Add the loader | `work/w202ds/persistent-magic/magic64` | Adds the small post-check loader to the stock LK. |
| Add the B2 change | `work/w202ds/persistent-magic/difftool` | Puts the B2 change into the loader's patch list. |
| Check the carrier | `work/w202ds/persistent-magic-b500/verify-magic64-b500.py` | Runs 28 offline checks on the finished file. |
| Flash and test | `work/w202ds/stage2b-run/magic-b500-run.sh` | Writes, reads back, reboots twice, checks props. |
| Emergency recovery | `work/w202ds/stage2b-run/magic-b500-recover.sh` | Restores the tethered state if the new carrier fails. |

---

## 1. Check the tablet

All commands start in this repository's root folder unless the step says
otherwise. The examples use `/path/to/zte-w202ds-bootloader-unlock` as the
repository path; replace it with the actual path on your machine.

```sh
cd /path/to/zte-w202ds-bootloader-unlock

adb devices
adb -s <serial> shell getprop ro.build.fingerprint
adb -s <serial> shell getprop ro.boot.slot_suffix
adb -s <serial> shell getprop ro.boot.flash.locked
adb -s <serial> shell getprop ro.boot.verifiedbootstate
```

**Expected fingerprint and slot:**

```text
zte/CN_P720P01/P720P01:13/TP1A.220624.014/20260709.232156:user/release-keys
_b
```

If the slot is `_a`, **stop**. This guide only works on slot B. The lock and
boot-state values are explained in the next table.

### Which state is the tablet in?

| What you see | What it means | What to do |
|---|---|---|
| `flash.locked=1`, `verifiedbootstate=green` | Stock, locked | Continue from Part 2. |
| `flash.locked=0`, `verifiedbootstate=orange` | Already unlocked | Reboot it once with no host command. If it comes back unlocked, it is already persistent — stop. |
| Unlocked only after running `spl-unlock` | Tethered state | Continue from Part 2. |
| Anything else | Unknown history | **Stop.** Do not guess. |

> Find your serial with `adb devices`. Set it once in every terminal that
> runs the helper or the flash script:
>
> ```sh
> export SERIAL=<adb-serial>
> export ADB_SERIAL="$SERIAL"
> ```
>
> The scripts do not contain a serial number. `magic-b500-run.sh` and
> `magic-b500-recover.sh` require `SERIAL`; `enter-download-mode.sh` accepts
> `ADB_SERIAL` or `SERIAL`.

---

## 2. Back up the partitions

You need at least `uboot_b` and `splloader`. A full backup is better.

### 2.1 Start the USB access helper

Open a **second terminal** and leave this running:

```sh
cd /path/to/zte-w202ds-bootloader-unlock/work/w202ds/stage2b-run
sudo ./fix-node.sh 3600
```

It prints a line like `fix-node: granted plugdev rw on /dev/bus/usb/003/036`
when the tablet appears. Keep it running until the end of the session.

Your normal user must be in the `plugdev` group for `spd_dump` to use that
node. Check with `id -nG`; if `plugdev` is missing, add yourself once and log
in again.

### 2.2 Enter download mode

In the first terminal:

```sh
cd /path/to/zte-w202ds-bootloader-unlock/work/w202ds
export ADB_SERIAL=<serial>
./enter-download-mode.sh 120
```

**Expected:** `[entry] download node up after …s` followed by a `1782:4d00`
line.

If it only reboots back to Android, hold **POWER + VOL_DOWN** for 7–10
seconds while the helper is still waiting. If the helper has already exited,
check `lsusb -d 1782:4d00` before starting `spd_dump`.

### 2.3 Dump the two important partitions

```sh
cd /path/to/zte-w202ds-bootloader-unlock
mkdir -p work/w202ds/backup-$(date +%F)
cd work/w202ds/backup-$(date +%F)

../../../tools/spreadtrum_flash/spd_dump --wait 300 \
  read_part splloader 0 0x40000 splloader.bin \
  read_part uboot_b 0 0x500000 uboot_b.bin \
  reset
```

**Expected:** `Read Part Done` for both partitions, then the tablet resets.

If the `splloader` read fails because the partition is erased, read `uboot_b`
on its own and use the known stock SPL file from the note below.

If the `read_part` form is rejected by your `spd_dump`, use the proven
full-backup command instead:

```sh
cp ../../../tools/spreadtrum_flash/backups/2026-10-17-full/read-list-full.xml .
../../../tools/spreadtrum_flash/spd_dump --wait 300 read_parts read-list-full.xml reset
```

That reads 76 partitions (about 8.5 GB, 6–8 minutes) and excludes `userdata`.

### 2.4 Check the backup

```sh
sha256sum splloader.bin uboot_b.bin
```

For this build, the stock values are:

```text
77a4fa3d739dfd6b333ed3c81301d59397445c246cd6def8ec9d4151c217a47d  splloader.bin
0ae123503d1fedb4d9cdf7b6bdab1ad9f5f9cf1aa5077605c4bf79a26050ad70  uboot_b.bin
```

If `uboot_b.bin` does **not** match, the tablet was already modified. Do not
use that file as the "stock" input. Use the known stock file:

```text
tools/spreadtrum_flash/backups/2026-10-17-full/uboot_b.bin
```

If `splloader.bin` is empty or all zeros, the SPL was erased by an earlier
tethered setup. Use the known stock file instead:

```text
tools/spreadtrum_flash/backups/2026-10-17-full/splloader.bin
```

> Keep these backups somewhere safe. Do not overwrite the only copy.

---

## 3. Build the unlock files

This part is completely offline. It does not touch the tablet.

```sh
cd /path/to/zte-w202ds-bootloader-unlock
mkdir -p work/w202ds/persistent \
         work/w202ds/persistent-magic \
         work/w202ds/persistent-magic-b500
```

### 3.1 Make the B2 reference LK

```sh
cd /path/to/zte-w202ds-bootloader-unlock

python3 analysis/patch-lk-verdict-stub.py \
  -i tools/spreadtrum_flash/backups/2026-10-17-full/uboot_b.bin \
  -o work/w202ds/persistent/uboot_b-unlock.bin
```

**Look for:**

```text
sha256    d221042556e13fe52d6093036c14ab8bac4fe9de40ba89cc4da516de9efac37e
match     expected W202DS slot-B image
```

If you see `error: stock bytes at 0x62bb4 differ`, you gave it a modified
image. Stop and use the stock backup.

**Check:**

```sh
sha256sum work/w202ds/persistent/uboot_b-unlock.bin
```

Expected: `d2210425…c37e`.

### 3.2 Trim the stock LK to its real size

The partition is 5 MiB, but the real image ends earlier. The loader needs the
real end, not the padding.

```sh
cd /path/to/zte-w202ds-bootloader-unlock

python3 - <<'PY'
from pathlib import Path

src = Path("tools/spreadtrum_flash/backups/2026-10-17-full/uboot_b.bin")
dst = Path("work/w202ds/persistent-magic/uboot_b-stock-trimmed.bin")

p = src.read_bytes()
assert len(p) == 0x500000 and p[:4] == b"DHTB"
dst.write_bytes(p[:0x113F18])
print(dst, dst.stat().st_size)
PY
```

**Expected:** `…/uboot_b-stock-trimmed.bin 1130264`.

Optional check: the SHA-256 should be
`015b660448597817ca241036ef09a51467b60a40ede711c9d1bbe09a4f5baa51`.

### 3.3 Add the loader with `magic64`

`magic64` writes its output as `patched.bin` in the **current folder**, so run
it from the build folder.

```sh
cd /path/to/zte-w202ds-bootloader-unlock/work/w202ds/persistent-magic
./magic64 uboot_b-stock-trimmed.bin
stat -c '%n %s' patched.bin
```

**Look for:**

```text
file size: 0x113f18
payload size: 0x113860
patched.bin 1130520
```

`magic64` also prints its small assembly listing; that is normal.

> `magic64` looks for `aarch64-linux-android-as`, `-ld` and `-objcopy` **in its
> own folder**. If this is a fresh clone, run `./setup-build-tools.sh` once in
> that folder to create them. Without those links you will get “assembler not
> found”.

Optional check: `patched.bin` SHA-256 should be
`f14d6e28828676efa5b4e5213bcbe05d8cfb0a62932a18ead2fe30b8e6c7fbd0`.

### 3.4 Put the B2 change into the carrier

This is the step where the load address matters. Use **`0xB5000000`**, not
`0x9F000000`.

```sh
cd /path/to/zte-w202ds-bootloader-unlock/work/w202ds/persistent-magic

./difftool \
  ../persistent/uboot_b-unlock.bin \
  patched.bin \
  0xB5000000 \
  ../persistent-magic-b500/uboot_b-magic64-b500.bin
```

**Look for this patch summary:**

```text
Patch entries: 1
[0] addr=0xB50629B4  len=4 words
    data: 0xF00005C1 0x52800020 0xB908C820 0xD65F03C0
Patched file saved to: ../persistent-magic-b500/uboot_b-magic64-b500.bin (1130520 bytes)
```

If the address is `0x9F0629B4`, you used the wrong load address. **Stop.**
Delete the output and run the command again with `0xB5000000`.

### 3.5 Verify the finished carrier

```sh
cd /path/to/zte-w202ds-bootloader-unlock
python3 work/w202ds/persistent-magic-b500/verify-magic64-b500.py
```

**Expected final line:**

```text
ALL 28 CHECKS PASS
```

**Check the hash:**

```sh
sha256sum work/w202ds/persistent-magic-b500/uboot_b-magic64-b500.bin
```

Expected: `c37d0a4c63ff5d1f9ce1782838435c2c0437224ec4731deb3e5a3242909174b0`.

### Checkpoint

Do not flash until all four are true:

| File | Size | SHA-256 starts with |
|---|---:|---|
| `uboot_b-unlock.bin` (B2 reference) | 5,242,880 | `d2210425` |
| `uboot_b-stock-trimmed.bin` | 1,130,264 | `015b6604` |
| `patched.bin` | 1,130,520 | `f14d6e28` |
| `uboot_b-magic64-b500.bin` (carrier) | 1,130,520 | `c37d0a4c` |

If any value is different, **stop**. Do not write to the tablet.

---

## 4. Flash the unlock

### 4.1 What will be written

| Partition | What goes in | Size |
|---|---|---:|
| `uboot_b` | the verified carrier | 1,130,520 B |
| `splloader` | the **stock** SPL | 262,144 B |

This procedure does **not** write `vbmeta_b`, `super`, `boot_b`,
`init_boot_b`, `misc`, or `userdata`.

### 4.2 Prepare

1. Battery at least **50%** (the script refuses below 50% when it can read it).
2. Tablet booted into Android with **ADB authorized**, or already in BROM.
3. The `fix-node.sh` watcher from step 2.1 still running.
4. The carrier hash is `c37d0a4c…74b0`.

### 4.3 Run the tested script

```sh
cd /path/to/zte-w202ds-bootloader-unlock/work/w202ds/stage2b-run
export SERIAL=<serial>
./magic-b500-run.sh
```

It asks:

```text
Type GO to confirm the corrected bootloader write:
```

Type `GO` and press Enter. Anything else aborts without writing.

If the tablet does not enter download mode by itself, the script waits and
then tells you to hold **POWER + VOL_DOWN** for 7–10 seconds. Do that while
the script is still running.

### 4.4 What the script does, in order

```text
1. Checks the carrier hash, stock SPL hash, sizes, watcher and battery.
2. Reboots the tablet to download mode.
3. Reads the old uboot_log (read-only).
4. Writes uboot_b = carrier.
5. Writes splloader = stock SPL.
6. Reads both partitions back.
7. Resets and waits for Android. No host unlock is sent.
8. Reboots a second time and waits for Android again.
9. Optionally reads the new uboot_log (read-only).
```

### 4.5 What you should see

The important lines are:

```text
[b500] readback gate: PASS
[b500] ANDROID UP after corrected carrier boot
[b500] PERSISTENT: second boot reached Android with no host spl-unlock
[b500] === corrected magic64 carrier test PASS ===
```

The readback values must match:

```text
uboot_b   1,130,520 B  c37d0a4c…74b0
splloader   262,144 B  77a4fa3d…a47d
```

### 4.6 If it stops

Do **not** keep rebooting or re-running the flash. Read the last `[b500]` line.

| Message | Meaning | What to do |
|---|---|---|
| `GUARD FAIL` | A file, hash, watcher or battery check failed | Fix it. Nothing was written. |
| `READBACK MISSING` / `MISMATCH` | The write did not land correctly | Do not boot. Go to [Recovery](#6-recovery). |
| `NO ADB after 180 s` | The carrier did not boot | Go to [Recovery](#6-recovery). |
| `SECOND BOOT FAILED` | It booted once, not twice | Go to [Recovery](#6-recovery). |

The script prints the exact recovery command. It is also in Part 6.

---

## 5. Confirm it is persistent

ADB can appear before Android has finished booting. Wait until
`sys.boot_completed` is `1`.

```sh
adb -s <serial> shell getprop sys.boot_completed
adb -s <serial> shell getprop ro.boot.flash.locked
adb -s <serial> shell getprop ro.boot.verifiedbootstate
adb -s <serial> shell getprop ro.boot.veritymode
adb -s <serial> shell getprop ro.boot.slot_suffix
adb -s <serial> shell getprop ro.boot.vbmeta.device_state
```

**Expected:**

```text
1
0
orange
disabled
_b
unlocked
```

The flash script already rebooted the tablet twice. To confirm independently
that this is a real cold boot, not a stale ADB session:

```sh
adb -s <serial> shell cat /proc/sys/kernel/random/boot_id
adb -s <serial> reboot
```

Wait for Android again, then read `boot_id` again. It must be **different**.
You can repeat this once more for a third boot. Do not run `spl-unlock`
between the reboots.

---

## 6. Recovery

### 6.1 Return to the tethered state

Use this if the new carrier does not boot, or if you want to go back to the
old host-unlock flow.

1. Hold **POWER + VOL_DOWN** for 7–10 seconds to enter BROM.
2. Keep the `fix-node.sh` watcher running.
3. Run:

```sh
cd /path/to/zte-w202ds-bootloader-unlock/work/w202ds/stage2b-run
export SERIAL=<serial>
./magic-b500-recover.sh
```

The script:

```text
1. Reads the failed uboot_log (read-only).
2. Writes the B2 LK back to uboot_b.
3. Reads it back and checks d2210425…c37e.
4. Erases splloader.
5. Resets, then runs the host spl-unlock flow.
6. Waits for Android.
```

This returns the tablet to the **tethered** state, not to stock. Do not run
this script just because you want to “clean up”; it deliberately erases
`splloader`.

### 6.2 Return to full stock

Only do this if you really want to remove the unlock. Write both stock images
back, read them back, and reset.

Start the `fix-node.sh` watcher, put the tablet in BROM, then run this from
`work/w202ds/stage2b-run`:

```sh
../../../tools/spreadtrum_flash/spd_dump --wait 300 \
  exec_addr 0x65012f48 \
  fdl fdl1-dl.bin 0x65000800 \
  fdl fdl2-dl.bin 0xb4fffe00 exec \
  w uboot_b ../../../tools/spreadtrum_flash/backups/2026-10-17-full/uboot_b.bin \
  w splloader ../../../tools/spreadtrum_flash/backups/2026-10-17-full/splloader.bin \
  read_part uboot_b 0 0x500000 stock-uboot_b-readback.bin \
  read_part splloader 0 0x40000 stock-splloader-readback.bin \
  reset
```

**Expected readback hashes:**

```text
uboot_b    0ae12350…ad70
splloader  77a4fa3d…a47d
```

If you also changed `vbmeta_b` or `super` for a custom system, restore their
stock images too. Otherwise the tablet may still boot the custom system or
show `veritymode=disabled`.

> Never leave a stock `uboot_b` paired with an erased `splloader` as a
> permanent state. That is a BROM-only recovery state.

### 6.3 If the tablet will not enter BROM

- Hold **POWER + VOL_DOWN** for 10–15 seconds.
- Try **POWER + VOL_UP**.
- Replug the USB cable while holding the keys.
- Make sure the `fix-node.sh` watcher is running before the keys.
- Do not keep writing blindly. If nothing enumerates as `1782:4d00`, stop and
  diagnose the USB/cable/host first.

---

## 7. Limits and rules

**This is an AP-side unlock.** It changes what Android/LK reports. It does not
change the TEE or secure-world state. Expect `orange`, not `green`.

**It is build-specific.** The `0xB50629B4` address, the 16-byte LK offset, and
slot B are for this exact W202DS firmware. Do not reuse them on `uboot_a`, a
different firmware, or a different SoC.

**An OTA can remove it.** If an update overwrites `uboot_b`, the tablet is
locked again. Re-check the hashes and props after any update.

**The stock SPL stays in flash.** That is intentional. Do not replace
`uboot_b` with stock and expect the unlock to remain.

**No Magisk was installed by this guide.** Patching `boot_b` or `init_boot_b`
is a separate operation with its own risk and confirmation.

**`veritymode=disabled` is separate.** On this tablet it comes from a modified
`vbmeta_b` used for the custom `super`/GApps image. The unlock carrier only
supplies the lock verdict. Flashing stock `vbmeta_b` changes verity behavior
independently.

**Keep the backups.** Without a stock `splloader`, stock `uboot_b`, and the
other original partitions, rollback is much harder.

---

## Appendix A — File map

| Purpose | Path |
|---|---|
| USB access helper | `work/w202ds/stage2b-run/fix-node.sh` |
| Enter download mode | `work/w202ds/enter-download-mode.sh` |
| Read/write partitions | `tools/spreadtrum_flash/spd_dump` |
| FDL1 / FDL2 | `work/w202ds/stage2b-run/fdl1-dl.bin`, `fdl2-dl.bin` |
| Patch the LK verdict | `analysis/patch-lk-verdict-stub.py` |
| Add the loader | `work/w202ds/persistent-magic/magic64` |
| Inject the B2 patch | `work/w202ds/persistent-magic/difftool` |
| Verify the carrier | `work/w202ds/persistent-magic-b500/verify-magic64-b500.py` |
| Flash + persistence test | `work/w202ds/stage2b-run/magic-b500-run.sh` |
| Recovery to tethered | `work/w202ds/stage2b-run/magic-b500-recover.sh` |
| Host unlock for recovery | `work/w202ds/stage2b-run/spl-unlock.bin` |
| Stock backup | `tools/spreadtrum_flash/backups/2026-10-17-full/` |

## Appendix B — Exact flash command

This is what `magic-b500-run.sh` runs. It is shown for transparency. Prefer
the script so the guards and readback gate run automatically.

From `work/w202ds/stage2b-run`:

```sh
../../../tools/spreadtrum_flash/spd_dump --wait 300 \
  exec_addr 0x65012f48 \
  fdl fdl1-dl.bin 0x65000800 \
  fdl fdl2-dl.bin 0xb4fffe00 exec \
  read_part uboot_log 0 0x1000000 magic-b500-out/uboot_log-pre.bin \
  w uboot_b ../persistent-magic-b500/uboot_b-magic64-b500.bin \
  w splloader ../../../tools/spreadtrum_flash/backups/2026-10-17-full/splloader.bin \
  read_part uboot_b 0 0x114018 magic-b500-out/uboot_b-readback.bin \
  read_part splloader 0 0x40000 magic-b500-out/splloader-readback.bin \
  reset
```

After the reset, **do not run `spl-unlock`**. The stock SPL loads the carrier
from flash.

## Appendix C — Why `0xB5000000`?

The stock SPL on this build loads the LK at `0xB5000000`. The function we need
to change sits `0x629B4` bytes into the LK, so the runtime address is:

```text
0xB5000000 + 0x629B4 = 0xB50629B4
```

The public `magic64` example uses `0x9F000000`, which is correct for some other
devices but wrong for this one. That was the only reason the first carrier
attempt stayed locked.

You do not need to understand the disassembly to follow this guide. Just use
`0xB5000000` in step 3.4 and check that the output says `0xB50629B4`.

## Appendix D — Source documents

- `docs/persistent-unlock-W202DS.md` — the full technical procedure and evidence.
- `analysis/r44-magic-b500-result-2026-10-21.md` — device test result.
- `analysis/r42-magic64-base-fix-2026-10-21.md` — load-address correction.
- `work/w202ds/persistent-magic-b500/verify-magic64-b500.log` — 28/28 offline checks.
- `work/w202ds/stage2b-run/logs/magic-b500-run.log` — full flash/readback/boot log.
- Public issue update:
  <https://github.com/TomKing062/CVE-2022-38694_unlock_bootloader/issues/337#issuecomment-6309209181>

---

## How this guide was checked

The offline build commands in Part 3 were re-run in a clean copy on
2026-10-26. They produced the same carrier hash
`c37d0a4c63ff5d1f9ce1782838435c2c0437224ec4731deb3e5a3242909174b0` and the
same **28/28** verifier result. The flash and recovery steps are taken from
the verified device run of 2026-10-21.

---

## Final checklist

- [ ] Fingerprint and slot `_b` checked.
- [ ] Battery at least 50%.
- [ ] `uboot_b` and `splloader` backed up and hashes checked.
- [ ] Carrier hash is `c37d0a4c…74b0`.
- [ ] Readback gate passed.
- [ ] `flash.locked=0`, `verifiedbootstate=orange`, `boot_completed=1`.
- [ ] Two reboots done with no host unlock; `boot_id` changed.
- [ ] Stock backup stored somewhere safe.
