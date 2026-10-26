# r42 — the r37/r40 magic64 carrier used the wrong LK load address

Date: 2026-10-21.  Stage: 3 pre-flight (offline).  Device: not contacted, no
write, no reset.  This record corrects r38 hypothesis 2 and the r40 conclusion
that "magic64-only is insufficient".  The earlier carrier was never testing the
B2¹² patch at the running LK address.

## 1. The error

r37 built the carrier with `difftool` and `LOAD_ADDR = 0x9F000000`.  The r37
verifier itself recorded that address as an assumption:

```
work/w202ds/persistent-magic/verify-magic64.py:25: LOAD_ADDR = 0x9F000000
work/w202ds/persistent-magic/verify-magic64.log: "load-address 0x9F000000 remains the device-test assumption"
```

The resulting patch entry was:

```
addr = 0x9F0629B4
data = c1 05 00 f0 20 00 80 52 20 c8 08 b9 c0 03 5f d6
```

`0x9F0629B4` is the payload offset `0x629B4` plus `0x9F000000`.  It is the
generic magic64 example address, not this tablet's LK address.  `[verified:
static]`

## 2. The actual LK address

The stock SPL's LK load call is at VA `0x6500AFAC`:

```
0x6500AFA8  mov   w1, #0x300000          ; maximum size
0x6500AFAC  mov   x2, #0xB5000000        ; LK payload destination
0x6500AFB0  movk  x3, #0xB4FF, lsl #16   ; header destination 0xB4FFFE00
0x6500AFB4  bl    #0x6500AC4C            ; load uboot partition
```

The same load-map conclusion appears at `0x6500B0C0` (`mov x20,
#0xB5000000`) and is consistent with the LK image's link base
(`file 0x200 -> 0xB5000000`).  `[verified: static]`

The loader function itself (`0x6500AC4C`) confirms the copy source and length:

```
read 0x200 bytes from partition offset 0      -> header at 0xB4FFFE00
w22 = *(u32 *)(header + 0x30) + 0x4E8          ; mImgSize + footer/cert span
read w22 bytes from partition offset 0x200     -> payload at 0xB5000000
```

So the stock SPL copies the **magic area beginning at file 0x200** into the LK
payload.  The jump at 0x200 is executed; this is not a carrier that the loader
skips in favour of the footer's `payload_offset`.  The magic64 shellcode is in
the copied range and the old test did run it.  `[verified: static]`

The device's own LK log independently shows LK data/BSS pointers in the
`0xB5...` range, including:

```
arch_context_switch: old 0xb513d230 (idle 0...), new 0xb56c9010 (bootstrap2...)
usb_add_config: adding config #1 .../0xb50ff8a0
adding 'gser'/0xb56daf40
```

These are running LK addresses, not `0x9F...`.  `[verified: log]`

Therefore the B2¹² patch target is:

```
0xB5000000 + 0x629B4 = 0xB50629B4
```

The old target was too high by `0x16000000`.  It could not modify
`get_lock_status` at the running address.  The old carrier's shellcode still
copied the stock payload and returned to the stock entry, so the LK booted,
reached `jump to kernel`, and stayed `green` / `flash.locked=1` — exactly the
r38/r40 observation.  `[verified: static + log]`

Consequences:

- r38 hypothesis 2 ("runtime patch target/base") is confirmed, not merely
  suspected.
- r38's statement "the exact kernel failure cause is unproven" is superseded:
  the LK never applied the B2 patch, so the kernel was booted with the stock
  locked/enforcing bootargs.
- r40's conclusion that a magic64 carrier plus a TOS donor still stays locked
  is a test of an inert carrier.  It does **not** show that a corrected
  magic64 carrier cannot persist.  The TOS donor was not the variable under
  test.

## 3. Corrected carrier

Built with the same `difftool`, same B2¹² input, and the SPL-proven base:

```
work/w202ds/persistent-magic-b500/uboot_b-magic64-b500.bin
size   = 1,130,520 (0x114018)
sha256 = c37d0a4c63ff5d1f9ce1782838435c2c0437224ec4731deb3e5a3242909174b0
```

It differs from the failed r37 carrier by exactly **one byte**:

```
file offset 0x113AE3: 0x9F -> 0xB5
```

That byte is the high byte of the patch entry's little-endian address.  The
patch entry is now:

```
addr = 0xB50629B4
data = c1 05 00 f0 20 00 80 52 20 c8 08 b9 c0 03 5f d6
```

The stock payload at `0x210`, the stock header hash, the stock footer, and the
stock certificate are unchanged.  The magic64 shellcode and the one branch at
`0x200` are unchanged.  `[verified: static]`

Offline verifier:

```
work/w202ds/persistent-magic-b500/verify-magic64-b500.py
work/w202ds/persistent-magic-b500/verify-magic64-b500.log
```

Result: **ALL 28 CHECKS PASS**, including:

- magic64 payload at `0x210` is byte-identical to the stock payload;
- header hash equals SHA-256 of the stock payload;
- footer payload offset `0x210`, payload size `0x113860`, cert offset
  `0x113BC0`, cert bytes byte-identical to stock;
- jump at `0x200` targets the shellcode at `0x113A70`;
- patch entry address is `0xB50629B4`;
- patch data equals the B2¹² 15-byte diff;
- on-flash payload remains stock at the patched offset.

## 4. What this does and does not establish

Established:

- The old magic64 test did not apply the B2¹² patch.  Its locked/green result
  is not evidence against magic64.
- The corrected carrier keeps every byte the stock SPL verifies and changes
  only the runtime patch target.
- The stock SPL already accepted the magic64 layout in the r38 test: the LK
  executed and reached `jump to kernel`.  The corrected carrier changes only
  one byte after the verified payload; the SPL acceptance path is unchanged.

Still unproven:

- Whether the corrected shellcode writes `0xB50629B4` before the LK calls
  `get_lock_status`.
- Whether the stock SPL's cache/coherency handling lets the self-modified code
  take effect (the shellcode uses `IC IALLUIS; ISB` after the copy and patch).
- Whether the patched LK produces `flash.locked=0`, `verifiedbootstate=orange`,
  and `veritymode=disabled` on a cold boot with the stock SPL.
- Whether the second cold boot persists.

These require one device test.  No device write has been made for this
candidate.

## 5. Test design (not executed)

Preconditions:

- `sudo ./fix-node.sh 3600` live in another terminal;
- tablet reachable by adb or key-combo BROM;
- battery at least 50%;
- explicit user GO for this specific one-byte-corrected carrier.

Armed scripts, all under `work/w202ds/stage2b-run/`:

| file | role |
|---|---|
| `magic-b500-run.sh` | guarded write, readback, reset, first/second boot, post-read |
| `magic-b500-cmd.txt` | write carrier + stock SPL, read both back, reset |
| `magic-b500-postread-cmd.txt` | read-only post-success `uboot_log` capture |
| `magic-b500-recover.sh` | BROM recovery: read post log, restore B2 LK, erase SPL, host unlock |
| `magic-b500-recover-cmd.txt` | restore session command file |

The runner writes only:

```
uboot_b  <- ../persistent-magic-b500/uboot_b-magic64-b500.bin  (0x114018)
splloader <- stock splloader.bin                                 (0x40000)
```

It writes no `super`, `vbmeta`, `userdata`, TOS, or miscdata bytes.
The recovery path restores `uboot_b-unlock.bin` (`d2210425…`), erases
`splloader`, and runs the normal `b2p14b-cmd.txt` host unlock.  It reads the
post-failure log into the new `magic-b500-out/` directory, so the older
`preverify-out/` and `tos-out/` evidence is preserved.

Success criteria:

1. readbacks exactly match the carrier and stock SPL;
2. no host `spl-unlock` after reset;
3. adb reaches Android with:
   - `ro.boot.flash.locked=0`
   - `ro.boot.verifiedbootstate=orange`
   - `ro.boot.veritymode=disabled`
   - `sys.boot_completed=1`
4. a second cold boot reaches the same state;
5. post-run `uboot_log` shows `LOCK FLAG IS : UNLOCK` / `SKIP VERIFY` and
   `arch_context_switch` pointers at `0xB5...`.

Failure handling:

- no adb after 180 s -> hold POWER+VOL_DOWN 7–10 s, run
  `./magic-b500-recover.sh` with the watcher live;
- readback mismatch -> do not boot; run the same recovery;
- the test is not a repeat of the failed carrier: the single changed byte is
  the address the old carrier could not reach.

## 6. Status

`[verified: static]` wrong target, one-byte correction, 28/28 offline checks.
`[verified: log]` old LK ran at `0xB5...`; old carrier could not have patched
`0xB50629B4`.
`[unproven]` corrected carrier on the device.

No write, reset, or reboot was performed while producing this record.
