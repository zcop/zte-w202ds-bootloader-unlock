# B500 carrier and verifier

`uboot_b-magic64-b500.bin` is the final verified carrier:

```text
size    1,130,520 bytes (0x114018)
sha256  c37d0a4c63ff5d1f9ce1782838435c2c0437224ec4731deb3e5a3242909174b0
```

It contains:

- the unchanged stock LK payload and stock payload hash,
- the stock `SIMGHDR` footer and certificate,
- the magic64 post-verification loader,
- one runtime patch at `0xB50629B4`, injected with load address `0xB5000000`.

## Verify offline

Run from anywhere:

```sh
python3 verify-magic64-b500.py
```

Expected final line:

```text
ALL 28 CHECKS PASS
```

The verifier is read-only. It checks the stock image, the B2 reference LK, the
trimmed stock LK, and the final carrier. It does **not** touch the tablet.

## Evidence

- `verify-magic64-b500.log` — the 28-check run.
- `difftool-b500.log` — the patch summary from `difftool`.
- `../../analysis/r44-magic-b500-result-2026-10-21.md` — the device test.

## Important

This carrier is for the exact W202DS build and slot B described in the guide.
The runtime patch address comes from the stock SPL's load call, not from a
generic magic64 example. Do not reuse it on another build.
