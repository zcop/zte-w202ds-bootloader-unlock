#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patch-lk-verdict-stub.py — build the r28 "verdict stub" LK image (W202DS, ums9620).

Input : stock `uboot_b.bin` (5 MiB, DHTB container, slot B)
Output: same image with `get_lock_status()` forced to return 1

The edit is 16 bytes at file offset 0x62bb4 (VA 0xb50629b4, base 0xb4fffe00):

    stock: fd 7b be a9  80 3b 80 d2  fd 03 00 91  f3 53 01 a9
           stp x29,x30 / mov x0,#0x1dc / mov x29,sp / stp x19,x20
    new:   c1 05 00 f0  20 00 80 52  20 c8 08 b9  c0 03 5f d6
           adrp x1,cache / mov w0,#1 / str w0,[x1,#0x8c8] / ret

All four new words are instructions that already exist inside the same function
(0xb5062a14/18/20/38), so no hand-assembly is involved.  The stub uses no stack
and clobbers only x0/x1; the original prologue never runs.

The DHTB header hash (bytes 0x08..0x28) is the SHA-256 of the payload
[0x200 : 0x113a60] and is recomputed, so the image stays header-consistent.

Offline only: reads the stock image, writes a new file, never touches a device.

Usage:
    python3 analysis/patch-lk-verdict-stub.py \
        -i tools/spreadtrum_flash/backups/2026-10-17-full/uboot_b.bin \
        -o /tmp/uboot_b-unlock.bin
"""
import argparse
import hashlib
import sys

SITE = 0x62BB4
STOCK = bytes.fromhex("fd7bbea9803b80d2fd030091f35301a9")
PATCH = bytes.fromhex("c10500f02000805220c808b9c0035fd6")
PAYLOAD = (0x200, 0x113A60)          # DHTB payload range for the header hash
EXPECT_SHA = "d221042556e13fe52d6093036c14ab8bac4fe9de40ba89cc4da516de9efac37e"
SIZE = 5 * 1024 * 1024


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-i", "--input", required=True, help="stock uboot_b.bin")
    ap.add_argument("-o", "--output", required=True, help="patched image to write")
    a = ap.parse_args()

    d = bytearray(open(a.input, "rb").read())
    if len(d) != SIZE:
        print(f"error: {a.input} is {len(d)} B, expected {SIZE}", file=sys.stderr)
        return 2
    if d[:4] != b"DHTB":
        print("error: not a DHTB image", file=sys.stderr)
        return 2
    if d[SITE:SITE + 16] != STOCK:
        print(f"error: stock bytes at 0x{SITE:x} differ:\n  {bytes(d[SITE:SITE+16]).hex(' ')}",
              file=sys.stderr)
        return 3

    d[SITE:SITE + 16] = PATCH
    d[0x08:0x28] = hashlib.sha256(bytes(d[PAYLOAD[0]:PAYLOAD[1]])).digest()
    open(a.output, "wb").write(d)

    diff = sum(1 for x, y in zip(open(a.input, "rb").read(), d) if x != y)
    sha = hashlib.sha256(d).hexdigest()
    print(f"site      0x{SITE:x} (VA 0xb50629b4) 16 B")
    print(f"diff      {diff} bytes vs stock (32 header hash + 15 stub bytes)")
    print(f"output    {a.output}")
    print(f"sha256    {sha}")
    if sha != EXPECT_SHA:
        print(f"note: expected {EXPECT_SHA} for the W202DS slot-B image", file=sys.stderr)
        return 1
    print("match     expected W202DS slot-B image")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
