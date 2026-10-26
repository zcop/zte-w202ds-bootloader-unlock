#!/usr/bin/env python3
"""Offline verification of the corrected magic64 carrier (load base 0xB5000000).

Read-only.  Checks that the magic64 carrier keeps the stock BTHD payload
(and therefore the stock SPL's payload hash) intact, that its footer/cert
were relocated correctly, and that the one runtime patch entry is exactly the
B2^12 15-byte code change at the runtime address proven by the SPL load map.

Load-address basis: stock SPL at VA 0x6500AFAC sets the LK destination to
0xB5000000 and the header destination to 0xB4FFFE00.  The previous r37
carrier used 0x9F000000 from the generic magic64 documentation, so its patch
defined no B2^12 change at the running LK.  This carrier changes only that
patch target; the stock payload, header hash, cert, and shellcode are kept.
"""
from pathlib import Path
import hashlib
import struct
import sys

ROOT = Path(__file__).resolve().parent
STOCK = ROOT / "../../../tools/spreadtrum_flash/backups/2026-10-17-full/uboot_b.bin"
B2 = ROOT / "../persistent/uboot_b-unlock.bin"
TRIM = ROOT.parent / "persistent-magic/uboot_b-stock-trimmed.bin"
MAGIC = ROOT / "uboot_b-magic64-b500.bin"

LOAD_ADDR = 0xB5000000
PAYLOAD_SIZE = 0x113860
STOCK_FOOTER = 0x113A60
MAGIC_FOOTER = 0x113B60
MAGIC_JUMP = 0x200
MAGIC_SHELLCODE = 0x113A70
PATCH_DATA = 0x113AE0
CERT_SIZE = 0x458
STOCK_CERT = 0x113AC0
MAGIC_CERT = 0x113BC0
MAGIC_SIZE = 0x114018
TRIM_SIZE = 0x113F18
FOOTER_FMT = "<8sII10Q"
PASS = 0


def check(cond, message):
    global PASS
    if cond:
        PASS += 1
        print(f"PASS: {message}")
    else:
        print(f"FAIL: {message}")
        sys.exit(1)


def main():
    for path in (STOCK, B2, TRIM, MAGIC):
        if not path.exists():
            print(f"FAIL: missing {path}")
            return 1

    stock = STOCK.read_bytes()
    b2 = B2.read_bytes()
    trim = TRIM.read_bytes()
    magic = MAGIC.read_bytes()

    print(f"stock file: 0x{len(stock):X}")
    print(f"trim file:  0x{len(trim):X}")
    print(f"magic file: 0x{len(magic):X} ({len(magic)} bytes)")
    print(f"magic sha256: {hashlib.sha256(magic).hexdigest()}")

    check(len(trim) == TRIM_SIZE, "trimmed stock image is 0x113F18 (no 5 MB partition padding)")
    check(len(magic) == MAGIC_SIZE, "magic64 carrier is 0x114018")
    check(len(b2) == 0x500000, "B2 patched LK is a full 5 MB partition image")

    stock_payload = trim[0x200:0x200 + PAYLOAD_SIZE]
    magic_payload = magic[0x210:0x210 + PAYLOAD_SIZE]
    b2_payload = b2[0x200:0x200 + PAYLOAD_SIZE]

    payload_sha = hashlib.sha256(stock_payload).digest()
    check(stock_payload == magic_payload, "magic64 payload at 0x210 is byte-identical to stock payload")
    check(trim[8:40] == payload_sha, "stock header hash equals SHA-256 of stock payload")
    check(magic[8:40] == payload_sha, "magic64 header hash is unchanged stock payload hash")
    check(struct.unpack_from("<I", trim, 0x30)[0] == PAYLOAD_SIZE, "stock mImgSize == 0x113860")
    check(struct.unpack_from("<I", magic, 0x30)[0] == PAYLOAD_SIZE + 0x100, "magic64 mImgSize == stock + 0x100")

    ft = struct.unpack_from(FOOTER_FMT, trim, STOCK_FOOTER)
    fm = struct.unpack_from(FOOTER_FMT, magic, MAGIC_FOOTER)
    print(f"stock footer: {ft}")
    print(f"magic footer: {fm}")
    check(ft[0] == b"SIMGHDR\x00", "stock footer magic is SIMGHDR")
    check(fm[0] == b"SIMGHDR\x00", "magic64 footer magic is SIMGHDR")
    check(fm[3] == PAYLOAD_SIZE, "magic64 footer payload_size is unchanged 0x113860")
    check(fm[4] == 0x210, "magic64 footer payload_offset is 0x210")
    check(fm[5] == CERT_SIZE, "magic64 footer cert_size is 0x458")
    check(fm[6] == MAGIC_CERT, "magic64 footer cert_offset is 0x113BC0")
    check(magic[MAGIC_CERT:MAGIC_CERT + CERT_SIZE] == trim[STOCK_CERT:STOCK_CERT + CERT_SIZE],
          "magic64 cert bytes are byte-identical to stock")

    jump = magic[MAGIC_JUMP:MAGIC_JUMP + 4]
    check(jump == bytes.fromhex("1c4e0414"), "jump word at 0x200 is AArch64 B to the magic area")
    imm26 = int.from_bytes(jump, "little") & 0x03FFFFFF
    check(MAGIC_JUMP + imm26 * 4 == MAGIC_SHELLCODE, "AArch64 branch target is 0x113A70")

    check(magic[MAGIC_SHELLCODE:MAGIC_SHELLCODE + 0x70] != b"\x00" * 0x70,
          "AArch64 shellcode is present at 0x113A70")
    addr, word_count = struct.unpack_from("<II", magic, PATCH_DATA)
    data = magic[PATCH_DATA + 8:PATCH_DATA + 8 + word_count * 4]
    terminator = struct.unpack_from("<I", magic, PATCH_DATA + 8 + word_count * 4)[0]
    print(f"patch entry: addr=0x{addr:X} words={word_count} data={data.hex()}")
    check(addr == LOAD_ADDR + 0x629B4, "patch runtime address == 0xB5000000 + 0x629B4")
    check(word_count == 4, "patch entry is 4 words (16 bytes)")
    check(terminator == 0, "patch list terminator follows the entry")

    diff = [i for i, (a, b) in enumerate(zip(b2_payload, stock_payload)) if a != b]
    check(len(diff) == 15, "B2^12 differs from stock payload in exactly 15 bytes")
    check(diff[0] == 0x629B4 and diff[-1] == 0x629C3, "B2^12 diff spans payload+0x629B4..0x629C3")
    check(data == b2_payload[0x629B4:0x629B4 + word_count * 4],
          "patch data equals the B2^12 bytes at payload+0x629B4")
    check(magic[0x210 + 0x629B4:0x210 + 0x629C4] == stock_payload[0x629B4:0x629C4],
          "on-flash magic payload is still stock at the patched offset (runtime patch only)")
    check(b2[8:40] != magic[8:40], "B2 header hash differs (as expected; it is not used by magic64)")
    check(b2[0x62BB4:0x62BC4] == data, "B2 file bytes at 0x62BB4 equal the injected patch data")

    used = 8 + word_count * 4 + 4
    check(used <= 0x80, f"patch data uses {used} bytes of the 128-byte magic64 area")

    print(f"\nALL {PASS} CHECKS PASS")
    print("magic64 carrier: stock payload + stock hash + stock cert + one B2^12 runtime patch")
    print("load-address 0xB5000000 is fixed by the stock SPL load call")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
