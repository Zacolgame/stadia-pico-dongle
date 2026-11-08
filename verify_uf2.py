#!/usr/bin/env python3
"""verify_uf2.py -- structural check of the produced UF2 + the XIP image inside it.

A Pico 2 W UF2 legitimately contains TWO block groups:
  * one block with ABSOLUTE_FAMILY_ID (0xe48bff57) at an absolute address
    (0x10ffff00) - the boot/AB metadata block emitted by the SDK;
  * N blocks with RP2350_ARM_S_FAMILY_ID (0xe48bff59) forming the XIP image.
Treating them as one sequence (or rejecting the absolute block) is a false alarm.

Catches: bad magics, bad block numbering, wrong MCU family, payload != .bin,
broken ARM vector table.

Usage:
    python verify_uf2.py build/stadia_one.uf2 build/stadia_one.bin
"""

import os
import struct
import sys

MAGIC0, MAGIC1, MAGIC_END = 0x0A324655, 0x9E5D5157, 0x0AB16F30

FAMILY = {
    0xE48BFF56: "RP2040",
    0xE48BFF57: "ABSOLUTE (boot metadata block)",
    0xE48BFF58: "DATA",
    0xE48BFF59: "RP2350 ARM-S",
    0xE48BFF5A: "RP2350 RISC-V",
    0xE48BFF5B: "RP2350 ARM-NS",
}
TARGET_FAMILY = 0xE48BFF59          # what a pico2_w build must use for the image
XIP_BASE = 0x10000000


def main(uf2_path, bin_path):
    bad = 0
    with open(uf2_path, "rb") as f:
        data = f.read()
    if len(data) % 512:
        print("!! size %d is not a multiple of 512" % len(data))
        bad += 1
    nblocks = len(data) // 512

    groups = {}
    for i in range(nblocks):
        b = data[i * 512:(i + 1) * 512]
        m0, m1, flags, addr, size, bno, nblk, fam = struct.unpack_from("<8I", b, 0)
        mend = struct.unpack_from("<I", b, 508)[0]
        if m0 != MAGIC0 or m1 != MAGIC1 or mend != MAGIC_END:
            print("!! block %d: bad magic" % i)
            bad += 1
            continue
        if size > 476:
            print("!! block %d: payload %d > 476" % (i, size))
            bad += 1
            continue
        groups.setdefault((fam, nblk), []).append((bno, addr, b[32:32 + size]))

    print("blocks in file: %d   groups: %d" % (nblocks, len(groups)))
    image = {}
    for (fam, nblk), blocks in groups.items():
        name = FAMILY.get(fam, "UNKNOWN(0x%08x)" % fam)
        bn = sorted(b[0] for b in blocks)
        seq_ok = bn == list(range(len(blocks)))
        print("  group fam=0x%08x %-32s blocks=%-5d numBlocks=%-5d numbering=%s"
              % (fam, name, len(blocks), nblk, "ok" if seq_ok else "BROKEN"))
        if not seq_ok:
            bad += 1
        # The SDK writes ONE absolute-addressed boot-metadata block but stamps it with
        # numBlocks=2 (it pairs with the first image block). Verified against a known-good
        # official artifact (picow_access_point_poll.uf2): same shape. So only the image
        # group's numBlocks is load-bearing.
        if fam == TARGET_FAMILY and nblk != len(blocks):
            print("    !! numBlocks(%d) != blocks present(%d)" % (nblk, len(blocks)))
            bad += 1
        if fam == TARGET_FAMILY:
            for bno, addr, payload in blocks:
                image[addr] = payload
        elif fam not in FAMILY:
            bad += 1

    if TARGET_FAMILY not in [f for (f, _) in groups]:
        print("!! no RP2350 ARM-S (0x%08x) group: the bootloader would reject this UF2"
              % TARGET_FAMILY)
        bad += 1

    # rebuild the XIP image in address order
    buf = bytearray()
    expect = XIP_BASE
    for addr in sorted(image):
        if addr != expect:
            print("!! image gap: next addr 0x%08x, expected 0x%08x" % (addr, expect))
            bad += 1
        buf += image[addr]
        expect = addr + len(image[addr])

    with open(bin_path, "rb") as f:
        raw = f.read()
    # The last UF2 block is padded to 256 bytes, so the reassembled payload is longer
    # than the .bin. Compare the real length and require the tail to be pure padding.
    tail = bytes(buf[len(raw):])
    tail_ok = all(c in (0x00, 0xFF) for c in tail)
    if bytes(buf[:len(raw)]) == raw and tail_ok:
        print("image payload matches %s (%d bytes, %d padding bytes)"
              % (os.path.basename(bin_path), len(raw), len(tail)))
    else:
        print("!! payload != %s (uf2 %d vs bin %d, tail clean=%s)"
              % (os.path.basename(bin_path), len(buf), len(raw), tail_ok))
        bad += 1

    sp, rv = struct.unpack_from("<II", raw, 0)
    sp_ok = 0x20000000 <= sp <= 0x20090000
    rv_ok = XIP_BASE <= rv < 0x10400000
    print("vector[0] SP    = 0x%08x  in SRAM: %s" % (sp, sp_ok))
    print("vector[1] reset = 0x%08x  in XIP:  %s" % (rv, rv_ok))
    if not (sp_ok and rv_ok):
        bad += 1

    print()
    print("RESULT:", "OK" if bad == 0 else "%d PROBLEM(S)" % bad)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    sys.exit(main(sys.argv[1], sys.argv[2]))
