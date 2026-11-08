#!/usr/bin/env python
"""IPv6 RA oracle diff: the firmware's Router Advertisement frame vs an
independent construction (p3-3050-ipv6ra).

Permanent assertion for the 2026-11-05 boot-crash fix: the controller floods
ICMPv6 Router Solicitations after associating (193 frames / ~15 s), nothing on
this IPv4-only AP answers, and the timeout escalates into the 3-round Crash
pattern (kPatterns[38-45]). The fix multicasts a Router Advertisement with
router_lifetime = 0 - "router present, NOT a default router" - so the client's
IPv6 init completes immediately.

Since p3-3050 the frame is built by proto.c build_ipv6_ra() - the ONE
constructor net_infra.c net_infra_ipv6_tick() transmits (shared-constructor
rule from the p3-2710 lesson: an inline replica in the test could not see the
firmware's own defect). This script:

  1. rebuilds + runs the host test exe via tests/run_host_tests.bat,
  2. rebuilds the expected 110 bytes HERE with an independent layout
     construction and an independent RFC 1071 checksum implementation
     (byte-wise accumulation, not the C carry-loop),
  3. byte-diffs the RA_A / RA_B vectors (two MACs: a Pico 2 W production
     shape, and one that stresses the U/L-bit flip + mixed EUI-64/SLLA bytes),
  4. re-verifies BOTH sides' checksums by the fold-to-zero property
     (sum over pseudo-header + message-with-checksum must fold to 0xffff),
  5. shape-asserts the load-bearing fields on the ACTUAL bytes (dst eth
     33:33:00:00:00:01, ethertype 0x86dd, type 134, router lifetime bytes
     [60..61] == 0, SLLA, PIO) so a vacuous pass is impossible.

The host test exe is (re)built and run via tests/run_host_tests.bat; last line
of output is "RESULT: OK" or "RESULT: FAIL"; exit status mirrors it.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAT = os.path.join(ROOT, "tests", "run_host_tests.bat")

FRAME_LEN = 110           # proto.h IPV6_RA_FRAME_LEN (asserted, not trusted)
PAYLOAD_LEN = 16 + 8 + 32  # RA body + SLLA + PIO

MAC_A = bytes((0x28, 0xCD, 0xC1, 0x02, 0x03, 0x04))  # Pico 2 W production shape
MAC_B = bytes((0x02, 0xFF, 0x00, 0xAB, 0xCD, 0xEF))  # U/L bit already set + mixed bytes


# ------------------------------------------------------------- checksum (RFC 1071)
def cksum(data):
    """One's-complement 16-bit sum. Independent of the C implementation."""
    total = 0
    for i in range(0, len(data) - 1, 2):
        total += (data[i] << 8) | data[i + 1]
    if len(data) & 1:
        total += data[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def cksum_pseudo(src, dst, plen, nh, msg):
    """ICMPv6 checksum over the IPv6 pseudo-header + message (RFC 4443)."""
    pseudo = bytes(src) + bytes(dst) + plen.to_bytes(4, "big") + bytes((0, 0, 0, nh))
    return cksum(pseudo + bytes(msg))


# ------------------------------------------------------------- expected frame
def expected_ra(mac):
    f = bytearray(FRAME_LEN)                       # zero-filled
    f[0:6] = bytes((0x33, 0x33, 0, 0, 0, 1))       # eth dst = ff02::1 all-nodes
    f[6:12] = mac
    f[12:14] = b"\x86\xdd"                         # ethertype IPv6
    f[14] = 0x60                                   # v6, TC 0, flow 0
    f[18:20] = PAYLOAD_LEN.to_bytes(2, "big")
    f[20] = 58                                     # next header ICMPv6
    f[21] = 255                                    # hop limit
    f[22:24] = b"\xfe\x80"                         # src fe80::/64
    f[30:38] = bytes(((mac[0] ^ 0x02), mac[1], mac[2], 0xFF, 0xFE,
                      mac[3], mac[4], mac[5]))     # modified EUI-64
    f[38] = 0xFF; f[39] = 0x02; f[53] = 0x01       # dst ff02::1
    f[54] = 134                                    # type = Router Advertisement
    f[70] = 1; f[71] = 1; f[72:78] = mac           # SLLA option
    f[78] = 3; f[79] = 4; f[80] = 64               # PIO /64, L=0 A=0
    f[90] = 0xFD                                   # prefix fd00:: (zero lifetimes)
    # everything else deliberately zero: code, cur hop limit, M/O flags,
    # ROUTER LIFETIME [60..61] = 0, reachable/retrans, PIO lifetimes
    ck = cksum_pseudo(f[22:38], f[38:54], PAYLOAD_LEN, 58, f[54:FRAME_LEN])
    f[56:58] = ck.to_bytes(2, "big")
    return bytes(f)


# ------------------------------------------------------------- harness (as check_rumble)
def run_host_tests():
    """Build + run the host test via the bat (vcvars64 + cl). Returns (rc, text)."""
    res = subprocess.run(["cmd", "/c", BAT], capture_output=True)
    text = res.stdout.decode("utf-8", "replace") + res.stderr.decode("utf-8", "replace")
    return res.returncode, text


def parse_vector(text, name):
    m = re.search(r"^%s\s*=\s*([0-9a-fA-F]*)\s*$" % re.escape(name), text, re.M)
    return bytes.fromhex(m.group(1)) if m else None


def report(name, actual, expected):
    if actual == expected:
        print("%s: OK (%d bytes)" % (name, len(actual)))
        return True
    print("%s: MISMATCH" % name)
    print("  actual  (%d B): %s" % (len(actual) or -1, (actual or b"").hex()))
    print("  expected(%d B): %s" % (len(expected), expected.hex()))
    i = 0
    if actual:
        while i < min(len(actual), len(expected)) and actual[i] == expected[i]:
            i += 1
        if i < min(len(actual), len(expected)):
            print("  first diff at byte %d (0-based): actual %02x, expected %02x"
                  % (i, actual[i], expected[i]))
        else:
            print("  common prefix matches; lengths differ (first extra byte index %d)" % i)
    return False


def shape_assertions(actual, mac):
    """Load-bearing fields read off the ACTUAL firmware bytes (a diff pass alone
    could be vacuous if both sides shared a layout bug)."""
    errs = []
    def want(off, val, what):
        got = actual[off] if actual and off < len(actual) else None
        if got != val:
            errs.append("  byte[%d] (%s): got %s, want %s"
                        % (off, what, "None" if got is None else "%02x" % got,
                           "%02x" % val if isinstance(val, int) else val.hex()))
    if not actual or len(actual) != FRAME_LEN:
        errs.append("  length: got %s, want %d" % (len(actual) if actual else "None", FRAME_LEN))
        return errs
    if actual[0:6] != bytes((0x33, 0x33, 0, 0, 0, 1)):
        errs.append("  eth dst: got %s, want 33:33:00:00:00:01" % actual[0:6].hex())
    if actual[6:12] != mac:
        errs.append("  eth src: got %s, want %s" % (actual[6:12].hex(), mac.hex()))
    if actual[12:14] != b"\x86\xdd":
        errs.append("  ethertype: got %s" % actual[12:14].hex())
    want(14, 0x60, "IPv6 version")
    if actual[18:20] != PAYLOAD_LEN.to_bytes(2, "big"):
        errs.append("  payload len: got %s, want %04x" % (actual[18:20].hex(), PAYLOAD_LEN))
    want(20, 58, "next header ICMPv6")
    want(21, 255, "hop limit")
    if actual[22:24] != b"\xfe\x80":
        errs.append("  src prefix: got %s" % actual[22:24].hex())
    if actual[60:62] != b"\x00\x00":
        errs.append("  ROUTER LIFETIME: got %s, MUST be 00 00" % actual[60:62].hex())
    want(54, 134, "ICMPv6 type RA")
    want(55, 0, "ICMPv6 code")
    want(59, 0, "M/O flags")
    want(70, 1, "SLLA type"); want(71, 1, "SLLA len")
    want(78, 3, "PIO type"); want(79, 4, "PIO len"); want(80, 64, "prefix len")
    if actual[81:89] != bytes(8):
        errs.append("  PIO lifetimes: got %s, must be all zero" % actual[81:89].hex())
    # fold property: pseudo-header + message WITH the checksum must fold to 0
    if cksum_pseudo(actual[22:38], actual[38:54], PAYLOAD_LEN, 58, actual[54:]) != 0:
        errs.append("  checksum fold property FAILED (sum-with-checksum != 0xffff)")
    return errs


def main():
    if not os.path.exists(BAT):
        print("RESULT: SKIP (needs tests/run_host_tests.bat + MSVC host build)")
        return 0
    rc, text = run_host_tests()
    if rc != 0:
        print("host test build/run failed (rc=%d)" % rc)
        print(text)
        print("RESULT: FAIL")
        return 1
    ok = True
    for name, mac in (("RA_A", MAC_A), ("RA_B", MAC_B)):
        actual = parse_vector(text, name)
        expected = expected_ra(mac)
        if actual is None:
            print("%s: MISSING from host test output" % name)
            ok = False
            continue
        ok = report(name, actual, expected) and ok
        errs = shape_assertions(actual, mac)
        for e in errs:
            print(e)
        if errs:
            ok = False
    print("RESULT: %s" % ("OK" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
