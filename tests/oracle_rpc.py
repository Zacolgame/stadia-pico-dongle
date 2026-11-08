#!/usr/bin/env python
"""Oracle diff: the firmware's display-link RPC builders vs the stadiacast live spec.

Expected bytes come from stadiacast itself (the reference implementation verified
against real controllers). Preferred path: load its dynamic descriptor pool via
stadiacast.protos.Protos and serialize with google.protobuf, then frame with
stadiacast.rtc.wire.pack_wire_message. Fallback when google.protobuf is not
importable: a hand-rolled wire encoder using only the field numbers documented in
stadiacast's schemas/*.proto (never the firmware source).

Vectors checked (names are the ph() lines of tests/proto_host_test.c):
  RPC_GCSR       RpcMessage{1: RpcRequest{1: ticket=1,
                                 2: DisplayToController{2: GetControllerStateRequest{2: false}}}}
  RPC_STARTGAME  RpcMessage{1: RpcRequest{1: ticket=2,
                                 2: DisplayToController{8: StringAndInt{1: "pico", 2: 1}}}}
  WH2_GCSR       WireHeader2(id 0x75) + RPC_GCSR: 8-byte header + payload
  WH2_STARTGAME  WireHeader2(id 0x75) + RPC_STARTGAME: 8-byte header + payload
  TIME_RESP      GetCurrentTimeResponse{1: echo=0x1122334455667788,
                                 2: display_us=0x99AABBCCDDEEFF00}
                 (build_current_time_response; oracle side builds the same
                 message via stadiacast's DisplayToController.current_time,
                 field 21 = config.h DTC_TIME_RESP)
  RPC_HEARTBEAT_RESP  the wire body of rtc.c:519 rpc_respond_display(ticket=77,
                 ST_OK, NULL, 0) = build_rpc_response(77, 0, NULL, 0). Oracle
                 side is the reference keepalive reply: controller.py
                 _answer_request -> p.rpc_response(ticket, code=0, message="")
                 which serializes ticket, code=0 AND error_message="" (proto2
                 optional presence). A firmware that omits code=0/payload is
                 semantically OK per the schema ("absent = OK") but byte-differs
                 from the reference; the diff is reported, never patched here.

The host test exe is (re)built and run via tests/run_host_tests.bat, whose stdout
carries the vector lines; each is compared byte for byte. Last line of output is
"RESULT: OK" or "RESULT: FAIL"; exit status mirrors it.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BAT = os.path.join(ROOT, "tests", "run_host_tests.bat")
# Optional checkout of the stadiacast reference for the dynamic oracle
# (pip-installed `stadiacast` works too if it still has rtc.wire).
STADIACAST_SRC = os.environ.get("STADIACAST_SRC", "")

TICKET_GCSR = 1        # first outbound request of a boot: _rpc_ticket=0, send_rpc
TICKET_STARTGAME = 2   # pre-increments (controller.py:671-673) => 1, 2, 3, ...
                       # (D5 alignment: firmware cloud_next_ticket() matches since p3-0355)
STARTGAME_KEY = "pico"
WIRE_ID = 0x75  # display -> controller RPC channel
TICKET_HEARTBEAT = 77
TIME_ECHO_US = 0x1122334455667788
TIME_DISPLAY_US = 0x99AABBCCDDEEFF00  # sign bit set: int64 reads it negative


def _as_int64(v):
    """The value a protobuf int64 field holds for the 64-bit pattern v."""
    return v - (1 << 64) if v >= (1 << 63) else v


# ---------------------------------------------------------------- expected bytes
def expected_dynamic():
    """Expected bytes from stadiacast's own schemas (google.protobuf present)."""
    if STADIACAST_SRC:
        sys.path.insert(0, STADIACAST_SRC)
    from stadiacast.protos import Protos  # noqa: E402
    from stadiacast.rtc.wire import pack_wire_message  # noqa: E402

    p = Protos()
    gcsr_dtc = p.DisplayToController()
    # proto2 optional: assigning False still sets presence, so the field IS
    # serialized (as a 0 varint) -- the firmware sends the explicit false too.
    gcsr_dtc.get_controller_state.display_supports_send_log_report = False
    gcsr = p.rpc_request(TICKET_GCSR, gcsr_dtc)

    sg_dtc = p.DisplayToController()
    sg_dtc.start_game.value = STARTGAME_KEY
    sg_dtc.start_game.number = 1
    sg = p.rpc_request(TICKET_STARTGAME, sg_dtc)

    # keepalive reply exactly as the reference sends it (controller.py
    # _answer_request, variant "keepalive" -> send_rpc("response", None)):
    # p.rpc_response(ticket) sets ticket, code=0 and error_message="" and
    # proto2 optional presence serializes all three.
    hb = p.rpc_response(TICKET_HEARTBEAT)

    # GetCurrentTimeResponse via the reference's own construction path
    # (controller.py: reply.current_time.controller_time_us = echo, .display_time_us = now).
    reply = p.DisplayToController()
    reply.current_time.controller_time_us = _as_int64(TIME_ECHO_US)
    reply.current_time.display_time_us = _as_int64(TIME_DISPLAY_US)
    time_resp = bytes(reply.current_time.SerializeToString())

    wh2 = pack_wire_message(WIRE_ID, gcsr)
    wh2_sg = pack_wire_message(WIRE_ID, sg)
    return gcsr, sg, wh2, hb, time_resp, wh2_sg


def _varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _vfield(field, v):
    return _varint((field << 3) | 0) + _varint(v)


def _lfield(field, payload):
    return _varint((field << 3) | 2) + _varint(len(payload)) + payload


def expected_manual():
    """Fallback expected bytes, hand-built ONLY from the .proto field numbers:
      rpc_message.proto:       RpcMessage.request=1, .response=2; RpcRequest.ticket=1,
                               RpcRequest.payload=2; RpcResponse.ticket=1, .code=2,
                               .error_message=3, .payload=4
      controller_message.proto: DisplayToController.get_controller_state=2,
                               DisplayToController.start_game=8,
                               DisplayToController.current_time=21,
                               GetControllerStateRequest.display_supports_
                                 send_log_report=2 (bool),
                               StringAndInt.value=1 (string), .number=2 (int32),
                               GetCurrentTimeResponse.controller_time_us=1 (int64),
                               .display_time_us=2 (int64)
      wire.py docstring:       WireHeader2 = 00 00 | id LE16 | total LE24 | 00
    """
    gcsr_req = _vfield(1, TICKET_GCSR) + _lfield(2, _lfield(2, _vfield(2, 0)))
    gcsr = _lfield(1, gcsr_req)
    sg_req = (
        _vfield(1, TICKET_STARTGAME)
        + _lfield(2, _lfield(8, _lfield(1, STARTGAME_KEY.encode("ascii")) + _vfield(2, 1)))
    )
    sg = _lfield(1, sg_req)
    # reference keepalive reply shape: ticket + code=0 + error_message="" (all
    # present; proto2 optional). Intentionally NOT the firmware's minimal shape.
    hb = _lfield(2, _vfield(1, TICKET_HEARTBEAT) + _vfield(2, 0) + _lfield(3, b""))
    # int64 varints are the two's-complement 64-bit pattern: _varint over the
    # unsigned value reproduces it (10 bytes when the sign bit is set).
    time_resp = _vfield(1, TIME_ECHO_US) + _vfield(2, TIME_DISPLAY_US)

    def frame(payload):
        total = 8 + len(payload)
        return (
            bytes((0, 0, WIRE_ID & 0xFF, (WIRE_ID >> 8) & 0xFF))
            + total.to_bytes(3, "little")
            + b"\x00"
            + payload
        )

    return gcsr, sg, frame(gcsr), hb, time_resp, frame(sg)


def protobuf_available():
    try:
        import google.protobuf  # noqa: F401
    except ImportError:
        return False
    return True


# ---------------------------------------------------------------- firmware bytes
def run_host_tests():
    """Build + run the host test via the bat (vcvars64 + cl). Returns (rc, text)."""
    res = subprocess.run(["cmd", "/c", BAT], capture_output=True)
    text = res.stdout.decode("utf-8", "replace") + res.stderr.decode("utf-8", "replace")
    return res.returncode, text


def parse_vector(text, name):
    m = re.search(r"^%s\s*=\s*([0-9a-fA-F]*)\s*$" % re.escape(name), text, re.M)
    return bytes.fromhex(m.group(1)) if m else None


# ---------------------------------------------------------------- reporting
def report(name, actual, expected):
    if actual == expected:
        print("%s: OK (%d bytes)" % (name, len(actual)))
        return True
    print("%s: MISMATCH" % name)
    print("  actual  (%d B): %s" % (len(actual), actual.hex()))
    print("  expected(%d B): %s" % (len(expected), expected.hex()))
    i = 0
    while i < min(len(actual), len(expected)) and actual[i] == expected[i]:
        i += 1
    if i < min(len(actual), len(expected)):
        print("  first diff at byte %d (0-based): actual %02x, expected %02x"
              % (i, actual[i], expected[i]))
    else:
        print("  common prefix matches; lengths differ (first extra byte index %d)" % i)
    return False


def main():
    if not os.path.exists(BAT):
        print("RESULT: SKIP (needs tests/run_host_tests.bat + MSVC host build)")
        return 0
    use_dynamic = protobuf_available()
    expected = None
    if use_dynamic:
        try:
            expected = expected_dynamic()
        except ImportError as e:
            print("oracle unavailable (%s); using manual wire encoder" % e)
            use_dynamic = False
    if use_dynamic:
        import google.protobuf
        gcsr, sg, wh2, hb, time_resp, wh2_sg = expected
        print("oracle source: stadiacast dynamic protobuf (google.protobuf %s)"
              % google.protobuf.__version__)
        try:
            m = expected_manual()
            if m == (gcsr, sg, wh2, hb, time_resp, wh2_sg):
                print("INFO: manual fallback builder agrees with the dynamic oracle")
            else:
                print("WARN: manual fallback builder DISAGREES with the dynamic oracle")
        except Exception as e:  # noqa: BLE001 - informational cross-check only
            print("WARN: manual fallback cross-check failed: %r" % e)
    else:
        gcsr, sg, wh2, hb, time_resp, wh2_sg = expected_manual()
        print("oracle source: manual wire encoder (oracle not importable)")

    rc, text = run_host_tests()
    if rc != 0:
        print("run_host_tests.bat exit code %d; output tail:" % rc)
        tail = "\n".join(text.splitlines()[-15:])
        print(tail)
        print("RESULT: FAIL")
        return 1

    vectors = {
        "RPC_GCSR": (parse_vector(text, "RPC_GCSR"), gcsr),
        "RPC_STARTGAME": (parse_vector(text, "RPC_STARTGAME"), sg),
        "WH2_GCSR": (parse_vector(text, "WH2_GCSR"), wh2),
        "WH2_STARTGAME": (parse_vector(text, "WH2_STARTGAME"), wh2_sg),
        "TIME_RESP": (parse_vector(text, "TIME_RESP"), time_resp),
        "RPC_HEARTBEAT_RESP": (parse_vector(text, "RPC_HEARTBEAT_RESP"), hb),
    }

    ok = True
    for name, (actual, expected) in vectors.items():
        if actual is None:
            print("%s: MISSING from host test output" % name)
            ok = False
        elif not report(name, actual, expected):
            ok = False

    print("RESULT: " + ("OK" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
