#!/usr/bin/env python
"""Rumble oracle diff: the firmware's vibration series vs the stadiacast live spec.

Permanent assertion for the 2026-11-04 23:47 post-mortem: the controller ACKED our
feedback series (gameframe 201f = InputProtocolMessage{4:31}) but the motors never
moved, so the series envelope was fine and only the CONTENT could differ. Expected
bytes come from stadiacast's own send_vibration (game_session.py:551-595, the
construction the live e4 session used when the motor verifiably spun and the
controller acked series 1,2,3):

  InputProtocolMessage{7: input_message_series{
      1: session_id?,            <- echoed when the controller announced one (string!)
      2: sequence_number,        <- _feedback_seq: 0 pre-incremented => first series = 1
      3: base_timestamp_us,      <- int(time.time()*1e6): EPOCH microseconds
      4: messages[] = InputMessageSlim{
          4: relative_time_us = 0,
          10: input_feedback_message_v2{
              1: gamepad_vibration{1: id, 2: left_motor_speed, 3: right_motor_speed}}}}}

Since p3-2710 the vectors are produced by proto.c build_rumble_series() /
learn_series_session() / wh2_wrap() - the SAME functions rtc.c rumble_flush(),
on_game_input() and wh2_send() call - NOT by an inline replica. The replica was the
blind spot of the 2026-11-05 27 B start frame: the device's inline constructor
passed sizeof(pb_out_t) (12 on ARM32) instead of the buffer size, dropped the f10
content after its length prefix (`22 04 20 00 52 0c` - a 12 B promise with nothing
behind it), and the host replica with the correct sizeof stayed green.

Vectors (the ph() lines of tests/proto_host_test.c):
  R15_START      start frame: id=1, 49151/49151 (75% of MOTOR_MAX), seq=1
  R15_STOP       explicit 0/0 stop frame, seq=2 (proto2 presence: 10 00 18 00 emitted)
  R15_SID        session_id echo "sid-1234567890abcdef" (20 B > the old 16 B cap)
  R15_WH2_START  WireHeader2(0x66) + R15_START - the raw-framing wire form, EXACTLY
  R15_WH2_STOP   WireHeader2(0x66) + R15_STOP   39 B / 35 B (shape-asserted below)
  R16_REG_LEARN  learn_series_session() on the REAL captured ota.282115 registration
                 series (f2+f3+f4 only, no f1) -> EMPTY echo: `sid=0` on the device
                 is the live baseline, the reference omits the echo too
  R16_LEARNED_SID/R16_SID_CHAIN  learn -> echo chain on a synthetic f1-carrying
                 series -> must equal R15_SID byte for byte
  R16_MAX        worst-case occupancy (5 B varints + the full 64 B echo cap)
  R16_OVERFLOW   g_pb_overflow delta across all builds: any dropped write fails

base_timestamp_us is pinned to 1793597554953620 - the t_us of the live e4
registration (2026-11-02T05:32:34Z), i.e. the epoch-us domain the controller itself
runs. Any regression back to an uptime-domain base, a re-wrapped slim, a missing
session echo or a seq off-by-one shows up as a byte mismatch here.

The host test exe is (re)built and run via tests/run_host_tests.bat; last line of
output is "RESULT: OK" or "RESULT: FAIL"; exit status mirrors it.
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

BASE_TS_US = 1793597554953620  # live e4 registration t_us (epoch microseconds)
GAMEPAD_ID = 1                 # live session: rumble_sent id=1
LEVEL_75 = 49151               # 75% of MOTOR_MAX 65535, the live test level
SESSION_ID = "sid-1234567890abcdef"
MAX_SID = "sid-max-" + "x" * 56  # 64 B: the echo buffer's full occupancy
WIRE_ID = 0x66                 # game-session input channel


# ---------------------------------------------------------------- expected bytes
def expected_dynamic():
    """stadiacast's send_vibration for the pinned values (google.protobuf present)."""
    if STADIACAST_SRC:
        sys.path.insert(0, STADIACAST_SRC)
    from stadiacast.protos import Protos  # noqa: E402
    from stadiacast.rtc.wire import pack_wire_message  # noqa: E402

    p = Protos()

    def send_vibration(left, right, seq, gamepad_id, session_id=""):
        # verbatim construction of game_session.py GameSession.send_vibration
        msg = p.InputProtocolMessage()
        series = msg.input_message_series
        if session_id:
            series.session_id = session_id
        series.sequence_number = seq
        series.base_timestamp_us = BASE_TS_US
        slim = series.messages.add()
        slim.relative_time_us = 0
        vib = slim.input_feedback_message_v2.gamepad_vibration
        vib.id = gamepad_id
        vib.left_motor_speed, vib.right_motor_speed = left, right
        return msg.SerializeToString()

    start = send_vibration(LEVEL_75, LEVEL_75, 1, GAMEPAD_ID)
    stop = send_vibration(0, 0, 2, GAMEPAD_ID)
    sid = send_vibration(LEVEL_75, LEVEL_75, 3, GAMEPAD_ID, SESSION_ID)
    mx = send_vibration(0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, MAX_SID)
    return start, stop, sid, pack_wire_message(WIRE_ID, start), pack_wire_message(WIRE_ID, stop), mx


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
      input.proto: InputProtocolMessage.input_message_series=7;
                   InputMessageSeries.session_id=1 (string), .sequence_number=2,
                   .base_timestamp_us=3, .messages=4;
                   InputMessageSlim.relative_time_us=4,
                   .input_feedback_message_v2=10;
                   InputFeedbackMessage_V2.gamepad_vibration=1;
                   GamepadVibrationMessage_V2.id=1, .left_motor_speed=2,
                   .right_motor_speed=3
      wire.py:     WireHeader2 = 00 00 | id LE16 | total LE24 | 00
    """
    def series(seq, vib_body, sid=b""):
        body = _lfield(1, sid) if sid else b""
        body += _vfield(2, seq) + _vfield(3, BASE_TS_US) + _lfield(4, _vfield(4, 0) + _lfield(10, _lfield(1, vib_body)))
        return _lfield(7, body)

    def vib(id_, left, right):
        return _vfield(1, id_) + _vfield(2, left) + _vfield(3, right)

    start = series(1, vib(GAMEPAD_ID, LEVEL_75, LEVEL_75))
    stop = series(2, vib(GAMEPAD_ID, 0, 0))
    sid = series(3, vib(GAMEPAD_ID, LEVEL_75, LEVEL_75), SESSION_ID.encode())
    mx = series(0xFFFFFFFF, vib(0xFFFFFFFF, 0xFFFF, 0xFFFF), MAX_SID.encode())

    def frame(payload):
        total = 8 + len(payload)
        return (
            bytes((0, 0, WIRE_ID & 0xFF, (WIRE_ID >> 8) & 0xFF))
            + total.to_bytes(3, "little")
            + b"\x00"
            + payload
        )

    return start, stop, sid, frame(start), frame(stop), mx


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
        start, stop, sid, wh2_start, wh2_stop, mx = expected
        print("oracle source: stadiacast dynamic protobuf (google.protobuf %s)"
              % google.protobuf.__version__)
        try:
            m = expected_manual()
            if m == (start, stop, sid, wh2_start, wh2_stop, mx):
                print("INFO: manual fallback builder agrees with the dynamic oracle")
            else:
                print("WARN: manual fallback builder DISAGREES with the dynamic oracle")
        except Exception as e:  # noqa: BLE001 - informational cross-check only
            print("WARN: manual fallback cross-check failed: %r" % e)
    if not use_dynamic:
        start, stop, sid, wh2_start, wh2_stop, mx = expected_manual()
        print("oracle source: manual wire encoder (oracle not importable)")

    rc, text = run_host_tests()
    if rc != 0:
        print("run_host_tests.bat exit code %d; output tail:" % rc)
        tail = "\n".join(text.splitlines()[-15:])
        print(tail)
        print("RESULT: FAIL")
        return 1

    vectors = {
        "R15_START": (parse_vector(text, "R15_START"), start),
        "R15_STOP": (parse_vector(text, "R15_STOP"), stop),
        "R15_SID": (parse_vector(text, "R15_SID"), sid),
        "R15_WH2_START": (parse_vector(text, "R15_WH2_START"), wh2_start),
        "R15_WH2_STOP": (parse_vector(text, "R15_WH2_STOP"), wh2_stop),
        # the learning path: real ota.282115 registration (no f1) -> empty echo;
        # synthetic f1-carrying series -> learned and echoed == R15_SID
        "R16_REG_LEARN": (parse_vector(text, "R16_REG_LEARN"), b""),
        "R16_LEARNED_SID": (parse_vector(text, "R16_LEARNED_SID"), SESSION_ID.encode()),
        "R16_SID_CHAIN": (parse_vector(text, "R16_SID_CHAIN"), sid),
        "R16_MAX": (parse_vector(text, "R16_MAX"), mx),
        "R16_OVERFLOW": (parse_vector(text, "R16_OVERFLOW"), b"\x00"),
    }

    ok = True
    for name, (actual, expected) in vectors.items():
        if actual is None:
            print("%s: MISSING from host test output" % name)
            ok = False
        elif not report(name, actual, expected):
            ok = False

    # ---- shape assertions for the p3-2710 defect class --------------------------
    # The 2026-11-05 start frame left the device 27 B: `3a11 1001 18<ts> 2204 2000
    # 520c` - f10 (input_feedback_message_v2) declared 12 B and carried nothing,
    # because pbo_raw dropped the sub-message after writing its length prefix. The
    # start WIRE frame (WireHeader2 included) must be EXACTLY 39 B and contain the
    # COMPLETE vibration sub-message; the stop frame EXACTLY 35 B. These hold even
    # if a future edit changes both sides of the byte comparison by mistake.
    def shape(name, cond, detail):
        nonlocal ok
        if cond:
            print("%s: OK (%s)" % (name, detail))
        else:
            print("%s: FAIL (%s)" % (name, detail))
            ok = False

    a_start = vectors["R15_START"][0]
    a_stop = vectors["R15_STOP"][0]
    w_start = vectors["R15_WH2_START"][0]
    w_stop = vectors["R15_WH2_STOP"][0]
    # complete f10 block: tag(52) len(0c) fb{0a 0a vib{08 01 10 ffff 02 18 ffff 02}}
    # (49151 = 0xBFFF serializes as the 3-byte varint ff ff 02)
    vib_start = bytes.fromhex("520c0a0a080110ffff0218ffff02")
    vib_stop = bytes.fromhex("52080a06080110001800")
    if w_start is not None:
        le24 = w_start[4] | (w_start[5] << 8) | (w_start[6] << 16)
        shape("SHAPE_START_FRAME_39B",
              w_start[:4] == bytes((0, 0, 0x66, 0)) and le24 == 39 and len(w_start) == 39,
              "len=%d total=%d hdr=%s" % (len(w_start), le24, w_start[:4].hex()))
        shape("SHAPE_START_VIB_COMPLETE", vib_start in w_start,
              "f10{f1{f1=1,f2=f3=49151}} present" if vib_start in w_start
              else "vibration sub-message truncated/absent")
    if a_start is not None:
        shape("SHAPE_START_PAYLOAD_31B", len(a_start) == 31, "len=%d" % len(a_start))
    if w_stop is not None:
        le24s = w_stop[4] | (w_stop[5] << 8) | (w_stop[6] << 16)
        shape("SHAPE_STOP_FRAME_35B",
              w_stop[:4] == bytes((0, 0, 0x66, 0)) and le24s == 35 and len(w_stop) == 35,
              "len=%d total=%d hdr=%s" % (len(w_stop), le24s, w_stop[:4].hex()))
        shape("SHAPE_STOP_VIB_COMPLETE", vib_stop in w_stop,
              "f10{f1{f1=1,f2=f3=0}} present" if vib_stop in w_stop
              else "vibration sub-message truncated/absent")
    if a_stop is not None:
        shape("SHAPE_STOP_PAYLOAD_27B", len(a_stop) == 27, "len=%d" % len(a_stop))

    print("RESULT: " + ("OK" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
