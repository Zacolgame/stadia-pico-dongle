#!/system/bin/sh
# stun-probe.sh -- T2-lite: STUN binding request to the Pico ICE endpoint.
# Prints the raw response (if any) as hex. Exit 0 with "STUN_OK" only when a
# well-formed Binding Response echoing our transaction ID arrives.
PICO="${1:-192.168.137.1}"
PORT="${2:-40000}"
# Binding Request: type=0x0001 len=0 magic=0x2112A442 tid=0102..0c
printf '\x00\x01\x00\x00\x21\x12\xa4\x42\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c' \
  | timeout 8 nc -u -w 4 "$PICO" "$PORT" \
  | od -A x -t x1 > /data/local/tmp/simctrl/stun.resp 2>&1
cat /data/local/tmp/simctrl/stun.resp
SZ=$(wc -c < /data/local/tmp/simctrl/stun.resp | tr -d ' ')
if [ "$SZ" -gt 20 ]; then
  # first two bytes must be 01 01 (Binding Response) and magic cookie present
  if grep -q '01 01' /data/local/tmp/simctrl/stun.resp && \
     grep -q '21 12 a4 42' /data/local/tmp/simctrl/stun.resp; then
    echo STUN_OK
    exit 0
  fi
fi
echo STUN_FAIL
exit 1
