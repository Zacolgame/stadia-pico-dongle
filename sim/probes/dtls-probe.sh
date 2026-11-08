#!/system/bin/sh
# dtls-probe.sh -- T2: bare DTLS 1.2 ClientHello (no cookie) to the Pico media port.
# A live DTLS server answers HelloVerifyRequest (or a ServerHello flight).
# omelet: ECDHE-RSA AES128-GCM + use_srtp, matching stadia_tls_config.h.
PICO="${1:-192.168.137.1}"
PORT="${2:-40000}"
RAND='\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
# record(13): 16 fedd 0000 000000000000 005b | hs(12): 01 00004f 0000 000000 00004f
# body(79): fedd + rand32 + sid0 + cookie0 + cslen4 + C02B+C02F + comp + extlen(33) +
#   use_srtp(9) + elliptic_curves secp256r1(8) + ec_point_formats(6) +
#   signature_algorithms ecdsa/sha256+rsa/sha256(10).
# (sigalgs REQUIRED: RFC 5246 says no-ext means SHA1-only; our EC cert is
# SHA256, so without it the server has no usable signature scheme -> Alert 40.)
printf "\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x5b\x01\x00\x00\x4f\x00\x00\x00\x00\x00\x00\x00\x4f\xfe\xfd${RAND}\x00\x00\x00\x04\xc0\x2b\xc0\x2f\x01\x00\x00\x21\x00\x0e\x00\x05\x00\x02\x00\x01\x00\x00\x0a\x00\x04\x00\x02\x00\x17\x00\x0b\x00\x02\x01\x00\x00\x0d\x00\x06\x00\x04\x04\x03\x04\x01" \
  | timeout 8 nc -u -w 4 "$PICO" "$PORT" \
  | od -A x -t x1 > /data/local/tmp/simctrl/dtls.resp 2>&1
cat /data/local/tmp/simctrl/dtls.resp
# HelloVerifyRequest = handshake type 03; ServerHello flight starts with 16 ... 02
if grep -q '16 fe fd' /data/local/tmp/simctrl/dtls.resp && \
   grep -Eq ' 03 | 02 00' /data/local/tmp/simctrl/dtls.resp; then
  echo DTLS_ALIVE
  exit 0
fi
echo DTLS_FAIL
exit 1
