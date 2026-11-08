#!/system/bin/sh
# t1.sh -- runs ON the phone (adb shell sh). T1: the controller's HTTPS boot
# sequence against the Pico's fake cloud at 192.168.137.1:443, then 3 parallel
# registrations on separate TLS connections (the firmware has NSLOTS=3).
# Writes <out>/<name>.resp and <out>/t1.log (one line per request:
#   name status bytes time_total time_appconnect ssl_verify_result).
#
# The phone leaves a no-internet AP on its own after ~25 s (verified: it
# disassociates and rejoins the home SSID). pin() re-joins before every step and
# every failed request is retried once after a re-pin, so the gate measures the
# Pico, not Android's network selection.
D=/data/local/tmp/simctrl
OUT=$D/out
HOST=cloudcast-pa.googleapis.com
BASE=https://$HOST
RES="--resolve $HOST:443:192.168.137.1"
KEY=AIzaSyDH7yIEC0dB7tA7dORjxTxURMTAPh9ydEk
AP=StadiaPhone
PIN_RETRIES=0
rm -rf "$OUT"
mkdir -p "$OUT"

on_ap() {
  cmd wifi status 2>/dev/null | grep -q 'connected to "StadiaPhone"'
}

pin() {
  on_ap && ip -4 addr show wlan0 2>/dev/null | grep -q 'inet 192.168.137\.' \
    && ip route 2>/dev/null | grep -q '192.168.137.0/24' && return 0
  i=0
  while [ $i -lt 8 ]; do
    cmd wifi connect-network $AP wpa2 TestPass1234a >/dev/null 2>&1
    sleep 2
    PIN_RETRIES=$((PIN_RETRIES+1))
    on_ap && ip -4 addr show wlan0 2>/dev/null | grep -q 'inet 192.168.137\.' \
      && ip route 2>/dev/null | grep -q '192.168.137.0/24' && return 0
    i=$((i+1))
  done
  return 1
}

curl_once() { # name path bodyfile
  curl -sS -k --http1.1 --connect-timeout 30 --max-time 60 $RES \
    -o "$OUT/$1.resp" \
    -w "%{http_code} %{size_download} %{time_total} %{time_appconnect} %{ssl_verify_result}" \
    -X POST -H "Host: $HOST" -H "Content-Type: application/x-protobuf" \
    --data-binary "@$3" "$BASE$2" 2>"$OUT/$1.err" > "$OUT/$1.stat"
  echo "$1 $(cat "$OUT/$1.stat")" >> "$OUT/t1.log"
}

curl_post() { # name path bodyfile -- up to 5 attempts, each preceded by a pin+settle
  n=0
  while [ $n -lt 3 ]; do
    pin
    sleep 1
    curl_once "$@"
    code=$(cut -d' ' -f1 "$OUT/$1.stat")
    [ "$code" != "000" ] && [ "$code" != "0" ] && return 0
    n=$((n+1))
    echo "$1 retry$n ssid=$(cmd wifi status 2>/dev/null | grep -o 'connected to "[^"]*"' | head -1)" >> "$OUT/t1.log"
    sleep 2
  done
}

# Keep the phone on the AP: Android hops back to the home SSID ~25 s after joining
# a network without internet. The loop re-pins within ~2 s, which is enough for the
# retry ladder above to make progress.
stay_on_ap() {
  while [ ! -f "$OUT/stop_stay" ]; do
    if ! on_ap; then
      cmd wifi connect-network $AP wpa2 TestPass1234a >/dev/null 2>&1
      STAY_REPINS=$((STAY_REPINS+1))
    fi
    sleep 2
  done
}

pin
sleep 2
STAY_REPINS=0
stay_on_ap &
STAY_PID=$!
{
  echo "ip: $(ip -4 addr show wlan0 2>/dev/null | grep -o 'inet [0-9.]*')"
  echo "route: $(ip route 2>/dev/null | grep 192.168.137)"
  echo "started: $(date)"
} > "$OUT/env.txt"

# --- the boot sequence, in the order the real controller sends it ---
curl_post log_batch  /log/batch                                              "$D/log_batch.bin"
curl_post fwcheck    "/v1:FirmwareVersionCheck?key=$KEY"                     "$D/fwcheck.bin"
curl_post register   "/v1:RegisterController?key=$KEY"                       "$D/register.bin"
curl_post gmsg1      /gmsg                                                   "$D/gmsg_poll0.bin"

# Recovery: an empty /gmsg body means the queued answer was consumed by an earlier
# poll that timed out on our side (deliver-once means a plain retry gets 200/0).
# Registering again queues a fresh answer for the same offer.
if [ "$(cut -d' ' -f2 "$OUT/gmsg1.stat")" = "0" ]; then
  echo "gmsg1_empty: re-register and re-poll" >> "$OUT/t1.log"
  curl_post register2 "/v1:RegisterController?key=$KEY" "$D/register.bin"
  curl_post gmsg1b   /gmsg                              "$D/gmsg_poll0.bin"
fi
curl_post gmsg2      /gmsg                                                   "$D/gmsg_poll_ack.bin"

# --- 3 concurrent TLS registrations (NSLOTS=3) ---
# NOTE: wait on the curl PIDs only. A bare `wait` also waits for the background
# stay_on_ap keeper (killed by stop_stay BELOW this line) and deadlocks forever
# (real-machine 2026-11-08: 33+ min hang, all tests already done).
pin
curl_once par0 "/v1:RegisterController?key=$KEY" "$D/register_par0.bin" &
P0=$!
curl_once par1 "/v1:RegisterController?key=$KEY" "$D/register_par1.bin" &
P1=$!
curl_once par2 "/v1:RegisterController?key=$KEY" "$D/register_par2.bin" &
P2=$!
wait $P0 $P1 $P2
echo "par_ssid: $(cmd wifi status 2>/dev/null | grep -o 'connected to "[^"]*"' | head -1)" >> "$OUT/t1.log"

# --- one more poll after the parallel churn: the last offer queued an answer ---
curl_post gmsg3 /gmsg "$D/gmsg_poll0.bin"

touch "$OUT/stop_stay"
STAY_REPINS=$STAY_REPINS
echo "pin_retries: $PIN_RETRIES stay_repins: $STAY_REPINS" >> "$OUT/env.txt"
echo "done: $(date)" >> "$OUT/env.txt"
echo T1_DONE
