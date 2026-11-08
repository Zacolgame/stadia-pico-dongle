# sim-controller — fake Stadia controller for the Pico 2W regression gate

Replaces the human with a script for `research/pico2w/stadia-one` (AP `StadiaPhone`,
Pico = 192.168.137.1 = fake cloud + display). **All packets leave the phone's
`wlan0`**; the PC only pushes payloads, pulls captures and judges them. Nothing here
touches the Pico hardware, the firmware tree, or any shared file.

```
run-sim.ps1                    # join AP, run T1, judge, rejoin home WiFi
run-sim.ps1 -Tier T1T2         # + DTLS probe (not built yet, see Coverage)
run-sim.ps1 -SkipWifi          # phone is already on the AP
run-sim.ps1 -PadRegister 6156  # reproduce the real-machine 6156 B registration
```

Exit codes: `0` = gate PASS, `2` = FAIL, `3` = could not get on the AP,
`4` = BLOCKED (AP up but the Pico's IP stack does not answer), `9` = setup error.

## Why PC-orchestrated (the recon decision)

The phone has **no python3 and no openssl**; Termux is installed but its `apt`/`pkg`
refuses to run as root ("Ability to run this command as root has been disabled
permanently", Termux's own patch) and `su` cannot switch to the app uid. What the
phone *does* have is a TLS-capable `curl` (`8.15.0 BoringSSL`), toybox `nc -u`,
Magisk busybox (`xxd`, `printf`) and `/system/bin/tcpdump`. So the design is:

* **phone** = TLS client + UDP socket sledgehammer (`curl`, `nc -u`),
* **PC** = protobuf encode/decode, retry ladder, verdict (Node, no deps).

This is the documented fallback shape, not a compromise on where the traffic
originates: every byte is emitted by the phone's WiFi.

## Protocol truth used by the simulator

Source of truth: the firmware itself (`src/cloud.c`, `src/proto.c`, `src/https.c`),
the captured real-device bodies in `research/live-cert-test/captures/`, and
`research/pico2w/stadia-one/pico-log-*.txt`.

The controller is a **client**; the Pico fakes the cloud and the display. Per boot
the controller opens a **new TCP connection per request** (the firmware has NSLOTS=3):

| # | request | body | response the firmware sends |
|---|---|---|---|
| 1 | `POST /log/batch` | 129 B Clearcut `LogRequest` (real capture) | `204` empty (`CLEARCUT_REPLY=0`) |
| 2 | `POST /v1:FirmwareVersionCheck?key=AIza…` | 8 B `{f1:"282115"}` | `200` `08 00` (requires_update=false) |
| 3 | `POST /v1:RegisterController?key=AIza…` | `RegisterControllerRequest` | `200` `RegisterControllerResponse` |
| 4 | `POST /gmsg` | `GmsgRequest{f1 token, f2{f1 acked_id}}` | `200` `GmsgEnvelope` |
| 5 | `POST /gmsg` again (ack) | same with ack | `200` **empty** (deliver-once rule) |

`RegisterControllerRequest` (built by `sim/make-bodies.cjs`, 306 B with a fresh offer):

```
f1  udn uuid                     f4  token(22)
f5  { f1 uuid, f9{1:1}, f4 bundle }
    bundle = WebRtcSdpAndIceCandidates{
      1: WebRtcSdp{ 1: type=1 (OFFER), 3: RtcSdpOffer }
      2: WebRtcSdp{ 1: type=3 (ICE_CANDIDATE), 5: candidate{1:"data",3:"1",4:2130706431,5:<ip>,6:<port>} }
    }
    RtcSdpOffer{ 3: ufrag(6), 4: pwd(22), 5: "sha-256 AA:..", 2:1, 21: raw_dtls=1, 23: delayed_acks=1 }
```

Response fields asserted by the gate (`sim/verify.cjs`):

```
RegisterControllerResponse{ f1 registration_id "pico-reg-XXXXXXXX", f2 poll_interval_ms=1000,
                            f3 registration_token, f5{ f1 display_id "pico-display-1", f4 display_token } }
GmsgEnvelope{ f1{ f1 id, f2 type=42, f269197544{ f1{ f1 <answer bundle> } } } }
answer bundle = { f1 WebRtcSdp{1: type=2 ANSWER, 4: {1 ufrag, 2 pwd, 3 fp, 4 fp2, 10 raw_dtls=1, 11 delayed_acks=1}},
                  f2 WebRtcSdp{1: type=3, 5: candidate{5: 192.168.137.1, 6: 40000}} }
```

So the answer advertises the display's own DTLS endpoint **192.168.137.1:40000**
(`PORT_DISPLAY`; the game session is `:40001`). The real controller then does ICE
(STUN binding, `FINGERPRINT` = IEEE CRC-32 xor `0x5354554E`, ICE-CONTROLLED) and
DTLS-SRTP to that port, then RTP (PT 111 Opus 48 kHz stereo, 20 ms = 960 ts) on the
0x66/0x74 channels — see PLAYBOOK §3.6y/§9.93 and `tools/net/pc-peer.cjs`.

Observed live on the 2026-11-08 firmware (`out/`, the PASS run):

```
T1 /log/batch          200  bytes=0   tls=7041ms
T1 /v1:FirmwareVersion 200  body=0800 tls=5255ms
T1 /v1:RegisterCtrl    200  bytes=78  tls=4828ms  reg_id=pico-reg-da2e8e78 poll_ms=1000
   display=pico-display-1 token=pico-tok-bb037235
T1 /gmsg #1            200  bytes=317 envelope id=2 type=42 answer_type=2
   ufrag=ohZPmH pwd_len=22 raw_dtls=1 delayed_acks=1 candidate=192.168.137.1:40000
   display_fp=sha-256 DA:AC:85:71:DC:FF:FA:B2:ED:13:31:FB:1C:FC:5E:7F:AD:FB:F9:4B:72:E9:E7:5F:53:C3:05:DF:37:CF:BA:DB
T1 /gmsg #2 (ack)      200  bytes=0   (deliver-once)
T1 parallel x3         200/9412ms 200/17726ms 200/10944ms  distinct reg ids = 3
RESULT T1 PASS  checks=16/16
```

Handshake cost varies a lot with the firmware's state: 4.8–7.0 s per connection in
the PASS run, 11–19 s in earlier runs. The gate's timeouts are sized for the slow end.

## Files

| file | role |
|---|---|
| `run-sim.ps1` | PC driver, ASCII-only: join/pin AP, preflight, push, run, pull, judge, restore home WiFi |
| `sim/pblite.cjs` | protobuf wire codec + the controller's request body builders (no deps) |
| `sim/make-bodies.cjs` | writes `payload/*.bin` for the current run (fresh uuid/ufrag/pwd/fingerprint, phone as ICE candidate) |
| `sim/t1.sh` | runs **on the phone**: boot sequence, 3 parallel registrations, stay-on-AP keeper, retry ladder |
| `sim/verify.cjs` | decodes the captured responses, prints the gate lines + metrics, writes `out/t1-result.json` |
| `payload/` | generated request bodies + `meta.json` (this run's credentials) |
| `out/` | pulled captures: `<name>.resp`, `<name>.stat`, `t1.log`, `env.txt`, `t1-result.json` |
| `_*.sh` | debug probes kept for the record (`_alive.sh` = subsystem liveness, `_probe2.sh` = pcap + DNS/UDP/TCP) |

## Coverage

| tier | what | state |
|---|---|---|
| **T1a** | boot sequence statuses + key response fields (register id, poll_interval_ms, display id/token) | **implemented, verified live PASS** |
| **T1b** | `/gmsg` answer: type=2, ufrag/pwd/fingerprint, raw_dtls, delayed_acks, candidate = 192.168.137.1:40000 | **implemented, verified live PASS** |
| **T1c** | deliver-once (second poll with ack returns 200/0 B) | implemented |
| **T1d** | 3 parallel TLS registrations | implemented; SKIPped when the phone hops off the AP mid-phase |
| **T1e** | 6156 B padded registration (`-PadRegister 6156`) to reproduce the old 6144-byte HTTP buffer overflow | implemented (`out/*` reports the drop/accept) |
| **T2** | DTLS 1.2 handshake to `:40000` + negotiated SRTP profile | **partially covered by `probes/`** (lead-added): `stun-probe.sh` = **STUN_OK** (Binding Response + integrity, proves the UDP path); `dtls-probe.sh` = **DTLS_ALIVE** (bare ClientHello answered with ServerHello cipher **C02B** + use_srtp **echoed** + Certificate flight). Full handshake (ClientKEX→Finished→SRTP keys) still needs ECDHE crypto — job of the real controller / listening test. Lessons baked in: server cert is ECDSA P-256 (RSA-only hello → Alert 40) and signature_algorithms is mandatory (else SHA1-only assumption → Alert 40) |
| **T3** | 10 s of SRTP/RTP, seq continuity + Opus frame sizes | **not built** — needs T2's keys first (SRTP payload is encrypted; only the header/seq is readable without keys). Path forward if ever needed: USB-tether the phone (RNDIS) + iptables FORWARD wlan0<->usb0 + PC route to 192.168.137.0/24, then run a Python DTLS client on the PC (`cryptography` for ECDHE/secp256r1 + PRF-SHA256 + AES-GCM; no HVR round trip since the server sets NULL cookies). Morning listening test covers audio instead — cheaper and higher fidelity. |

### Gap vs a real controller

Covered: the whole HTTPS boot sequence, the registration body shape (offer with our
own ICE candidate), the gmsg answer parsing, deliver-once, TLS concurrency,
STUN binding on :40000, DTLS Serverhello negotiation (cipher + use_srtp echo).
Not covered: DTLS-SRTP with the Pico's certificate and
the `EXTRACTOR-dtls_srtp` key export, RTP/Opus input frames, the display-RPC
(`ResolveDiscovery`, `GetControllerStateRequest`), `DiscoverDisplay`, and the game
session on `:40001`. In short: T1 proves the *signalling* half of a real controller.

## Environment landmines found while building this (all reproduced)

1. **Android hops off the AP ~25 s after joining** (the AP has no internet): it
   disassociates, rejoins the home SSID, and traffic to 192.168.137.1 then fails at
   0 ms with `ENETUNREACH`. Turning **Private DNS off** (`settings put global
   private_dns_mode off`) makes it stable for >36 s; `network_avoid_bad_wifi 0` and
   `svc data disable` alone are not enough. `sim/t1.sh` therefore runs a
   stay-on-AP keeper + a 5-attempt retry ladder; `run-sim.ps1` restores both
   settings in its `finally`.
2. **The Pico's TLS handshake takes 11–19 s per connection.** Curl defaults or a
   10 s connect timeout abort the handshake and the firmware then stops serving.
   The gate uses `--connect-timeout 30 --max-time 90` on purpose.
3. **3 truly-parallel TLS handshakes are flaky, not broken** (corrected 2026-11-08:
two full 3/3 PASS runs since, one per firmware variant): occasionally one leg
gets RST (the firmware's by-design refuse when a 4th connection overlaps) and
passes on retry. Sequential cadence (the real controller's) always works. The
per-accept heap numbers below remain valid sizing data:
   handshake needs a ~4.2 KB certificate record and tens of KB of heap; the
   heartbeat shows `heap=90112`/`73728` per accept). Sequential connections (the
   real controller's cadence) are fine. This is the most likely real firmware
   limit found by the gate so far.
4. **Wedge: after aborted handshakes the Pico's IP stack can go completely silent**
   while the AP keeps beaconing and accepting associations: no ARP reply, DNS 53,
   UDP 40000 and TCP 443 all silent, `ping 100% loss`, `ip neigh` empty — and the
   30 s hardware watchdog does not fire (core0 is still feeding it). It recovered
   on its own once (≈2 min) and needed a power cycle on another occasion.
   `run-sim.ps1` detects this in preflight (no ARP reply) and exits **4 BLOCKED**
   with that diagnosis instead of printing 16 meaningless FAILs.

## What breaks if the Pico reboots mid-run

* The phone keeps its DHCP lease and association state for a moment, then
  re-associates; the in-flight `curl` gets a reset/timeout and the retry ladder
  re-pins. Run level: the four boot requests are independent, so a reboot costs the
  current request, not the run — **except** that a reboot also resets
  `cloud_offer`/`gmsg_id`/`gmsg_delivered`, so a `/gmsg` answer queued by a
  pre-reboot registration is gone: `/gmsg` then returns `200` with an **empty body**
  and the gate fails T1b (correctly — that is a real registration loss).
* The registration id/token and the display fingerprint change; anything cached from
  the previous boot (our `payload/meta.json`, the answer parsed earlier) is stale.
* If it reboots *during* the 3-way parallel phase, expect 1–3 connection failures
  and a fresh `gmsg_id=1`; the SSID marker in `t1.log` plus the empty `/gmsg` body
  are how you tell this apart from the phone hopping off the AP.
