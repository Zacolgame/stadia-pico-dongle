// stadia-one — the whole fake cloud + gamepad bridge on one Pico 2 W.
#pragma once

#define WIFI_SSID        "StadiaPhone"      // burned into the controller; DO NOT change
#define WIFI_PASS        "TestPass1234a"
#define WIFI_CHANNEL     6

#define AP_IP            "192.168.137.1"    // the Pico IS the cloud: DNS answers itself
// NOTE: the vendored dhcpserver.h hardcodes the pool as DHCPS_BASE_IP(16)..
// DHCPS_MAX_IP(8), i.e. 192.168.137.16-.23. The two macros below are documentation
// only and are NOT consumed by dhcp_server_init(); they used to claim .100-.150.
#define DHCP_POOL_START  (.16)
#define DHCP_POOL_END    (.23)

// ---------------------------------------------------------------------------
// Bisect switch. 1 = reproduce build p3-0826 exactly: the only build in which the
// controller actually started ICE and sent a DTLS ClientHello. That build carried four
// defects which later turned out not to block ICE, so restoring them tells us whether the
// later "fixes" caused the regression. Set to 0 for the corrected behaviour.
#define BISECT_0826 1
// ---------------------------------------------------------------------------
// UAC1_ONLY bisect switch (p3-3170, 2026-11-05). The full composite (CDC +
// XInput + UAC1) fails Windows enumeration with NO interface at all, even in
// the proven DS5Dongle audio-first order. This switch builds the MINIMAL
// UAC1-only firmware to bisect where that failure lives:
//   - device descriptor: class 0x01 (Audio) / sub 0x00 / proto 0x00, VID/PID
//     0x0D8C:0x013C (C-Media USB audio - native usbaudio.sys, zero install),
//     bcdDevice 0x0201 (fresh devnode). NO IAD, NO MISC composite class.
//   - config: ONLY AudioControl if0 + AudioStreaming if1 (alt0 idle / alt1
//     48k stereo s16, iso OUT EP 0x04 adaptive 192 B/ms) - CDC, XInput and
//     the WCID exchange are all compiled out (CFG_TUD_CDC/VENDOR = 0).
//   - serial CDC log is GONE by construction; the pass/fail signal is
//     Windows Device Manager only (see check_usb_desc.py --uac1-only).
// Read-out: "USB Audio Device" appears  -> the hand-written UAC1 descriptors
// are fine, the COMPOSITE structure is the problem. Nothing appears -> the
// iso endpoint / UAC1 descriptors themselves are the problem.
// The default 0 keeps the full-composite build bit-identical. The value is
// normally set by the BUILD (build-uac-only.bat configures build-only/ with
// -DUAC1_ONLY=1 via CMake), so both uf2s build from one source tree; the
// #ifndef default below only covers builds that never set it (host tests).
#ifndef UAC1_ONLY
#define UAC1_ONLY 0
#endif
// ---------------------------------------------------------------------------
// UAC1_CDC_ONLY bisect switch (p3-3190, 2026-11-06). Second rung of the
// composite enumeration bisection ladder:
//   UAC1_ONLY      audio alone               -> WORKS (p3-3180: Windows shows
//                  "USB Audio Device" once the EP direction bit was fixed) -
//                  the hand-written UAC1 bytes and the iso path are proven.
//   full composite audio + CDC + XInput      -> FAILS (p3-3150..3180: Windows
//                  enumerates NO interface at all, even audio-first).
//   UAC1_CDC_ONLY  audio + CDC, no XInput    -> this rung: the failing
//                  composite minus exactly one suspect - the vendor-class
//                  XInput function AND its whole WCID exchange (0xEE string,
//                  vendor control replies) are compiled out. Layout:
//   device class EF/02/01 (IAD - the CDC pair needs it), VID/PID stay
//   0x045E:0xFFFF (unclaimed by any inbox INF), bcdDevice 0x0202 (fresh
//                  devnodes: 0x0108 = failing 3-function composite, 0x0201 =
//                  working audio-only, neither may be reused).
//   - config: UAC1 IAD pair if0-1 (AC + AS, iso OUT EP 0x04, byte-identical
//     to both proven builds) + CDC IAD pair if2-3 (EP 0x82/0x83/0x03,
//     byte-identical to the composite's CDC block). 170 bytes, 4 interfaces,
//     4 endpoints. TinyUSB: CFG_TUD_CDC=1, CFG_TUD_VENDOR=0, CFG_TUD_HID=0.
//   - the serial CDC console IS present in this variant (the COM port is
//     half of the read-out, and the boot log is back for free).
// Read-out: COM port + "USB Audio Device" BOTH appear -> audio and CDC
// coexist fine, the failure is locked to the XInput vendor function/WCID;
// either one missing -> the audio-CDC IAD interaction itself is broken.
// Mutually exclusive with UAC1_ONLY (one bisect variable per flash). The
// default 0 is set by the build (build-uac-cdc.bat configures build-cdc/
// with -DUAC1_CDC_ONLY=1 via CMake), same pattern as UAC1_ONLY above.
#ifndef UAC1_CDC_ONLY
#define UAC1_CDC_ONLY 0
#endif
#if UAC1_ONLY && UAC1_CDC_ONLY
#error "UAC1_ONLY and UAC1_CDC_ONLY are mutually exclusive bisect variants - pick one per build"
#endif
// ---------------------------------------------------------------------------
#if UAC1_ONLY
#define FW_BUILD "p3-3180-uac4only"   // audio-only bisect build; CDC log is
                                      // gone, this tag only shows in the
                                      // binary (grep the .uf2 to tell the
                                      // builds apart when flashing).
                                      // p3-3180: iso EP direction fixed
                                      // 0x84 (IN) -> 0x04 (OUT) + vendored
                              // rp2040_usb.c (RP2350 DPRAM copy
                              // hard-fault fix + ISO never
                              // double-buffered); bcdDevice 0x0201.
#elif UAC1_CDC_ONLY
#define FW_BUILD "p3-3190-uac4cdc"   // UAC1+CDC bisect build (second rung of
                              // the composite bisection: the p3-3180
                              // full 3-function composite fails Windows
                              // enumeration entirely while the audio-only
                              // rung works; this build drops exactly the
                              // XInput vendor function + WCID exchange and
                              // keeps audio if0-1 + CDC if2-3, both
                              // byte-identical to the composite). Judged by
                              // Device Manager: COM + USB Audio Device both
                              // up = XInput/WCID is the culprit; anything
                              // missing = the audio-CDC IAD interaction.
#else
// p3-3654: DTLS (media) identity. 1 = reuse the upstream GTS EC credential that
// HTTPS already serves (one identity end to end, exactly like stadiacast);
// 0 = the historical self-signed EC leaf (single datagram flight, but the
// controller abandons the session once HTTPS presented a different chain).
// p3-3656: back to 0 - mixed build (GTS HTTPS + fresh self-signed DTLS leaf).
// The p3-3654 unified attempt failed: the 1058 B GTS leaf makes a 1486 B flight
// that this controller drops (no IP-fragment reassembly); the p3-3652 mixed
// failure is being retested cleanly because its evidence was confounded by WDTs.
#define DTLS_IDENTITY_UPSTREAM 0
#define FW_BUILD "p3-3656-mixed"   // p3-3646: static canaried Opus pseudostack
                             // (48 KiB .bss, OVERRIDE_OPUS_ALLOC_SCRATCH) + creep
                             // and peak telemetry. p3-3609: Opus init step probe
                             // (setup -> encode -> publish as separate timed
                             // stages; the auto-recovery delay identifies the
                             // wedging call).
                             // Printed at boot AND every 15s (hb line) so a late-opened
                             // serial port still captures build + DTLS fingerprint.
                             // p3-3500 plugplay (2026-11-06): the FINAL zero-config
                             // build. (1) The vendor XInput interface is BACK
                             // (restored byte-exact from the p3-3180/57537e3
                             // lineage): interface 4 = FF/5D/01 + 17B 0x21 xusb
                             // capability blob + EP 0x81 IN 20B / 0x01 OUT 8B,
                             // plus the whole MS OS 1.0 WCID exchange (0xEE
                             // MSFT100 string, XUSB10 ext-compat replies) - the
                             // p3-3200 standard-HID gamepad is deleted (it was
                             // DirectInput-only; XInput games need the vendor
                             // interface). TinyUSB: CFG_TUD_VENDOR=1,
                             // CFG_TUD_HID=0. Config 206B->214B, bcdDevice
                             // 0x0301 -> 0x0302 (fresh devnode: 0x03xx
                             // devnodes recorded "non-WCID" and must re-probe).
                             // (2) Plug-and-play audio: the speaker source is
                             // fully automatic now - rtc_tick watches the UAC1
                             // fifo (usb_audio_ms_since_data), data arriving =
                             // USB source ("audio: usb source auto-detected"),
                             // gone >100 ms = mute (never the test tone); the
                             // AUDIOSRC console command is deleted. TONE stays
                             // as the manual speaker check.
                             // p3-3400 uacfixA (2026-11-06): WiFi-rx fix ladder
                             // plan A - the tud_task alarm period goes back to
                             // 1 ms (usb_hid.c usb_tud_alarm_cb). The 500 us
                             // period from p3-2700 (iso re-arm margin) broke
                             // WiFi reception on hardware (rx=0/0 rxr=2 from
                             // boot, AP still beaconing; master @1 ms fine).
                             // p3-3300: TinyUSB-vendored UAC1 driver (98741b55)
                             // replaced the crashing hand-written usb_audio.c
                             // class driver; UAC1-spec 9/7-byte EP/CS-EP forms;
                             // bcdDevice 0x0301.
                             // p3-3200 stdhid: XInput vendor interface (0xFF/5D/01 +
                             // 17B 0x21 xusb blob) and the whole MS OS 1.0 WCID exchange
                             // (0xEE string, XUSB10 ext-compat replies) replaced by a
                             // STANDARD HID gamepad: interface 4 class 03/00/00, 9B 0x21
                             // HID descriptor + 103B report descriptor (16 buttons,
                             // X/Y/Z/Rz 16-bit sticks, Rx/Ry 8-bit triggers, 4-bit hat),
                             // EP 0x81 IN 13B reports / EP 0x01 OUT 4B rumble (u16 L/R
                             // motors, vendor 0xFF00 usages - the p3-2215 hidparse lesson
                             // is honored: every non-constant field carries a usage).
                             // TinyUSB: CFG_TUD_HID=1, CFG_TUD_VENDOR=0 (hid_device
                             // claims if 4; no vendor driver remains, so MS OS/vendor
                             // control requests STALL = the non-WCID behaviour Windows
                             // must see). All three functions standard-class now
                             // (usbaudio / usbser / hidusb bind on compatible ids
                             // alone). Config 210B->202B, bcdDevice 0x0108 -> 0x0300
                             // (fresh REV over the whole poisoned 0x01xx/0x02xx range).
                             // p3-3180: iso EP direction fixed 0x84 (IN) -> 0x04 (OUT)
                             // - the actual root cause behind every UAC1 Windows
                             // failure since p3-2700 (usbaudio.sys refuses a
                             // playback AS interface whose data EP is IN);
                             // vendored TinyUSB rp2040_usb.c patch; bcdDevice 0x0108.
                             // p3-3160 uac3: interface order rearranged audio-first
                             // (AC 0 / AS 1 / CDC 2-3 / XInput 4) after Windows
                             // refused to enumerate the WHOLE device with audio
                             // last - mirrors the proven DS5Dongle RP2350 +
                             // TinyUSB + UAC1 composite layout; WCID
                             // bFirstInterfaceNumber 2 -> 4, bcdDevice 0x0106 -> 0x0107.
                             // p3-3150 final: uac + datehdr features combined.
                             // p3-2900 uac2: uac branch merged with master p3-2820
                             // (bootfix lineage: rumblefix + boot2 + top5 audit).
                             // The p3-2800-grand FLASH showed VID_045E nodes Unknown
                             // and no COM port on Windows - grand was reverted to
                             // p3-2820 on master while uac debugs here. This merge
                             // re-unions both lineages; enumeration audit below
                             // (usbd itf accounting vs the 5-IF vendor descriptor).
                             // p3-2700 uac: route B phase 2 - the PC plays into a
                             // driverless UAC1 USB speaker (iso OUT
                             // EP 0x84, 48k stereo s16, hand-written class driver
                             // because TinyUSB 0.18's class/audio is UAC2-only and
                             // Windows' usbaudio2.sys does not bind full-speed UAC2);
                             // the stream is resampled 48k->16k mono with a
                             // fill-steered software clock and Opus-encoded (vendored
                             // libopus 1.3.1 fixed-point) into the EXISTING SRTP
                             // pump - seq/ts/marker/attach semantics untouched.
                             // AUDIOSRC usb|tone selects the frame source, OPUSBENCH
                             // runs the on-device encoder benchmark.
                             // p3-2710 rumblefix: the 2026-11-05 01:0x start frame left
                             // the device 27 B (`3a11 1001 18<ts> 2204 2000 520c`): the
                             // inline rumble constructor's slim buffer was initialized
                             // with `pbo_init(&sl, slim, sizeof sl)` - sizeof of the
                             // pb_out_t STRUCT (12 B on ARM32, 16 B on x64) instead of
                             // the 48 B array - so pbo_raw dropped the 12-byte f10
                             // (input_feedback_message_v2) content right after its
                             // length prefix. The 35 B stop frame survived by luck (its
                             // f10 content is 8 B: 4+8 <= 12). The host test never saw
                             // it because tests/proto_host_test.c REPLICATED the
                             // construction inline with the correct sizeofs. Fixes:
                             // (1) the series is built by proto.c build_rumble_series()
                             // - ONE constructor shared with the host test - and
                             // wh2_send frames via the shared wh2_wrap(), so the host
                             // oracle asserts the firmware's own bytes; (2) the shared
                             // constructor uses NUMERIC caps: sizeof(pb_out_t) differs
                             // x64(16)/ARM32(12), so a struct-sizeof typo in shared
                             // code would STILL pass on host and truncate on device;
                             // (3) rumble_flush logs `rumble pbdrop:` when g_pb_overflow
                             // moves (the 27 B frame left no other trace); (4) R16
                             // vectors: learn_series_session() on the REAL captured
                             // registration series proves ota.282115 announces NO f1
                             // session_id - `sid=0` in `rumble tx:` is the live
                             // baseline (send_vibration's `if session_id:` skips too),
                             // NOT a learning failure; a controller that does announce
                             // one is echoed through the shared, host-tested path;
                             // (5) check_rumble.py shape-asserts start==39 B with the
                             // complete f10 block, stop==35 B.
                             // p3-2640 rumblepath: the 00:40 "rumble tx: never prints"
                             // post-mortem was a LOG-BUDGET artifact, not a path fork:
                             // rumble_flush() was already the only series sender and it DID
                             // run (controller acked series 22, twice), but every visibility
                             // budget (rumble tx 16 / game tx 16 / game ack in 8 / gameframe
                             // 30) is per-BOOT static and the capture opened 26.6 min into a
                             // session that had already run 10 RUMBLE pulses - all drained.
                             // Fixes: (1) SINGLE send path - rtc_rumble_pulse and the pulse
                             // auto-off no longer flush directly (the auto-off's direct
                             // flush + the next tick's dirty flush DOUBLE-SENT every stop
                             // series; the duplicated `2016 2016` ack in rumble-live2.txt
                             // is those two sends), writers only set rumble_dirty and
                             // rtc_tick's flush block is the sole sender; (2) a refused
                             // send re-arms dirty (no silent drop); (3) the RUMBLE command
                             // resets the rumble tx / hex / ack-in budgets so a mid-session
                             // test always shows its own lines; (4) device-side
                             // self-certification: every outbound SERIES (field 7) dumps
                             // its full wire frame hex at the 0x66 TX (budget 4, `rumble
                             // hex1/N ...`), directly comparable to check_rumble.py's
                             // R15_START/R15_STOP vectors; (5) "pulse done" logs hs= so a
                             // down game link is visible as "armed, not sent".
                             // p3-2550 rumble: feedback-series content aligned to the live
                             // baseline byte for byte (rtc.c rumble_wall_us + R15 vectors in
                             // tests/proto_host_test.c, asserted by tests/check_rumble.py):
                             // base_timestamp_us in EPOCH microseconds (was uptime = 1970
                             // domain), session_id echo cap 64 B (was 16), gamepad id also
                             // learned from V1 registrations, first series seq=1.
                             // p3-2530 fastboot: boot "internet self-check" made instant.
                             // At power-on the controller resolves play.googleapis.com 4x
                             // (2 via DHCP DNS + 2 via hard-coded 8.8.8.8, both land on us)
                             // BEFORE it will try cloudcast-pa; the old §9.83 NXDOMAIN answer
                             // failed that check and it walked a 3-round discovery ritual
                             // first (pico-log-20261104-232650 lines 959-973: 4x NXDOMAIN,
                             // cloudcast-pa only ~13 s after association; the PC-era rig had
                             // real DNS so the check passed instantly = white LED at once).
                             // Fix mirrors the reference "live" preset exactly:
                             //   DNS  *.googleapis.com -> our IP (dns_sink DEFAULT_REDIRECTS),
                             //   TLS  ClientHello SNI play.googleapis.com -> fatal
                             //        handshake_failure (clearcut_block="tls"). The upload
                             //        MUST keep failing: "every wake otherwise powers off
                             //        ~0.3 s after its first Clearcut upload" (config.py:97).
                             // Switches below (CLEARCUT_DNS_NXDOMAIN / CLEARCUT_BLOCK_TLS /
                             // CLEARCUT_REPLY) keep the old behaviour selectable for bisection.
                             // p3-2450 wcid2: XInput child MI_02 stayed Code 28 with NO
                             // USB\MS_COMP_XUSB10 in its CompatibleIds. NOT a hook-point
                             // problem: TinyUSB 0.18 usbd.c process_control_request()
                             // routes EVERY vendor-type request (any recipient,
                             // including the device-level 0xC0 MS OS query) to
                             // tud_vendor_control_xfer_cb before the recipient switch -
                             // and usb_hid.c already overrode that callback. The bug was
                             // the match condition: p3-2420 required wValue low byte == 2
                             // ("interface in wValue"), but per MS OS 1.0 the wIndex=4
                             // Extended Compat ID query carries wValue = page number
                             // 0x0000 (the wValue-interface convention belongs to the
                             // wIndex=5 Extended Properties query). Windows sent
                             // wValue=0x0000, the handler fell through to STALL,
                             // usbccgp concluded "non-WCID device", so the child never
                             // got the XUSB10 compatible id xusb22.inf matches. Fix:
                             // usb_hid.c matches wValue == 0x0000. The 0xEE "MSFT100"
                             // string probe (step 1) was already answered via
                             // tud_descriptor_string_cb and is unchanged. Bump bcdDevice
                             // to 0x0104 (fresh devnodes, see usb_hid.c).
                             // p3-2420 cdcfix: CDC COM port was GONE on Windows since the
                             // XInput merge - root cause was NOT a truncated descriptor
                             // (the 115B/3IF/5EP composite was already intact on the
                             // wire). PID 0x028E made inbox xusb22.inf match the DEVICE
                             // hardware id USB\Vid_045E&Pid_028E, which outranks the
                             // USB\COMPOSITE compatible id: xusb22.sys took the whole
                             // device, usbccgp never loaded, CDC never got a child
                             // devnode -> no COM port (XInput kept working - that is
                             // how a real wired 360 pad binds). Fix in usb_hid.c:
                             // PID 0x028E -> 0xFFFF (unclaimed by any inbox INF),
                             // bcdDevice 0x0103 (fresh devnodes), plus MS OS 1.0 WCID
                             // descriptors so the XInput interface child still binds
                             // xusb22 via compatible id USB\MS_COMP_XUSB10 (string
                             // 0xEE "MSFT100" + 40B Extended Compat ID "XUSB10" for
                             // interface 2 - no inbox INF matches Class_FF&SubClass_5D
                             // _Prot_01, the MS OS descriptor is the only path).
                             // p3-2330 audiofix: TWO root causes for "RUMBLE parsed but
                             // no motor" and "125 tone frames sent but no sound", both
                             // reproduced offline against the device log evidence
                             // (autotest-result.txt 2026-11-04 22:02, build p3-2300):
                             // (1) rtc.c rumble_flush: pbo_init(&se, series, sizeof se)
                             //     passed sizeof(pb_out_t)=12 instead of sizeof(series)=
                             //     112, so the InputMessageSeries was cut at 12 bytes
                             //     right after the "22 10" length prefix of the messages
                             //     field - exactly the 11-byte "game tx: len=11" on the
                             //     wire, a malformed protobuf the controller drops
                             //     silently. Fixed; the motor series is now ~27 B and
                             //     "game ack in: ... seq=2/3" is the success line.
                             // (2) rtc.c audio_keys_derive: the RFC 5705 exporter seed
                             //     carried a trailing uint16be(60) (TLS 1.3 HKDF-Label
                             //     convention, wrong for TLS 1.2). werift (the stack
                             //     behind the PC-verified audible tone) seeds
                             //     label||client_random||server_random with NO length,
                             //     so every SRTP key/salt we derived was wrong and the
                             //     controller silently dropped all protected frames
                             //     (emu37). Seed is now exactly cr||sr (64 B).
                             // Plus: AUDPTEST CDC command (one deliberately-unprotected
                             // RTP frame as the drop-control experiment), the attach
                             // RPC wire id is AUDIO_ATTACH_WID (0x74, pc-peer's audible
                             // channel; 0x75 also proven to reach - tag=4 ack in log
                             // 220015), and the audio frame log prints the destination
                             // 5-tuple. RUMBLE/TONE parsing needed NO fix - both
                             // commands verifiably reached the parser in p3-2300.
                             // p3-2300 all: MERGE of master p3-2215-hiddesc (USB side:
                             // hidrum 1ms tud_task alarm + RUMBLE, hiddesc descriptor fix,
                             // 4 endpoints, bcdDevice 0x0101) and branch audio p3-2150
                             // (speaker side: SRTP/Opus tone pump, tag16 attach, TONE
                             // command, tone_frames.h). Functional UNION - both CDC
                             // commands (RUMBLE + TONE) live, USB descriptors unchanged
                             // from p3-2215 (check_usb_desc.py still asserts 100 B /
                             // 3 interfaces / 4 endpoints), main.c drives rtc_tick at
                             // 20 ms for the audio pump. Conflict files resolved by
                             // union: config.h (this block), rtc.h, usb_hid.c; rtc.c
                             // and main.c auto-merged.
                             // p3-2215 hiddesc: Windows HID Code 10 root-caused and fixed
                             // in the USB descriptors (usb_hid.c). The Report ID 2 Output
                             // main item declared no usages; Windows hidparse rejects the
                             // whole report descriptor for that ("A non constant main item
                             // was declared without a corresponding usage", hidpddi.h) and
                             // the HID interface start fails with CM_PROB_FAILED_START
                             // while CDC (no HID parsing) works. Now vendor usages are
                             // declared for both rumble u16 fields. Also: the HID
                             // interrupt OUT endpoint was dropped (TinyUSB 0.18's OUT
                             // path passes report_id=0 with the ID byte still in the
                             // buffer - dead code for our callback; rumble goes via
                             // control SET_REPORT, which Windows HID uses as fallback
                             // anyway), config descriptor 107 -> 100 bytes / 4 endpoints,
                             // and bcdDevice 0x0100 -> 0x0101 so Windows builds a fresh
                             // devnode instead of reusing the rejected one.
                             // p3-2130 hidrum: two host-side deliverables, no protocol
                             // changes. (A) Windows HID Code 10: tud_task() moved out of
                             // the main loop into a repeating 1 ms hardware alarm
                             // (usb_hid.c usb_tud_alarm_cb) that owns it EXCLUSIVELY -
                             // the main loop used to stall for seconds inside mbedTLS
                             // (RSA 2-4 s in https drive) so host control transfers
                             // timed out and the HID interface start failed while CDC
                             // started by luck; every TinyUSB call left in the main
                             // loop (HID report, CDC read/write/flush) now runs inside
                             // save_and_disable_interrupts() windows because TinyUSB is
                             // not reentrant and its CDC fifos are pico-mutexed
                             // (OSAL_MUTEX_REQUIRED=1: IRQ preempting a mutex holder
                             // would deadlock). (B) Rumble trigger: new CDC command
                             // "RUMBLE" -> rtc_rumble_pulse() (rtc.c): 75% (49151 =
                             // 0.75*0xFFFF, MOTOR_MAX game_session.py:56) both motors,
                             // flushed immediately, auto-off at 200 ms with a 0,0 stop
                             // frame from rtc_tick - mirrors the live rumble() helper
                             // (game_session.py:595-637).
                             // p3-2150 audio: SPEAKER PATH. Synthesized 440 Hz tone to the
                             // controller speaker on its own WiFi, entirely from the Pico
                             // (the PC-verified recipe of PLAYBOOK 3.6z6 ported into the
                             // firmware): (1) attach DisplayToController{16:
                             // SetAudioModeRequest{1:2}} (WebRTC Opus) - auto-sent when
                             // the controller answers our GetControllerStateRequest and
                             // re-armed by the TONE command, 60 s guard like pc-peer;
                             // (2) feed Opus RTP PT 111, 20 ms frames (ts step 960,
                             // stereo 48 kHz), seq+1 no gaps, marker on each tone's first
                             // frame, ssrc 0x5a17d1a - the packet source is a PRE-ENCODED
                             // 10-frame (200 ms) steady-state cycle in src/tone_frames.h
                             // (tools/gen-tone-frames.cjs, same opusscript encoder and
                             // parameters as the PC recipe; the cycle repeats 59x in the
                             // source encode so looping it is byte-exact to any length);
                             // (3) wrap each packet in SRTP AES128_CM_SHA1_80 keyed from
                             // the display DTLS handshake (mbedtls export-keys callback ->
                             // RFC 5705 exporter "EXTRACTOR-dtls_srtp" -> RFC 3711 KDF,
                             // exactly stadiacast dtls.py export_srtp_keys + srtp.py) -
                             // emu37 proved the device silently DROPS unprotected RTP;
                             // (4) send over UDP on the display link's own 5-tuple
                             // (BUNDLE: same socket as DTLS/STUN), paced by rtc_tick at
                             // 20 ms (main.c now drives rtc_tick every 20 ms; all other
                             // tick work is time-gated). Trigger: "TONE\r\n" on the CDC
                             // console (2500 ms = 125 frames, the 3.6z6 recipe).
                             // p3-2050 inpath: input channel DETERMINED. The controller's
                             // input is an RpcNotification{message3} on the DISPLAY link
                             // 0x74 (READY only, on change) - NOT RTP on the game link
                             // 0x66. Evidence: the live 9.46 session (research/e4/sc-run/
                             // server.jsonl) logs "type":"rpc_input" events 1:1 with its
                             // rpc_in message3 lines (kind=notification, ticket 65/66,
                             // {"f1":0,...,"f6":2,"f7":0} = a light L2 tap) and ZERO
                             // rtp_input, while the game link carried exactly ONE
                             // registration series (game_wire_in={0x0066:4}) - identical
                             // to our p3-2035 session where button presses produced no
                             // 0x66 traffic. Reference chain: stadiacast
                             // controller.py:731 (_on_rpc notification/message3 ->
                             // _on_input_rpc:758) fed by _on_app_data:569 (0x74).
                             // Changes, receive-side only: (a) on_display_rpc's
                             // CTD_INPUT branch - present since p3-1155 but SILENT, so
                             // it never produced a log line and could not be told apart
                             // from "input never arrives" - now logs "disp in3:" per
                             // message3 (budget 60) and non-message3 notifications log
                             // "disp notif: tag=" (budget 12); (b) its field map re-
                             // verified vs controller_message.proto:237 + gamepad.py:97
                             // from_message3 (f1 buttons, f2-f5 sint32-zigzag lx/ly/rx/
                             // ry, f6/f7 uint32 triggers L2/R2) - ALREADY CORRECT,
                             // untouched; (c) pad logging moved into shared pad_commit
                             // (apply_gamepad_v2 keeps behaviour, now tagged src=g66)
                             // and the message3 path commits through it (src=disp3), so
                             // a decoded press is visible whichever link delivered it;
                             // (d) on_display_frame dumps the full record hex
                             // ("dispframe", budget 20) for every size that is not the
                             // known-chatty 16B heartbeat / 19+22B time requests - a
                             // 23B display record in pico-log-20261104-201526.txt was
                             // previously unidentifiable; sizes COLLIDE (single-button
                             // message3 ~= 19B) so the kind-based logs are the
                             // discriminator, the dump settles everything else.
                             // p3-2000 input: the 0x66 stall root-caused from the two live
                             // logs + the 9.46 reference session: the BARE ACK of p3-1725
                             // WAS accepted (pico-log-20261104-183025.txt: one gameframe
                             // in 28 min, ZERO retransmissions - and ota.282115's window-1
                             // sender with PeriodicResend and no give-up MUST retransmit
                             // an unacked series), while p3-1855's RTP-framed ACK was
                             // rejected (pico-log-20261104-185840.txt: seq=1 retransmitted
                             // all 26 min; the controller's bare-framed 0x66 reader is
                             // strict, see tests/fake_controller.py:464-469). Fix: MIRROR
                             // the controller's framing exactly like the live spec's
                             // game_framing=auto (game_session.py:528-548) - raw/bare for
                             // ota.282115, RTP only if the controller uses RTP. Also:
                             // rumble goes through the same mirrored sender (echoes the
                             // series session_id f1 and the gamepad id like
                             // send_vibration, no f4 piggyback); game-RPC reply id
                             // mirrors the request (0x74->0x75 else same id,
                             // game_session.py:746); gameframe dump = whole record hex
                             // + budget 30 + per-frame series seq + "gseq" line on every
                             // NEW seq; every 0x66 TX logs its framing and write result.
                             // RTCP RR deliberately NOT implemented: the reference
                             // sends RR on the DISPLAY link only (1510 in the 9.46
                             // session, rtc_stats.rtcp_out) and never on the game link
                             // (game_rtc_stats has no rtcp_out at all) - and our display
                             // link stays healthy without it (26-min st=4 sessions).
                             // p3-1855 rtpack: the 0x66 input ACK now goes out the way the
                             // live spec's send_input_message frames it by default
                             // (game_session.py:528-548): RTP(PT=96, seq/ts/ssrc per
                             // endpoint.py:598-615) inside WireHeader2 0x66 - REGRESSION:
                             // the reference default only applies until the controller's
                             // own framing is seen, and ota.282115 sends BARE.
                             // p3-1725-ack: bare InputProtocolMessage{4:ack} on 0x66 -
                             // this form was live-accepted (see above).
                             // p3-1435 gamereply: game link answers ICE checks. Root cause of
                             // "0 stun game: lines" was MEMP_NUM_UDP_PCB=4 vs FIVE udp_new() at
                             // boot (dhcp+dns+sntp+disp+game) - game udp_new() got NULL, :40001
                             // never bound, every game check dropped (RXF shows them arriving).
                             // Also: ProxyRequest body now read through the ControllerToDisplay
                             // wrapper (CTD.f1.f4, one level was missing) so game_offer actually
                             // parses; reactive check uses the link's own ufrag; hb shows pcbs=.
                             // p3 = phase ladder: 0-4s normal / 4s no-PM / 8s forced-poll
                             // / 25s STA rx test. 0127 fp; 0131 DTC wrap; 0135 HID id;
                             // 0137 DTLS MTU; 0139 http chunked; 0145 hb; 0148 ap probe
                             // 1155 baseline (=1090 repro, BISECT_0826=1 kept);
                             // 2252 multi3 = 1155 + https.c 3-slot (P0-1), NOTHING else
                             // 2305 p0two = 2252 + rtc.c dtls_drive advance (P0-2)
                             // 0340 gate = STADIACAST-DIFF Top1/Top2/D9: GCSR armed by
                             //   v1:ResolveDiscovery (+0.6s, 30s fallback), post-handshake
                             //   STUN keepalive 2.5s, session reset after close/fatal alert
                             // 0355 align = STADIACAST-DIFF low-risk tail (D5/D6-f14/D7/D9):
                             //   GCSR ticket starts at 1 per boot (cloud.c mirror of
                             //   controller.py _rpc_ticket), SDP answer build_number f14
                             //   "stadia-local-receiver/0.1.0" (signaling.py:119),
                             //   DiscoverDisplay answers with the register display
                             //   id/token pair AND extracts its offer (fresh answer on
                             //   gmsg), new offer adopted -> full Ld session reset
                             //   (rtc_reset_display_session = reset_boot_state mirror)
#endif  // UAC1_ONLY (FW_BUILD tag)

// Three-phase diagnostic ladder (one flash isolates two variables):
//   0 .. 4s   default power management (CYW43_PERFORMANCE_PM == PM2 powersave), IRQ driven
//   4 .. 8s   CYW43_NONE_PM (true no-power-save) - does PM alone fix RX?
//   8s ..     + forced poll (bypass both host-wake pin gates) - is the IRQ the fault?
#define DIAG_NO_PM_AFTER_MS       4000
#define DIAG_FORCE_POLL_AFTER_MS  8000
// Phase 4: stop being an AP and join the phone's hotspot as a STA. This tests the
// chip's RECEIVE path independently of our AP (needs only a phone, no controller):
// if STA receives frames the chip/transport is fine and the fault is AP-specific.
// Phase 4 disables the AP and joins a hotspot. It was unconditionally ON, which is
// catastrophic on a real device: at t=25 s the AP disappears and NOTHING can associate
// afterwards, so every later attempt is tested against a dead AP. Off by default; turn
// it on only when deliberately running that experiment.
#define DIAG_ENABLE_STA_PHASE     0
#define DIAG_STA_TEST_AFTER_MS    25000

#define PORT_DNS         53
#define PORT_SNTP        123
#define PORT_HTTPS       443
#define PORT_DISPLAY     40000              // first WebRTC (display link)
#define PORT_GAME        40001              // second WebRTC (game session)

// ---- fastboot self-check / Clearcut (2026-11-04) ---------------------------------
// play.googleapis.com is BOTH the boot internet check name AND the Clearcut analytics
// host. It must RESOLVE (else slow 3-round discovery ritual) but the upload must FAIL
// (else §9.83: power off ~0.3 s after a successful upload). The reference "live" preset
// (proven end-to-end on ota.282115) resolves the name and blocks at TLS.
#define CLEARCUT_DNS_NXDOMAIN 0  // 1 = §9.83 legacy: NXDOMAIN for play.googleapis.com
                                 //     (safe but the boot check fails -> yellow/red ritual).
                                 // 0 = answer our IP like every other name (fastboot).
#define CLEARCUT_BLOCK_TLS    0  // 1 = refuse the TLS handshake when the ClientHello SNI
                                 //     is play.googleapis.com (fatal handshake_failure, the
                                 //     reference clearcut_block="tls" behaviour). Failed
                                 //     uploads are requeued 60 s out - harmless.
#define CLEARCUT_REPLY        1  // /log/batch answer if CLEARCUT_BLOCK_TLS=0 or the SNI
                                 //     scan missed. 0 = 204 empty (soft fail; real Google
                                 //     never 204s Clearcut, so the uploader should treat it
                                 //     as a failed upload). 1 = 200 empty. 2 = 200 +
                                 //     LogResponse{next=30 min} (receiver.py _clearcut
                                 //     verbatim) - KNOWN LETHAL per §9.83, experiments only.

// WireHeader2 message ids on the wire (byte 2-3 LE)
#define WID_CTRL_RPC     0x0074             // controller -> us (display link)
#define WID_DISP_RPC     0x0075             // us -> controller
#define WID_INPUT        0x0066             // game session input channel
#define WID_GAME_RPC     0xFFFA             // game session RPC channel

// RPC envelope: RpcMessage{request{f1:ticket, f2:payload}} / response{f1,f2:status,f3:err}
// ControllerToDisplay tags (payload of the controller's requests/notifications):
#define CTD_STATE_RESP   2                  // GetControllerStateResponse
#define CTD_INPUT        3                  // input report notification
#define CTD_PROXY_REQ    1                  // ProxyRequest (game envelope)
#define CTD_HEARTBEAT    14                 // empty keepalive (1.5s)
#define CTD_TIME_REQ     18                 // GetCurrentTimeRequest (3s)

// DisplayToController tags (what we send):
#define DTC_STATE_REQ    2                  // GetControllerStateRequest (until answered)
#define DTC_PROXY_RESP   1                  // ProxyResponse (game envelope reply)
#define DTC_START_GAME   8                  // StartGame {value:key, number:1}
#define DTC_TIME_RESP    21                 // inside response payload; see proto.c
#define DTC_SET_AUDIO_MODE 16               // SetAudioModeRequest{1: mode} (mode 2 = WebRTC Opus)

// Audio (speaker) path: PC-verified recipe constants, PLAYBOOK 3.6z6 + audio-tone.cjs.
#define AUDIO_PT         111                // Opus payload type (m=audio SAVPF 111)
#define AUDIO_SSRC       0x05A17D1Au        // sender SSRC (device learns it from packets)
#define AUDIO_FRAME_MS   20                 // device builds 20 ms buffers (emu37) -> 960 ts
#define AUDIO_TS_STEP    960                // 48000 Hz * 20 ms
// Wire id of the tag16 SetAudioMode attach RPC. pc-peer sends it on 0x74 (display-rpc.cjs
// muxFrame(CH)); the stadiacast "live" preset sends all display RPCs on 0x75 and our own
// p3-2300 run showed 0x75 reaches the audio logic too (log 220015: "disp notif: t=1
// pl=51 tag=4" AudioConfigurationChanged{mode:2,...} right after the attach). Default is
// pc-peer's 0x74 to mirror the audibly-verified recipe byte for byte; flip to
// WID_DISP_RPC if the tag=4 ack ever stops coming on 0x74.
#define AUDIO_ATTACH_WID 0x0074

// USB-audio -> Opus encoder knobs (route B phase 2, usb_audio.c).
// p3-3624: the encoder MUST match the PC-verified recipe (PLAYBOOK 3.6z6 /
// audio-tone.cjs): 48 kHz STEREO, 20 ms frames. The tone frames that are audible
// on real hardware are 48k stereo; the previous 16 kHz MONO live encoder produced
// low-frequency garbage on the controller's decoder (real-machine 2026-11-06:
// TONE audible, PC audio only buzzed). The UAC1 capture is already 48k stereo s16,
// so the live path now feeds the encoder directly - no resampling at all.
// If OPUSBENCH ever misses the <10 ms/frame budget, lower COMPLEXITY first.
#define AUDIO_OPUS_RATE       48000
#define AUDIO_OPUS_CHANNELS   2
#define AUDIO_OPUS_BITRATE    96000           // VBR, application AUDIO (48k stereo)
#define AUDIO_OPUS_COMPLEXITY 1
#define AUDIO_BENCH_FRAMES    500             // frames per OPUSBENCH phase

// absl status codes
#define ST_OK            0
#define ST_NOT_FOUND     5
#define ST_UNIMPLEMENTED 12
#define ST_INTERNAL      13
