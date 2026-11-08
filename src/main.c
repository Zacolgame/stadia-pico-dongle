// main.c — stadia-one: the whole cloud on a Pico 2 W, core 0 side.
//
// p3-3600-dualcore: the firmware is split across the RP2350's two Cortex-M33
// cores. Everything in this file (and the network/cloud modules it drives) stays
// on CORE 0, unchanged in spirit:
//
//   core0 (here):  CYW43 poll mode + lwIP, fake cloud HTTPS/TLS, ICE/DTLS/SRTP,
//                  RTP pacing, display/game session state machines, the main loop
//   core1 (core1_main.c): TinyUSB device stack (tud_task in a tight loop), UAC1
//                  iso capture -> 20 ms PCM blocks -> IPC ring, the XInput pad IN
//                  report, the CDC console
//
// They talk ONLY through src/ipc.c (lock-free SPSC rings + snapshots). The old
// 1 ms repeating alarm that called tud_task() from timer-IRQ context on core 0
// is gone: it was the WiFi-rx starvation suspect (PLAYBOOK: uac @500us = rx=0)
// and it still left the iso endpoint re-arm at the mercy of the alarm phase.
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/bootrom.h"
#include "hardware/watchdog.h"
#include "pico/cyw43_arch.h"
#include "net_infra.h"
#include "cloud.h"
#include "https.h"
#include "rtc.h"
#include "usb_hid.h"
#include "ipc.h"
#include "hfault.h"
#include "ramlog.h"
#include "config.h"

volatile int ap_err = 0;   // >0: cyw43 init error; <0: ap_enable error

// --- diagnostics / IRQ workaround -------------------------------------------------
// After FORCE_POLL_AFTER_MS the driver stops trusting the host-wake pin and polls
// the gSPI F2_PACKET_AVAILABLE status bit instead. Phase 1 (0..8s) = normal IRQ-driven,
// phase 2 (>=8s) = forced. Comparing the two phases in one boot tells us whether the
// IRQ line is the thing that is broken.
extern volatile int g_cyw43_force_poll;
extern int rtc_cert_rc, rtc_key_rc;
extern int rtc_dtls_selftest(void);
extern void cyw43_schedule_internal_poll_dispatch(void (*func)(void));
// CDC console commands that must execute on core0 (the state they touch lives here);
// the core1 parser only queues an IPC command id.
extern void rtc_request_dtls_selftest(void);
extern void rtc_audio_tone_start(uint32_t ms);
extern void rtc_audio_test_raw(void);
extern void rtc_rumble_pulse(void);
extern void cloud_encoder_dump(void);

// ---- core1 liveness -------------------------------------------------------------
// p3-3604 STAGE DIAGNOSTIC: core1 increments an IPC beat every loop pass. If it
// stops, core0 reads the stage core1 was in and encodes it into the delay before
// dropping into the ROM bootloader (stage*2 s) - that makes a core1 hang
// diagnosable without a working console, and recovery automatic.
// Healthy() returns true until the beat is stale for >5 s.
static bool core1_healthy(void) {
    static uint32_t last_beats;
    static uint32_t last_change_ms;
    static bool warned;
    uint32_t beats = ipc_core1_beats();
    uint32_t now = to_ms_since_boot(get_absolute_time());
    if (!last_change_ms) last_change_ms = now ? now : 1;
    if (beats != last_beats) {
        last_beats = beats;
        last_change_ms = now;
        warned = false;
        return true;
    }
    if (now - last_change_ms > 5000) {
        if (!warned) {
            warned = true;
            FWLOG("FATAL: core1 no beat for %u ms (stage=%u)",
                  (unsigned)(now - last_change_ms), (unsigned)ipc_diag_stage_get());
        }
        return false;
    }
    return true;
}

// ---- core-1 -> core-0 console commands ----------------------------------------
static void core0_command_pump(void) {
    uint8_t cmd;
    while (ipc_cmd_pop(&cmd)) {
        switch (cmd) {
        case IPC_CMD_TONE:
            rtc_audio_tone_start(2500);
            FWLOG("host: tone requested (2500ms)");
            break;
        case IPC_CMD_RUMBLE:
            rtc_rumble_pulse();
            FWLOG("host: rumble pulse requested (200ms/75%%)");
            break;
        case IPC_CMD_DTLS_TEST:
            rtc_request_dtls_selftest();
            FWLOG("host: DTLS self test requested");
            break;
        case IPC_CMD_ENCDUMP:
            cloud_encoder_dump();
            break;
        case IPC_CMD_AUDPTEST:
            rtc_audio_test_raw();
            FWLOG("host: audptest requested (one raw RTP frame)");
            break;
        default:
            break;
        }
    }
}

int main(void) {
    stdio_init_all();
    // Mirror ALL stdio (notably panic/assert text, otherwise lost to the
    // unconnected UART) into retained SRAM; dumped by ramlog_dump() below.
    stdio_set_driver_enabled(&ramlog_driver, true);
    // IPC first: every FWLOG from here on goes into the per-core log rings, and
    // core1 is launched below (ipc_init must precede the launch).
    ipc_init();
    // Hardware watchdog: if any code path ever wedges the main loop (which also kills USB,
    // making the CDC port un-openable and requiring a physical replug), reboot.
    // The loop kicks it on every pass (as long as core1 is alive - see core1_healthy),
    // so only a real hang trips it.
    // 12000 ms, not 3000: one main-loop pass can legally contain an RSA-2048 private
    // operation (TLS ClientKeyExchange decrypt in https drive()), which takes 2-4 s on
    // this CPU. With a 3 s timeout the WDT reset mid-RSA whenever the op ran slow -
    // that looked like a silent hang at the /gmsg connection (PLAYBOOK 9.97: three
    // resets, last hb showed slot ssl.state=8 with unflushed tx). 12 s gives ~4x
    // headroom over the slowest legitimate pass while still recovering real hangs.
    watchdog_enable(30000, 1);
    int rc_init = cyw43_arch_init();   // EXACTLY like the official example (default country)
    if (rc_init) { ap_err = 100 + rc_init; }
    // core1: the USB island. Launched before the network bring-up so USB enumeration
    // proceeds while core0 is still initialising the fake cloud (~1-2 s) - the host
    // only tolerates a short delay before it gives up on the device.
    // NOTE: multisore launch uses OUR 16 KiB stack buffer (core1_main.c); the SDK
    // default is a 4 KiB SCRATCH_X stack, too small for the Opus encoder.
    // p3-3605 MONITORED FULL BUILD: the real dual-core code, but core1 publishes
    // progress marks and core0 turns a stalled heartbeat into a ROM-bootloader
    // reset after stage*2 s so a hang is both localised and self-recovering.
    multicore_launch_core1_with_stack(core1_main, core1_stack_area(), core1_stack_bytes());
    cloud_init();
    net_infra_init();     // AP + DHCP + DNS + SNTP (safe from lwIP raw-API thread via cyw43 init)
    rtc_init();           // STUN/DTLS endpoints (needs tcpip context: run via callback)
    https_init();         // TLS 443
    // p3-3641: the Opus encode runs on CORE 0 now (rtc_tick); core1 only pumps
    // UAC1 PCM into the IPC ring, so the iso OUT endpoint is never blocked.
    FWLOG("boot: build=%s wdt=%d cyw43 rc=%d cores=2 usb=core1 audio=core1pcm/core0opus",
          FW_BUILD, watchdog_caused_reboot() ? 1 : 0, rc_init);
    // p3-3626: if the PREVIOUS boot ended in a watchdog reset, the last core0 log
    // line survived in NOLOAD SRAM - print it now, it says where the 12 s stall was.
    {   // p3-3629: heap headroom = RAM end - end of bss. The controller opens three
        // concurrent TLS connections and each ssl_setup mallocs its record buffers
        // from this pool, so the number must stay well above ~60 KiB (4 KB records:
        // ~12-15 KiB per connection) or registration dies silently.
        // p3-3646: libopus's pseudostack is STATIC .bss now (48 KiB, canaried), so
        // __end__ already sits above it and heap_total is the REAL working pool -
        // there is no runtime malloc to subtract any more. Printed for the record.
#ifndef OPUS_STATIC_SCRATCH_BYTES
#define OPUS_STATIC_SCRATCH_BYTES 49152
#endif
        extern char __end__[], __HeapLimit[];
        uint32_t heap_total = (uint32_t)((uintptr_t)__HeapLimit - (uintptr_t)__end__);
        FWLOG("heap: %u bytes total, opus pseudostack %u B is static .bss (already excluded; mbedTLS needs ~45K for 3 concurrent TLS)",
              (unsigned)heap_total, (unsigned)OPUS_STATIC_SCRATCH_BYTES);
    }
    {
        char pl[124]; uint32_t pms = 0;
        int pn = ipc_prev_log_copy(pl, (int)sizeof pl, &pms);
        if (pn > 0) {
            FWLOG("PREVRESET t=%u last-line: %s", (unsigned)pms, pl);
            char ph[100];
            if (ipc_prev_https_copy(ph, (int)sizeof ph) > 0)
                FWLOG("PREVRESET https: %s", ph);
            ipc_prev_log_clear();
        }
    }
    // p3-3646 HFAULT BLACKBOX (ported from variant A): if the PREVIOUS boot died
    // on a HardFault (on EITHER core) the custom handler captured the stacked
    // frame + fault status registers into NOLOAD SRAM and rebooted immediately.
    // Print it here, then clear the magic so a later clean boot cannot report a
    // stale fault (a copy is kept for this boot: CDC "HFAULT" re-prints it).
    // pc is the faulting instruction: addr2line it against build/stadia_one.elf.
    {
        bool shown = false;
        for (int c = 0; c < HFAULT_MAX_CORE; c++) {
            hfault_rec_t hf;
            if (!hfault_copy(c, &hf)) continue;
            hfault_log(&hf);
            hfault_clear(c);
            shown = true;
        }
        if (!shown) {
            uint32_t sc[4];
            if (hfault_scratch_read(sc)) {
                FWLOG("HFAULT-R core=%u pc=%08x cfsr=%08x lr=%08x (scratch copy only: SRAM record lost)",
                      (unsigned)(sc[0] & 1u), (unsigned)sc[1], (unsigned)sc[2],
                      (unsigned)sc[3]);
            }
        }
        hfault_scratch_clear();
    }
    ramlog_dump();   // retained stdio (panic/assert text) from the previous boot, if any
    absolute_time_t last_tick = get_absolute_time();
    absolute_time_t last_rtc = last_tick;
    bool nopm = false, forced = false, sta_tried = false;
    while (true) {
        uint32_t up = to_ms_since_boot(get_absolute_time());
        if (!nopm && up >= DIAG_NO_PM_AFTER_MS) {
            nopm = true;
            // CYW43_DEFAULT_PM is actually CYW43_PERFORMANCE_PM = PM2 powersave.
            // An AP must stay awake to receive its clients' frames; try true none-PM.
            int prc = cyw43_wifi_pm(&cyw43_state, CYW43_NONE_PM);
            FWLOG("DIAG: phase2 no-power-save (cyw43_wifi_pm rc=%d)", prc);
        }
        if (!forced && up >= DIAG_FORCE_POLL_AFTER_MS) {
            forced = true;
            g_cyw43_force_poll = 1;
            FWLOG("DIAG: phase3 forced-poll (both host-wake pin gates bypassed)");
        }
        if (DIAG_ENABLE_STA_PHASE && !sta_tried && up >= DIAG_STA_TEST_AFTER_MS) {
            sta_tried = true;
            // Only run the STA experiment when the AP path is still dead. If the
            // mitigations from phase 2/3 already fixed reception, tearing the AP down
            // here would destroy a working setup.
            extern volatile uint32_t g_eth_rx_total;
            if (g_eth_rx_total > 0) {
                FWLOG("DIAG: phase4 SKIPPED - rx already works (%u frames), keeping AP up",
                      (unsigned)g_eth_rx_total);
                goto phase4_done;
            }
            // Tear the AP down and become a client of the phone hotspot. Any frame we
            // receive here proves the chip's rx path itself works, which separates
            // "chip/transport broken" from "AP-mode forwarding broken". No DHCP client is
            // compiled in, so an IP is not expected - only received frames matter.
            FWLOG("DIAG: phase4 STA rx test -> joining ssid=%s", WIFI_SSID);
            cyw43_arch_disable_ap_mode();
            cyw43_arch_enable_sta_mode();
            int rc = cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASS,
                                                        CYW43_AUTH_WPA2_AES_PSK, 15000);
            FWLOG("DIAG: phase4 wifi_connect rc=%d sta_link=%d", rc,
                  cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA));
        }
    phase4_done:
        // A stalled core1 -> ROM bootloader after stage*2 s (delay encodes the hang
        // stage). Keep feeding the watchdog during the wait so the WDT cannot fire
        // before the ROM handoff.
        {
            static bool fell;
            bool alive = core1_healthy();
            watchdog_update();
            if (!alive && !fell) {
                fell = true;
                uint8_t st = ipc_diag_stage_get();
                uint32_t wait_ms = (uint32_t)st * 2000u;
                FWLOG("DIAG: core1 stalled at stage %u -> ROM bootloader in %u ms",
                      (unsigned)st, (unsigned)wait_ms);
                for (uint32_t k = 0; k < wait_ms; k += 250u) {
                    watchdog_update();
                    sleep_ms(250);
                }
                reset_usb_boot(0, 0);        // does not return
            }
        }
        cyw43_arch_poll();   // poll mode: we drive the chip+lwIP from this loop
        if (forced) {
            // make sure the driver actually drains the chip even if no IRQ arrived
            cyw43_schedule_internal_poll_dispatch(cyw43_poll);
        }
        core0_command_pump();   // CDC commands relayed from core1
        // rtc_tick at 20 ms (was 50): the speaker pump needs one 20 ms Opus frame
        // per pass (pc-peer recipe: 50 packets/s, ts+960). Everything else inside
        // rtc_tick is time-gated (>=500 ms..2 s), so the faster cadence is inert for it.
        if (absolute_time_diff_us(last_rtc, get_absolute_time()) >= 20000) {
            last_rtc = get_absolute_time();
            rtc_tick();
        }
        if (absolute_time_diff_us(last_tick, get_absolute_time()) >= 50000) {
            last_tick = get_absolute_time();
            https_poll();
            // RA lifetime=0 (p3-3050-ipv6ra): periodic 5 s + RS-triggered. Must stay
            // OUTSIDE cyw43_arch_poll - cyw43_send_ethernet needs the async-context
            // lock, which the poll call above may already hold on this core.
            net_infra_ipv6_tick();
            uint32_t ms = to_ms_since_boot(get_absolute_time());
            // Periodic banner: the one-shot boot lines are lost if the user opens the
            // CDC port a few seconds late, which would leave the log without even the
            // build tag or the DTLS fingerprint. Repeating them keeps any capture usable.
            {
                static uint32_t last_banner;
                if (last_banner == 0 || ms - last_banner >= 15000) {
                    last_banner = ms ? ms : 1;
                    char asid[24] = ""; int ams = 0, ach = 0, aau = 0;
                    net_infra_ap_info(asid, sizeof asid, &ams, &ach, &aau);
                    FWLOG("ap ssid=[%s] maxassoc=%d ch=%d auth=0x%x", asid, ams, ach, (unsigned)aau);
                    FWLOG("hb build=%s dsel=%d cloud=%d sta=%d crt=%d key=%d pcbs=%d enum=%d c1=%u aud=%d fp=%s", FW_BUILD,
                          rtc_dtls_selftest(),
                          cloud_state, net_infra_client_associated() ? 1 : 0,
                          rtc_cert_rc, rtc_key_rc, rtc_pcb_mask(),
                          ipc_enum_count(),
                          (unsigned)ipc_core1_beats(),
                          ipc_audio_stream_get() ? 1 : 0,
                          cloud_cert_fingerprint()[0] ? cloud_cert_fingerprint() : "(NONE)");
                }
            }
            static uint32_t last_diag;
            if (ms - last_diag >= 1000) {
                last_diag = ms;
                char dbg[192];
                net_infra_diag(dbg, sizeof dbg);
                // Per-slot HTTPS state in the 1 Hz line: the last heartbeat before a
                // wedge shows which connection was mid-handshake/headers/response.
                char hd[96];
                https_diag(hd, sizeof hd);
                ipc_prev_https_set(hd);   // survives a watchdog reset for diagnosis
                FWLOG("t=%u ap=%d sta=%d st=%d err=%d au=%d %s %s", (unsigned)ms,
                      net_infra_ap_beaconing(), net_infra_client_associated(),
                      (int)cloud_state, ap_err, rtc_audio_frames_sent(), dbg, hd);
            }
            // LED diagnostics: 1 long = AP DOWN; double-blink = AP up no client;
            // fast = client joined; solid = game session
            static uint32_t phase;
            bool on;
            if (ap_err) {  // blink out |ap_err| pulses per 2s window
                int n = ap_err < 0 ? -ap_err : ap_err; if (n > 8) n = 8;
                phase = ms % 2000;
                on = false;
                for (int k = 0; k < n; k++) if (phase >= (uint32_t)(k * 200) && phase < (uint32_t)(k * 200 + 100)) on = true;
            }
            else if (rtc_game_connected()) on = true;
            else if (rtc_display_ready()) on = (ms / 62) & 1;
            else if (net_infra_client_associated()) on = (ms / 100) & 1;
            else if (net_infra_ap_beaconing()) { phase = (ms % 1000); on = phase < 100 || (phase >= 250 && phase < 350); }
            else { phase = (ms % 1500); on = phase < 700; }
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, on);
        }
        sleep_ms(2);
    }
}
