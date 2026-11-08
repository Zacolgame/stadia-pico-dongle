// core1_main.c — RP2350 core 1 entry point (p3-3600-dualcore).
//
// Everything that needs a hard real-time or a "always responsive" guarantee runs
// here, isolated from the network stack on core 0:
//
//   TinyUSB device stack (tud_task loop, no timer-IRQ proxy any more)
//   UAC1 iso OUT capture (TinyUSB audio class -> fifo -> 20 ms PCM -> IPC ring)
//   the XInput vendor pad IN report (fed by the core0 pad snapshot)
//   the CDC console (log ring drain + the host command parser)
//
// p3-3641-core0encode: the Opus encode moved to core0 (src/rtc.c + usb_audio.c),
// so core1 must never block on a codec between tud_task() passes - that 7.9 ms
// encode was starving the single-buffered iso OUT endpoint.
//
// Core 0 keeps WiFi/lwIP, the fake cloud, ICE/DTLS/SRTP and the RTP pacing; the
// two sides talk only through src/ipc.h.
//
// Why this fixes the WiFi/USB conflict: on core 0 the 1 ms repeating alarm used
// to call tud_task() from timer-IRQ context, which (a) doubled the timer IRQ
// rate and starved the CYW43 host-wake GPIO IRQ / cyw43_poll servicing (the
// 2026-11-06 rx=0 signature) and (b) still left iso re-arm at the mercy of the
// alarm phase. On core 1 tud_task() runs in a tight loop - USB events are
// drained within microseconds, control transfers never wait seconds behind an
// RSA-2048 operation, and the iso OUT endpoint is re-armed by the very next
// iteration after the transfer-complete event.
#include "pico/stdlib.h"
#include "tusb.h"
#include "ipc.h"
#include "usb_hid.h"
#include "usb_audio.h"
#include "config.h"

// 16 KiB core1 stack in main SRAM (not SCRATCH_X). p3-3641: the Opus encoder -
// which needed 33,332 B of VLA stack for 48 kHz stereo - is GONE from core1, so
// the 48 KiB stack it forced is back to the 16 KiB size that ran the no-opus
// dual-core build (p3-3608) stable on real hardware. p3-3646: libopus's
// pseudostack is a STATIC 48 KiB .bss buffer on core0 (canaried, see
// src/usb_audio.c), not a heap malloc, so it costs the mbedTLS pool exactly that
// 48 KiB at link time and nothing at runtime.
#define CORE1_STACK_BYTES (16 * 1024)
static uint32_t core1_stack[CORE1_STACK_BYTES / 4] __attribute__((aligned(8)));

uint32_t *core1_stack_area(void) { return core1_stack; }
uint32_t core1_stack_bytes(void) { return CORE1_STACK_BYTES; }

void core1_main(void) {
    // TinyUSB MUST be initialised on this core: dcd_init() installs the
    // USBCTRL_IRQ handler in the (shared) vector table and dcd_int_enable()
    // enables the IRQ in THIS core's NVIC, so USB interrupts are delivered to
    // core1 only. Core 0 never calls any tusb_*/tud_* function.
    ipc_diag_stage_set(1);     // about to init TinyUSB
    usb_hid_init();            // tusb_init() + descriptor self-check (+WCID/MS OS)
    ipc_diag_stage_set(2);     // TinyUSB up (tud_task not yet called)
    usb_audio_init();

    // Mount-gated warm-up: the class data paths start only after the host has
    // configured the device (tud_mount_cb -> ipc_enum_count != 0) plus 200 ms of
    // settle time. The Opus-init hang it originally worked around is impossible
    // now (the encoder lives on core0), but keeping the gate preserves the proven
    // enumeration timing: USB must be up before any class data path runs.
    bool warm = false;
    uint32_t mounted_ms = 0;
    while (true) {
        tud_task();                  // drain USB events: control, class, mount/reset
        ipc_core1_beat();            // liveness for core0's watchdog gate
        if (!warm && ipc_enum_count()) {
            uint32_t now = to_ms_since_boot(get_absolute_time());
            if (!mounted_ms) mounted_ms = now ? now : 1u;
            if (now - mounted_ms >= 200u) {
                ipc_diag_stage_set(3);
                ipc_diag_stage_set(4);
                warm = true;
                FWLOG("core1: warm-up done (usb+hid+cdc on core1, stack=%uB, pcm->core0)",
                      (unsigned)CORE1_STACK_BYTES);
            }
        }
        if (warm) {
            ipc_diag_stage_set(5); usb_audio_core1_tick();
            ipc_diag_stage_set(6); usb_hid_task();
            ipc_diag_stage_set(7); usb_hid_pump_cdc();
        }
        tight_loop_contents();
    }
}
