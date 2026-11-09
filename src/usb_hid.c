// usb_hid.c — TinyUSB vendor XInput pad (Xbox 360 wired controller identity)
// + CDC console: pad state in, rumble out.
//
// p3-3600-dualcore: THIS FILE NOW RUNS ON CORE 1. Together with usb_audio.c it
// is the whole core-1 USB island: tud_task() is called from core1_main's tight
// loop (the old 1 ms repeating alarm on core 0 is GONE), the pad state arrives
// through ipc_pad_read() (core0 decodes the WiFi input), the rumble OUT frame is
// handed to core0 through rtc_send_rumble() -> ipc_rumble_push(), the log ring is
// drained here (core1 owns the CDC), and CDC console commands that touch core-0
// state (TONE/RUMBLE/AUDPTEST/DTLSTEST/ENCDUMP) are queued via ipc_cmd_push().
// Every TinyUSB call in the firmware is now on this core, which is also why the
// old "mask IRQs around every TinyUSB call" dance (the 1 ms alarm preempting the
// main loop) is no longer needed - the USB ISR only enqueues events; callbacks
// are dispatched by tud_task() in this loop.
//
// Build variants (bisect ladder, see src/config.h):
//   default        full composite: UAC1 audio if0-1 + CDC if2-3 + XInput if4.
//   UAC1_CDC_ONLY  (p3-3190) audio + CDC only: the gamepad interface is compiled
//                  out - the middle rung of the composite bisection. Everything
//                  gamepad lives inside "#if !UAC1_ONLY && !UAC1_CDC_ONLY"
//                  blocks below.
//   UAC1_ONLY      (p3-3170) audio only: no CDC, no gamepad, no IAD.
//
// p3-3500 plugplay: interface 4 is the VENDOR XInput function again (restored
// byte-exact from p3-3180/57537e3): class 0xFF/0x5D/0x01, the 17-byte 0x21
// xusb capability blob, EP 0x81 IN (20-byte input report) + EP 0x01 OUT
// (8-byte rumble frame), and the whole MS OS 1.0 WCID exchange (0xEE string
// probe + XUSB10 ext-compat replies) that makes Windows' inbox xusb22.sys
// bind the child as "Xbox 360 Controller for Windows" - XInput games work
// with ZERO configuration, which the p3-3200 standard-HID pad could not
// offer (DirectInput only). The interim standard-HID interface is deleted.
// The p3-3200 lesson is kept where it still applies: no HID report
// descriptors exist at all any more, so the p3-2215 hidparse Code 10 surface
// stays gone. Everything else from the p3-3300/3400 line is preserved: the
// audio function stays on TinyUSB's OWN vendored 98741b55 UAC1 driver.
//
// TinyUSB side: the builtin vendor_device class claims the 0xFF interface
// (vendord_open matches ANY vendor-class interface, opens its interrupt
// endpoints and auto-re-arms the OUT endpoint after every frame).
// CFG_TUD_VENDOR_*_BUFSIZE are 0 (tusb_config.h) so tud_vendor_n_write arms
// the IN endpoint directly with our 20 bytes and tud_vendor_rx_cb hands us
// each OUT frame - no fifos, no bulk-64 assumptions.
#include "rtc.h"
#include "usb_audio.h"
#include "ipc.h"
#include "hfault.h"
#include "config.h"
#include "pico/stdlib.h"
#include <string.h>
#include <stdio.h>
#include "tusb.h"
#include "pico/bootrom.h"
#include "pico/time.h"
#include "device/usbd.h"
void clog_(const char *fmt, ...);   // defined at the bottom of this file; the
                                    // rumble callback up here logs too
#if !UAC1_ONLY   // CDC console is compiled out of the audio-only bisect build
                 // (tusb_config.h: CFG_TUD_CDC 0); present in the composite
                 // AND the UAC1_CDC_ONLY bisect (the COM port is half of its
                 // read-out).
#include "class/cdc/cdc_device.h"
#endif
#if !UAC1_ONLY && !UAC1_CDC_ONLY   // XInput vendor interface: FULL composite
                 // only (tusb_config.h: CFG_TUD_VENDOR 0 in both bisect
                 // builds).
#include "class/vendor/vendor_device.h"
#endif

#if !UAC1_ONLY && !UAC1_CDC_ONLY   // XInput vendor interface: compiled out of
                 // the audio-only AND the UAC1+CDC bisect builds (each drops
                 // exactly one suspect from the failing full composite; the
                 // UAC1_CDC_ONLY rung drops THIS one).
// Wired Xbox 360 pad input report (EP 0x81 IN, exactly 20 bytes):
//   [0] 0x00 (input)  [1] 0x14 (size)  [2]+[3] wButtons LE  [4] LT  [5] RT
//   [6..9] LX,LY s16 LE  [10..13] RX,RY s16 LE  [14..19] zero. Y is positive UP.
typedef struct __attribute__((packed)) {
    uint8_t type;        // 0x00
    uint8_t size;        // 0x14 (20)
    uint8_t buttons[2];  // wButtons, little-endian
    uint8_t lt, rt;      // triggers, 0..255 direct
    int16_t lx, ly, rx, ry;  // little-endian host == wire order
    uint8_t zero[6];
} xinput_report_t;
_Static_assert(sizeof(xinput_report_t) == 20, "XInput wired report is 20 bytes");

// pad.buttons (Message3 f1) is ALREADY the XInput wButtons layout for bits 0-9
// and 12-15 - stadiacast gamepad.py documents the live mapping: dpad 0-3, Menu(4)="≡"=
// XInput START, Options(5)="⋯"=XInput BACK, L3/R3 6-7, L1/R1 8-9 = LB/RB, A/B/X/Y
// 12-15. Only two edits: Assistant(10)/Capture(11) have no XInput slot (dropped),
// and the Stadia logo (bit 16 - pad.buttons is u32 since p3-2340 for exactly this)
// becomes the guide bit 0x0400 (XInputGetStateEx). Sticks pass through unchanged:
// Message3 Y is positive up, same as XInput, full s32 -> s16 (values are s16 range).
// pad_state_t comes from core0 through the seqlock snapshot (ipc_pad_read);
// this function therefore takes the snapshot instead of reading the global.
static void xinput_build(xinput_report_t *r, const pad_state_t *p) {
    uint32_t b = p->buttons;
    uint16_t w = (uint16_t)(b & 0xF3FF);      // drop Assistant(10) + Capture(11)
    if (b & (1u << 16)) w |= 0x0400;          // Stadia logo -> Guide
    memset(r, 0, sizeof *r);
    r->type = 0x00;
    r->size = 0x14;
    r->buttons[0] = (uint8_t)(w & 0xFF);
    r->buttons[1] = (uint8_t)(w >> 8);
    r->lt = p->lt;
    r->rt = p->rt;
    r->lx = p->lx; r->ly = p->ly; r->rx = p->rx; r->ry = p->ry;
}

// Set while the IN endpoint carries an armed report; cleared by tud_vendor_tx_cb
// (inside core1's tud_task). We only arm a new report when it is clear - the
// RP2040 dcd has no claim/busy flow control (dcd_edpt_xfer just calls
// hw_endpoint_xfer), so arming twice would corrupt the endpoint state.
// Both toucher and setter are core1 (tud_task / the core1 loop), so no masking.
static volatile bool xinput_in_busy;
static xinput_report_t prev;   // starts all-zero, which differs from the neutral
                              // report (type 0x00 / size 0x14 header), so exactly ONE
                              // neutral report is sent right after enumeration and
                              // after that only real input changes the wire

void tud_vendor_tx_cb(uint8_t itf, uint32_t sent_bytes) {
    (void)itf; (void)sent_bytes;
    xinput_in_busy = false;   // IN endpoint idle again (core1 tud_task context)
}

// OUT EP 0x01 frame, delivered by core1's tud_task (callback context, not IRQ):
// byte 0 command, byte 1 length. Rumble (cmd 0x00, len 0x08): [2]=mode, [3]=LEFT
// motor (the large low-frequency one), [4]=RIGHT motor (small/high). LED frames
// (cmd 0x01) are ignored - this pad has no LED ring. u8 0..255 scales to the
// 0..0xFFFF amplitude scale by v*257.
void tud_vendor_rx_cb(uint8_t itf, uint8_t const *buffer, uint16_t bufsize) {
    if (itf != 0) return;
    if (bufsize >= 5 && buffer[0] == 0x00 && buffer[1] == 0x08) {
        uint16_t l = (uint16_t)((buffer[3] << 8) | buffer[3]);   // large  -> left
        uint16_t r = (uint16_t)((buffer[4] << 8) | buffer[4]);   // small  -> right
        // Queue to core0, which owns the rumble state and the single send point
        // (rtc_tick's rumble_flush). Review P1-9: call ipc_rumble_push() directly
        // instead of the core0 rtc_send_rumble(), so no "core0 function changes
        // behaviour by core" trap exists.
        ipc_rumble_push(l, r);
    }
}
#endif  // !UAC1_ONLY && !UAC1_CDC_ONLY (XInput vendor interface)

// ---- tud_task scheduling: core1 owns it now (p3-3600-dualcore) ----------------
//
// HISTORY (kept so nobody re-chases these): the HID Code 10 (CM_PROB_FAILED_START)
// on Windows was first blamed on tud_task() being pumped from the main loop
// (which disappears for SECONDS inside the network stack - an RSA-2048 private op
// in https drive() alone takes 2-4 s), so p3-2130 moved tud_task() into a
// repeating 1 ms hardware alarm. That was correct about control transfers (they
// MUST be serviced within 1 ms) but the real Code 10 root cause was the old HID
// report descriptor's usage-less Output main item - the XInput switch deleted that
// surface entirely. The alarm then became the WiFi-rx suspect: p3-3400 proved
// that a 500 us alarm period produced the old `rx=0` signature on real hardware.
// The dual-core split resolves the tension structurally: tud_task() now runs in
// core1's tight loop (sub-100 us latency, iso OUT re-armed on the very next
// iteration) while CYW43/lwIP keep core0 to themselves - no timer-IRQ proxy, no
// core0 masking, no alarm-phase dependency.
//
// Concurrency: every TinyUSB API call in the firmware lives on core1 (this file,
// usb_audio.c, core1_main.c). Core0 never calls tusb_*/tud_*; it only reads/writes
// the IPC buffers in ipc.c. The USB ISR only enqueues events; class callbacks are
// dispatched by tud_task() in the core1 loop, so the old save_and_disable_interrupts()
// windows around TinyUSB calls (needed when a timer IRQ on the SAME core could
// preempt a mutex holder) have no counterpart here: there is no other core1 task
// to preempt, and cross-core traffic never touches TinyUSB state.

// ---- enumeration self-check (p3-2900): one-round real-machine localization ----
// The p3-2800-grand flash failed on Windows with every VID_045E node Unknown and
// no COM port. The offline audit (merge p3-2900) proved the usbd.c interface walk
// and the linked descriptor bytes correct, so the remaining suspects were
// Windows-side devnode-cache poisoning (bcdDevice bumped to 0x0106 for this) and
// anything only visible at runtime. These lines put the ACTUAL bytes and the
// ACTUAL enumeration milestones on the CDC log: if a later capture shows
// "self-check FAILED" the const placement/linker moved the descriptor; if
// "MOUNTED" never prints the device never finished SET_CONFIG; if the WCID
// line never prints usbccgp never probed. (p3-3300: the audio function is
// driven by TinyUSB's own class (vendored 98741b55), which logs nothing on
// claim - the first audio milestone is usb_audio.c's "uac1: set_itf" line
// when Windows selects an AS alt setting. p3-3500: the "usb: WCID ext-compat
// query" line is back with the restored WCID exchange - it proves usbccgp
// probed and the XUSB10 reply left the device.)
// (Self-check body lives after the descriptors it reads; forward-declared here.)
static void usb_desc_selfcheck(void);

void usb_hid_init(void) {
    // Core1 only (core1_main.c). tusb_init() -> tud_rhport_init() -> dcd_init()
    // installs USBCTRL_IRQ in the shared vector table and dcd_int_enable() turns
    // it on in THIS core's NVIC, so the USB interrupt belongs to core1 alone.
    tusb_init();
    usb_desc_selfcheck();
    // The p3-2130 1 ms repeating alarm is deliberately GONE: core1_main() calls
    // tud_task() directly in its tight loop (see the scheduling note above).
}

void usb_hid_task(void) {
    // Core1 context. tud_task() is driven by core1_main's loop, not here.
#if !UAC1_ONLY && !UAC1_CDC_ONLY
    if (!tud_vendor_n_mounted(0)) {   // bus reset / not configured yet
        xinput_in_busy = false;       // never leave the IN endpoint "armed" across a reset
        return;
    }
    // Pad state comes from core0's decode via the IPC seqlock. A torn/absent
    // read keeps the last good snapshot (the reader retries internally).
    static pad_state_t snap;
    pad_state_t p;
    if (ipc_pad_read(&p)) snap = p;
    xinput_report_t rpt;
    xinput_build(&rpt, &snap);
    if (memcmp(&rpt, &prev, sizeof rpt)) {
        if (!xinput_in_busy) {
            // fifo-less write == arm the IN endpoint with exactly these 20 bytes
            if (tud_vendor_n_write(0, &rpt, sizeof rpt) == sizeof rpt)
                { xinput_in_busy = true; memcpy(&prev, &rpt, sizeof rpt); }
        }
    }
#endif
}

// ---- USB descriptors ----
#if UAC1_ONLY
// Audio-only bisect device (p3-3170): a CLASS 0x01 USB speaker, the classic
// driverless full-speed layout - no IAD, no MISC composite class, no WCID.
// VID/PID 0x0D8C:0x013C is the C-Media USB audio dongle identity: Windows'
// inbox usbaudio.sys binds it (and USB\Class_01 compatible ids) with zero
// install, so the only variable left in the bisect is our own descriptor
// bytes. bcdDevice 0x0200 = a fresh devnode, nowhere near the 0x010x range
// the failing composites used (Windows caches binding state per REV).
static const tusb_desc_device_t desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0x01, .bDeviceSubClass = 0x00, .bDeviceProtocol = 0x00,   // plain Audio
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x0D8C, .idProduct = 0x013C,
    .bcdDevice = 0x0202,   // bumped p3-3300: TinyUSB-vendored UAC1 driver + the
                            // 9/7-byte EP/CS-EP descriptor forms; fresh REV so
                            // usbaudio.sys re-parses. History: 0x0201 p3-3180
                            // (iso EP address fixed 0x84->0x04); 0x0200 first
                            // audio-only bisect (broken IN-endpoint function).
    .iManufacturer = 0x01, .iProduct = 0x02, .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01,
};
#elif UAC1_CDC_ONLY
// UAC1+CDC bisect device (p3-3190): same IAD composite identity as the full
// build (class EF/02/01 - the CDC interface pair needs usbccgp, and VID/PID
// stay 0x045E:0xFFFF, unclaimed by any inbox INF), but bcdDevice 0x0202: a
// REV no Windows devnode has ever seen (0x0108 = the failing audio+CDC+
// XInput composite, 0x0201 = the working audio-only device - neither cached
// binding state must be reused), so usbccgp re-parses the 2-function layout
// from scratch. NO WCID in this build: the vendor control callback is
// compiled out, so the 0xEE probe stalls and Windows sees a plain 2-function
// class composite (usbaudio + usbser bind on standard compatible ids alone).
static const tusb_desc_device_t desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0xEF, .bDeviceSubClass = 0x02, .bDeviceProtocol = 0x01,   // IAD composite
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x045E, .idProduct = 0xFFFF,
    .bcdDevice = 0x0203,   // fresh devnode for the p3-3300 audio+CDC layout
                            // (TinyUSB-vendored UAC1 driver + 9/7-byte EP/CS-EP
                            // forms; same per-REV caching lesson as every bump
                            // in the composite branch below). History: 0x0202
                            // p3-3190 bisect with the handwritten driver.
    .iManufacturer = 0x01, .iProduct = 0x02, .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01,
};
#else
// (CDC console + vendor XInput pad + UAC1 audio composite)
static const tusb_desc_device_t desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    .bDeviceClass = 0xEF, .bDeviceSubClass = 0x02, .bDeviceProtocol = 0x01,   // IAD composite
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    // p3-2420 CDC-loss root cause: PID 0x028E made Windows' inbox xusb22.inf
    // match the DEVICE hardware id "USB\Vid_045E&Pid_028E" (device-level, beats
    // the USB\COMPOSITE compatible id), so xusb22.sys became the function
    // driver for the WHOLE device, usbccgp never loaded, the CDC interfaces
    // were never enumerated as child devnodes -> no COM port at all, while
    // XInput kept working (that is exactly how a real wired 360 pad binds).
    // The descriptors were never truncated - 3IF/5EP was already on the wire;
    // the identity itself was the bug. VID stays 0x045E (Xbox family), PID
    // stays 0xFFFF: not claimed by ANY inbox INF (verified against every
    // C:\Windows\INF\*.inf match on Vid_045E), so usbccgp loads and the XInput
    // interface binds through the MS OS "XUSB10" compatible id below.
    .idVendor = 0x045E, .idProduct = 0xFFFF,
    .bcdDevice = 0x0302,   // p3-3500-plugplay: the standard-HID gamepad of
                            // 0x0300/0x0301 is replaced by the vendor XInput
                            // interface (restored byte-exact from p3-3180) +
                            // the WCID exchange, and the speaker source goes
                            // fully automatic (USB audio detected = play, gone
                            // >100 ms = mute). Fresh REV so Windows re-parses
                            // the whole topology AND re-runs the WCID query -
                            // the 0x0300/0x0301 devnodes recorded "non-WCID"
                            // (MS OS probes stalled there) and must never be
                            // reused. History: 0x0301 p3-3300 (TinyUSB-vendored
                            // UAC1 driver); 0x0300 p3-3200 (stdhid composite);
                            // 0x0108 p3-3180 (iso EP direction fix, XInput
                            // layout); 0x0107 p3-3160 (audio-first order);
                            // 0x0106 p3-2900; 0x0105 grand flash; 0x0104
                            // p3-2450 (WCID wValue=0 fix); 0x0103 p3-2420 (PID
                            // 0x028E->0xFFFF, WCID added); 0x0102 p3-2340
                            // (XInput merge); 0x0101 p3-2215 (HID report
                            // descriptor fix).
    .iManufacturer = 0x01, .iProduct = 0x02, .iSerialNumber = 0x03,
    .bNumConfigurations = 0x01,
};
#endif  // UAC1_ONLY (desc_device)
#if UAC1_ONLY
// Audio-only bisect configuration (p3-3170): total 100 bytes, 2 interfaces,
// 1 endpoint - JUST the UAC1 function of the composite, byte-for-byte the
// same AC/AS class descriptors, but with NO IAD (device class 0x01 at the
// device level replaces it). Asserted by check_desc.py and
// tests/check_usb_desc.py with --uac1-only.
static const uint8_t desc_configuration[] = {
    9, 2, 100, 0, 2, 1, 0, 0x80, 50,    // wTotalLength=100, 2 interfaces (AC 0 + AS 1)
    // AudioControl interface 0: IT(USB streaming) -> OT(speaker), no status EP,
    // no feature unit (Windows volume stays in the software mixer) - identical
    // bytes to the composite's audio function.
    9, 4, 0, 0, 0, 0x01, 0x01, 0x00, 0,  // if 0 alt 0: AudioControl, 0 EPs
    9, 0x24, 0x01, 0x00, 0x01, 30, 0, 1, 1,          // CS AC header (bcdADC 1.00)
    12, 0x24, 0x02, 0x01, 0x01, 0x01, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,  // IT id 1
    9, 0x24, 0x03, 0x02, 0x01, 0x03, 0x00, 0x01, 0x00,                     // OT id 2
    // AudioStreaming interface 1: alt 0 = zero-bandwidth idle, alt 1 = the stream.
    9, 4, 1, 0, 0, 0x01, 0x02, 0x00, 0,  // if 1 alt 0: AudioStreaming idle, 0 EPs
    9, 4, 1, 1, 1, 0x01, 0x02, 0x00, 0,  // if 1 alt 1: AudioStreaming, 1 EP
    7, 0x24, 0x01, 0x01, 0x01, 0x01, 0x00,             // CS AS general (PCM)
    11, 0x24, 0x02, 0x01, 0x02, 0x02, 0x10, 0x01, 0x80, 0xBB, 0x00,  // type I 48k
    // p3-3180: bEndpointAddress 0x84 -> 0x04. D7 is the direction bit (1=IN):
    // 0x84 declared an IN data endpoint on an AS interface linked to the
    // USB-streaming Input Terminal (playback topology) - usbaudio.sys refused
    // the function, so no USB Audio Device ever appeared. A playback data EP
    // is OUT: 0x04. (DS5Dongle's playback EP is 0x01 OUT; its 0x84 is the
    // mic feedback IN endpoint - the address was cargo-culted from the wrong
    // reference endpoint.)
    // p3-3300: UAC1-spec 9-byte EP form (bRefresh=0, bSynchAddress=0 appended,
    // audio10.pdf 4.6.1.1) + 7-byte CS EP form (wLockDelay appended, 4.6.1.2)
    // - the exact shapes DS5Dongle's AS block uses, byte-compared.
    9, 0x05, 0x04, 0x09, 192, 0, 1, 0, 0,   // EP4 OUT iso ADAPTIVE data, 192 B/ms, no refresh/synch EP
    7, 0x25, 0x01, 0x00, 0x00, 0x00, 0x00,  // CS iso endpoint: no pitch/samfreq control, no lock delay
};
_Static_assert(sizeof(desc_configuration) == 100, "audio-only config descriptor must be 100 bytes; update wTotalLength too");
#elif UAC1_CDC_ONLY
// UAC1+CDC bisect configuration (p3-3190): the full composite MINUS the
// gamepad function (interface 4 + its capability descriptor + two interrupt
// endpoints) = 174 bytes, 4 interfaces (audio IAD pair 0-1 + CDC
// IAD pair 2-3), 4 endpoints. Both functions are BYTE-IDENTICAL to the
// composite's blocks, so the only variable this flash introduces is the
// ABSENCE of the gamepad function (the vendor XInput interface + WCID
// exchange since p3-3500 restored it; p3-3200..3400 carried the standard HID
// gamepad here instead). Asserted by
// check_desc.py and tests/check_usb_desc.py with --uac1-cdc.
static const uint8_t desc_configuration[] = {
    9, 2, 174, 0, 4, 1, 0, 0x80, 50,   // wTotalLength=174, 4 interfaces
    // --------------------------------------------------------------------
    // UAC1 audio function: byte-identical to the composite's audio block
    // (IAD + AC if0 + AS if1 alt0/alt1, one ADAPTIVE iso OUT EP 0x04 - the
    // layout Windows already accepted in the audio-only bisect).
    8, 0x0B, 0, 2, 0x01, 0x01, 0x00, 0,  // IAD: firstIf=0, ifCount=2, class=1, sub=1 (CONTROL)
    9, 4, 0, 0, 0, 0x01, 0x01, 0x00, 0,  // if 0 alt 0: AudioControl, 0 EPs
    9, 0x24, 0x01, 0x00, 0x01, 30, 0, 1, 1,          // CS AC header (bcdADC 1.00)
    12, 0x24, 0x02, 0x01, 0x01, 0x01, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,  // IT id 1
    9, 0x24, 0x03, 0x02, 0x01, 0x03, 0x00, 0x01, 0x00,                     // OT id 2
    9, 4, 1, 0, 0, 0x01, 0x02, 0x00, 0,  // if 1 alt 0: AudioStreaming idle, 0 EPs
    9, 4, 1, 1, 1, 0x01, 0x02, 0x00, 0,  // if 1 alt 1: AudioStreaming, 1 EP
    7, 0x24, 0x01, 0x01, 0x01, 0x01, 0x00,             // CS AS general (PCM)
    11, 0x24, 0x02, 0x01, 0x02, 0x02, 0x10, 0x01, 0x80, 0xBB, 0x00,  // type I 48k
    9, 0x05, 0x04, 0x09, 192, 0, 1, 0, 0,     // EP4 OUT iso ADAPTIVE data, 192 B/ms (UAC1 9-byte form)
    7, 0x25, 0x01, 0x00, 0x00, 0x00, 0x00,    // CS iso endpoint: no control, no lock delay
    // --------------------------------------------------------------------
    // CDC function: byte-identical to the composite's CDC block (IAD pair
    // 2-3, control EP 0x82 interrupt + bulk 0x83 IN / 0x03 OUT).
    8, 0x0B, 2, 2, 0x02, 0x02, 0x00, 0,   // IAD: firstIf=2, ifCount=2, class=2/CDC, sub=2/ACM
    9, 4, 2, 0, 1, 0x02, 0x02, 0x01, 0,
    5, 0x24, 0x00, 0x10, 0x01,
    5, 0x24, 0x01, 0x00, 0x01,
    4, 0x24, 0x02, 0x02,
    5, 0x24, 0x06, 0x00, 0x01,
    7, 0x05, 0x82, 3, 8, 0, 16,
    9, 4, 3, 0, 2, 0x0A, 0x00, 0x00, 0,
    7, 0x05, 0x83, 2, 64, 0, 0,
    7, 0x05, 0x03, 2, 64, 0, 0,
    // ------------------------------------------------------------------
    // (Gamepad interface 4 + its 0x21 class descriptor + EPs 0x81/0x01
    // deliberately ABSENT - that is the variable under test. The full
    // 3-function layout lives in the composite branch below.)
};
_Static_assert(sizeof(desc_configuration) == 174, "audio+CDC config descriptor must be 174 bytes; update wTotalLength too");
#else
static const uint8_t desc_configuration[] = {
    // config: total 214 bytes, 5 interfaces (UAC1 IAD 2 + CDC IAD 2 + XInput),
    // 6 endpoints. asserted by check_desc.py / check_usb_desc.py
    //
    // p3-3160-uac3 INTERFACE ORDER: audio function FIRST (AC 0 + AS 1), then CDC
    // (2-3), then the gamepad (4). The previous layout (CDC 0-1 / XInput 2 /
    // audio 3-4) was byte-correct and usbd-parsed fine, yet Windows refused to
    // enumerate the WHOLE device (no COM, no pad, no audio) - while DS5Dongle,
    // the same chip (RP2350) + same stack (pico-sdk TinyUSB) + UAC1 + HID +
    // optional CDC, enumerates fine with AUDIO FIRST (AC 0 -> AS OUT 1 -> AS IN
    // 2 -> HID 3). The audio-first order matches the proven working reference.
    // p3-3300-tinyuac: the class driver behind the audio function is TinyUSB's
    // own (vendored 98741b55, see src/tinyusb-patch/class/audio/) - the
    // handwritten usb_audio.c driver is gone.
    // p3-3500 plugplay: interface 4 is the vendor XInput function again
    // (byte-exact p3-3180 block: FF/5D/01 + the 17-byte 0x21 xusb capability
    // blob) and the WCID exchange is back in the source below - see the MS OS
    // block; config 206 -> 214 bytes (the 17-byte blob replaces the 9-byte HID
    // class descriptor of p3-3200).
    9, 2, 214, 0, 5, 1, 0, 0x80, 50,   // wTotalLength=214
    // --------------------------------------------------------------------
    // UAC1 audio function (p3-2700, moved up front p3-3160): interfaces 0
    // (AudioControl) + 1 (AudioStreaming), one ADAPTIVE iso OUT endpoint.
    // Layout mirrors Linux f_uac1: IAD(class 1, subclass 1
    // CONTROL) -> AC(if 0, no EP) with IT(USB streaming) -> OT (speaker) and NO
    // feature unit (so Windows volume stays in the software mixer instead of a
    // hardware knob we would have to honour) -> AS(if 1) alt 0 = zero-bandwidth
    // idle, alt 1 = PCM 48 kHz stereo s16.
    8, 0x0B, 0, 2, 0x01, 0x01, 0x00, 0,  // IAD: firstIf=0, ifCount=2, class=1, sub=1 (CONTROL)
    9, 4, 0, 0, 0, 0x01, 0x01, 0x00, 0,  // if 0 alt 0: AudioControl, 0 EPs
    // CS AC header (bcdADC 1.00, CS total 9+12+9=30, 1 streaming if: nr 1)
    9, 0x24, 0x01, 0x00, 0x01, 30, 0, 1, 1,
    // Input Terminal id=1: USB streaming, 2ch (L+R)
    12, 0x24, 0x02, 0x01, 0x01, 0x01, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,
    // Output Terminal id=2: speaker (0x0301), source = IT id 1
    9, 0x24, 0x03, 0x02, 0x01, 0x03, 0x00, 0x01, 0x00,
    9, 4, 1, 0, 0, 0x01, 0x02, 0x00, 0,  // if 1 alt 0: AudioStreaming idle, 0 EPs
    9, 4, 1, 1, 1, 0x01, 0x02, 0x00, 0,  // if 1 alt 1: AudioStreaming, 1 EP
    // CS AS general: linked to IT 1, 1 frame delay, format PCM (0x0001)
    7, 0x24, 0x01, 0x01, 0x01, 0x01, 0x00,
    // CS AS format type I: 2ch, 2 B/subframe, 16 bit, 1 rate: 48000 (0x0000BB80)
    11, 0x24, 0x02, 0x01, 0x02, 0x02, 0x10, 0x01, 0x80, 0xBB, 0x00,
    // EP4 OUT iso ADAPTIVE data (attr 0x09 = iso|adaptive), 192 B/ms, 1 ms poll
    // (p3-3180: 0x84 -> 0x04 - D7 is the IN direction bit, see the audio-only
    // descriptor above for the full story; p3-3300: UAC1-spec 9-byte form with
    // bRefresh=0/bSynchAddress=0, the shape DS5Dongle's AS block uses)
    9, 0x05, 0x04, 0x09, 192, 0, 1, 0, 0,
    // CS iso endpoint: no pitch/samfreq control, no lock delay (adaptive OUT:
    // no feedback endpoint); 7-byte UAC1 form (wLockDelay appended)
    7, 0x25, 0x01, 0x00, 0x00, 0x00, 0x00,
    // --------------------------------------------------------------------
    // CDC control interface (IAD)
    8, 0x0B, 2, 2, 0x02, 0x02, 0x00, 0,   // IAD: 8 bytes, firstIf=2, ifCount=2, class=2/CDC, sub=2/ACM
    9, 4, 2, 0, 1, 0x02, 0x02, 0x01, 0,
    5, 0x24, 0x00, 0x10, 0x01,
    5, 0x24, 0x01, 0x00, 0x01,
    4, 0x24, 0x02, 0x02,
    5, 0x24, 0x06, 0x00, 0x01,
    7, 0x05, 0x82, 3, 8, 0, 16,
    // CDC data interface
    9, 4, 3, 0, 2, 0x0A, 0x00, 0x00, 0,
    7, 0x05, 0x83, 2, 64, 0, 0,
    7, 0x05, 0x03, 2, 64, 0, 0,
    // --------------------------------------------------------------------
    // XInput interface (what a real wired 360 pad exposes as interface 0; the
    // headset/security interfaces 1-3 of the original are omitted - xusb does
    // not need them). Vendor class 0xFF/0x5D/0x01, two INTERRUPT endpoints:
    // 0x81 IN carries the 20-byte input report (matches tud_vendor_n_write),
    // 0x01 OUT carries the 8-byte rumble frame (matches tud_vendor_rx_cb).
    // MPS 32 / intervals 4+8 copied from the real pad; the wire packet sizes
    // (20 in / 8 out) are declared inside the 17-byte 0x21 capability blob.
    9, 4, 4, 0, 2, 0xFF, 0x5D, 0x01, 0,
    // 17-byte "unknown" 0x21 descriptor, byte-exact from a real Xbox 360 wired
    // pad (partsnotincluded.com dump). xusb identifies XInput-capable interfaces
    // by this blob; its entries 5-7 (25 81 14) and 12-14 (13 01 08) encode
    // IN EP 0x81 packet 20 and OUT EP 0x01 packet 8 - tests/check_usb_desc.py
    // cross-checks them against the endpoint descriptors below.
    17, 0x21, 0x00, 0x01, 0x01, 0x25, 0x81, 0x14, 0x00, 0x00, 0x00, 0x00,
    0x13, 0x01, 0x08, 0x00, 0x00,
    7, 0x05, 0x81, 3, 32, 0, 4,   // EP1 IN  interrupt, MPS 32, 4 ms (reports are 20 B)
    7, 0x05, 0x01, 3, 32, 0, 8,   // EP1 OUT interrupt, MPS 32, 8 ms (rumble frames are 8 B)
};
_Static_assert(sizeof(desc_configuration) == 214, "config descriptor must be 214 bytes; update wTotalLength too");
#endif  // UAC1_ONLY (desc_configuration)

// (p3-3300) uac1_ep_desc is deleted: the TinyUSB audio driver activates the
// iso endpoint from the descriptor bytes it parsed during audiod_open(), so
// there is no second byte array to keep in sync.
#if UAC1_ONLY
static const char *string_desc[] = { "", "StadiaDev", "Stadia Pico Audio", "SPA1" };
#else
static const char *string_desc[] = { "", "StadiaDev", "Stadia Pico Bridge", "SPB1" };
#endif
uint8_t const *tud_descriptor_device_cb(void) { return (uint8_t const *)&desc_device; }
uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return desc_configuration;   // wTotalLength is a verified literal; check_desc.py asserts it
}

// ---- live descriptor self-check + enumeration milestones (p3-2900) ----------------
// Walks the ACTUAL const bytes the callbacks above hand to the host (not the
// source array the offline checkers parse) and prints the header: catches any
// "right source, wrong binary" linker/placement accident at boot. Then the
// milestone hooks below narrate enumeration on the log ring.
static volatile uint8_t usb_enum_count;    // tud_mount_cb hits since boot

static void usb_desc_selfcheck(void) {
    uint16_t wtl = (uint16_t)(desc_configuration[2] | (desc_configuration[3] << 8));
    int p = 0, itfs = 0, eps = 0;
    while (p < (int)sizeof desc_configuration && desc_configuration[p]) {
        if (desc_configuration[p + 1] == 4) itfs++;
        if (desc_configuration[p + 1] == 5) eps++;
        p += desc_configuration[p];
    }
    clog_("usb: selfcheck hdr=%02x%02x%02x%02x%02x%02x%02x%02x wtl=%u sz=%u walk=%d itf=%d ep=%d rev=%04x",
          desc_configuration[0], desc_configuration[1], desc_configuration[2], desc_configuration[3],
          desc_configuration[4], desc_configuration[5], desc_configuration[6], desc_configuration[7],
          wtl, (unsigned)sizeof desc_configuration, p, itfs, eps,
          (unsigned)desc_device.bcdDevice);
#if UAC1_ONLY
    if (wtl != sizeof desc_configuration || p != (int)wtl || itfs != 3 || eps != 1)
        clog_("usb: SELF-CHECK FAILED (want wtl==sz, walk==wtl, itf=3, ep=1)");
#elif UAC1_CDC_ONLY
    // 5 interface DESCRIPTORS (AC + AS alt0/alt1 + CDC ctrl + CDC data = 4
    // interface numbers), 4 endpoints (iso 0x04 + CDC 0x82/0x83/0x03).
    if (wtl != sizeof desc_configuration || p != (int)wtl || itfs != 5 || eps != 4)
        clog_("usb: SELF-CHECK FAILED (want wtl==sz, walk==wtl, itf=5, ep=4)");
#else
    // 6 interface DESCRIPTORS over 5 interface numbers (AC 0 + AS 1 alt0/alt1 +
    // CDC ctrl 2 + CDC data 3 + XInput 4), 6 endpoints (iso 0x04 + CDC
    // 0x82/0x83/0x03 + XInput 0x81/0x01). p3-3200 note (kept): this used to
    // assert itf=5, but the walk counts interface DESCRIPTORS (the AS alt-1
    // duplicate included) and has been 6 since the audio function was added -
    // the boot log of every full-composite build since p3-2700 printed a bogus
    // SELF-CHECK FAILED line for exactly this reason.
    if (wtl != sizeof desc_configuration || p != (int)wtl || itfs != 6 || eps != 6)
        clog_("usb: SELF-CHECK FAILED (want wtl==sz, walk==wtl, itf=6, ep=6)");
#endif
}

// SET_CONFIG completed on the device (TinyUSB calls this after process_set_config
// succeeded - every class driver opened, all interfaces bound). The definitive
// "device side of enumeration is done" marker. The count is published to core0
// (heartbeat `enum=` field) through the IPC snapshot.
void tud_mount_cb(void) {
    usb_enum_count++;
    ipc_enum_count_set(usb_enum_count);
    clog_("usb: MOUNTED (set_config ok) enum=%u", usb_enum_count);
}

// Bus reset / SET_CONFIG(0): Windows normally enumerates 2-3 times per plug-in
// (child devnode installs), so a few of these per mount are normal;
// an endless mount/unmount alternation = crash-loop signature.
// p3-3600: a bus reset closes ALL non-control endpoints inside the dcd WITHOUT
// invoking the class transfer callback, so tud_vendor_tx_cb() never runs and a
// report armed just before the reset would leave xinput_in_busy stuck forever
// (the pad would re-enumerate but never report again). Clear it here.
void tud_umount_cb(void) {
#if !UAC1_ONLY && !UAC1_CDC_ONLY
    xinput_in_busy = false;   // see the comment above: no class cb on a bus reset
#endif
    usb_audio_detach();   // p3-3300: mirror the old uac1_reset() stream-flag drop
    clog_("usb: unmount (bus reset / cfg 0)");
}

uint8_t usb_hid_enum_count(void) { return usb_enum_count; }

#if !UAC1_ONLY && !UAC1_CDC_ONLY
// ---- MS OS 1.0 descriptors (WCID): how XInput binds on a composite device ----
//
// Restored p3-3500 (byte-exact from the p3-3180/p3-2420/p3-2450 lineage; the
// interim p3-3200 stdhid build deleted it). With usbccgp loading (see
// desc_device), Windows creates one child devnode per function: the UAC1 IAD
// pair (interfaces 0-1, matched by usbaudio on its standard class compatible
// ids - nothing to do here), the CDC IAD pair (interfaces 2-3, usbser
// likewise) and the XInput vendor interface 4. NO inbox INF matches
// USB\Class_FF&SubClass_5D&Prot_01 (verified against every C:\Windows\INF\*.inf
// on this Win11 host), so the ONLY remaining way interface 4 reaches xusb22.sys
// is the Microsoft OS 1.0 Extended Compat ID descriptor ("WCID"): usbccgp
// probes string index 0xEE for the "MSFT100" signature, then issues a vendor
// control request (bmRequestType 0xC0, bRequest = bVendorCode, wIndex = 0x0004
// Extended Compat ID, wValue = 0x0000 page number - NOT the interface; the
// interface lives in bFirstInterfaceNumber inside the reply. p3-2420 wrongly
// demanded wValue low byte == 2, which is the convention of the Extended
// PROPERTIES request wIndex=5, so the real query STALLed and the MI_02 child
// stayed Code 28). Answering "XUSB10" for interface 4 gives that child the
// compatible id USB\MS_COMP_XUSB10, which xusb22.inf matches:
//   %XUSB22.DeviceName.Wired%=CC_Install, USB\MS_COMP_XUSB10
// Reference layout: libwdi WCID Devices wiki (byte-exact header/function dump).
#define MS_OS_VENDOR_CODE 0x20
static const uint8_t ms_os_string_ee[18] __attribute__((aligned(2))) = {
    0x12, 0x03,                                   // bLength=18, STRING
    'M', 0, 'S', 0, 'F', 0, 'T', 0, '1', 0, '0', 0, '0', 0,   // UTF-16 "MSFT100"
    MS_OS_VENDOR_CODE, 0x00,                      // bVendorCode, padding
};
static const uint8_t ms_os_ext_compat[] = {
    0x28, 0x00, 0x00, 0x00,   // dwLength = 40 (one function section)
    0x00, 0x01,               // bcdVersion 1.00
    0x04, 0x00,               // wIndex = 0x0004 (Extended Compat ID)
    0x01,                     // bCount = 1 function section
    0, 0, 0, 0, 0, 0, 0,      // reserved (7)
    4,                        // bFirstInterfaceNumber = 4 (the XInput interface;
                              //  was 2 before the p3-3160 audio-first reorder)
    0x01,                     // reserved = 1 (per the WCID reference dump)
    'X', 'U', 'S', 'B', '1', '0', 0, 0,   // CompatibleID "XUSB10", NUL padded
    0, 0, 0, 0, 0, 0, 0, 0,   // SubCompatibleID (none)
    0, 0, 0, 0, 0, 0,         // reserved (6)
};
_Static_assert(sizeof(ms_os_ext_compat) == 40, "MS OS ext-compat descriptor is 40 bytes");

// TinyUSB routes every vendor-type control request here - TinyUSB 0.18 usbd.c
// process_control_request() checks bmRequestType_bit.type == TUSB_REQ_TYPE_VENDOR
// BEFORE any recipient switch, so the device-level MS OS query (recipient 0)
// arrives here too; the callback is also re-invoked for the DATA/ACK stages as
// the transfer completion callback. Answer ONLY the usbccgp WCID query; stall
// everything else so the CDC function falls through to its standard class
// matching untouched. usbccgp reads the 16B header first, then the full 40B
// (two queries, different wLength); tud_control_xfer truncates to wLength, so
// both are served by this single reply. p3-2450: wValue must match the spec's
// page number 0x0000 (see comment above) - p3-2420's `wValue & 0xFF == 2`
// never matched the real request, the query STALLed, Windows saw a non-WCID
// device and the XInput child fell to Code 28 with no MS_COMP_XUSB10.
bool tud_vendor_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const *request) {
    if (stage != CONTROL_STAGE_SETUP) return true;
    if (request->bmRequestType == 0xC0 && request->bRequest == MS_OS_VENDOR_CODE &&
        request->wIndex == 0x0004 && request->wValue == 0x0000) {
        clog_("usb: WCID ext-compat query (wLen=%u) -> XUSB10 iface %d",
              request->wLength, ms_os_ext_compat[16]);
        return tud_control_xfer(rhport, request, (void *)(uintptr_t)ms_os_ext_compat,
                                sizeof ms_os_ext_compat);
    }
    // Budgeted stall trace: any OTHER vendor request reaching the device is
    // exactly what the p3-2420/p3-2450 archaeology says to watch for - if a
    // future Windows build probes a different MS OS page or an xusb22 vendor
    // command, its bytes land in the log instead of vanishing into a STALL.
    {
        static uint8_t stall_budget = 8;
        if (stall_budget) {
            stall_budget--;
            clog_("usb: vendor req STALL bm=%02x br=%02x wV=%04x wI=%04x wL=%u",
                  request->bmRequestType, request->bRequest, request->wValue,
                  request->wIndex, request->wLength);
        }
    }
    return false;   // stall (TinyUSB's no-handler default behaviour)
}
#endif  // !UAC1_ONLY && !UAC1_CDC_ONLY (MS OS 1.0 WCID: both bisect builds are
        // plain class composites - no 0xEE string, no vendor replies, every
        // function binds on standard compatible ids alone)

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    static uint16_t buf[32];
#if !UAC1_ONLY && !UAC1_CDC_ONLY
    if (index == 0xEE)   // MS OS 1.0 signature probe from usbccgp (WCID)
        return (uint16_t const *)(uintptr_t)ms_os_string_ee;
#endif
    if (index == 0) { buf[1] = 0x0409; buf[0] = 4; return buf; }
    if (index >= sizeof(string_desc) / sizeof(string_desc[0])) return NULL;
    const char *s = string_desc[index];
    int n = (int)strlen(s); if (n > 31) n = 31;
    buf[0] = (uint16_t)(2 + 2 * n);
    for (int i = 0; i < n; i++) buf[1 + i] = s[i];
    return buf;
}


// ---- CDC console: IPC log ring (both cores) drained by core1 -> USB ----------
//
// p3-3600-dualcore: the ring itself moved to ipc.c because it is now written by
// BOTH cores (core0's network/cloud logs and core1's USB logs) and drained only
// by core1 (which owns the CDC). ipc_log_write() takes a hardware spinlock, so a
// core0 log line cannot interleave with a core1 line any more - the old
// save_and_disable_interrupts() trick only ever protected against IRQs on the
// same core.
#include <stdarg.h>
#include "pico/platform.h"

void clog_(const char *fmt, ...) {
    char line[160];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof line - 2) n = (int)sizeof line - 2;
    line[n] = 13; line[n + 1] = 10;
    // p3-3606: per-core lock-free rings. core1's lines go to its own local ring
    // and can never block/be blocked by core0 (the shared-spinlock version let a
    // core1 fault freeze core0's logging and wedge the whole chip).
    if (get_core_num() != 0) ipc_c1_log_write(line, n + 2);
    else                     ipc_log_write(line, n + 2);
}
#define LOG(...) clog_(__VA_ARGS__)

// CDC RX is drained into a small buffer, then PARSED with the USB lock free: the
// command handlers log and may block (BOOTSEL sleeps 30 ms) - none of that may
// run inside a critical section.
#define CDC_RX_BATCH 64

#if !UAC1_ONLY   // ---- CDC console (gone in the audio-only build) ----
// Copy the IPC log ring into the CDC TX fifo and arm the endpoint. Core1-only
// context now: TinyUSB is not touched by any other core, so no IRQ masking.
static void cdc_flush_ring(void) {
    // Do NOT wipe a ring while no host has the port open: the boot/one-shot
    // milestone lines (selfcheck/MOUNTED/WCID/core1 ready) are exactly what an
    // operator opens the port to read a few seconds later. Lines are dropped only
    // by ring wrap and by a consumer that is actually reading.
    if (!tud_cdc_connected()) return;
    // p3-3606: drain core1's local ring first (its own newest lines), then the
    // core0 -> core1 ring. Both are lock-free SPSC.
    for (int pass = 0; pass < 2; pass++) {
        for (int guard = 0; guard < 32; guard++) {
            int avail = (int)tud_cdc_write_available();
            if (avail <= 0) break;
            char buf[128];
            int want = avail < (int)sizeof buf ? avail : (int)sizeof buf;
            int got = pass ? ipc_log_read(buf, want) : ipc_c1_log_read(buf, want);
            if (got <= 0) break;
            if (tud_cdc_write(buf, (uint32_t)got) == 0) break;
        }
    }
    tud_cdc_write_flush();
}

void usb_hid_pump_cdc(void) {
    char rx[CDC_RX_BATCH];
    int nrx = 0;
    while (nrx < CDC_RX_BATCH && tud_cdc_available()) {
        int ch = tud_cdc_read_char();
        if (ch < 0) break;
        rx[nrx++] = (char)ch;
    }
    // Console commands. p3-3600-dualcore: the ones that belong to core0 (tone,
    // rumble, audio test, DTLS self test, encoder dump) are QUEUED through IPC and
    // executed by core0's main loop, which owns that state; executing them here
    // would race core0's rtc_tick. BOOTSEL stays on core1 (the USB stack lives
    // here). OPUSBENCH also queues through usb_audio_bench_start(): p3-3641 the
    // encoder moved to core0, so the benchmark executes there.
    //
    // Remote flashing support: send the literal line "BOOTSEL" on the CDC port and the
    // device reboots into the RP2350 ROM bootloader, which mounts as the RPI-RP2 drive.
    // The host can then copy a new .uf2 without the user touching BOOTSEL again.
    {
        static char cmd[104]; static int cl;
        for (int i = 0; i < nrx; i++) {
            char ch = rx[i];
            if (ch == '\r' || ch == '\n') {
                cmd[cl] = 0;
                if (cl == 8 && cmd[0]=='D' && cmd[1]=='T' && cmd[2]=='L' && cmd[3]=='S' &&
                    cmd[4]=='T' && cmd[5]=='E' && cmd[6]=='S' && cmd[7]=='T') {
                    ipc_cmd_push(IPC_CMD_DTLS_TEST);      // core0: rtc_request_dtls_selftest
                    cl = 0; continue;
                }
                if (cl == 7 && cmd[0]=='E' && cmd[1]=='N' && cmd[2]=='C' && cmd[3]=='D' &&
                    cmd[4]=='U' && cmd[5]=='M' && cmd[6]=='P') {
                    ipc_cmd_push(IPC_CMD_ENCDUMP);        // core0: cloud_encoder_dump
                    cl = 0; continue;
                }
                if (cl == 6 && cmd[0]=='R' && cmd[1]=='U' && cmd[2]=='M' && cmd[3]=='B' &&
                    cmd[4]=='L' && cmd[5]=='E') {
                    ipc_cmd_push(IPC_CMD_RUMBLE);         // core0: rtc_rumble_pulse
                    cl = 0; continue;
                }
                if (cl == 4 && cmd[0]=='T' && cmd[1]=='O' && cmd[2]=='N' && cmd[3]=='E') {
                    // 440 Hz test tone to the controller speaker (2500 ms = the
                    // PC-verified recipe duration, PLAYBOOK 3.6z6). Requires the
                    // display session up (registered -> ICE -> DTLS -> READY).
                    ipc_cmd_push(IPC_CMD_TONE);           // core0: rtc_audio_tone_start(2500)
                    cl = 0; continue;
                }
                if (cl == 8 && cmd[0]=='A' && cmd[1]=='U' && cmd[2]=='D' && cmd[3]=='P' &&
                    cmd[4]=='T' && cmd[5]=='E' && cmd[6]=='S' && cmd[7]=='T') {
                    // ONE deliberately-unprotected RTP frame (p3-2330 control
                    // experiment): emu37 says the controller silently drops packets
                    // it cannot SRTP-unprotect, so AUDPTEST must stay silent while
                    // TONE plays - if AUDPTEST ever makes sound the controller is
                    // NOT enforcing protection and any TONE silence is elsewhere.
                    ipc_cmd_push(IPC_CMD_AUDPTEST);       // core0: rtc_audio_test_raw
                    cl = 0; continue;
                }
                if (cl == 7 && cmd[0]=='P' && cmd[1]=='R' && cmd[2]=='E' && cmd[3]=='V' &&
                    cmd[4]=='L' && cmd[5]=='O' && cmd[6]=='G') {
                    // p3-3631: print the "last log line of the previous boot" that was
                    // kept in NOLOAD SRAM across a watchdog reset (main.c prints it once
                    // at boot too; this lets us re-read it after the console reconnects).
                    char pl[124], ph[100]; uint32_t pms = 0;
                    int pn = ipc_prev_log_copy(pl, (int)sizeof pl, &pms);
                    if (pn > 0) {
                        clog_("PREVRESET t=%u last-line: %s", (unsigned)pms, pl);
                        if (ipc_prev_https_copy(ph, (int)sizeof ph) > 0)
                            clog_("PREVRESET https: %s", ph);
                    } else {
                        clog_("PREVRESET: none (cold boot / already consumed)");
                    }
                    cl = 0; continue;
                }
                if (cl == 9 && cmd[0]=='O' && cmd[1]=='P' && cmd[2]=='U' && cmd[3]=='S' &&
                    cmd[4]=='B' && cmd[5]=='E' && cmd[6]=='N' && cmd[7]=='C' &&
                    cmd[8]=='H') {
                    // On-device libopus encoder benchmark (route B Go/No-Go).
                    // p3-3641: the encoder is on core0, so this only queues the
                    // request; rtc_tick runs one bench encode per 20 ms slot.
                    usb_audio_bench_start();
                    clog_("host: opusbench requested (runs on core0)");
                    cl = 0; continue;
                }
                if (cl == 10 && cmd[0]=='H' && cmd[1]=='F' && cmd[2]=='A' &&
                    cmd[3]=='U' && cmd[4]=='L' && cmd[5]=='T' && cmd[6]=='T' &&
                    cmd[7]=='E' && cmd[8]=='S' && cmd[9]=='T') {
                    // p3-3646 HFAULT blackbox self-test: deliberately take a
                    // HardFault on THIS core (core1). The handler records the
                    // stacked frame + CFSR/HFSR/BFAR/MMFAR into NOLOAD SRAM and
                    // reboots; the next boot prints "HFAULT core=1 pc=...".
                    clog_("host: HFAULTTEST - deliberate HardFault on core1 now");
                    cdc_flush_ring();
                    tud_cdc_write_flush();
                    sleep_ms(50);
                    hfault_selftest();              // does not return: record + reboot
                }
                if (cl == 6 && cmd[0]=='H' && cmd[1]=='F' && cmd[2]=='A' &&
                    cmd[3]=='U' && cmd[4]=='L' && cmd[5]=='T') {
                    // Re-print this boot's captured fault record (main.c prints
                    // once at boot and clears the NOLOAD magic; this reads the
                    // copy kept for this boot).
                    int shown = 0;
                    for (int c = 0; c < HFAULT_MAX_CORE; c++) {
                        hfault_rec_t hf;
                        if (!hfault_last_copy(c, &hf)) continue;
                        hfault_log(&hf);
                        shown++;
                    }
                    if (!shown) clog_("HFAULT: none captured this boot");
                    cl = 0; continue;
                }
                // p3-3500: the AUDIOSRC usb|tone command is DELETED - the
                // speaker source is fully automatic now (rtc_tick watches the
                // USB audio data arrival: data arriving -> USB source, gone
                // >100 ms -> mute; see the auto-source block in rtc.c). No
                // command is needed for plug-and-play audio, and none may
                // override the automatic selection. TONE stays for the speaker
                // path check.
                if (cl == 7 && cmd[0]=='B' && cmd[1]=='O' && cmd[2]=='O' && cmd[3]=='T' &&
                    cmd[4]=='S' && cmd[5]=='E' && cmd[6]=='L') {
                    clog_("host: reboot to BOOTSEL requested");
                    cdc_flush_ring();                 // flush pending log text first
                    tud_cdc_write_flush();
                    sleep_ms(30);
                    reset_usb_boot(0, 0);        // does not return
                }
                // WIFI console: AP credential management, executed on core0 (it
                // owns the flash + AP state). Values are rest-of-line so SSIDs
                // and passphrases may contain spaces. core0 validates + reports.
                if (cl >= 4 && !strncmp(cmd, "WIFI", 4) && (cl == 4 || cmd[4] == ' ')) {
                    const char *sub = (cl > 5) ? cmd + 5 : "";
                    char vpass[65]; vpass[0] = 0;
                    if (cl == 4) {
                        clog_("wifi: WIFI SHOW | WIFI SSID <1..32> | WIFI PASS <8..63> | WIFI OPEN | WIFI SAVE | WIFI RESET");
                    } else if (!strcmp(sub, "SHOW")) {
                        ipc_wifi_push(WIFI_OP_SHOW, NULL, NULL);
                        ipc_cmd_push(IPC_CMD_WIFI);
                    } else if (!strcmp(sub, "OPEN")) {
                        ipc_wifi_push(WIFI_OP_OPEN, NULL, NULL);
                        ipc_cmd_push(IPC_CMD_WIFI);
                    } else if (!strcmp(sub, "SAVE")) {
                        ipc_wifi_push(WIFI_OP_SAVE, NULL, NULL);
                        ipc_cmd_push(IPC_CMD_WIFI);
                    } else if (!strcmp(sub, "RESET")) {
                        ipc_wifi_push(WIFI_OP_RESET, NULL, NULL);
                        ipc_cmd_push(IPC_CMD_WIFI);
                    } else if (!strncmp(sub, "SSID ", 5) && cl > 10) {
                        size_t n = (size_t)cl - 10;
                        if (n > 32) n = 32;
                        memcpy(vpass, sub + 5, n);
                        vpass[n] = 0;
                        ipc_wifi_push(WIFI_OP_SSID, vpass, NULL);
                        ipc_cmd_push(IPC_CMD_WIFI);
                    } else if (!strncmp(sub, "PASS ", 5) && cl > 10) {
                        size_t n = (size_t)cl - 10;
                        if (n > 64) n = 64;
                        memcpy(vpass, sub + 5, n);
                        vpass[n] = 0;
                        ipc_wifi_push(WIFI_OP_PASS, NULL, vpass);
                        ipc_cmd_push(IPC_CMD_WIFI);
                    } else {
                        clog_("wifi: WIFI SHOW | WIFI SSID <1..32> | WIFI PASS <8..63> | WIFI OPEN | WIFI SAVE | WIFI RESET");
                    }
                    cl = 0; continue;
                }
                cl = 0;
            } else if (cl < (int)sizeof cmd - 1) {
                cmd[cl++] = ch;
            }
        }
    }
    cdc_flush_ring();
}
#else   // UAC1_ONLY: no CDC interface exists - the IPC log ring still collects
        // clog_ lines from boot (they simply wrap around, nothing reads
        // them) and the console command parser is gone with the port. The
        // whole USB surface is the UAC1 function in usb_audio.c.
void usb_hid_pump_cdc(void) { }
#endif

