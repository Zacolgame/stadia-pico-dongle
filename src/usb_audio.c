// usb_audio.c — UAC1 playback data path on TinyUSB's OWN audio class driver.
//
// p3-3641-core0encode: the Opus ENCODE moved off core1 onto core0.
//
// Why: the single-buffered isochronous USB OUT endpoint must be re-armed within
// ~1 ms, but a 48 kHz stereo Opus encode blocks for 7.9 ms average / 15.8 ms
// worst per 20 ms frame. On real hardware that dropped 58% of the UAC1 PCM
// (p3-3635: 81-86 KB/s accepted vs the 192 KB/s the host sends).
//
// New split:
//
//   core1 (this file, usb_audio_core1_tick)        core0 (rtc.c + usb_audio_encode_live)
//   TinyUSB audiod (tud_task, tight loop)
//     EP 0x04 iso OUT -> lin_buf_out -> ep_out_ff
//     -> usb_audio_pump(): staging -> 3840 B block
//     -> ipc_pcm_push() ---------------------------> ipc_pcm_read() (one 20 ms slot)
//                                                      -> opus_encode()
//                                                      -> SRTP/RTP send
//
// core1 therefore only ever touches the USB fifo, the PCM block assembler and
// the IPC ring: no libopus call, no encoder state, no demand pacing, no silence
// frame. The encoder object and its scratch (static pseudostack) live here but
// are created and used from CORE 0 only (usb_audio_encoder_init /
// usb_audio_encode_live / usb_audio_bench_tick).
//
// p3-3300-tinyuac: the hand-written UAC1 class driver that used to live in
// this file (usbd_app_driver_get_cb + uac1_open/control/xfer/reset, ~160
// lines) is DELETED. It was the root cause of the composite enumeration
// crashes: it took Windows' endpoint-initialisation sequence down paths that
// wedged the firmware. The USB audio function is now driven by TinyUSB's
// builtin audio class, vendored from upstream 98741b55 into
// src/tinyusb-patch/class/audio/ (the pico-sdk 0.18 copy is UAC2-only; the
// vendored one accepts UAC 1.0 protocol 0x00 - the same driver+commit
// DS5Dongle runs stable on this very chip) and swapped in via CMakeLists.txt
// exactly like the vendored rp2040_usb.c.
//
// Data flow out of the driver: tud_audio_available()/tud_audio_read() from
// core1's loop. Concurrency: the driver's fifo is written by the USB IRQ's
// enqueued events during tud_task (also core1) and read here on the same core;
// the vendored audiod_init() attaches NO mutexes to it, so the fifo is plain
// SPSC and needs no locking.
//
// Stream state: TinyUSB's driver has no "is alt 1 active" query on the 0.18
// declaration surface, so we implement its SET_INTERFACE callbacks
// (tud_audio_set_itf_cb / tud_audio_set_itf_close_ep_cb) to maintain
// stream_on + log the open/close milestones the serial console expects.
#include "usb_audio.h"
#include "usb_hid.h"         // FWLOG()
#include "ipc.h"
#include "config.h"
#include "net_infra.h"
#include "pico/stdlib.h"     // get_core_num(), to_us_since_boot()
#include "hardware/sync.h"   // __dmb()
#include <string.h>
#include <stdio.h>
#include "tusb.h"
#include "opus.h"

// The encoder scratch comes from libopus's NONTHREADSAFE_PSEUDOSTACK build:
// celt/stack_alloc.h borrows one process-global buffer for every ALLOC() inside
// an encode. That is what keeps a 33 KB encoder off the CPU stack: core0's stack
// is the SDK's 4 KiB SCRATCH_Y one. CMakeLists.txt defines both sizes for the
// opus target and for us; see the p3-3646-bpsfix section below for why WE own the
// buffer (static, canaried) instead of libopus's default malloc().
#ifndef OPUS_PSEUDOSTACK_BYTES
#define OPUS_PSEUDOSTACK_BYTES 40960     // what libopus asks for (GLOBAL_STACK_SIZE)
#endif
#ifndef OPUS_STATIC_SCRATCH_BYTES
#define OPUS_STATIC_SCRATCH_BYTES 49152  // what we actually hand it (.bss)
#endif

// ===================================================== p3-3646 static pseudostack
// BEFORE (p3-3641): opus_alloc_scratch() was libopus's default, i.e. one
// malloc(40960) on the very first opus_encode(), never freed. libopus NEVER
// bounds-checks a pseudostack push (celt/stack_alloc.h PUSH just advances
// global_stack), so an encode that needed more than 40960 B silently wrote over
// whatever the heap had placed after that chunk. That is the prime suspect for
// the real-machine core0 symptoms: OPUSBENCH prints "start", then the main loop
// stalls 13-25 s over and over and a 500-frame phase never completes; the A+B
// combined build hangs inside the very first encode at boot.
//
// AFTER: this static .bss buffer (8-aligned) + a 16-byte 0xC5 canary immediately
// behind it. An overrun now hits OUR canary - logged and counted, the board keeps
// running - and can never touch heap metadata. CMake passes
// OVERRIDE_OPUS_ALLOC_SCRATCH to the opus target, which drops libopus's inline
// definition and routes celt/stack_alloc.h's ALLOC_STACK to opus_alloc_scratch()
// at the bottom of this section. Cost: 48 KiB of .bss (heap shrinks by the same
// amount, once, at link time - no runtime malloc, no fragmentation).
//
// Two numbers come straight from libopus's own globals (celt/stack_alloc.h):
//   creep = global_stack - scratch_ptr
//        Measured after every top-level opus_encode(). Exactly 0 when every
//        ALLOC_STACK/SAVE_STACK/RESTORE_STACK pair balanced. A monotonically
//        growing creep is a pointer leak (a path returning without RESTORE),
//        independent of how deep that path went.
//   peak = high-water mark of one call
//        The buffer is poisoned with 0xA5 before each top-level encode and the
//        end scanned backwards afterwards. libopus guarantees the scratch is dead
//        once RESTORE_STACK ran, so rewriting it is safe. This is the number that
//        says whether GLOBAL_STACK_SIZE=40960 ever WAS big enough (the old
//        VAR_ARRAYS stack peak was 33,332 B, but pseudostack accounting differs).
#define PS_FILL_BYTE   0xA5u
#define PS_CANARY_BYTE 0xC5u
#define PS_CANARY_LEN  16u

// celt/celt.c (the CELT_C TU) defines these two globals. They are the only
// visibility we have into how deep an encode went and whether it came back.
extern char *global_stack, *scratch_ptr;

static struct {
    uint8_t stack[OPUS_STATIC_SCRATCH_BYTES];
    uint8_t canary[PS_CANARY_LEN];          // MUST stay immediately after stack[]
} ps_area __attribute__((aligned(8)));

static bool ps_canary_armed;
static uint32_t ps_requested;               // size libopus asked for (logged once)
static uint32_t ps_creep, ps_creep_max;     // global_stack - scratch_ptr, now / worst
static uint32_t ps_peak, ps_peak_max;       // this call / worst high-water mark
static uint32_t ps_canary_trips;            // canary trashed N times
static bool ps_cfg_logged, ps_creep_warned;

// libopus celt/stack_alloc.h ALLOC_STACK: called ONCE per boot, from the first
// opus_encode(), with GLOBAL_STACK_SIZE. Deliberately branch-light: this runs at
// the deepest point of the first encode, so it only records the request and arms
// the canary. The one-shot FWLOG happens in ps_after(), in our own shallow frame.
// The size is advisory (PUSH never checks it) and failing here would kill the
// whole audio path over a RAM-math number, so an oversized request is logged and
// IGNORED - the fixed buffer is always what gets returned.
void *opus_alloc_scratch(size_t size) {
    ps_requested = (uint32_t)size;
    memset(ps_area.canary, PS_CANARY_BYTE, sizeof ps_area.canary);
    ps_canary_armed = true;
    return ps_area.stack;
}

// Poison the whole pseudostack, but only from a balanced head (creep == 0): if a
// previous call leaked, the bytes above global_stack may still matter to nothing
// - but rewriting from a moved head would also destroy the evidence of the leak.
static bool ps_fill(void) {
    if (!global_stack || !scratch_ptr || global_stack != scratch_ptr) return false;
    memset(ps_area.stack, PS_FILL_BYTE, sizeof ps_area.stack);
    return true;
}

// Highest offset touched by the call that just returned, i.e. the real pseudostack
// depth. Scans backwards from the end: the untouched tail is 0xA5, so this stops
// after a handful of bytes in the normal case.
static uint32_t ps_peak_scan(void) {
    const uint8_t *p = ps_area.stack + sizeof ps_area.stack;
    while (p > ps_area.stack && p[-1] == PS_FILL_BYTE) p--;
    return (uint32_t)(p - ps_area.stack);
}

// Core0, right after each top-level opus_encode(): canary check + the two depth
// counters + the one-shot messages. Never crashes and never fails a call - the
// point is that the lead can SEE an overflow/leak while the firmware keeps going.
static void ps_after(const char *where, bool measured) {
    if (!ps_cfg_logged) {
        ps_cfg_logged = true;
        if (ps_requested > (uint32_t)sizeof ps_area.stack)
            FWLOG("opus: PSEUDOSTACK request %u > static %u B - IGNORED, using %u",
                  (unsigned)ps_requested, (unsigned)sizeof ps_area.stack,
                  (unsigned)sizeof ps_area.stack);
        else
            FWLOG("opus: static pseudostack %u B (.bss, request %u B) - heap untouched",
                  (unsigned)sizeof ps_area.stack, (unsigned)ps_requested);
    }
    // 1) canary - the 16 bytes right behind the pseudostack.
    bool bad = false;
    for (unsigned i = 0; ps_canary_armed && i < PS_CANARY_LEN; i++) {
        if (ps_area.canary[i] != PS_CANARY_BYTE) { bad = true; break; }
    }
    if (bad) {
        ps_canary_trips++;
        if (ps_canary_trips == 1) {          // one loud line; counter goes in the telemetry
            FWLOG("opus: PSEUDOSTACK OVERFLOW (canary at +%u trashed after %s, creep=%u peak=%u)",
                  (unsigned)sizeof ps_area.stack, where, (unsigned)ps_creep, (unsigned)ps_peak);
        }
        memset(ps_area.canary, PS_CANARY_BYTE, sizeof ps_area.canary);   // keep counting
    }
    // 2) creep - should be 0 after every balanced call.
    ps_creep = (global_stack && scratch_ptr && global_stack > scratch_ptr)
             ? (uint32_t)(global_stack - scratch_ptr) : 0u;
    if (ps_creep > ps_creep_max) ps_creep_max = ps_creep;
    if (ps_creep > 8192u && !ps_creep_warned) {
        ps_creep_warned = true;
        FWLOG("opus: PSEUDOSTACK CREEP %u B after %s (leaked pointer, not depth)",
              (unsigned)ps_creep, where);
    }
    // 3) peak - only when ps_fill() actually ran before this call.
    ps_peak = measured ? ps_peak_scan() : 0u;
    if (ps_peak > ps_peak_max) ps_peak_max = ps_peak;
}

// Pseudostack telemetry for the core0 10 s line (bench lines print it inline).
void usb_audio_ps_stats(uint32_t *creep, uint32_t *creep_max, uint32_t *peak_max,
                        uint32_t *canary_trips) {
    if (creep) *creep = ps_creep;
    if (creep_max) *creep_max = ps_creep_max;
    if (peak_max) *peak_max = ps_peak_max;
    if (canary_trips) *canary_trips = ps_canary_trips;
}

// p3-3621/3622 audio telemetry counters (core1 pump + core0 encoder)
static uint32_t c1_pump_calls;                                   // USB fifo service count
int16_t c1_raw_peak_pub;                                         // raw USB PCM peak
static uint32_t c0_enc_ok, c0_enc_fail;                          // core0 encode outcomes
static uint32_t c0_enc_us_sum, c0_enc_us_max, c0_enc_us_last;    // core0 encode timing
static int16_t c0_pcm_peak_pub;                                  // encoded block peak

// The callback below exists in the vendored 98741b55 audio_device.h but NOT
// in the SDK's 0.18 copy (which tusb.h includes) - declare it here with the
// exact vendored signature so our strong definition overrides the driver's
// weak default correctly.
bool tud_audio_set_itf_close_ep_cb(uint8_t rhport, tusb_control_request_t const *p_request);

// --------------------------------------------------------------- stats
// core1-only counters (single writer = core1's loop thread).
static struct {
    uint32_t pkts;                        // pump batches that moved data
    uint32_t pushed;                      // bytes handed to the IPC PCM ring
    uint32_t blocks;                      // 3840 B blocks assembled from the fifo
} usb_stats;

// --------------------------------------------------------------- UAC1 state
static volatile bool stream_on;           // host set AS interface to alt 1
                                          // (maintained by the set_itf callbacks)

// ================================================================== PCM block
// p3-3624: the UAC1 capture is 48 kHz stereo s16 - exactly what the controller's
// audio profile wants (SDP audio_format: channels=2, sample_rate=48000). The live
// path needs NO resampling: one 20 ms stereo block is 960 frames = 3840 B.
#define BLOCK_FRAMES (AUDIO_FRAME_MS * AUDIO_OPUS_RATE / 1000)   // 960
#define BLOCK_BYTES  (BLOCK_FRAMES * AUDIO_OPUS_CHANNELS * 2)    // 3840

_Static_assert(BLOCK_BYTES == IPC_PCM_BLOCK_BYTES,
               "IPC_PCM_BLOCK_BYTES must match the 20 ms 48k stereo block");

// ================================================================== pump
// Core1 drain of the TinyUSB audio fifo into whole 3840-byte PCM blocks for the
// IPC ring. Called thousands of times per second from usb_audio_core1_tick(),
// so the fifo is emptied between USB frames and the single-buffered iso OUT
// endpoint is always re-armed by the next tud_task() pass.
//
// Alignment: host packets are 192 B = 96 stereo frames, but tud_audio_read()
// can hand back a partial chunk; a read must never split a 4-byte stereo frame
// across block boundaries or core0 reads torn L/R. Hold back the tail bytes in
// staging[] until the next pass completes the frame.
static uint8_t staging[256];
static uint16_t staging_len;

// Whole stereo frames are packed into this 20 ms block; when it fills it is
// pushed to core0 as ONE block (so the consumer never sees a partial block).
static uint8_t pcm_block[BLOCK_BYTES];
static uint16_t pcm_fill;

// p3-3500 plug-and-play source detection: the recency probe is published to core0
// through the IPC snapshot (ipc_audio_data_seen). rtc_tick compares
// ipc_audio_ms_since_data() against its thresholds: data arriving -> the speaker
// source switches to USB automatically, no data for >100 ms -> back to mute
// (never the test tone). 0 = "no data since boot".
void usb_audio_pump(void) {
    c1_pump_calls++;                              // p3-3635: service-rate telemetry
    // p3-3643: after the host closes the stream (alt 0) the class driver has
    // de-initialised the OUT fifo; calling tud_audio_available()/read() in that
    // window dereferenced a torn-down fifo and hard-faulted core1. Never touch
    // the driver while the stream is closed.
    if (!stream_on) return;
    if (!tud_audio_available()) return;
    ipc_audio_data_seen(net_infra_uptime_us());   // fifo has data RIGHT NOW
    bool feed = ipc_audio_get_want();             // core0 wants USB audio right now
    for (int guard = 8; guard-- && staging_len < sizeof staging;) {
        if (!tud_audio_available()) break;
        uint16_t n = tud_audio_read(staging + staging_len,
                                    (uint16_t)(sizeof staging - staging_len));
        if (!n) break;
        staging_len = (uint16_t)(staging_len + n);
        uint16_t whole = staging_len & ~(uint16_t)3u;   // whole stereo frames only
        if (whole) {
            {   // p3-3622: peak of the RAW USB PCM (s16 LE stereo) - proves whether
                // the host is actually streaming non-silent audio into the UAC1 device.
                int16_t pk = 0;
                for (uint16_t k = 0; k + 1 < whole; k += 2) {
                    int16_t v = (int16_t)((uint16_t)staging[k] | ((uint16_t)staging[k + 1] << 8));
                    if (v < 0) v = (int16_t)-v;
                    if (v > pk) pk = v;
                }
                if (pk > c1_raw_peak_pub) c1_raw_peak_pub = pk;
            }
            usb_stats.pkts++;
            if (feed) {
                uint32_t off = 0;
                while (off < whole) {
                    uint32_t room = (uint32_t)BLOCK_BYTES - (uint32_t)pcm_fill;
                    uint32_t take = (uint32_t)whole - off;
                    if (take > room) take = room;
                    memcpy(pcm_block + pcm_fill, staging + off, take);
                    pcm_fill = (uint16_t)(pcm_fill + take);
                    off += take;
                    if (pcm_fill == BLOCK_BYTES) {       // one full 20 ms block
                        ipc_pcm_push(pcm_block, BLOCK_BYTES);
                        usb_stats.blocks++;
                        usb_stats.pushed += BLOCK_BYTES;
                        pcm_fill = 0;
                    }
                }
            }
            staging_len = (uint16_t)(staging_len - whole);
            if (staging_len) memmove(staging, staging + whole, staging_len);
        }
    }
}

// Drop everything currently buffered (staging tail + partial block), so a stream
// that just resumed starts from LIVE audio instead of the tail accumulated before
// the idle mute. Core1 context only; the IPC ring is reset by the core0 consumer
// (ipc_pcm_reset) - the producer must never write its tail.
void usb_audio_flush(void) {
    staging_len = 0;
    pcm_fill = 0;
}

// ================================================================== callbacks
// SET_INTERFACE completed with EPs opened/closed (TinyUSB audio driver, from
// the 1 kHz alarm's tud_task -> IRQ context: set flags and log only).
// set_itf fires for EVERY successful alt change (alt 0 included - Windows
// sets alt 0 first), so parse the requested alt from wValue instead of
// assuming "open".
bool tud_audio_set_itf_cb(uint8_t rhport, tusb_control_request_t const *p_request) {
    (void)rhport;
    uint8_t alt = (uint8_t)(p_request->wValue & 0xFF);
    uint8_t itf = (uint8_t)(p_request->wIndex & 0xFF);
    stream_on = (alt == 1);
    FWLOG("uac1: set_itf itf=%u alt=%u (%s)", itf, alt,
          alt ? "stream open 48k stereo s16" : "idle");
    return true;
}

bool tud_audio_set_itf_close_ep_cb(uint8_t rhport, tusb_control_request_t const *p_request) {
    (void)rhport;
    FWLOG("uac1: close EPs (itf=%u alt=%u)", p_request->wIndex & 0xFF,
          p_request->wValue & 0xFF);
    stream_on = false;      // the PCM block assembler survives; a restarted stream refills it
    return true;
}

bool usb_audio_streaming(void) { return stream_on; }

// Bus reset / SET_CONFIG(0) (called from tud_umount_cb on CORE 1): the TinyUSB
// driver resets its own state silently, so mirror the old uac1_reset() behaviour
// and drop our stream flag too. Published to core0 so it stops selecting the USB
// source at once.
void usb_audio_detach(void) {
    stream_on = false;
    ipc_audio_stream_set(false);
    ipc_audio_set_want(false);
}

// ================================================================== Opus (CORE 0)
// Encoder in static storage (no heap policy questions). p3-3624: 48 kHz STEREO
// input, matching the controller's SDP audio profile and the audible TONE recipe.
// The runtime check below refuses (and logs) rather than corrupting RAM.
//
// p3-3641: created and used from CORE 0 only. libopus is built with
// NONTHREADSAFE_PSEUDOSTACK, so opus_encode() borrows its ~33-40 KiB of ALLOC()
// scratch from the static, canaried buffer above instead of the CPU stack or the
// heap. core0's stack is 4 KiB, so every PCM buffer below is deliberately static.
#define OPUS_MEM_BYTES 45056
static uint8_t opus_mem[OPUS_MEM_BYTES] __attribute__((aligned(4)));
static OpusEncoder *opus_enc;
static bool opus_tried;
static int16_t pcm_blk[BLOCK_FRAMES * AUDIO_OPUS_CHANNELS];   // one 20 ms 48k stereo block
static uint8_t silence_frame[IPC_AUDIO_FRAME_MAX];           // pre-encoded fallback
static volatile uint16_t silence_len;

static bool opus_setup(void) {
    if (opus_enc) return true;
    if (opus_tried) return false;
    opus_tried = true;
    int need = opus_encoder_get_size(AUDIO_OPUS_CHANNELS);
    if (need <= 0 || (uint32_t)need > sizeof opus_mem) {
        FWLOG("opus: encoder size %d exceeds %u", need, (unsigned)sizeof opus_mem);
        return false;
    }
    int rc = opus_encoder_init((OpusEncoder *)opus_mem, AUDIO_OPUS_RATE,
                               AUDIO_OPUS_CHANNELS, OPUS_APPLICATION_AUDIO);
    if (rc != OPUS_OK) { FWLOG("opus: init rc=%d", rc); return false; }
    opus_enc = (OpusEncoder *)opus_mem;
    opus_encoder_ctl(opus_enc, OPUS_SET_BITRATE(AUDIO_OPUS_BITRATE));
    opus_encoder_ctl(opus_enc, OPUS_SET_COMPLEXITY(AUDIO_OPUS_COMPLEXITY));
    opus_encoder_ctl(opus_enc, OPUS_SET_VBR(1));
    opus_encoder_ctl(opus_enc, OPUS_SET_INBAND_FEC(0));
    opus_encoder_ctl(opus_enc, OPUS_SET_DTX(0));
    opus_encoder_ctl(opus_enc, OPUS_SET_PACKET_LOSS_PERC(0));
    FWLOG("opus: encoder ready size=%dB rate=%d ch=%d br=%d cpx=%d ps=%u/%u (%s)",
          need, AUDIO_OPUS_RATE, AUDIO_OPUS_CHANNELS, AUDIO_OPUS_BITRATE,
          AUDIO_OPUS_COMPLEXITY, (unsigned)OPUS_STATIC_SCRATCH_BYTES,
          (unsigned)OPUS_PSEUDOSTACK_BYTES, opus_get_version_string());
    return true;
}

// Core0 boot: create the encoder and pre-encode the SILENCE frame the RTP pump
// falls back to when a 20 ms slot has no PCM yet (encoder warm-up / underflow).
// The controller's playback pump only advances on CONSECUTIVE RTP sequence
// numbers, so a slot must never be skipped. This first opus_encode() is also the
// one and only call that arms libopus's pseudostack (opus_alloc_scratch), so the
// heap log printed right after rtc_init() is already the real working headroom -
// and the ps_after() below prints what the static buffer actually measured.
bool usb_audio_encoder_init(void) {
    if (!opus_setup()) return false;
    static int16_t zeros[BLOCK_FRAMES * AUDIO_OPUS_CHANNELS];   // static: 4 KiB stack!
    uint8_t frame[IPC_AUDIO_FRAME_MAX];
    bool poisoned = ps_fill();              // only the 2nd+ call can measure a peak
    int n = opus_encode(opus_enc, zeros, BLOCK_FRAMES, frame, (int)sizeof frame);
    ps_after("silence", poisoned);
    if (n <= 0) {
        FWLOG("audio: silence frame encode rc=%d", n);
        return false;
    }
    memcpy(silence_frame, frame, (size_t)n);
    __dmb();
    silence_len = (uint16_t)n;
    FWLOG("core0: silence frame ready (%d B)", n);
    return true;
}

const uint8_t *usb_audio_silence(int *n) {
    *n = (int)silence_len;
    return silence_frame;
}

// Core0: one RTP slot's live frame. Reads EXACTLY one 3840-byte PCM block from
// the IPC ring (zero-filled if core1 has not delivered enough - that keeps the
// RTP sequence gapless), encodes it, returns the packet size or 0 on failure.
int usb_audio_encode_live(uint8_t *out, int cap) {
    if (!opus_setup()) return 0;
    (void)ipc_pcm_read(pcm_blk, BLOCK_BYTES);   // zero-fill short; underruns counted in ipc.c
    {   // p3-3621 input-signal probe: is the 48k stereo block actually non-zero?
        int16_t peak = 0;
        for (int i = 0; i < BLOCK_FRAMES * AUDIO_OPUS_CHANNELS; i++) {
            int16_t v = pcm_blk[i] < 0 ? (int16_t)-pcm_blk[i] : pcm_blk[i];
            if (v > peak) peak = v;
        }
        c0_pcm_peak_pub = peak;
    }
    // p3-3646: poison before t0 such that the memset cost stays OUTSIDE the timed
    // interval; the backwards scan in ps_after() is ~30 B of work in the normal case.
    bool poisoned = ps_fill();
    uint32_t t0 = net_infra_uptime_us();
    int n = opus_encode(opus_enc, pcm_blk, BLOCK_FRAMES, out, cap);
    uint32_t dt = net_infra_uptime_us() - t0;
    ps_after("live", poisoned);             // canary + creep + peak, never fails the frame
    if (n < 0) { c0_enc_fail++; FWLOG("opus: encode rc=%d", n); return 0; }
    c0_enc_ok++;
    c0_enc_us_last = dt;
    c0_enc_us_sum += dt;
    if (dt > c0_enc_us_max) c0_enc_us_max = dt;
    return n;
}

void usb_audio_encode_stats(uint32_t *ok, uint32_t *fail, uint32_t *last_us,
                            uint32_t *avg_us, uint32_t *max_us, int16_t *peak) {
    if (ok) *ok = c0_enc_ok;
    if (fail) *fail = c0_enc_fail;
    if (last_us) *last_us = c0_enc_us_last;
    if (avg_us) *avg_us = c0_enc_ok ? (c0_enc_us_sum / c0_enc_ok) : 0;
    if (max_us) *max_us = c0_enc_us_max;
    if (peak) *peak = c0_pcm_peak_pub;
}

// p3-3621 raw-USB peak + pump counters, for core1's 5 s line.
void usb_audio_pump_stats(uint32_t *pumps, uint32_t *pushed, uint32_t *blocks,
                          int16_t *raw_peak) {
    if (pumps) *pumps = c1_pump_calls;
    if (pushed) *pushed = usb_stats.pushed;
    if (blocks) *blocks = usb_stats.blocks;
    if (raw_peak) *raw_peak = c1_raw_peak_pub;
}

// ================================================================== bench
// OPUSBENCH: paced on-device benchmark (route B Go/No-Go: < 10 ms per 20 ms frame
// leaves room for the USB/network loops).
// p3-3641: MOVED TO CORE 0 (stated choice). core1's CDC parser only queues a
// request (usb_audio_bench_start); usb_audio_bench_tick() runs from rtc_tick and
// encodes on the SAME encoder the live path uses, one frame per 20 ms slot.
// Measuring core0 is also the number that now matters: core0 must fit the encode
// next to WiFi/TLS. The old core1 stack high-water probe is gone with the
// pseudostack (there is no big stack use left to measure).
static struct {
    volatile uint32_t request;            // core1 -> core0
    bool running;
    int phase;                            // 0..3: cpx0/cpx1/cpx2 square, cpx1* noise
    int frames_left;
    uint32_t t_us, frames, max_us;
    uint32_t sq_phase;                    // 440 Hz square oscillator phase (Q16)
    int16_t pcm[BLOCK_FRAMES * AUDIO_OPUS_CHANNELS];
} bench;
static const int bench_cpx[4] = { 0, 1, 2, AUDIO_OPUS_COMPLEXITY };
#include "pico/rand.h"

static void bench_fill(int noise) {
    for (int i = 0; i < BLOCK_FRAMES; i++) {
        int v;
        if (noise) v = (int)((get_rand_32() >> 16) * 15000) - 7500;  // ~ +-7.5k white
        else {
            // p3-3646: this used to advance a 32-bit phase and toggle on bit 31 -
            // (440<<16)/48000 = 600/sample needs 3.58M samples per half period (74 s
            // at 48 kHz), so phases 0-2 encoded a constant DC level and libopus
            // answered with a 3-byte "silence" frame (tests/pseudostack_peak_probe.c
            // host measurement: 3 B for that, 241 B for a real 440 Hz square). The
            // bench was timing the cheapest path in the codec, not an encode.
            bench.sq_phase = (bench.sq_phase + (440u << 16) / (unsigned)AUDIO_OPUS_RATE) & 0xFFFFu;
            v = (bench.sq_phase < 0x8000u) ? 9000 : -9000;   // ~109.2 samples/cycle = 439.5 Hz
        }
        bench.pcm[2 * i]     = (int16_t)v;   // stereo interleaved (same on both channels)
        bench.pcm[2 * i + 1] = (int16_t)v;
    }
}

// Called from the CORE 1 CDC parser: queue the request, never touch the encoder.
void usb_audio_bench_start(void) {
    if (bench.request) { FWLOG("opusbench: already queued/running"); return; }
    __dmb();
    bench.request = 1;
    FWLOG("opusbench: requested (runs on core0)");
}

static void bench_begin(void) {
    if (!opus_setup()) { FWLOG("opusbench: no encoder"); return; }
    bench.phase = 0;
    bench.frames = 0; bench.t_us = 0; bench.max_us = 0;
    bench.frames_left = AUDIO_BENCH_FRAMES;
    bench.sq_phase = 0;
    bench.running = true;
    opus_encoder_ctl(opus_enc, OPUS_SET_COMPLEXITY(bench_cpx[0]));
    FWLOG("opusbench: start %d frames/phase, %d Hz stereo 20ms, phases cpx0/1/2+noise (core%u)",
          AUDIO_BENCH_FRAMES, AUDIO_OPUS_RATE, (unsigned)get_core_num());
}

static void bench_next_phase(void) {
    uint32_t avg = bench.frames ? bench.t_us / bench.frames : 0;
    FWLOG("opusbench: phase=%d cpx=%d %s avg=%lu.%02lu ms/frame max=%lu.%02lu ms pscreep=%u pspeak=%u",
          bench.phase, bench_cpx[bench.phase],
          bench.phase == 3 ? "noise" : "square",
          (unsigned long)(avg / 1000), (unsigned long)((avg % 1000) / 10),
          (unsigned long)(bench.max_us / 1000), (unsigned long)((bench.max_us % 1000) / 10),
          (unsigned)ps_creep, (unsigned)ps_peak_max);
    bench.phase++;
    if (bench.phase >= 4) {
        bench.running = false;
        opus_encoder_ctl(opus_enc, OPUS_SET_COMPLEXITY(AUDIO_OPUS_COMPLEXITY));
        FWLOG("opusbench: done (core%u, pseudostack=%u B static/%u req, pscreep=%u psmax=%u canary=%u)",
              (unsigned)get_core_num(), (unsigned)OPUS_STATIC_SCRATCH_BYTES,
              (unsigned)OPUS_PSEUDOSTACK_BYTES, (unsigned)ps_creep,
              (unsigned)ps_peak_max, (unsigned)ps_canary_trips);
        return;
    }
    bench.frames = 0; bench.t_us = 0; bench.max_us = 0;
    bench.frames_left = AUDIO_BENCH_FRAMES;
    opus_encoder_ctl(opus_enc, OPUS_SET_COMPLEXITY(bench_cpx[bench.phase]));
}

// Core0 only, called once per rtc_tick.
void usb_audio_bench_tick(void) {
    if (!bench.running) {
        if (!bench.request) return;
        bench.request = 0;
        bench_begin();
        if (!bench.running) return;
    }
    static uint32_t next_bench_us;
    uint32_t now = net_infra_uptime_us();
    if ((int32_t)(now - next_bench_us) < 0) return;
    next_bench_us = now + 20000;
    static uint8_t sink[400];
    // ONE encode per 20 ms slot. The benchmark measures encoder cost; running it
    // alongside live USB audio is a deliberate stress test (each tick then does
    // one live + one bench encode), so expect PCM underruns while it runs.
    bench_fill(bench.phase == 3);
    bool poisoned = ps_fill();              // p3-3646: peak probe, outside the timing window
    uint32_t t0 = net_infra_uptime_us();
    int n = opus_encode(opus_enc, bench.pcm, BLOCK_FRAMES, sink, sizeof sink);
    uint32_t dt = net_infra_uptime_us() - t0;
    ps_after("bench", poisoned);
    if (n < 0) { FWLOG("opusbench: encode rc=%d", n); bench.running = false; return; }
    bench.t_us += dt; bench.frames++;
    if (dt > bench.max_us) bench.max_us = dt;
    bench.frames_left--;
    if (!bench.frames_left) bench_next_phase();
}

// ================================================================== core1 loop
// One pass of the core1 audio work. Called thousands of times per second from the
// USB loop: it drains the TinyUSB fifo into the IPC PCM ring and publishes the
// source-detection/telemetry snapshots. NO encoder call happens here any more.
void usb_audio_core1_tick(void) {
    usb_audio_pump();

    ipc_audio_stream_set(stream_on);            // core0's auto-source detector

    // core0 asked to drop buffered audio (source switched away / stream restart)
    if (ipc_audio_take_flush()) usb_audio_flush();

    static bool was_want;
    bool want = ipc_audio_get_want();
    if (want != was_want) {
        was_want = want;
        usb_audio_flush();                      // start/stop from LIVE audio
        FWLOG("core1: pcm feed %s (stream=%d)", want ? "start" : "stop", stream_on ? 1 : 0);
    }

    // p3-3621 AUDIO TELEMETRY (5 s while the USB source is active): core1's side
    // of the pipeline - how fast the fifo is drained, how much PCM reached the
    // ring, and how much the ring dropped because core0 fell behind.
    if (want) {
        static uint32_t last_ms;
        uint32_t ms = to_ms_since_boot(get_absolute_time());
        if (!last_ms || ms - last_ms >= 5000) {
            last_ms = ms ? ms : 1;
            uint32_t pumps, pushed, blocks; int16_t raw;
            usb_audio_pump_stats(&pumps, &pushed, &blocks, &raw);
            static uint32_t pump_prev, push_prev;
            uint32_t pump_win = pumps - pump_prev;
            uint32_t push_win = pushed - push_prev;
            pump_prev = pumps; push_prev = pushed;
            FWLOG("audio c1: pump=%u/s push=%u/s blk=%u ring=%u drop=%u stream=%d raw=%d",
                  (unsigned)(pump_win / 5u), (unsigned)(push_win / 5u),
                  (unsigned)blocks, (unsigned)ipc_pcm_level(),
                  (unsigned)ipc_pcm_dropped(), stream_on ? 1 : 0, (int)raw);
            c1_raw_peak_pub = 0;   // per-window peak
        }
    }
}

void usb_audio_init(void) { }   // TinyUSB registers the class driver itself;
                                // our state is static-zero (stream_on = false).
                                // The encoder is created by usb_audio_encoder_init()
                                // on CORE 0 (rtc_init).
