// pseudostack_peak_probe.c - OFFLINE measurement of libopus's pseudostack peak
// for the EXACT firmware encoder configuration, so the p3-3646 question ("is
// GLOBAL_STACK_SIZE=40960 actually enough?") is answered before touching hardware.
//
// Why this number transfers: libopus is built here with the same
// NONTHREADSAFE_PSEUDOSTACK + OVERRIDE_OPUS_ALLOC_SCRATCH defines the firmware
// target uses, FIXED_POINT (opus_val16 = int16, celt_sig = int32), and the same
// 48 kHz / 2 ch / 960-frame settings - so every ALLOC() size is identical to the
// Cortex-M33 build and the peak (in bytes) is identical too. Only CPU time
// differs; this probe does not measure timing.
//
// Method (mirrors src/usb_audio.c ps_fill/ps_peak_scan): poison the whole scratch
// with 0xA5 before each top-level opus_encode(), scan backwards from the end
// afterwards; the highest non-0xA5 byte is the true high-water mark of that call.
// Also prints creep = global_stack - scratch_ptr after every call (must be 0; a
// growing value would be a leaked pseudostack pointer, i.e. a SAVE/RESTORE bug).
//
// Build+run: tests\run_pseudostack_probe.bat
#include "opus.h"
#include <stdio.h>
#include <stddef.h>
#include <string.h>

// celt/celt.c (CELT_C) owns both globals; celt/stack_alloc.h declares them.
extern char *global_stack, *scratch_ptr;

#define STACK_BYTES 65536            // deliberately way over 40960: measure, then compare
#define FILL_BYTE   0xA5u
#define CANARY_BYTE 0xC5u
#define CANARY_LEN  16

static struct {
    unsigned char s[STACK_BYTES];
    unsigned char canary[CANARY_LEN];
} area;

static unsigned canary_trips;

// libopus calls this once (ALLOC_STACK, first encode) with GLOBAL_STACK_SIZE.
void *opus_alloc_scratch(size_t size) {
    printf("opus_alloc_scratch(request=%u B) -> probe buffer %u B\n",
           (unsigned)size, (unsigned)STACK_BYTES);
    memset(area.canary, CANARY_BYTE, CANARY_LEN);
    return area.s;
}

static unsigned peak_scan(void) {
    const unsigned char *p = area.s + STACK_BYTES;
    while (p > area.s && p[-1] == FILL_BYTE) p--;
    return (unsigned)(p - area.s);
}

static unsigned creep_now(void) {
    if (!global_stack || !scratch_ptr || global_stack <= scratch_ptr) return 0;
    return (unsigned)(global_stack - scratch_ptr);
}

#define FRAME      960                    // 20 ms @ 48 kHz
#define CH         2
#define BITRATE    96000                  // config.h AUDIO_OPUS_BITRATE
#define CPX_MAX    1                      // config.h AUDIO_OPUS_COMPLEXITY

static short pcm[FRAME * CH];
static unsigned char out[400];
static unsigned sq_phase;

static void fill_signal(int noise) {
    unsigned s = 12345u;
    for (int i = 0; i < FRAME; i++) {
        int v;
        if (noise == 2) {                              // proper 440 Hz square (AC)
            sq_phase = (sq_phase + (440u << 16) / 48000u) & 0xFFFFu;
            v = (sq_phase < 0x8000u) ? 9000 : -9000;
        } else if (noise) {
            s = s * 1103515245u + 12345u;
            v = (int)((s >> 16) % 15001u) - 7500;      // +-7.5k white
        } else {
            sq_phase += (440u << 16) / 48000u;         // the FIRMWARE's bench_fill math:
            v = (sq_phase & 0x80000000u) ? 9000 : -9000;  // 600/sample never reaches bit 31
        }
        pcm[2 * i] = pcm[2 * i + 1] = (short)v;
    }
}

int main(void) {
    static unsigned char enc_mem[45056];               // config.h OPUS_MEM_BYTES
    static short zeros[FRAME * CH];
    printf("libopus: %s\n", opus_get_version_string());
    int need = opus_encoder_get_size(CH);
    printf("opus_encoder_get_size(%d) = %d B (firmware buffer 45056)\n", CH, need);
    if (need <= 0 || (unsigned)need > sizeof enc_mem) { printf("RESULT: FAIL needs=%d\n", need); return 1; }
    OpusEncoder *e = (OpusEncoder *)enc_mem;
    int rc = opus_encoder_init(e, 48000, CH, OPUS_APPLICATION_AUDIO);
    if (rc != OPUS_OK) { printf("init rc=%d\n", rc); return 1; }
    opus_encoder_ctl(e, OPUS_SET_BITRATE(BITRATE));
    opus_encoder_ctl(e, OPUS_SET_COMPLEXITY(CPX_MAX));
    opus_encoder_ctl(e, OPUS_SET_VBR(1));
    opus_encoder_ctl(e, OPUS_SET_INBAND_FEC(0));
    opus_encoder_ctl(e, OPUS_SET_DTX(0));

    unsigned peak_all = 0, creep_max = 0;
    const int cpx_list[5] = { 0, 1, 2, CPX_MAX, CPX_MAX };
    const int sig_list[5] = { 0, 0, 0, 1, 2 };
    const char *name[5] = { "cpx0-DC(fw)", "cpx1-DC(fw)", "cpx2-DC(fw)",
                            "cpx1-noise", "cpx1-ac440" };

    // The boot path's very first encode is the all-zero silence frame, before any
    // real audio exists - give it its own measurement (and it is what arms the
    // pseudostack, so it cannot be poisoned beforehand).
    int n = opus_encode(e, zeros, FRAME, out, (int)sizeof out);
    unsigned first_peak = peak_scan();      // garbage (unpoisoned) on purpose: report 0
    unsigned creep = creep_now();
    printf("silence(1st, unpoisoned) rc=%d creep=%u\n", n, creep);
    if (creep > creep_max) creep_max = creep;

    for (int ph = 0; ph < 5; ph++) {
        opus_encoder_ctl(e, OPUS_SET_COMPLEXITY(cpx_list[ph]));
        unsigned peak_ph = 0;
        for (int f = 0; f < 50; f++) {
            fill_signal(sig_list[ph]);
            memset(area.s, FILL_BYTE, STACK_BYTES);     // poison (as usb_audio.c ps_fill)
            n = opus_encode(e, pcm, FRAME, out, (int)sizeof out);
            if (n < 0) { printf("encode rc=%d\n", n); return 1; }
            unsigned pk = peak_scan();
            if (pk > peak_ph) peak_ph = pk;
            if (pk > peak_all) peak_all = pk;
            creep = creep_now();
            if (creep > creep_max) creep_max = creep;
            for (int i = 0; i < CANARY_LEN; i++)
                if (area.canary[i] != CANARY_BYTE) { canary_trips++; break; }
        }
        printf("%-12s peak=%u B frame=%d B\n", name[ph], peak_ph, n);
    }
    (void)first_peak;

    // u16 arithmetic is enough: peaks are < 65536 by construction.
    printf("RESULT: peak=%u B (GLOBAL_STACK_SIZE=%u, %s by %d B) creep_max=%u canary=%u\n",
           peak_all, 40960u,
           peak_all > 40960u ? "OVER" : "under",
           peak_all > 40960u ? (int)(peak_all - 40960u) : (int)(40960u - peak_all),
           creep_max, canary_trips);
    return (peak_all > 40960u) ? 2 : 0;     // exit 2 = the 40960 buffer WAS too small
}
