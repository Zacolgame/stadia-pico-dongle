// opus_host_bench.c - host build of the VENDORED libopus (same fixed-point sources
// the firmware compiles) to (a) prove the vendored subset links and encodes valid
// packets with our exact settings, (b) measure the relative cost of complexity
// 0/1/2 and worst-case (noise) input. Host timings do NOT translate to the
// Cortex-M33 - the on-device Go/No-Go numbers come from the firmware's OPUSBENCH
// command (usb_audio.c) once the rig's COM port is free. Build script:
// tests/run_opus_host_bench.bat (MSVC needs USE_ALLOCA instead of VAR_ARRAYS).
#include "opus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FRAME 320            // 20 ms @ 16 kHz
#define NFRAMES 500

static long long now_ms(void) {
    return (long long)clock() * 1000ll / CLOCKS_PER_SEC;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);   // survive crashes: see how far we got
    static unsigned char mem[40960];
    printf("opus_get_version_string: %s\n", opus_get_version_string());
    printf("opus_encoder_get_size(1) = %d bytes (firmware buffer 40960)\n",
           opus_encoder_get_size(1));
    int rc = opus_encoder_init((OpusEncoder *)mem, 16000, 1, OPUS_APPLICATION_AUDIO);
    if (rc != OPUS_OK) { printf("init rc=%d\n", rc); return 1; }
    OpusEncoder *e = (OpusEncoder *)mem;
    opus_encoder_ctl(e, OPUS_SET_BITRATE(64000));
    opus_encoder_ctl(e, OPUS_SET_VBR(1));
    opus_encoder_ctl(e, OPUS_SET_INBAND_FEC(0));
    opus_encoder_ctl(e, OPUS_SET_DTX(0));

    static short pcm[FRAME];
    static unsigned char out[400];
    srand(1234);
    for (int cpx = 0; cpx <= 2; cpx++) {
        for (int noise = 0; noise <= (cpx == 1 ? 1 : 0); noise++) {
            opus_encoder_ctl(e, OPUS_SET_COMPLEXITY(cpx));
            // deterministic content: 440 Hz square (matches firmware bench) or noise
            unsigned phase = 0;
            long long t0 = now_ms();
            int n = 0, total = 0, minn = 1 << 30, maxn = 0;
            for (int f = 0; f < NFRAMES; f++) {
                for (int i = 0; i < FRAME; i++) {
                    if (noise) pcm[i] = (short)(rand() % 15000) - 7500;
                    else { phase += 1802; pcm[i] = (phase & 0x80000000u) ? 9000 : -9000; }
                }
                n = opus_encode(e, pcm, FRAME, out, sizeof out);
                if (n < 0) { printf("encode rc=%d\n", n); return 1; }
                total += n; if (n < minn) minn = n; if (n > maxn) maxn = n;
            }
            long long dt = now_ms() - t0;
            printf("cpx=%d %s: %d frames, %lld ms total = %.3f ms/frame "
                   "(host; packet %d..%d B, avg %d B)\n",
                   cpx, noise ? "noise" : "square", NFRAMES, dt,
                   (double)dt / NFRAMES, minn, maxn, total / NFRAMES);
        }
    }
    // silence cost (what the stream sends when the PC plays nothing)
    opus_encoder_ctl(e, OPUS_SET_COMPLEXITY(1));
    memset(pcm, 0, sizeof pcm);
    long long t0 = now_ms();
    int total = 0;
    for (int f = 0; f < NFRAMES; f++) total += opus_encode(e, pcm, FRAME, out, sizeof out);
    long long dt = now_ms() - t0;
    printf("cpx=1 silence: %d frames, %lld ms total = %.3f ms/frame, avg packet %d B "
           "(host)\n", NFRAMES, dt, (double)dt / NFRAMES, total / NFRAMES);
    printf("RESULT: OK\n");
    return 0;
}
