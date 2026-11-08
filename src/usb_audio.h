// usb_audio.h — UAC1 playback data path (PC audio in) + the Opus frame source.
//
// p3-3641-core0encode: the data path is split across both cores.
//   core1: usb_audio_core1_tick() drains the TinyUSB audio fifo into whole
//          3840-byte 20 ms PCM blocks and pushes them into the IPC PCM ring
//          (ipc.h). It never calls libopus.
//   core0: usb_audio_encoder_init() creates the encoder at boot,
//          usb_audio_encode_live() encodes one block per RTP slot, and
//          usb_audio_silence() supplies the gapless-sequence fallback frame.
#pragma once
#include <stdint.h>
#include <stdbool.h>

void usb_audio_init(void);     // nothing at the moment (TinyUSB registers the
                               // audio class driver itself via its driver table)

// ---- core1 (USB island) ----------------------------------------------------
// Called every loop pass from core1_main(): pump the TinyUSB fifo, publish the
// stream/recency telemetry, and push PCM blocks into the IPC ring.
void usb_audio_core1_tick(void);

void usb_audio_pump(void);     // fifo -> 3840 B block -> ipc_pcm_push (core1)
void usb_audio_flush(void);    // core1: drop staging tail + partial block

bool usb_audio_streaming(void);              // host set AS alt 1 (a stream is open)
void usb_audio_detach(void);                 // bus reset: drop the stream flag

// ---- core0 (encoder owner) -------------------------------------------------
// Create the 48 kHz stereo encoder and pre-encode the silence fallback. Also
// arms libopus's pseudostack (static .bss buffer, see src/usb_audio.c), so call
// it BEFORE the boot heap-headroom log.
bool usb_audio_encoder_init(void);

// One 20 ms RTP slot: read exactly one 3840-byte PCM block from the IPC ring
// (zero-filled if short), encode it, return the packet size (0 = unusable).
int  usb_audio_encode_live(uint8_t *out, int cap);

// Pre-encoded silence frame for a slot with no fresh frame (keeps RTP seq
// gapless). *n = 0 until usb_audio_encoder_init() succeeded.
const uint8_t *usb_audio_silence(int *n);

// Encode counters/timing for the 10 s `audio usb:` line (core0).
void usb_audio_encode_stats(uint32_t *ok, uint32_t *fail, uint32_t *last_us,
                            uint32_t *avg_us, uint32_t *max_us, int16_t *peak);
// p3-3646 pseudostack health for the 10 s `audio ps:` line (core0):
//   creep      = global_stack - scratch_ptr after the last top-level encode
//                (0 = every SAVE/RESTORE balanced; growing = leaked pointer)
//   creep_max  = worst creep seen
//   peak_max   = deepest single-call pseudostack use (0xA5 high-water probe)
//   canary     = times the 0xC5 canary behind the static buffer was trashed
void usb_audio_ps_stats(uint32_t *creep, uint32_t *creep_max, uint32_t *peak_max,
                        uint32_t *canary_trips);
// Core1 pump counters for the 5 s `audio c1:` line (core1).
void usb_audio_pump_stats(uint32_t *pumps, uint32_t *pushed, uint32_t *blocks,
                          int16_t *raw_peak);

// ---- console commands ------------------------------------------------------
void usb_audio_bench_start(void);   // OPUSBENCH request (queued core1 -> core0)
void usb_audio_bench_tick(void);    // core0: execute/pacing from rtc_tick
