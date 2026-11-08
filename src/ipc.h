// ipc.h — core0 <-> core1 shared-memory IPC for the RP2350 dual-core split
// (p3-3600-dualcore).
//
// Split contract:
//   core0: CYW43/lwIP, fake cloud (HTTPS/TLS), ICE/DTLS/SRTP, RTP pacing, the
//          Opus ENCODE of the UAC1 PCM (p3-3641), network main loop.
//   core1: TinyUSB (tud_task loop), UAC1 iso capture -> PCM block -> IPC ring,
//          XInput pad IN reports and OUT rumble frames, CDC console.
//
// Every buffer below is SINGLE-PRODUCER / SINGLE-CONSUMER with a fixed core
// assignment, so no lock is needed on the data path - only release/acquire
// barriers (`__dmb()`). The one exception is the log ring, which both cores
// write (MPSC) and core1 drains: it is protected by a hardware spinlock.
//
// All `volatile` index/flag fields are 32-bit aligned; the ARMv8-M store
// ordering plus __dmb() at the publish point is what makes the payload visible
// before the index.
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "rtc.h"                 // pad_state_t

// ---- audio: PCM ring core1 (USB pump) -> core0 (Opus encode + send) -------
// p3-3641-core0encode: the Opus encode moved OFF core1 (it blocked the single-
// buffered iso OUT endpoint for 7.9 ms avg / 15.8 ms worst per 20 ms frame, so
// 58% of the UAC1 PCM was dropped on real hardware). core1 now only drains the
// TinyUSB audio fifo into this ring; core0 encodes exactly one block per 20 ms
// RTP slot. 48 kHz stereo s16, 20 ms = 960 frames = 3840 B.
#define IPC_AUDIO_FRAME_MAX  400        // max Opus packet (VBR 96 kbps peaks ~300 B)
#define IPC_PCM_BLOCK_BYTES  3840       // one 20 ms 48k stereo s16 block
#define IPC_PCM_RING_BYTES   16384      // 85 ms @ 192 kB/s; power of two (SPSC mask). p3-3647: 32K->16K to fund the RAM hot path; prefill 60 ms keeps margin (same as variant A).
#define IPC_PCM_PREFILL_BYTES (3u * IPC_PCM_BLOCK_BYTES)   // 60 ms jitter cushion

// ---- console commands: core1 (CDC parser) -> core0 (state owner) ----------
enum {
    IPC_CMD_TONE = 1,       // rtc_audio_tone_start(2500)
    IPC_CMD_RUMBLE,         // rtc_rumble_pulse()
    IPC_CMD_DTLS_TEST,      // rtc_request_dtls_selftest()
    IPC_CMD_ENCDUMP,        // cloud_encoder_dump()
    IPC_CMD_AUDPTEST,       // rtc_audio_test_raw()
};

// ---- lifecycle -------------------------------------------------------------
// Call from core0 BEFORE multicore_launch_core1(): claims the log spinlock and
// clears every buffer. Idempotent (a second call is a no-op - it must never wipe
// queues a live core1 is using).
void ipc_init(void);

// ---- log rings (two lock-free SPSC rings, p3-3606) --------------------------
// Ring A: core0 writes, core1 drains to the CDC. Ring B: core1-local (writes and
// drains on the same core). Separate rings = no cross-core lock, so a wedged or
// faulting core1 can never freeze core0's logging (and vice versa).
void ipc_log_write(const char *data, int n);     // core0 (core1 calls are rerouted)
// core1 only: move up to cap bytes out (returns 0 when empty).
int  ipc_log_read(char *dst, int cap);
void ipc_log_clear(void);      // core1 only: drop ring A (CDC detached)
void ipc_c1_log_write(const char *data, int n);  // core1 local ring
int  ipc_c1_log_read(char *dst, int cap);        // core1 local ring

// ---- post-watchdog-reset diagnosis (p3-3626) --------------------------------
// The last core0 log line survives a watchdog reset in NOLOAD SRAM; print it on
// the next boot to see where a 12 s stall happened even when the console died.
int  ipc_prev_log_copy(char *dst, int cap, uint32_t *ms_out);   // 0 = none
void ipc_prev_log_clear(void);
void ipc_prev_https_set(const char *diag);        // core0: remember last https_diag
int  ipc_prev_https_copy(char *dst, int cap);     // 0 = none

// ---- pad snapshot (core0 decode -> core1 XInput IN report) -----------------
// Seqlock: writer may be interrupted by an IRQ, reader retries on tear.
void ipc_pad_publish(const pad_state_t *p);
bool ipc_pad_read(pad_state_t *out);

// ---- rumble frames (core1 USB OUT callback -> core0 rumble_flush) ----------
void ipc_rumble_push(uint16_t l, uint16_t r);
bool ipc_rumble_pop(uint16_t *l, uint16_t *r);

// ---- console commands (core1 -> core0) -------------------------------------
void ipc_cmd_push(uint8_t cmd);
bool ipc_cmd_pop(uint8_t *cmd);

// ---- audio source handshake (core0 decides, core1 feeds PCM) --------------
// want=1: core0's speaker source is the USB stream -> core1 pushes PCM blocks.
// want=0: stop feeding (core1 drops its staging tail).
void ipc_audio_set_want(bool on);
bool ipc_audio_get_want(void);
// core0 -> core1: drop buffered USB audio (source switched away / stream restart).
void ipc_audio_request_flush(void);
bool ipc_audio_take_flush(void);

// ---- PCM SPSC byte ring (core1 producer -> core0 consumer) ----------------
// p3-3641-core0encode. core1 writes whole 3840-byte 20 ms blocks; core0 reads
// exactly one block per RTP slot. Lock-free like the other queues: the producer
// writes the payload, __dmb(), then bumps pcm_head; the consumer reads the head,
// __dmb(), copies the payload, then bumps pcm_tail.
void ipc_pcm_push(const uint8_t *data, int n);   // core1: whole block, drops if full
int  ipc_pcm_read(void *dst, int n);             // core0: exactly n B (zero-fill short);
                                                 //        returns bytes that came from the ring
uint32_t ipc_pcm_level(void);                    // buffered bytes
uint32_t ipc_pcm_dropped(void);                  // bytes dropped because the ring was full
uint32_t ipc_pcm_under(void);                    // bytes zero-filled because the ring ran dry
void ipc_pcm_reset(void);                        // core0: drop all buffered PCM (stream restart)
void ipc_audio_stream_set(bool on);        // host selected AS alt 1
bool ipc_audio_stream_get(void);
// Core1's USB-audio pump saw fifo data at this uptime (us, low 32 bits).
void ipc_audio_data_seen(uint32_t uptime_us);
// Milliseconds since the last data, computed on whatever core asks (both cores
// read the same 1 MHz timer). 0xFFFFFFFF = no data since boot.
uint32_t ipc_audio_ms_since_data(uint32_t now_us);
void ipc_enum_count_set(uint8_t n);        // tud_mount_cb hits since boot
uint8_t ipc_enum_count(void);

// ---- liveness ---------------------------------------------------------------
// core1 increments its beat counter every loop pass; core0 watches it and stops
// feeding the watchdog if core1 has been wedged for seconds (the WDT is a
// chip-level counter - core0's own loop would otherwise keep a dead core1 alive
// forever and the USB side would silently stop).
void ipc_core1_beat(void);                 // core1
uint32_t ipc_core1_beats(void);            // core0

// ---- diagnostics (p3-3604 stage probe) --------------------------------------
// core1 publishes the init/loop stage it is entering. If core1 wedges, core0
// reads the stage the hang happened in and encodes it into the delay before it
// drops into the ROM bootloader (2 s per stage) - that makes a hang diagnosable
// without a working serial console.
void ipc_diag_stage_set(uint8_t stage);    // core1
uint8_t ipc_diag_stage_get(void);          // core0
