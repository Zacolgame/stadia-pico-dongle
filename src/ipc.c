// ipc.c — core0 <-> core1 shared-memory IPC (see ipc.h for the contract).
//
// Memory-ordering rule used everywhere below: the payload is written first, then
// `__dmb()` (a full data memory barrier, ARMv8-M `dmb sy`), then the index is
// bumped. The consumer reads the index, then `__dmb()`, then the payload. That
// is enough for SPSC queues without any lock: only one core ever writes a given
// index. The log ring is the only MPSC structure and uses a hardware spinlock.
#include "ipc.h"
#include "pico/stdlib.h"
#include "hardware/sync.h"
#include <string.h>

// ---------------------------------------------------------------- log ring
// Both cores log (clog_/FWLOG); core1 is the only drainer (it owns the CDC).
// The spinlock is claimed in ipc_init(); taking it also masks IRQs on the
// calling core.
//
// ---------------------------------------------------------------- log rings
// p3-3606: TWO LOCK-FREE SPSC RINGS, NO CROSS-CORE LOCK AT ALL.
//
// Background (real-machine post-mortem): the p3-3600 design had ONE MPSC ring
// protected by a hardware spinlock. A core1 fault/hang that happened while
// holding that lock froze core0 too (its next FWLOG spun forever with IRQs
// masked), so the whole chip silently watchdog-reset-looped with no USB and no
// console - the "dead board" we hit on hardware.
//
// The fix removes cross-core locking from the log path entirely:
//   * ring A: CORE0 writes (single producer), core1 drains (single consumer).
//   * ring B: core1 writes AND drains (same core, same thread -> no lock).
// A wedge in either core can therefore never block the other core's logging,
// and core1's crash cannot freeze core0.
#define LOG_BYTES  4096
#define C1LOG_BYTES 2048
static char logring[LOG_BYTES];
static volatile uint32_t lr_head, lr_tail;       // A: core0 -> core1
static char c1ring[C1LOG_BYTES];
static volatile uint32_t c1_head, c1_tail;       // B: core1 local

// ---------------------------------------------------------------- prev-reset log
// A watchdog reset keeps SRAM contents, so the last core0 log line can be kept in
// a NOLOAD section and printed on the NEXT boot. This is how a "core0 wedged for
// 12 s and the WDT fired" fault becomes diagnosable even though the CDC console is
// gone at the moment of the reset (real-machine 2026-11-07: unknown hang right when
// the controller connects; the console ring had already been overwritten).
#define PREV_LOG_MAGIC 0x504C4F47u            // "PLOG"
#define PREV_LOG_MAX   120
__attribute__((section(".uninitialized_data"))) static char prev_log_buf[PREV_LOG_MAX];
__attribute__((section(".uninitialized_data"))) static volatile uint32_t prev_log_magic;
__attribute__((section(".uninitialized_data"))) static volatile uint32_t prev_log_ms;
// Snapshot taken in ipc_init BEFORE this boot writes any log line, so the boot
// banner itself cannot overwrite the previous reset's evidence.
static char prev_saved[PREV_LOG_MAX];
static uint32_t prev_saved_ms;
static bool prev_saved_valid;
// Last HTTPS slot diagnostic string (ssl state / ring levels) before the reset -
// "accept then nothing" hangs need the per-slot TLS state to be diagnosable.
__attribute__((section(".uninitialized_data"))) static char prev_https_buf[96];
static char prev_https_saved[96];

// ---------------------------------------------------------------- pad snapshot
// seqlock: even = stable, odd = write in progress. The writer (core0 main loop)
// can be preempted by an IRQ but never by itself, so ++/++ is safe. `volatile` on
// the payload keeps the compiler from caching it across the barriers.
static volatile uint32_t pad_seq;
static volatile pad_state_t pad_snap;

// ---------------------------------------------------------------- rumble queue
// 16 slots: the host sends an OUT frame every 8 ms and core0 drains every 20 ms,
// so ~3 can queue; 16 makes the "full" drop path unreachable in practice.
#define RUMBLE_N 16
static volatile uint16_t rumble_l[RUMBLE_N], rumble_r[RUMBLE_N];
static volatile uint32_t rumble_head, rumble_tail;

// ---------------------------------------------------------------- command queue
#define CMD_N 8
static volatile uint8_t cmd_q[CMD_N];
static volatile uint32_t cmd_head, cmd_tail;

// ---------------------------------------------------------------- audio PCM ring
// p3-3641-core0encode: core1 (USB pump) writes whole 3840-byte 20 ms blocks,
// core0 (Opus encode + RTP) reads exactly one block per 20 ms slot. Single
// producer / single consumer, no lock - same payload/dmb/index discipline as the
// queues above. The old encoded-frame queue + demand counters + core1-side
// silence publication are gone with the encoder move.
static uint8_t pcm_ring[IPC_PCM_RING_BYTES] __attribute__((aligned(4)));
static volatile uint32_t pcm_head, pcm_tail;         // free-running byte counters
static volatile uint32_t pcm_drop_bytes;             // core1: block dropped (ring full)
static volatile uint32_t pcm_under_bytes;            // core0: zero-filled (ring empty)

// ---------------------------------------------------------------- handshake /
// status snapshots (plain aligned 32-bit fields; single writer each)
static volatile uint32_t audio_want;          // core0 -> core1
static volatile uint32_t audio_flush_req;     // core0 -> core1 (counter)
static volatile uint32_t audio_flush_ack;     // core1 -> core0 (counter)
static volatile uint32_t audio_stream;        // core1 -> core0
static volatile uint32_t audio_last_data_us;  // core1 -> core0 (0 = never)
static volatile uint32_t usb_enum;            // core1 -> core0
static volatile uint32_t core1_beats;         // core1 liveness counter
static volatile uint8_t  diag_stage;          // p3-3604: core1 progress stage

void ipc_init(void) {
    static bool inited;
    if (inited) return;                  // never wipe queues a live core1 is using
    inited = true;
    memset(logring, 0, sizeof logring);
    lr_head = lr_tail = 0;
    memset(c1ring, 0, sizeof c1ring);
    c1_head = c1_tail = 0;
    if (prev_log_magic != PREV_LOG_MAGIC) {      // cold boot: nothing to report
        memset(prev_log_buf, 0, sizeof prev_log_buf);
        prev_log_ms = 0;
        prev_log_magic = PREV_LOG_MAGIC;
        prev_saved_valid = false;
    } else if (prev_log_ms) {                    // previous boot ended in a reset
        memset(prev_saved, 0, sizeof prev_saved);
        memcpy(prev_saved, prev_log_buf, sizeof prev_saved);
        memcpy(prev_https_saved, prev_https_buf, sizeof prev_https_saved);
        prev_saved_ms = prev_log_ms;
        prev_saved_valid = true;
        prev_log_ms = 0;                         // this boot starts its own history
    }                                            // else: already consumed
    pad_seq = 0;
    memset((void *)&pad_snap, 0, sizeof pad_snap);
    rumble_head = rumble_tail = 0;
    cmd_head = cmd_tail = 0;
    pcm_head = pcm_tail = 0;
    pcm_drop_bytes = pcm_under_bytes = 0;
    audio_want = 0;
    audio_flush_req = audio_flush_ack = 0;
    audio_stream = 0;
    audio_last_data_us = 0;
    usb_enum = 0;
    core1_beats = 0;
    diag_stage = 0;
    // No cross-core lock is claimed any more: the log path is two lock-free SPSC
    // rings (see "log rings" below), so there is nothing to claim or deadlock on.
}

// ---------------------------------------------------------------- log rings
// Ring A: core0 producer, core1 consumer (both single-threaded per core).
void ipc_log_write(const char *data, int n) {
    if (n <= 0) return;
    if (get_core_num() != 0) { ipc_c1_log_write(data, n); return; }  // defensive
    {   // remember the LAST core0 line across a watchdog reset (SRAM is retained)
        uint32_t k = (uint32_t)n < (uint32_t)(PREV_LOG_MAX - 1) ? (uint32_t)n : (uint32_t)(PREV_LOG_MAX - 1);
        memcpy(prev_log_buf, data, k);
        prev_log_buf[k] = 0;
        prev_log_ms = (uint32_t)to_ms_since_boot(get_absolute_time());
    }
    uint32_t head = lr_head;
    for (int i = 0; i < n; i++) {
        uint32_t next = (head + 1u) % LOG_BYTES;
        if (next == lr_tail) break;          // full: drop the tail of the line
        logring[head] = data[i];
        head = next;
    }
    lr_head = head;
}

int ipc_log_read(char *dst, int cap) {
    if (cap <= 0) return 0;
    if (lr_head == lr_tail) return 0;
    int n = 0;
    uint32_t tail = lr_tail;
    while (n < cap && tail != lr_head) {
        dst[n++] = logring[tail];
        tail = (tail + 1u) % LOG_BYTES;
    }
    lr_tail = tail;
    return n;
}

void ipc_log_clear(void) { lr_tail = lr_head; }

// ---- prev-reset diagnosis ---------------------------------------------------
// Copy the last core0 log line that was written BEFORE the previous reset (only
// meaningful when this boot followed a watchdog reset - SRAM is retained, cleared
// by cold boot because the magic lives in NOLOAD .uninitialized_data).
int ipc_prev_log_copy(char *dst, int cap, uint32_t *ms_out) {
    if (!prev_saved_valid || cap <= 0) return 0;
    int n = 0;
    while (n < cap - 1 && prev_saved[n]) { dst[n] = prev_saved[n]; n++; }
    dst[n] = 0;
    if (ms_out) *ms_out = prev_saved_ms;
    return n;
}

void ipc_prev_log_clear(void) {
    prev_saved_valid = false;
    prev_saved[0] = 0;
    prev_https_saved[0] = 0;
    prev_log_ms = 0;
    prev_log_buf[0] = 0;
}

void ipc_prev_https_set(const char *s) {
    int i = 0;
    for (; i < (int)sizeof prev_https_buf - 1 && s[i]; i++) prev_https_buf[i] = s[i];
    prev_https_buf[i] = 0;
}

int ipc_prev_https_copy(char *dst, int cap) {
    if (!prev_saved_valid || cap <= 0) return 0;
    int n = 0;
    while (n < cap - 1 && prev_https_saved[n]) { dst[n] = prev_https_saved[n]; n++; }
    dst[n] = 0;
    return n;
}

// Ring B: core1 producer AND consumer - plain memory, no cross-core concerns.
void ipc_c1_log_write(const char *data, int n) {
    if (n <= 0) return;
    uint32_t head = c1_head;
    for (int i = 0; i < n; i++) {
        uint32_t next = (head + 1u) % C1LOG_BYTES;
        if (next == c1_tail) break;
        c1ring[head] = data[i];
        head = next;
    }
    c1_head = head;
}

int ipc_c1_log_read(char *dst, int cap) {
    if (cap <= 0) return 0;
    if (c1_head == c1_tail) return 0;
    int n = 0;
    uint32_t tail = c1_tail;
    while (n < cap && tail != c1_head) {
        dst[n++] = c1ring[tail];
        tail = (tail + 1u) % C1LOG_BYTES;
    }
    c1_tail = tail;
    return n;
}

// ---------------------------------------------------------------- pad snapshot
void ipc_pad_publish(const pad_state_t *p) {
    // Single writer must be core0 (rtc.c pad_commit). Refuse a stray core1 write
    // instead of leaving pad_seq odd, which would freeze the pad reader forever.
    if (get_core_num() != 0) return;
    uint32_t s = pad_seq;
    pad_seq = s + 1;                 // odd: write in progress
    __dmb();
    pad_snap = *p;
    __dmb();
    pad_seq = s + 2;                 // even: stable again
}

bool ipc_pad_read(pad_state_t *out) {
    for (int tries = 0; tries < 8; tries++) {
        uint32_t s1 = pad_seq;
        if (s1 & 1u) continue;       // writer mid-update
        __dmb();
        *out = pad_snap;
        __dmb();
        if (pad_seq == s1) return true;
    }
    return false;
}

// ---------------------------------------------------------------- rumble queue
void ipc_rumble_push(uint16_t l, uint16_t r) {
    uint32_t head = rumble_head;
    if (head - rumble_tail >= RUMBLE_N) return;   // full: drop (a newer frame follows)
    uint32_t i = head % RUMBLE_N;
    rumble_l[i] = l;
    rumble_r[i] = r;
    __dmb();
    rumble_head = head + 1;
}

bool ipc_rumble_pop(uint16_t *l, uint16_t *r) {
    uint32_t tail = rumble_tail;
    if (tail == rumble_head) return false;
    uint32_t i = tail % RUMBLE_N;
    __dmb();
    *l = rumble_l[i];
    *r = rumble_r[i];
    __dmb();
    rumble_tail = tail + 1;
    return true;
}

// ---------------------------------------------------------------- command queue
void ipc_cmd_push(uint8_t cmd) {
    uint32_t head = cmd_head;
    if (head - cmd_tail >= CMD_N) return;         // full: drop
    cmd_q[head % CMD_N] = cmd;
    __dmb();
    cmd_head = head + 1;
}

bool ipc_cmd_pop(uint8_t *cmd) {
    uint32_t tail = cmd_tail;
    if (tail == cmd_head) return false;
    __dmb();
    *cmd = cmd_q[tail % CMD_N];
    __dmb();
    cmd_tail = tail + 1;
    return true;
}

// ---------------------------------------------------------------- audio handshake
void ipc_audio_set_want(bool on) { audio_want = on ? 1u : 0u; __dmb(); }
bool ipc_audio_get_want(void) { return audio_want != 0; }

void ipc_audio_request_flush(void) { audio_flush_req++; __dmb(); }

bool ipc_audio_take_flush(void) {
    if (audio_flush_ack == audio_flush_req) return false;
    audio_flush_ack = audio_flush_req;
    __dmb();
    return true;
}

// ---------------------------------------------------------------- audio PCM ring
// Producer: core1's usb_audio_core1_tick(), whole 3840-byte blocks only.
// Consumer: core0's RTP slot, exactly 3840 bytes per call.
void ipc_pcm_push(const uint8_t *data, int n) {
    if (n <= 0 || n > IPC_PCM_BLOCK_BYTES) return;
    uint32_t head = pcm_head;
    if ((uint32_t)(head - pcm_tail) + (uint32_t)n > IPC_PCM_RING_BYTES) {
        pcm_drop_bytes += (uint32_t)n;   // full: drop the whole block (never split)
        return;
    }
    uint32_t idx = head & (IPC_PCM_RING_BYTES - 1u);
    uint32_t first = IPC_PCM_RING_BYTES - idx;
    if (first > (uint32_t)n) first = (uint32_t)n;
    memcpy(pcm_ring + idx, data, first);
    if ((uint32_t)n > first) memcpy(pcm_ring, data + first, (uint32_t)n - first);
    __dmb();                             // payload before the published index
    pcm_head = head + (uint32_t)n;
}

int ipc_pcm_read(void *dst, int n) {
    if (n <= 0) return 0;
    uint32_t tail = pcm_tail;
    uint32_t head = pcm_head;
    __dmb();                             // index before the payload
    uint32_t avail = head - tail;
    uint32_t take = ((uint32_t)n < avail) ? (uint32_t)n : avail;
    take &= ~3u;                         // whole stereo s16 frames only
    if (take) {
        uint32_t idx = tail & (IPC_PCM_RING_BYTES - 1u);
        uint32_t first = IPC_PCM_RING_BYTES - idx;
        if (first > take) first = take;
        memcpy(dst, pcm_ring + idx, first);
        if (take > first) memcpy((uint8_t *)dst + first, pcm_ring, take - first);
        __dmb();                         // payload read before the tail is released
        pcm_tail = tail + take;
    }
    if (take < (uint32_t)n) {
        memset((uint8_t *)dst + take, 0, (uint32_t)n - take);
        pcm_under_bytes += (uint32_t)n - take;
    }
    return (int)take;
}

uint32_t ipc_pcm_level(void) {
    return pcm_head - pcm_tail;          // wrap-safe SPSC depth
}

uint32_t ipc_pcm_dropped(void) { return pcm_drop_bytes; }
uint32_t ipc_pcm_under(void)   { return pcm_under_bytes; }

void ipc_pcm_reset(void) {
    // Consumer-side only (core0): advance the tail past everything buffered. A
    // producer block that lands concurrently is at head and stays queued; it can
    // only be at most one 20 ms block, so a restart is still effectively live.
    pcm_tail = pcm_head;
    __dmb();
}

void ipc_audio_stream_set(bool on) { audio_stream = on ? 1u : 0u; }
bool ipc_audio_stream_get(void) { return audio_stream != 0; }

void ipc_audio_data_seen(uint32_t uptime_us) {
    if (!uptime_us) uptime_us = 1;      // 0 means "never"
    audio_last_data_us = uptime_us;
}

uint32_t ipc_audio_ms_since_data(uint32_t now_us) {
    uint32_t last = audio_last_data_us;
    if (!last) return 0xFFFFFFFFu;
    return (uint32_t)(now_us - last) / 1000u;    // wrap-safe u32 subtraction
}

void ipc_enum_count_set(uint8_t n) { usb_enum = n; }
uint8_t ipc_enum_count(void) { return (uint8_t)usb_enum; }

void ipc_core1_beat(void) { core1_beats++; }
uint32_t ipc_core1_beats(void) { return core1_beats; }

void ipc_diag_stage_set(uint8_t stage) { diag_stage = stage; __dmb(); }
uint8_t ipc_diag_stage_get(void) { return diag_stage; }
