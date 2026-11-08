// ramlog.c — NOLOAD stdio mirror (see ramlog.h).
//
// Rules (same as hfault.c): callable from panic/fault context on EITHER core,
// so: no malloc, no FWLOG, no locks, no SDK time calls. Two cores appending
// concurrently may garble a byte via the head++ race; that is acceptable for
// diagnostics (a spinlock could deadlock inside panic).
#include "ramlog.h"
#include "pico/stdio.h"
#include "pico/stdio/driver.h"   // full stdio_driver_t (out_chars/out_flush/in_chars)
#include "pico/error.h"
#include <string.h>

#define RAMLOG_MAGIC 0x52414D4Cu          // "RAML"
#define RAMLOG_BYTES 1024                 // power of two (mask indexing)
#define RAMLOG_MASK  (RAMLOG_BYTES - 1)

__attribute__((section(".uninitialized_data"))) static char ramlog_buf[RAMLOG_BYTES];
__attribute__((section(".uninitialized_data"))) static volatile uint32_t ramlog_head;
__attribute__((section(".uninitialized_data"))) static volatile uint32_t ramlog_magic;

static void ramlog_out_chars(const char *buf, int len) {
    if (ramlog_magic != RAMLOG_MAGIC) {   // cold boot / garbage: (re)init
        ramlog_head = 0;
        ramlog_magic = RAMLOG_MAGIC;
    }
    for (int i = 0; i < len; i++)
        ramlog_buf[(ramlog_head++) & RAMLOG_MASK] = buf[i];
}

static void ramlog_out_flush(void) { }

static int ramlog_in_chars(char *buf, int len) {
    (void)buf; (void)len;
    return PICO_ERROR_NO_DATA;            // write-only driver
}

stdio_driver_t ramlog_driver = {
    .out_chars = ramlog_out_chars,
    .out_flush = ramlog_out_flush,
    .in_chars = ramlog_in_chars,
#if PICO_STDIO_ENABLE_CRLF_SUPPORT
    .crlf_enabled = false,
#endif
};

// Boot-time dump (core0, normal context): emit retained bytes as FWLOG lines.
// FWLOG goes to the IPC rings, not stdio, so this cannot recurse.
extern void clog_(const char *fmt, ...);
void ramlog_dump(void) {
    if (ramlog_magic != RAMLOG_MAGIC || !ramlog_head) return;
    uint32_t n = ramlog_head;
    if (n > RAMLOG_BYTES) n = RAMLOG_BYTES;   // wrapped: show the newest window
    // If wrapped, the oldest byte is at head&mask; else buffer starts at 0.
    uint32_t start = (ramlog_head > RAMLOG_BYTES) ? (ramlog_head & RAMLOG_MASK) : 0;
    char line[121];
    int li = 0;
    clog_("RAMLOG %u bytes retained stdio:", (unsigned)n);
    for (uint32_t i = 0; i < n; i++) {
        char ch = ramlog_buf[(start + i) & RAMLOG_MASK];
        if (ch == '\n' || ch == '\r' || li >= 120) {
            if (li) { line[li] = 0; clog_("RAMLOG | %s", line); li = 0; }
        } else if ((unsigned char)ch >= 32 || ch == '\t') {
            line[li++] = ch;
        }
    }
    if (li) { line[li] = 0; clog_("RAMLOG | %s", line); }
    ramlog_head = 0;   // consumed; keep magic so new output appends cleanly
}
