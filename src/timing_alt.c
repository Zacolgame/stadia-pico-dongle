// timing_alt.c — MBEDTLS_TIMING_ALT on RP2350 absolute time.
#include <stdint.h>
#include <stdbool.h>
#include "pico/time.h"

typedef struct { uint64_t fin; uint32_t int_ms, fin_ms; } mbedtls_timing_delay_context;

void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms) {
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *)data;
    ctx->int_ms = int_ms; ctx->fin_ms = fin_ms;
    if (!fin_ms) { ctx->fin = 0; return; }
    ctx->fin = to_ms_since_boot(get_absolute_time()) + fin_ms;
}

int mbedtls_timing_get_delay(void *data) {
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *)data;
    if (!ctx->fin) return -1;
    uint64_t now = to_ms_since_boot(get_absolute_time());
    if ((int64_t)(ctx->fin - now) <= 0) return 2;
    if (ctx->int_ms && (int64_t)(ctx->fin - ctx->int_ms - now) <= 0) return 1;
    return 0;
}
