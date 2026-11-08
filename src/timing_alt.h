#pragma once
#include <stdint.h>
typedef struct { uint64_t fin; uint32_t int_ms, fin_ms; } mbedtls_timing_delay_context;
void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms);
int mbedtls_timing_get_delay(void *data);
