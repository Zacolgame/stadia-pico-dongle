// ramlog.h — NOLOAD stdio mirror: captures puts/printf output into retained SRAM.
//
// Why: panic()/assert messages go to stdio (UART pins, unconnected on this
// board) and vanish. The blackbox records THAT a panic happened (pc=_exit);
// this records WHAT it said (file:line). Registered as an extra stdio driver,
// so every puts/printf - including LWIP_PLATFORM_ASSERT=panic() and SDK
// pico_assert - is mirrored here with zero changes to callers.
#pragma once
#include <stdint.h>
#include "pico/stdio.h"

#ifdef __cplusplus
extern "C" {
#endif

// The mirror driver: enable once at boot with
//   stdio_set_driver_enabled(&ramlog_driver, true);
extern stdio_driver_t ramlog_driver;

// Print the retained stdio text (if any) to the FWLOG console, then clear it.
// Call once at boot, after the PREVRESET/HFAULT prints.
void ramlog_dump(void);

#ifdef __cplusplus
}
#endif
