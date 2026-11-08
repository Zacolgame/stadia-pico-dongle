#pragma once
#include <stdarg.h>
#include <stdint.h>
// p3-3600-dualcore: usb_hid.c / usb_audio.c / core1_main.c all run on core 1.
// Only these three entry points are called from outside the core-1 island:
void usb_hid_init(void);           // core1: tusb_init() + descriptor self-check
void usb_hid_task(void);           // core1: pad snapshot -> XInput IN report
void usb_hid_pump_cdc(void);       // core1: log ring drain + CDC command parser
void clog_(const char *fmt, ...);  // BOTH cores: formatted line -> IPC log ring
#define FWLOG(...) clog_(__VA_ARGS__)
uint8_t usb_hid_enum_count(void);  // tud_mount_cb hits since boot (0 = never enumerated)

// core1_main.c: entry point + its dedicated stack (multicore_launch_core1_with_stack).
void core1_main(void);
uint32_t *core1_stack_area(void);
uint32_t core1_stack_bytes(void);
