// hfault.h — p3-3646 HardFault blackbox ("ablackbox").
//
// WHY: variant A (40 KB of libopus .text copied to SRAM) encodes fine
// standalone (OPUSBENCH ~5.6 ms) but core1 STALLS about a minute after a
// controller connects, and core0's stall monitor then walks the board into the
// ROM bootloader. p3-3635 (same code, flash-resident) never dies. There was no
// direct evidence of WHAT died: the CDC console is gone at that point and the
// log rings may be the victim. So the next crash records itself:
//
//   * HardFault_Handler (hfault.c) overrides the SDK weak handler. It runs for
//     EITHER core: one handler, one record slot per core, no locking (a fault
//     handler must never contend).
//   * It captures the hardware-stacked frame (R0-R3, R12, LR, PC, xPSR), the
//     fault status registers (CFSR/HFSR/MMFAR/BFAR), the core id (SIO CPUID),
//     the faulting stack pointer and a 1 MHz timestamp, into a
//     .uninitialized_data NOLOAD struct. That section is not zeroed by crt0 and
//     SRAM survives a watchdog reset, so the record is still there next boot.
//   * It then forces an immediate watchdog_reboot(0,0,0). main.c prints the
//     record early in the next boot ("HFAULT core=... pc=..."), then clears the
//     magic. A copy is kept for this boot so the CDC command "HFAULT" can
//     re-print it if the port was opened late.
//
// RULES the fault path obeys (see hfault.c): no malloc, no FWLOG/clog_ (the log
// rings may be what crashed), no locks, no SDK time functions (they take
// spinlocks), no floating point.
#pragma once
#include <stdint.h>
#include <stdbool.h>

#define HFAULT_MAGIC 0x48464C54u          // "HFLT"
#define HFAULT_MAX_CORE 2

// Layout is shared with main.c (printed as raw hex) and with the hardware
// verification procedure in the commit message. Keep the field order stable.
typedef struct {
    uint32_t magic;        // HFAULT_MAGIC once the rest of this slot is valid
    uint32_t core;         // SIO CPUID of the faulting core: 0 or 1
    uint32_t us;           // TIMER0 TIMERAWL at the fault, 1 MHz (wraps ~71 min)
    uint32_t ms;           // us / 1000 == to_ms_since_boot() at the fault
    uint32_t exc_return;   // LR at exception entry (EXC_RETURN)
    uint32_t frame;        // address of the hardware-stacked exception frame
    uint32_t fault_sp;     // SP the frame was stacked on (MSP or PSP at entry)
    uint32_t frame_words;  // 0x20 basic frame, 0x68 with the FP extension
    uint32_t r0, r1, r2, r3, r12, lr, pc, psr;   // the stacked frame
    uint32_t cfsr;         // SCB->CFSR  (0xE000ED28)
    uint32_t hfsr;         // SCB->HFSR  (0xE000ED2C)
    uint32_t mmfar;        // SCB->MMFAR (0xE000ED34), valid if CFSR bit 7
    uint32_t bfar;         // SCB->BFAR  (0xE000ED38), valid if CFSR bit 15
} hfault_rec_t;

// core0, at boot: copy the NOLOAD record for `core` if it holds a real fault.
// Returns false when the slot is empty / a cold boot (magic mismatch).
bool hfault_copy(int core, hfault_rec_t *out);

// Invalidate the NOLOAD slot after printing (and keep a this-boot copy for
// hfault_last_copy), so a later normal boot cannot report a stale fault.
void hfault_clear(int core);

// This-boot copy of a record that hfault_clear() retired (for the HFAULT
// console command). False when this boot has not retired a record for `core`.
bool hfault_last_copy(int core, hfault_rec_t *out);

// Normal context only: print one record as two hex lines via clog_.
void hfault_log(const hfault_rec_t *f);

// HFAULTTEST console command (core1): deliberately take a HardFault so the
// blackbox can be proven end-to-end without a controller. Does not return -
// it records and reboots exactly like a real fault.
void hfault_selftest(void) __attribute__((noreturn));

// Last-resort redundancy: the record above needs SRAM to survive the watchdog
// reset. The watchdog SCRATCH0..3 registers live in the always-on block and are
// guaranteed to survive it, so the handler also leaves {tag|core, pc, cfsr, lr}
// there. Reads/clears them for the boot banner; `out` is 4 words.
bool hfault_scratch_read(uint32_t out[4]);
void hfault_scratch_clear(void);
