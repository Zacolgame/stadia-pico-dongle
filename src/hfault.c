// hfault.c — p3-3646 HardFault blackbox ("ablackbox"). See hfault.h for why.
//
// One handler, two record slots. A fault on either core lands in
// HardFault_Handler (the SDK vector table routes isr_hardfault here because this
// C function overrides crt0.S's weak alias; the SDK does not enable
// MemManage/BusFault/UsageFault, so every configurable fault escalates).
//
// The handler is deliberately primitive:
//   * naked asm entry: pick the exception frame (MSP or PSP via EXC_RETURN
//     bit 2), then switch SP to a dedicated 256-byte reporting stack BEFORE any
//     C code, so a corrupted/overflowed faulting stack cannot break the report
//     and the C prologue cannot push over the frame evidence;
//   * C body: raw loads/stores only. No malloc, no FWLOG/clog_ (the log rings
//     may be the victim and the CDC is core1's), no SDK time functions
//     (pico_time's time_us_64 takes a spinlock, which can deadlock if the fault
//     happened while that lock was held), no locks, no floating point;
//   * then watchdog_reboot(0, 0, 0): a full chip reset that keeps SRAM, which
//     is what makes the record readable on the next boot.
//
// Everything below hfaul_report() is normal-context code (boot print, console).
#include <stdint.h>
#include "hardware/watchdog.h"      // watchdog_reboot(0,0,0) - no locks, no heap
#include "usb_hid.h"                // clog_ / FWLOG (normal context only!)
#include "hfault.h"

// ---------------------------------------------------------------------------
// Record storage. .uninitialized_data is NOLOAD: crt0 does not zero it and
// SRAM contents (including this section) survive a watchdog reset, so the
// faulting boot leaves the record behind for the next boot to print.
// Separate slot per core => no locking is ever needed in fault context.
// ---------------------------------------------------------------------------
#define HFAUL_STACK_BYTES 256
static hfault_rec_t hfaul_rec[HFAULT_MAX_CORE]
    __attribute__((section(".uninitialized_data"), aligned(8), used));
static uint32_t hfaul_report_stack[HFAUL_STACK_BYTES / 4]
    __attribute__((section(".uninitialized_data"), aligned(8), used));

// This-boot copies retired by hfault_clear(), for the HFAULT console command
// (normal .bss: zeroed by crt0 every boot).
static hfault_rec_t hfaul_last[HFAULT_MAX_CORE];
static bool hfaul_last_valid[HFAULT_MAX_CORE];

// Raw register addresses: avoid SDK accessors in fault context.
#define HFAUL_SIO_CPUID   (*(volatile uint32_t *)0xD0000000u)  // SIO CPUID: 0/1
#define HFAUL_TIMERAWL    (*(volatile uint32_t *)0x400B0028u)  // TIMER0 1 MHz
#define HFAUL_CFSR        (*(volatile uint32_t *)0xE000ED28u)  // SCB->CFSR
#define HFAUL_HFSR        (*(volatile uint32_t *)0xE000ED2Cu)  // SCB->HFSR
#define HFAUL_MMFAR       (*(volatile uint32_t *)0xE000ED34u)  // SCB->MMFAR
#define HFAUL_BFAR        (*(volatile uint32_t *)0xE000ED38u)  // SCB->BFAR
#define HFAUL_AIRCR       (*(volatile uint32_t *)0xE000ED0Cu)  // SCB->AIRCR

// Redundant copy in the watchdog scratch registers: the always-on watchdog block
// survives a watchdog reset by design (boot-to-address mode depends on it),
// whereas the SRAM record relies on retained SRAM. Four words hold the two facts
// that identify a crash without any decoding: pc and CFSR (+ lr and the core).
#define HFAUL_SCRATCH_TAG 0x48464C50u       // "HFLP": HFLT + P(fallback copy)

// Called from the naked stub below with the reporting stack already installed.
// r0 = frame, r1 = EXC_RETURN, r2 = the SP the frame was stacked on.
void hfaul_report(uint32_t *frame, uint32_t exc_return, uint32_t fault_sp)
    __attribute__((noreturn, used, noinline));

__attribute__((naked, noreturn)) void HardFault_Handler(void) {
    __asm volatile(
        "movs r0, #4                          \n\t"  // EXC_RETURN bit 2: frame on PSP?
        "mov  r1, lr                          \n\t"
        "tst  r0, r1                          \n\t"
        "beq  1f                              \n\t"
        "mrs  r0, psp                         \n\t"
        "b    2f                              \n\t"
        "1:                                   \n\t"
        "mrs  r0, msp                         \n\t"
        "2:                                   \n\t"
        "mov  r2, r0                          \n\t"  // r2 = faulting SP (frame base)
        "mov  r1, lr                          \n\t"  // r1 = EXC_RETURN
        "ldr  r3, =(hfaul_report_stack + 256) \n\t"
        "mov  sp, r3                          \n\t"  // dedicated reporting stack
        "ldr  r3, =hfaul_report               \n\t"
        "blx  r3                              \n\t"
        "3: b 3b                              \n\t"  // hfaul_report never returns
    );
}

// THIS SDK build puts the RAW name in the vector table: crt0.S declares its
// default handler as `isr_hardfault` (.weak isr_hardfault / bkpt), and
// cmsis/rename_exceptions.h (the isr_hardfault -> HardFault_Handler alias) is
// not applied to the assembler pass. Verified in the linked image: .vectors
// word[3] pointed at the crt0 bkpt stub, and the HardFault_Handler definition
// above was silently garbage-collected. So the vector entry must be overridden
// under its real name too - a naked 1-instruction branch (no stack use, no C
// prologue) keeps the "one handler" property.
__attribute__((naked, noreturn)) void isr_hardfault(void) {
    __asm volatile("b HardFault_Handler");
}

void hfaul_report(uint32_t *frame, uint32_t exc_return, uint32_t fault_sp) {
    uint32_t core = HFAUL_SIO_CPUID;
    hfault_rec_t *r = &hfaul_rec[core & 1u];
    uint32_t us = HFAUL_TIMERAWL;

    r->core         = core & 1u;
    r->us           = us;
    r->ms           = us / 1000u;            // == to_ms_since_boot() at the fault
                                             // (the SDK's timer adapter is the
                                             // same raw 1 MHz counter, no offset;
                                             // us wraps every 4295 s)
    r->exc_return   = exc_return;
    r->frame        = (uint32_t)(uintptr_t)frame;
    r->fault_sp     = fault_sp;
    // 0x68 when the FP extension stacked S0-S15+FPSCR, else 0x20. The basic
    // frame (R0..xPSR) always starts at the same offset, so the reads below are
    // valid either way.
    r->frame_words  = (exc_return & 0x10u) ? 0x68u : 0x20u;
    r->r0           = frame[0];
    r->r1           = frame[1];
    r->r2           = frame[2];
    r->r3           = frame[3];
    r->r12          = frame[4];
    r->lr           = frame[5];
    r->pc           = frame[6];
    r->psr          = frame[7];
    r->cfsr         = HFAUL_CFSR;
    r->hfsr         = HFAUL_HFSR;
    r->mmfar        = HFAUL_MMFAR;
    r->bfar         = HFAUL_BFAR;
    __asm volatile("dmb sy" ::: "memory");
    r->magic        = HFAULT_MAGIC;          // valid marker written last
    // Redundant, reset-guaranteed copy (watchdog_reboot(0,0,0) only writes
    // scratch[4], so 0..3 stay intact across the reset).
    watchdog_hw->scratch[0] = HFAUL_SCRATCH_TAG | (core & 1u);
    watchdog_hw->scratch[1] = r->pc;
    watchdog_hw->scratch[2] = r->cfsr;
    watchdog_hw->scratch[3] = r->lr;
    __asm volatile("dmb sy" ::: "memory");

    // Immediate full-chip reset. SRAM (and therefore the record) is retained;
    // the boot log shows wdt=1 and main.c prints the record as "HFAULT ...".
    watchdog_reboot(0, 0, 0);

    // Not reached in practice. If the watchdog path ever failed, force a core
    // reset through AIRCR (no watchdog involvement) and wait for it.
    HFAUL_AIRCR = 0x05FA0004u;               // VECTKEY | SYSRESETREQ
    for (;;) __asm volatile("wfi");
}

// ---------------------------------------------------------------------------
// Boot / console accessors (normal context only).
// ---------------------------------------------------------------------------
bool hfault_copy(int core, hfault_rec_t *out) {
    if (!out || core < 0 || core >= HFAULT_MAX_CORE) return false;
    const hfault_rec_t *r = &hfaul_rec[core];
    if (r->magic != HFAULT_MAGIC) return false;   // cold boot / already cleared
    *out = *r;
    return out->magic == HFAULT_MAGIC;
}

void hfault_clear(int core) {
    if (core < 0 || core >= HFAULT_MAX_CORE) return;
    if (hfaul_rec[core].magic == HFAULT_MAGIC) {  // keep it for this boot
        hfaul_last[core] = hfaul_rec[core];
        hfaul_last_valid[core] = true;
    }
    hfaul_rec[core].magic = 0;                    // magic first: record is dead
    __asm volatile("dmb sy" ::: "memory");
}

bool hfault_last_copy(int core, hfault_rec_t *out) {
    if (!out || core < 0 || core >= HFAULT_MAX_CORE) return false;
    if (!hfaul_last_valid[core]) return false;
    *out = hfaul_last[core];
    return true;
}

void hfault_log(const hfault_rec_t *f) {
    if (!f) return;
    FWLOG("HFAULT core=%u t=%u pc=%08x lr=%08x psr=%08x r0=%08x r1=%08x r2=%08x r3=%08x",
          (unsigned)f->core, (unsigned)f->ms, (unsigned)f->pc, (unsigned)f->lr,
          (unsigned)f->psr, (unsigned)f->r0, (unsigned)f->r1, (unsigned)f->r2,
          (unsigned)f->r3);
    FWLOG("HFAULT core=%u r12=%08x cfsr=%08x hfsr=%08x bfar=%08x mmfar=%08x exc=%08x sp=%08x frame=%08x",
          (unsigned)f->core, (unsigned)f->r12, (unsigned)f->cfsr, (unsigned)f->hfsr,
          (unsigned)f->bfar, (unsigned)f->mmfar, (unsigned)f->exc_return,
          (unsigned)f->fault_sp, (unsigned)f->frame);
}

// ---------------------------------------------------------------------------
// Reset-guaranteed scratch copy (normal context only).
// ---------------------------------------------------------------------------
bool hfault_scratch_read(uint32_t out[4]) {
    if (!out) return false;
    if ((watchdog_hw->scratch[0] & 0xFFFFFFF0u) != HFAUL_SCRATCH_TAG) return false;
    for (int i = 0; i < 4; i++) out[i] = watchdog_hw->scratch[i];
    return true;
}

void hfault_scratch_clear(void) {
    watchdog_hw->scratch[0] = 0;                  // tag first: copy is dead
}

// ---------------------------------------------------------------------------
// HFAULTTEST: the deliberate fault used to prove the recorder end-to-end.
// ---------------------------------------------------------------------------
void hfault_selftest(void) {
    // 0x6000_0000 is decoded by nothing on the RP2350 (ROM 0x0000_0000, XIP
    // 0x1000_0000, SRAM 0x2000_0000, APB 0x4000_0000, AHB 0x5000_0000, PPB
    // 0xE000_0000), so this store gets an error response -> precise BusFault ->
    // HardFault. NOTE: the usual *(volatile uint32_t *)0 trick would NOT work
    // here - address 0 is the readable boot ROM on this chip.
    *(volatile uint32_t *)0x60000000u = 0xDEADBEEFu;
    // If the bus somehow accepted that, an undefined instruction is a
    // guaranteed UNDEFINSTR UsageFault -> HardFault.
    __asm volatile("udf #0");
    for (;;) { }                                  // not reached
}
