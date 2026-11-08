cmake_minimum_required(VERSION 3.13)
if (NOT DEFINED PICO_SDK_PATH AND DEFINED ENV{PICO_SDK_PATH})
    set(PICO_SDK_PATH $ENV{PICO_SDK_PATH})
endif()
include(${PICO_SDK_PATH}/external/pico_sdk_import.cmake)
project(stadia_one C CXX ASM)

# ---- UAC1_ONLY bisect variant (p3-3170) -------------------------------------
# 1 = minimal UAC1-only firmware: audio interfaces only (no CDC / no XInput /
# no IAD / no WCID), device class 0x01, C-Media VID/PID - see src/config.h.
# Defined at DIRECTORY scope BEFORE pico_sdk_init() so it reaches every target
# below (opus, stadia_one, and all TinyUSB TUs - the SDK compiles those inside
# the consuming target, which inherits this directory's definitions). tusb.h
# reads it through tusb_config.h, so the whole TinyUSB library sees the same
# value. build-uac.bat passes -DUAC1_ONLY=0, build-uac-only.bat -DUAC1_ONLY=1
# (separate build dir -> two independent uf2s from one source tree).
set(UAC1_ONLY 0 CACHE STRING "1 = UAC1-only audio bisect firmware (no CDC/XInput)")
add_compile_definitions(UAC1_ONLY=${UAC1_ONLY})

# ---- UAC1_CDC_ONLY bisect variant (p3-3190) ---------------------------------
# 1 = UAC1 + CDC firmware with NO XInput: the middle rung of the composite
# bisection - audio alone works (p3-3180) and audio+CDC+XInput fails, so this
# build removes exactly the XInput vendor function + WCID exchange (interfaces
# 0-1 audio IAD + 2-3 CDC IAD, device class EF/02/01, VID/PID 0x045E:0xFFFF,
# bcdDevice 0x0202 - see src/config.h). Same directory-scope mechanism as
# UAC1_ONLY above. Mutually exclusive with UAC1_ONLY (enforced in src/config.h);
# build-uac-cdc.bat passes -DUAC1_CDC_ONLY=1 into its own build-cdc/ dir.
set(UAC1_CDC_ONLY 0 CACHE STRING "1 = UAC1+CDC bisect firmware (no XInput/WCID)")
add_compile_definitions(UAC1_CDC_ONLY=${UAC1_CDC_ONLY})


# our TLS/DTLS config for the SDK-bundled mbedtls 2.28 (server + TLS1.2 + DTLS).
# MUST be set before pico_sdk_init(): the SDK freezes it into pico_mbedtls_headers.
set(PICO_MBEDTLS_CONFIG_FILE "stadia_tls_config.h")

# The SDK default core-0 stack is only 0x800 (2048) bytes AND it lives in SCRATCH_Y
# (4 KiB). Our .scratch_y section is empty, so the whole 4 KiB is available: double the
# stack. This matters because the HTTPS/DTLS paths run mbedTLS (ecp_mul alone needs
# ~492 B) on top of our own frames. Must be a global definition so pico_crt0 (crt0.S:
# ".equ StackSize, PICO_STACK_SIZE") picks it up, not just the stadia_one target.
add_compile_definitions(PICO_STACK_SIZE=0x1000)

pico_sdk_init()

# ---- tinyusb vendor patch (p3-3180) ------------------------------------------
# The SDK bundles TinyUSB 0.18.0 (86ad6e5). src/tinyusb-patch/ holds a patched
# copy of its RP2040/RP2350 portable driver rp2040_usb.c (provenance + the two
# backported fixes are documented in the file header):
#   1. volatile unaligned_memcpy - upstream c0c1566b / #3554: RP2350 hard
#      faults on compiler-widened 16/32-bit accesses to USB DPRAM.
#   2. isochronous endpoints never take the double-buffered arm path -
#      upstream 98741b55 (the commit DS5Dongle pins): iso DPRAM is single-
#      sized, buffer 1 would overrun into the neighbouring endpoint's slot.
# rp2040_usb.h is vendored byte-identical so the quoted include resolves next
# to the patched .c instead of the SDK's portable dir.
# Mechanism: tinyusb_device_base / tinyusb_host_base are INTERFACE libraries
# that compile rp2040_usb.c inside the CONSUMER; drop the SDK path from
# INTERFACE_SOURCES and hand them ours instead (dcd/hcd keep using the SDK
# files - they only call the unchanged hw_endpoint_* API).
foreach(_tu_base tinyusb_device_base tinyusb_host_base)
    if (TARGET ${_tu_base})
        get_target_property(_tu_srcs ${_tu_base} INTERFACE_SOURCES)
        if (_tu_srcs)
            set(_tu_kept "")
            foreach(_s IN LISTS _tu_srcs)
                if (NOT _s MATCHES "rp2040_usb\\.c$")
                    list(APPEND _tu_kept ${_s})
                endif()
            endforeach()
            set_target_properties(${_tu_base} PROPERTIES INTERFACE_SOURCES "${_tu_kept}")
        endif()
        target_sources(${_tu_base} INTERFACE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/tinyusb-patch/rp2040_usb.c)
    endif()
endforeach()
# same GCC false-positive suppressions the SDK applies to its copy of the file
if (PICO_C_COMPILER_IS_GNU)
    set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/src/tinyusb-patch/rp2040_usb.c
        PROPERTIES COMPILE_FLAGS "-Wno-stringop-overflow -Wno-array-bounds")
endif()

# ---- tinyusb vendor patch #2 (p3-3300-tinyuac): UAC 1.0 audio class -------
# The SDK's TinyUSB 0.18.0 audio class is UAC2-ONLY: audiod_open() demands
# bInterfaceProtocol == 0x20, which Windows' inbox usbaudio2.sys does not
# reliably bind at FULL speed (the RP2350 device controller is FS only).
# src/tinyusb-patch/class/audio/ carries the audio class from upstream
# 98741b55 - the commit DS5Dongle (same chip + pico-sdk stack) pins and runs
# stable with UAC1 audio on Windows - with audiod_open() accepting protocol
# 0x00 (UAC1) and the full UAC1 control/set-interface paths. The vendored
# copy is adapted to the 0.18 core API (see the STADIA VENDOR PATCH header in
# audio_device.c: tu_fifo_config item_size, usbd_edpt_xfer is_isr arg, the
# .xfer_isr dispatch folded into audiod_xfer_cb, two tusb_common helpers).
# Same swap mechanism as rp2040_usb.c above, but ONLY on the device base
# (the host base compiles audio_host.c, which is untouched). Header note:
# the vendored audio_device.c includes its own audio_device.h/audio.h via
# quote-include from its directory; tusb.h keeps including the SDK's
# UAC2-only headers elsewhere - the declaration surface we rely on from our
# code (tud_audio_available/read inlines, tud_audio_set_itf_cb) is identical
# in both versions, verified signature-for-signature.
if (TARGET tinyusb_device_base)
    get_target_property(_tu_dev_srcs tinyusb_device_base INTERFACE_SOURCES)
    if (_tu_dev_srcs)
        set(_tu_dev_kept "")
        foreach(_s IN LISTS _tu_dev_srcs)
            if (NOT _s MATCHES "class/audio/audio_device\\.c$")
                list(APPEND _tu_dev_kept ${_s})
            endif()
        endforeach()
        set_target_properties(tinyusb_device_base PROPERTIES INTERFACE_SOURCES "${_tu_dev_kept}")
    endif()
    target_sources(tinyusb_device_base INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tinyusb-patch/class/audio/audio_device.c)
endif()

# ---- vendored libopus 1.3.1 (fixed-point) — see vendor/libopus/README-stadia.txt ----
# The generic fixed-point build set: celt top-level, silk common, silk/fixed, plus the
# opus/analysis cores. No x86/ARM intrinsics subdirs, no silk/float, no multistream.
file(GLOB OPUS_CELT_SRC  vendor/libopus/celt/*.c)
file(GLOB OPUS_SILK_SRC  vendor/libopus/silk/*.c vendor/libopus/silk/fixed/*.c)
file(GLOB OPUS_CORE_SRC  vendor/libopus/src/*.c)
add_library(opus STATIC ${OPUS_CORE_SRC} ${OPUS_CELT_SRC} ${OPUS_SILK_SRC})
target_include_directories(opus PUBLIC
  vendor/libopus/include vendor/libopus/src vendor/libopus/celt
  vendor/libopus/silk vendor/libopus/silk/fixed
)
# p3-3641-core0encode: the Opus encode moved to core0, whose stack is the SDK's
# 4 KiB SCRATCH_Y one. libopus's default VAR_ARRAYS build puts ~33 KB of VLA
# scratch on the CPU stack and would overflow that instantly. The alternative
# libopus 1.3.1 build mode is NONTHREADSAFE_PSEUDOSTACK (celt/stack_alloc.h,
# selected together with celt/arch.h's GLOBAL_STACK_SIZE): the per-call scratch
# comes from ONE process-global buffer, requested by opus_alloc_scratch() on the
# first opus_encode(). As of p3-3646 that buffer is STATIC .bss, not heap - see
# the p3-3646-bpsfix note below.
#
# NOTE on names/values: this tree is libopus 1.3.1, which has NO
# OPUS_PSEUDOSTACK_SIZE macro - the size knob is GLOBAL_STACK_SIZE (celt/arch.h,
# default 120000). The real-machine 48k-stereo stack peak was 33,332 B, and the
# pseudostack carries essentially all of it (ALLOC() scratch + the silk_nsq_state
# copies moved there by the STADIA PATCH below), so 32768 would have ~0 margin;
# 40960 leaves ~7 KB. libopus only borrows the buffer, never checks the bound, so
# a too-small value silently corrupts RAM: keep the margin.
#
# STADIA PATCH in vendor/libopus/silk/fixed/encode_frame_FIX.c: its two 4,704 B
# silk_nsq_state copies (and the LBRR one) were PLAIN LOCALS - a 9,408 B fixed
# stack frame that the pseudostack cannot cover and that would overflow core0's
# 4 KiB stack immediately. They are now ALLOC()'d on this pseudostack (same
# semantics); the fixed frame measured 9,408 -> 748 B.
set(OPUS_PSEUDOSTACK_SIZE 40960)
# p3-3646-bpsfix: OVERRIDE_OPUS_ALLOC_SCRATCH moves the pseudostack out of the
# heap. libopus's default opus_alloc_scratch() = malloc(GLOBAL_STACK_SIZE) on the
# first encode; a silent overflow of that 40960-byte chunk corrupted whatever the
# heap had next (prime suspect for the core0 encode stalls / boot hang), and a
# malloc in a 4 KiB-stack context also drags in fragmentation. src/usb_audio.c now
# supplies opus_alloc_scratch() returning a STATIC 49152-byte .bss buffer with a
# 0xC5 canary right behind it: GLOBAL_STACK_SIZE stays 40960 (only the size the
# library *asks* for; our function ignores it) and the extra 8 KiB is deliberate
# overflow margin + measurement headroom. Overriding removes libopus's own inline
# definition, so celt/os_support.h now declares it (STADIA PATCH there).
# OPUS_BUILD/FIXED_POINT is the canonical embedded configure; PACKAGE_VERSION
# feeds opus_get_version_string (its "fixed-point" suffix is chosen from FIXED_POINT).
target_compile_definitions(opus PRIVATE
  OPUS_BUILD FIXED_POINT PACKAGE_VERSION="1.3.1"
  NONTHREADSAFE_PSEUDOSTACK GLOBAL_STACK_SIZE=${OPUS_PSEUDOSTACK_SIZE}
  OVERRIDE_OPUS_ALLOC_SCRATCH
)
target_compile_options(opus PRIVATE -O2 -fno-math-errno)   # speed over size for the codec

add_executable(stadia_one
  # class sources are documented intent (they also arrive via tinyusb_device_base
  # INTERFACE_SOURCES); p3-3500: vendor_device.c replaces hid_device.c - the
  # pad interface is the vendor XInput function again (the interim p3-3200
  # standard-HID gamepad is deleted), and each TU compiles to nothing in the
  # build variants that switch its CFG_TUD_* off (tusb_config.h).
  ${PICO_SDK_PATH}/lib/tinyusb/src/class/vendor/vendor_device.c
  ${PICO_SDK_PATH}/lib/tinyusb/src/class/cdc/cdc_device.c
  # p3-3600-dualcore: core1_main.c + ipc.c are the dual-core split (core1 owns
  # TinyUSB/audio/opus; ipc.c is the only shared-memory surface between cores).
  src/dhcpserver.c src/dnsserver.c src/timing_alt.c src/certs.c src/main.c src/pb.c src/proto.c src/net_infra.c src/cloud.c src/https.c src/rtc.c src/usb_hid.c src/usb_audio.c src/ipc.c src/core1_main.c src/hfault.c src/ramlog.c
)
target_include_directories(stadia_one PRIVATE src ${CMAKE_CURRENT_SOURCE_DIR})
# usb_audio.c owns the static pseudostack and logs the RAM math; same values, one
# source. OPUS_PSEUDOSTACK_BYTES = what libopus asks for (GLOBAL_STACK_SIZE);
# OPUS_STATIC_SCRATCH_BYTES = the .bss buffer we hand it (canary right after).
# p3-3647: 49152 -> 40960. Measured pseudostack peak is 29,600 B (stable across
# all phases/content, offline probe + on-board pspeak), so 40960 keeps a 38%
# margin while freeing 8 KB of heap for the RAM hot path below.
set(OPUS_STATIC_SCRATCH_SIZE 40960)
target_compile_definitions(stadia_one PRIVATE
  OPUS_PSEUDOSTACK_BYTES=${OPUS_PSEUDOSTACK_SIZE}
  OPUS_STATIC_SCRATCH_BYTES=${OPUS_STATIC_SCRATCH_SIZE})
target_link_libraries(stadia_one PRIVATE
  pico_stdlib
  pico_cyw43_arch_lwip_poll
  pico_lwip
  pico_multicore
  pico_mbedtls pico_mbedtls_tls
  tinyusb_device
  opus
)
pico_enable_stdio_uart(stadia_one 1)
pico_enable_stdio_usb(stadia_one 0)
# p3-3647: RAM hot path (ported from p3-3640-ramhotpath). The core0 live encode
# costs 16.5 ms avg / 17.8 ms max from flash (real-signal OPUSBENCH) - too close
# to the 20 ms slot. A curated subset of libopus archive members (celt_encoder,
# bands, pitch, mdct, kiss_fft, vq, cwrs, ~40 KB) lands in the crt0-copied .data
# section and executes from main SRAM (~30% faster, proven on variant A).
# pico_set_linker_script() is the SDK hook (PICO_TARGET_LINKER_SCRIPT); it also
# registers the file as a link dependency, so editing the script relinks.
pico_set_linker_script(stadia_one ${CMAKE_CURRENT_SOURCE_DIR}/linker/memmap_stadia_ram.ld)
pico_add_extra_outputs(stadia_one)
# Distinct artifact names for the bisect builds so the uf2s cannot be
# confused when flashing (build/stadia_one.uf2 vs build-only/stadia-one-uac1only.uf2
# vs build-cdc/stadia-one-uac1cdc.uf2).
if (UAC1_ONLY)
    set_target_properties(stadia_one PROPERTIES OUTPUT_NAME "stadia-one-uac1only")
elseif (UAC1_CDC_ONLY)
    set_target_properties(stadia_one PROPERTIES OUTPUT_NAME "stadia-one-uac1cdc")
endif()
target_compile_options(stadia_one PRIVATE -Wall -Wextra)
