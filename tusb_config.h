#ifndef _TUSB_CONFIG_H_
#define _TUSB_CONFIG_H_

// UAC1_ONLY / UAC1_CDC_ONLY (p3-3170 / p3-3190): come from the build system
// (build-uac-only.bat / build-uac-cdc.bat set them via CMake, which compiles
// every TinyUSB TU inside the stadia_one target so the value is consistent
// everywhere); 0 is the safe default for any TU built without the flag. Keep
// in sync with src/config.h - the documented home of the switches. This
// header must NOT include config.h: TinyUSB core TUs find tusb_config.h
// through their own include path, which does not carry src/.
#ifndef UAC1_ONLY
#define UAC1_ONLY 0
#endif
#ifndef UAC1_CDC_ONLY
#define UAC1_CDC_ONLY 0
#endif

#define CFG_TUSB_MCU OPT_MCU_RP2040
#define CFG_TUSB_OS OPT_OS_PICO
#define CFG_TUD_ENABLED 1
#define CFG_TUSB_RHPORT0_MODE (OPT_MODE_DEVICE | OPT_MODE_FULL_SPEED)
#define CFG_TUD_ENDPOINT0_SIZE 64
// p3-3500 plugplay: the pad interface is the VENDOR XInput function again
// (class 0xFF/0x5D/0x01, TinyUSB's builtin vendor_device driver) - Windows'
// inbox xusb22.sys binds it via the MS OS 1.0 WCID exchange (usb_hid.c), so
// XInput games see an Xbox 360 pad with zero configuration. The interim
// p3-3200 standard-HID gamepad (hid_device + input.inf, DirectInput only) is
// deleted; CFG_TUD_HID is 0 in EVERY variant (XInput is not HID, and no HID
// interface must exist for Windows to treat the pad as pure XInput).
//
// No stream fifos on the vendor interface: with RX/TX bufsize 0,
// tud_vendor_n_write arms the IN endpoint for exactly the 20-byte report
// (write == arm, single packet), and the OUT endpoint delivers each 8-byte
// rumble frame straight to tud_vendor_rx_cb. The fifo paths would additionally
// assume bulk-64 arithmetic (tu_edpt_stream mps = TUSB_EPSIZE_BULK_FS) and
// re-arm only while >=64 fifo bytes are free, which is wrong for an 8-byte
// interrupt OUT. The fifo-less IN completion also skips
// tu_edpt_stream_write_zlp_if_needed - a ZLP makes no sense on interrupt.
//
// UAC1_ONLY (p3-3170): CDC + vendor are compiled OUT - only the audio class
// remains, so the audio-only bisect firmware really has no serial console and
// no gamepad interface (and TinyUSB's builtin class drivers cannot claim
// anything in the 2-interface audio descriptor).
//
// UAC1_CDC_ONLY (p3-3190): the gamepad interface is compiled OUT (the middle
// rung of the composite bisection), CDC stays ON: TinyUSB's cdc driver claims
// the CDC IAD pair (interfaces 2-3) and the COM port + serial console are
// half of the read-out. The vendor control callback is compiled out too, so
// the 0xEE probe stalls and Windows sees a plain 2-function class composite.
#if UAC1_ONLY
#define CFG_TUD_HID 0
#define CFG_TUD_VENDOR 0
#define CFG_TUD_CDC 0
#elif UAC1_CDC_ONLY
#define CFG_TUD_HID 0
#define CFG_TUD_VENDOR 0
#define CFG_TUD_CDC 1
#define CFG_TUD_CDC_RX_BUFSIZE 256
#define CFG_TUD_CDC_TX_BUFSIZE 1024
#else
#define CFG_TUD_HID 0
#define CFG_TUD_VENDOR 1
#define CFG_TUD_CDC 1
#define CFG_TUD_CDC_RX_BUFSIZE 256
#define CFG_TUD_CDC_TX_BUFSIZE 1024
#define CFG_TUD_VENDOR_EPSIZE 64
#define CFG_TUD_VENDOR_RX_BUFSIZE 0
#define CFG_TUD_VENDOR_TX_BUFSIZE 0
#endif

// ---- TinyUSB audio class: UAC1 speaker via the vendored driver (p3-3300) --
// The handwritten UAC1 driver in usb_audio.c CRASHED the firmware when
// Windows initialized the iso endpoints (root cause of every composite
// failure); it is replaced by TinyUSB's own audio class from
// src/tinyusb-patch/class/audio/ (upstream 98741b55, the commit DS5Dongle
// proves on this same chip+stack - the SDK's 0.18 copy is UAC2-only and
// Windows has no reliable full-speed UAC2 path). One function, EP OUT only
// (speaker, no mic/feedback/interrupt EP): 48 kHz stereo s16 = 192 B/ms on
// EP 0x04. CFG_TUD_AUDIO=1 also makes the SDK's tusb.h include its (UAC2-
// only) audio_device.h everywhere - that header has its own #error config
// contract, so the FUNC_1_DESC_LEN / N_AS_INT / CTRL_BUF_SZ defines below
// exist ONLY to satisfy it; the vendored driver never reads them (it walks
// the descriptor itself). The macros with real runtime meaning for the
// vendored driver: ENABLE_EP_OUT/EP_IN, EP_OUT_SZ_MAX, EP_OUT_SW_BUF_SZ,
// CTRL_BUF_SZ (generic), N_CHANNELS_RX/N_BYTES_PER_SAMPLE_RX/RESOLUTION_RX.
#define CFG_TUD_AUDIO 1
#define CFG_TUD_AUDIO_FUNC_1_N_CHANNELS_RX          2    // stereo in (host->device)
#define CFG_TUD_AUDIO_FUNC_1_N_BYTES_PER_SAMPLE_RX  2    // s16
#define CFG_TUD_AUDIO_FUNC_1_RESOLUTION_RX          16
#define CFG_TUD_AUDIO_FUNC_1_SAMPLE_RATE            48000
#define CFG_TUD_AUDIO_FUNC_1_EP_OUT_SZ_MAX          192  // 48000*2*2/1000 - must equal the EP 0x04 wMaxPacketSize
#define CFG_TUD_AUDIO_FUNC_1_EP_OUT_SW_BUF_SZ       (4096)      // 21 ms landing FIFO (power of 2; tu_fifo max index space is 2*depth). p3-3633: 6144 (32*192) BROKE the pump - the vendored tu_fifo wants a power-of-two depth, and a non-power-of-two made it silently under-deliver (real machine: 100% underrun). 8 ms is enough because usb_audio_core1_tick now pumps the fifo BETWEEN encodes.
#define CFG_TUD_AUDIO_ENABLE_EP_OUT                 1
#define CFG_TUD_AUDIO_ENABLE_EP_IN                  0    // speaker only (S5 in the vendored file: EP IN flow control needs a 0.18 tu_fifo backport)
#define CFG_TUD_AUDIO_CTRL_BUF_SZ                   64   // class control request buffer (vendored driver)
// SDK-0.18-header contract only (unused by the vendored driver):
#if UAC1_ONLY
#define CFG_TUD_AUDIO_FUNC_1_DESC_LEN               91   // audio function claim w/o IAD: AC 9 + CS AC 30 + AS 9+9 + CS AS 7+11 + EP 9 + CS EP 7
#else
#define CFG_TUD_AUDIO_FUNC_1_DESC_LEN               99   // ... + the 8-byte IAD in front
#endif
#define CFG_TUD_AUDIO_FUNC_1_N_AS_INT               2    // AS interface descriptors: alt 0 + alt 1
#define CFG_TUD_AUDIO_FUNC_1_CTRL_BUF_SZ            64
#endif
