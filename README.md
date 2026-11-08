# stadia-pico-dongle

**English** | [中文](README.zh-CN.md)

Current release: **[v0.0.1](https://github.com/Zacolgame/stadia-pico-dongle/releases)**
(prebuilt firmware attached, no build needed) · [CHANGELOG](CHANGELOG.md)

A small USB dongle built from a Raspberry Pi Pico 2 W. It keeps a **Stadia
Controller you already own** working over its own Wi-Fi, even though Google shut
Stadia down in 2023.

The dongle pretends to be the old Stadia servers on your local network. The
controller connects to it, sends input, rumbles, and plays audio into its
headset jack. Nothing leaves your home network.

Plug the dongle into your PC and it also appears as a normal USB gamepad
(XInput) and a USB sound card.

> This is a **learning and interoperability project**. The goal is to keep
> hardware people already paid for out of the landfill after the service died.
> Please read [LEGAL.md](LEGAL.md) before you use or share it.

## What it does

- Creates a Wi-Fi access point called `StadiaPhone` and answers the controller
- Serves the old HTTPS boot sequence (firmware check, registration, messages)
- Runs the audio and input link (DTLS-SRTP, UDP port 40000)
- Appears to the PC as one USB device: sound card + serial port + gamepad
- Uses both Pico cores: core 0 for Wi-Fi and servers, core 1 for USB and audio

## What you need

- Raspberry Pi Pico 2 W, unmodified
- A Stadia Controller you own, in Wi-Fi mode
- A PC with a USB port (the build steps below are for Windows)

## Build

Install: `cmake`, `ninja`, `arm-none-eabi-gcc`, `picotool`, `python`, and
Visual Studio Build Tools (needed for two small host tools). Point
`PICO_SDK_PATH` at pico-sdk 2.1.x.

```bat
build.bat
```

The result is `build/stadia_one.uf2`. The script also runs offline checks
(USB descriptors, firmware image, protocol tests). No hardware is needed for
those checks.

## Flash

1. Hold the BOOTSEL button and plug the Pico in. A USB drive appears.
2. Copy `build/stadia_one.uf2` onto that drive.

If a working firmware is already on the board, you can flash over serial:

```bat
python tools/raw-serial.py COMx flash build/stadia_one.uf2
```

## Use

1. Power the dongle. The controller joins its Wi-Fi by itself.
2. Press the Stadia button on the controller. A steady light means it is connected.
3. In Windows, set the sound output to **USB Audio Device**. Music now plays on
   the controller's headset jack.
4. Read logs with `python tools/raw-serial.py COMx read 10`.

## Certificates (short version; full details in LEGAL.md)

- **HTTPS** uses the revoked test certificate that the
  [stadiacast](https://github.com/jkfran/stadiacast) project publishes for this
  exact purpose. It is revoked, so normal browsers and TLS clients reject it.
  The controller only checks that the chain ends at a Google root, so it accepts
  it. Files and provenance: `vendor/upstream-credential/`.
- **DTLS** (the audio link) uses a throwaway self-signed certificate in
  `vendor/selfsigned-dtls/`. This link identifies the peer by a fingerprint, not
  by a certificate chain, so self-signed is fine here and keeps the handshake
  small enough to fit one packet. Regenerate it with `tools/gen-dtls-cert.py`.
- Both certificates are compiled into the firmware by `python tools/gen-certs.py`.

## Hardware test driver (optional)

`sim/` runs the firmware's real HTTPS and DTLS endpoints from a rooted Android
phone. It checks registration, game messages, parallel TLS connections, STUN and
the DTLS handshake. You need `adb`, `node`, and a phone you own. See
[sim/README.md](sim/README.md).

## Project layout

| Path | Contents |
|---|---|
| `src/` | firmware source (dual-core app, cloud/HTTPS/RTC/USB) |
| `linker/` | RP2350 linker script (Opus code in RAM) |
| `vendor/libopus/` | trimmed libopus 1.3.1 (fixed point) |
| `vendor/upstream-credential/` | revoked stadiacast certificate + provenance |
| `vendor/selfsigned-dtls/` | test certificate for the audio link |
| `third_party/stadiacast/` | upstream NOTICE, LICENSE, attribution |
| `tools/` | `raw-serial.py` (flash/logs), `gen-certs.py`, `padtest.html` |
| `tests/` | offline checks and host-side protocol tests |
| `sim/` | Android-based integration test |

## About stadiacast

This is an independent implementation for a microcontroller. Protocol details
were learned from watching how the real controller talks, with
[stadiacast](https://github.com/jkfran/stadiacast) (MIT license) as the working
reference. Its revoked test certificate is reused as described above, with
attribution in `third_party/stadiacast/`. No Google services, accounts, or
protobuf schema files are used or included.

## License

MIT, see [LICENSE](LICENSE). Third-party parts keep their own licenses, see
[THIRD-PARTY.md](THIRD-PARTY.md). Nothing here is legal advice; read
[LEGAL.md](LEGAL.md).
