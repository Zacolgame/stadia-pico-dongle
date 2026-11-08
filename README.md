# stadia-pico-wifi-dongle

**English** | [中文](README.zh-CN.md)

Current release: **[v0.0.1](https://github.com/Zacolgame/stadia-pico-wifi-dongle/releases)**
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
> Please read the [legal notices](#legal-notices) below before you use or share it.

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

## Certificates (short version; full details in [Legal notices](#legal-notices))

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

## About stadiacast

This is an independent implementation for a microcontroller. Protocol details
were learned from watching how the real controller talks, with
[stadiacast](https://github.com/jkfran/stadiacast) (MIT license) as the working
reference. Its revoked test certificate is reused as described above, with
attribution in `third_party/stadiacast/`. No Google services, accounts, or
protobuf schema files are used or included.

## License

MIT, see [LICENSE](LICENSE). Third-party parts keep their own licenses, see
[THIRD-PARTY.md](THIRD-PARTY.md).

## Legal notices

> **This is not legal advice.** The author is not a lawyer. This section explains
> what the project does, where its certificates come from, and the known facts,
> so you can decide for yourself. For a definite answer, ask a lawyer in your
> country.

### 1. Why this project exists

Google shut Stadia down in January 2023. The controllers people bought still
work, but their Wi-Fi mode needs servers that no longer exist. This is a
learning and interoperability project: it lets people keep using hardware they
legally bought.

It does not modify, flash, jailbreak or unlock any device. It talks to the
controller's existing firmware as it is.

### 2. Everything stays on your own network

- It runs only on your own LAN: a local Wi-Fi access point and local servers.
- It uses no Google account and contacts no Google service.
- It collects no data, sends no data out, and stores no user data.
- It does not access any game, stream, account or copyrighted content. It only
  handles the controller's own input, rumble motors and headset audio.

### 3. No affiliation, and trademarks

This is an independent project. It is not affiliated with, endorsed by or
supported by Google. Stadia and related names are trademarks of Google LLC,
used here only to describe what the hardware is compatible with. All trademarks
belong to their owners.

### 4. The stadiacast project and its certificate

Protocol details were learned by watching how the real controller talks, using
[stadiacast](https://github.com/jkfran/stadiacast) (MIT license) as the working
reference. Its NOTICE and LICENSE are copied word for word into
`third_party/stadiacast/`, next to a note saying exactly what was reused.

What was reused: the revoked test certificate in `vendor/upstream-credential/`.

Why that is safe:

- It is a Google Trust Services chain that the stadiacast authors had revoked
  at their own request, before they published the private key.
- Ordinary TLS clients check revocation, so they reject this certificate. It
  cannot be used to impersonate anyone on the public internet.
- The Stadia controller only checks that the server's chain ends at a Google
  root. It does not check the hostname, the dates, or revocation. That was
  confirmed on real hardware, so the controller accepts it.

This project reuses the certificate for the same purpose and with the same
warning: it is a local-network compatibility tool, not a secret and not
something to trust.

### 5. The DTLS test certificate

`vendor/selfsigned-dtls/` contains a throwaway self-signed certificate
(`CN=stadia-dtls.local`, deliberately not a real domain). It was generated for
packet size, not for trust:

- On this link the controller identifies the server by a SHA-256 fingerprint
  that was sent to it over the validated HTTPS connection.
- It does not build or check a DTLS certificate chain at all.
- So a self-signed certificate is correct here, has no impersonation value, and
  can be regenerated at any time with `tools/gen-dtls-cert.py`.

### 6. What this project does not do

- It does not get around any technical protection of copyrighted works. There
  is no content, account or paywall here; it is one local device talking to a
  local server you run yourself.
- It does not use Google services, private APIs, Google credentials, or
  trademarks beyond naming what the hardware is.
- It does not ship any private key except the two certificates described above,
  both published deliberately by their owners for exactly this use. There is no
  live, unrevoked third-party private key in this repository. You can check
  yourself: `python tools/gen-certs.py` prints the fingerprint of every
  certificate it compiles in.

### 7. If you use it or fork it

- Use only hardware you own, on networks you own or are allowed to administer.
- Keep the attribution in `third_party/stadiacast/` if you share this project.
- If you replace the certificates, prefer short-lived, revoked or self-signed
  test identities. Never commit a live private key for a real domain.
- Replace the copyright holder in LICENSE with your own name.

### 8. No warranty

The software is provided "as is", without warranty of any kind. You use it at
your own risk.
