# 更新记录

[English](#english) | [中文](#中文)

<a id="中文"></a>
## 中文

### 0.0.1 — 首个公开版本

- 树莓派 Pico 2 W 固件：恢复 Stadia 手柄的 Wi-Fi 模式，按键、震动、耳机音频都可用。
- 在电脑上枚举为 USB 复合设备：UAC1 声卡、CDC 串口、XInput 手柄三合一。
- 双核分工：核心 0 跑 Wi-Fi、HTTPS、ICE、DTLS、SRTP，核心 1 跑 USB 与音频采集。
- Opus 编码跑在核心 0，USB 采集永远不会被编码卡住，连续音频不丢包。
- HTTPS 使用 stadiacast 公开发布的已吊销测试证书；DTLS 使用本地生成的自签测试证书。
- 附带离线检查（USB 描述符、固件镜像、协议自测）。
- 已在真机和真手柄上验证：连接、按键、震动、耳机出声。

已知限制：

- 这套证书方案只适用于本地局域网，不要拿到公网上用。
- DTLS 身份靠指纹锁定，换证书需要重新编译固件。
- 目前只测了单手柄，多手柄没验证。

<a id="english"></a>
## English

### 0.0.1 — first public release

- Firmware for the Raspberry Pi Pico 2 W that restores a Stadia Controller's Wi-Fi mode: input, rumble and headset audio.
- Enumerates on the PC as a USB composite device: UAC1 sound card, CDC serial and XInput gamepad.
- Dual core: core 0 runs Wi-Fi, HTTPS, ICE, DTLS and SRTP; core 1 runs USB and audio capture.
- Opus encoding runs on core 0, so USB capture is never blocked by an encode: continuous audio, no dropped packets.
- HTTPS uses the revoked test certificate published by stadiacast; DTLS uses a locally generated self-signed test certificate.
- Includes offline checks (USB descriptors, firmware image, protocol self-tests).
- Verified on real hardware with a real controller: connection, input, rumble and headset audio.

Known limitations:

- The certificate setup is for a local network only; do not expose it to the internet.
- The DTLS identity is pinned by fingerprint, so replacing it requires rebuilding the firmware.
- Only one controller has been tested; multiple controllers are unverified.
