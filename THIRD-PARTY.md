# 第三方组件

[English](#english) | [中文](#中文)

本项目由原创代码和下面这些第三方作品组成。每个组件保留自己的许可证，归属信息按
表中说明保留。

<a id="中文"></a>
## 中文

| 组件 | 位置 | 许可证 | 说明 |
|---|---|---|---|
| stadiacast（参考实现与已吊销测试证书） | third_party/stadiacast/、vendor/upstream-credential/ | MIT + NOTICE 例外条款 | NOTICE 和 LICENSE 原文照录；另见 third_party/stadiacast/README-attribution.md |
| libopus 1.3.1（精简版，定点） | vendor/libopus/（含 COPYING） | BSD-3-Clause（Xiph.Org） | 只保留 celt 与 silk/fixed；另见 vendor/libopus/README-stadia.txt |
| TinyUSB（打过补丁的 RP2040/RP2350 驱动与 UAC1 类） | src/tinyusb-patch/ | MIT（hathach 及贡献者） | 基于 SDK 自带 TinyUSB 的补丁副本；上游见 https://github.com/hathach/tinyusb |
| 树莓派 Pico SDK 2.1.x（仅构建期，外部依赖） | PICO_SDK_PATH（不随仓库分发） | BSD-3-Clause | 含 RP2350 启动 ROM 头文件、cyw43 驱动、TinyUSB、lwIP、mbedTLS |
| ARM GNU 工具链（仅构建期，外部依赖） | 本机工具链（不随仓库分发） | GPL + 运行时例外 | 标准嵌入式工具链，不进入固件产物 |
| 谷歌信任服务公钥体系（仅用于验链） | 无（根证书在手柄里） | 不适用 | 手柄用自带的 GTS 根证书校验我们的服务端证书链 |

本项目不使用、不包含任何谷歌服务、谷歌账号、SDK、protobuf schema 或固件提取文件。

<a id="english"></a>
## English

| component | location | license | notes |
|---|---|---|---|
| stadiacast (reference + revoked test credential) | third_party/stadiacast/, vendor/upstream-credential/ | MIT + NOTICE exception | NOTICE/LICENSE reproduced verbatim; see third_party/stadiacast/README-attribution.md |
| libopus 1.3.1 (trimmed, fixed-point) | vendor/libopus/ (with COPYING) | BSD-3-Clause (Xiph.Org) | trimmed to celt + silk/fixed; see vendor/libopus/README-stadia.txt |
| TinyUSB (patched RP2040/RP2350 driver + UAC1 class) | src/tinyusb-patch/ | MIT (hathach and contributors) | patched copy of the SDK-bundled TinyUSB; upstream https://github.com/hathach/tinyusb |
| Raspberry Pi Pico SDK 2.1.x (build-time, external) | PICO_SDK_PATH (not shipped) | BSD-3-Clause | includes RP2350 boot ROM headers, cyw43-driver, TinyUSB, lwIP, mbedTLS |
| ARM GNU Toolchain (build-time, external) | local install (not shipped) | GPL + runtime exception | standard embedded toolchain, never enters the firmware image |
| Google Trust Services PKI (trust only) | none (roots live in the controller) | n/a | the controller validates our server chain against its built-in GTS roots |

No Google services, accounts, SDKs, protobuf schemas, or firmware extracts are
used or shipped.
