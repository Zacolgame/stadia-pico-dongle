# stadia-pico-dongle

[English](README.md) | **中文**

当前版本：**[v0.0.1](https://github.com/Zacolgame/stadia-pico-dongle/releases)**
（Release 里附了编好的固件，不想编译可以直接下）· [更新记录](CHANGELOG.md)

用一块树莓派 Pico 2 W 做的 USB 加密狗。谷歌 2023 年关停 Stadia 之后，它让你手上
那台已经买下的 Stadia 手柄还能继续用 Wi-Fi 模式。

原理不复杂：它在你家的局域网里冒充当年那套 Stadia 服务器。手柄连上以后，按键、震动、
耳机出声都恢复正常。所有数据只在家里网络里走，不会发到外面去。

插到电脑上，它同时还是一个标准的 USB 手柄（XInput）和一块 USB 声卡。

> 这是学习与互操作项目，目的就是让用户花钱买下的硬件在服务停掉后不至于变成废品。
> 使用前请先看一下 [LEGAL.md](LEGAL.md)。

## 功能

- 开一个叫 StadiaPhone 的热点，接管手柄的网络请求
- 复刻当年的 HTTPS 开机流程：版本检查、注册、消息
- 跑音频和输入的媒体链路（DTLS-SRTP，UDP 40000 端口）
- 在电脑上表现为一个 USB 复合设备：声卡、串口、手柄三合一
- 双核分工：核心 0 跑 Wi-Fi 和服务端，核心 1 跑 USB 和音频

## 需要准备

- 树莓派 Pico 2 W，原装即可，不用改硬件
- 你自己的一台 Stadia 手柄，切到 Wi-Fi 模式
- 一台带 USB 口的电脑（下面的构建步骤按 Windows 写）

## 构建

先装好这些工具：cmake、ninja、arm-none-eabi-gcc、picotool、python，以及 Visual Studio
Build Tools（编译两个小主机工具时要用）。然后把环境变量 PICO_SDK_PATH 指向
pico-sdk 2.1.x。

```bat
build.bat
```

编译结果在 build/stadia_one.uf2。脚本顺手还会跑一遍离线检查（USB 描述符、固件镜像、
协议自测），这一步不需要接硬件。

## 烧录

1. 按住 BOOTSEL 键插上 USB，电脑会多出一个 U 盘。
2. 把 build/stadia_one.uf2 拖进这个 U 盘。

如果板子上已经有能跑的固件，也可以走串口刷：

```bat
python tools/raw-serial.py COMx flash build/stadia_one.uf2
```

## 使用

1. 给加密狗通电，手柄会自己连上它的热点。
2. 按一下手柄上的 Stadia 键。指示灯常亮就是连上了。
3. 在 Windows 的声音设置里把输出切到 USB Audio Device，音乐就从手柄耳机口出来。
4. 看日志：`python tools/raw-serial.py COMx read 10`

## 关于证书（细节见 LEGAL.md）

- **HTTPS** 用的是 [stadiacast](https://github.com/jkfran/stadiacast) 公开的那张
  已吊销测试证书。它被吊销过，所以普通浏览器和 TLS 客户端都会拒绝；但手柄只检查
  证书链能不能走到谷歌根证书，所以会接受。文件与出处：vendor/upstream-credential/。
- **DTLS**（音频链路）用的是一张用完就丢的自签证书，放在 vendor/selfsigned-dtls/。
  这条链路只靠指纹认对方，不验证书链，自签完全够用，而且能让握手小到一个包装得下。
  需要时用 `tools/gen-dtls-cert.py` 重新生成。
- 两张证书都由 `python tools/gen-certs.py` 编译进固件。

## 硬件联调工具（可选）

sim/ 目录会用一台 root 过的安卓手机去调用固件真实的 HTTPS 与 DTLS 接口，检查注册、
消息、并发 TLS、STUN 和 DTLS 握手。需要 adb、node，以及你自己的手机。具体见
[sim/README.md](sim/README.md)。

## 目录结构

| 路径 | 内容 |
|---|---|
| src/ | 固件源码（双核应用、云服务、HTTPS、RTC、USB） |
| linker/ | RP2350 链接脚本（把 Opus 代码放进 RAM） |
| vendor/libopus/ | 精简版 libopus 1.3.1（定点） |
| vendor/upstream-credential/ | stadiacast 的已吊销证书与出处说明 |
| vendor/selfsigned-dtls/ | 音频链路用的自签测试证书 |
| third_party/stadiacast/ | 上游的 NOTICE、LICENSE 与归属说明 |
| tools/ | raw-serial.py（烧录、看日志）、gen-certs.py、padtest.html |
| tests/ | 离线检查与主机侧协议测试 |
| sim/ | 基于安卓的集成测试 |

## 和 stadiacast 的关系

本项目是面向单片机的独立实现。协议细节是靠观察真手柄的实际通信摸出来的，
[stadiacast](https://github.com/jkfran/stadiacast)（MIT 许可）作为可以参考的实现。
上面那张已吊销测试证书就是从它那里复用的，归属说明放在 third_party/stadiacast/。
本项目不使用、也不包含任何谷歌服务、谷歌账号或 protobuf schema 文件。

## 许可证

MIT，见 [LICENSE](LICENSE)。第三方组件保留各自的许可证，见
[THIRD-PARTY.md](THIRD-PARTY.md)。本文和 [LEGAL.md](LEGAL.md) 都不构成法律意见。
