# stadia-pico-wifi-dongle

[English](README.md) | **中文**

当前版本：**[v0.0.1](https://github.com/Zacolgame/stadia-pico-wifi-dongle/releases)**（Release 里附了编好的固件，不想编译可以直接下）· [更新记录](CHANGELOG.md)

用一块树莓派 Pico 2 W 做的 USB 加密狗。谷歌 2023 年关停 Stadia 之后，它让你手上那台已经买下的 Stadia 手柄还能继续用 Wi-Fi 模式。

原理不复杂：它在你家的局域网里冒充当年那套 Stadia 服务器。手柄连上以后，按键、震动、耳机出声都恢复正常，所有数据只在家里网络里走，不会发到外面去。

插到电脑上，它同时还是一个标准的 USB 手柄（XInput）和一块 USB 声卡。

> 这是学习与互操作项目，目的就是让用户花钱买下的硬件在服务停掉后不至于变成废品。使用前请先看下面的[法律声明](#法律声明)。

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

先装好这些工具：cmake、ninja、arm-none-eabi-gcc、picotool、python，以及 Visual Studio Build Tools（编译两个小主机工具时要用）。然后把环境变量 PICO_SDK_PATH 指向 pico-sdk 2.1.x。

```bat
build.bat
```

编译结果在 build/stadia_one.uf2。脚本顺手还会跑一遍离线检查（USB 描述符、固件镜像、协议自测），这一步不需要接硬件。

## 烧录

1. 按住 BOOTSEL 键插上 USB，电脑会多出一个 U 盘。
2. 把 build/stadia_one.uf2 拖进这个 U 盘。

如果板子上已经有能跑的固件，也可以走串口刷：

```bat
python tools/raw-serial.py COMx flash build/stadia_one.uf2
```

## 使用

1. 给加密狗通电，手柄会自己连上它的热点。
2. 按一下手柄上的 Stadia 键，指示灯常亮就是连上了。
3. 在 Windows 的声音设置里把输出切到 USB Audio Device，音乐就从手柄耳机口出来。
4. 看日志：`python tools/raw-serial.py COMx read 10`

## WiFi 账密

加密狗自己开一个 Wi-Fi 热点。默认值：名字 `StadiaPhone`，密码 `TestPass1234a`
（WPA2）。手柄那边记着同一套账密，所以两边必须永远一致：改了一边，另一边也要改。

加密狗这边用串口命令管理：

```
WIFI SHOW              看当前配置（生效中 + 暂存 + 已保存，密码永远不打印）
WIFI SSID <1..32字>    暂存新名字（可以带空格）
WIFI PASS <8..63字>    暂存新 WPA2 密码（可以带空格）
WIFI OPEN              暂存为开放网络（不要密码）
WIFI SAVE              写入 flash 并重启生效
WIFI RESET             清掉已存配置，重启回到编译默认值
```

例子：`python tools/raw-serial.py COMx send "WIFI SSID MyDongle"`。

完整改账密的顺序：

1. 在加密狗上设好并 `WIFI SAVE`。它会重启，手柄掉线是正常的。
2. 用 BLE 把同一套账密教给手柄，推荐用上游工具：`pip install "stadiacast[ble]"`，
   然后 `stadiacast-provision scan` 和
   `stadiacast-provision provision --address <手柄蓝牙地址> --ssid <名字>`。
   先让手柄进 BLE 配网模式（按住 `···` + Assistant 键直到橙灯闪）。电脑需要有能用的蓝牙。
3. 手柄连上加密狗热点，正常注册使用。

救砖：如果两边对不上，手柄只是连不上，什么都不会坏。USB 串口永远能用：
`WIFI SHOW` 看状态，`WIFI RESET` 回默认值（手柄记得默认值，会自己回来）。
重刷固件不会丢已存的 WiFi 配置，只有 `WIFI RESET` 或整片擦除才会清掉。

## 关于证书（细节见下面的[法律声明](#法律声明)）

- **HTTPS** 用的是 [stadiacast](https://github.com/jkfran/stadiacast) 公开的那张已吊销测试证书。它被吊销过，所以普通浏览器和 TLS 客户端都会拒绝；但手柄只检查证书链能不能走到谷歌根证书，所以会接受。文件与出处在 vendor/upstream-credential/。
- **DTLS**（音频链路）用的是一张用完就丢的自签证书，放在 vendor/selfsigned-dtls/。这条链路只靠指纹认对方，不验证书链，自签完全够用，而且能让握手小到一个包装得下。需要时用 `tools/gen-dtls-cert.py` 重新生成。
- 两张证书都由 `python tools/gen-certs.py` 编译进固件。

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

## 和 stadiacast 的关系

本项目是面向单片机的独立实现。协议细节是靠观察真手柄的实际通信摸出来的，[stadiacast](https://github.com/jkfran/stadiacast)（MIT 许可）作为可以参考的实现。上面那张已吊销测试证书就是从它那里复用的，归属说明放在 third_party/stadiacast/。本项目不使用、也不包含任何谷歌服务、谷歌账号或 protobuf schema 文件。

## 许可证

MIT，见 [LICENSE](LICENSE)。第三方组件保留各自的许可证，见 [THIRD-PARTY.md](THIRD-PARTY.md)。

## 法律声明

> **这不是法律意见。** 作者不是律师。下面只是把项目做了什么、证书从哪来、已知事实有哪些讲清楚，方便你自己判断。需要确定结论，请咨询你所在地区的律师。

### 一、项目为什么存在

谷歌在 2023 年 1 月关停了 Stadia。用户买下的手柄本身没坏，但它的 Wi-Fi 模式依赖的服务器已经不存在了。本项目是学习与互操作项目，目的就是让用户能继续用自己合法买下的硬件。

它不修改、不刷写、不越狱、不解锁任何设备，只是按原样和手柄现有固件通信。

### 二、数据不出你自己的网络

- 只在你自己的局域网里跑：本地 Wi-Fi 热点加本地服务器。
- 不用谷歌账号，也不连接任何谷歌服务。
- 不收集数据，不往外发数据，不保存用户数据。
- 不访问任何游戏、串流、账号或受版权保护的内容，只处理手柄自己的按键、震动马达和耳机音频。

### 三、无关联与商标

本项目是独立项目，和谷歌没有任何关系，也没有得到谷歌的认可或支持。Stadia 和相关名称是 Google LLC 的商标，这里提到它们只是为了说明兼容什么硬件。所有商标归各自的所有者。

### 四、stadiacast 项目和它的证书

协议细节是靠观察真手柄的实际通信摸出来的，[stadiacast](https://github.com/jkfran/stadiacast)（MIT 许可）作为可以参考的实现。它的 NOTICE 和 LICENSE 原文已经放进 third_party/stadiacast/，旁边还有一份说明，写清楚到底复用了什么。

复用内容：vendor/upstream-credential/ 里那张已吊销的测试证书。

为什么这样做是安全的：

- 这是一条谷歌信任服务（Google Trust Services）签发的证书链。stadiacast 的作者在公开私钥之前，就主动申请把它吊销了。
- 普通 TLS 客户端会检查吊销状态，所以都会拒绝这张证书。它没法在公网上冒充任何人。
- Stadia 手柄只检查服务器证书链能不能走到谷歌根证书，不查域名、不查有效期、也不查吊销状态，这一点在真机上确认过，所以手柄会接受它。

本项目复用这张证书，用途一样，提醒也一样：它是局域网兼容工具，不是秘密，也不该被当成可信凭据。

### 五、DTLS 测试证书

vendor/selfsigned-dtls/ 里是一张用完就丢的自签证书（CN=stadia-dtls.local，故意不用真实域名）。它生成出来是为了控制数据包大小，不是为了建立信任：

- 在这条链路上，手柄靠一个 SHA-256 指纹来认服务器，这个指纹是通过已经验证过的 HTTPS 连接传给它的。
- 手柄既不构建也不校验 DTLS 证书链。
- 所以自签证书在这里本来就是正确做法，没有任何冒充价值，需要时用 tools/gen-dtls-cert.py 重新生成即可。

### 六、本项目不做什么

- 不规避任何针对版权作品的技术保护措施。这里没有内容、没有账号、没有付费墙，只是一个本地设备和你自己运行的本地服务器在通信。
- 不使用谷歌服务、私有 API 或谷歌凭据；提到商标只是为了说明兼容的硬件。
- 除了上面两处，不分发任何私钥。这两张也都是其所有者为了这个用途主动公开的，本仓库里没有留下任何有效的、未吊销的第三方私钥。你可以自己验证：运行 python tools/gen-certs.py，它会打印每张被编译进去的证书的指纹。

### 七、使用或二开时请注意

- 只用你自己拥有的硬件，只在你拥有或有权管理的网络上跑。
- 转发本项目时，请保留 third_party/stadiacast/ 里的归属说明。
- 如果要换证书，尽量用短期的、已吊销的或自签的测试身份，别把真实域名的有效私钥提交进仓库。
- 发布自己的分支前，把 LICENSE 里的版权人换成你自己的名字。

### 八、免责

本软件按“现状”提供，不附带任何形式的担保。用不用、怎么用，风险自负。
