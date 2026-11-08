# 法律声明

**English** | [中文](#中文)

> **这不是法律意见。** 作者不是律师。下面只是把项目做了什么、证书从哪来、已知事实
> 有哪些讲清楚，方便你自己判断。需要确定结论，请咨询你所在地区的律师。
>
> **This is not legal advice.** The author is not a lawyer. This file explains what
> the project does, where its certificates come from, and the known facts, so you
> can decide for yourself. For a definite answer, ask a lawyer in your country.

---

<a id="中文"></a>
## 中文

### 一、项目为什么存在

谷歌在 2023 年 1 月关停了 Stadia。用户买下的手柄本身没坏，但它的 Wi-Fi 模式依赖的
服务器已经不存在了。本项目是学习与互操作项目，目的就是让用户能继续用自己合法买下的
硬件。

它不修改、不刷写、不越狱、不解锁任何设备，只是按原样和手柄现有固件通信。

### 二、数据不出你自己的网络

- 只在你自己的局域网里跑：本地 Wi-Fi 热点加本地服务器。
- 不用谷歌账号，也不连接任何谷歌服务。
- 不收集数据，不往外发数据，不保存用户数据。
- 不访问任何游戏、串流、账号或受版权保护的内容，只处理手柄自己的按键、震动马达
  和耳机音频。

### 三、无关联与商标

本项目是独立项目，和谷歌没有任何关系，也没有得到谷歌的认可或支持。Stadia 和相关
名称是 Google LLC 的商标，这里提到它们只是为了说明兼容什么硬件。所有商标归各自的
所有者。

### 四、stadiacast 项目和它的证书

协议细节是靠观察真手柄的实际通信摸出来的，
[stadiacast](https://github.com/jkfran/stadiacast)（MIT 许可）作为可以参考的实现。
它的 NOTICE 和 LICENSE 原文已经放进 third_party/stadiacast/，旁边还有一份说明，
写清楚到底复用了什么。

复用内容：vendor/upstream-credential/ 里那张已吊销的测试证书。

为什么这样做是安全的：

- 这是一条谷歌信任服务（Google Trust Services）签发的证书链。stadiacast 的作者在
  公开私钥之前，就主动申请把它吊销了。
- 普通 TLS 客户端会检查吊销状态，所以都会拒绝这张证书。它没法在公网上冒充任何人。
- Stadia 手柄只检查服务器证书链能不能走到谷歌根证书，不查域名、不查有效期、也不查
  吊销状态，这一点在真机上确认过。所以手柄会接受它。

本项目复用这张证书，用途一样，提醒也一样：它是局域网兼容工具，不是秘密，也不该被
当成可信凭据。

### 五、DTLS 测试证书

vendor/selfsigned-dtls/ 里是一张用完就丢的自签证书（CN=stadia-dtls.local，故意不用
真实域名）。它生成出来是为了控制数据包大小，不是为了建立信任：

- 在这条链路上，手柄靠一个 SHA-256 指纹来认服务器，这个指纹是通过已经验证过的
  HTTPS 连接传给它的。
- 手柄既不构建也不校验 DTLS 证书链。
- 所以自签证书在这里本来就是正确做法，没有任何冒充价值，需要时用
  tools/gen-dtls-cert.py 重新生成即可。

### 六、本项目不做什么

- 不规避任何针对版权作品的技术保护措施。这里没有内容、没有账号、没有付费墙，只是
  一个本地设备和你自己运行的本地服务器在通信。
- 不使用谷歌服务、私有 API 或谷歌凭据；提到商标只是为了说明兼容的硬件。
- 除了上面两处，不分发任何私钥。这两张也都是其所有者为了这个用途主动公开的。
  本仓库里没有留下任何有效的、未吊销的第三方私钥。你可以自己验证：运行
  python tools/gen-certs.py，它会打印每张被编译进去的证书的指纹。

### 七、使用或二开时请注意

- 只用你自己拥有的硬件，只在你拥有或有权管理的网络上跑。
- 转发本项目时，请保留 third_party/stadiacast/ 里的归属说明。
- 如果要换证书，尽量用短期的、已吊销的或自签的测试身份，别把真实域名的有效私钥
  提交进仓库。
- 发布自己的分支前，把 LICENSE 里的版权人换成你自己的名字。

### 八、免责

本软件按“现状”提供，不附带任何形式的担保。用不用、怎么用，风险自负。

---

<a id="english"></a>
## English

### 1. Why this project exists

Google shut Stadia down in January 2023. The controllers people bought still work,
but their Wi-Fi mode needs servers that no longer exist. This is a learning and
interoperability project: it lets people keep using hardware they legally bought.

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
supported by Google. Stadia and related names are trademarks of Google LLC, used
here only to describe what the hardware is compatible with. All trademarks belong
to their owners.

### 4. The stadiacast project and its certificate

Protocol details were learned by watching how the real controller talks, using
[stadiacast](https://github.com/jkfran/stadiacast) (MIT license) as the working
reference. Its NOTICE and LICENSE are copied word for word into
third_party/stadiacast/, next to a note saying exactly what was reused.

What was reused: the revoked test certificate in vendor/upstream-credential/.

Why that is safe:

- It is a Google Trust Services chain that the stadiacast authors had revoked at
  their own request, before they published the private key.
- Ordinary TLS clients check revocation, so they reject this certificate. It
  cannot be used to impersonate anyone on the public internet.
- The Stadia controller only checks that the server's chain ends at a Google
  root. It does not check the hostname, the dates, or revocation. That was
  confirmed on real hardware, so the controller accepts it.

This project reuses the certificate for the same purpose and with the same
warning: it is a local-network compatibility tool, not a secret and not
something to trust.

### 5. The DTLS test certificate

vendor/selfsigned-dtls/ contains a throwaway self-signed certificate
(CN=stadia-dtls.local, deliberately not a real domain). It was generated for
packet size, not for trust:

- On this link the controller identifies the server by a SHA-256 fingerprint
  that was sent to it over the validated HTTPS connection.
- It does not build or check a DTLS certificate chain at all.
- So a self-signed certificate is correct here, has no impersonation value, and
  can be regenerated at any time with tools/gen-dtls-cert.py.

### 6. What this project does not do

- It does not get around any technical protection of copyrighted works. There is
  no content, account or paywall here; it is one local device talking to a local
  server you run yourself.
- It does not use Google services, private APIs, Google credentials, or
  trademarks beyond naming what the hardware is.
- It does not ship any private key except the two certificates described above,
  both published deliberately by their owners for exactly this use. There is no
  live, unrevoked third-party private key in this repository. You can check
  yourself: python tools/gen-certs.py prints the fingerprint of every
  certificate it compiles in.

### 7. If you use it or fork it

- Use only hardware you own, on networks you own or are allowed to administer.
- Keep the attribution in third_party/stadiacast/ if you share this project.
- If you replace the certificates, prefer short-lived, revoked or self-signed
  test identities. Never commit a live private key for a real domain.
- Replace the copyright holder in LICENSE with your own name.

### 8. No warranty

The software is provided "as is", without warranty of any kind. You use it at
your own risk.
