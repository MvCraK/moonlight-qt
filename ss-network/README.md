# SS-NETWORK · 内置 SS 组网（Windows / macOS）

导入组网配置后，访问 10.0.0.0/24（家庭）和 10.1.1.0/24（公司）的流量会经 Shadowsocks（AEAD 与 Shadowsocks 2022 `2022-blake3-*`）节点转发。回家线路可在「直连（订阅）」与「公司转发（固定 `homeRelay` / `homeRelayTcp`+`homeRelayUdp`）」之间一键切换。

- **串流 UDP**（视频、音频、ENet 控制、麦克风等）：`shim/ss_shim.h` 在编译期把 moonlight-common-c 的 socket 调用改到 `ss_*`。Moonlight 自己的 socket 直接发往 SS 节点，并在收包线程里零拷贝解密，路径为网络 → SS 解密 → Moonlight 接收器，没有本地中继。
- **common-c 的 TCP**（RTSP 等）：走 Rust 里的一次性本地回环中继（连接后立即 flush 握手以兼容服务端先发的协议）。
- **Qt 网络**（配对/轮询 HTTP、USB 转发、文件映射等）：经应用级 `QNetworkProxyFactory` 只把路由主机交给本地 SOCKS5（Rust 实现），其他地址仍然直连。
- **与系统 VPN / FlClash TUN 共存**：
  - 未开启内置组网时，桌面端流量自然走系统路由（如 FlClash TUN）；
  - 检测到系统 VPN/TUN 运行且开启内置组网时，SS 外层 TCP/UDP 和节点 DNS 解析会自动绑定到底层物理网卡（macOS `IP_BOUND_IF` / Windows `IP_UNICAST_IF`）并绕过 `198.18.0.0/15` Fake-IP，避免双重代理；
  - 订阅拉取允许走系统代理并支持最多 5 次 HTTPS 重定向。
- 走 SS 的主机按 VPN 处理：串流使用远程模式，包长 1024。
- 组网开关不持久化。配置、节点与回家线路模式会保存在 `AppDataLocation/ss-network.json`，但每次启动组网都是关闭的。
- 断开组网时，已有代理连接会关闭，正在使用组网的串流需要重新连接。
- Linux / Steam Link 不编译 native 部分，工具栏入口自动隐藏。

## 界面

右上角工具栏在“设置”左侧有一个组网按钮：灰色表示关闭，亮绿色加方形指示灯表示已连接且节点可达，琥珀色表示有节点不可达，悬停时显示状态提示。

点击按钮在下方弹出紧凑面板：
- 标题栏：状态文字和“开启/断开组网”主按钮；
- 系统 VPN 状态提示条（检测到系统 VPN/TUN 时显示）；
- 回家线路切换：直连（订阅） / 公司转发（固定）；
- 当前生效节点与延迟、直连接收流量与订阅更新时间；
- 底部：导入配置（系统文件对话框）、更新订阅、检测节点。

面板支持 Tab 切换焦点和 Esc 关闭，点击外部也会关闭。文案在中英文间切换，跟随应用的语言设置，没有改动上游的翻译文件。

## 目录

| 路径 | 职责 |
|---|---|
| ss-network.pri | app 侧：cargo 构建并静态链接 Rust 库、Qt/QML 源文件、`SS_NETWORK_ENABLED` 宏。 |
| ss-network-common-c.pri | common-c 侧：编译 shim，并对每个 common-c 源文件强制 include `ss_shim.h`。 |
| shim/ | socket 重定向与底层网卡绑定。macOS 覆盖 connect/sendto/recvfrom/sendmsg/recvmsg/close；Windows 覆盖 connect/sendto/recvfrom/closesocket/WSASendMsg，并通过 WSAIoctl 换掉 WSARecvMsg。 |
| rust/ | `libss_network`：SS AEAD / SS 2022 加解密、物理网卡与抗 Fake-IP DNS、TCP 中继、SOCKS5、TCP 探测、Clash YAML 解析（`cargo test` 覆盖）。 |
| qt/ssnetwork.* | QML 单例 `SsNetwork`：配置、回家模式切换、订阅拉取（支持重定向与系统代理）、VPN 检测与物理网卡选择、节点探测、代理工厂、开关。 |
| qml/ | 工具栏按钮、弹出面板、图标、中英文文案。 |

## 合并上游时的接入点

上游文件内的改动都用 `SS-NETWORK [MODIFIED]` 标记，可用 `git grep -n "SS-NETWORK \[MODIFIED\]" app moonlight-common-c` 列出。

| 上游文件 | 内容 |
|---|---|
| moonlight-common-c/moonlight-common-c.pro | `include(../ss-network/ss-network-common-c.pri)` |
| app/app.pro | `include(../ss-network/ss-network.pri)` |
| app/gui/main.qml | 工具栏“设置”按钮前加一个 `Loader`，加载 `qrc:/ss-network/SsNetworkButton.qml`。 |
| app/backend/nvhttp.cpp | NvHTTP 的 QNAM 改用 `SsNetwork::createProxyFactory()`。 |
| app/backend/nvcomputer.cpp | `getActiveAddressReachability()` 对路由主机返回 `RI_VPN`。 |

升级 moonlight-common-c 子模块时：
- 若新增了 socket 调用方式（例如新的 `WSA*` 收发函数），需要在 `ss_shim.h/.c` 补上；
- 用 `nm -u libmoonlight-common-c.a` 确认，除 `ss_shim.o` 外不应再出现 `_sendto`、`_recvfrom` 等裸调用。

## 构建

需要 Rust（cargo；rustup 会按需安装 target）。Windows x64/ARM64 用对应的 MSVC target；macOS 按 `QMAKE_APPLE_DEVICE_ARCHS` 编译，多架构时用 lipo 合并。

**注意**：从旧的构建目录升级时，需要删掉 `moonlight-common-c` 的中间文件让它重新编译，否则强制 include 不会生效。
