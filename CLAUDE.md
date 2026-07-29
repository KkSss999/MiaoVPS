# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

本地优先的桌面端 WireGuard VPN 客户端：把用户自己的 VPS 一键转成 VPN 节点，
客户端用纯 Rust 协议栈（boringtun）接管系统流量。无账户、无中心服务。
代码注释与文档使用中文。

## 常用命令

```bash
cargo build                          # 编译全部 9 crate + 1 binary
cargo test                           # 全部测试
cargo test -p miaovps-connect        # 单个 crate
cargo test -p miaovps-connect backoff  # 按名字过滤单个测试
cargo clippy --all-targets           # lint
```

CLI 二进制名是 `miaovps`（不是 `miaovps-cli`）：

```bash
cargo run -p miaovps-cli -- help
./target/debug/miaovps validate <ip:port> <client-priv> <server-pub>
sudo ./target/debug/miaovps connect [--full] [--skip-validate]
sudo ./target/debug/miaovps disconnect
```

日志默认只显示 `miaovps=info`（见 `main.rs` 的 `with_env_filter`）。
要看隧道内部细节需要 `RUST_LOG=miaovps=debug`。

真机验证脚本（需先 sudo 起隧道）：

```bash
bash scripts/test-reconnect.sh    # 断线重连，默认阻断 130s
bash scripts/bootstrap-server.sh  # 服务端手动部署（在 VPS 上跑）
```

## 架构：控制平面与数据平面分离

这是理解本项目的关键。两条路径完全独立，不共享运行时状态：

**控制平面** — 通过 SSH 远程部署 WireGuard，服务端不装常驻 Agent。
`miaovps-ssh`（russh）→ `miaovps-provisioner`（9 步状态机 + 环境检测 + 回滚）。

**数据平面** — 本机 utun 虚拟网卡 + boringtun 加解密，不依赖 `wg-quick`。
`miaovps-connect`。这是唯一涉及实时数据包处理的部分。

### 依赖分层

严格单向，`core` 是纯领域模型（无内部依赖），同层之间禁止横向依赖：

```
core ← wireguard-config ← connect
     ← ssh ← provisioner
     ← storage / telemetry / tunnel-api
                              ↑
                             cli （聚合层，依赖除 telemetry/tunnel-api 外全部）
```

## 数据平面：三线程，不能合并

`native.rs` 用三个线程，这个划分是必要的而非风格选择：

```
[出站] TUN poll(500ms) → read → encapsulate → UDP send
[入站] UDP recv(500ms 超时) → decapsulate → TUN write
[计时] update_timers 每 250ms → 握手重传 / keepalive / 断线重连
```

- **出站与入站必须分线程**：合并后 `udp.recv()` 的读超时会阻塞出站方向，
  空闲链路上 TUN 每个超时周期才被读一次，吞吐塌到不可用。
- **出站用 `poll` 而不是直接 `read`**：`TunReader` 持有 TUN 的 fd，
  若线程阻塞在 `read()`，`shutdown()` 的 `join()` 会与之互等 ——
  空闲隧道上 Ctrl+C 死锁。先 `poll(500ms)` 再读打破这个环。
- 三个线程都以 500ms 量级轮询停止标志，`shutdown()` 最坏 500ms 返回。
- `Tunn` 经 `Arc<Mutex<..>>` 共享，锁只在加解密期间持有，I/O 一律在锁外。

## macOS utun 的三个硬约束

都踩过，改动 `tun.rs` 前必读：

1. **4 字节地址族头**：每个 IP 包前有 AF 头（`AF_INET`=2 / `AF_INET6`=30），
   读时剥离、写时附加。真实 IPv4 包首字节 `0x45`，作为 BE u32 不会与 2/30
   混淆，所以按值判断是安全的。
2. **写入必须单次 `write()`**：utun 是字符设备，每次 write 即一个数据包。
   分两次写 AF 头和包体 → 内核收到两个畸形包，全部丢弃。
3. **地址走 `Configuration` 传入，不要事后 `set_alias`**：
   `Device::new` 内部已调用一次 `set_alias`（缺省 10.0.0.1）。
   事后再调是**追加**第二个地址，留下多余的 10.0.0.1 和一条
   10.0.0.255 主机路由。另外 `set_alias` 第二参数对 POINTOPOINT
   接口是**对端地址**，不是广播地址 —— 传错会导致 ping 网关不通。

## 断线重连：不要重复 boringtun 的逻辑

boringtun 已实现 RFC 标准逻辑（见其 `src/noise/timers.rs`）：
静默 15s 触发握手 → 每 5s 重传 → 累计 90s 放弃并返回 `ConnectionExpired`。

**不要在此之上再叠自己的静默检测**，会打架并产生重复握手。
本项目只在 boringtun 放弃的那一点接手：

```
0s ─────15s──────────────────────105s──────────────→
   静默    boringtun 每5s重传      ConnectionExpired
                                  ↓  MiaoVPS 接手，无限复活
```

`Tunn` 可**原地复活**，无需重建实例：`format_handshake_initiation(force_resend=true)`
在 expired 状态下会 `timers.clear()`，内层无条件把 state 改写为 `InitSent`。

策略是无限重试、退避 5s→60s。短于 105s 的中断由 boringtun 自愈。

## 网络切换：两件事必须同时做，且有顺序

WiFi 换网段或 WiFi↔有线时，缺任何一半都无法恢复：

1. **UDP socket 源地址被内核钉死**。`connect()` 后 `local_addr()` 从
   `0.0.0.0:0` 变成具体 IP；换网段后该地址不存在，`send()` 永久失败
   （macOS errno 49）。必须重绑定 —— 用 `Endpoint` 封装
   `RwLock<Arc<UdpSocket>>`。服务端按公钥识别 peer 支持 endpoint 漫游，
   新源端口不会被拒（已实测）。
2. **VPS 直连路由钉死旧网关**。`VpsRouteGuard` 每 5s 核对并重建。

**顺序必须是「先修路由，再重绑定」** —— 路由不通时绑任何本地地址都发不出包。
CLI 修好路由后调 `NativeTunnel::notify_network_changed()`。

### 陷阱：重绑定绝不能放在数据路径

首版把重绑定放进 `Endpoint::send`，断网时 TUN 积压的每个包都触发一次 ——
**实测一秒 700 次重绑定 + 700 行日志**。现在：

- 数据路径的 `send` 不重绑定，只丢包计数（断网时丢出站包是正确的，
  恢复只依赖握手包，TCP 自己重传）
- 重绑定限流 2s，握手路径用 `send_with_rebind`
- 断网 1 分钟默认可见日志约 6 行

## Full Tunnel 断线回落（默认行为）

会话中断 30s → 撤下 `0/1`+`128/1` 并还原 DNS，隧道继续重连 →
恢复后自动重新接管。由 `FullTunnelOverlay` 管状态。

不回落的话，全局流量与 DNS 都进黑洞，macOS 判定「已连接但无互联网」——
用户看到的是 WiFi 连不上。回落期间会明确提示流量不经 VPN。

两个易埋雷处：**重新接管时必须重抓 DNS 备份**（回落期间可能换了网络，
旧备份会写回错误 DNS）；**`teardown` 必须区分接管/回落状态**
（回落时 DNS 已还原，再 restore 会写回过期备份）。

### 陷阱：keepalive 返回 `Done`，不是 `WriteToTunnel*`

`validate_decapsulated_packet` 对 `len == 0` 直接返回 `TunnResult::Done`。
回落期间隧道内**只有 keepalive、没有数据流量** —— 若用 `WriteToTunnel*`
判定存活，隧道恢复了也检测不到，永久停在直连状态，
**用户以为受保护实际在裸奔**。

恢复判定用 `Tunn::stats().0`（`time_since_last_handshake()` 返回 `Some`
即会话已建立），与流量无关。见 `TunnelStats::session_alive`。

## 必须维持的不变量

产品原则是"永不一键丢网"，以下约束不能破：

- **验证全部通过才动路由**。任一步失败立即返回，不碰路由表。
- **路由事务化**：`apply_routes` 逐条应用，任一条失败则逆序回滚。
  半套路由比没有路由更危险 —— 用户不知道该删哪几条才能恢复。
- **VPS 公网 IP 必须经原始网关直连**，否则加密包被路由回隧道形成死循环。
- **Full Tunnel 必须同时接管 DNS**。只切路由不改 DNS 时，本地网段的接口
  路由比 `0/1` 更具体，查询仍走 ISP —— IP 走 VPN 而域名明文外泄。
  原始配置落盘到 `dns-backup.json`，`kill -9` 后 `disconnect` 仍可还原。
- **客户端密钥必须稳定**。服务端只接受 peer 列表已注册的公钥，
  新生成的密钥握手包被**静默丢弃**（表现为"握手超时"，极难排查）。
  `connect` 启动时校验公钥由私钥推导得出，不自洽直接拒绝。
- 日志中密钥一律经 `short_key()` 截断。

## 权限与密钥存储

`connect` / `disconnect` 需要 root（创建 TUN、改路由）。权限检查放在流程
最前面，避免用户白等几秒验证才失败。

**密钥存文件而非 Keychain**：sudo 下访问的是 **root 的** Keychain，
读不到用户态写入的密钥。`~/.miaovps/profile.json`（0600）对两种身份都可见。
`data_dir()` 通过 `SUDO_USER` 反查真实用户 home，避免 root 写到 `/var/root`。

MTU 默认 1380，**必须与服务端 wg0 一致**，否则大包静默丢弃
（症状是"ping 通但传文件卡死"）。`TunInterface::create` 会校验 MTU 是否生效。

## 尚未接线的代码（不要误判为可用）

- `miaovps-tunnel-api` 的 `TunnelBackend` trait **无任何实现**，
  且 `miaovps-connect` 并不依赖它。为未来平台抽象预留。
- `connect/src/lib.rs` 的 `VpnConnection` 状态机**未被 CLI 使用**，
  CLI 直接调 `NativeTunnel`。为前端 IPC 预留。
- `miaovps-telemetry` crate **未被任何代码引用**。
- CLI 的 `inspect` / `deploy` / `status` / `export-config` 是占位实现，
  只打印提示，需接 SSH 才能真正工作。
- **IPv6 未处理**：Full Tunnel 只路由 IPv4，v6 流量会绕过隧道泄露真实 IP。
- 前端 0 行（计划 Tauri 2 + React）。

## 测量陷阱

在高 RTT 国际链路上测性能极易得出错误结论，本项目已踩过：

- **单次 iperf3 不可信**。同配置 9 次采样极差 5.6 倍
  （15.1 ~ 85.5 Mbps）。至少 6 次取中位数，并**同时记录重传数** ——
  零重传的低吞吐与高重传的低吞吐是完全不同的故障。
- **ICMP 丢包率不能推断链路质量**。云厂商常对公网 IP 的 ICMP 限速：
  直连 ping 曾显示 73% 丢包，而同时隧道内 ping 是 50/50 零丢包。
- **小文件测速无意义**，结果被 TCP 慢启动主导（5MB→5.2 Mbps，
  20MB→14.3 Mbps，同一链路）。
- **测断线重连必须制造 >105s 的中断**，短于此测的是 boringtun
  自身的重传，测不到本项目的重连代码。
- **测网络切换要真的切换网络**（关 WiFi >40s 再开 / 换网段）。
  `scripts/test-reconnect.sh` 只阻断 VPS 端口，源地址和网关都没变，
  测不到 socket 重绑定与网关看护这两条路径。

SSH 到测试 VPS 执行 sudo 命令时，`echo pw | sudo -S cmd <<EOF` 会把
**密码写进文件** —— `sudo -S` 与 heredoc 争抢 stdin。
正确做法：普通用户身份写临时文件，再 `sudo cp`。

## 项目记忆（pmem）

跨会话状态存在 `.pmem/`，工作流见 `AGENTS.md`。开始任务前读，结束时同步：

```bash
pmem recall --format compact --budget 2000
pmem ask "<主题>" --format compact
pmem sync -s "<改了什么>" -n "<下一步>"
```

- `.pmem/state.md` — 当前状态、真机验证结果、VPS 凭据
- `.pmem/next.md` — 待办与优先级
- `.pmem/decisions/` — 决策记录，含本文档提到的各项根因分析

Markdown 卡片是唯一真实来源，`.pmem/pmem.db` 是可重建索引，不要直接编辑。
新增 crate 时记得建对应的 module 卡片并写准 `source_files` ——
路径过宽（如 `crates/`）会导致所有 crate 的改动都误挂到同一张卡片。
