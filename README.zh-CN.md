# MiaoVPS

**把你已有的一台 VPS 变成自己的 AmneziaWG / WireGuard 私人网络。**

[English](README.md) · [CLI 指南](docs/CLI.md) · [部署指南](docs/deployment.md) · [核心架构](docs/architecture.md) · [安全策略](SECURITY.md)

MiaoVPS 是一个本地优先的 Rust 核心与 CLI。它通过 SSH 检查和配置远程
VPS，在本地管理节点与设备 Peer，并建立 Split Tunnel 或 Full Tunnel。
它不出售公共节点、不要求注册账户，也不依赖托管式云端控制面。

## 核心特点

- **基础设施归用户所有**：使用自己的 VPS，节点、Peer 和网络路径均由用户控制。
- **本地优先**：节点信息保存在本地 SQLite，认证信息与私钥使用系统凭据存储。
- **统一工作流**：通过一个 CLI 完成检查、部署、Peer 管理、验证、连接、状态查看和断开。
- **验证失败不切路由**：在接管流量前依次检查 UDP 与所选协议的认证握手。
- **网络状态可恢复**：Full Tunnel 保留 VPS 直连路由，断开或回落时恢复路由与 DNS。
- **IPv6 策略明确**：当前数据面仅承载 IPv4；Full Tunnel 会阻止公网 IPv6 绕过隧道。

## 工作原理

```text
                         SSH 控制面
┌──────────────┐  检查 / 部署 / Peer / 状态   ┌──────────────┐
│ MiaoVPS CLI  │ ────────────────────────────▶ │ 用户的 VPS   │
│ 本地数据库   │                                │ miao-awg/wg0 │
│ 系统凭据存储 │ ◀════ AMNEZIAWG/WG UDP ═════▶ │ NAT 与转发   │
└──────────────┘             数据面             └──────────────┘
```

SSH 只承担服务器管理，VPN 流量由所选的 AmneziaWG 或 WireGuard 传输。客户端私钥在本地生成并保存，VPS 只接收 Peer 公钥。两种协议使用各自的服务端监听端口和本地配置，切换时不会静默替换另一套配置。

## 快速开始

```bash
cargo install --locked --path crates/miaovps-cli

miaovps add-server "我的 VPS" 203.0.113.10 22 ubuntu --key ~/.ssh/id_ed25519
miaovps inspect <server-id>
# 先在云防火墙和 VPS 防火墙放行 UDP 52181；部署 AWG 并保存本机配置
miaovps deploy <server-id> --port 52181

# 仅 VPN 网段 / IPv4 全局
sudo miaovps connect
sudo miaovps connect --full

# 断开并恢复 MiaoVPS 创建的路由与 DNS 状态
sudo miaovps disconnect
```

部署和连接默认使用 AmneziaWG，不需要另装客户端；一次 AWG 部署只对应本机一个 Peer。原生 WireGuard 请显式使用 `deploy --wg`、`add-device --wg`、`connect --wg` 等命令，可注册多台设备。切换前先断开当前隧道；另一协议的监听和配置保留。首次检测或部署前，先通过可信渠道核对 VPS 的 SSH 指纹，再将对应密钥加入 `~/.ssh/known_hosts`；MiaoVPS 会拒绝未知或已变更的主机密钥。

完整参数与安全边界请阅读 [CLI 指南](docs/CLI.md) 和
[部署指南](docs/deployment.md)。

## 开发

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets --all-features
```

MiaoVPS 当前处于 **pre-1.0** 阶段。Rust workspace 与 macOS、Linux 客户端隧道
链路是当前实际验证路径；其他平台必须完成 TUN、路由、DNS、权限和恢复行为的
端到端验证后，才能宣称正式支持。

首次使用请选择非关键 VPS，并保留云厂商控制台访问能力。不要在 Issue、日志
或提交中公开真实节点地址、密码、私钥、导出的 WireGuard 配置或本地数据目录。

## License

[MIT](LICENSE) © 2026 Wentao Ge
