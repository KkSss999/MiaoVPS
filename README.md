# MiaoVPS

> 买一台 VPS，建立自己的私人网络。
> Turn your VPS into a private network in minutes.

[![Rust](https://img.shields.io/badge/Rust-1.95%2B-orange)](https://www.rust-lang.org)
[![WireGuard](https://img.shields.io/badge/WireGuard-%F0%9F%94%92-blue)](https://www.wireguard.com)

**本地优先的桌面端私人 VPN 客户端**。将 VPS 一键转换为 WireGuard 节点，系统级 TUN 接管全局流量，无需注册任何账户。

---

## 架构

```
┌─────────────────────────────────────────────────────┐
│                 MiaoVPS Desktop                     │
│                                                     │
│  ┌──────────────┐  ┌──────────────────────────────┐ │
│  │  React UI    │  │  Rust Core (9 crates)        │ │
│  │  (Tauri 2)   │  │                              │ │
│  │              │  │  ├─ Provisioner  SSH 部署     │ │
│  │  · 服务器列表 │  │  ├─ Connect      连接管理     │ │
│  │  · 一键部署   │  │  │   ├─ Validator 分步验证   │ │
│  │  · 连接/断开  │  │  │   └─ Tunnel    boringtun  │ │
│  │  · 实时状态   │  │  ├─ Telemetry    实时遥测    │ │
│  │              │  │  └─ Storage      SQLite+密钥  │ │
│  └──────────────┘  └──────────────────────────────┘ │
└──────────────────┬──────────────────────────────────┘
                   │ WireGuard 协议 (boringtun)
                   ▼
┌─────────────────────────────────────────────────────┐
│                      VPS                            │
│        wg0 / NAT / IP Forward                       │
└─────────────────────────────────────────────────────┘
```

### 连接流程（不会丢网的设计）

```
点击连接
  ↓
UDP 可达测试 ──❌──→ 提示：检查安全组/防火墙，未切路由
  ↓ ✅
WG 握手测试  ──❌──→ 提示：密钥不匹配/服务未启动
  ↓ ✅
NAT 路由检查 ──❌──→ 提示：iptables MASQUERADE 未配置
  ↓ ✅
出口 IP 验证 ──❌──→ 提示：IP Forward 未开启
  ↓ ✅
Split Tunnel (仅路由 VPS 流量，本地网络不受影响)
  ↓ 验证通过
Full Tunnel (全局流量走 VPN)
```

---

## 开发进度

```
v0.1.0 后端 ✅  v0.1.0 macOS 隧道 ⬜  v0.1.0 前端 ⬜
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ miaovps-core            322行  领域模型
✅ miaovps-wireguard-config 363行 密钥·配置·二维码
✅ miaovps-tunnel-api       191行 平台隧道抽象
✅ miaovps-ssh              139行 russh SSH
✅ miaovps-provisioner      715行 环境检测·部署·回滚
✅ miaovps-telemetry        202行 WSS 客户端
✅ miaovps-storage          627行 SQLite + Keychain
✅ miaovps-connect          634行 状态机·验证器·boringtun 隧道
✅ miaovps-cli              439行 12 命令 (含 validate/connect/disconnect)
✅ 端到端验证                VPS WG 握手 575ms ✅
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   总计: 3999 行 · 21 tests · 0 warnings
```

## 项目结构

```
MiaoVPS/
├── crates/
│   ├── miaovps-core/              领域模型
│   ├── miaovps-wireguard-config/  WireGuard 配置生成
│   ├── miaovps-tunnel-api/        隧道抽象接口
│   ├── miaovps-ssh/               SSH 连接 (russh)
│   ├── miaovps-provisioner/       服务器部署
│   ├── miaovps-telemetry/         实时遥测 (WSS)
│   ├── miaovps-storage/           SQLite + Keychain
│   ├── miaovps-connect/           连接管理 (boringtun + 分步验证)
│   └── miaovps-cli/               命令行工具 (12 命令)
├── native/macos/                  macOS Network Extension (待)
├── scripts/
│   └── bootstrap-server.sh        手动部署脚本
└── docs/                          项目文档
```

## 快速开始

### 手动部署

```bash
# 1. 上传脚本
scp scripts/bootstrap-server.sh ubuntu@<VPS_IP>:/tmp/

# 2. 执行部署
ssh ubuntu@<VPS_IP>
sudo bash /tmp/bootstrap-server.sh

# 3. 验证链路（不切路由，安全）
miaovps validate <VPS_IP>:51820 <客户端私钥> <服务器公钥>

# 4. 连接
miaovps connect <server-id>

# 5. 断开
miaovps disconnect
```

### 开发

```bash
cargo build              # 编译全部 9 crate + 1 binary
cargo test               # 21 tests
cargo run -p miaovps-cli -- help  # CLI 帮助
```

## CLI 命令

| 命令 | 功能 |
|------|------|
| `add-server` | 添加 VPS 到本地数据库 |
| `list-servers` | 列出所有服务器 |
| `inspect` | 环境检测 |
| `deploy` | 一键部署 WireGuard |
| `add-device` | 添加 VPN 设备 + 生成密钥 |
| `list-devices` | 列出设备 |
| `status` | 查看服务状态 |
| `export-config` | 导出 WireGuard 配置 |
| `generate-keypair` | 生成 x25519 密钥对 |
| `validate` | **分步验证（不切路由，安全）** |
| `connect` | **建立 VPN 连接（Split Tunnel）** |
| `disconnect` | **断开连接** |

## 产品原则

- **安全连接** — 分步验证，失败不切路由，永不一键丢网
- **本地优先** — 所有数据存本地 SQLite + Keychain
- **密钥私有** — 私钥永不离开客户端
- **纯 Rust** — boringtun WireGuard 协议栈，零外部依赖

## License

MIT
