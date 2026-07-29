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
│  │  · 连接/断开  │  │  │   └─ Native    三线程隧道  │ │
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
v0.1.0 后端 ✅  macOS 隧道 ✅  前端 ⬜
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ miaovps-core             领域模型
✅ miaovps-wireguard-config 密钥·配置·二维码
✅ miaovps-tunnel-api       平台隧道抽象
✅ miaovps-ssh              russh SSH
✅ miaovps-provisioner      环境检测·部署·回滚
✅ miaovps-telemetry        WSS 客户端
✅ miaovps-storage          SQLite + Keychain
✅ miaovps-connect          三线程数据平面·验证器·断线重连
✅ miaovps-cli              14 命令 (含 profile/connect --full)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   ~4900 行 · 45 tests · 0 warnings
```

### 真机验证状态 (VPS 新加坡, RTT 275ms)

| 能力 | 状态 |
|------|------|
| WireGuard 握手 | ✅ 194ms |
| Split Tunnel | ✅ ping 50/50 零丢包 |
| Full Tunnel | ✅ 出口 IP = VPS |
| DNS 接管 / 还原 | ✅ 无泄露，退出正确还原 |
| MTU 1380 生效 | ✅ 1352B 通过 / 1400B+DF 失败 |
| 吞吐 | ✅ UDP 176 Mbps · TCP 稳态 ~79 Mbps |
| **断线自动重连** | ⬜ **代码完成，待真机验证** |

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
│   └── miaovps-cli/               命令行工具 (14 命令)
├── native/macos/                  macOS Network Extension (待)
├── scripts/
│   ├── bootstrap-server.sh        手动部署脚本
│   └── test-reconnect.sh          断线重连验证
└── docs/                          项目文档
```

## 快速开始

### 手动部署

```bash
# 1. 上传并执行部署脚本
scp scripts/bootstrap-server.sh ubuntu@<VPS_IP>:/tmp/
ssh ubuntu@<VPS_IP> "sudo bash /tmp/bootstrap-server.sh"
```

### 连接

客户端密钥必须**稳定** — WireGuard 服务端只接受 peer 列表里已注册的公钥，
每次连接换新密钥会被静默丢弃（表现为握手超时）。

```bash
# 1. 生成客户端密钥对（只做一次）
miaovps generate-keypair

# 2. 在 VPS 上注册公钥
ssh <VPS> "sudo wg set wg0 peer <客户端公钥> allowed-ips 10.66.66.2/32"

# 3. 保存连接配置到 ~/.miaovps/profile.json (0600)
miaovps profile init <VPS_IP>:51820 <客户端私钥> <服务器公钥> 10.66.66.2 10.66.66.1

# 4. 验证链路（不切路由，安全）
miaovps validate <VPS_IP>:51820 <客户端私钥> <服务器公钥>

# 5. 连接 — Split Tunnel 只路由 VPN 网段，Full Tunnel 接管全局流量 + DNS
sudo miaovps connect          # Split Tunnel
sudo miaovps connect --full   # Full Tunnel

# 6. 清理残留路由 / DNS（异常退出后使用）
sudo miaovps disconnect
```

验证连通性：Split Tunnel 下 `ping 10.66.66.1`；Full Tunnel 下
`curl ifconfig.me` 应返回 VPS 的公网 IP。

### 断线重连

隧道运行期间每 30 秒输出一行状态。断线后自动重连，无限重试、不改动路由 ——
链路恢复即自动可用，与 WireGuard 本身语义一致。

时序分工（这决定了怎么测才有意义）：

| 阶段 | 耗时 | 负责方 |
|------|------|--------|
| 对端静默 → 触发新握手 | 15s | boringtun |
| 握手重传（每 5s） | 90s | boringtun |
| → `ConnectionExpired` | 累计 ~105s | — |
| 强制复活 + 无限重试（退避 5s→60s） | 之后 | MiaoVPS |

短于 105s 的中断由 boringtun 自行恢复；超过则由 MiaoVPS 接手。
验证脚本（需先启动隧道，建议用 Split Tunnel 以免影响正常上网）：

```bash
bash scripts/test-reconnect.sh    # 在 VPS 侧阻断 UDP 51820 共 130s
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
| `profile init` | **保存连接配置（稳定密钥）** |
| `profile show` | **查看配置 + 公私钥自洽校验** |
| `connect [--full]` | **建立隧道，需 sudo** |
| `disconnect` | **清理路由 + 还原 DNS** |

## 产品原则

- **安全连接** — 分步验证，失败不切路由；路由分步应用，任一步失败即回滚
- **断线自愈** — 无限重试重连，退避 5s→60s，全程不改动路由
- **本地优先** — 所有数据存本地 SQLite + Keychain
- **密钥私有** — 私钥永不离开客户端
- **不泄露 DNS** — Full Tunnel 接管 DNS 并在退出时还原（含崩溃后恢复）
- **纯 Rust** — boringtun WireGuard 协议栈，零外部依赖

## License

MIT
