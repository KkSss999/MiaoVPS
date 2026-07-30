# MiaoVPS

> 买一台 VPS，建立自己的私人网络。
> Turn your VPS into a private network in minutes.

[![Rust](https://img.shields.io/badge/Rust-1.95%2B-orange)](https://www.rust-lang.org)
[![WireGuard](https://img.shields.io/badge/WireGuard-%F0%9F%94%92-blue)](https://www.wireguard.com)

**本地优先的桌面端私人 VPN 客户端**。将 VPS 一键转换为 WireGuard 节点，系统级 TUN 接管全局流量，无需注册任何账户。

---

## 架构

控制平面与数据平面完全分离，不共享运行时状态：

```
┌──────────────────────────────────────────────────────────┐
│  MiaoVPS.app (普通用户权限)                                │
│                                                          │
│  ┌────────────────┐    ┌──────────────────────────────┐  │
│  │  React 18 + TS │IPC │  miaovps-app  应用服务层      │  │
│  │  Tauri 2       │───▶│  （CLI 与前端共用，行为一致） │  │
│  │                │    │    ├─ Provisioner  SSH 部署   │  │
│  │  首页 / 节点   │    │    ├─ Storage  SQLite+Keychain│  │
│  │  设备 / 设置   │    │    └─ TunnelCtl  隧道控制     │  │
│  └────────────────┘    └───────────┬──────────────────┘  │
└────────────────────────────────────┼─────────────────────┘
                        osascript 提权 │ tunnel-state.json
                                     ▼
┌──────────────────────────────────────────────────────────┐
│  miaovps connect --daemon (root)                         │
│    miaovps-connect: utun + boringtun 三线程数据平面        │
└────────────────────────┬─────────────────────────────────┘
                         │ WireGuard 协议
                         ▼
┌──────────────────────────────────────────────────────────┐
│                        VPS                               │
│              wg0 / NAT / IP Forward                      │
└──────────────────────────────────────────────────────────┘
```

**隧道进程为什么独立**：创建 utun 和改路由需要 root，但整个 App 跑在 root 下会让
Keychain 和数据目录都变成 root 的（sudo 下访问的是 root 的 Keychain，读不到
用户态写入的密钥）。所以 App 保持普通用户权限，连接时经 macOS 原生授权框
拉起独立隧道进程，状态经 `tunnel-state.json` 交换。

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
v0.1.0 后端 ✅  macOS 隧道 ✅  桌面前端 ✅
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ miaovps-core             领域模型
✅ miaovps-wireguard-config 密钥·配置·二维码
✅ miaovps-tunnel-api       平台隧道抽象（预留，无实现）
✅ miaovps-ssh              russh SSH（密码 + 私钥认证）
✅ miaovps-provisioner      环境检测·9 步部署·回滚
✅ miaovps-telemetry        WSS 客户端（预留，未接线）
✅ miaovps-storage          SQLite + Keychain
✅ miaovps-connect          三线程数据平面·验证器·断线重连·网络漫游
✅ miaovps-app              应用服务层（CLI 与前端的共同边界）
✅ miaovps-cli              14 命令（含 profile / connect --full --daemon）
✅ apps/desktop             Tauri 2 + React 18 + TS（4 路由·18 command）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   137 tests · clippy 0 warnings
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
| 长时间稳定性 | ✅ 连续 85 分钟 / 130 MB 无中断 |
| 断线重连 | ✅ 阻断 >105s 后自动恢复 |
| 网络切换 | ✅ 换网段后重绑定 + 网关重建 |
| **前端一键连接全流程** | ⬜ **待真机验证（需交互输入授权密码）** |

当前版本已经完成代码级测试和构建验证；上表中仍标记为 ⬜ 的项目，需要在真实 macOS 桌面会话中输入系统授权密码后验证。前端验证顺序为：添加节点 → 环境检测 → 部署 → 添加设备 → 设为本机设备 → 首页连接 / 断开。终端启动的前台隧道也会被前端识别为“已连接（终端启动）”，避免重复创建隧道。

## 项目结构

```
MiaoVPS/
├── crates/
│   ├── miaovps-core/              领域模型
│   ├── miaovps-wireguard-config/  WireGuard 配置生成
│   ├── miaovps-tunnel-api/        隧道抽象接口（预留）
│   ├── miaovps-ssh/               SSH 连接 (russh)
│   ├── miaovps-provisioner/       9 步部署·环境检测·回滚
│   ├── miaovps-telemetry/         实时遥测 WSS（预留）
│   ├── miaovps-storage/           SQLite + Keychain
│   ├── miaovps-connect/           数据平面 (boringtun + 分步验证)
│   ├── miaovps-app/               应用服务层（IPC 边界）
│   └── miaovps-cli/               命令行工具
├── apps/
│   └── desktop/                   Tauri 2 + React 18 桌面应用
│       ├── src/                   前端源码
│       └── src-tauri/             Rust 后端（Tauri commands）
├── miaovps-frontend/              HTML 设计原型（视觉基线，只读）
├── scripts/
│   ├── bootstrap-server.sh        手动部署脚本（VPS 侧）
│   └── test-reconnect.sh          断线重连验证
└── pubilc/                        品牌素材
```

## 快速开始

### 桌面应用（推荐）

```bash
# 安装依赖
cargo install --path crates/miaovps-cli   # 隧道进程依赖

cd apps/desktop
pnpm install
pnpm tauri dev    # 开发模式
pnpm tauri build  # 打包 .app
```

App 内流程：**节点页添加 VPS** → **检测** → **部署** →
**设备页添加本机设备** → **设为本机连接** → **首页一键连接**。

连接时弹 macOS 系统授权框（隧道进程需要 root）。授权后
`tunnel-state.json` 存放隧道状态，App 每 2s 轮询显示实时信息。

### 命令行（高级 / 调试）

```bash
# 全局安装 CLI
cargo install --path crates/miaovps-cli

# 服务器管理
miaovps add-server "我的 VPS" 203.0.113.10 22 ubuntu \
  --key ~/.ssh/id_ed25519
miaovps inspect  <server-id前缀>   # 11 项环境检测
miaovps deploy   <server-id前缀>   # 一键部署 WireGuard（9 步）
miaovps add-device <server-id前缀> "我的 Mac" mac

# 连接管理
miaovps profile init <VPS_IP>:51820 <客户端私钥> <服务器公钥> 10.66.66.2 10.66.66.1
miaovps validate <VPS_IP>:51820 <客户端私钥> <服务器公钥>  # 分步验证，不切路由

sudo miaovps connect          # Split Tunnel
sudo miaovps connect --full   # Full Tunnel（全局流量 + DNS 接管）
sudo miaovps connect --full --daemon  # 后台模式（App 使用此模式）
sudo miaovps disconnect       # 清理路由 + 还原 DNS
```

验证连通性：Split Tunnel 下 `ping 10.66.66.1`；
Full Tunnel 下 `curl ifconfig.me` 应返回 VPS 公网 IP。

### 断线重连与网络切换

隧道每 5s 刷一次状态文件，App 每 2s 轮询并显示；CLI 前台模式每 30s 输出一行：

```text
正常 · 运行 4989s · ↑87.7MiB ↓129.4MiB · 最后入站 0s 前 · 重连 25 次 · 换钥丢包 468
```

「换钥丢包」是 WireGuard 每 120s rekey 的正常会话轮换现象。旧会话在途数据包到达时可能产生 `WrongIndex` 等错误，这些会计入 `session_churn`，只在 debug 日志中记录，不代表密钥不匹配或遭到攻击。真正异常的是可疑的 AEAD/密钥/计数器校验失败，计入 `decrypt_errors` 并以 warning 记录。

断线后无限重试，链路恢复即自动可用。Full Tunnel 断线 30s 后自动回落直连并
明确提示，隧道继续重连，恢复后重新接管全局流量 + DNS。

| 阶段 | 耗时 | 负责方 |
|------|------|--------|
| 对端静默 → 触发新握手 | 15s | boringtun |
| 握手重传（每 5s） | 90s | boringtun |
| → `ConnectionExpired`，隧道进入 Expired 终态 | 累计 ~105s | — |
| 强制复活 + 无限重试（退避 5s→60s） | 之后 | MiaoVPS |

短于 105s 的中断由 boringtun 自行恢复；超过则由 MiaoVPS 接手。

```bash
# 验证断线重连（需先启动隧道，建议 Split Tunnel）
bash scripts/test-reconnect.sh    # 在 VPS 侧阻断 UDP 51820 共 130s
```

### 开发

```bash
# 编译所有 crate + CLI
cargo build

# 全量测试（137 tests）
cargo test --workspace

# Lint
cargo clippy --all-targets --all-features

# 前端
cd apps/desktop
pnpm typecheck   # 类型检查
pnpm build       # 生产构建
pnpm tauri dev   # 开发模式（热重载）
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
- **断线自愈** — 无限重试重连；网络切换自动重绑定 socket 与修正路由
- **断网不失联** — Full Tunnel 断线 30s 自动回落直连，恢复后重新接管
- **本地优先** — 所有数据存本地 SQLite + Keychain
- **密钥私有** — 私钥永不离开客户端
- **不泄露 DNS** — Full Tunnel 接管 DNS 并在退出时还原（含崩溃后恢复）
- **纯 Rust** — boringtun WireGuard 协议栈，零外部依赖

## License

MIT
