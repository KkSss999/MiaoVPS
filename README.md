# MiaoVPS

> 买一台 VPS，建立自己的私人网络。
> Turn your VPS into a private network in minutes.

[![Rust](https://img.shields.io/badge/Rust-1.95%2B-orange)](https://www.rust-lang.org)
[![WireGuard](https://img.shields.io/badge/WireGuard-%F0%9F%94%92-blue)](https://www.wireguard.com)

**本地优先的桌面端私人 VPN 客户端**。将 VPS 一键转换为 WireGuard 节点，系统级 TUN 接管全局流量，无需注册任何账户。

---

## 架构

```
┌─────────────────────────────────────────┐
│           MiaoVPS Desktop               │
│                                         │
│  React UI (Tauri 2)                     │
│      │                                  │
│  Rust Core                              │
│  ├─ Provisioner    SSH 部署和管理        │
│  ├─ Tunnel Ctrl    本地 VPN 隧道         │
│  └─ Telemetry      实时 VPS 状态         │
└──────┬──────────────┬───────────────────┘
       │ WireGuard    │ WSS / SSH
       │ 数据平面      │ 控制与观测平面
       ▼              ▼
┌─────────────────────────────────────────┐
│                VPS                      │
│  wg0 / NAT / Forward / Agent            │
└─────────────────────────────────────────┘
```

## 开发进度

```
v0.1.0 后端 ✅  v0.1.0 前端 ⬜
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ miaovps-core           322行  领域模型
✅ miaovps-wireguard-config 363行 密钥·配置·二维码
✅ miaovps-tunnel-api      191行  平台隧道抽象
✅ miaovps-ssh             139行  russh SSH
✅ miaovps-provisioner     715行  环境检测·部署·回滚
✅ miaovps-telemetry       202行  WSS 客户端
✅ miaovps-storage         627行  SQLite + Keychain
✅ miaovps-cli             258行  命令行工具
✅ 端到端验证               VPS WireGuard 部署成功
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   总计: 2950 行 · 16 tests · 0 warnings
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
│   └── miaovps-cli/               命令行工具
├── native/macos/                  macOS Network Extension (待)
├── agent/miaovps-agent/           VPS Agent (待)
├── scripts/
│   └── bootstrap-server.sh        手动部署脚本
└── docs/                          项目文档
```

## 快速开始

### 手动部署（5 分钟）

```bash
# 1. 上传脚本
scp scripts/bootstrap-server.sh ubuntu@<VPS_IP>:/tmp/

# 2. 执行部署
ssh ubuntu@<VPS_IP>
sudo bash /tmp/bootstrap-server.sh

# 3. 本地生成密钥 + 添加 Peer + 导出配置
miaovps generate-keypair
miaovps add-device <server-id> MacBook
miaovps export-config <device-id>
```

### 开发

```bash
cargo build              # 编译全部 crate
cargo test               # 16 测试
cargo run -p miaovps-cli -- help  # CLI 帮助
```

## 产品原则

- **本地优先** — 所有数据存本地 SQLite + Keychain
- **无 Agent** — SSH 直连部署，不装长期服务（Agent 可选）
- **密钥私有** — 私钥永不离开客户端
- **官方 WireGuard** — 不重写协议，使用 WireGuardKit

## License

MIT
