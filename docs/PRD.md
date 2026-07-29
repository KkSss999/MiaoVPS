# MiaoVPS PRD

> 版本：v0.1.0 | 2026-07-29 | Phase 0

---

## Problem Statement

想自建 VPN 的人通常卡在几个环节：不会在 Linux 上配置 WireGuard、不知道密钥怎么生成和分发、每加一台设备都要手动编辑配置文件、连不上也不知道哪里出了问题。现有的 VPN 客户端要么绑定商业服务，要么只管连接不管部署。

用户真正需要的是一个**从购买 VPS 到所有设备连上 VPN，中间每一步都有人帮他搞定的工具**。

## Solution

MiaoVPS —— 私人 VPN 节点部署器 + 设备配置管理器。

桌面端通过 SSH 直连 VPS，一键完成 WireGuard 的安装、配置和防火墙设置。用户在界面上添加设备，桌面端自动生成密钥、分配 IP、导出配置。全程私钥不离开客户端，不需要注册任何账户。

---

## User Stories

### P0 — 端到端验证

1. 作为用户，我希望跟着文档手动完成一次 VPS 部署和客户端连接，验证整个链路可行。
2. 作为用户，我希望用 macOS 官方 WireGuard 客户端连接自己的 VPS，确认握手成功。
3. 作为用户，我希望确认连接后公网出口 IP 变成 VPS 的 IP。

### P1 — 桌面端部署器

4. 作为用户，我希望输入 VPS 的 IP、SSH 端口、用户名和私钥，将服务器添加到管理列表。
5. 作为用户，我希望点击一个按钮，桌面端自动 SSH 到 VPS 完成 WireGuard 的全部安装和配置。
6. 作为用户，我希望在初始化过程中看到实时进度回显，知道每一步在做什么。
7. 作为用户，我希望为 VPN 添加新设备，客户端本地生成密钥，只把公钥传到服务器。
8. 作为用户，我希望一键导出设备的 WireGuard 配置文件 (.conf)。
9. 作为用户，我希望看到配置文件的二维码，方便手机扫描导入。
10. 作为用户，我希望点击按钮直接在系统 WireGuard 客户端中打开配置。
11. 作为用户，我希望查看服务器是否在线、WireGuard 服务是否运行。
12. 作为用户，我希望看到每台设备的最近握手时间和流量统计。
13. 作为用户，我希望查看当前 VPN 连接的公网出口 IP 和延迟。
14. 作为用户，我希望启用/禁用某台设备，或将其从 VPN 中移除。
15. 作为用户，我希望从管理列表中删除一台不再使用的 VPS。

### P2 — macOS 一键连接

16. 作为 macOS 用户，我希望在 MiaoVPS 里一键连接 VPN，不需要打开官方客户端。
17. 作为 macOS 用户，我希望 VPN 连接状态实时同步到桌面端界面。
18. 作为 macOS 用户，我希望断开 VPN 后流量恢复正常网络出口。

### P3 — 产品化

19. 作为用户，我希望管理多台 VPS 节点，在不同地区切换。
20. 作为用户，我希望自动选择延迟最低的节点连接。
21. 作为用户，我希望节点故障时自动切换到备用节点。
22. 作为用户，我希望 VPN 断开时自动阻断所有流量（Kill Switch）。
23. 作为用户，我希望指定哪些流量走 VPN、哪些走本地（Split Tunnel）。
24. 作为用户，我希望设定流量额度并收到告警。
25. 作为用户，我希望系统启动后自动连接 VPN。
26. 作为用户，我希望断线后自动重连。

---

## Implementation Decisions

### 架构决策

1. **Tauri 2 + React** — 轻量桌面框架，Rust 核心处理系统级操作
2. **russh 纯 Rust SSH** — 无 C 依赖，交叉编译简单
3. **分阶段交付** — P0 先验证链路，P1 出可用产品，P2 做隧道集成
4. **不自己写 WireGuard 协议** — 使用官方实现，安全可靠

### 核心模块设计

#### M1 — vpn-core（领域模型）
- **职责**：VpnServer、VpnDevice、TunnelStatus 等核心数据结构
- **技术**：Rust + serde
- **接口**：纯数据结构 + 基础方法

#### M2 — wg-config（配置生成）
- **职责**：WireGuard 密钥对生成、服务端/客户端配置生成
- **技术**：x25519-dalek、base64
- **接口**：`generate_keypair()`, `generate_server_config()`, `generate_client_config()`

#### M3 — server-provisioner（服务器部署）
- **职责**：SSH 连接、OS 检测、WireGuard 安装、Peer 管理
- **技术**：russh + tokio
- **接口**：`ServerProvisioner` trait（inspect/install/add_peer/remove_peer/status）

#### M4 — storage（本地存储）
- **职责**：SQLite 数据持久化 + Keychain 密钥管理
- **技术**：sqlx + keyring-rs
- **接口**：CRUD for servers/devices/configs/tunnels

#### M5 — security（安全模块）
- **职责**：密钥生成、加密存储、内存安全释放
- **技术**：ring、zeroize、keyring-rs
- **原则**：私钥不出客户端

#### M6 — desktop-ui（桌面界面）
- **职责**：服务器管理、设备配置、状态监控的 UI
- **技术**：React + Tailwind CSS + shadcn/ui + Zustand
- **Tauri Commands**：add_server, init_server, add_device, export_config, get_status

#### M7 — platform-tunnel（平台隧道·P2）
- **职责**：跨平台 VPN 隧道抽象
- **技术**：平台原生 FFI 绑定
- **接口**：`TunnelBackend` trait（install/connect/disconnect/status）

### 状态管理

- **Zustand store**: `serverStore`、`deviceStore`、`configStore`、`statusStore`
- **持久化**：关键状态同步 SQLite，UI 状态存内存

### 性能优化

1. SSH 连接复用，避免重复握手
2. 状态监控增量刷新（仅更新变化字段）
3. SQLite WAL 模式提升并发读

### 数据流

```
用户操作 → React UI → Zustand Action
                         ↓
                   Tauri invoke()
                         ↓
                   Rust Command
                         ↓
              ┌──────────┼──────────┐
              ↓          ↓          ↓
        provisioner   storage   wg-config
        (SSH→VPS)    (SQLite)  (生成配置)
```

---

## Testing Decisions

### 测试原则

- Rust crate 单元测试覆盖率 > 80%
- 核心模块（provisioner、security）必须有测试
- UI 组件用手动测试 + 未来补充 Playwright E2E

### 测试策略

| 模块 | 测试类型 | 工具 |
|------|----------|------|
| vpn-core | 单元测试 | `cargo test` |
| wg-config | 单元测试 + 配置解析测试 | `cargo test` |
| server-provisioner | 集成测试（需测试 VPS） | `cargo test` + Docker |
| storage | 单元测试 (SQLite in-memory) | `cargo test` |
| security | 单元测试 | `cargo test` |
| desktop-ui | 手动测试 + 未来 E2E | Playwright |

---

## Out of Scope

1. **用户账户系统** — 本地优先，不需要注册登录
2. **云同步** — 配置导出即可，不做自动跨设备同步
3. **订阅/付费** — 免费开源工具
4. **iOS/Android 客户端** — 首版只做桌面端，移动端用户用官方 WireGuard
5. **WireGuard 协议自实现** — 使用官方实现
6. **代理/翻墙功能** — 定位是私人 VPN，不是代理工具
7. **多用户管理** — 单用户场景

---

## Further Notes

### 项目开发阶段

| 阶段 | 内容 | 优先级 | 状态 |
|------|------|--------|------|
| Phase 0 | 手动跑通 WireGuard 端到端连接 | P0 | 🔄 进行中 |
| Phase 1 | 桌面端部署器（服务器+设备管理+导出） | P1 | ⬜ 待启动 |
| Phase 2 | macOS 一键连接（系统隧道集成） | P2 | ⬜ 待启动 |
| Phase 3 | 产品化（多节点/Kill Switch/Split Tunnel） | P3 | ⬜ 待启动 |

### 关键技术风险

| 风险 | 等级 | 应对 |
|------|------|------|
| macOS Network Extension 权限 | 高 | P1 不依赖，P2 提前申请 Developer 账号 |
| SSH 私钥安全 | 严重 | Keychain 存储 + zeroize + 审计 |
| 跨平台 SSH 兼容性 | 中 | 多发行版测试 + 容错脚本 |
| Tauri 打包分发 | 中 | 研究最佳实践，先 dev 模式开发 |

### 后期扩展方向

- 手机端管理 App（先用官方 WireGuard 客户端过渡）
- 可选局域网穿透 (Tailscale-like mesh)
- 配置分享（一键帮朋友部署）
- Docker 容器化部署
