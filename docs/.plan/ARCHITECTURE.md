# MiaoVPS 架构设计文档

> 最后更新：2026-07-29

## 项目结构

```
MiaoVPS/
├── apps/
│   └── desktop/                    # Tauri 桌面应用
│       ├── src/                    # React 前端
│       │   ├── components/         # UI 组件
│       │   │   ├── ServerList/     # 服务器列表
│       │   │   ├── DeviceList/     # 设备列表
│       │   │   ├── StatusPanel/    # 状态面板
│       │   │   ├── ConfigExport/   # 配置导出
│       │   │   └── Layout/         # 布局组件
│       │   ├── stores/             # Zustand stores
│       │   │   ├── serverStore.ts
│       │   │   ├── deviceStore.ts
│       │   │   └── statusStore.ts
│       │   ├── hooks/              # 自定义 hooks
│       │   ├── lib/                # 工具函数
│       │   ├── App.tsx
│       │   └── main.tsx
│       ├── src-tauri/              # Tauri Rust 后端
│       │   ├── src/
│       │   │   ├── commands/       # Tauri commands
│       │   │   │   ├── mod.rs
│       │   │   │   ├── server.rs   # add_server, init_server, ...
│       │   │   │   ├── device.rs   # add_device, remove_device, ...
│       │   │   │   └── config.rs   # export_config, ...
│       │   │   ├── provisioning/   # 服务器部署逻辑
│       │   │   ├── tunnel/         # 隧道管理 (P2)
│       │   │   ├── storage/        # 本地存储封装
│       │   │   ├── security/       # 安全模块
│       │   │   ├── lib.rs
│       │   │   └── main.rs
│       │   ├── Cargo.toml
│       │   └── tauri.conf.json
│       ├── package.json
│       ├── tsconfig.json
│       └── vite.config.ts
│
├── crates/                         # 独立 Rust crates
│   ├── vpn-core/                   # 核心领域模型
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── server.rs           # VpnServer
│   │   │   ├── device.rs           # VpnDevice
│   │   │   └── tunnel.rs           # TunnelStatus
│   │   └── Cargo.toml
│   ├── wg-config/                  # WireGuard 配置生成
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── keygen.rs           # 密钥生成
│   │   │   ├── server_config.rs    # 服务端配置
│   │   │   ├── client_config.rs    # 客户端配置
│   │   │   └── qr.rs               # 二维码
│   │   └── Cargo.toml
│   ├── server-provisioner/         # SSH 服务器部署
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── ssh.rs              # SSH 连接管理
│   │   │   ├── detect.rs           # OS 检测
│   │   │   ├── install.rs          # WireGuard 安装
│   │   │   ├── config.rs           # 服务端配置
│   │   │   ├── firewall.rs         # 防火墙配置
│   │   │   └── status.rs           # 状态查询
│   │   └── Cargo.toml
│   └── platform-tunnel/            # 平台隧道抽象 (P2)
│       ├── src/
│       │   ├── lib.rs              # TunnelBackend trait
│       │   ├── macos.rs            # MacTunnelBackend
│       │   ├── windows.rs          # WindowsTunnelBackend
│       │   └── linux.rs            # LinuxTunnelBackend
│       └── Cargo.toml
│
├── scripts/
│   └── bootstrap-server.sh         # 手动部署参考脚本
│
├── docs/                           # 项目文档
│   ├── 项目思考.md
│   ├── 技术栈.md
│   ├── PRD.md
│   └── .plan/
│       ├── ROADMAP.md
│       ├── TASKS.md
│       ├── ARCHITECTURE.md
│       ├── CHECKLIST.md
│       └── DEVLOG.md
│
├── .pmem/                          # pmem 项目记忆
│   ├── modules/
│   ├── decisions/
│   ├── features/
│   ├── tasks/
│   └── risks/
│
└── AGENTS.md                       # Agent 入口指令
```

## 模块依赖关系

```
                    ┌─────────────┐
                    │  desktop-ui  │
                    │  (React)     │
                    └──────┬──────┘
                           │ Tauri IPC
                    ┌──────▼──────┐
                    │ Tauri Rust  │
                    │  commands   │
                    └──┬──┬──┬──┬─┘
                       │  │  │  │
            ┌──────────┘  │  │  └──────────┐
            ▼             ▼  ▼             ▼
   ┌────────────┐  ┌────────────┐  ┌────────────┐
   │provisioner │  │  storage   │  │  security  │
   │  (russh)   │  │  (sqlx)    │  │ (keyring)  │
   └──────┬─────┘  └────────────┘  └────────────┘
          │
    ┌─────▼─────┐
    │  wg-config │
    │  (x25519) │
    └─────┬─────┘
          │
    ┌─────▼─────┐
    │  vpn-core  │
    │  (models)  │
    └───────────┘
```

依赖方向自上而下：
- `vpn-core` 无依赖（纯数据结构）
- `wg-config` 依赖 `vpn-core`
- `server-provisioner` 依赖 `vpn-core`、`wg-config`
- `storage`、`security` 独立模块
- Tauri commands 编排以上所有模块
- React UI 通过 Tauri IPC 调用 commands

## 数据流

### 服务器初始化流程
```
用户点击"初始化"
  → React: initServer(serverId)
  → Tauri invoke("init_server", { serverId })
  → Rust command: 从 storage 读取 server 信息
  → server-provisioner: SSH 连接 → 检测 OS → 安装 wg → 配置 → 启动
  → 进度通过 Tauri event 回传前端
  → 完成后更新 storage
```

### 添加设备流程
```
用户点击"添加设备"
  → React: addDevice(serverId, deviceName)
  → Tauri invoke("add_device", { serverId, deviceName })
  → Rust command:
      1. wg-config: 本地生成密钥对
      2. security: 私钥存入 Keychain
      3. server-provisioner: 公钥传给服务器 (add_peer)
      4. storage: 保存设备记录
  → 返回设备信息给前端
```

### 状态监控流程
```
定时器触发 (每 5 秒)
  → React: refreshStatus(serverId)
  → Tauri invoke("get_status", { serverId })
  → Rust command:
      1. server-provisioner: SSH 执行 wg show
      2. 解析握手时间、流量等
      3. 返回 TunnelStatus
  → 前端更新状态面板
```

## 安全边界

```
┌────────────── 客户端 ──────────────┐    ┌──── 服务器 ────┐
│                                    │    │                 │
│  Keychain                          │    │  /etc/wireguard │
│  ├─ SSH 私钥 (加密存储)            │    │  ├─ private.key  │
│  └─ WG 私钥  (加密存储)            │    │  └─ wg0.conf     │
│                                    │    │                 │
│  SQLite                            │    │  wg show        │
│  ├─ 服务器信息 (不存私钥)          │    │  ├─ public keys  │
│  └─ 设备列表 (不存私钥)            │    │  └─ rx/tx bytes  │
│                                    │    │                 │
│  传输层                            │    │                 │
│  └─ SSH 加密隧道 ──────────────────┼────→ 仅传输公钥      │
│                                    │    │  和配置信息      │
└────────────────────────────────────┘    └─────────────────┘
```

**硬性规则**：
1. 私钥永不离开客户端 Keychain
2. 只通过 SSH 传输公钥和配置
3. 服务器不存储任何客户端私钥
