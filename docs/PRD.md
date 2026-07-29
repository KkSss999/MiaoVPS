# MiaoVPS 产品需求文档 PRD

**文档版本：** v0.1  
**产品阶段：** v0.1.0 一次性完整开发  
**技术基线：** Tauri 2 + Rust + React/TypeScript  
**首发平台：** macOS  
**核心协议：** WireGuard  
**产品定位：** 将 VPS 一键转换为私人 VPN 节点，实现系统级全局 VPN 连接

---

## 1. 产品定义

MiaoVPS 是本地优先的桌面端私人 VPN 客户端。

用户只需要提供 VPS 的公网 IP、SSH 用户名和凭据，MiaoVPS 自动完成：
```
添加 VPS → SSH 部署 WireGuard → 创建设备 → 启动本地 VPN 隧道 → 
系统 TUN 接管流量 → 从 VPS 出口访问网络 → 实时监控节点状态
```

### 产品边界

MiaoVPS 是**系统级全局 VPN**，不是 HTTP/SOCKS 代理。用户不需要给浏览器、终端等应用分别配置代理地址。

MiaoVPS 不是：通用 VPS 面板、云服务器销售平台、公共 VPN 节点服务、自研 VPN 协议。

---

## 2. 核心架构：三条通道

```
┌─────────────────────────────────────────────────┐
│                  MiaoVPS Desktop                │
│                                                 │
│  React UI                                       │
│      │                                          │
│  Tauri 2 / Rust Core                            │
│      ├── Provisioner：SSH 部署和管理服务器       │
│      ├── Tunnel Controller：启动本地 VPN         │
│      └── Telemetry Client：实时读取 VPS 状态     │
└──────┬─────────────────┬────────────────────────┘
       │                 │
       │ WireGuard UDP   │ WSS / SSH
       │ 数据平面         │ 控制与观测平面
       ▼                 ▼
┌─────────────────────────────────────────────────┐
│                      VPS                        │
│  wg0 / WireGuard Server + NAT / Forward         │
│  MiaoVPS Agent（可选轻量服务）                   │
└─────────────────────────────────────────────────┘
```

### 数据平面 — WireGuard UDP
```
本机应用 → 系统路由 → TUN/utun → WireGuard加密 → UDP 51820 → VPS wg0 → NAT → 公网
```

### 控制平面 — SSH
首次部署、Peer 管理、配置修改、密钥轮换、故障修复、高风险操作。

### 观测平面 — WSS（VPN已连接）/ SSH（VPN未连接）
实时 CPU/内存/带宽、Peer 状态、延迟丢包、异常检测。Agent 只监听 VPN 私网地址 `10.66.66.1:7443`，不暴露公网。

---

## 3. 本地 VPN 连接流程

用户点击"连接私人网络"后：
```
1. 从系统 Keychain 读取本机 WireGuard 私钥
2. 从本地数据库读取节点配置
3. 创建或加载系统 VPN 配置
4. 请求操作系统启动 Packet Tunnel
5. 系统创建 TUN/utun 虚拟网络接口
6. 写入虚拟 IP、DNS 和路由
7. WireGuard 向 VPS 发起握手
8. 握手成功
9. 验证公网出口 IP
10. UI 切换为"已连接"
```

### macOS 实现
```
Tauri React UI → Rust TunnelController → Swift Tunnel Manager 
→ NETunnelProviderManager → NEPacketTunnelProvider → WireGuardKit → utun
```

### 客户端配置核心
```ini
[Interface]
PrivateKey = <本机私钥>
Address = 10.66.66.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <VPS 公钥>
Endpoint = <VPS 公网 IP>:51820
AllowedIPs = 0.0.0.0/0, ::/0    # 全局 VPN
PersistentKeepalive = 25
```

---

## 4. 首页设计

```
┌──────────────────────────────────────────┐
│  MiaoVPS                                 │
│  你的私人网络                             │
│             ● 已连接                     │
│          Singapore VPS · 43 ms           │
│          [ 断开连接 ]                    │
├──────────────────────────────────────────┤
│ 当前出口: 203.0.113.18 · Singapore       │
│ 实时速率: ↓ 3.8 MB/s  ↑ 420 KB/s        │
│ 节点: CPU 4%  内存 21%  磁盘 15%         │
│ 本次连接: 1.2 GB · 01:42:18             │
└──────────────────────────────────────────┘
```

连接状态机：未连接→正在准备→正在请求系统权限→正在建立隧道→正在握手→正在验证出口→已连接。失败时必须具体说明原因（非泛化"连接失败"）。

---

## 5. 开发计划

**v0.1.0 一次性完整开发，后端优先，前端后做。**

| 阶段 | 内容 | 任务数 | 状态 |
|------|------|:--:|:--:|
| Phase 1-6 | 后端：Rust crates + native + Agent + 集成验证 | 22 | 🔄 |
| Phase 7-10 | 前端：React UI + 对接 + 打包发布 | 20 | ⬜ |

### 后端优先顺序
1. 基础 crates（vpn-core, wg-config）
2. SSH + 部署（ssh, provisioner）
3. 隧道抽象 + macOS 实现（tunnel-api, Network Extension）
4. Agent + 遥测（agent, telemetry）
5. 存储 + 安全（SQLite, Keychain, 日志脱敏, 错误模型）
6. 集成验证（单元测试 + 测试 VPS 验证）

---

## 6. 产品原则

- **本地优先**：数据存本机，无中心账户
- **无服务器 Agent**（默认）：SSH 完成部署，Agent 可选
- **密钥归用户所有**：私钥不出客户端，不上传
- **不重写 WireGuard**：使用官方实现
- **系统级 VPN**：TUN 接管全局流量，非代理模式

---

*完整技术细节、领域模型、安全约束、WebSocket 协议等详见 `.pmem/` 下的模块卡片和决策记录。*
