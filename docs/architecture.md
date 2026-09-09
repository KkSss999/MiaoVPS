# 核心架构

MiaoVPS 仓库维护 Rust 核心、CLI、协议、部署器、存储与隧道数据平面。

## 数据流

```text
miaovps CLI / compatible clients
        │
        ├─ 控制面：SSH（检测、部署、设备注册、状态读取）
        │
        └─ 数据面：WireGuard UDP
                 │
                 ▼
        VPS: wg0 + IP forwarding + NAT
```

控制面和数据面相互独立：SSH 只用于管理，VPN 流量不会通过 SSH 转发；WireGuard 私钥只在客户端侧生成和保存。

## Crate 分层

| Crate | 职责 |
| --- | --- |
| `miaovps-core` | VPS、设备、隧道等领域模型 |
| `miaovps-wireguard-config` | 密钥和 WireGuard 配置生成 |
| `miaovps-ssh` | SSH 认证与远程命令执行 |
| `miaovps-provisioner` | 环境检测、安装、配置、启动和回滚 |
| `miaovps-storage` | SQLite 本地数据与系统 Keychain |
| `miaovps-connect` | TUN、路由、DNS、握手验证和重连 |
| `miaovps-app` | CLI 与其他客户端可复用的应用服务边界 |
| `miaovps-cli` | 用户可执行的命令行入口 |
| `miaovps-tunnel-api` | 平台无关的隧道接口 |
| `miaovps-telemetry` | 预留的状态观测客户端 |

## 连接安全边界

连接前按 UDP 可达、WireGuard 握手、隧道创建、路由应用的顺序验证；验证失败时不切换全局路由。Full Tunnel 使用 `0.0.0.0/1` 和 `128.0.0.0/1`，并保留 VPS 直连路由，避免把握手回程错误地送进自身隧道。当前数据面只配置 IPv4，因此 Full Tunnel 同时安装 `2000::/3` 的 IPv6 reject 路由，明确禁止公网 IPv6 绕过隧道；该规则由 MiaoVPS 归属标记管理，在回落或退出时精确撤销。

## 构建边界

```bash
# 本仓库：核心和 CLI
cargo build
cargo test --workspace

```

所有 Cargo 产物统一位于本仓库 `target/`。
