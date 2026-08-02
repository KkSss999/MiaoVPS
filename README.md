# MiaoVPS

> 用自己的 VPS 建立私人网络。

MiaoVPS 是一个本地优先的 Rust 核心和 CLI：通过 SSH 把 VPS 配置为 WireGuard 节点，创建和管理设备 peer，并在本机建立 Split Tunnel 或 Full Tunnel。它不提供公共节点、账户系统或云端控制面。

桌面客户端是同级目录中的独立项目 `../MiaoVPS-Desktop`。本仓库只维护 CLI、协议核心、部署器、存储和隧道数据平面。

## 快速开始

### 安装 CLI

```bash
cargo install --path crates/miaovps-cli
miaovps --help
```

### 部署并连接一台 VPS

```bash
miaovps add-server "我的 VPS" 203.0.113.10 22 ubuntu --key ~/.ssh/id_ed25519
miaovps inspect <server-id>
miaovps deploy <server-id> --port 443
miaovps add-device <server-id> "我的 Mac" mac
sudo miaovps connect <server-id> --device <device-id> --full
```

连接成功后：

```bash
curl -s ifconfig.me       # Full Tunnel 下应返回 VPS 公网 IP
sudo miaovps disconnect   # 停止隧道并还原路由、DNS
```

若不需要全局流量，省略 `--full` 即可建立 Split Tunnel。完整参数和安全注意事项见 [CLI 指南](docs/CLI.md)。

## 文档

- [CLI 使用指南](docs/CLI.md) — 安装、命令、节点/设备和安全边界
- [VPS 部署指南](docs/deployment.md) — SSH、云防火墙、端口迁移和排障
- [核心架构](docs/architecture.md) — 控制面、数据面、crate 分层和构建边界

## 项目结构

```text
MiaoVPS/
├── crates/                 # Rust 核心与 CLI
├── scripts/                # 部署参考脚本和链路健康检查
├── docs/                   # 当前使用文档
├── .pmem/                  # 项目记忆 Markdown（SQLite 索引可重建）
└── target/                 # 本地构建产物，不提交
```

## 开发

```bash
cargo build
cargo test --workspace
cargo clippy --all-targets --all-features
```

桌面端开发请进入同级目录 `../MiaoVPS-Desktop`。核心仓库和桌面仓库分别提交、构建和发布。

## 设计原则

- **本地优先**：节点、设备和密钥由本地 SQLite/Keychain 管理。
- **私钥私有**：客户端私钥不上传 VPS；VPS 只保存 peer 公钥。
- **SSH 控制、WireGuard 传输**：部署管理与 VPN 数据流分离。
- **失败不切路由**：握手或关键验证失败时不接管系统流量。
- **可恢复**：断开时清理路由并还原 DNS，部署过程保留远端网络备份。

## License

MIT
