# MiaoVPS CLI

`miaovps` 是 MiaoVPS 的命令行入口，负责本地节点记录、SSH 部署、设备密钥管理和 WireGuard 隧道连接。

## 安装

```bash
cargo install --path crates/miaovps-cli
miaovps --help
```

升级已安装版本时重复执行 `cargo install` 即可。构建产物位于仓库根目录的 `target/`，不会写入仓库源文件。

## 常用流程

```bash
# 1. 添加 VPS。认证二选一：--key 或 --password
miaovps add-server "我的 VPS" 203.0.113.10 22 ubuntu --key ~/.ssh/id_ed25519

# 2. 检查系统、权限、网络和 WireGuard 条件
miaovps inspect <server-id>

# 3. 部署 WireGuard；如果 UDP 51820 受限，可迁移到其他端口
miaovps deploy <server-id> --port 443

# 4. 为本机或其他设备创建 peer
miaovps add-device <server-id> "我的 Mac" mac

# 5. 按节点和设备连接；不写节点时使用当前 profile
sudo miaovps connect <server-id> --device <device-id> --full

# 6. 断开并还原路由、DNS
sudo miaovps disconnect
```

`<server-id>` 和 `<device-id>` 支持完整 UUID 或唯一前缀。`--full` 会将 IPv4 默认流量和 DNS 交给 VPS；省略它则只建立 VPN 网段路由。当前版本不提供 IPv6 隧道，Full Tunnel 会明确阻止公网 IPv6（`2000::/3`），避免 IPv6 经本地网络绕过 VPN；断开或断线回落后只撤销 MiaoVPS 自己创建的拦截路由。

## 命令索引

| 命令 | 用途 |
| --- | --- |
| `add-server` / `remove-server` | 添加或删除本地 VPS 记录 |
| `list-servers` | 列出节点 |
| `inspect` | 部署前环境检测 |
| `deploy` | 通过 SSH 安装并配置 WireGuard |
| `add-device` / `list-devices` | 管理 peer 和设备 |
| `status` | 查询远端 WireGuard 状态 |
| `export-config` | 导出设备 `.conf` |
| `generate-keypair` | 生成 WireGuard 密钥对 |
| `validate` | 只验证 UDP/WireGuard，不切换路由 |
| `profile init` / `profile show` | 创建或检查默认连接 profile |
| `connect` / `disconnect` | 建立或停止本机隧道 |

完整参数以 `miaovps --help` 和各子命令帮助为准。

## 安全提醒

- 私钥保存在本机 Keychain；不要把终端输出、`.conf` 或密码提交到 Git。
- `connect` 和 `disconnect` 需要 root 权限，因为它们要创建 TUN、修改路由和 DNS。
- `inspect` 是只读检查；部署前应确认目标机器不是承载关键业务的生产机。
- `deploy --port` 修改的是 VPS WireGuard 监听端口，也必须同步放行云防火墙的 UDP 端口。
