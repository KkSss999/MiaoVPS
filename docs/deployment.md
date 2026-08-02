# VPS 部署指南

MiaoVPS 通过 SSH 在目标 VPS 上完成一次性 WireGuard 部署，不需要在 VPS 上长期运行 MiaoVPS Agent。

## 前置条件

目标机器需要满足：

- Ubuntu/Debian 等受支持的 Linux 系统；
- 可通过 SSH 登录；用户拥有 root 权限，或能无交互执行 sudo；
- 有公网 IPv4（或明确可用的公网 IPv6 路径）；
- 云厂商安全组放行 WireGuard 使用的 UDP 端口；
- 开启 IP 转发、NAT 和 systemd 的权限。

## 部署步骤

```bash
miaovps add-server "我的 VPS" <公网IP> 22 ubuntu --key ~/.ssh/VPS.pem
miaovps inspect <server-id>
miaovps deploy <server-id> --port 443
miaovps add-device <server-id> "我的 Mac" mac
sudo miaovps connect <server-id> --device <device-id> --full
```

密码认证可以把 `--key` 换成 `--password '密码'`。密码会写入本地凭据存储；不要把它放进脚本或提交记录。

## 云防火墙

至少放行：

| 协议 | 端口 | 方向 | 用途 |
| --- | ---: | --- | --- |
| UDP | 与 `deploy --port` 相同 | 入站 | WireGuard 数据和握手 |
| TCP | 22 | 入站 | SSH 部署与诊断 |

ICMP 不是 WireGuard 必需项。若要使用 `ping 10.66.66.1` 作为诊断指标，再按云厂商控制台说明放行 ICMP；ICMP 被禁时不代表隧道不可用。

## 迁移端口

如果 UDP 51820 在本地网络或运营商路径上不可用：

```bash
miaovps deploy <server-id> --port 443
sudo miaovps connect <server-id> --device <device-id> --full
```

迁移后必须确认云防火墙和 VPS 内部防火墙都放行新的 UDP 端口。端口 443 上运行的是 WireGuard UDP，并不是 HTTPS；它仍可能受 UDP 策略影响。

## 验证与排障

```bash
miaovps inspect <server-id>
sudo miaovps connect <server-id> --device <device-id> --full
curl -s ifconfig.me
```

Full Tunnel 成功时出口 IP 应为 VPS 公网 IP。握手超时优先检查：端口协议是否为 UDP、云防火墙、VPS 防火墙、服务端 peer 公钥和客户端节点/设备是否匹配。

连接建立后可运行只读健康检查：

```bash
bash scripts/test-tunnel-health.sh --vps <公网IP>
```

## 回滚

停止本机隧道：

```bash
sudo miaovps disconnect
```

部署过程会在 VPS 上备份相关网络配置；如果远端部署失败，应先保留 CLI 输出和 `inspect` 结果，再通过 SSH 按备份恢复，避免直接覆盖生产网络配置。
