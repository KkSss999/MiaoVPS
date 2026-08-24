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

## 多台物理设备连接同一节点

同一个 WireGuard 接口只有一个服务端监听端口。一个 MiaoVPS 节点上的所有设备
应连接相同的 VPS 目标端口，由各自的客户端公钥和 VPN 地址区分身份：

```text
设备 A：随机本地 UDP 端口 -> VPS:443  (独立公钥，10.66.66.2/32)
设备 B：随机本地 UDP 端口 -> VPS:443  (独立公钥，10.66.66.3/32)
```

为每台物理设备分别创建 peer，不要把同一份设备配置复制给多台设备：

```bash
miaovps add-device <server-id> "MacBook" mac
miaovps add-device <server-id> "iPhone" iphone
miaovps list-devices <server-id>
miaovps export-config <device-id>
```

两台设备如果复用同一个客户端私钥、公钥或 VPN 地址，WireGuard 会把它们视为
同一个 peer，并把远端 endpoint 在两台设备之间反复切换，表现为一台连通时另一台
断流。设备使用不同的本地源端口是正常现象，无需手工配置。

端口参数的作用范围：

- `connect --port <port>` 只临时覆盖客户端要连接的 VPS 目标端口，不会让 VPS
  新增监听端口，也不是每设备端口。
- `deploy --port <port>` 会迁移整个节点的 `wg0` 监听端口，影响该节点的所有设备。
  迁移后，其他物理设备上的旧配置也必须更新为新端口。
- 当前版本不支持同一 `wg0` 同时为不同设备提供多个公网目标端口。如果某台设备
  所在网络只能使用另一个 UDP 端口，应先统一迁移节点端口；不要让两台设备分别
  指向不同端口。

可在不停止隧道的情况下检查服务端端口和 peer：

```bash
sudo wg show wg0 listen-port
sudo wg show wg0 peers
sudo wg show wg0 endpoints
sudo wg show wg0 allowed-ips
```

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
