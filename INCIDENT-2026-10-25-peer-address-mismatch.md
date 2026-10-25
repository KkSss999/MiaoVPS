# 事故记录：peer 地址表为空导致「连上但没有下载流量」

- **状态**：服务端临时改动已执行；端到端结果 **未核验**
- **日期**：2026-10-25
- **影响**：单台客户端设备（macOS，MiaoVPS CLI userspace 隧道）无法收发任何隧道数据
- **标识脱敏**：本文不含真实 IP、公钥与 endpoint，公钥仅保留前 6 位

## 一句话结论

服务端 peer 的 `AllowedIPs` 为空，客户端 profile 认领的地址又归在另一把公钥名下。握手只需要 endpoint + 公钥，不查地址表，所以 `connect` 一路「验证通过」，数据面却双向静默丢弃。

## 症状

客户端视角：

- `miaovps connect` 的握手校验通过，会话建立
- `wg show` 里自身 peer 有 `latest handshake`，有 `endpoint`，但 `transfer` 只有握手量级（数百字节）
- 下载流量恒为 0；`curl` 超时；`ping 10.66.66.1` 不通

服务端视角（`sudo wg show`）：

```
peer: <本机公钥 oRqZHj…>
  endpoint: <客户端 NAT 出口>:38977
  allowed ips: (none)          <-- 关键
  latest handshake: 51 seconds ago
  transfer: 784 B received, 592 B sent
```

## 现场数据

改动前，服务端 5 个 peer 的地址分配：

| 地址 | 公钥前缀 | 备注 |
| --- | --- | --- |
| `10.66.66.2/32` | `/PCwd8…` | 无握手 |
| `10.66.66.3/32` | `NAljkj…` | 无握手；与故障机同一 NAT 出口，疑似废弃设备 |
| `10.66.66.4/32` | `4B+lIC…` | |
| `10.66.66.8/32` | `zug6q2…` | 无 endpoint |
| **(none)** | `oRqZHj…` | 故障本机 |

故障本机 profile：`client_ip = 10.66.66.3`，与服务端 `NAljkj…` 的 `10.66.66.3/32` **撞车**。

## 根因

三个独立缺陷叠加，任何一个单独存在都不至于变成「看起来连上了却完全没流量」。

### 1. 地址分配只看本地 DB，看不到远端运行态

`crates/miaovps-app/src/service.rs:399` `allocate_vpn_address(vpn_cidr, devices)` 只拿本地 SQLite 的设备列表算「已用地址」。远端已注册但本地 DB 没有的 peer（`NAljkj…` 这类历史设备、或由别的路径注册的 peer）完全不可见。

`service.rs:213-216` 的注释声称该函数已经防住了地址冲突，实际上只防了「删掉中间设备后 `len()` 回退」，没防 DB 与远端运行态不一致。

### 2. `wg set` 之后不校验地址归属

`crates/miaovps-provisioner/src/provisioner.rs:813` `add_peer` 执行：

```
wg set wg0 peer <公钥> allowed-ips <地址>/32
```

WireGuard 的语义是「地址只能属于一个 peer」——给新 peer 设置一个已被占用的地址，会**把该地址从旧 peer 上移走**，旧 peer 随即变成 `(none)`，而命令仍然成功。`add_peer` 没有回读校验，调用方无条件打印「✓ 设备已创建并注册为服务端 peer」。

同一函数 `provisioner.rs:818` 的持久化是盲追加 `\n[Peer]\nPublicKey = …\nAllowedIPs = …`，同一公钥重复调用会写出重复 `[Peer]` 段，之后 `wg syncconf` 的行为不可预期。`crates/miaovps-control/src/main.rs:457` 的 `enroll_device` 有同样问题。

### 3. 连接前校验只做握手

`crates/miaovps-connect/src/validator.rs:47` `validate_all` 实际只有两步：UDP 出站可达、WireGuard 握手（文件头部注释写的 4 步已经与代码不一致）。握手响应直接发往 UDP 来源 endpoint，不查地址表，因此**地址表为空也能握手成功**。

结果：`AllowedIPs` 为空、地址错配这两种情况，永远在 `connect` 阶段显示「验证链路 ✅」，故障一路推到用户可见的数据面。

### 数据其实早就有，只是被丢掉了

`crates/miaovps-app/src/service.rs:355` `parse_wg_dump` 解析 `wg show wg0 dump` 时，每行 8 列只取了公钥、握手、rx、tx，**第 4 列 allowed-ips 直接丢弃**。判断「这个 peer 到底持有哪个地址」所需的信息已经通过 SSH 拿到了，只是没有解析、没有存、没有比较。

## 手动绕过（本次实际执行）

服务端：

```bash
sudo wg set wg0 peer <本机公钥> allowed-ips 10.66.66.5/32
sudo wg show wg0 allowed-ips          # 确认 .5 已归属本机公钥
```

客户端：

```bash
sudo sed -i '' 's/"10\.66\.66\.3"/"10.66.66.5"/' ~/.miaovps/profile.json
sudo miaovps connect --full --dev    # 不带 <server> --device，否则会用 DB 地址重写 profile
```

**尚未完成 / 未核验：**

- `AllowedIPs = 10.66.66.5/32` 尚未写回 `/etc/wireguard/wg0.conf`。只做 `wg set` 不落盘，下次 `wg syncconf` 或重启会退回 `(none)`。
- 端到端结果未核验：需要 `curl -s ifconfig.me` 返回 VPS 公网 IP，且 `~/.miaovps/tunnel-dev.log` 的 5 秒快照里 `rx` 持续增长。
- 废弃 peer `NAljkj…`（`10.66.66.3/32`）未清理。

注意：`miaovps connect <server> --device <id>` 会调用 `__prepare-profile` 用数据库设备记录重写 `profile.json`（`crates/miaovps-cli/src/main.rs:609`）。手改 profile 后必须用不带参数的 `connect`。

## 计划中的软件修复

按顺序做，每步可单独验证。

### 1. 分配地址时并入远端运行态

`allocate_vpn_address` 增加 `reserved` 参数，`add_device` 先取一次 `wg show wg0 dump`，把远端 peer 的 allowed-ips 并入「已用」集合。

远端读取失败时的策略待定（见下）。

### 2. 注册后回读校验

`add_peer` 之后立即 `wg show wg0 allowed-ips`，确认该公钥确实持有该 `/32`；不持有则报错并标记设备未注册。同时把持久化改成按 PublicKey 幂等改写，替换盲追加。

### 3. `connect` 前置地址自检

连之前用 SSH 拉一次 dump，检查「profile 的公钥是否持有 profile 的 client_ip」，不匹配就在**切换路由之前**失败，并直接打印可执行的修复命令。这是性价比最高的一步，因为它把故障挡在用户能自查的位置。

### 4. `miaovps doctor <server-id> [--fix]`

DB × 远端三方对账，输出四类发现：

| 发现 | 含义 | 建议处置 |
| --- | --- | --- |
| `missing_peer` | DB 有、远端无 | 可自动重新注册 |
| `orphan_peer` | 远端有、DB 无 | 只报告 |
| `address_mismatch` | 同公钥两边地址不同 | 按 DB 改远端（可自动） |
| `address_conflict` | 两把不同公钥抢同一地址 | 只报告 |

### 自动修复的边界（建议）

可以自动：**幂等写操作的重放**（补注册、按 DB 改地址、去重 conf 段）。

不自动：**删除任何 peer、决定哪把钥匙让位**。这两件事不可逆，且可能断掉别的设备，必须由人决定。

## 待决定

1. 远端 dump 读取失败时，`add-device` 是硬失败，还是降级为「分配后不校验」？
2. `connect` 地址自检失败是硬阻断，还是 warning 继续？`--skip-validate` 与断网开机自动重连是否豁免？
3. `orphan_peer` 只报告，还是允许 `--fix` 自动 `wg peer remove`？

## 自查清单（同类问题）

```bash
# 服务端：谁持有哪个地址
sudo wg show wg0 allowed-ips
sudo wg show wg0 | grep -A2 '<公钥前缀>'

# 客户端：profile 认领哪个地址
sudo miaovps profile show

# 判定标准只有一条：以上两处地址一致，且 transfer 双向增长
curl -s ifconfig.me
tail -f ~/.miaovps/tunnel-dev.log
```

`[1/4] 验证链路 ✅` 不能作为数据面可用的证据。
