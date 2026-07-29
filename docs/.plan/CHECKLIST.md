# MiaoVPS 阶段验收清单

## Phase 0: 端到端验证 ✅/❌

### T0-1 准备 VPS
- [ ] 已购买/准备一台轻量 VPS
- [ ] 记录：公网 IP、操作系统版本、SSH 端口
- [ ] 确认 root 或 sudo 权限

### T0-2 安装 WireGuard
- [ ] wireguard-tools 安装成功
- [ ] `wg --version` 正常输出

### T0-3 服务端配置
- [ ] 生成服务端私钥和公钥
- [ ] wg0.conf 配置正确（私钥、监听端口、CIDR）
- [ ] 文件权限 600

### T0-4 网络配置
- [ ] IP Forward 已开启 (`sysctl net.ipv4.ip_forward=1`)
- [ ] iptables/nftables NAT 规则生效
- [ ] 防火墙允许 WireGuard 端口
- [ ] 持久化配置（重启后生效）

### T0-5 启动服务
- [ ] `wg-quick up wg0` 成功
- [ ] `wg show` 显示接口 wg0
- [ ] `systemctl enable wg-quick@wg0` 开机自启

### T0-6 客户端配置
- [ ] 生成客户端密钥对
- [ ] client.conf 配置正确
- [ ] 服务器 Peer 段已添加客户端公钥

### T0-7 客户端连接
- [ ] macOS 官方 WireGuard 客户端安装
- [ ] 导入 client.conf 成功
- [ ] 激活隧道

### T0-8 连接验证
- [ ] `wg show` 显示握手时间（非 0）
- [ ] 客户端可以 ping 通服务端 VPN IP
- [ ] 客户端公网出口 IP 变为 VPS IP（`curl ifconfig.me`）
- [ ] DNS 解析正常

### T0-9 文档
- [ ] 完整部署步骤已记录
- [ ] 遇到的问题和解决方法已记录
- [ ] 脚本化候选步骤已标注

---

## Phase 1: 桌面端部署器 ✅/❌

### 项目骨架
- [ ] `cargo create-tauri-app` 成功
- [ ] React + TypeScript + Vite 运行正常
- [ ] `tauri dev` 启动无报错

### vpn-core crate
- [ ] VpnServer / VpnDevice / TunnelStatus 结构定义
- [ ] serde 序列化/反序列化
- [ ] 单元测试通过

### wg-config crate
- [ ] 密钥对生成函数
- [ ] 服务端配置生成
- [ ] 客户端配置生成
- [ ] 配置解析（反向解析为结构化数据）
- [ ] 二维码生成
- [ ] 单元测试通过

### server-provisioner crate
- [ ] SSH 连接（密钥认证）
- [ ] OS 检测（Ubuntu/Debian/CentOS）
- [ ] WireGuard 安装脚本
- [ ] wg0.conf 写入
- [ ] IP Forward + NAT 配置
- [ ] 防火墙配置
- [ ] 服务启动与自启
- [ ] 状态查询（wg show 解析）
- [ ] Peer 添加/删除
- [ ] 错误处理与诊断信息

### storage 模块
- [ ] SQLite 数据库初始化
- [ ] servers 表 CRUD
- [ ] devices 表 CRUD
- [ ] configs 表
- [ ] Keychain 读写（SSH 私钥）

### security 模块
- [ ] 私钥 Keychain 存储/读取
- [ ] zeroize 安全释放
- [ ] 密钥不记录到日志

### UI — 添加服务器
- [ ] 表单：IP、端口、用户名、私钥文件
- [ ] 文件选择器导入私钥
- [ ] SSH 连接测试
- [ ] 服务器列表展示

### UI — 一键初始化
- [ ] 初始化按钮 + 确认弹窗
- [ ] 实时进度回显
- [ ] 错误诊断展示
- [ ] 初始化完成状态

### UI — 设备管理
- [ ] 设备列表展示
- [ ] 添加设备弹窗
- [ ] 设备启用/禁用
- [ ] 设备删除确认

### UI — 配置导出
- [ ] .conf 文件下载
- [ ] 二维码弹窗
- [ ] "在 WireGuard 中打开"按钮
- [ ] 安全提示（含私钥时）

### UI — 状态监控
- [ ] 服务器在线/离线指示
- [ ] 握手时间、流量显示
- [ ] 公网出口 IP
- [ ] 延迟显示
- [ ] 定时自动刷新

### 集成验收
- [ ] 完整流程：添加→初始化→加设备→导出→连接
- [ ] 错误场景：SSH 不通、安装失败、权限不足
- [ ] 多服务器切换
- [ ] 异常断线恢复

---

## Phase 2: macOS 一键连接 ✅/❌

- [ ] WireGuardKit 集成到 Xcode project
- [ ] Swift Tunnel Helper 编译成功
- [ ] Tauri ↔ Swift IPC 通信正常
- [ ] Apple Developer 账号已申请
- [ ] Network Extension entitlement 配置
- [ ] Provisioning Profile 配置
- [ ] 应用签名流程走通
- [ ] 一键连接功能
- [ ] 一键断开功能
- [ ] 连接状态实时同步
- [ ] 系统授权弹窗引导
- [ ] 后台运行正常
- [ ] 端到端测试通过

---

## Phase 3: 产品化 ✅/❌

- [ ] 多节点添加/切换
- [ ] 延迟测速
- [ ] 最优节点自动选择
- [ ] 节点健康检测
- [ ] 故障自动切换
- [ ] Kill Switch
- [ ] Split Tunnel 配置
- [ ] 开机自动连接
- [ ] 断线自动重连
- [ ] 流量用量告警
- [ ] 密钥轮换
- [ ] 设备吊销
- [ ] Windows 打包
- [ ] Linux 打包
- [ ] 配置备份/恢复
