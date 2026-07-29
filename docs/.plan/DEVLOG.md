# MiaoVPS 开发日志 (DevLog)

> 从 2026-07-29 开始记录

---

## 2026-07-29 — 项目启动

### 完成事项
- [x] 分析用户提供的详细技术规划建议
- [x] 确定产品定位：私人 VPN 节点部署器 + 设备配置管理器
- [x] 技术栈决策：Tauri 2 + React + Rust + russh + SQLite
- [x] 分阶段策略：P0(验证) → P1(部署器) → P2(macOS隧道) → P3(产品化)
- [x] 初始化 Git 仓库
- [x] 初始化 pmem 项目记忆（25 卡片，24 关联边）
- [x] 生成完整项目文档
  - [x] `docs/项目思考.md`
  - [x] `docs/技术栈.md`
  - [x] `docs/PRD.md`
  - [x] `docs/.plan/ROADMAP.md`
  - [x] `docs/.plan/TASKS.md`（43 个任务）
  - [x] `docs/.plan/ARCHITECTURE.md`
  - [x] `docs/.plan/CHECKLIST.md`
  - [x] `docs/.plan/DEVLOG.md`

### 当前阶段
Phase 0 — 跑通 WireGuard 端到端连接 🔄

### 下一步
1. 获取 VPS 信息（公网 IP、OS、SSH 方式）
2. 手动 SSH 部署 WireGuard
3. 生成客户端配置
4. 用 macOS 官方 WireGuard 客户端连接验证

### 待解决问题
- VPS 信息待用户提供
- 需要确认 VPS 是否有 sudo 权限

### 重要决策
- 不使用 my-init 流程，改用 pmem 管理项目记忆
- React 作为前端框架（vs Vue/Solid）
- russh 作为 SSH 客户端（vs ssh2）
- P0 不写代码，只做手动验证

---

## 模板：每日记录格式

### 完成事项
- [x] ...
- [x] ...

### 当前阶段
Phase X — ... 🔄

### 下一步
1. ...

### 待解决问题
- ...

### 重要决策
- ...
