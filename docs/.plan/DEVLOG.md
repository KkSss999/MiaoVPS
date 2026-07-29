# MiaoVPS 开发日志 (DevLog)

> 从 2026-07-29 开始记录

---

## 2026-07-29（第三次更新）— 第二轮架构完善

### 完成事项
- [x] 产品定位升级：从"部署器"到"完整 VPN 客户端"
- [x] 确立三条通道架构：数据平面(WireGuard) + 控制平面(SSH) + 观测平面(WSS/SSH)
- [x] 新增 3 个模块卡片：tunnel-api、telemetry、agent
- [x] 大幅更新 platform-tunnel（macOS Network Extension 完整方案）
- [x] 更新 desktop-ui（新首页设计 + 连接状态机）
- [x] 新增 4 个决策卡片：three-channel-arch、agent-design、websocket-protocol、version-plan
- [x] 版本规划统一：v0.1.0 一次性完整开发，不再分 Sprint/Phase
- [x] 开发顺序确定：后端优先（6 个 Phase, 22 任务）→ 前端后做（4 个 Phase, 20 任务）
- [x] 卡片总数：41 张

### 当前阶段
v0.1.0 后端开发 Phase 1 — 基础 crates 🔄

### 下一步
B1-1: 搭建 Cargo workspace + crates 目录结构
B1-2: `miaovps-core` 领域模型实现

---

## 2026-07-29（第二次更新）— PRD 沉淀

### 完成事项
- [x] 基于正式 PRD 更新全部 pmem 记忆卡片
- [x] Sprint 0-4 替代 P0-P3

---

## 2026-07-29（第一次）— 项目启动

### 完成事项
- [x] 分析用户提供的详细技术规划建议
- [x] 确定产品定位
- [x] 技术栈决策
- [x] 初始化 Git + pmem 项目记忆

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
