# MiaoVPS 任务跟踪清单 (Tasks Tracker)

> v0.1.0 一次性开发 · 后端优先 · 前端后做
> 状态：⬜ 待启动 | 🔄 进行中 | ✅ 已完成

---

## Phase 1: 基础 crates

| 编号 | 任务 | 状态 |
|------|------|:--:|
| B1-1 | 搭建 Cargo workspace + crates 目录结构 | ⬜ |
| B1-2 | `miaovps-core` — 领域模型 | ⬜ |
| B1-3 | `miaovps-wireguard-config` — 密钥+配置+二维码 | ⬜ |

## Phase 2: SSH 与部署

| 编号 | 任务 | 状态 |
|------|------|:--:|
| B2-1 | `miaovps-ssh` — SSH 连接管理 + Host Key 验证 | ⬜ |
| B2-2 | `miaovps-provisioner` — 环境检测 + 部署状态机 + 幂等/备份/回滚 | ⬜ |

## Phase 3: 隧道抽象 + macOS 实现

| 编号 | 任务 | 状态 |
|------|------|:--:|
| B3-1 | `miaovps-tunnel-api` — TunnelBackend trait + 模型 | ⬜ |
| B3-2 | `native/macos/TunnelManager` — Swift NETunnelProviderManager | ⬜ |
| B3-3 | `native/macos/PacketTunnelExtension` — WireGuardKit 集成 | ⬜ |
| B3-4 | Rust ↔ Swift FFI 桥接 | ⬜ |

## Phase 4: Agent + 遥测

| 编号 | 任务 | 状态 |
|------|------|:--:|
| B4-1 | `miaovps-agent` — VPS 轻量 Agent（5 组件） | ⬜ |
| B4-2 | `miaovps-telemetry` — Rust WSS 客户端 | ⬜ |

## Phase 5: 存储 + 安全

| 编号 | 任务 | 状态 |
|------|------|:--:|
| B5-1 | SQLite 数据库 + 迁移 | ⬜ |
| B5-2 | Keychain 集成（keyring-rs） | ⬜ |
| B5-3 | 日志脱敏框架（tracing） | ⬜ |
| B5-4 | 错误模型（AppError + 错误码映射） | ⬜ |
| B5-5 | Tauri commands 定义（具体命令，非泛化 shell） | ⬜ |

## Phase 6: 集成验证

| 编号 | 任务 | 状态 |
|------|------|:--:|
| B6-1 | 单元测试覆盖率 > 80% | ⬜ |
| B6-2 | 测试 VPS 端到端集成测试 | ⬜ |
| B6-3 | 10 个故障场景覆盖测试 | ⬜ |
| B6-4 | macOS Network Extension 编译 + 签名验证 | ⬜ |

## Phase 7: 前端骨架

| 编号 | 任务 | 状态 |
|------|------|:--:|
| F7-1 | Tauri 2 + React + TypeScript + Vite 初始化 | ⬜ |
| F7-2 | 路由（首页/节点/设备/设置） | ⬜ |
| F7-3 | 状态管理（Zustand + TanStack Query） | ⬜ |
| F7-4 | 主题系统 + 通用组件库 | ⬜ |

## Phase 8: 核心页面

| 编号 | 任务 | 状态 |
|------|------|:--:|
| F8-1 | 欢迎引导页 | ⬜ |
| F8-2 | 添加 VPS 表单 + 连接测试 + 环境检测 | ⬜ |
| F8-3 | 部署流程 UI（9 步 + 高级设置） | ⬜ |
| F8-4 | 首页（大状态 + 实时速率 + 资源 + 统计） | ⬜ |
| F8-5 | 连接状态机 UI（7 状态 + 8 失败原因） | ⬜ |
| F8-6 | 设备列表 + 详情（5 状态 + 密钥限制） | ⬜ |
| F8-7 | 配置导出（.conf + 二维码 + 系统关联） | ⬜ |
| F8-8 | 诊断结果 UI | ⬜ |
| F8-9 | 设置页 | ⬜ |

## Phase 9: 集成打磨

| 编号 | 任务 | 状态 |
|------|------|:--:|
| F9-1 | Tauri commands 对接 | ⬜ |
| F9-2 | Tauri events 对接（进度/遥测推送） | ⬜ |
| F9-3 | 错误处理（AppError → 用户可读） | ⬜ |
| F9-4 | 深色/浅色模式完善 | ⬜ |
| F9-5 | 键盘可访问性 | ⬜ |
| F9-6 | 状态不只用颜色区分 | ⬜ |

## Phase 10: 打包发布

| 编号 | 任务 | 状态 |
|------|------|:--:|
| F10-1 | macOS 应用打包 + 签名 | ⬜ |
| F10-2 | Network Extension 签名 + Provisioning Profile | ⬜ |
| F10-3 | 自动更新机制 | ⬜ |
| F10-4 | 端到端验收测试 | ⬜ |
| F10-5 | v0.1.0 发布 | ⬜ |

## 任务统计

| 阶段 | 总任务 | 已完成 | 待启动 | 完成率 |
|------|:--:|:--:|:--:|:--:|
| 后端 (P1-6) | 22 | 0 | 22 | 0% |
| 前端 (P7-10) | 20 | 0 | 20 | 0% |
| **合计** | **42** | **0** | **42** | **0%** |
