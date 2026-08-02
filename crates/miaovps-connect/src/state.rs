//! 连接状态机 — 两阶段连接（Split Tunnel → Full Tunnel）

use serde::{Deserialize, Serialize};

/// VPN 连接状态
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// 未连接
    Disconnected,

    /// 正在验证连通性（UDP → 握手 → NAT → 出口 IP）
    Validating {
        /// 当前验证步骤
        step: ValidationStep,
        /// 步骤序号 (1-based)
        step_num: u32,
        /// 总步骤数
        total_steps: u32,
        /// 步骤描述
        description: String,
    },

    /// Split Tunnel — 只路由 VPS 流量，不影响本地网络
    SplitTunnel,

    /// Full Tunnel — 全局流量走 VPN
    FullTunnel,

    /// 正在断开
    Disconnecting,

    /// 连接失败
    Failed {
        /// 失败步骤
        step: ValidationStep,
        /// 错误信息
        error: String,
    },
}

/// 验证步骤
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStep {
    /// 创建 TUN 接口
    CreateTun,

    /// UDP 端口可达测试
    UdpReachable,

    /// WireGuard 握手测试
    Handshake,

    /// NAT/路由验证
    NatCheck,

    /// 出口 IP 验证
    EgressIp,

    /// 全部通过
    Complete,
}

impl std::fmt::Display for ValidationStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateTun => write!(f, "创建虚拟网卡"),
            Self::UdpReachable => write!(f, "UDP 端口可达"),
            Self::Handshake => write!(f, "WireGuard 握手"),
            Self::NatCheck => write!(f, "NAT 路由检查"),
            Self::EgressIp => write!(f, "出口 IP 验证"),
            Self::Complete => write!(f, "全部通过"),
        }
    }
}

impl ConnectionState {
    /// 是否已连接（SplitTunnel 或 FullTunnel）
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::SplitTunnel | Self::FullTunnel)
    }

    /// 是否正在过渡状态
    pub fn is_transitioning(&self) -> bool {
        matches!(self, Self::Validating { .. } | Self::Disconnecting)
    }

    /// 进度百分比 (0-100)
    pub fn progress_pct(&self) -> u32 {
        match self {
            Self::Disconnected => 0,
            Self::Validating {
                step_num,
                total_steps,
                ..
            } => {
                if *total_steps == 0 {
                    0
                } else {
                    (step_num * 100) / total_steps
                }
            }
            Self::SplitTunnel => 80,
            Self::FullTunnel => 100,
            Self::Disconnecting => 100,
            Self::Failed { .. } => 100,
        }
    }
}
