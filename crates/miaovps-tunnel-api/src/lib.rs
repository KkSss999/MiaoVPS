//! 平台无关的 VPN 隧道抽象接口
//!
//! 定义 TunnelBackend trait 和相关数据模型。
//! 各平台（macOS/Windows/Linux）分别实现此接口。

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  隧道配置模型
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 路由策略
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoutingPolicy {
    /// 全局隧道：接管全部流量 (AllowedIPs = 0.0.0.0/0, ::/0)
    #[default]
    FullTunnel,
    /// 分流模式：仅指定路由走隧道
    SplitTunnel {
        included_routes: Vec<String>,
        excluded_routes: Vec<String>,
    },
}

impl RoutingPolicy {
    /// 转为 WireGuard AllowedIPs 列表
    pub fn to_allowed_ips(&self) -> Vec<String> {
        match self {
            RoutingPolicy::FullTunnel => vec!["0.0.0.0/0".into(), "::/0".into()],
            RoutingPolicy::SplitTunnel {
                included_routes, ..
            } => included_routes.clone(),
        }
    }
}

/// 隧道对端 (VPS WireGuard 服务器)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelPeer {
    pub public_key: String,
    /// VPS_IP:PORT
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

/// 隧道配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub id: String,
    pub name: String,
    /// Keychain 引用，非明文私钥
    pub private_key_ref: String,
    /// 本机虚拟 IP，如 ["10.66.66.2/32"]
    pub local_addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub peer: TunnelPeer,
    pub routing: RoutingPolicy,
    pub mtu: Option<u16>,
}

/// 隧道连接状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    Disconnected,
    Preparing,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Failed,
}

impl TunnelState {
    pub fn label(&self) -> &'static str {
        match self {
            TunnelState::Disconnected => "未连接",
            TunnelState::Preparing => "正在准备",
            TunnelState::Connecting => "正在建立隧道",
            TunnelState::Connected => "已连接",
            TunnelState::Reconnecting => "正在重连",
            TunnelState::Disconnecting => "正在断开",
            TunnelState::Failed => "失败",
        }
    }
}

/// 隧道失败原因（具体，非泛化"连接失败"）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelFailureReason {
    ServerUnreachable,
    UdpPortNoResponse,
    HandshakeTimeout,
    DnsConfigFailed,
    SystemPermissionDenied,
    LocalKeyNotFound,
    PeerPublicKeyChanged,
    EgressVerificationFailed,
}

impl TunnelFailureReason {
    pub fn message(&self) -> &'static str {
        match self {
            TunnelFailureReason::ServerUnreachable => "服务器不可达",
            TunnelFailureReason::UdpPortNoResponse => "UDP 51820 无响应",
            TunnelFailureReason::HandshakeTimeout => "WireGuard 握手超时",
            TunnelFailureReason::DnsConfigFailed => "DNS 配置失败",
            TunnelFailureReason::SystemPermissionDenied => "系统拒绝 VPN 权限",
            TunnelFailureReason::LocalKeyNotFound => "本机密钥不存在",
            TunnelFailureReason::PeerPublicKeyChanged => "节点公钥发生变化",
            TunnelFailureReason::EgressVerificationFailed => "出口网络验证失败",
        }
    }
}

/// 隧道运行状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub state: TunnelState,
    pub failure_reason: Option<TunnelFailureReason>,
    pub connected_since: Option<i64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub egress_ip: Option<String>,
}

/// 隧道配置档案
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelProfile {
    pub id: String,
    pub name: String,
    pub config: TunnelConfig,
    pub created_at: i64,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  TunnelBackend trait
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 平台 VPN 隧道后端统一接口
///
/// 各平台实现：
/// - macOS:  Swift Tunnel Manager → NETunnelProviderManager → WireGuardKit
/// - Windows: embeddable-dll-service → WireGuardNT
/// - Linux:   wg-quick / Netlink / NetworkManager D-Bus
#[async_trait]
pub trait TunnelBackend: Send + Sync {
    /// 安装隧道配置档案
    async fn install_profile(&self, config: TunnelConfig) -> Result<TunnelProfile, TunnelError>;

    /// 启动隧道连接
    async fn connect(&self, profile_id: &str) -> Result<(), TunnelError>;

    /// 断开隧道连接
    async fn disconnect(&self, profile_id: &str) -> Result<(), TunnelError>;

    /// 查询隧道当前状态
    async fn status(&self, profile_id: &str) -> Result<TunnelStatus, TunnelError>;

    /// 删除隧道配置档案
    async fn remove_profile(&self, profile_id: &str) -> Result<(), TunnelError>;
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  错误类型
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("System permission denied: {0}")]
    PermissionDenied(String),

    #[error("Tunnel operation failed: {0}")]
    OperationFailed(String),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("{0}")]
    Other(String),
}
