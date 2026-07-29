//! 连接错误类型

use thiserror::Error;

/// 连接过程中的错误
#[derive(Debug, Error)]
pub enum ConnectError {
    /// 网络不可达
    #[error("网络不可达: {0}")]
    NetworkUnreachable(String),

    /// UDP 端口不可达
    #[error("UDP 端口 {port} 不可达: {detail}")]
    UdpUnreachable { port: u16, detail: String },

    /// WireGuard 握手失败
    #[error("WireGuard 握手失败: 服务器无响应 (已重试 {retries} 次)")]
    HandshakeTimeout { retries: u32 },

    /// WireGuard 密钥错误
    #[error("WireGuard 密钥不匹配: {0}")]
    KeyMismatch(String),

    /// TUN 接口创建失败
    #[error("无法创建 TUN 接口: {0}")]
    TunError(String),

    /// 路由操作失败
    #[error("路由操作失败: {0}")]
    RouteError(String),

    /// NAT 不工作
    #[error("NAT 测试失败: {0}")]
    NatError(String),

    /// 出口 IP 验证失败
    #[error("出口 IP 验证失败: 期望 {expected}, 实际 {actual}")]
    EgressIpMismatch { expected: String, actual: String },

    /// DNS 配置失败
    #[error("DNS 配置失败: {0}")]
    DnsError(String),

    /// 隧道内部错误
    #[error("隧道内部错误: {0}")]
    TunnelError(String),

    /// boringtun 错误
    #[error("WireGuard 协议错误: {0}")]
    WireGuardError(String),

    /// IO 错误
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),

    /// 配置错误
    #[error("配置错误: {0}")]
    Config(String),

    /// 已连接
    #[error("已经处于连接状态")]
    AlreadyConnected,

    /// 未连接
    #[error("当前未连接")]
    NotConnected,
}
