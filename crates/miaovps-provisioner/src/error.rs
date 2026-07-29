//! 错误模型
//!
//! 统一错误类型，支持用户可读的展示和建议操作。

use serde::{Deserialize, Serialize};

/// 应用错误码
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ErrorCode {
    // SSH
    SshHostUnreachable,
    SshAuthFailed,
    SshHostKeyChanged,
    SshTimeout,

    // 环境检测
    SudoRequired,
    UnsupportedOs,
    PortOccupied,
    LowDiskSpace,
    LowMemory,

    // 部署
    PackageInstallFailed,
    ConfigWriteFailed,
    ServiceStartFailed,
    IpForwardDisabled,
    NatRuleMissing,
    FirewallConfigFailed,

    // 设备/Peer
    PeerDuplicated,
    PeerNotFound,
    NoHandshake,
    DnsUnreachable,
    ConfigExportFailed,

    // 隧道
    TunnelPermissionDenied,
    TunnelKeyNotFound,
    TunnelHandshakeTimeout,
    EgressCheckFailed,

    // 通用
    ConnectionRefused,
    Timeout,
    IoError,
    InternalError,
}

/// 应用错误（面向用户）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppError {
    pub code: ErrorCode,
    pub title: String,
    pub message: String,
    pub recoverable: bool,
    pub suggested_action: Option<String>,
    pub technical_details: Option<String>,
}

impl AppError {
    pub fn new(
        code: ErrorCode,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            title: title.into(),
            message: message.into(),
            recoverable: true,
            suggested_action: None,
            technical_details: None,
        }
    }

    pub fn with_suggestion(mut self, action: impl Into<String>) -> Self {
        self.suggested_action = Some(action.into());
        self
    }

    pub fn with_technical(mut self, details: impl Into<String>) -> Self {
        self.technical_details = Some(details.into());
        self
    }

    pub fn unrecoverable(mut self) -> Self {
        self.recoverable = false;
        self
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code.code_str(), self.message)
    }
}

impl std::error::Error for AppError {}

impl ErrorCode {
    pub fn code_str(&self) -> &'static str {
        match self {
            ErrorCode::SshHostUnreachable => "SSH_HOST_UNREACHABLE",
            ErrorCode::SshAuthFailed => "SSH_AUTH_FAILED",
            ErrorCode::SshHostKeyChanged => "SSH_HOST_KEY_CHANGED",
            ErrorCode::SshTimeout => "SSH_TIMEOUT",
            ErrorCode::SudoRequired => "SUDO_REQUIRED",
            ErrorCode::UnsupportedOs => "UNSUPPORTED_OS",
            ErrorCode::PortOccupied => "WG_PORT_OCCUPIED",
            ErrorCode::LowDiskSpace => "LOW_DISK_SPACE",
            ErrorCode::LowMemory => "LOW_MEMORY",
            ErrorCode::PackageInstallFailed => "PACKAGE_INSTALL_FAILED",
            ErrorCode::ConfigWriteFailed => "CONFIG_WRITE_FAILED",
            ErrorCode::ServiceStartFailed => "WG_SERVICE_FAILED",
            ErrorCode::IpForwardDisabled => "IP_FORWARD_DISABLED",
            ErrorCode::NatRuleMissing => "NAT_RULE_MISSING",
            ErrorCode::FirewallConfigFailed => "FIREWALL_CONFIG_FAILED",
            ErrorCode::PeerDuplicated => "PEER_DUPLICATED",
            ErrorCode::PeerNotFound => "PEER_NOT_FOUND",
            ErrorCode::NoHandshake => "NO_HANDSHAKE",
            ErrorCode::DnsUnreachable => "DNS_UNREACHABLE",
            ErrorCode::ConfigExportFailed => "CONFIG_EXPORT_FAILED",
            ErrorCode::TunnelPermissionDenied => "TUNNEL_PERMISSION_DENIED",
            ErrorCode::TunnelKeyNotFound => "TUNNEL_KEY_NOT_FOUND",
            ErrorCode::TunnelHandshakeTimeout => "TUNNEL_HANDSHAKE_TIMEOUT",
            ErrorCode::EgressCheckFailed => "EGRESS_CHECK_FAILED",
            ErrorCode::ConnectionRefused => "CONNECTION_REFUSED",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::IoError => "IO_ERROR",
            ErrorCode::InternalError => "INTERNAL_ERROR",
        }
    }
}
