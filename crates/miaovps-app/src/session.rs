//! SSH 会话构建
//!
//! 从数据库的 Server 记录 + 凭据文件构建 SshSession，
//! 并自动探测提权方式（root / sudo）。

use crate::credentials::{CredError, ServerCredential};
use miaovps_core::{Server, SshAuthType};
use miaovps_provisioner::{AppError, ErrorCode, SshProvisioner};
use miaovps_ssh::{SshAuthMethod, SshConnectionConfig, SshError, SshSession};
use std::path::Path;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ServiceError — 统一应用层错误
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("{0}")]
    App(#[from] AppError),
    #[error("SSH 错误: {0}")]
    Ssh(#[from] SshError),
    #[error("凭据错误: {0}")]
    Cred(#[from] CredError),
    #[error("存储错误: {0}")]
    Storage(#[from] miaovps_storage::StorageError),
    #[error("服务器不存在: {0}")]
    ServerNotFound(String),
    #[error("设备不存在: {0}")]
    DeviceNotFound(String),
    #[error("WireGuard 配置未找到，请先执行 deploy")]
    WgNodeNotFound,
    #[error("请先完成环境检测并处理阻塞项，再部署 WireGuard")]
    InspectionRequired,
    #[error("{0}")]
    Other(String),
}

impl ServiceError {
    pub fn other(msg: impl Into<String>) -> Self {
        ServiceError::Other(msg.into())
    }

    /// 机器可读错误码 —— 前端按此分支处理，不要匹配错误文案
    pub fn code(&self) -> &'static str {
        match self {
            ServiceError::App(_) => "app_error",
            ServiceError::Ssh(_) => "ssh_error",
            ServiceError::Cred(_) => "credential_error",
            ServiceError::Storage(_) => "storage_error",
            ServiceError::ServerNotFound(_) => "server_not_found",
            ServiceError::DeviceNotFound(_) => "device_not_found",
            ServiceError::WgNodeNotFound => "wg_node_not_found",
            ServiceError::InspectionRequired => "inspection_required",
            ServiceError::Other(_) => "other",
        }
    }
}

/// 可序列化错误 DTO —— Tauri command 的 Err 必须能过 IPC
///
/// `ServiceError` 内层包着 `SshError` 等不实现 Serialize 的类型，
/// 所以走这层转换而不是给 ServiceError 直接 derive。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ErrorDto {
    pub code: String,
    pub message: String,
}

impl From<ServiceError> for ErrorDto {
    fn from(e: ServiceError) -> Self {
        Self {
            code: e.code().to_string(),
            message: e.to_string(),
        }
    }
}

impl serde::Serialize for ServiceError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        ErrorDto {
            code: self.code().to_string(),
            message: self.to_string(),
        }
        .serialize(s)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  会话构建
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 从 Server 记录和凭据目录构建 SSH 连接配置
fn build_config(server: &Server, cred: &ServerCredential) -> SshConnectionConfig {
    let auth = match cred {
        ServerCredential::Password { password } => SshAuthMethod::Password(password.clone()),
        ServerCredential::PrivateKey { key_path, passphrase } => SshAuthMethod::PrivateKey {
            key_path: key_path.clone(),
            passphrase: passphrase.clone(),
        },
    };
    SshConnectionConfig {
        host: server.host.clone(),
        port: server.ssh_port,
        username: server.ssh_user.clone(),
        auth,
    }
}

/// 从数据库 Server + 凭据目录打开 SSH 连接，自动探测提权方式，返回 SshProvisioner
pub async fn open_provisioner(
    server: &Server,
    cred_dir: &Path,
    sudo_password: Option<&str>,
) -> Result<SshProvisioner, ServiceError> {
    let cred = ServerCredential::load(cred_dir, &server.id)?;
    let config = build_config(server, &cred);
    let session = SshSession::connect(&config).await?;

    let privilege = SshProvisioner::detect_privilege(&session, sudo_password)
        .await
        .map_err(|e| ServiceError::App(AppError::new(
            ErrorCode::SudoRequired,
            "权限探测失败",
            e.to_string(),
        )))?;

    Ok(SshProvisioner::new(session, server.id.clone()).with_privilege(privilege))
}

/// 无需提权时直接返回普通 SshProvisioner（inspect 等只读操作）
pub async fn open_provisioner_any(
    server: &Server,
    cred_dir: &Path,
) -> Result<SshProvisioner, ServiceError> {
    open_provisioner(server, cred_dir, None).await
}

/// 将 SshAuthType（core 领域模型）转为命令行可用的提示字符串
pub fn auth_type_hint(auth: &SshAuthType) -> &'static str {
    match auth {
        SshAuthType::Password => "密码认证",
        SshAuthType::PrivateKey => "私钥认证",
        SshAuthType::SshAgent => "SSH Agent 认证",
    }
}
