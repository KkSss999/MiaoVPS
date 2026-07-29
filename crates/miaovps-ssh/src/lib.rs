//! SSH 连接管理
//!
//! 基于 russh 0.45 实现 SSH 密码/私钥登录、Host Key 验证。
//! 完整的 SSH 认证流程留待集成阶段完善。

use russh::*;
use std::sync::Arc;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  连接配置
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub enum SshAuthMethod {
    Password(String),
    PrivateKey { key_path: String, passphrase: Option<String> },
    SshAgent,
}

#[derive(Debug, Clone)]
pub struct SshConnectionConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuthMethod,
}

impl Default for SshConnectionConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            username: "root".into(),
            auth: SshAuthMethod::Password(String::new()),
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Host Key
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone)]
pub struct HostKeyInfo {
    pub key_type: String,
    pub fingerprint_sha256: String,
}

/// 从 russh_keys PublicKey 提取指纹
pub fn host_key_info(_key: &russh_keys::key::PublicKey) -> HostKeyInfo {
    HostKeyInfo {
        key_type: "RSA/ED25519".into(),
        fingerprint_sha256: "fingerprint_placeholder".into(),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SSH 客户端 Handler
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

struct ClientHandler;

#[async_trait::async_trait]
impl client::Handler for ClientHandler {
    type Error = russh::Error;

    /// 服务端 Host Key 验证
    /// 首次连接由上层 UI 确认后写入 known-hosts
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: 与本地 known-hosts 对比，首次提示用户确认
        Ok(true)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SSH 会话
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct SshSession {
    session: client::Handle<ClientHandler>,
}

impl SshSession {
    /// 建立 SSH 连接（密码认证）
    pub async fn connect_password(config: &SshConnectionConfig, password: &str) -> Result<Self, SshError> {
        let addr = format!("{}:{}", config.host, config.port);

        let ssh_config = Arc::new(client::Config::default());
        let handler = ClientHandler;

        let mut client = client::connect(ssh_config, &addr, handler).await?;

        // 密码认证
        let auth_result = client.authenticate_password(&config.username, password).await?;
        if !auth_result {
            return Err(SshError::AuthFailed("密码认证失败".into()));
        }

        Ok(Self { session: client })
    }

    /// 执行命令并返回 stdout
    pub async fn exec(&self, command: &str) -> Result<String, SshError> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut output = String::new();
        loop {
            let Some(msg) = channel.wait().await else { break };
            match msg {
                russh::ChannelMsg::Data { data } => {
                    output.push_str(&String::from_utf8_lossy(&data));
                }
                russh::ChannelMsg::ExitStatus { .. } => break,
                _ => {}
            }
        }
        Ok(output)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  错误
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("SSH connection failed: {0}")]
    ConnectionFailed(#[from] russh::Error),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Command execution failed: {0}")]
    CommandFailed(String),
}
