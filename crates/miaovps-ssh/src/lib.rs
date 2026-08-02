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
    PrivateKey {
        key_path: String,
        passphrase: Option<String>,
    },
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

/// 命令执行结果
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    /// 退出码；None 表示进程被信号终止
    pub exit_status: Option<u32>,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_status == Some(0)
    }

    /// 供错误信息使用：优先 stderr，为空则退回 stdout
    fn failure_detail(&self) -> String {
        let msg = if self.stderr.trim().is_empty() {
            self.stdout.trim()
        } else {
            self.stderr.trim()
        };
        if msg.is_empty() {
            "（无输出）".into()
        } else {
            msg.chars().take(500).collect()
        }
    }
}

impl SshSession {
    /// 建立 SSH 连接，按配置里的认证方式自动选择
    pub async fn connect(config: &SshConnectionConfig) -> Result<Self, SshError> {
        match &config.auth {
            SshAuthMethod::Password(pw) => Self::connect_password(config, pw).await,
            SshAuthMethod::PrivateKey {
                key_path,
                passphrase,
            } => Self::connect_key(config, key_path, passphrase.as_deref()).await,
            SshAuthMethod::SshAgent => Err(SshError::AuthFailed(
                "ssh-agent 认证尚未实现，请使用密码或私钥".into(),
            )),
        }
    }

    async fn open(config: &SshConnectionConfig) -> Result<client::Handle<ClientHandler>, SshError> {
        let addr = format!("{}:{}", config.host, config.port);
        let ssh_config = Arc::new(client::Config::default());
        client::connect(ssh_config, &addr, ClientHandler)
            .await
            .map_err(SshError::ConnectionFailed)
    }

    /// 建立 SSH 连接（密码认证）
    pub async fn connect_password(
        config: &SshConnectionConfig,
        password: &str,
    ) -> Result<Self, SshError> {
        let mut client = Self::open(config).await?;
        if !client
            .authenticate_password(&config.username, password)
            .await?
        {
            return Err(SshError::AuthFailed(format!(
                "密码认证被拒绝（用户 {}）",
                config.username
            )));
        }
        Ok(Self { session: client })
    }

    /// 建立 SSH 连接（私钥认证）
    ///
    /// `key_path` 支持 `~` 开头。私钥有 passphrase 时必须提供，
    /// 否则 russh 会报解码失败而不是认证失败 —— 错误信息里区分开，
    /// 免得用户以为是密钥不被接受。
    pub async fn connect_key(
        config: &SshConnectionConfig,
        key_path: &str,
        passphrase: Option<&str>,
    ) -> Result<Self, SshError> {
        let path = expand_tilde(key_path);
        if !path.exists() {
            return Err(SshError::KeyLoadFailed(format!(
                "私钥文件不存在: {}",
                path.display()
            )));
        }

        let key = russh_keys::load_secret_key(&path, passphrase).map_err(|e| {
            SshError::KeyLoadFailed(format!(
                "无法读取私钥 {}: {e}{}",
                path.display(),
                if passphrase.is_none() {
                    "（若私钥有密码短语，需要一并提供）"
                } else {
                    ""
                }
            ))
        })?;

        let mut client = Self::open(config).await?;
        if !client
            .authenticate_publickey(&config.username, Arc::new(key))
            .await?
        {
            return Err(SshError::AuthFailed(format!(
                "私钥认证被拒绝（用户 {}，密钥 {}）—— 确认公钥已在服务器 authorized_keys 中",
                config.username,
                path.display()
            )));
        }
        Ok(Self { session: client })
    }

    /// 执行命令，返回 stdout/stderr/退出码
    ///
    /// 不判定成功与否 —— 调用方需要区分「命令失败」和「命令成功但输出为空」时用这个。
    pub async fn exec_raw(&self, command: &str) -> Result<CommandOutput, SshError> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit_status = None;

        // 不能在收到 ExitStatus 时立即 break —— 剩余的 Data 帧可能还在后面，
        // 提前退出会截断输出。等到通道关闭（wait 返回 None）为止。
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { data } => {
                    stdout.push_str(&String::from_utf8_lossy(&data));
                }
                // ext == 1 是 stderr（SSH_EXTENDED_DATA_STDERR）
                russh::ChannelMsg::ExtendedData { data, ext: 1 } => {
                    stderr.push_str(&String::from_utf8_lossy(&data));
                }
                russh::ChannelMsg::ExitStatus { exit_status: code } => {
                    exit_status = Some(code);
                }
                _ => {}
            }
        }

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_status,
        })
    }

    /// 执行命令，非零退出码视为错误
    ///
    /// 原实现只收 stdout、忽略退出码，命令失败时返回空字符串 ——
    /// provisioner 的 9 步部署建立在这上面，任何一步失败都会被当成成功。
    pub async fn exec(&self, command: &str) -> Result<String, SshError> {
        let out = self.exec_raw(command).await?;
        if !out.success() {
            return Err(SshError::CommandFailed(format!(
                "`{}` 退出码 {}: {}",
                truncate_cmd(command),
                out.exit_status
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into()),
                out.failure_detail()
            )));
        }
        Ok(out.stdout)
    }

    /// 执行命令并忽略失败，只取 stdout
    ///
    /// 用于探测类命令（如 `which wg`），失败是预期结果之一。
    pub async fn exec_lenient(&self, command: &str) -> Result<String, SshError> {
        Ok(self.exec_raw(command).await?.stdout)
    }

    /// 显式关闭 SSH 连接。
    ///
    /// russh 的客户端连接任务由内部 runtime 持有；仅丢弃 Handle 不一定会
    /// 立即发送 disconnect，短命 CLI 因此可能在命令完成后仍保持进程不退出。
    pub async fn disconnect(self) -> Result<(), SshError> {
        self.session
            .disconnect(Disconnect::ByApplication, "command complete", "en")
            .await
            .map_err(SshError::ConnectionFailed)
    }
}

/// 展开路径开头的 `~`
fn expand_tilde(path: &str) -> std::path::PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    std::path::PathBuf::from(path)
}

/// 命令过长时截断，避免错误信息里塞进整个脚本
fn truncate_cmd(cmd: &str) -> String {
    let one_line: String = cmd
        .chars()
        .map(|c| if c == '\n' { ' ' } else { c })
        .collect();
    if one_line.chars().count() <= 80 {
        one_line
    } else {
        format!("{}…", one_line.chars().take(80).collect::<String>())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  错误
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("SSH 连接失败: {0}")]
    ConnectionFailed(#[from] russh::Error),

    #[error("SSH 认证失败: {0}")]
    AuthFailed(String),

    #[error("私钥加载失败: {0}")]
    KeyLoadFailed(String),

    #[error("命令执行失败: {0}")]
    CommandFailed(String),
}
