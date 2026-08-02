//! MiaoVPS 核心领域模型
//!
//! 定义项目中所有核心数据结构，不依赖任何具体实现。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Server — VPS 服务器
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// SSH 认证方式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SshAuthType {
    Password,
    PrivateKey,
    SshAgent,
}

/// 服务器状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatus {
    /// 仅保存了 SSH 信息，尚未完成环境检测
    PendingInspection,
    /// 已添加，未部署
    Added,
    /// 部署进行中
    Deploying,
    /// 正常运行
    Online,
    /// 需要处理
    NeedsAttention,
    /// 离线
    Offline,
    /// 配置损坏
    ConfigBroken,
    /// 未完成部署
    Incomplete,
}

impl ServerStatus {
    /// 只有完成成功检测、已部署或一次部署中断的节点才允许进入部署流程。
    /// 其他状态必须先检测，避免把 SSH 可达误当作可安全修改远端网络。
    pub fn permits_deployment(&self) -> bool {
        matches!(self, Self::Added | Self::Online | Self::Incomplete)
    }
}

/// VPS 服务器
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub auth_type: SshAuthType,
    /// Keychain 引用标识，不存明文凭据
    pub credential_ref: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub architecture: Option<String>,
    pub public_ipv4: Option<String>,
    pub status: ServerStatus,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Server {
    pub fn new(
        name: String,
        host: String,
        ssh_port: u16,
        ssh_user: String,
        auth_type: SshAuthType,
    ) -> Self {
        let now = current_timestamp();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            host,
            ssh_port,
            ssh_user,
            auth_type,
            credential_ref: None,
            os_name: None,
            os_version: None,
            architecture: None,
            public_ipv4: None,
            status: ServerStatus::PendingInspection,
            created_at: now,
            updated_at: now,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  WireGuardNode — VPS 上的 WireGuard 配置
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Running,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardNode {
    pub server_id: String,
    pub interface_name: String,
    pub listen_port: u16,
    pub vpn_cidr: String,
    pub server_public_key: String,
    pub dns: Vec<String>,
    pub mtu: Option<u16>,
    pub ipv6_enabled: bool,
    pub service_status: ServiceStatus,
}

impl WireGuardNode {
    pub fn new(
        server_id: String,
        listen_port: u16,
        vpn_cidr: String,
        server_public_key: String,
        dns: Vec<String>,
    ) -> Self {
        Self {
            server_id,
            interface_name: "wg0".into(),
            listen_port,
            vpn_cidr,
            server_public_key,
            dns,
            mtu: Some(1380),
            ipv6_enabled: false,
            service_status: ServiceStatus::Unknown,
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Device — VPN 客户端设备 (Peer)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Mac,
    Windows,
    IPhone,
    Android,
    Linux,
    Other,
}

impl DeviceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Mac => "Mac",
            DeviceType::Windows => "Windows",
            DeviceType::IPhone => "iPhone",
            DeviceType::Android => "Android",
            DeviceType::Linux => "Linux",
            DeviceType::Other => "Other",
        }
    }
}

/// 设备在线状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// 最近 3 分钟有握手
    Online,
    /// 最近 24 小时有握手
    RecentOnline,
    /// 超过 24 小时无握手
    Offline,
    /// 尚无握手记录
    NeverConnected,
    /// Peer 已从配置移除
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub server_id: String,
    pub name: String,
    pub device_type: DeviceType,
    /// 仅存储公钥；私钥通过 private_key_ref 引用 Keychain
    pub public_key: String,
    pub private_key_ref: Option<String>,
    pub vpn_address: String,
    pub enabled: bool,
    pub latest_handshake_at: Option<i64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub created_at: i64,
}

impl Device {
    pub fn new(
        server_id: String,
        name: String,
        device_type: DeviceType,
        public_key: String,
        vpn_address: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            server_id,
            name,
            device_type,
            public_key,
            private_key_ref: None,
            vpn_address,
            enabled: true,
            latest_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
            created_at: current_timestamp(),
        }
    }

    pub fn status(&self) -> DeviceStatus {
        if !self.enabled {
            return DeviceStatus::Disabled;
        }
        match self.latest_handshake_at {
            None => DeviceStatus::NeverConnected,
            Some(ts) => {
                let now = current_timestamp();
                let elapsed = now - ts;
                if elapsed < 180 {
                    DeviceStatus::Online
                } else if elapsed < 86400 {
                    DeviceStatus::RecentOnline
                } else {
                    DeviceStatus::Offline
                }
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Deployment — 部署任务
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Pending,
    InProgress,
    Success,
    Warning,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DeploymentStep {
    Connect,
    Backup,
    InstallWireGuard,
    GenerateServerKeys,
    ConfigureInterface,
    ConfigureRouting,
    StartService,
    CreateFirstDevice,
    Verify,
}

impl DeploymentStep {
    pub fn label(&self) -> &'static str {
        match self {
            DeploymentStep::Connect => "建立安全连接",
            DeploymentStep::Backup => "备份现有网络配置",
            DeploymentStep::InstallWireGuard => "安装 WireGuard",
            DeploymentStep::GenerateServerKeys => "生成服务器密钥",
            DeploymentStep::ConfigureInterface => "配置虚拟网络",
            DeploymentStep::ConfigureRouting => "配置路由和防火墙",
            DeploymentStep::StartService => "启动 WireGuard",
            DeploymentStep::CreateFirstDevice => "创建第一台设备",
            DeploymentStep::Verify => "验证服务状态",
        }
    }

    pub fn all_steps() -> Vec<DeploymentStep> {
        vec![
            DeploymentStep::Connect,
            DeploymentStep::Backup,
            DeploymentStep::InstallWireGuard,
            DeploymentStep::GenerateServerKeys,
            DeploymentStep::ConfigureInterface,
            DeploymentStep::ConfigureRouting,
            DeploymentStep::StartService,
            DeploymentStep::CreateFirstDevice,
            DeploymentStep::Verify,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentFailure {
    pub step: DeploymentStep,
    pub reason: String,
    pub raw_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub id: String,
    pub server_id: String,
    pub status: DeploymentStatus,
    pub current_step: DeploymentStep,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub backup_path: Option<String>,
    pub failure: Option<DeploymentFailure>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::{Server, ServerStatus, SshAuthType};

    #[test]
    fn new_server_requires_inspection_before_deployment() {
        let server = Server::new(
            "new VPS".into(),
            "203.0.113.10".into(),
            22,
            "root".into(),
            SshAuthType::Password,
        );
        assert_eq!(server.status, ServerStatus::PendingInspection);
        assert!(!server.status.permits_deployment());
        assert!(ServerStatus::Added.permits_deployment());
    }
}
