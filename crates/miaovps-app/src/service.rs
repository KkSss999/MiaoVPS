//! 应用服务层 — Tauri IPC 边界
//!
//! 所有方法均可直接作为 `#[tauri::command]` 使用。
//! 入参和返回值均实现 serde::Serialize/Deserialize。

use crate::credentials::ServerCredential;
use crate::session::{open_provisioner, open_provisioner_any, ServiceError};
use miaovps_core::{Device, DeviceType, Server, ServerStatus, SshAuthType, WireGuardNode};
use miaovps_provisioner::{
    DeploymentOptions, DeploymentProgress, ServerReport, StepSender,
};
use miaovps_storage::{keychain::WgKeyStore, Database};
use miaovps_wireguard_config::{generate_client_config, generate_keypair, ClientConfigParams};
use std::path::PathBuf;
use tracing::info;

/// 应用服务 — 持有数据库和凭据目录
pub struct AppService {
    pub db: Database,
    pub cred_dir: PathBuf,
}

impl AppService {
    pub fn new(db: Database, cred_dir: PathBuf) -> Self {
        Self { db, cred_dir }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Server 管理
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// Tauri IPC: #[tauri::command] async fn list_servers(...)
    /// 列出所有服务器
    pub async fn list_servers(&self) -> Result<Vec<Server>, ServiceError> {
        Ok(self.db.list_servers().await?)
    }

    /// Tauri IPC: #[tauri::command] async fn add_server(...)
    /// 添加服务器，保存凭据
    pub async fn add_server(
        &self,
        name: String,
        host: String,
        port: u16,
        user: String,
        auth_type: SshAuthType,
        credential: ServerCredential,
    ) -> Result<Server, ServiceError> {
        let mut server = Server::new(name, host, port, user, auth_type);
        let cred_ref = credential.save(&self.cred_dir, &server.id)?;
        server.credential_ref = Some(cred_ref);
        self.db.insert_server(&server).await?;
        info!(server_id=%server.id, "服务器已添加: {}", server.name);
        Ok(server)
    }

    /// Tauri IPC: #[tauri::command] async fn inspect_server(...)
    /// 环境检测，返回 11 项检测结果
    pub async fn inspect_server(&self, server_id: String) -> Result<ServerReport, ServiceError> {
        let server = self
            .db
            .get_server(&server_id)
            .await?
            .ok_or_else(|| ServiceError::ServerNotFound(server_id.clone()))?;

        info!(server_id=%server_id, "开始环境检测: {}", server.name);
        let mut provisioner = open_provisioner_any(&server, &self.cred_dir).await?;
        let report = provisioner.inspect().await?;

        // 持久化检测结果到 Server
        let mut updated = server.clone();
        for item in &report.items {
            match item.name.as_str() {
                "操作系统" => {
                    if let Some(msg) = item.message.split_whitespace().nth(1) {
                        updated.os_name = Some(item.message.clone());
                        if msg.contains("24.04") {
                            updated.os_version = Some("24.04".into());
                        } else if msg.contains("22.04") {
                            updated.os_version = Some("22.04".into());
                        }
                    }
                }
                "架构" => updated.architecture = Some(item.message.clone()),
                "公网 IPv4" if item.message != "无法检测公网 IP" => {
                    updated.public_ipv4 = Some(item.message.clone());
                }
                _ => {}
            }
        }
        updated.status = if report.blocked {
            ServerStatus::ConfigBroken
        } else if report.all_passed {
            ServerStatus::Added
        } else {
            ServerStatus::NeedsAttention
        };
        updated.updated_at = current_timestamp();
        self.db.update_server(&updated).await?;

        info!(server_id=%server_id, passed=%report.all_passed, "检测完成");
        Ok(report)
    }

    /// Tauri IPC: #[tauri::command] async fn deploy_server(...)
    /// 一键部署 WireGuard
    ///
    /// `events` 非空时，每一步状态变更会实时推送到通道。
    /// 前端把接收端接到 `app_handle.emit("deploy-progress", ev)`。
    pub async fn deploy_server(
        &self,
        server_id: String,
        options: Option<DeploymentOptions>,
        events: Option<StepSender>,
    ) -> Result<DeploymentProgress, ServiceError> {
        let server = self
            .db
            .get_server(&server_id)
            .await?
            .ok_or_else(|| ServiceError::ServerNotFound(server_id.clone()))?;

        info!(server_id=%server_id, "开始部署: {}", server.name);
        self.db
            .update_server_status(&server_id, &ServerStatus::Deploying)
            .await?;

        let opts = options.unwrap_or_default();
        let mut provisioner = open_provisioner(&server, &self.cred_dir, None).await?;
        let progress = provisioner.deploy_reporting(&opts, events).await?;

        // 部署成功后保存 WireGuardNode
        if progress.status == miaovps_core::DeploymentStatus::Success {
            if let Some(pubkey) = &progress.server_public_key {
                let node = WireGuardNode::new(
                    server_id.clone(),
                    opts.wireguard_port,
                    opts.vpn_cidr.clone(),
                    pubkey.clone(),
                    opts.dns.clone(),
                );
                self.db.upsert_wg_node(&node).await?;
                info!(server_id=%server_id, "WireGuard 节点已保存");
            }
            self.db
                .update_server_status(&server_id, &ServerStatus::Online)
                .await?;
        } else {
            self.db
                .update_server_status(&server_id, &ServerStatus::ConfigBroken)
                .await?;
        }

        info!(server_id=%server_id, status=?progress.status, "部署完成");
        Ok(progress)
    }

    /// Tauri IPC: #[tauri::command] async fn server_status(...)
    /// 获取 WireGuard 状态（wg show wg0）
    pub async fn server_status(&self, server_id: String) -> Result<String, ServiceError> {
        let server = self
            .db
            .get_server(&server_id)
            .await?
            .ok_or_else(|| ServiceError::ServerNotFound(server_id.clone()))?;

        let mut provisioner = open_provisioner_any(&server, &self.cred_dir).await?;
        let status = provisioner.get_status().await?;
        Ok(status)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Device 管理
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// Tauri IPC: #[tauri::command] async fn add_device(...)
    /// 添加设备，生成密钥，写入 DB，返回 WireGuard 配置
    pub async fn add_device(
        &self,
        server_id: String,
        name: String,
        device_type: DeviceType,
    ) -> Result<(Device, String), ServiceError> {
        let server = self
            .db
            .get_server(&server_id)
            .await?
            .ok_or_else(|| ServiceError::ServerNotFound(server_id.clone()))?;

        let node = self
            .db
            .get_wg_node(&server_id)
            .await?
            .ok_or(ServiceError::WgNodeNotFound)?;

        // 生成客户端密钥
        let keypair = generate_keypair();

        // 分配 VPN IP（简化实现：按设备数 +2）
        let devices = self.db.list_devices(&server_id).await?;
        let next_ip = 2 + devices.len();
        let vpn_address = format!("10.66.66.{}/32", next_ip);

        let mut device = Device::new(
            server_id.clone(),
            name.clone(),
            device_type,
            keypair.public_key.clone(),
            vpn_address.clone(),
        );

        // 存储私钥到 Keychain
        let key_ref = WgKeyStore::store(&device.id, &keypair.private_key)
            .map_err(|e| ServiceError::other(format!("Keychain 存储失败: {e}")))?;
        device.private_key_ref = Some(key_ref);

        self.db.insert_device(&device).await?;

        // 添加到服务端 WireGuard peer
        let mut provisioner = open_provisioner(&server, &self.cred_dir, None).await?;
        provisioner
            .add_peer(&keypair.public_key, &vpn_address)
            .await?;

        // 生成客户端配置文件
        let wg_config = generate_client_config(ClientConfigParams {
            private_key: keypair.private_key.clone(),
            address: vpn_address.clone(),
            dns: node.dns.clone(),
            mtu: node.mtu,
            server_public_key: node.server_public_key.clone(),
            server_endpoint: format!("{}:{}", server.host, node.listen_port),
            allowed_ips: "0.0.0.0/0".into(),
            persistent_keepalive: Some(25),
        });

        info!(device_id=%device.id, server_id=%server_id, "设备已添加: {}", name);
        Ok((device, wg_config))
    }

    /// Tauri IPC: #[tauri::command] async fn export_config(...)
    /// 导出设备的 WireGuard 配置文件
    pub async fn export_config(&self, device_id: String) -> Result<String, ServiceError> {
        let device = self
            .db
            .get_device(&device_id)
            .await?
            .ok_or_else(|| ServiceError::DeviceNotFound(device_id.clone()))?;

        let server = self
            .db
            .get_server(&device.server_id)
            .await?
            .ok_or_else(|| ServiceError::ServerNotFound(device.server_id.clone()))?;

        let node = self
            .db
            .get_wg_node(&device.server_id)
            .await?
            .ok_or(ServiceError::WgNodeNotFound)?;

        let private_key = match &device.private_key_ref {
            Some(key_ref) => WgKeyStore::load(key_ref)
                .map_err(|e| ServiceError::other(format!("私钥读取失败: {e}")))?,
            None => return Err(ServiceError::other("设备私钥未找到")),
        };

        let config_str = generate_client_config(ClientConfigParams {
            private_key,
            address: device.vpn_address.clone(),
            dns: node.dns.clone(),
            mtu: node.mtu,
            server_public_key: node.server_public_key.clone(),
            server_endpoint: format!("{}:{}", server.host, node.listen_port),
            allowed_ips: "0.0.0.0/0".into(),
            persistent_keepalive: Some(25),
        });

        Ok(config_str)
    }

    /// Tauri IPC: #[tauri::command] async fn list_devices(...)
    /// 列出服务器下的所有设备
    pub async fn list_devices(&self, server_id: String) -> Result<Vec<Device>, ServiceError> {
        Ok(self.db.list_devices(&server_id).await?)
    }
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
