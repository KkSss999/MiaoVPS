//! 应用服务层 — Tauri IPC 边界
//!
//! 所有方法均可直接作为 `#[tauri::command]` 使用。
//! 入参和返回值均实现 serde::Serialize/Deserialize。

use crate::credentials::ServerCredential;
use crate::session::{open_provisioner, open_provisioner_any, ServiceError};
use miaovps_core::{Device, DeviceType, Server, ServerStatus, SshAuthType, WireGuardNode};
use miaovps_provisioner::{
    DeploymentOptions, DeploymentProgress, DetectKey, DetectStatus, ServerReport, StepSender,
};
use miaovps_storage::{keychain::WgKeyStore, Database};
use miaovps_wireguard_config::{generate_client_config, generate_keypair, ClientConfigParams};
use std::collections::HashMap;
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
        //
        // 按 DetectKey 匹配而非 item.name —— name 是 UI 文案，
        // 改一次措辞就会静默丢掉 os/arch/ip 的持久化。
        let mut updated = server.clone();
        for item in &report.items {
            match item.key {
                DetectKey::Os => {
                    updated.os_name = Some(item.message.clone());
                    updated.os_version = parse_os_version(&item.message);
                }
                DetectKey::Arch => updated.architecture = Some(item.message.clone()),
                // Warning 时 message 是「无法检测公网 IP」这类提示文案，不是 IP
                DetectKey::PublicIpv4 if item.status == DetectStatus::Pass => {
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

        // 部署会改防火墙、路由和 WireGuard 配置；未做检测时不知道系统、
        // 权限、端口和磁盘是否满足前提。UI 的禁用只是提示，这里才是
        // 最终门禁，避免 IPC 或未来 CLI 调用绕过。
        if !server.status.permits_deployment() {
            return Err(ServiceError::InspectionRequired);
        }

        info!(server_id=%server_id, "开始部署: {}", server.name);
        self.db
            .update_server_status(&server_id, &ServerStatus::Deploying)
            .await?;

        let opts = options.unwrap_or_default();
        let mut provisioner = open_provisioner(&server, &self.cred_dir, None).await?;
        let mut progress = provisioner.deploy_reporting(&opts, events).await?;
        // 部署完成后显式关闭 russh 会话。仅丢弃 Handle 可能让后台连接任务
        // 继续存活，CLI 会表现为部署成功但进程不自动退出。
        if let Err(e) = provisioner.disconnect().await {
            tracing::warn!(server_id=%server_id, error=%e, "关闭部署 SSH 会话失败");
        }
        // 事件接收方由 CLI/Tauri 调用方管理；返回最终结果前必须释放发送端，
        // 否则 CLI 的进度打印任务会一直等待，导致部署成功后无法退出。
        progress.clear_sink();

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

        // 分配 VPN IP —— 扫首个空闲地址，不能用设备数递增
        //
        // 删掉中间某台设备后 len() 会回退，下次分配就撞上已存在的地址，
        // 服务端 AllowedIPs 冲突表现为「新设备连上后旧设备莫名断流」。
        let devices = self.db.list_devices(&server_id).await?;
        let vpn_address = allocate_vpn_address(&node.vpn_cidr, &devices)?;

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

    /// 通过 SSH 读取服务端的 WireGuard peer 指标并同步到本地设备记录。
    ///
    /// 设备表只保存展示用的快照，WireGuard 本身才是握手和流量的权威来源。
    /// 只更新能按公钥匹配到的 peer；远端暂时缺失的 peer 保留最后一次已知
    /// 状态，避免服务端短暂故障被误显示为“从未连接”。
    pub async fn refresh_device_runtime(
        &self,
        server_id: String,
    ) -> Result<Vec<Device>, ServiceError> {
        let server = self
            .db
            .get_server(&server_id)
            .await?
            .ok_or_else(|| ServiceError::ServerNotFound(server_id.clone()))?;
        let devices = self.db.list_devices(&server_id).await?;
        if devices.is_empty() {
            return Ok(devices);
        }

        let mut provisioner = open_provisioner_any(&server, &self.cred_dir).await?;
        let peer_stats = parse_wg_dump(&provisioner.get_status_dump().await?);

        let mut refreshed = 0usize;
        for device in &devices {
            if let Some(stats) = peer_stats.get(&device.public_key) {
                self.db
                    .update_device_runtime(
                        &device.id,
                        stats.latest_handshake_at,
                        stats.rx_bytes,
                        stats.tx_bytes,
                    )
                    .await?;
                refreshed += 1;
            }
        }

        info!(server_id=%server_id, refreshed, peer_count=peer_stats.len(), "设备 WireGuard 运行状态已刷新");
        Ok(self.db.list_devices(&server_id).await?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerRuntime {
    latest_handshake_at: Option<i64>,
    rx_bytes: u64,
    tx_bytes: u64,
}

/// 解析 `wg show wg0 dump`。
///
/// 第一行是接口信息；每个 peer 行的字段固定为：公钥、预共享密钥、endpoint、
/// allowed-ips、最近握手、rx、tx、keepalive。格式损坏的行宁可忽略，不能让
/// 单个异常 peer 阻断整个设备列表。
fn parse_wg_dump(dump: &str) -> HashMap<String, PeerRuntime> {
    dump.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            if fields.len() != 8 || fields[0].is_empty() {
                return None;
            }
            let latest_handshake = fields[4].parse::<i64>().ok()?;
            let rx_bytes = fields[5].parse::<u64>().ok()?;
            let tx_bytes = fields[6].parse::<u64>().ok()?;
            Some((
                fields[0].to_string(),
                PeerRuntime {
                    latest_handshake_at: (latest_handshake > 0).then_some(latest_handshake),
                    rx_bytes,
                    tx_bytes,
                },
            ))
        })
        .collect()
}

fn current_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// 从「Ubuntu 24.04」这类检测文案里取版本号
fn parse_os_version(message: &str) -> Option<String> {
    message
        .split_whitespace()
        .find(|tok| tok.contains('.') && tok.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .map(|s| s.to_string())
}

/// 在 VPN 网段内分配首个空闲地址
///
/// `.1` 是服务端网关，客户端从 `.2` 开始。返回带 `/32` 的地址 ——
/// 客户端 peer 的 AllowedIPs 必须是单机地址，给整个网段会抢走其他设备的流量。
fn allocate_vpn_address(vpn_cidr: &str, devices: &[Device]) -> Result<String, ServiceError> {
    // vpn_cidr 形如 "10.66.66.0/24"，取前三段作为前缀
    let base = vpn_cidr.split('/').next().unwrap_or(vpn_cidr);
    let octets: Vec<&str> = base.split('.').collect();
    if octets.len() != 4 {
        return Err(ServiceError::other(format!("VPN 网段格式错误: {vpn_cidr}")));
    }
    let prefix = format!("{}.{}.{}", octets[0], octets[1], octets[2]);

    let used: std::collections::HashSet<&str> = devices
        .iter()
        .map(|d| d.vpn_address.split('/').next().unwrap_or(&d.vpn_address))
        .collect();

    // .1 留给服务端网关，.255 是广播地址
    for host in 2u16..255 {
        let candidate = format!("{prefix}.{host}");
        if !used.contains(candidate.as_str()) {
            return Ok(format!("{candidate}/32"));
        }
    }
    Err(ServiceError::other(format!(
        "{vpn_cidr} 内无空闲地址（已用 {} 个）",
        used.len()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_at(addr: &str) -> Device {
        Device::new(
            "srv".into(),
            "dev".into(),
            DeviceType::Other,
            "pubkey".into(),
            addr.into(),
        )
    }

    #[test]
    fn first_device_gets_dot_two() {
        let addr = allocate_vpn_address("10.66.66.0/24", &[]).unwrap();
        assert_eq!(addr, "10.66.66.2/32");
    }

    #[test]
    fn allocates_sequentially() {
        let devices = vec![device_at("10.66.66.2/32"), device_at("10.66.66.3/32")];
        assert_eq!(
            allocate_vpn_address("10.66.66.0/24", &devices).unwrap(),
            "10.66.66.4/32"
        );
    }

    /// 这是修复的核心 —— 删掉中间设备后必须复用空洞，不能跳到 .4 撞车
    #[test]
    fn reuses_gap_after_deletion() {
        let devices = vec![device_at("10.66.66.2/32"), device_at("10.66.66.4/32")];
        assert_eq!(
            allocate_vpn_address("10.66.66.0/24", &devices).unwrap(),
            "10.66.66.3/32"
        );
    }

    #[test]
    fn respects_custom_cidr() {
        let addr = allocate_vpn_address("10.7.0.0/24", &[]).unwrap();
        assert_eq!(addr, "10.7.0.2/32");
    }

    #[test]
    fn handles_address_without_mask() {
        let devices = vec![device_at("10.66.66.2")];
        assert_eq!(
            allocate_vpn_address("10.66.66.0/24", &devices).unwrap(),
            "10.66.66.3/32"
        );
    }

    #[test]
    fn rejects_malformed_cidr() {
        assert!(allocate_vpn_address("not-a-cidr", &[]).is_err());
    }

    #[test]
    fn errors_when_pool_exhausted() {
        let devices: Vec<Device> = (2u16..255)
            .map(|h| device_at(&format!("10.66.66.{h}/32")))
            .collect();
        assert!(allocate_vpn_address("10.66.66.0/24", &devices).is_err());
    }

    #[test]
    fn parses_os_version() {
        assert_eq!(parse_os_version("Ubuntu 24.04").as_deref(), Some("24.04"));
        assert_eq!(parse_os_version("Ubuntu 22.04").as_deref(), Some("22.04"));
        assert_eq!(parse_os_version("Debian"), None);
    }

    #[test]
    fn parses_wireguard_dump_with_handshake_and_counters() {
        let dump = concat!(
            "server-private\tserver-public\t51820\toff\n",
            "peer-a\t(none)\t203.0.113.1:51820\t10.66.66.2/32\t1785495944\t1449785\t1068600\t25\n",
            "peer-b\t(none)\t(none)\t10.66.66.3/32\t0\t0\t0\t0\n",
            "malformed\tline\n",
        );

        let peers = parse_wg_dump(dump);
        assert_eq!(peers.len(), 2);
        assert_eq!(
            peers.get("peer-a"),
            Some(&PeerRuntime {
                latest_handshake_at: Some(1_785_495_944),
                rx_bytes: 1_449_785,
                tx_bytes: 1_068_600,
            })
        );
        assert_eq!(
            peers.get("peer-b"),
            Some(&PeerRuntime {
                latest_handshake_at: None,
                rx_bytes: 0,
                tx_bytes: 0,
            })
        );
    }
}
