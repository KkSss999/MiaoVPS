//! Tauri commands —— 前端唯一的后端入口
//!
//! 每个 command 都只做三件事：解参数、调 AppService、把错误转成 ErrorDto。
//! 业务逻辑一律留在 miaovps-app，这样 CLI 和前端行为不会漂移。

use crate::profile::{self, ConnectionProfile, ProfileSummary};
use crate::state::AppState;
use miaovps_app::credentials::ServerCredential;
use miaovps_app::tunnel::{TunnelMode, TunnelState};
use miaovps_app::{ErrorDto, TunnelCtl, TunnelCtlError};
use miaovps_core::{Device, DeviceType, Server, SshAuthType, WireGuardNode};
use miaovps_provisioner::{DeploymentOptions, DeploymentProgress, ServerReport, StepEvent};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tracing::{info, warn};

/// command 统一返回类型
type CmdResult<T> = Result<T, ErrorDto>;

fn dto(code: &str, message: impl Into<String>) -> ErrorDto {
    ErrorDto {
        code: code.to_string(),
        message: message.into(),
    }
}

impl From<TunnelCtlError> for ErrorDtoWrap {
    fn from(e: TunnelCtlError) -> Self {
        ErrorDtoWrap(ErrorDto {
            code: e.code().to_string(),
            message: e.to_string(),
        })
    }
}

/// 本地 newtype —— 孤儿规则不允许直接给外部 ErrorDto 实现 From<外部错误>
pub struct ErrorDtoWrap(pub ErrorDto);

impl From<profile::ProfileError> for ErrorDtoWrap {
    fn from(e: profile::ProfileError) -> Self {
        ErrorDtoWrap(dto("profile_error", e.to_string()))
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Server
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn list_servers(state: State<'_, AppState>) -> CmdResult<Vec<Server>> {
    state.service.list_servers().await.map_err(Into::into)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn add_server(
    state: State<'_, AppState>,
    name: String,
    host: String,
    port: u16,
    user: String,
    auth_type: SshAuthType,
    password: Option<String>,
    key_path: Option<String>,
    passphrase: Option<String>,
) -> CmdResult<Server> {
    // 凭据必须给 —— 没凭据的服务器记录建了也连不上，
    // 后面 inspect/deploy 全会失败，不如在这里挡住
    let credential = match auth_type {
        SshAuthType::Password => {
            let pw = password
                .filter(|p| !p.is_empty())
                .ok_or_else(|| dto("credential_error", "密码认证需要填写密码"))?;
            ServerCredential::Password { password: pw }
        }
        SshAuthType::PrivateKey => {
            let path = key_path
                .filter(|p| !p.is_empty())
                .ok_or_else(|| dto("credential_error", "私钥认证需要选择私钥文件"))?;
            if !std::path::Path::new(&expand_tilde(&path)).is_file() {
                return Err(dto("credential_error", format!("私钥文件不存在: {path}")));
            }
            ServerCredential::PrivateKey {
                key_path: path,
                passphrase: passphrase.filter(|p| !p.is_empty()),
            }
        }
        SshAuthType::SshAgent => {
            return Err(dto("credential_error", "SSH Agent 认证尚未实现"));
        }
    };

    state
        .service
        .add_server(name, host, port, user, auth_type, credential)
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn remove_server(state: State<'_, AppState>, server_id: String) -> CmdResult<()> {
    // 设备记录由外键 ON DELETE CASCADE 一起清掉；凭据文件要手动删
    state
        .service
        .db
        .delete_server(&server_id)
        .await
        .map_err(|e| dto("storage_error", e.to_string()))?;
    let cred_file = state.service.cred_dir.join(format!("{server_id}.json"));
    if let Err(e) = std::fs::remove_file(&cred_file) {
        if e.kind() != std::io::ErrorKind::NotFound {
            warn!("凭据文件删除失败 {}: {e}", cred_file.display());
        }
    }
    info!(server_id = %server_id, "服务器已删除");
    Ok(())
}

#[tauri::command]
pub async fn inspect_server(
    state: State<'_, AppState>,
    server_id: String,
) -> CmdResult<ServerReport> {
    state
        .service
        .inspect_server(server_id)
        .await
        .map_err(Into::into)
}

/// 部署 WireGuard —— 九步进度经 `deploy-progress` 事件实时推送
#[tauri::command]
pub async fn deploy_server(
    app: AppHandle,
    state: State<'_, AppState>,
    server_id: String,
    options: Option<DeploymentOptions>,
) -> CmdResult<DeploymentProgress> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<StepEvent>();

    // 转发任务：channel → Tauri 事件。tx 被 deploy_server 消费并 drop 后自然结束
    let forwarder = app.clone();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let Err(e) = forwarder.emit("deploy-progress", &ev) {
                warn!("部署进度事件发送失败: {e}");
            }
        }
    });

    state
        .service
        .deploy_server(server_id, options, Some(tx))
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn server_status(state: State<'_, AppState>, server_id: String) -> CmdResult<String> {
    state
        .service
        .server_status(server_id)
        .await
        .map_err(Into::into)
}

#[tauri::command]
pub async fn get_wg_node(
    state: State<'_, AppState>,
    server_id: String,
) -> CmdResult<Option<WireGuardNode>> {
    state
        .service
        .db
        .get_wg_node(&server_id)
        .await
        .map_err(|e| dto("storage_error", e.to_string()))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Device
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub async fn list_devices(
    state: State<'_, AppState>,
    server_id: String,
) -> CmdResult<Vec<Device>> {
    state
        .service
        .list_devices(server_id)
        .await
        .map_err(Into::into)
}

#[derive(Serialize)]
pub struct AddDeviceResult {
    pub device: Device,
    pub config: String,
}

#[tauri::command]
pub async fn add_device(
    state: State<'_, AppState>,
    server_id: String,
    name: String,
    device_type: DeviceType,
) -> CmdResult<AddDeviceResult> {
    let (device, config) = state
        .service
        .add_device(server_id, name, device_type)
        .await?;
    Ok(AddDeviceResult { device, config })
}

#[tauri::command]
pub async fn remove_device(state: State<'_, AppState>, device_id: String) -> CmdResult<()> {
    state
        .service
        .db
        .delete_device(&device_id)
        .await
        .map_err(|e| dto("storage_error", e.to_string()))?;
    info!(device_id = %device_id, "设备已删除");
    Ok(())
}

#[tauri::command]
pub async fn export_config(state: State<'_, AppState>, device_id: String) -> CmdResult<String> {
    state
        .service
        .export_config(device_id)
        .await
        .map_err(Into::into)
}

/// 把配置写到用户选定路径
///
/// 配置里含客户端私钥，所以落盘后立刻收权限到 0600。
#[tauri::command]
pub async fn save_config_file(path: String, contents: String) -> CmdResult<()> {
    std::fs::write(&path, contents).map_err(|e| dto("io_error", format!("写入失败: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  本机隧道
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[tauri::command]
pub fn tunnel_status(state: State<'_, AppState>) -> TunnelState {
    TunnelState::load(&state.data_dir)
}

#[tauri::command]
pub fn tunnel_connect(state: State<'_, AppState>, mode: TunnelMode) -> CmdResult<TunnelState> {
    let ctl = TunnelCtl::new(state.data_dir.clone()).map_err(|e| ErrorDtoWrap::from(e).0)?;
    ctl.connect(mode).map_err(|e| ErrorDtoWrap::from(e).0)
}

#[tauri::command]
pub fn tunnel_disconnect(state: State<'_, AppState>) -> CmdResult<()> {
    let ctl = TunnelCtl::new(state.data_dir.clone()).map_err(|e| ErrorDtoWrap::from(e).0)?;
    ctl.disconnect().map_err(|e| ErrorDtoWrap::from(e).0)
}

#[tauri::command]
pub fn profile_summary(state: State<'_, AppState>) -> ProfileSummary {
    match ConnectionProfile::load(&state.data_dir) {
        Ok(p) => p.summary(),
        Err(_) => ProfileSummary::missing(),
    }
}

/// 用某台设备的凭据初始化本机 profile
///
/// 这一步是「部署完成」到「一键连接」之间缺失的桥。CLI 需要用户手工
/// 复制私钥跑 `profile init`，前端必须自动完成。
///
/// 覆盖前不做确认 —— 本机同时只能有一个隧道配置，切换节点就是覆盖。
#[tauri::command]
pub async fn use_device_as_local(
    state: State<'_, AppState>,
    device_id: String,
) -> CmdResult<ProfileSummary> {
    let device = state
        .service
        .db
        .get_device(&device_id)
        .await
        .map_err(|e| dto("storage_error", e.to_string()))?
        .ok_or_else(|| dto("device_not_found", format!("设备不存在: {device_id}")))?;

    let server = state
        .service
        .db
        .get_server(&device.server_id)
        .await
        .map_err(|e| dto("storage_error", e.to_string()))?
        .ok_or_else(|| dto("server_not_found", "设备关联的服务器已不存在"))?;

    let node = state
        .service
        .db
        .get_wg_node(&device.server_id)
        .await
        .map_err(|e| dto("storage_error", e.to_string()))?
        .ok_or_else(|| dto("wg_node_not_found", "该服务器尚未部署 WireGuard"))?;

    // 私钥从 Keychain 取 —— 数据库里只有引用
    let key_ref = device
        .private_key_ref
        .as_deref()
        .ok_or_else(|| dto("credential_error", "该设备没有保存私钥，无法用于本机连接"))?;
    let private_key = miaovps_storage::keychain::WgKeyStore::load(key_ref)
        .map_err(|e| dto("credential_error", format!("私钥读取失败: {e}")))?;

    // 公钥由私钥推导，不信数据库里存的那份 —— 不自洽的话握手会被静默丢弃
    let derived = profile::derive_public_key(&private_key).map_err(|e| ErrorDtoWrap::from(e).0)?;
    if derived != device.public_key {
        return Err(dto(
            "credential_error",
            "设备的公私钥不匹配，请删除该设备后重新添加",
        ));
    }

    // 公网 IP 优先用检测结果，回落到 SSH 主机名 —— 后者可能是域名，
    // 但 profile 的 endpoint 需要 IP:PORT 能 parse 成 SocketAddr
    let endpoint_host = server
        .public_ipv4
        .clone()
        .unwrap_or_else(|| server.host.clone());

    let prof = ConnectionProfile {
        client_private_key: private_key,
        client_public_key: derived,
        server_public_key: node.server_public_key.clone(),
        server_endpoint: format!("{}:{}", endpoint_host, node.listen_port),
        client_ip: profile::strip_mask(&device.vpn_address).to_string(),
        peer_ip: profile::gateway_of(&node.vpn_cidr).map_err(|e| ErrorDtoWrap::from(e).0)?,
        netmask: "255.255.255.0".into(),
        // MTU 必须与服务端 wg0 一致，否则大包静默丢弃
        mtu: node.mtu.unwrap_or(1380),
        dns: node.dns.clone(),
    };

    prof.save(&state.data_dir)
        .map_err(|e| ErrorDtoWrap::from(e).0)?;
    info!(device_id = %device_id, "本机连接配置已更新");
    Ok(prof.summary())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  杂项
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Serialize)]
pub struct AppInfo {
    pub version: String,
    pub data_dir: String,
    pub cli_available: bool,
    pub cli_path: Option<String>,
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    // 隧道控制依赖已安装的 miaovps CLI —— 缺了要在设置页明确提示
    let cli = TunnelCtl::new(state.data_dir.clone()).ok();
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        data_dir: state.data_dir.display().to_string(),
        cli_available: cli.is_some(),
        cli_path: which_miaovps(),
    }
}

fn which_miaovps() -> Option<String> {
    if let Some(home) = std::env::var_os("HOME") {
        let p = std::path::Path::new(&home).join(".cargo/bin/miaovps");
        if p.is_file() {
            return Some(p.display().to_string());
        }
    }
    None
}

/// 展开路径开头的 `~`
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::Path::new(&home)
                .join(rest)
                .display()
                .to_string();
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_home_prefix() {
        std::env::set_var("HOME", "/Users/tester");
        assert_eq!(expand_tilde("~/.ssh/id_ed25519"), "/Users/tester/.ssh/id_ed25519");
    }

    #[test]
    fn leaves_absolute_path_untouched() {
        assert_eq!(expand_tilde("/tmp/key.pem"), "/tmp/key.pem");
        // 只展开开头的 ~/，路径中间的 ~ 是合法文件名
        assert_eq!(expand_tilde("/tmp/~weird"), "/tmp/~weird");
    }

    #[test]
    fn tunnel_ctl_error_maps_to_stable_code() {
        let wrapped = ErrorDtoWrap::from(TunnelCtlError::AuthCancelled);
        assert_eq!(wrapped.0.code, "auth_cancelled");
        let wrapped = ErrorDtoWrap::from(TunnelCtlError::ProfileMissing);
        assert_eq!(wrapped.0.code, "profile_missing");
    }
}
