//! macOS 菜单栏入口。
//!
//! Dock 图标负责品牌识别，菜单栏只保留 head mark 并提供最快的
//! 节点选择、连接与断开入口。菜单从本地数据库和 profile 实时生成，
//! 不保留任何演示节点。

use crate::profile::ConnectionProfile;
use crate::state::AppState;
use miaovps_app::{TunnelCtl, TunnelMode, TunnelState, TunnelStatus};
use miaovps_core::Server;
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem, Submenu},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager,
};
use tracing::warn;

const TRAY_ID: &str = "miaovps-status";
const SHOW_ID: &str = "tray-show";
const CONNECT_ID: &str = "tray-connect";
const DISCONNECT_ID: &str = "tray-disconnect";
const QUIT_ID: &str = "tray-quit";
const SERVER_ID_PREFIX: &str = "tray-server:";

/// 用户从菜单栏选中的节点。选择只影响快捷入口；真正的私钥配置仍必须
/// 在设备页显式执行，避免菜单栏悄悄替用户切换设备密钥。
#[derive(Default)]
pub struct TrayState {
    selected_server_id: Mutex<Option<String>>,
}

impl TrayState {
    fn selected_server_id(&self) -> Option<String> {
        self.selected_server_id.lock().ok()?.clone()
    }

    fn select(&self, server_id: String) {
        if let Ok(mut selected) = self.selected_server_id.lock() {
            *selected = Some(server_id);
        }
    }
}

/// 初始化常驻菜单栏图标。采用 head mark + macOS template 模式，因此会随
/// 菜单栏浅深色自动反转，且不带 Dock 那种品牌底板。
pub fn init(app: &AppHandle) -> tauri::Result<()> {
    let menu = empty_menu(app)?;
    let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray-head.png"))?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon)
        .icon_as_template(true)
        .tooltip("MiaoVPS")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| handle_menu_event(app, event.id().as_ref()))
        .build(app)?;

    Ok(())
}

/// 由前端查询更新和托盘动作触发。菜单数据始终从 Rust 的本地数据库读取，
/// WebView 只负责请求刷新，不能伪造节点或连接状态。
pub async fn refresh(app: &AppHandle) -> Result<(), String> {
    let (service, data_dir) = {
        let state = app.state::<AppState>();
        (state.service.clone(), state.data_dir.clone())
    };
    let servers = service
        .list_servers()
        .await
        .map_err(|e| format!("读取托盘节点失败: {e}"))?;
    let profile = ConnectionProfile::load(&data_dir).ok();
    let tunnel = tauri::async_runtime::spawn_blocking(move || TunnelState::load(&data_dir))
        .await
        .unwrap_or_else(|_| TunnelState::disconnected());

    let tray_state = app.state::<TrayState>();
    let profile_server_id = profile
        .as_ref()
        .and_then(|profile| server_for_endpoint(&servers, &profile.server_endpoint));
    let selected_server_id = tray_state
        .selected_server_id()
        .filter(|id| servers.iter().any(|server| server.id == *id))
        .or(profile_server_id.clone());

    if tray_state.selected_server_id().is_none() {
        if let Some(server_id) = selected_server_id.clone() {
            tray_state.select(server_id);
        }
    }

    let menu = build_menu(
        app,
        &servers,
        selected_server_id.as_deref(),
        profile_server_id.as_deref(),
        &tunnel,
    )
    .map_err(|e| format!("构建托盘菜单失败: {e}"))?;
    let tray = app
        .tray_by_id(TRAY_ID)
        .ok_or_else(|| "菜单栏图标未初始化".to_string())?;
    tray.set_menu(Some(menu))
        .map_err(|e| format!("更新托盘菜单失败: {e}"))?;
    tray.set_tooltip(Some(tray_tooltip(&tunnel)))
        .map_err(|e| format!("更新托盘提示失败: {e}"))?;
    Ok(())
}

fn empty_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let status = MenuItem::with_id(
        app,
        "tray-status",
        "MiaoVPS · 正在加载",
        false,
        None::<&str>,
    )?;
    let open = MenuItem::with_id(app, SHOW_ID, "打开 MiaoVPS", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, QUIT_ID, "退出 MiaoVPS", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    Menu::with_items(app, &[&status, &separator, &open, &quit])
}

fn build_menu(
    app: &AppHandle,
    servers: &[Server],
    selected_server_id: Option<&str>,
    profile_server_id: Option<&str>,
    tunnel: &TunnelState,
) -> tauri::Result<Menu<tauri::Wry>> {
    let status = MenuItem::with_id(
        app,
        "tray-status",
        format!("状态：{}", tunnel_label(tunnel.status)),
        false,
        None::<&str>,
    )?;
    let nodes = Submenu::with_id(app, "tray-nodes", "选择 VPS 节点", true)?;
    if servers.is_empty() {
        let empty = MenuItem::with_id(app, "tray-empty", "还没有添加 VPS", false, None::<&str>)?;
        nodes.append(&empty)?;
    } else {
        for server in servers {
            let selected = selected_server_id == Some(server.id.as_str());
            let marker = if selected { "✓ " } else { "  " };
            let item = MenuItem::with_id(
                app,
                format!("{SERVER_ID_PREFIX}{}", server.id),
                format!(
                    "{marker}{} · {}",
                    server.name,
                    node_status_label(&server.status)
                ),
                true,
                None::<&str>,
            )?;
            nodes.append(&item)?;
        }
    }

    let selected_matches_profile =
        selected_server_id.is_some() && selected_server_id == profile_server_id;
    let can_connect = selected_matches_profile
        && matches!(
            tunnel.status,
            TunnelStatus::Disconnected | TunnelStatus::Stale | TunnelStatus::FallbackDirect
        );
    let connect_text = if selected_server_id.is_none() {
        "连接（先选择节点）"
    } else if !selected_matches_profile {
        "连接（先在设备页设为本机连接）"
    } else {
        "连接（完整隧道）"
    };
    let connect = MenuItem::with_id(app, CONNECT_ID, connect_text, can_connect, None::<&str>)?;
    let can_disconnect = !matches!(
        tunnel.status,
        TunnelStatus::Disconnected | TunnelStatus::External
    );
    let disconnect =
        MenuItem::with_id(app, DISCONNECT_ID, "断开连接", can_disconnect, None::<&str>)?;
    let open = MenuItem::with_id(app, SHOW_ID, "打开 MiaoVPS", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, QUIT_ID, "退出 MiaoVPS", true, None::<&str>)?;
    let separator_a = PredefinedMenuItem::separator(app)?;
    let separator_b = PredefinedMenuItem::separator(app)?;

    Menu::with_items(
        app,
        &[
            &status,
            &separator_a,
            &nodes,
            &connect,
            &disconnect,
            &separator_b,
            &open,
            &quit,
        ],
    )
}

fn handle_menu_event(app: &AppHandle, id: &str) {
    if let Some(server_id) = id.strip_prefix(SERVER_ID_PREFIX) {
        app.state::<TrayState>().select(server_id.to_string());
        let _ = app.emit("tray-select-server", server_id);
        show_main_window(app);
        refresh_later(app.clone());
        return;
    }

    match id {
        SHOW_ID => show_main_window(app),
        QUIT_ID => app.exit(0),
        CONNECT_ID => {
            let data_dir = app.state::<AppState>().data_dir.clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let result = tauri::async_runtime::spawn_blocking(move || {
                    TunnelCtl::new(data_dir)?.connect(TunnelMode::Full)
                })
                .await;
                match result {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => warn!("托盘连接失败: {error}"),
                    Err(error) => warn!("托盘连接任务异常: {error}"),
                }
                refresh_later(app_handle);
            });
        }
        DISCONNECT_ID => {
            let data_dir = app.state::<AppState>().data_dir.clone();
            let app_handle = app.clone();
            tauri::async_runtime::spawn(async move {
                let result = tauri::async_runtime::spawn_blocking(move || {
                    TunnelCtl::new(data_dir)?.disconnect()
                })
                .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => warn!("托盘断开失败: {error}"),
                    Err(error) => warn!("托盘断开任务异常: {error}"),
                }
                refresh_later(app_handle);
            });
        }
        _ => {}
    }
}

fn refresh_later(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        if let Err(error) = refresh(&app).await {
            warn!("刷新托盘菜单失败: {error}");
        }
    });
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn server_for_endpoint(servers: &[Server], endpoint: &str) -> Option<String> {
    let host = endpoint.split(':').next()?;
    servers
        .iter()
        .find(|server| server.host == host || server.public_ipv4.as_deref() == Some(host))
        .map(|server| server.id.clone())
}

fn tunnel_label(status: TunnelStatus) -> &'static str {
    match status {
        TunnelStatus::Disconnected => "未连接",
        TunnelStatus::Connecting => "连接中",
        TunnelStatus::Connected => "已连接",
        TunnelStatus::Reconnecting => "重连中",
        TunnelStatus::FallbackDirect => "已回落直连",
        TunnelStatus::Stale => "连接异常",
        TunnelStatus::External => "外部终端连接中",
    }
}

fn node_status_label(status: &miaovps_core::ServerStatus) -> &'static str {
    match status {
        miaovps_core::ServerStatus::PendingInspection => "待检测",
        miaovps_core::ServerStatus::Added => "可部署",
        miaovps_core::ServerStatus::Deploying => "部署中",
        miaovps_core::ServerStatus::Online => "已部署",
        miaovps_core::ServerStatus::NeedsAttention => "需处理检测项",
        miaovps_core::ServerStatus::Offline => "离线",
        miaovps_core::ServerStatus::ConfigBroken => "配置异常",
        miaovps_core::ServerStatus::Incomplete => "部署未完成",
    }
}

fn tray_tooltip(tunnel: &TunnelState) -> String {
    format!("MiaoVPS · {}", tunnel_label(tunnel.status))
}
