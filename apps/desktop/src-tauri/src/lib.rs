//! MiaoVPS 桌面端 Tauri 后端
//!
//! 只做 IPC 转发：业务逻辑在 `miaovps-app`，数据平面在 `miaovps-connect`
//! （由独立的 root 进程承载，见 `miaovps_app::tunnel_ctl`）。

pub mod commands;
pub mod profile;
pub mod state;

use state::AppState;
use tauri::Manager;

pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("miaovps=info")),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            // 数据库初始化是 async 的，但 setup 是同步的 —— 借 Tauri 的
            // runtime 阻塞等一下。失败就直接退出，带着坏状态起界面更糟。
            let state = tauri::async_runtime::block_on(AppState::init())
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_servers,
            commands::add_server,
            commands::remove_server,
            commands::inspect_server,
            commands::deploy_server,
            commands::server_status,
            commands::get_wg_node,
            commands::list_devices,
            commands::add_device,
            commands::remove_device,
            commands::export_config,
            commands::save_config_file,
            commands::tunnel_status,
            commands::tunnel_connect,
            commands::tunnel_disconnect,
            commands::profile_summary,
            commands::use_device_as_local,
            commands::app_info,
        ])
        .run(tauri::generate_context!())
        .expect("Tauri 应用启动失败");
}
