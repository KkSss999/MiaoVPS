//! 应用状态 —— Tauri State 持有的共享对象
//!
//! 数据目录解析必须与 CLI 完全一致，否则前端看到的服务器列表和
//! `miaovps list-servers` 是两份不同的数据。

use miaovps_app::AppService;
use miaovps_storage::Database;
use std::path::PathBuf;
use std::sync::Arc;

pub struct AppState {
    pub service: Arc<AppService>,
    pub data_dir: PathBuf,
}

impl AppState {
    pub async fn init() -> Result<Self, String> {
        let data_dir = data_dir();
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| format!("无法创建数据目录 {}: {e}", data_dir.display()))?;

        let db = Database::open(data_dir.join("miaovps.db"))
            .await
            .map_err(|e| format!("无法打开数据库: {e}"))?;

        Ok(Self {
            service: Arc::new(AppService::new(db, data_dir.join("credentials"))),
            data_dir,
        })
    }
}

/// 数据目录 —— 与 miaovps-cli 的 `data_dir()` 保持同一套解析规则
///
/// 顺序：`MIAOVPS_DATA_DIR` → `SUDO_USER` 反查 → `HOME`。
/// App 正常以普通用户运行，`SUDO_USER` 分支只在开发时 sudo 启动才生效。
pub fn data_dir() -> PathBuf {
    if let Some(custom) = std::env::var_os("MIAOVPS_DATA_DIR") {
        return PathBuf::from(custom);
    }
    real_home().join(".miaovps")
}

fn real_home() -> PathBuf {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            let candidate = PathBuf::from("/Users").join(&sudo_user);
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 CLI 的 data_dir() 必须落到同一处，否则前端和命令行看到两份数据
    #[test]
    fn falls_back_to_home_dot_miaovps() {
        if std::env::var_os("MIAOVPS_DATA_DIR").is_some() {
            return; // 环境有覆盖时这条不适用
        }
        assert!(data_dir().ends_with(".miaovps"));
    }

    #[test]
    fn real_home_is_absolute() {
        assert!(real_home().is_absolute());
    }
}
