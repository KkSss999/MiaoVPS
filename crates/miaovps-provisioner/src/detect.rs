//! 环境检测
//!
//! 11 项服务器环境检测，返回通过/警告/阻塞结果。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectStatus {
    Pass,
    Warning,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectItem {
    pub name: String,
    pub status: DetectStatus,
    pub message: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerReport {
    pub server_id: String,
    pub items: Vec<DetectItem>,
    pub all_passed: bool,
    pub blocked: bool,
}

impl ServerReport {
    pub fn new(server_id: String) -> Self {
        Self {
            server_id,
            items: Vec::new(),
            all_passed: false,
            blocked: false,
        }
    }

    pub fn add_item(&mut self, name: &str, status: DetectStatus, message: &str, suggestion: Option<&str>) {
        self.items.push(DetectItem {
            name: name.into(),
            status: status.clone(),
            message: message.into(),
            suggestion: suggestion.map(|s| s.into()),
        });
        if status == DetectStatus::Blocked {
            self.blocked = true;
        }
    }

    pub fn finalize(&mut self) {
        self.all_passed = self.items.iter().all(|i| i.status != DetectStatus::Blocked);
    }
}

/// 所有 11 项检测的名称和描述
pub fn detection_items() -> Vec<(&'static str, &'static str)> {
    vec![
        ("操作系统", "Ubuntu 22.04 / 24.04"),
        ("架构", "x86_64 / arm64"),
        ("权限", "root 或免交互 sudo"),
        ("公网 IPv4", "检测公网出口 IP"),
        ("WireGuard", "可安装或已安装"),
        ("systemd", "系统服务管理器"),
        ("网络转发", "IP Forward 可配置"),
        ("防火墙", "UFW / iptables / nftables"),
        ("UDP 端口", "51820 未被占用"),
        ("磁盘空间", "> 200MB"),
        ("内存", "> 256MB"),
    ]
}
