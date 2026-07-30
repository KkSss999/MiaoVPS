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
    /// 机器可读标识 —— 调用方按此匹配，不要用 `name`
    ///
    /// `name` 是给人看的 UI 文案，改一次文案就会静默破坏所有匹配逻辑。
    pub key: DetectKey,
    pub name: String,
    pub status: DetectStatus,
    pub message: String,
    pub suggestion: Option<String>,
}

/// 11 项检测的机器可读标识
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectKey {
    Os,
    Arch,
    Privilege,
    PublicIpv4,
    WireGuard,
    Systemd,
    IpForward,
    Firewall,
    UdpPort,
    Disk,
    Memory,
}

impl DetectKey {
    /// UI 显示名 —— 与 `detection_items()` 保持一致
    pub fn label(&self) -> &'static str {
        match self {
            Self::Os => "操作系统",
            Self::Arch => "架构",
            Self::Privilege => "权限",
            Self::PublicIpv4 => "公网 IPv4",
            Self::WireGuard => "WireGuard",
            Self::Systemd => "systemd",
            Self::IpForward => "网络转发",
            Self::Firewall => "防火墙",
            Self::UdpPort => "UDP 端口",
            Self::Disk => "磁盘空间",
            Self::Memory => "内存",
        }
    }
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

    /// 追加一项检测结果 —— `name` 由 `key.label()` 自动填充
    pub fn add_item(
        &mut self,
        key: DetectKey,
        status: DetectStatus,
        message: &str,
        suggestion: Option<&str>,
    ) {
        self.items.push(DetectItem {
            key,
            name: key.label().into(),
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

    /// 按 key 取某项检测结果
    pub fn item(&self, key: DetectKey) -> Option<&DetectItem> {
        self.items.iter().find(|i| i.key == key)
    }
}

/// 所有 11 项检测的标识和描述
pub fn detection_items() -> Vec<(DetectKey, &'static str)> {
    vec![
        (DetectKey::Os, "Ubuntu 22.04 / 24.04"),
        (DetectKey::Arch, "x86_64 / arm64"),
        (DetectKey::Privilege, "root 或免交互 sudo"),
        (DetectKey::PublicIpv4, "检测公网出口 IP"),
        (DetectKey::WireGuard, "可安装或已安装"),
        (DetectKey::Systemd, "系统服务管理器"),
        (DetectKey::IpForward, "IP Forward 可配置"),
        (DetectKey::Firewall, "UFW / iptables / nftables"),
        (DetectKey::UdpPort, "51820 未被占用"),
        (DetectKey::Disk, "> 200MB"),
        (DetectKey::Memory, "> 256MB"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_item_fills_name_from_key() {
        let mut report = ServerReport::new("s1".into());
        report.add_item(DetectKey::Os, DetectStatus::Pass, "Ubuntu 24.04", None);
        assert_eq!(report.items[0].name, "操作系统");
        assert_eq!(report.items[0].key, DetectKey::Os);
    }

    #[test]
    fn blocked_item_sets_blocked_flag() {
        let mut report = ServerReport::new("s1".into());
        report.add_item(DetectKey::UdpPort, DetectStatus::Blocked, "占用", None);
        report.finalize();
        assert!(report.blocked);
        assert!(!report.all_passed);
    }

    #[test]
    fn warning_does_not_block() {
        let mut report = ServerReport::new("s1".into());
        report.add_item(DetectKey::PublicIpv4, DetectStatus::Warning, "未知", None);
        report.finalize();
        assert!(!report.blocked);
        assert!(report.all_passed);
    }

    #[test]
    fn lookup_by_key() {
        let mut report = ServerReport::new("s1".into());
        report.add_item(DetectKey::Arch, DetectStatus::Pass, "x86_64", None);
        assert_eq!(report.item(DetectKey::Arch).unwrap().message, "x86_64");
        assert!(report.item(DetectKey::Os).is_none());
    }

    /// key 与 label 必须一一对应 —— 漏映射会让 UI 显示错误项名
    #[test]
    fn all_detection_keys_have_distinct_labels() {
        let items = detection_items();
        assert_eq!(items.len(), 11);
        let mut labels: Vec<&str> = items.iter().map(|(k, _)| k.label()).collect();
        labels.sort_unstable();
        let count = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), count, "label 有重复");
    }

    /// snake_case 序列化是前端 TS 类型的契约
    #[test]
    fn key_serializes_snake_case() {
        let json = serde_json::to_string(&DetectKey::PublicIpv4).unwrap();
        assert_eq!(json, "\"public_ipv4\"");
    }
}
