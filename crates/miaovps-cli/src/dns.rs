//! Full Tunnel 的 DNS 接管 — 防止 DNS 查询泄露到 ISP
//!
//! 只切路由不改 DNS 时，系统仍然把查询发给本地路由器（如 192.168.1.1）。
//! 本地网段的接口路由比隧道的 0/1 更具体，所以这些查询**不会**进隧道 —
//! 结果是 IP 流量走 VPN、DNS 明文走 ISP，暴露了全部访问域名。
//!
//! 这里在启用 Full Tunnel 时把 DNS 指向隧道内的解析器，退出时还原。
//!
//! ## 还原保证
//!
//! 原始配置在切换前抓取并保存到磁盘（`dns-backup.json`）。即使进程被
//! `kill -9`，下一次 `miaovps disconnect` 也能从备份文件恢复 —
//! 否则用户会留下一台 DNS 指向已关闭隧道的机器，表现为完全无法上网。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// `networksetup` 在无自定义 DNS 时返回的字面量
const NO_DNS_SENTINEL: &str = "There aren't any DNS Servers set on";

/// DNS 原始状态备份
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBackup {
    /// 网络服务名（如 "Wi-Fi"）
    pub service: String,
    /// 原始 DNS 服务器列表；空表示原本是 DHCP 自动获取
    pub servers: Vec<String>,
}

impl DnsBackup {
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("dns-backup.json")
    }

    /// 抓取当前活动网络服务的 DNS 设置
    pub fn capture(data_dir: &Path) -> Result<Self> {
        let service = active_service()?;
        let output = Command::new("networksetup")
            .args(["-getdnsservers", &service])
            .output()
            .context("无法执行 networksetup")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let servers = if stdout.contains(NO_DNS_SENTINEL) {
            Vec::new() // 原本是 DHCP 自动
        } else {
            stdout
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        };

        let backup = Self { service, servers };
        backup.persist(data_dir)?;
        Ok(backup)
    }

    fn persist(&self, data_dir: &Path) -> Result<()> {
        let path = Self::path(data_dir);
        std::fs::write(&path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("无法写入 DNS 备份 {}", path.display()))?;
        Ok(())
    }

    /// 从磁盘加载备份（用于崩溃后恢复）
    pub fn load(data_dir: &Path) -> Option<Self> {
        let raw = std::fs::read_to_string(Self::path(data_dir)).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// 描述原始状态，用于日志
    pub fn describe(&self) -> String {
        if self.servers.is_empty() {
            format!("{} (DHCP 自动)", self.service)
        } else {
            format!("{} ({})", self.service, self.servers.join(", "))
        }
    }

    /// 还原到原始 DNS 设置，并删除备份文件
    pub fn restore(&self, data_dir: &Path) -> Result<()> {
        // 空列表要还原成 "Empty" — networksetup 用这个关键字表示回到 DHCP
        let args: Vec<&str> = if self.servers.is_empty() {
            vec!["-setdnsservers", &self.service, "Empty"]
        } else {
            let mut a = vec!["-setdnsservers", self.service.as_str()];
            a.extend(self.servers.iter().map(|s| s.as_str()));
            a
        };

        let output = Command::new("networksetup")
            .args(&args)
            .output()
            .context("无法执行 networksetup 还原 DNS")?;

        if !output.status.success() {
            anyhow::bail!(
                "DNS 还原失败: {}\n手动修复: sudo networksetup -setdnsservers {} {}",
                String::from_utf8_lossy(&output.stderr).trim(),
                self.service,
                if self.servers.is_empty() { "Empty".into() } else { self.servers.join(" ") }
            );
        }

        let _ = std::fs::remove_file(Self::path(data_dir));
        Ok(())
    }
}

/// 把 DNS 指向隧道内解析器
pub fn apply(servers: &[String]) -> Result<()> {
    if servers.is_empty() {
        anyhow::bail!("未配置 DNS 服务器，无法接管");
    }
    let service = active_service()?;

    let mut args = vec!["-setdnsservers", service.as_str()];
    args.extend(servers.iter().map(|s| s.as_str()));

    let output = Command::new("networksetup")
        .args(&args)
        .output()
        .context("无法执行 networksetup 设置 DNS")?;

    if !output.status.success() {
        anyhow::bail!(
            "DNS 设置失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// 崩溃恢复：若存在备份则还原
pub fn restore_if_pending(data_dir: &Path) -> Option<String> {
    let backup = DnsBackup::load(data_dir)?;
    match backup.restore(data_dir) {
        Ok(()) => Some(backup.describe()),
        Err(e) => {
            eprintln!("  ⚠ DNS 还原失败: {e}");
            None
        }
    }
}

/// 找到当前默认路由对应的网络服务名
///
/// `networksetup` 只认服务名（"Wi-Fi"），而路由表给的是设备名（"en0"），
/// 需要通过服务顺序列表做映射。
fn active_service() -> Result<String> {
    let device = default_route_device()?;

    let output = Command::new("networksetup")
        .arg("-listnetworkserviceorder")
        .output()
        .context("无法列出网络服务")?;
    let listing = String::from_utf8_lossy(&output.stdout);

    // 输出形如:
    //   (4) Wi-Fi
    //   (Hardware Port: Wi-Fi, Device: en0)
    let mut current_name: Option<String> = None;
    for line in listing.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('(') {
            if let Some((idx, name)) = rest.split_once(')') {
                if idx.chars().all(|c| c.is_ascii_digit()) {
                    current_name = Some(name.trim().to_string());
                    continue;
                }
            }
        }
        if trimmed.contains(&format!("Device: {device}")) {
            if let Some(name) = current_name.take() {
                return Ok(name);
            }
        }
    }

    anyhow::bail!("无法把设备 {device} 映射到网络服务名")
}

/// 默认路由使用的物理设备
fn default_route_device() -> Result<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .context("无法读取默认路由")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("默认路由没有关联设备 — 当前无网络连接"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_roundtrip_through_disk() {
        let dir = std::env::temp_dir().join(format!("miaovps-dns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let backup = DnsBackup {
            service: "Wi-Fi".into(),
            servers: vec!["223.5.5.5".into()],
        };
        backup.persist(&dir).unwrap();

        let loaded = DnsBackup::load(&dir).unwrap();
        assert_eq!(loaded.service, "Wi-Fi");
        assert_eq!(loaded.servers, vec!["223.5.5.5"]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn describes_dhcp_state() {
        let dhcp = DnsBackup { service: "Wi-Fi".into(), servers: vec![] };
        assert_eq!(dhcp.describe(), "Wi-Fi (DHCP 自动)");

        let custom = DnsBackup {
            service: "Wi-Fi".into(),
            servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
        };
        assert_eq!(custom.describe(), "Wi-Fi (1.1.1.1, 8.8.8.8)");
    }

    #[test]
    fn load_returns_none_without_backup() {
        let empty = std::env::temp_dir().join("miaovps-dns-nonexistent-xyz");
        assert!(DnsBackup::load(&empty).is_none());
    }

    #[test]
    fn apply_rejects_empty_server_list() {
        assert!(apply(&[]).is_err());
    }

    /// active_service 依赖真机网络状态，只断言它不 panic
    #[test]
    fn active_service_does_not_panic() {
        let _ = active_service();
    }
}
