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
//!
//! ## 平台
//!
//! - **macOS**：`networksetup` 按「网络服务」改 DNS。服务名（"Wi-Fi"）与
//!   设备名（"en0"）不同，需要从服务顺序列表做映射。
//! - **Linux**：优先 systemd-resolved（`resolvectl` 按接口设置，接口消失时
//!   resolved 自动丢弃配置，因此备份里只需记住接口名）；没有 resolved
//!   且 `/etc/resolv.conf` 是普通文件时，才改写它并整份备份。
//!   两者都不成立就拒绝接管 —— 改了却无法还原比 DNS 泄露更糟。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// DNS 原始状态备份
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBackup {
    /// macOS：网络服务名（如 "Wi-Fi"）；Linux + resolved：接口名（如 "tun0"）；
    /// Linux 直接改写 resolv.conf 时为空字符串
    pub service: String,
    /// 原始 DNS 服务器列表；空表示原本是 DHCP 自动获取
    pub servers: Vec<String>,
    /// Linux 改写 /etc/resolv.conf 时的原始全文
    ///
    /// 只记 nameserver 行会丢掉 search / options，还原时等于改坏用户的配置。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    raw: Option<String>,
}

impl DnsBackup {
    fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("dns-backup.json")
    }

    fn persist(&self, data_dir: &Path) -> Result<()> {
        let path = Self::path(data_dir);
        std::fs::write(&path, serde_json::to_string_pretty(self)?)
            .with_context(|| format!("无法写入 DNS 备份 {}", path.display()))
    }

    /// 从磁盘加载备份（用于崩溃后恢复）
    pub fn load(data_dir: &Path) -> Option<Self> {
        let raw = std::fs::read_to_string(Self::path(data_dir)).ok()?;
        serde_json::from_str(&raw).ok()
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Command, Context, DnsBackup, Path, Result};

    /// `networksetup` 在无自定义 DNS 时返回的字面量
    const NO_DNS_SENTINEL: &str = "There aren't any DNS Servers set on";

    /// 抓取当前活动网络服务的 DNS 设置
    ///
    /// `tun_name` 在 macOS 上用不到 —— 这里改的是物理网络服务。
    pub fn capture(data_dir: &Path, _tun_name: &str) -> Result<DnsBackup> {
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

        let backup = DnsBackup {
            service,
            servers,
            raw: None,
        };
        backup.persist(data_dir)?;
        Ok(backup)
    }

    /// 还原到原始 DNS 设置，并删除备份文件
    pub fn restore(backup: &DnsBackup, data_dir: &Path) -> Result<()> {
        // 空列表要还原成 "Empty" — networksetup 用这个关键字表示回到 DHCP
        let args: Vec<&str> = if backup.servers.is_empty() {
            vec!["-setdnsservers", &backup.service, "Empty"]
        } else {
            let mut a = vec!["-setdnsservers", backup.service.as_str()];
            a.extend(backup.servers.iter().map(|s| s.as_str()));
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
                backup.service,
                if backup.servers.is_empty() {
                    "Empty".into()
                } else {
                    backup.servers.join(" ")
                }
            );
        }

        let _ = std::fs::remove_file(DnsBackup::path(data_dir));
        Ok(())
    }

    /// 把 DNS 指向隧道内解析器
    pub fn apply(servers: &[String], _tun_name: &str) -> Result<()> {
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

    pub fn describe(backup: &DnsBackup) -> String {
        if backup.servers.is_empty() {
            format!("{} (DHCP 自动)", backup.service)
        } else {
            format!("{} ({})", backup.service, backup.servers.join(", "))
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
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Command, Context, DnsBackup, Path, Result};

    const RESOLV_CONF: &str = "/etc/resolv.conf";

    /// 接口是否还存在 —— TUN 销毁后 resolved 的 per-link 配置也一起消失
    pub(super) fn interface_exists(name: &str) -> bool {
        Path::new("/sys/class/net").join(name).exists()
    }

    /// systemd-resolved 是否在跑 —— 它启动时会创建这个运行时目录
    fn resolved_active() -> bool {
        Path::new("/run/systemd/resolve").is_dir()
    }

    /// resolv.conf 是不是我们可以安全改写的普通文件
    ///
    /// 符号链接（NetworkManager / resolved 管理的）由别人维护，写进去会被
    /// 覆盖或直接写坏 stub 配置，那种情况宁可不接管 DNS。
    fn resolv_conf_editable() -> bool {
        std::fs::symlink_metadata(RESOLV_CONF)
            .map(|m| m.file_type().is_file())
            .unwrap_or(false)
    }

    pub fn capture(data_dir: &Path, tun_name: &str) -> Result<DnsBackup> {
        let backup = if resolved_active() {
            // 接口消失时 resolved 会自动丢弃 per-link 配置，备份只需记接口名
            DnsBackup {
                service: tun_name.to_string(),
                servers: Vec::new(),
                raw: None,
            }
        } else if resolv_conf_editable() {
            let raw = std::fs::read_to_string(RESOLV_CONF)
                .with_context(|| format!("无法读取 {RESOLV_CONF}"))?;
            DnsBackup {
                servers: super::parse_nameservers(&raw),
                service: String::new(),
                raw: Some(raw),
            }
        } else {
            anyhow::bail!(
                "未发现运行中的 systemd-resolved，{RESOLV_CONF} 也不是普通文件 —— 无法可靠还原 DNS"
            );
        };

        backup.persist(data_dir)?;
        Ok(backup)
    }

    pub fn restore(backup: &DnsBackup, data_dir: &Path) -> Result<()> {
        if !backup.service.is_empty() {
            // 隧道进程退出时 TUN 已经销毁，resolved 也随之丢弃了 per-link
            // 配置，此时 revert 必然报 "Failed to resolve interface"。
            // 判据用设备节点是否存在，而不是匹配 resolvectl 的错误文案 ——
            // 文案会被本地化，中文系统上就是「没有那个设备」。
            if interface_exists(&backup.service) {
                let output = Command::new("resolvectl")
                    .args(["revert", &backup.service])
                    .output()
                    .context("无法执行 resolvectl 还原 DNS")?;
                if !output.status.success() {
                    anyhow::bail!(
                        "DNS 还原失败: {}\n手动修复: sudo resolvectl revert {}",
                        String::from_utf8_lossy(&output.stderr).trim(),
                        backup.service
                    );
                }
            }
        } else if let Some(raw) = &backup.raw {
            std::fs::write(RESOLV_CONF, raw)
                .with_context(|| format!("无法写回 {RESOLV_CONF}"))?;
        }

        let _ = std::fs::remove_file(DnsBackup::path(data_dir));
        Ok(())
    }

    pub fn apply(servers: &[String], tun_name: &str) -> Result<()> {
        if resolved_active() {
            let mut args = vec!["dns", tun_name];
            args.extend(servers.iter().map(|s| s.as_str()));
            let output = Command::new("resolvectl")
                .args(&args)
                .output()
                .context("无法执行 resolvectl 设置 DNS")?;
            if !output.status.success() {
                anyhow::bail!(
                    "DNS 设置失败: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }

            // "~." 把所有域名都路由到隧道接口 —— 只设 dns 不改 domain 时，
            // 本地网段的 per-link DNS 仍然优先，查询继续泄露给 ISP。
            let output = Command::new("resolvectl")
                .args(["domain", tun_name, "~."])
                .output()
                .context("无法执行 resolvectl 设置域名路由")?;
            if !output.status.success() {
                anyhow::bail!(
                    "DNS 域名路由设置失败: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            return Ok(());
        }

        if resolv_conf_editable() {
            let content: String = servers.iter().map(|s| format!("nameserver {s}\n")).collect();
            std::fs::write(RESOLV_CONF, content)
                .with_context(|| format!("无法写入 {RESOLV_CONF}"))?;
            return Ok(());
        }

        anyhow::bail!("没有可用的 DNS 接管方式（systemd-resolved 未运行，{RESOLV_CONF} 被接管）")
    }

    pub fn describe(backup: &DnsBackup) -> String {
        if backup.service.is_empty() {
            format!("resolv.conf ({})", backup.servers.join(", "))
        } else {
            format!("{} (systemd-resolved)", backup.service)
        }
    }
}

/// 从 resolv.conf 内容里取出 nameserver 列表
pub(crate) fn parse_nameservers(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            // 分隔符可能是空格也可能是 tab
            let mut words = line.split_whitespace();
            if words.next() != Some("nameserver") {
                return None;
            }
            words.next().map(str::to_string)
        })
        .collect()
}

impl DnsBackup {
    /// 抓取原始 DNS 状态并在任何修改前落盘
    pub fn capture(data_dir: &Path, tun_name: &str) -> Result<Self> {
        platform::capture(data_dir, tun_name)
    }

    /// 还原到原始 DNS 设置，并删除备份文件
    pub fn restore(&self, data_dir: &Path) -> Result<()> {
        platform::restore(self, data_dir)
    }

    /// 描述原始状态，用于日志
    pub fn describe(&self) -> String {
        platform::describe(self)
    }
}

/// 把 DNS 指向隧道内解析器
pub fn apply(servers: &[String], tun_name: &str) -> Result<()> {
    if servers.is_empty() {
        anyhow::bail!("未配置 DNS 服务器，无法接管");
    }
    platform::apply(servers, tun_name)
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
            raw: None,
        };
        backup.persist(&dir).unwrap();

        let loaded = DnsBackup::load(&dir).unwrap();
        assert_eq!(loaded.service, "Wi-Fi");
        assert_eq!(loaded.servers, vec!["223.5.5.5"]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parses_nameserver_lines() {
        let text = "# generated\nnameserver 192.168.1.1\nnameserver\t8.8.8.8\nsearch lan\n";
        assert_eq!(
            parse_nameservers(text),
            vec!["192.168.1.1".to_string(), "8.8.8.8".to_string()]
        );
        assert!(parse_nameservers("# nothing\n").is_empty());
    }

    #[test]
    fn load_returns_none_without_backup() {
        let empty = std::env::temp_dir().join("miaovps-dns-nonexistent-xyz");
        assert!(DnsBackup::load(&empty).is_none());
    }

    #[test]
    fn apply_rejects_empty_server_list() {
        assert!(apply(&[], "tun0").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn describes_dhcp_state() {
        let dhcp = DnsBackup {
            service: "Wi-Fi".into(),
            servers: vec![],
            raw: None,
        };
        assert_eq!(dhcp.describe(), "Wi-Fi (DHCP 自动)");

        let custom = DnsBackup {
            service: "Wi-Fi".into(),
            servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            raw: None,
        };
        assert_eq!(custom.describe(), "Wi-Fi (1.1.1.1, 8.8.8.8)");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interface_existence_uses_sysfs() {
        // loopback 永远存在，伪造的名字永远不存在
        assert!(platform::interface_exists("lo"));
        assert!(!platform::interface_exists("miaovps-nonexistent0"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn describes_both_linux_backends() {
        let resolved = DnsBackup {
            service: "tun0".into(),
            servers: vec![],
            raw: None,
        };
        assert_eq!(resolved.describe(), "tun0 (systemd-resolved)");

        let resolv = DnsBackup {
            service: String::new(),
            servers: vec!["192.168.1.1".into()],
            raw: Some("nameserver 192.168.1.1\n".into()),
        };
        assert_eq!(resolv.describe(), "resolv.conf (192.168.1.1)");
    }
}
