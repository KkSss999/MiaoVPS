//! 路由与网关操作 —— macOS 与 Linux 的平台实现
//!
//! 上层只认 [`RouteSpec`] 和几个语义化函数，命令差异全部留在这里：
//! macOS 用 BSD 的 `route(8)`，Linux 用 iproute2 的 `ip(8)`。
//!
//! 两者都假设进程已经是 root —— CLI 在流程最前面就检查过权限。

use anyhow::Result;

/// 一条待应用的路由
#[derive(Debug, Clone)]
pub struct RouteSpec {
    /// 目标网段 CIDR
    pub destination: String,
    /// 下一跳 —— 网关 IP 或接口名
    pub via: RouteVia,
}

#[derive(Debug, Clone)]
pub enum RouteVia {
    Gateway(String),
    Interface(String),
}

impl RouteSpec {
    pub fn gateway(destination: String, gw: &str) -> Self {
        Self {
            destination,
            via: RouteVia::Gateway(gw.to_string()),
        }
    }

    pub fn interface(destination: String, iface: &str) -> Self {
        Self {
            destination,
            via: RouteVia::Interface(iface.to_string()),
        }
    }

    pub fn add(&self) -> Result<()> {
        imp::add_route(&self.destination, &self.via)
    }

    fn delete(&self) {
        delete_route(&self.destination);
    }
}

/// 按顺序应用路由，任一条失败则回滚已应用的部分
///
/// 半套路由比没有路由更危险 — 用户可能只剩部分流量可达，
/// 且不知道该删哪几条才能恢复。
pub fn apply_routes(plan: &[RouteSpec]) -> Result<()> {
    let mut applied: Vec<&RouteSpec> = Vec::with_capacity(plan.len());

    for spec in plan {
        if let Err(e) = spec.add() {
            for done in applied.iter().rev() {
                done.delete();
            }
            return Err(e.context(format!(
                "应用路由 {} 失败，已回滚 {} 条先前路由",
                spec.destination,
                applied.len()
            )));
        }
        applied.push(spec);
    }
    Ok(())
}

/// 删除一条路由，逐条静默 —— 清理路径上任何一条失败都不该中断其余清理
pub fn delete_route(destination: &str) {
    imp::delete_route(destination)
}

/// 当前默认网关 IP
pub fn default_gateway() -> Result<String> {
    imp::default_gateway()
}

/// 公网 IPv6 前缀拦截的安装结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6Block {
    /// 本次新安装
    Added,
    /// 已存在（上一轮异常退出或别的程序装的），调用方需自行核验类型
    AlreadyPresent,
    /// 本机没有 IPv6 栈 —— 没有可泄漏的面，无需拦截
    Unsupported,
}

/// 安装一条拦截公网 IPv6 的路由
pub fn add_ipv6_block(prefix: &str) -> Result<Ipv6Block> {
    imp::add_ipv6_block(prefix)
}

/// 核验前缀确实命中「拒绝」类型，而不是一条普通路由
pub fn verify_ipv6_block(prefix: &str) -> Result<()> {
    imp::verify_ipv6_block(prefix)
}

/// 删除拦截路由；不存在视为成功
pub fn delete_ipv6_block(prefix: &str) -> Result<()> {
    imp::delete_ipv6_block(prefix)
}

/// 从 BSD `route -n get default` 的输出里取 `gateway:`
///
/// 只有 macOS 调用它，但解析逻辑在这里统一测试。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn parse_bsd_gateway(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("gateway:"))
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
}

/// 从 `ip route show default` 的输出里取 `via`
///
/// 输出形如 `default via 192.168.1.1 dev wlan0 proto dhcp metric 600`；
/// `default dev ppp0` 这类没有网关的默认路由返回 None。
///
/// 只有 Linux 调用它，但解析逻辑在这里统一测试。
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn parse_default_via(stdout: &str) -> Option<String> {
    stdout
        .lines()
        .find(|l| l.split_whitespace().next() == Some("default"))
        .and_then(|line| {
            let mut words = line.split_whitespace();
            while let Some(w) = words.next() {
                if w == "via" {
                    return words.next().map(|g| g.to_string());
                }
            }
            None
        })
        .filter(|g| !g.is_empty())
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{Ipv6Block, RouteVia};
    use anyhow::{Context, Result};
    use std::process::Command;

    /// 仅用于确认路由查找实际命中 reject；不是媒体或服务商特判。
    const VERIFY_ADDRESS: &str = "2001:4860:4860::8888";

    /// 执行 route 命令。已经 root 了，不再套 sudo。
    ///
    /// 「路由已存在」不算失败 — 上次异常退出可能留下同名路由，
    /// 目标状态（该网段走隧道）已经满足。
    fn run_route(args: &[&str]) -> Result<()> {
        let output = Command::new("route")
            .arg("-n")
            .args(args)
            .output()
            .context("无法执行 route 命令")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("File exists") {
                return Ok(());
            }
            anyhow::bail!("route {} 失败: {}", args.join(" "), stderr.trim());
        }
        Ok(())
    }

    pub fn add_route(destination: &str, via: &RouteVia) -> Result<()> {
        let (flag, target) = match via {
            RouteVia::Gateway(gw) => ("-gateway", gw.as_str()),
            RouteVia::Interface(i) => ("-interface", i.as_str()),
        };
        run_route(&["add", "-inet", destination, flag, target])
    }

    pub fn delete_route(destination: &str) {
        let _ = Command::new("route")
            .args(["-q", "-n", "delete", "-inet", destination])
            .output();
    }

    pub fn default_gateway() -> Result<String> {
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .context("无法执行 route 命令")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        super::parse_bsd_gateway(&stdout)
            .ok_or_else(|| anyhow::anyhow!("无法获取默认网关 — 当前可能没有可用网络连接"))
    }

    pub fn add_ipv6_block(prefix: &str) -> Result<Ipv6Block> {
        let output = Command::new("route")
            // macOS 的 RTF_REJECT 路由必须提供 loopback gateway；只给
            // destination 和 -reject 会出现命令成功但没有安装 reject 路由的假象。
            .args(["-n", "add", "-inet6", prefix, "::1", "-reject"])
            .output()
            .context("无法添加 IPv6 防泄漏路由")?;

        if output.status.success() {
            return Ok(Ipv6Block::Added);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("File exists") {
            return Ok(Ipv6Block::AlreadyPresent);
        }
        // 系统关掉 IPv6 时没有可泄漏的地址族，不该因此拒绝建立隧道
        if stderr.contains("not supported") || stderr.contains("Address family") {
            return Ok(Ipv6Block::Unsupported);
        }
        anyhow::bail!(
            "route add -inet6 {prefix} ::1 -reject 失败: {}",
            stderr.trim()
        );
    }

    pub fn verify_ipv6_block(_prefix: &str) -> Result<()> {
        let output = Command::new("route")
            .args(["-n", "get", "-inet6", VERIFY_ADDRESS])
            .output()
            .context("无法核验 IPv6 防泄漏路由")?;
        if !output.status.success() {
            anyhow::bail!(
                "IPv6 路由查找失败: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout
            .lines()
            .any(|line| line.trim_start().starts_with("flags:") && line.contains("REJECT"))
        {
            return Ok(());
        }
        anyhow::bail!(
            "IPv6 路由未命中 REJECT（仍可能经本地网络直连）: {}",
            stdout
                .lines()
                .find(|line| line.trim_start().starts_with("flags:"))
                .unwrap_or("未返回 flags")
                .trim()
        );
    }

    pub fn delete_ipv6_block(prefix: &str) -> Result<()> {
        let output = Command::new("route")
            .args(["-q", "-n", "delete", "-inet6", prefix, "::1"])
            .output()
            .context("无法删除 IPv6 防泄漏路由")?;
        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // 路由已被系统或用户删除，目标状态同样成立。
        if stderr.contains("not in table") || stderr.contains("not found") {
            return Ok(());
        }
        anyhow::bail!("route delete -inet6 {prefix} ::1 失败: {}", stderr.trim());
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Ipv6Block, RouteVia};
    use anyhow::{Context, Result};
    use std::process::Command;

    fn run_ip(args: &[&str]) -> Result<()> {
        let output = Command::new("ip")
            .args(args)
            .output()
            .context("无法执行 ip 命令 — 需要 iproute2")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // 与 macOS 路径一致：路由已存在时目标状态已经满足
            if stderr.contains("File exists") {
                return Ok(());
            }
            anyhow::bail!("ip {} 失败: {}", args.join(" "), stderr.trim());
        }
        Ok(())
    }

    pub fn add_route(destination: &str, via: &RouteVia) -> Result<()> {
        match via {
            RouteVia::Gateway(gw) => run_ip(&["route", "add", destination, "via", gw]),
            RouteVia::Interface(iface) => run_ip(&["route", "add", destination, "dev", iface]),
        }
    }

    pub fn delete_route(destination: &str) {
        let _ = Command::new("ip")
            .args(["route", "del", destination])
            .output();
    }

    pub fn default_gateway() -> Result<String> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .context("无法执行 ip 命令 — 需要 iproute2")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        super::parse_default_via(&stdout)
            .ok_or_else(|| anyhow::anyhow!("无法获取默认网关 — 当前可能没有可用网络连接"))
    }

    pub fn add_ipv6_block(prefix: &str) -> Result<Ipv6Block> {
        // prohibit 返回 ICMP admin prohibited，与 macOS 的 -reject 语义一致：
        // 应用立即失败而不是静默挂起。
        let output = Command::new("ip")
            .args(["-6", "route", "add", "prohibit", prefix])
            .output()
            .context("无法添加 IPv6 防泄漏路由")?;

        if output.status.success() {
            return Ok(Ipv6Block::Added);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("File exists") {
            return Ok(Ipv6Block::AlreadyPresent);
        }
        // IPv6 被内核参数关掉时没有可泄漏的地址族，不该因此拒绝建立隧道
        if stderr.contains("not supported") || stderr.contains("disabled") {
            return Ok(Ipv6Block::Unsupported);
        }
        anyhow::bail!("ip -6 route add prohibit {prefix} 失败: {}", stderr.trim());
    }

    pub fn verify_ipv6_block(prefix: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(["-6", "route", "show"])
            .output()
            .context("无法核验 IPv6 防泄漏路由")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        // 只看类型和前缀，不依赖 iproute2 的展示细节
        if stdout.lines().any(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("prohibit") && words.next() == Some(prefix)
        }) {
            return Ok(());
        }
        anyhow::bail!(
            "IPv6 路由 {prefix} 未命中 prohibit（仍可能经本地网络直连）: {}",
            stdout.trim()
        );
    }

    pub fn delete_ipv6_block(prefix: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(["-6", "route", "del", prefix])
            .output()
            .context("无法删除 IPv6 防泄漏路由")?;
        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // 路由已被系统或用户删除，目标状态同样成立。
        if stderr.contains("No such process") || stderr.contains("not found") {
            return Ok(());
        }
        anyhow::bail!("ip -6 route del {prefix} 失败: {}", stderr.trim());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bsd_default_gateway() {
        let out = "   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(parse_bsd_gateway(out).as_deref(), Some("192.168.1.1"));
        assert_eq!(parse_bsd_gateway("no gateway here"), None);
        assert_eq!(parse_bsd_gateway("    gateway:    \n"), None);
    }

    #[test]
    fn parses_linux_default_via() {
        let out = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n";
        assert_eq!(parse_default_via(out).as_deref(), Some("192.168.1.1"));

        // 多条默认路由取第一条；没有 via 的（PPP/直连）返回 None
        let multi = "default via 10.0.0.1 dev eth0 metric 100\ndefault dev ppp0 metric 700\n";
        assert_eq!(parse_default_via(multi).as_deref(), Some("10.0.0.1"));
        assert_eq!(parse_default_via("default dev ppp0 scope link\n"), None);
        assert_eq!(parse_default_via(""), None);
    }

    #[test]
    fn route_spec_carries_correct_next_hop() {
        let gw = RouteSpec::gateway("203.0.113.10/32".into(), "192.168.1.1");
        assert!(matches!(gw.via, RouteVia::Gateway(ref g) if g == "192.168.1.1"));

        let iface = RouteSpec::interface("0.0.0.0/1".into(), "tun5");
        assert!(matches!(iface.via, RouteVia::Interface(ref i) if i == "tun5"));
        assert_eq!(iface.destination, "0.0.0.0/1");
    }
}
