//! SSH 远端部署实现
//!
//! 通过 SSH 在 VPS 上执行 WireGuard 的检测、安装、配置和管理。
//! 所有操作通过 russh 执行远端命令，不安装长期 Agent。

use crate::deploy::{DeploymentOptions, DeploymentProgress, StepResult, StepSender};
use crate::detect::{DetectKey, DetectStatus, ServerReport};
use crate::error::{AppError, ErrorCode};
use miaovps_core::DeploymentStep;
use miaovps_ssh::SshSession;
use tracing::{debug, info};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SshProvisioner
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 远端命令的提权方式
#[derive(Debug, Clone, Default)]
pub enum Privilege {
    /// 已是 root，无需提权
    #[default]
    Root,
    /// 免交互 sudo（NOPASSWD）
    SudoNoPassword,
    /// 需要密码的 sudo — 密码经 stdin 传给 `sudo -S`
    SudoPassword(String),
}

impl Privilege {
    /// 把命令包装成具备 root 权限的形式
    ///
    /// `sudo -S` 从 stdin 读密码，所以整条命令必须通过 `sudo -S sh -c '...'`
    /// 执行，且**命令本身不能再占用 stdin**（heredoc 会和密码抢 stdin，
    /// 曾导致密码被写进配置文件）。这里改用 `printf | base64 -d | sh` 传递
    /// 脚本内容，彻底避开 stdin 争抢。
    fn wrap(&self, cmd: &str) -> String {
        match self {
            Privilege::Root => cmd.to_string(),
            Privilege::SudoNoPassword => format!("sudo -n sh -c {}", shell_quote(cmd)),
            Privilege::SudoPassword(pw) => {
                // 密码 + 换行喂给 sudo -S；脚本经 base64 传入，不碰 stdin
                let b64 = base64_encode(cmd.as_bytes());
                format!(
                    "printf '%s\\n' {} | sudo -S -p '' sh -c \"echo {} | base64 -d | sh\"",
                    shell_quote(pw),
                    b64
                )
            }
        }
    }

    /// 用于日志的脱敏描述
    pub fn describe(&self) -> &'static str {
        match self {
            Privilege::Root => "root",
            Privilege::SudoNoPassword => "sudo (NOPASSWD)",
            Privilege::SudoPassword(_) => "sudo (密码)",
        }
    }
}

/// 把 SshError 转成 AppError，保留命令上下文
fn ssh_err(cmd: &str, e: miaovps_ssh::SshError) -> AppError {
    AppError::new(ErrorCode::InternalError, "远程命令执行失败", format!("{e}"))
        .with_technical(format!("命令: {cmd}"))
}

/// 从 VPN 网段计算服务端网关地址。`10.66.66.0/24` 的网段地址不能作为
/// wg0 的主机地址；服务端约定使用第一个可用地址 `10.66.66.1/24`。
fn gateway_address(cidr: &str) -> Result<String, AppError> {
    let (raw_ip, raw_prefix) = cidr
        .split_once('/')
        .ok_or_else(|| AppError::new(ErrorCode::ConfigWriteFailed, "VPN 网段无效", cidr))?;
    let ip: std::net::Ipv4Addr = raw_ip
        .parse()
        .map_err(|_| AppError::new(ErrorCode::ConfigWriteFailed, "VPN 网段无效", cidr))?;
    let prefix: u8 = raw_prefix
        .parse()
        .map_err(|_| AppError::new(ErrorCode::ConfigWriteFailed, "VPN 网段前缀无效", cidr))?;
    if prefix > 30 {
        return Err(AppError::new(
            ErrorCode::ConfigWriteFailed,
            "VPN 网段过小",
            "网段前缀必须不大于 /30",
        ));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(ip) & mask;
    let gateway = std::net::Ipv4Addr::from(network + 1);
    Ok(format!("{gateway}/{prefix}"))
}

/// 单引号包裹并转义，供 sh -c 使用
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// 最小 base64 编码 —— 避免为此引入依赖
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub struct PortChange<'a> {
    pub wireguard: bool,
    pub token: &'a str,
    pub old: u16,
    pub new: u16,
    pub public_key: &'a str,
    pub peer: &'a str,
}

pub enum PortAction {
    Prepare,
    Commit,
    Abort,
}

pub struct SshProvisioner {
    session: SshSession,
    server_id: String,
    privilege: Privilege,
}

impl SshProvisioner {
    pub fn new(session: SshSession, server_id: String) -> Self {
        Self {
            session,
            server_id,
            privilege: Privilege::Root,
        }
    }

    /// Bring up the isolated, single-peer AmneziaWG trial. Only the peer's public key leaves the client.
    pub async fn deploy_awg_trial(
        &self,
        port: u16,
        peer_public_key: &str,
    ) -> Result<String, AppError> {
        let cmd = format!(
            "bash -c {} -- {port} {}",
            shell_quote(include_str!("deploy-awg.sh")),
            shell_quote(peer_public_key)
        );
        self.exec_root(&cmd, "deploy-awg").await
    }

    /// Query the live listener without returning private or preshared keys.
    pub async fn listener(&self, wireguard: bool) -> Result<(String, u16), AppError> {
        let (tool, iface) = if wireguard {
            ("wg", "wg0")
        } else {
            ("awg", "miao-awg")
        };
        let raw = self
            .exec_root(
                &format!("test ! -e /run/miaovps-{iface}-port && {tool} show {iface} public-key && {tool} show {iface} listen-port"),
                "vpn-listener",
            )
            .await?;
        let mut lines = raw.lines();
        let key = lines.next().unwrap_or_default();
        let port = lines
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|p| *p != 0);
        match port.filter(|_| !key.is_empty() && lines.next().is_none()) {
            Some(port) => Ok((key.to_string(), port)),
            None => Err(AppError::new(
                ErrorCode::InternalError,
                "监听状态无效",
                "无法确认服务端公钥或端口",
            )),
        }
    }

    /// Use the same guarded port transaction for both protocols, without restarting either service.
    pub async fn switch_port(
        &self,
        change: &PortChange<'_>,
        action: PortAction,
    ) -> Result<(), AppError> {
        let proto = if change.wireguard { "wg" } else { "awg" };
        let action = match action {
            PortAction::Prepare => "prepare",
            PortAction::Commit => "commit",
            PortAction::Abort => "abort",
        };
        let cmd = format!(
            "bash -c {} -- {action} {proto} {} {} {} {} {}",
            shell_quote(include_str!("switch-port.sh")),
            shell_quote(change.token),
            change.old,
            change.new,
            shell_quote(change.public_key),
            shell_quote(change.peer)
        );
        self.exec_root(&cmd, "switch-port").await?;
        Ok(())
    }

    pub async fn awg_status(&self) -> Result<String, AppError> {
        self.exec_root(
            "awg show miao-awg 2>/dev/null || echo 'not-running'",
            "awg-show",
        )
        .await
    }

    /// 结束短命部署命令持有的 SSH 会话。
    pub async fn disconnect(self) -> Result<(), AppError> {
        self.session
            .disconnect()
            .await
            .map_err(|e| ssh_err("disconnect", e))
    }

    /// 指定提权方式（非 root 登录时必需）
    pub fn with_privilege(mut self, privilege: Privilege) -> Self {
        self.privilege = privilege;
        self
    }

    /// 自动探测可用的提权方式
    ///
    /// `sudo_password` 为 None 时只尝试 root / NOPASSWD。
    pub async fn detect_privilege(
        session: &SshSession,
        sudo_password: Option<&str>,
    ) -> Result<Privilege, AppError> {
        let whoami = session
            .exec_lenient("whoami")
            .await
            .map_err(|e| ssh_err("whoami", e))?;
        if whoami.trim() == "root" {
            return Ok(Privilege::Root);
        }

        let nopass = session
            .exec_lenient("sudo -n true 2>/dev/null && echo ok")
            .await
            .map_err(|e| ssh_err("sudo -n", e))?;
        if nopass.contains("ok") {
            return Ok(Privilege::SudoNoPassword);
        }

        let Some(pw) = sudo_password else {
            return Err(AppError::new(
                ErrorCode::SudoRequired,
                "需要 root 权限",
                format!("登录用户是 {}，且未配置免密 sudo", whoami.trim()),
            )
            .with_suggestion("请用 root 登录、配置 NOPASSWD sudo，或提供 sudo 密码"));
        };

        // 验证密码可用 —— 否则后续每一步都会失败且原因不明
        let probe = Privilege::SudoPassword(pw.to_string());
        let check = session
            .exec_lenient(&probe.wrap("whoami"))
            .await
            .map_err(|e| ssh_err("sudo -S", e))?;
        if check.contains("root") {
            Ok(probe)
        } else {
            Err(AppError::new(
                ErrorCode::SudoRequired,
                "sudo 密码无效",
                "提供的 sudo 密码被拒绝".to_string(),
            )
            .with_suggestion("确认密码正确，或改用 root 登录"))
        }
    }

    /// 在远端执行命令（空输入），返回 stdout
    async fn exec(&self, cmd: &str) -> Result<String, AppError> {
        self.session.exec(cmd).await.map_err(|e| {
            AppError::new(
                ErrorCode::InternalError,
                "命令执行失败",
                "远程命令执行出错".to_string(),
            )
            .with_technical(format!("{}: {}", cmd, e))
        })
    }

    /// 以 root 权限执行命令，非零退出码即报错
    ///
    /// 部署的每一步都必须走这里 —— 原实现直接用 `exec` 且不加提权，
    /// 非 root 登录时每步都会因权限不足失败。
    async fn exec_root(&self, cmd: &str, step: &str) -> Result<String, AppError> {
        info!(target: "provisioner", server=%self.server_id, step, "执行远端步骤");
        let wrapped = self.privilege.wrap(cmd);
        let out = self
            .session
            .exec_raw(&wrapped)
            .await
            .map_err(|e| ssh_err(step, e))?;

        debug!(target: "provisioner", step, code=?out.exit_status);

        if !out.success() {
            let detail = if matches!(step, "wg-peer-stats" | "write-config") {
                "敏感步骤失败，已隐藏远端输出".to_string()
            } else {
                out.stderr.trim().to_string()
            };
            return Err(AppError::new(
                ErrorCode::InternalError,
                format!("步骤失败: {step}"),
                detail.chars().take(400).collect::<String>(),
            )
            .with_technical(format!(
                "步骤: {step} · 退出码: {:?} · 提权: {}",
                out.exit_status,
                self.privilege.describe()
            )));
        }
        Ok(out.stdout)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  兼容旧调用名
    async fn exec_checked(&self, cmd: &str, step: &str) -> Result<String, AppError> {
        self.exec_root(cmd, step).await
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  环境检测
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    pub async fn inspect(&mut self) -> Result<ServerReport, AppError> {
        let mut report = ServerReport::new(self.server_id.clone());
        info!(target: "provisioner", server=%self.server_id, "开始环境检测");

        // 1. 操作系统
        let os = self
            .exec("cat /etc/os-release 2>/dev/null || cat /etc/lsb-release 2>/dev/null")
            .await
            .unwrap_or_default();
        let is_ubuntu = os.contains("Ubuntu") || os.contains("ubuntu");
        let version = if os.contains("24.04") {
            "24.04"
        } else if os.contains("22.04") {
            "22.04"
        } else {
            "unknown"
        };

        if is_ubuntu && version != "unknown" {
            report.add_item(
                DetectKey::Os,
                DetectStatus::Pass,
                &format!("Ubuntu {}", version),
                None,
            );
        } else if is_ubuntu {
            report.add_item(
                DetectKey::Os,
                DetectStatus::Warning,
                "Ubuntu 但版本非 22.04/24.04",
                Some("建议使用 Ubuntu 22.04 或 24.04 LTS"),
            );
        } else {
            report.add_item(
                DetectKey::Os,
                DetectStatus::Blocked,
                &format!("不支持的系统: {}", os.lines().next().unwrap_or("unknown")),
                Some("需要 Ubuntu 22.04 或 24.04"),
            );
        }

        // 2. 架构
        let arch = self
            .exec("uname -m")
            .await
            .unwrap_or_default()
            .trim()
            .to_string();
        match arch.as_str() {
            "x86_64" | "aarch64" => {
                report.add_item(DetectKey::Arch, DetectStatus::Pass, &arch, None)
            }
            _ => report.add_item(
                DetectKey::Arch,
                DetectStatus::Blocked,
                &arch,
                Some("需要 x86_64 或 arm64"),
            ),
        }

        // 3. root/sudo 权限
        let whoami = self
            .exec("whoami")
            .await
            .unwrap_or_default()
            .trim()
            .to_string();
        if whoami == "root" {
            report.add_item(DetectKey::Privilege, DetectStatus::Pass, "root 用户", None);
        } else {
            let sudo = self
                .exec("sudo -n true 2>/dev/null && echo ok || echo no")
                .await
                .unwrap_or_default();
            if sudo.contains("ok") {
                report.add_item(
                    DetectKey::Privilege,
                    DetectStatus::Pass,
                    "免交互 sudo",
                    None,
                );
            } else {
                report.add_item(
                    DetectKey::Privilege,
                    DetectStatus::Blocked,
                    "需要 root 或免交互 sudo",
                    Some("请使用 root 登录或配置 NOPASSWD sudo"),
                );
            }
        }

        // 4. 公网 IPv4
        let ip = self
            .exec("curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo 'unknown'")
            .await
            .unwrap_or_default()
            .trim()
            .to_string();
        if ip != "unknown" && !ip.is_empty() {
            report.add_item(DetectKey::PublicIpv4, DetectStatus::Pass, &ip, None);
        } else {
            report.add_item(
                DetectKey::PublicIpv4,
                DetectStatus::Warning,
                "无法检测公网 IP",
                Some("可能影响 VPN 连通性"),
            );
        }

        // 5. WireGuard 安装状态
        let wg = self
            .exec("which wg 2>/dev/null && wg --version 2>/dev/null || echo 'not-installed'")
            .await
            .unwrap_or_default();
        if wg.contains("not-installed") {
            report.add_item(DetectKey::WireGuard, DetectStatus::Pass, "可安装", None);
        } else {
            report.add_item(
                DetectKey::WireGuard,
                DetectStatus::Pass,
                &format!("已安装: {}", wg.trim()),
                None,
            );
        }

        // 6. systemd
        let systemd = self
            .exec("systemctl --version 2>/dev/null | head -1 || echo 'no'")
            .await
            .unwrap_or_default();
        if systemd.contains("systemd") {
            report.add_item(DetectKey::Systemd, DetectStatus::Pass, systemd.trim(), None);
        } else {
            report.add_item(
                DetectKey::Systemd,
                DetectStatus::Blocked,
                "systemd 不可用",
                Some("需要 systemd 管理 WireGuard 服务"),
            );
        }

        // 7. IP Forward
        let forward = self
            .exec("sysctl net.ipv4.ip_forward 2>/dev/null")
            .await
            .unwrap_or_default();
        if forward.contains("= 1") {
            report.add_item(DetectKey::IpForward, DetectStatus::Pass, "已开启", None);
        } else {
            report.add_item(DetectKey::IpForward, DetectStatus::Pass, "可配置", None);
        }

        // 8. 防火墙
        let fw = self.exec("which ufw 2>/dev/null && ufw status 2>/dev/null || which iptables 2>/dev/null && echo 'iptables' || echo 'none'").await.unwrap_or_default();
        report.add_item(DetectKey::Firewall, DetectStatus::Pass, fw.trim(), None);

        // A custom port is valid; deployment checks the actual selected listener, not 51820.
        let port_check = self.exec("command -v ss").await.unwrap_or_default();
        if port_check.is_empty() {
            report.add_item(
                DetectKey::UdpPort,
                DetectStatus::Blocked,
                "缺少 ss",
                Some("请安装 iproute2"),
            );
        } else {
            report.add_item(
                DetectKey::UdpPort,
                DetectStatus::Pass,
                "部署时检查所选 UDP 端口",
                None,
            );
        }

        // 10. 磁盘
        let disk = self
            .exec("df -BM / | tail -1 | awk '{print $4}' 2>/dev/null || echo '0'")
            .await
            .unwrap_or_default()
            .trim()
            .to_string();
        let disk_mb: u64 = disk.trim_end_matches('M').parse().unwrap_or(0);
        if disk_mb > 200 {
            report.add_item(
                DetectKey::Disk,
                DetectStatus::Pass,
                &format!("{}MB 可用", disk_mb),
                None,
            );
        } else {
            report.add_item(
                DetectKey::Disk,
                DetectStatus::Blocked,
                &format!("仅 {}MB", disk_mb),
                Some("需要至少 200MB"),
            );
        }

        // 11. 内存
        let mem = self
            .exec("free -m | grep Mem | awk '{print $7}' 2>/dev/null || echo '0'")
            .await
            .unwrap_or_default()
            .trim()
            .to_string();
        let mem_mb: u64 = mem.parse().unwrap_or(0);
        if mem_mb > 256 {
            report.add_item(
                DetectKey::Memory,
                DetectStatus::Pass,
                &format!("{}MB 可用", mem_mb),
                None,
            );
        } else {
            report.add_item(
                DetectKey::Memory,
                DetectStatus::Blocked,
                &format!("仅 {}MB", mem_mb),
                Some("需要至少 256MB"),
            );
        }

        report.finalize();
        info!(target: "provisioner", server=%self.server_id, passed=%report.all_passed, blocked=%report.blocked, "环境检测完成");
        Ok(report)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  一键部署
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    pub async fn deploy(
        &mut self,
        options: &DeploymentOptions,
    ) -> Result<DeploymentProgress, AppError> {
        self.deploy_reporting(options, None).await
    }

    /// 一键部署，`events` 非空时实时推送每一步的状态变更
    ///
    /// CLI 用它打印进度，前端把事件转成 Tauri event。
    pub async fn deploy_reporting(
        &mut self,
        options: &DeploymentOptions,
        events: Option<StepSender>,
    ) -> Result<DeploymentProgress, AppError> {
        let deployment_id = uuid::Uuid::new_v4().to_string();
        let mut progress = DeploymentProgress::new(deployment_id);
        if let Some(tx) = events {
            progress.set_sink(tx);
        }
        info!(target: "provisioner", server=%self.server_id, "开始部署");

        // Step 1: 建立连接
        progress.update_step(DeploymentStep::Connect, StepResult::Running);
        match self.exec_checked("echo 'connected'", "connect").await {
            Ok(_) => progress.update_step(DeploymentStep::Connect, StepResult::Success),
            Err(e) => {
                progress.fail(DeploymentStep::Connect, e.to_string());
                return Ok(progress);
            }
        }

        // Existing listeners must go through the verified port transaction, never full redeploy.
        let port_guard = format!(
            r#"set -e
port={}
if [ -e /etc/wireguard/wg0.conf ]; then
    disk=$(awk '$1 == "ListenPort" {{print $3}}' /etc/wireguard/wg0.conf)
    [ "$disk" = "$port" ] || {{ echo 'Existing wg0 uses a different port; use the verified port-change command' >&2; exit 1; }}
fi
live=$(wg show wg0 listen-port 2>/dev/null || true)
if [ -n "$live" ]; then
    [ "$live" = "$port" ] || {{ echo 'Live wg0 uses a different port' >&2; exit 1; }}
else
    sockets=$(ss -H -uan "sport = :$port")
    [ -z "$sockets" ] || {{ echo 'UDP port is occupied' >&2; exit 1; }}
fi"#,
            options.wireguard_port
        );
        if let Err(e) = self.exec_checked(&port_guard, "check-listen-port").await {
            progress.fail(DeploymentStep::Connect, e.to_string());
            return Ok(progress);
        }

        // Step 2: 备份
        progress.update_step(DeploymentStep::Backup, StepResult::Running);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let backup_dir = format!("/var/lib/miaovps/backups/{}", ts);
        let backup_cmd = format!(
            "mkdir -p {dir} && cp -r /etc/wireguard {dir}/ 2>/dev/null; cp -r /etc/sysctl.d {dir}/ 2>/dev/null; echo 'ok'",
            dir = backup_dir
        );
        match self.exec_checked(&backup_cmd, "backup").await {
            Ok(o) if o.contains("ok") => {
                progress.update_step(DeploymentStep::Backup, StepResult::Success)
            }
            Ok(_) => progress.update_step(
                DeploymentStep::Backup,
                StepResult::Warning("部分备份失败".into()),
            ),
            Err(e) => {
                progress.fail(DeploymentStep::Backup, e.to_string());
                return Ok(progress);
            }
        }

        // Step 3: 安装 WireGuard（幂等）
        progress.update_step(DeploymentStep::InstallWireGuard, StepResult::Running);
        let install_cmd = "which wg >/dev/null 2>&1 && echo 'already-installed' || (apt-get update -qq && apt-get install -y -qq wireguard-tools 2>&1 && echo 'installed')";
        match self.exec_checked(install_cmd, "install-wg").await {
            Ok(o) if o.contains("already-installed") => {
                progress.update_step(DeploymentStep::InstallWireGuard, StepResult::Success)
            }
            Ok(o) if o.contains("installed") => {
                progress.update_step(DeploymentStep::InstallWireGuard, StepResult::Success)
            }
            Ok(_) => {
                progress.fail(
                    DeploymentStep::InstallWireGuard,
                    "安装 WireGuard 失败".into(),
                );
                return Ok(progress);
            }
            Err(e) => {
                progress.fail(DeploymentStep::InstallWireGuard, e.to_string());
                return Ok(progress);
            }
        }

        // Step 4: 生成服务器密钥
        progress.update_step(DeploymentStep::GenerateServerKeys, StepResult::Running);
        let key_cmd = "mkdir -p /etc/wireguard && [ -f /etc/wireguard/private.key ] && echo 'keys-exist' || (wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key && chmod 600 /etc/wireguard/private.key && echo 'keys-generated')";
        match self.exec_checked(key_cmd, "generate-keys").await {
            Ok(o) if o.contains("keys-exist") || o.contains("keys-generated") => {
                progress.update_step(DeploymentStep::GenerateServerKeys, StepResult::Success)
            }
            Ok(_) => progress.fail(DeploymentStep::GenerateServerKeys, "生成密钥失败".into()),
            Err(e) => {
                progress.fail(DeploymentStep::GenerateServerKeys, e.to_string());
                return Ok(progress);
            }
        }

        // 获取服务器公钥 —— 客户端连接必须用它，不能丢弃
        let server_pubkey = match self
            .exec_root("cat /etc/wireguard/public.key", "read-pubkey")
            .await
        {
            Ok(k) => k.trim().to_string(),
            Err(e) => {
                progress.fail(DeploymentStep::GenerateServerKeys, e.to_string());
                return Ok(progress);
            }
        };
        if server_pubkey.is_empty() {
            progress.fail(
                DeploymentStep::GenerateServerKeys,
                "服务器公钥为空 —— 密钥生成疑似失败".into(),
            );
            return Ok(progress);
        }
        progress.server_public_key = Some(server_pubkey);

        // Step 5: 配置虚拟网络（原子写入）
        progress.update_step(DeploymentStep::ConfigureInterface, StepResult::Running);

        let mtu = options.mtu.unwrap_or(1380);
        let mss = mtu.saturating_sub(40);
        if mss < 536 {
            progress.fail(
                DeploymentStep::ConfigureInterface,
                format!("MTU {} 过小，无法计算安全 TCP MSS", mtu),
            );
            return Ok(progress);
        }
        let wg_conf = format!(
            "ListenPort = {}\nAddress = {}\nMTU = {}",
            options.wireguard_port,
            gateway_address(&options.vpn_cidr)?,
            mtu
        );
        // Keep the private key on the VPS, and create the temporary config as 0600 before any write.
        let write_conf_cmd = format!(
            r#"set -eu
umask 077
tmp=$(mktemp /etc/wireguard/wg0.conf.XXXXXXXX)
trap 'rm -f "$tmp"' EXIT
key=$(cat /etc/wireguard/private.key)
printf '%s' "$key" | grep -Eq '^[A-Za-z0-9+/]{{43}}=$' || exit 1
{{
    printf '[Interface]\nPrivateKey = %s\n' "$key"
    cat <<'WGCONF'
{config}
WGCONF
}} > "$tmp"
if wg show wg0 >/dev/null 2>&1; then
    peers=$(wg showconf wg0)
    printf '%s\n' "$peers" | awk '/^\[Peer\]/{{found=1}} found' >> "$tmp"
elif [ -f /etc/wireguard/wg0.conf ]; then
    awk '/^\[Peer\]/{{found=1}} found' /etc/wireguard/wg0.conf >> "$tmp"
fi
mv -f "$tmp" /etc/wireguard/wg0.conf"#,
            config = wg_conf
        );
        if let Err(e) = self.exec_checked(&write_conf_cmd, "write-config").await {
            progress.fail(DeploymentStep::ConfigureInterface, e.to_string());
            return Ok(progress);
        }
        progress.update_step(DeploymentStep::ConfigureInterface, StepResult::Success);

        // Step 6: 配置路由和防火墙
        progress.update_step(DeploymentStep::ConfigureRouting, StepResult::Running);

        // IP Forward
        let forward_cmd = "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-miaovps.conf && sysctl -p /etc/sysctl.d/99-miaovps.conf >/dev/null 2>&1";
        if let Err(e) = self.exec_checked(forward_cmd, "ip-forward").await {
            progress.fail(DeploymentStep::ConfigureRouting, e.to_string());
            return Ok(progress);
        }

        // NAT (iptables)
        let nat_cmd = "iptables -t nat -C POSTROUTING -o $(ip route show default | awk '{print $5}') -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o $(ip route show default | awk '{print $5}') -j MASQUERADE";
        if let Err(e) = self.exec_checked(nat_cmd, "nat").await {
            progress.fail(DeploymentStep::ConfigureRouting, e.to_string());
            return Ok(progress);
        }

        // FORWARD rules
        let fwd1 = "iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT";
        if let Err(e) = self.exec_checked(fwd1, "forward-wg0-in").await {
            progress.fail(DeploymentStep::ConfigureRouting, e.to_string());
            return Ok(progress);
        }
        let fwd2 = "iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT";
        if let Err(e) = self.exec_checked(fwd2, "forward-wg0-out").await {
            progress.fail(DeploymentStep::ConfigureRouting, e.to_string());
            return Ok(progress);
        }

        // WireGuard 的隧道 MTU 默认是 1380。没有 MSS clamp 时，部分公网路径
        // 会丢弃超过路径 MTU 的 TCP 分片，而 ICMP 太大报文又可能被过滤，最终
        // 表现为握手正常但 HTTPS/GitHub 下载严重降速。规则必须幂等，避免每次
        // 迁移端口或重新部署都重复追加。
        let mss_to_wg = format!(
            "iptables -t mangle -C FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss} 2>/dev/null || iptables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss}"
        );
        if let Err(e) = self.exec_checked(&mss_to_wg, "mss-clamp-to-wg").await {
            progress.fail(DeploymentStep::ConfigureRouting, e.to_string());
            return Ok(progress);
        }
        let mss_from_wg = format!(
            "iptables -t mangle -C FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss} 2>/dev/null || iptables -t mangle -A FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {mss}"
        );
        if let Err(e) = self.exec_checked(&mss_from_wg, "mss-clamp-from-wg").await {
            progress.fail(DeploymentStep::ConfigureRouting, e.to_string());
            return Ok(progress);
        }

        progress.update_step(DeploymentStep::ConfigureRouting, StepResult::Success);

        // Step 7: 启动 WireGuard
        progress.update_step(DeploymentStep::StartService, StepResult::Running);
        // `start` 对已 active 的服务什么也不做，重新部署后的配置不会生效。
        // Peer 已在上一步保留，因此这里可以安全 restart 并验证真实运行状态。
        let start_cmd = "systemctl enable wg-quick@wg0 >/dev/null 2>&1 && systemctl restart wg-quick@wg0 && systemctl is-active --quiet wg-quick@wg0 && echo 'active'";
        match self.exec_checked(start_cmd, "start-service").await {
            Ok(o) if o.contains("active") => {
                progress.update_step(DeploymentStep::StartService, StepResult::Success)
            }
            Ok(_) => {
                progress.fail(
                    DeploymentStep::StartService,
                    "WireGuard 启动后未进入 active 状态".into(),
                );
                return Ok(progress);
            }
            Err(e) => {
                progress.fail(DeploymentStep::StartService, e.to_string());
                return Ok(progress);
            }
        }

        // Step 8: 创建第一台设备（由上层调用 add_peer 完成，此处占位）
        progress.update_step(DeploymentStep::CreateFirstDevice, StepResult::Success);

        // Step 9: 验证
        progress.update_step(DeploymentStep::Verify, StepResult::Running);
        let verify_cmd = format!(
            "test \"$(wg show wg0 listen-port 2>/dev/null)\" = \"{}\" && wg show wg0 | head -5",
            options.wireguard_port
        );
        match self.exec_root(&verify_cmd, "verify-wg").await {
            Ok(verify) if verify.contains("interface: wg0") => {
                progress.update_step(DeploymentStep::Verify, StepResult::Success);
                progress.complete();
            }
            Ok(_) => progress.fail(
                DeploymentStep::Verify,
                format!("wg0 未监听请求端口 {}", options.wireguard_port),
            ),
            Err(e) => progress.fail(DeploymentStep::Verify, e.to_string()),
        }

        info!(target: "provisioner", server=%self.server_id, status=?progress.status, "部署完成");
        Ok(progress)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  Peer 管理
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// 添加 Peer（公钥 + AllowedIPs）
    pub async fn add_peer(&mut self, public_key: &str, allowed_ips: &str) -> Result<(), AppError> {
        let cmd = format!("wg set wg0 peer {} allowed-ips {}", public_key, allowed_ips);
        self.exec_checked(&cmd, "add-peer").await?;

        // 持久化：追加到 wg0.conf
        let persist = format!(
            r#"echo -e "\n[Peer]\nPublicKey = {pk}\nAllowedIPs = {ips}" >> /etc/wireguard/wg0.conf"#,
            pk = public_key,
            ips = allowed_ips
        );
        let _ = self.exec_checked(&persist, "persist-peer").await;
        Ok(())
    }

    /// 移除 Peer
    pub async fn remove_peer(&mut self, public_key: &str) -> Result<(), AppError> {
        let cmd = format!("wg set wg0 peer {} remove", public_key);
        self.exec_checked(&cmd, "remove-peer").await?;
        Ok(())
    }

    /// 获取 WireGuard 状态
    pub async fn get_status(&mut self) -> Result<String, AppError> {
        self.exec_checked("wg show wg0 2>/dev/null || echo 'not-running'", "wg-show")
            .await
    }

    /// Drop interface private and peer preshared keys on the server, before returning counters.
    pub async fn get_peer_stats(&mut self) -> Result<String, AppError> {
        self.exec_checked(
            "bash -o pipefail -c \"wg show wg0 dump | cut -f1,5-7 | tail -n +2\"",
            "wg-peer-stats",
        )
        .await
    }

    /// 获取服务器公钥
    pub async fn get_server_public_key(&mut self) -> Result<String, AppError> {
        self.exec_checked(
            "cat /etc/wireguard/public.key 2>/dev/null || echo ''",
            "get-pubkey",
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_transaction_rolls_back_or_commits_for_both_protocols() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/test-port-transaction.sh");
        assert!(std::process::Command::new("bash")
            .arg(script)
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn gateway_address_uses_first_host_not_network_address() {
        assert_eq!(gateway_address("10.66.66.0/24").unwrap(), "10.66.66.1/24");
        assert_eq!(
            gateway_address("192.168.10.128/25").unwrap(),
            "192.168.10.129/25"
        );
        assert!(gateway_address("10.0.0.0/31").is_err());
    }

    #[test]
    fn root_passes_command_through_unchanged() {
        assert_eq!(Privilege::Root.wrap("wg show wg0"), "wg show wg0");
    }

    #[test]
    fn sudo_nopassword_wraps_in_sh() {
        let out = Privilege::SudoNoPassword.wrap("wg show wg0");
        assert_eq!(out, "sudo -n sh -c 'wg show wg0'");
    }

    /// 带 heredoc 的脚本必须经 base64 传递 —— 明文拼进去会和 `sudo -S` 抢 stdin，
    /// 曾导致密码被写进目标配置文件
    #[test]
    fn sudo_password_never_inlines_script_text() {
        let script = "cat > /etc/wireguard/wg0.conf <<'EOF'\nPrivateKey = abc\nEOF";
        let out = Privilege::SudoPassword("pw123".into()).wrap(script);

        assert!(!out.contains("PrivateKey"), "脚本内容不能明文出现: {out}");
        assert!(!out.contains("<<'EOF'"), "heredoc 不能进命令行: {out}");
        assert!(out.contains("base64 -d"));
        assert!(out.contains(&base64_encode(script.as_bytes())));
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quotes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    /// describe() 会进日志，必须不含密码
    #[test]
    fn describe_does_not_leak_password() {
        let p = Privilege::SudoPassword("topsecret".into());
        assert!(!p.describe().contains("topsecret"));
        assert_eq!(p.describe(), "sudo (密码)");
    }

    #[test]
    fn base64_encode_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
