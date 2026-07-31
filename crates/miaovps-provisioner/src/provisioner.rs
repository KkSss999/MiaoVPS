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

/// 命令过长时截断，用于日志与错误信息
fn elide(cmd: &str) -> String {
    let one: String = cmd.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    if one.chars().count() <= 100 {
        one
    } else {
        format!("{}…", one.chars().take(100).collect::<String>())
    }
}

/// 把 SshError 转成 AppError，保留命令上下文
fn ssh_err(cmd: &str, e: miaovps_ssh::SshError) -> AppError {
    AppError::new(
        ErrorCode::InternalError,
        "远程命令执行失败",
        format!("{e}"),
    )
    .with_technical(format!("命令: {cmd}"))
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
        out.push(if chunk.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

pub struct SshProvisioner {
    session: SshSession,
    server_id: String,
    privilege: Privilege,
}

impl SshProvisioner {
    pub fn new(session: SshSession, server_id: String) -> Self {
        Self { session, server_id, privilege: Privilege::Root }
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
        // 日志里不能出现 wrap 后的命令 —— sudo 密码在里面
        info!(target: "provisioner", server=%self.server_id, step, "执行: {}", elide(cmd));
        let wrapped = self.privilege.wrap(cmd);
        let out = self
            .session
            .exec_raw(&wrapped)
            .await
            .map_err(|e| ssh_err(&elide(cmd), e))?;

        debug!(target: "provisioner", step, code=?out.exit_status,
               output=%out.stdout.chars().take(200).collect::<String>());

        if !out.success() {
            let detail = if out.stderr.trim().is_empty() {
                out.stdout.trim().to_string()
            } else {
                out.stderr.trim().to_string()
            };
            return Err(AppError::new(
                ErrorCode::InternalError,
                format!("步骤失败: {step}"),
                detail.chars().take(400).collect::<String>(),
            )
            .with_technical(format!(
                "命令: {} · 退出码: {:?} · 提权: {}",
                elide(cmd),
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
        let os = self.exec("cat /etc/os-release 2>/dev/null || cat /etc/lsb-release 2>/dev/null").await.unwrap_or_default();
        let is_ubuntu = os.contains("Ubuntu") || os.contains("ubuntu");
        let version = if os.contains("24.04") { "24.04" } else if os.contains("22.04") { "22.04" } else { "unknown" };

        if is_ubuntu && version != "unknown" {
            report.add_item(DetectKey::Os, DetectStatus::Pass, &format!("Ubuntu {}", version), None);
        } else if is_ubuntu {
            report.add_item(DetectKey::Os, DetectStatus::Warning, "Ubuntu 但版本非 22.04/24.04", Some("建议使用 Ubuntu 22.04 或 24.04 LTS"));
        } else {
            report.add_item(DetectKey::Os, DetectStatus::Blocked, &format!("不支持的系统: {}", os.lines().next().unwrap_or("unknown")), Some("需要 Ubuntu 22.04 或 24.04"));
        }

        // 2. 架构
        let arch = self.exec("uname -m").await.unwrap_or_default().trim().to_string();
        match arch.as_str() {
            "x86_64" | "aarch64" => report.add_item(DetectKey::Arch, DetectStatus::Pass, &arch, None),
            _ => report.add_item(DetectKey::Arch, DetectStatus::Blocked, &arch, Some("需要 x86_64 或 arm64")),
        }

        // 3. root/sudo 权限
        let whoami = self.exec("whoami").await.unwrap_or_default().trim().to_string();
        if whoami == "root" {
            report.add_item(DetectKey::Privilege, DetectStatus::Pass, "root 用户", None);
        } else {
            let sudo = self.exec("sudo -n true 2>/dev/null && echo ok || echo no").await.unwrap_or_default();
            if sudo.contains("ok") {
                report.add_item(DetectKey::Privilege, DetectStatus::Pass, "免交互 sudo", None);
            } else {
                report.add_item(DetectKey::Privilege, DetectStatus::Blocked, "需要 root 或免交互 sudo", Some("请使用 root 登录或配置 NOPASSWD sudo"));
            }
        }

        // 4. 公网 IPv4
        let ip = self.exec("curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo 'unknown'").await.unwrap_or_default().trim().to_string();
        if ip != "unknown" && !ip.is_empty() {
            report.add_item(DetectKey::PublicIpv4, DetectStatus::Pass, &ip, None);
        } else {
            report.add_item(DetectKey::PublicIpv4, DetectStatus::Warning, "无法检测公网 IP", Some("可能影响 VPN 连通性"));
        }

        // 5. WireGuard 安装状态
        let wg = self.exec("which wg 2>/dev/null && wg --version 2>/dev/null || echo 'not-installed'").await.unwrap_or_default();
        if wg.contains("not-installed") {
            report.add_item(DetectKey::WireGuard, DetectStatus::Pass, "可安装", None);
        } else {
            report.add_item(DetectKey::WireGuard, DetectStatus::Pass, &format!("已安装: {}", wg.trim()), None);
        }

        // 6. systemd
        let systemd = self.exec("systemctl --version 2>/dev/null | head -1 || echo 'no'").await.unwrap_or_default();
        if systemd.contains("systemd") {
            report.add_item(DetectKey::Systemd, DetectStatus::Pass, systemd.trim(), None);
        } else {
            report.add_item(DetectKey::Systemd, DetectStatus::Blocked, "systemd 不可用", Some("需要 systemd 管理 WireGuard 服务"));
        }

        // 7. IP Forward
        let forward = self.exec("sysctl net.ipv4.ip_forward 2>/dev/null").await.unwrap_or_default();
        if forward.contains("= 1") {
            report.add_item(DetectKey::IpForward, DetectStatus::Pass, "已开启", None);
        } else {
            report.add_item(DetectKey::IpForward, DetectStatus::Pass, "可配置", None);
        }

        // 8. 防火墙
        let fw = self.exec("which ufw 2>/dev/null && ufw status 2>/dev/null || which iptables 2>/dev/null && echo 'iptables' || echo 'none'").await.unwrap_or_default();
        report.add_item(DetectKey::Firewall, DetectStatus::Pass, fw.trim(), None);

        // 9. UDP 端口
        //
        // 占用者是 wg0 自己时不算阻塞 —— 重新检测一台已经部署好的机器必然
        // 撞上自己监听的 51820，报「阻塞」会让用户以为部署失败。
        // WireGuard 是内核模块，socket 不挂在用户态进程上，所以只能反过来
        // 问 wg：wg0 的 listen-port 是不是它。
        let port_check = self.exec("ss -uln | grep ':51820 ' 2>/dev/null && echo 'occupied' || echo 'free'").await.unwrap_or_default();
        if port_check.contains("free") {
            report.add_item(DetectKey::UdpPort, DetectStatus::Pass, "51820 可用", None);
        } else {
            // 走 exec_root：`wg show` 需要 root。`|| echo ''` 保证退出码为 0，
            // 没有 wg0 时不会被 exec_root 的非零码检查判成失败。
            let owner = self
                .exec_root("wg show wg0 listen-port 2>/dev/null || echo ''", "detect-port")
                .await
                .unwrap_or_default();
            if owner.trim() == "51820" {
                report.add_item(
                    DetectKey::UdpPort,
                    DetectStatus::Pass,
                    "51820 已被本机 wg0 占用（重新部署会复用）",
                    None,
                );
            } else {
                report.add_item(DetectKey::UdpPort, DetectStatus::Blocked, "51820 已被其他服务占用", Some("请更换 WireGuard 监听端口或释放该端口"));
            }
        }

        // 10. 磁盘
        let disk = self.exec("df -BM / | tail -1 | awk '{print $4}' 2>/dev/null || echo '0'").await.unwrap_or_default().trim().to_string();
        let disk_mb: u64 = disk.trim_end_matches('M').parse().unwrap_or(0);
        if disk_mb > 200 {
            report.add_item(DetectKey::Disk, DetectStatus::Pass, &format!("{}MB 可用", disk_mb), None);
        } else {
            report.add_item(DetectKey::Disk, DetectStatus::Blocked, &format!("仅 {}MB", disk_mb), Some("需要至少 200MB"));
        }

        // 11. 内存
        let mem = self.exec("free -m | grep Mem | awk '{print $7}' 2>/dev/null || echo '0'").await.unwrap_or_default().trim().to_string();
        let mem_mb: u64 = mem.parse().unwrap_or(0);
        if mem_mb > 256 {
            report.add_item(DetectKey::Memory, DetectStatus::Pass, &format!("{}MB 可用", mem_mb), None);
        } else {
            report.add_item(DetectKey::Memory, DetectStatus::Blocked, &format!("仅 {}MB", mem_mb), Some("需要至少 256MB"));
        }

        report.finalize();
        info!(target: "provisioner", server=%self.server_id, passed=%report.all_passed, blocked=%report.blocked, "环境检测完成");
        Ok(report)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  一键部署
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    pub async fn deploy(&mut self, options: &DeploymentOptions) -> Result<DeploymentProgress, AppError> {
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

        // Step 2: 备份
        progress.update_step(DeploymentStep::Backup, StepResult::Running);
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let backup_dir = format!("/var/lib/miaovps/backups/{}", ts);
        let backup_cmd = format!(
            "mkdir -p {dir} && cp -r /etc/wireguard {dir}/ 2>/dev/null; cp -r /etc/sysctl.d {dir}/ 2>/dev/null; echo 'ok'",
            dir = backup_dir
        );
        match self.exec_checked(&backup_cmd, "backup").await {
            Ok(o) if o.contains("ok") => progress.update_step(DeploymentStep::Backup, StepResult::Success),
            Ok(_) => progress.update_step(DeploymentStep::Backup, StepResult::Warning("部分备份失败".into())),
            Err(e) => {
                progress.fail(DeploymentStep::Backup, e.to_string());
                return Ok(progress);
            }
        }

        // Step 3: 安装 WireGuard（幂等）
        progress.update_step(DeploymentStep::InstallWireGuard, StepResult::Running);
        let install_cmd = "which wg >/dev/null 2>&1 && echo 'already-installed' || (apt-get update -qq && apt-get install -y -qq wireguard-tools 2>&1 && echo 'installed')";
        match self.exec_checked(install_cmd, "install-wg").await {
            Ok(o) if o.contains("already-installed") => progress.update_step(DeploymentStep::InstallWireGuard, StepResult::Success),
            Ok(o) if o.contains("installed") => progress.update_step(DeploymentStep::InstallWireGuard, StepResult::Success),
            Ok(_) => {
                progress.fail(DeploymentStep::InstallWireGuard, "安装 WireGuard 失败".into());
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
            Ok(o) if o.contains("keys-exist") || o.contains("keys-generated") => progress.update_step(DeploymentStep::GenerateServerKeys, StepResult::Success),
            Ok(_) => progress.fail(DeploymentStep::GenerateServerKeys, "生成密钥失败".into()),
            Err(e) => {
                progress.fail(DeploymentStep::GenerateServerKeys, e.to_string());
                return Ok(progress);
            }
        }

        // 获取服务器公钥 —— 客户端连接必须用它，不能丢弃
        let server_pubkey = match self.exec_root("cat /etc/wireguard/public.key", "read-pubkey").await
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

        // 私钥读取失败绝不能静默继续 —— 原实现 unwrap_or_default() 会把
        // 空字符串写进 wg0.conf，部署"成功"但服务永远起不来
        let server_private = match self
            .exec_root("cat /etc/wireguard/private.key", "read-privkey")
            .await
        {
            Ok(k) => k.trim().to_string(),
            Err(e) => {
                progress.fail(DeploymentStep::ConfigureInterface, e.to_string());
                return Ok(progress);
            }
        };
        if server_private.is_empty() {
            progress.fail(
                DeploymentStep::ConfigureInterface,
                "服务器私钥为空 —— 拒绝写入无效配置".into(),
            );
            return Ok(progress);
        }
        let wg_conf = format!(
            "[Interface]\nPrivateKey = {}\nListenPort = {}\nAddress = {}\n",
            server_private, options.wireguard_port, options.vpn_cidr
        );
        // 原子写入：写临时文件 → 验证 → 替换
        let write_conf_cmd = format!(
            r#"cat > /etc/wireguard/wg0.conf.tmp <<'WGCONF'
{config}
WGCONF
# 重新部署时不能删掉已有设备。优先从内核运行态提取 Peer（它比磁盘配置
# 更可信，也能修复旧版本已经覆盖过 wg0.conf 的情况）；首次部署则没有 Peer。
if wg show wg0 >/dev/null 2>&1; then
    wg showconf wg0 | awk '/^\[Peer\]/{{found=1}} found' >> /etc/wireguard/wg0.conf.tmp
elif [ -f /etc/wireguard/wg0.conf ]; then
    awk '/^\[Peer\]/{{found=1}} found' /etc/wireguard/wg0.conf >> /etc/wireguard/wg0.conf.tmp
fi
[ -s /etc/wireguard/wg0.conf.tmp ] && chmod 600 /etc/wireguard/wg0.conf.tmp && mv /etc/wireguard/wg0.conf.tmp /etc/wireguard/wg0.conf && echo 'ok' || echo 'failed'"#,
            config = wg_conf
        );
        match self.exec_checked(&write_conf_cmd, "write-config").await {
            Ok(o) if o.contains("ok") => progress.update_step(DeploymentStep::ConfigureInterface, StepResult::Success),
            Ok(_) => progress.fail(DeploymentStep::ConfigureInterface, "写入配置失败".into()),
            Err(e) => {
                progress.fail(DeploymentStep::ConfigureInterface, e.to_string());
                return Ok(progress);
            }
        }

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

        progress.update_step(DeploymentStep::ConfigureRouting, StepResult::Success);

        // Step 7: 启动 WireGuard
        progress.update_step(DeploymentStep::StartService, StepResult::Running);
        // `start` 对已 active 的服务什么也不做，重新部署后的配置不会生效。
        // Peer 已在上一步保留，因此这里可以安全 restart 并验证真实运行状态。
        let start_cmd = "systemctl enable wg-quick@wg0 >/dev/null 2>&1 && systemctl restart wg-quick@wg0 && systemctl is-active --quiet wg-quick@wg0 && echo 'active'";
        match self.exec_checked(start_cmd, "start-service").await {
            Ok(o) if o.contains("active") => progress.update_step(DeploymentStep::StartService, StepResult::Success),
            Ok(_) => {
                progress.fail(DeploymentStep::StartService, "WireGuard 启动后未进入 active 状态".into());
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
        match self.exec_root("wg show wg0 | head -5", "verify-wg").await {
            Ok(verify) if verify.contains("interface: wg0") => {
                progress.update_step(DeploymentStep::Verify, StepResult::Success);
                progress.complete();
            }
            Ok(_) => progress.fail(DeploymentStep::Verify, "wg show 未返回 wg0 接口".into()),
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
        let cmd = format!(
            "wg set wg0 peer {} allowed-ips {}",
            public_key, allowed_ips
        );
        self.exec_checked(&cmd, "add-peer").await?;

        // 持久化：追加到 wg0.conf
        let persist = format!(
            r#"echo -e "\n[Peer]\nPublicKey = {pk}\nAllowedIPs = {ips}" >> /etc/wireguard/wg0.conf"#,
            pk = public_key, ips = allowed_ips
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
        self.exec_checked("wg show wg0 2>/dev/null || echo 'not-running'", "wg-show").await
    }

    /// 获取服务器公钥
    pub async fn get_server_public_key(&mut self) -> Result<String, AppError> {
        self.exec_checked("cat /etc/wireguard/public.key 2>/dev/null || echo ''", "get-pubkey").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn elide_collapses_newlines_and_truncates() {
        assert_eq!(elide("a\nb"), "a b");
        let long = "x".repeat(200);
        let out = elide(&long);
        assert_eq!(out.chars().count(), 101); // 100 + 省略号
        assert!(out.ends_with('…'));
    }
}
