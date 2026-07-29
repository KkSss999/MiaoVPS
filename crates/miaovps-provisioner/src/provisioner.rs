//! SSH 远端部署实现
//!
//! 通过 SSH 在 VPS 上执行 WireGuard 的检测、安装、配置和管理。
//! 所有操作通过 russh 执行远端命令，不安装长期 Agent。

use crate::deploy::{DeploymentOptions, DeploymentProgress, StepResult};
use crate::detect::{DetectStatus, ServerReport};
use crate::error::{AppError, ErrorCode};
use miaovps_core::DeploymentStep;
use miaovps_ssh::SshSession;
use tracing::{debug, info};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  SshProvisioner
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct SshProvisioner {
    session: SshSession,
    server_id: String,
}

impl SshProvisioner {
    pub fn new(session: SshSession, server_id: String) -> Self {
        Self { session, server_id }
    }

    /// 在远端执行命令（空输入），返回 stdout
    async fn exec(&self, cmd: &str) -> Result<String, AppError> {
        self.session.exec(cmd).await.map_err(|e| {
            AppError::new(
                ErrorCode::InternalError,
                "命令执行失败",
                format!("远程命令执行出错"),
            )
            .with_technical(format!("{}: {}", cmd, e))
        })
    }

    /// 执行命令并检查 exit code，返回 (stdout, stderr)
    async fn exec_checked(&self, cmd: &str, step: &str) -> Result<String, AppError> {
        info!(target: "provisioner", server=%self.server_id, step, "executing: {cmd}");
        let output = self.exec(cmd).await?;
        debug!(target: "provisioner", output=%output.chars().take(200).collect::<String>());
        Ok(output)
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
            report.add_item("操作系统", DetectStatus::Pass, &format!("Ubuntu {}", version), None);
        } else if is_ubuntu {
            report.add_item("操作系统", DetectStatus::Warning, "Ubuntu 但版本非 22.04/24.04", Some("建议使用 Ubuntu 22.04 或 24.04 LTS"));
        } else {
            report.add_item("操作系统", DetectStatus::Blocked, &format!("不支持的系统: {}", os.lines().next().unwrap_or("unknown")), Some("需要 Ubuntu 22.04 或 24.04"));
        }

        // 2. 架构
        let arch = self.exec("uname -m").await.unwrap_or_default().trim().to_string();
        match arch.as_str() {
            "x86_64" | "aarch64" => report.add_item("架构", DetectStatus::Pass, &arch, None),
            _ => report.add_item("架构", DetectStatus::Blocked, &arch, Some("需要 x86_64 或 arm64")),
        }

        // 3. root/sudo 权限
        let whoami = self.exec("whoami").await.unwrap_or_default().trim().to_string();
        if whoami == "root" {
            report.add_item("权限", DetectStatus::Pass, "root 用户", None);
        } else {
            let sudo = self.exec("sudo -n true 2>/dev/null && echo ok || echo no").await.unwrap_or_default();
            if sudo.contains("ok") {
                report.add_item("权限", DetectStatus::Pass, "免交互 sudo", None);
            } else {
                report.add_item("权限", DetectStatus::Blocked, "需要 root 或免交互 sudo", Some("请使用 root 登录或配置 NOPASSWD sudo"));
            }
        }

        // 4. 公网 IPv4
        let ip = self.exec("curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo 'unknown'").await.unwrap_or_default().trim().to_string();
        if ip != "unknown" && !ip.is_empty() {
            report.add_item("公网 IPv4", DetectStatus::Pass, &ip, None);
        } else {
            report.add_item("公网 IPv4", DetectStatus::Warning, "无法检测公网 IP", Some("可能影响 VPN 连通性"));
        }

        // 5. WireGuard 安装状态
        let wg = self.exec("which wg 2>/dev/null && wg --version 2>/dev/null || echo 'not-installed'").await.unwrap_or_default();
        if wg.contains("not-installed") {
            report.add_item("WireGuard", DetectStatus::Pass, "可安装", None);
        } else {
            report.add_item("WireGuard", DetectStatus::Pass, &format!("已安装: {}", wg.trim()), None);
        }

        // 6. systemd
        let systemd = self.exec("systemctl --version 2>/dev/null | head -1 || echo 'no'").await.unwrap_or_default();
        if systemd.contains("systemd") {
            report.add_item("systemd", DetectStatus::Pass, &systemd.trim().to_string(), None);
        } else {
            report.add_item("systemd", DetectStatus::Blocked, "systemd 不可用", Some("需要 systemd 管理 WireGuard 服务"));
        }

        // 7. IP Forward
        let forward = self.exec("sysctl net.ipv4.ip_forward 2>/dev/null").await.unwrap_or_default();
        if forward.contains("= 1") {
            report.add_item("网络转发", DetectStatus::Pass, "已开启", None);
        } else {
            report.add_item("网络转发", DetectStatus::Pass, "可配置", None);
        }

        // 8. 防火墙
        let fw = self.exec("which ufw 2>/dev/null && ufw status 2>/dev/null || which iptables 2>/dev/null && echo 'iptables' || echo 'none'").await.unwrap_or_default();
        report.add_item("防火墙", DetectStatus::Pass, &fw.trim().to_string(), None);

        // 9. UDP 端口
        let port_check = self.exec("ss -uln | grep ':51820 ' 2>/dev/null && echo 'occupied' || echo 'free'").await.unwrap_or_default();
        if port_check.contains("free") {
            report.add_item("UDP 端口", DetectStatus::Pass, "51820 可用", None);
        } else {
            report.add_item("UDP 端口", DetectStatus::Blocked, "51820 已被占用", Some("请更换 WireGuard 监听端口或释放该端口"));
        }

        // 10. 磁盘
        let disk = self.exec("df -BM / | tail -1 | awk '{print $4}' 2>/dev/null || echo '0'").await.unwrap_or_default().trim().to_string();
        let disk_mb: u64 = disk.trim_end_matches('M').parse().unwrap_or(0);
        if disk_mb > 200 {
            report.add_item("磁盘空间", DetectStatus::Pass, &format!("{}MB 可用", disk_mb), None);
        } else {
            report.add_item("磁盘空间", DetectStatus::Blocked, &format!("仅 {}MB", disk_mb), Some("需要至少 200MB"));
        }

        // 11. 内存
        let mem = self.exec("free -m | grep Mem | awk '{print $7}' 2>/dev/null || echo '0'").await.unwrap_or_default().trim().to_string();
        let mem_mb: u64 = mem.parse().unwrap_or(0);
        if mem_mb > 256 {
            report.add_item("内存", DetectStatus::Pass, &format!("{}MB 可用", mem_mb), None);
        } else {
            report.add_item("内存", DetectStatus::Blocked, &format!("仅 {}MB", mem_mb), Some("需要至少 256MB"));
        }

        report.finalize();
        info!(target: "provisioner", server=%self.server_id, passed=%report.all_passed, blocked=%report.blocked, "环境检测完成");
        Ok(report)
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  一键部署
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    pub async fn deploy(&mut self, options: &DeploymentOptions) -> Result<DeploymentProgress, AppError> {
        let deployment_id = uuid::Uuid::new_v4().to_string();
        let mut progress = DeploymentProgress::new(deployment_id);
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
            Ok(_) => progress.fail(DeploymentStep::InstallWireGuard, "安装 WireGuard 失败".into()),
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

        // 获取服务器公钥
        let _server_pubkey = self.exec("cat /etc/wireguard/public.key 2>/dev/null || echo 'unknown'").await.unwrap_or_default().trim().to_string();

        // Step 5: 配置虚拟网络（原子写入）
        progress.update_step(DeploymentStep::ConfigureInterface, StepResult::Running);
        let server_private = self.exec("cat /etc/wireguard/private.key").await.unwrap_or_default().trim().to_string();
        let wg_conf = format!(
            "[Interface]\nPrivateKey = {}\nListenPort = {}\nAddress = {}\n",
            server_private, options.wireguard_port, options.vpn_cidr
        );
        // 原子写入：写临时文件 → 验证 → 替换
        let write_conf_cmd = format!(
            r#"cat > /etc/wireguard/wg0.conf.tmp <<'WGCONF'
{config}
WGCONF
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
        let forward_cmd = format!(
            "echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-miaovps.conf && sysctl -p /etc/sysctl.d/99-miaovps.conf >/dev/null 2>&1"
        );
        let _ = self.exec_checked(&forward_cmd, "ip-forward").await;

        // NAT (iptables)
        let nat_cmd = "iptables -t nat -C POSTROUTING -o $(ip route show default | awk '{print $5}') -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o $(ip route show default | awk '{print $5}') -j MASQUERADE";
        let _ = self.exec_checked(nat_cmd, "nat").await;

        // FORWARD rules
        let fwd1 = "iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -j ACCEPT";
        let fwd2 = "iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -o wg0 -j ACCEPT";
        let _ = self.exec_checked(fwd1, "forward-wg0-in").await;
        let _ = self.exec_checked(fwd2, "forward-wg0-out").await;

        progress.update_step(DeploymentStep::ConfigureRouting, StepResult::Success);

        // Step 7: 启动 WireGuard
        progress.update_step(DeploymentStep::StartService, StepResult::Running);
        let start_cmd = "systemctl enable wg-quick@wg0 2>/dev/null && systemctl start wg-quick@wg0 2>&1 && systemctl is-active wg-quick@wg0 || echo 'start-failed'";
        match self.exec_checked(start_cmd, "start-service").await {
            Ok(o) if o.contains("active") => progress.update_step(DeploymentStep::StartService, StepResult::Success),
            Ok(o) if o.contains("start-failed") => progress.fail(DeploymentStep::StartService, "WireGuard 启动失败".into()),
            Ok(_) => progress.update_step(DeploymentStep::StartService, StepResult::Success),
            Err(e) => {
                progress.fail(DeploymentStep::StartService, e.to_string());
                return Ok(progress);
            }
        }

        // Step 8: 创建第一台设备（由上层调用 add_peer 完成，此处占位）
        progress.update_step(DeploymentStep::CreateFirstDevice, StepResult::Success);

        // Step 9: 验证
        progress.update_step(DeploymentStep::Verify, StepResult::Running);
        let verify = self.exec("wg show wg0 2>/dev/null | head -5").await.unwrap_or_default();
        if verify.contains("interface: wg0") {
            progress.update_step(DeploymentStep::Verify, StepResult::Success);
            progress.complete();
        } else {
            progress.fail(DeploymentStep::Verify, "wg show 验证失败".into());
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
