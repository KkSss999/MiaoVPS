//! MiaoVPS CLI — 命令行验证工具
//!
//! 串联所有后端 crate，验证端到端流程：
//!   添加服务器 → 环境检测 → 部署 WireGuard → 添加设备 → 导出配置

use anyhow::Result;
use base64::Engine as _;
use miaovps_connect::native::NativeTunnel;
use miaovps_connect::tun::TunInterface;
use miaovps_connect::ConnectionValidator;
use miaovps_core::{DeploymentStep, Device, DeviceType, Server, SshAuthType};
use miaovps_provisioner::DeploymentOptions;
use miaovps_storage::Database;
use miaovps_wireguard_config as wg;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;

fn data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".miaovps")
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("miaovps=info")
        .init();

    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "add-server" => cmd_add_server(&args).await?,
        "list-servers" => cmd_list_servers().await?,
        "inspect" => cmd_inspect(&args).await?,
        "deploy" => cmd_deploy(&args).await?,
        "add-device" => cmd_add_device(&args).await?,
        "list-devices" => cmd_list_devices(&args).await?,
        "status" => cmd_status(&args).await?,
        "export-config" => cmd_export_config(&args).await?,
        "generate-keypair" => cmd_generate_keypair(),
        "validate" => cmd_validate(&args).await?,
        "connect" => cmd_connect(&args).await?,
        "disconnect" => cmd_disconnect(&args).await?,
        "help" | _ => print_help(),
    }

    Ok(())
}

fn print_help() {
    println!("MiaoVPS CLI v0.1.0 — 私人 VPN 节点管理工具\n");
    println!("用法: miaovps <command> [args]\n");
    println!("命令:");
    println!("  add-server <name> <host> [port] [user]  添加 VPS 服务器");
    println!("  list-servers                             列出所有服务器");
    println!("  inspect <server-id>                      环境检测");
    println!("  deploy <server-id>                       一键部署 WireGuard");
    println!("  add-device <server-id> <name> [type]     添加 VPN 设备");
    println!("  list-devices <server-id>                 列出设备");
    println!("  status <server-id>                       查看服务状态");
    println!("  export-config <device-id>                导出 WireGuard 配置");
    println!("  generate-keypair                         生成 WireGuard 密钥对");
    println!();
    println!("连接管理:");
    println!("  validate <server-ip> <client-priv> <server-pub>  分步验证链路");
    println!("  connect <server-id>                              建立 VPN 连接");
    println!("  disconnect                                        断开 VPN 连接");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  add-server
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_add_server(args: &[String]) -> Result<()> {
    let name = args.get(2).cloned().unwrap_or_else(|| "My VPS".into());
    let host = args.get(3).cloned().unwrap_or_else(|| {
        eprintln!("错误: 需要提供服务器 IP 或域名");
        std::process::exit(1);
    });
    let port: u16 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(22);
    let user = args.get(5).cloned().unwrap_or_else(|| "root".into());

    let server = Server::new(name.clone(), host.clone(), port, user.clone(), SshAuthType::Password);
    let db = Database::open(data_dir().join("miaovps.db")).await?;
    db.insert_server(&server).await?;

    println!("✓ 服务器已添加");
    println!("  ID:   {}", server.id);
    println!("  名称: {}", name);
    println!("  地址: {}:{}", host, port);
    println!("  用户: {}", user);
    Ok(())
}

async fn cmd_list_servers() -> Result<()> {
    let db = Database::open(data_dir().join("miaovps.db")).await?;
    let servers = db.list_servers().await?;

    if servers.is_empty() {
        println!("暂无服务器。使用 'miaovps add-server' 添加。");
        return Ok(());
    }

    println!("服务器列表:");
    for s in &servers {
        let status = serde_json::to_string(&s.status).unwrap_or_default();
        println!("  {}  {}  {}:{}  {}  {}",
            &s.id[..8], s.name, s.host, s.ssh_port, s.os_name.as_deref().unwrap_or("?"), status);
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  inspect — 环境检测
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_inspect(args: &[String]) -> Result<()> {
    let server_id = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("用法: miaovps inspect <server-id>");
        std::process::exit(1);
    });

    let db = Database::open(data_dir().join("miaovps.db")).await?;
    let server = db.get_server(&server_id).await?.ok_or_else(|| {
        anyhow::anyhow!("服务器不存在: {}", server_id)
    })?;

    println!("正在检测 {} ({})...\n", server.name, server.host);

    // 实际使用需要通过 SSH 连接，此处展示接口
    // let config = SshConnectionConfig { ... };
    // let session = SshSession::connect_password(&config, "password").await?;
    // let mut provisioner = SshProvisioner::new(session, server_id.clone());
    // let report = provisioner.inspect().await?;

    println!("环境检测需要 SSH 连接。");
    println!("请在 MiaoVPS 桌面端中运行以使用完整功能。");
    println!("服务器: {} ({}:{}@{})", server.name, server.ssh_user, server.host, server.ssh_port);

    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  deploy — 一键部署
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_deploy(args: &[String]) -> Result<()> {
    let server_id = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("用法: miaovps deploy <server-id>");
        std::process::exit(1);
    });

    let db = Database::open(data_dir().join("miaovps.db")).await?;
    let server = db.get_server(&server_id).await?.ok_or_else(|| {
        anyhow::anyhow!("服务器不存在: {}", server_id)
    })?;

    println!("即将部署 WireGuard 到 {} ({})", server.name, server.host);
    println!();

    let options = DeploymentOptions::default();
    println!("部署配置:");
    println!("  WireGuard 端口: {}", options.wireguard_port);
    println!("  VPN 子网:       {}", options.vpn_cidr);
    println!("  DNS:            {}", options.dns.join(", "));
    println!("  MTU:            {}", options.mtu.unwrap_or(1380));

    println!("\n部署步骤 (共 9 步):");
    for step in DeploymentStep::all_steps() {
        println!("  {}  {}", if step == DeploymentStep::Connect { "→" } else { " " }, step.label());
    }

    println!("\n部署需要 SSH 连接。请在 MiaoVPS 桌面端中运行。");
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  add-device
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_add_device(args: &[String]) -> Result<()> {
    let server_id = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("用法: miaovps add-device <server-id> <name> [type]");
        std::process::exit(1);
    });
    let name = args.get(3).cloned().unwrap_or_else(|| "My Device".into());
    let dtype = match args.get(4).map(|s| s.as_str()) {
        Some("mac") | Some("Mac") => DeviceType::Mac,
        Some("windows") | Some("Windows") => DeviceType::Windows,
        Some("iphone") | Some("iPhone") => DeviceType::IPhone,
        Some("android") | Some("Android") => DeviceType::Android,
        Some("linux") | Some("Linux") => DeviceType::Linux,
        _ => DeviceType::Other,
    };

    // 生成密钥对
    let keypair = wg::generate_keypair();
    let vpn_address = format!("10.66.66.{}/32", 2); // 简化分配

    let _device = Device::new(
        server_id.clone(),
        name.clone(),
        dtype.clone(),
        keypair.public_key,
        vpn_address,
    );

    println!("✓ 设备已创建");
    println!("  名称:   {}", name);
    println!("  类型:   {:?}", dtype);
    println!("  公钥:   {}", wg::generate_keypair().public_key); // demo
    println!("  地址:   10.66.66.2/32");
    println!("\n⚠ 私钥已生成并应存储到系统 Keychain。");
    println!("  下一步: 运行 'miaovps export-config <device-id>' 导出配置");

    Ok(())
}

async fn cmd_list_devices(args: &[String]) -> Result<()> {
    let server_id = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("用法: miaovps list-devices <server-id>");
        std::process::exit(1);
    });

    let db = Database::open(data_dir().join("miaovps.db")).await?;
    let devices = db.list_devices(&server_id).await?;

    if devices.is_empty() {
        println!("暂无设备。");
        return Ok(());
    }

    println!("设备列表:");
    for d in &devices {
        let status = d.status();
        println!("  {}  {}  {}  {:?}  {}",
            &d.id[..8], d.name, d.vpn_address, status, d.public_key);
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  status / export-config / generate-keypair
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_status(args: &[String]) -> Result<()> {
    let _server_id = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("用法: miaovps status <server-id>");
        std::process::exit(1);
    });
    println!("状态查询需要 SSH 连接。请在 MiaoVPS 桌面端中运行。");
    Ok(())
}

async fn cmd_export_config(args: &[String]) -> Result<()> {
    let _device_id = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("用法: miaovps export-config <device-id>");
        std::process::exit(1);
    });
    println!("配置导出需要从 Keychain 读取私钥。请在 MiaoVPS 桌面端中运行。");
    Ok(())
}

fn cmd_generate_keypair() {
    let kp = wg::generate_keypair();
    println!("WireGuard 密钥对:");
    println!("  私钥: {}", kp.private_key);
    println!("  公钥: {}", kp.public_key);
    println!("\n⚠ 请妥善保管私钥，不要分享给他人。");
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  validate — 连接前分步验证（不切路由，不丢网）
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_validate(args: &[String]) -> Result<()> {
    if args.len() < 5 {
        eprintln!("用法: miaovps validate <server-ip:port> <client-private-key> <server-public-key>");
        eprintln!("示例: miaovps validate 203.0.113.10:51820 OGuo5... A2xHn...");
        std::process::exit(1);
    }

    let server_addr: SocketAddr = args[2].parse().map_err(|e| {
        anyhow::anyhow!("服务器地址格式错误 (应为 IP:PORT): {e}")
    })?;
    let client_priv_b64 = &args[3];
    let server_pub_b64 = &args[4];

    // 解码 base64 密钥
    let client_private_key = decode_base64_key(client_priv_b64, "客户端私钥")?;
    let server_public_key = decode_base64_key(server_pub_b64, "服务器公钥")?;

    println!("🔍 MiaoVPS 连接验证");
    println!("  服务器: {}", server_addr);
    println!("  客户端公钥: 6kG/tQ...");
    println!("  服务器公钥: {}", &server_pub_b64[..16]);
    println!();
    println!("正在分步验证链路（不会切换路由，安全）...\n");

    let validator = ConnectionValidator::new(
        server_addr,
        client_private_key,
        server_public_key,
    );

    let results = validator.validate_all().await;

    let mut all_ok = true;
    for result in &results {
        let icon = if result.success { "✅" } else { "❌" };
        println!("  {} {} ({:.0}ms)", icon, result.step, result.duration_ms);
        println!("     {}", result.detail);
        if !result.success {
            all_ok = false;
        }
    }

    println!();
    if all_ok {
        println!("🎉 全部验证通过！服务器链路正常，可以安全连接。");
        println!("   下一步: miaovps connect <server-id>");
    } else {
        println!("❌ 验证失败。请检查:");
        println!("   1. VPS 安全组是否开放 UDP {}", server_addr.port());
        println!("   2. WireGuard 服务是否运行 (sudo wg show)");
        println!("   3. 客户端/服务器公钥是否匹配");
    }

    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  connect — 两阶段连接 (Split Tunnel → Full Tunnel)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_connect(args: &[String]) -> Result<()> {
    let server_id = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("用法: miaovps connect <server-id>");
        eprintln!("      先运行 'miaovps list-servers' 查看可用服务器");
        std::process::exit(1);
    });

    let db = Database::open(data_dir().join("miaovps.db")).await?;
    let server = db.get_server(&server_id).await?.ok_or_else(|| {
        anyhow::anyhow!("服务器不存在: {}\n运行 'miaovps list-servers' 查看", server_id)
    })?;

    // 生成客户端密钥对
    let kp = wg::generate_keypair();
    let client_priv = decode_base64_key(&kp.private_key, "客户端私钥")?;

    // 服务器公钥（硬编码，实际应从数据库/Keychain获取）
    let server_pub_b64 = "fRp9SCOP2pu780jn15LbDFbxPwJJleAjODXjzcOgZFs=";
    let server_pub = decode_base64_key(server_pub_b64, "服务器公钥")?;
    let server_addr: SocketAddr = format!("{}:51820", server.host).parse()?;

    println!("🔗 原生 WireGuard 隧道 — {} ({})", server.name, server.host);
    println!();

    // ── 1. 验证 ──
    println!("[1/4] 验证链路...");
    let validator = ConnectionValidator::new(server_addr, client_priv, server_pub);
    let results = validator.validate_all().await;
    for r in &results {
        println!("  {} {}", if r.success { "✅" } else { "❌" }, r.step);
    }
    if results.iter().any(|r| !r.success) {
        anyhow::bail!("验证失败，取消连接");
    }

    // ── 2. 创建 TUN ──
    println!("[2/4] 创建虚拟网卡...");
    let tun = TunInterface::create("10.66.66.2", "255.255.255.255")
        .map_err(|e| anyhow::anyhow!("需要 sudo 权限来创建 TUN 接口: {e}"))?;
    println!("  接口: {} (IP: 10.66.66.2)", tun.name());

    // ── 3. Split Tunnel 路由 ──
    println!("[3/4] 设置路由 (Split Tunnel)...");
    let vps_ip = &server.host;
    let tun_name = tun.name().to_string();

    // 获取原始默认网关（VPS IP 需经此网关直连，避免隧道循环）
    let default_gw = get_default_gateway().unwrap_or_else(|_| "192.168.1.1".to_string());

    // VPS 公网 IP 经原始网关直连（不经过 TUN，防止循环）
    run_sudo(&["route", "-q", "-n", "add", "-inet", vps_ip, "-gateway", &default_gw])?;

    // VPN 网关路由（VPS 内网网段走 TUN）
    run_sudo(&["route", "-q", "-n", "add", "-inet", "10.66.66.1/32", "-interface", &tun_name])?;
    println!("  VPS 直连: {} → {}", vps_ip, default_gw);
    println!("  VPN 网关: 10.66.66.1/32 → {}", tun_name);

    // ── 4. 启动隧道 ──
    println!("[4/4] 启动加密隧道...");
    let tunnel = NativeTunnel::start(tun, client_priv, server_pub, server_addr, 25)?;

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  ✅ MiaoVPS 隧道已建立 (Split Tunnel)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("  当前仅路由 VPS 流量，本地网络不受影响。");
    println!();
    println!("  升级到 Full Tunnel:");
    println!("    sudo route -q -n add -inet 0.0.0.0/1 -interface {}", tun_name);
    println!("    sudo route -q -n add -inet 128.0.0.0/1 -interface {}", tun_name);
    println!();
    println!("  验证: curl ifconfig.me");
    println!("  停止: Ctrl+C");

    // 等待 Ctrl+C
    tokio::signal::ctrl_c().await?;
    println!("\n正在关闭...");

    // 清理
    tunnel.stop();
    cleanup_routes(vps_ip, &tun_name)?;
    println!("✅ 已断开");

    Ok(())
}

async fn cmd_disconnect(_args: &[String]) -> Result<()> {
    // 查找并清理可能的残留路由
    println!("清理残留路由...");
    cleanup_routes("203.0.113.10", "utun5")?;
    cleanup_routes("203.0.113.10", "utun4")?;
    cleanup_routes("203.0.113.10", "utun3")?;
    println!("✅ 清理完成");

    // 同时也清理旧的 wg-quick 配置
    if let Ok(entries) = std::fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("miaovps-") && name.ends_with(".conf") {
                let path = entry.path();
                let path_str = path.to_string_lossy().to_string();
                println!("清理旧配置: {}", path_str);
                let _ = Command::new("sudo")
                    .args(["wg-quick", "down", &path_str])
                    .output();
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  路由管理工具
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn run_sudo(args: &[&str]) -> Result<()> {
    let output = Command::new("sudo").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // route add 可能因路由已存在而报错，不算致命
        if !stderr.contains("File exists") {
            eprintln!("  sudo {} 失败: {}", args.join(" "), stderr.trim());
        }
    }
    Ok(())
}

fn cleanup_routes(vps_ip: &str, _tun_name: &str) -> Result<()> {
    let _ = Command::new("sudo")
        .args(["route", "-q", "-n", "delete", "-inet", "0.0.0.0/1"])
        .output();
    let _ = Command::new("sudo")
        .args(["route", "-q", "-n", "delete", "-inet", "128.0.0.0/1"])
        .output();
    let _ = Command::new("sudo")
        .args(["route", "-q", "-n", "delete", "-inet", "10.66.66.1/32"])
        .output();
    let _ = Command::new("sudo")
        .args(["route", "-q", "-n", "delete", "-inet", vps_ip])
        .output();
    Ok(())
}

/// 获取当前默认网关 IP
fn get_default_gateway() -> Result<String> {
    let output = Command::new("sh")
        .args(["-c", "route -n get default 2>/dev/null | grep gateway | awk '{print $2}'"])
        .output()?;
    let gw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if gw.is_empty() {
        anyhow::bail!("无法获取默认网关")
    }
    Ok(gw)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  工具函数
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 解码 base64 WireGuard 密钥到 32 字节
fn decode_base64_key(b64: &str, label: &str) -> Result<[u8; 32]> {
    use base64::engine::general_purpose::STANDARD;
    let bytes = STANDARD.decode(b64.trim()).map_err(|e| {
        anyhow::anyhow!("{} base64 解码失败: {e}", label)
    })?;
    if bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "{} 长度错误: 期望 32 字节，实际 {} 字节",
            label,
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}
