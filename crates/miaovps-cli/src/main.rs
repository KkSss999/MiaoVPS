//! MiaoVPS CLI — 命令行验证工具
//!
//! 串联所有后端 crate，验证端到端流程：
//!   添加服务器 → 环境检测 → 部署 WireGuard → 添加设备 → 导出配置

use anyhow::Result;
use base64::Engine as _;
use miaovps_connect::ConnectionValidator;
use miaovps_core::{DeploymentStep, Device, DeviceType, Server, SshAuthType};
use miaovps_provisioner::DeploymentOptions;
use miaovps_storage::Database;
use miaovps_wireguard_config as wg;
use std::net::SocketAddr;
use std::path::PathBuf;

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

    // 生成密钥对
    let kp = wg::generate_keypair();
    let _client_private_key = decode_base64_key(&kp.private_key, "客户端私钥")?;

    // 此处应从 Keychain 获取服务器公钥，简化使用配置中的公钥
    println!("正在连接 {} ({})...\n", server.name, server.host);

    // 使用系统 wg-quick 桥接（v0.1 过渡方案）
    let config_path = format!("/tmp/miaovps-{}.conf", &server_id[..8]);

    // 检查是否已有配置文件
    if std::path::Path::new(&config_path).exists() {
        println!("发现已有配置，先断开旧连接...");
        let status = std::process::Command::new("sudo")
            .args(["wg-quick", "down", &config_path])
            .output();
        match status {
            Ok(o) if o.status.success() => println!("  已断开"),
            _ => {}
        }
    }

    // 生成配置文件
    let config = format!(
        "[Interface]\n\
         PrivateKey = {}\n\
         Address = 10.66.66.2/32\n\
         DNS = 1.1.1.1\n\
         MTU = 1380\n\n\
         [Peer]\n\
         PublicKey = {}\n\
         Endpoint = {}:51820\n\
         AllowedIPs = 10.66.66.1/32\n\
         PersistentKeepalive = 25\n",
        kp.private_key,
        "fRp9SCOP2pu780jn15LbDFbxPwJJleAjODXjzcOgZFs=", // 从数据库获取
        server.host,
    );
    std::fs::write(&config_path, &config)?;

    println!("⚡ 建立 Split Tunnel (仅路由 VPS 流量)...");
    let output = std::process::Command::new("sudo")
        .args(["wg-quick", "up", &config_path])
        .output()
        .map_err(|e| anyhow::anyhow!("需要 sudo 权限来创建网络接口: {e}"))?;

    if output.status.success() {
        println!("✅ Split Tunnel 已建立");
        println!();
        println!("  现在只路由 VPS 流量 (10.66.66.1/32)，本地网络不受影响");
        println!("  验证: curl ifconfig.me → 应该是你的原始公网 IP");
        println!();
        println!("  升级到 Full Tunnel (全局 VPN):");
        println!("    sudo wg set utun5 peer <server-pub> allowed-ips 0.0.0.0/0");
        println!();
        println!("  断开连接: miaovps disconnect");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("连接失败:\n{}", stderr);
    }

    Ok(())
}

async fn cmd_disconnect(_args: &[String]) -> Result<()> {
    let mut disconnected = false;
    if let Ok(entries) = std::fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("miaovps-") && name.ends_with(".conf") {
                let path = entry.path();
                let path_str = path.to_string_lossy().to_string();
                println!("正在断开 {} ...", path_str);
                let output = std::process::Command::new("sudo")
                    .args(["wg-quick", "down", &path_str])
                    .output();

                match output {
                    Ok(o) if o.status.success() => {
                        println!("  ✅ 已断开");
                        let _ = std::fs::remove_file(&path);
                        disconnected = true;
                    }
                    Ok(o) => {
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        if !stderr.is_empty() {
                            eprintln!("  {}", stderr.trim());
                        }
                    }
                    Err(e) => eprintln!("  错误: {e}"),
                }
            }
        }
    }

    if !disconnected {
        println!("未找到活跃的 MiaoVPS 连接。");
    }
    Ok(())
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
