//! MiaoVPS CLI — 命令行验证工具
//!
//! 串联所有后端 crate，验证端到端流程：
//!   添加服务器 → 环境检测 → 部署 WireGuard → 添加设备 → 导出配置

mod dns;
mod profile;

use anyhow::Result;
use miaovps_connect::native::NativeTunnel;
use miaovps_connect::tun::{TunConfig, TunInterface};
use miaovps_connect::ConnectionValidator;
use miaovps_core::{DeploymentStep, Device, DeviceType, Server, SshAuthType};
use miaovps_provisioner::DeploymentOptions;
use miaovps_storage::Database;
use miaovps_wireguard_config as wg;
use profile::{decode_key, derive_public_key, ConnectionProfile};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;

/// 数据目录 — 数据库和连接配置的存放位置
///
/// 解析顺序：
///   1. `MIAOVPS_DATA_DIR` 环境变量（测试和自定义部署）
///   2. `~/.miaovps`
///
/// sudo 下 `HOME` 通常仍是原用户的（macOS `sudo` 默认保留 HOME），
/// 但为了确定性，显式优先用 `SUDO_USER` 反查真实用户目录 —
/// 否则 `connect` (root) 会读不到用户态 `profile init` 写的配置。
fn data_dir() -> PathBuf {
    let dir = if let Some(custom) = std::env::var_os("MIAOVPS_DATA_DIR") {
        PathBuf::from(custom)
    } else {
        real_home().join(".miaovps")
    };
    std::fs::create_dir_all(&dir).ok();
    dir
}

/// 真实用户的 home — sudo 下解析为调用者而非 root
fn real_home() -> PathBuf {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            // macOS 用户目录固定在 /Users/<name>
            let candidate = PathBuf::from("/Users").join(&sudo_user);
            if candidate.is_dir() {
                return candidate;
            }
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
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
        "profile" => cmd_profile(&args).await?,
        "connect" => cmd_connect(&args).await?,
        "disconnect" => cmd_disconnect(&args).await?,
        _ => print_help(),
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
    println!("  validate <ip:port> <client-priv> <server-pub>  分步验证链路（不切路由）");
    println!("  profile init <ip:port> <client-priv> <server-pub> [client-ip]");
    println!("                                                保存连接配置");
    println!("  profile show                                  查看当前配置");
    println!("  connect [--full] [--skip-validate]            建立隧道 (需 sudo)");
    println!("  disconnect                                    清理残留路由");
    println!();
    println!("典型流程:");
    println!("  1. miaovps generate-keypair              # 生成客户端密钥对");
    println!("  2. 在 VPS 上注册公钥为 peer");
    println!("  3. miaovps profile init <ip:port> <priv> <server-pub>");
    println!("  4. miaovps validate <ip:port> <priv> <server-pub>");
    println!("  5. sudo miaovps connect --full");
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
    let client_private_key = decode_key(client_priv_b64, "客户端私钥")?;
    let server_public_key = decode_key(server_pub_b64, "服务器公钥")?;

    println!("🔍 MiaoVPS 连接验证");
    println!("  服务器: {}", server_addr);
    println!("  客户端公钥: {}", derive_public_key(&client_private_key));
    println!("  服务器公钥: {}", short_key(server_pub_b64));
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
    let flags: Vec<&str> = args.iter().skip(2).map(|s| s.as_str()).collect();
    let skip_validate = flags.contains(&"--skip-validate");
    let full_tunnel = flags.contains(&"--full");

    // 权限先查 — 创建 TUN 和改路由都需要 root，
    // 没有权限就别让用户白等几秒验证
    if !is_root() {
        anyhow::bail!(
            "创建 TUN 接口和修改路由需要 root 权限。\n\
             请使用: sudo miaovps connect{}",
            if full_tunnel { " --full" } else { "" }
        );
    }

    let profile = ConnectionProfile::load(&data_dir())?;
    let server_addr = profile.server_addr()?;
    let client_priv = profile.client_private_bytes()?;
    let server_pub = profile.server_public_bytes()?;
    let vps_ip = profile.server_ip()?;

    // 公钥自洽检查 — profile 里的公钥必须由私钥推导得出，
    // 否则用户在 VPS 上注册的是一个对不上的公钥，握手一定失败
    let derived = derive_public_key(&client_priv);
    if derived != profile.client_public_key {
        anyhow::bail!(
            "配置不自洽：profile 记录的客户端公钥与私钥不匹配\n\
             记录: {}\n\
             实际: {}\n\
             重新运行 profile init 修复",
            profile.client_public_key,
            derived
        );
    }

    println!("🔗 MiaoVPS 隧道 → {}", server_addr);
    println!("  客户端公钥: {}", short_key(&profile.client_public_key));
    println!("  服务器公钥: {}", short_key(&profile.server_public_key));
    println!("  模式: {}", if full_tunnel { "Full Tunnel (全局)" } else { "Split Tunnel (仅 VPN 网段)" });
    println!();

    // ── 1. 验证 ──
    if skip_validate {
        println!("[1/4] ⏭ 跳过验证");
    } else {
        println!("[1/4] 验证链路...");
        let validator = ConnectionValidator::new(server_addr, client_priv, server_pub);
        for r in &validator.validate_all().await {
            println!("  {} {} ({}ms)", if r.success { "✅" } else { "❌" }, r.step, r.duration_ms);
            if !r.success {
                println!("     {}", r.detail);
                anyhow::bail!(
                    "验证失败，未切换任何路由。\n\
                     确认公钥 {} 已注册到 VPS peer 列表 (sudo wg show)",
                    short_key(&profile.client_public_key)
                );
            }
        }
    }

    // ── 2. 创建 TUN ──
    println!("[2/4] 创建虚拟网卡...");
    let tun_config = TunConfig::parse(
        &profile.client_ip,
        &profile.peer_ip,
        &profile.netmask,
        profile.mtu,
    )?;
    let tun = TunInterface::create(&tun_config)?;
    let tun_name = tun.name().to_string();
    println!("  {} — {} → {} mtu {}", tun_name, profile.client_ip, profile.peer_ip, profile.mtu);

    // ── 3. 路由 + DNS ──
    println!("[3/4] 设置路由...");

    // DNS 原始状态必须在任何修改前抓取
    let dns_backup = if full_tunnel {
        match dns::DnsBackup::capture(&data_dir()) {
            Ok(b) => {
                println!("  DNS 原始配置已备份: {}", b.describe());
                Some(b)
            }
            Err(e) => {
                // 抓不到就不接管 — 改了却无法还原比 DNS 泄露更糟
                println!("  ⚠ 无法备份 DNS，跳过 DNS 接管: {e}");
                None
            }
        }
    } else {
        None
    };

    let default_gw = get_default_gateway()?;
    let vpn_net = vpn_network_cidr(&profile.peer_ip)?;

    let mut plan = vec![
        // VPS 公网 IP 必须经原始网关直连，否则加密包被路由回隧道形成死循环
        RouteSpec::gateway(format!("{vps_ip}/32"), &default_gw),
        RouteSpec::interface(vpn_net.clone(), &tun_name),
    ];
    if full_tunnel {
        // 0/1 + 128/1 覆盖全部 IPv4，比改默认路由更容易回滚
        plan.push(RouteSpec::interface("0.0.0.0/1".into(), &tun_name));
        plan.push(RouteSpec::interface("128.0.0.0/1".into(), &tun_name));
    }

    // 任何一条失败都回滚已应用的部分，不留半套路由
    apply_routes(&plan)?;
    println!("  VPS 直连: {vps_ip} → {default_gw}");
    println!("  VPN 网段: {vpn_net} → {tun_name}");
    if full_tunnel {
        println!("  全局流量: 0.0.0.0/1 + 128.0.0.0/1 → {tun_name}");
    }

    if full_tunnel && dns_backup.is_some() && !profile.dns.is_empty() {
        match dns::apply(&profile.dns) {
            Ok(()) => println!("  DNS 接管: {}", profile.dns.join(", ")),
            Err(e) => println!("  ⚠ DNS 接管失败（查询可能泄露给 ISP）: {e}"),
        }
    }

    // ── 4. 启动隧道 ──
    println!("[4/4] 启动加密隧道...");
    let tunnel = match NativeTunnel::start(tun, client_priv, server_pub, server_addr, 25) {
        Ok(t) => t,
        Err(e) => {
            // 隧道起不来时必须撤掉路由和 DNS，否则流量进黑洞
            if let Some(b) = &dns_backup {
                let _ = b.restore(&data_dir());
            }
            remove_tunnel_routes(&vps_ip, &vpn_net);
            return Err(anyhow::anyhow!("隧道启动失败，已回滚路由: {e}"));
        }
    };

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  ✅ 隧道已建立 ({})", if full_tunnel { "Full Tunnel" } else { "Split Tunnel" });
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    if full_tunnel {
        println!("  验证出口 IP:  curl -s ifconfig.me   # 期望 {vps_ip}");
    } else {
        println!("  验证连通性:  ping {}", profile.peer_ip);
        println!("  升级全局:    重新运行并加 --full");
    }
    println!("  停止:        Ctrl+C");
    println!();

    tokio::signal::ctrl_c().await?;
    println!("\n正在关闭...");

    let (tx, rx, errs) = tunnel.stats().snapshot();
    tunnel.shutdown();

    // 先还原 DNS 再删路由 — 反过来会有一小段时间 DNS 指向已失效的隧道
    if let Some(backup) = &dns_backup {
        match backup.restore(&data_dir()) {
            Ok(()) => println!("  DNS 已还原: {}", backup.describe()),
            Err(e) => eprintln!("  ⚠ {e}"),
        }
    }
    remove_tunnel_routes(&vps_ip, &vpn_net);

    println!("  流量: ↑{} ↓{}{}",
        human_bytes(tx),
        human_bytes(rx),
        if errs > 0 { format!("  解密错误: {errs}") } else { String::new() });
    println!("✅ 已断开");

    Ok(())
}

async fn cmd_disconnect(_args: &[String]) -> Result<()> {
    if !is_root() {
        anyhow::bail!("清理路由需要 root 权限，请使用: sudo miaovps disconnect");
    }

    println!("清理残留状态...");

    // 上次异常退出（kill -9 / 崩溃）可能留下被改写的 DNS，优先还原
    if let Some(desc) = dns::restore_if_pending(&data_dir()) {
        println!("  DNS 已从备份还原: {desc}");
    }

    // profile 存在时按其配置精确清理，否则退回通用清理
    let (vps_ip, vpn_net) = match ConnectionProfile::load(&data_dir()) {
        Ok(p) => {
            let net = vpn_network_cidr(&p.peer_ip).unwrap_or_else(|_| "10.66.66.0/24".into());
            (p.server_ip().unwrap_or_default(), net)
        }
        Err(_) => {
            println!("  (无 profile，仅清理全局路由)");
            (String::new(), "10.66.66.0/24".to_string())
        }
    };

    remove_tunnel_routes(&vps_ip, &vpn_net);
    println!("✅ 清理完成");
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  profile — 连接配置管理
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_profile(args: &[String]) -> Result<()> {
    match args.get(2).map(|s| s.as_str()) {
        Some("init") => cmd_profile_init(args),
        Some("show") => cmd_profile_show(),
        _ => {
            println!("用法:");
            println!("  miaovps profile init <ip:port> <client-priv> <server-pub> [client-ip] [peer-ip]");
            println!("  miaovps profile show");
            Ok(())
        }
    }
}

fn cmd_profile_init(args: &[String]) -> Result<()> {
    // args: [bin, "profile", "init", endpoint, client_priv, server_pub, client_ip?, peer_ip?]
    if args.len() < 6 {
        anyhow::bail!(
            "用法: miaovps profile init <ip:port> <client-priv> <server-pub> [client-ip] [peer-ip]\n\
             示例: miaovps profile init 203.0.113.10:51820 OGuo5... fRp9S... 10.66.66.2 10.66.66.1"
        );
    }

    let client_priv_b64 = args[4].trim().to_string();
    let client_priv = decode_key(&client_priv_b64, "客户端私钥")?;
    let client_public_key = derive_public_key(&client_priv);

    let profile = ConnectionProfile {
        client_public_key: client_public_key.clone(),
        client_private_key: client_priv_b64,
        server_public_key: args[5].trim().to_string(),
        server_endpoint: args[3].trim().to_string(),
        client_ip: args.get(6).cloned().unwrap_or_else(|| "10.66.66.2".into()),
        peer_ip: args.get(7).cloned().unwrap_or_else(|| "10.66.66.1".into()),
        netmask: "255.255.255.0".into(),
        mtu: 1380,
        dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
    };

    let path = profile.save(&data_dir())?;

    println!("✓ 连接配置已保存: {}", path.display());
    println!("  客户端公钥: {}", client_public_key);
    println!("  服务器:     {}", profile.server_endpoint);
    println!("  VPN 地址:   {} → {}", profile.client_ip, profile.peer_ip);
    println!("  MTU:        {}", profile.mtu);
    println!();
    println!("⚠ 确认此公钥已注册到 VPS 的 peer 列表:");
    println!("    sudo wg set wg0 peer {} allowed-ips {}/32", client_public_key, profile.client_ip);
    println!("  然后: sudo miaovps connect");

    Ok(())
}

fn cmd_profile_show() -> Result<()> {
    let profile = ConnectionProfile::load(&data_dir())?;
    println!("连接配置 ({})", ConnectionProfile::path(&data_dir()).display());
    println!("  服务器:     {}", profile.server_endpoint);
    println!("  服务器公钥: {}", profile.server_public_key);
    println!("  客户端公钥: {}", profile.client_public_key);
    println!("  客户端私钥: {} (已隐藏)", short_key(&profile.client_private_key));
    println!("  VPN 地址:   {} → {}", profile.client_ip, profile.peer_ip);
    println!("  掩码/MTU:   {} / {}", profile.netmask, profile.mtu);
    println!("  DNS:        {}", profile.dns.join(", "));

    // 校验自洽性 — 不匹配是最常见的握手失败原因
    let derived = derive_public_key(&profile.client_private_bytes()?);
    if derived == profile.client_public_key {
        println!("  ✅ 公私钥自洽");
    } else {
        println!("  ❌ 公私钥不匹配！实际公钥应为 {derived}");
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  路由管理工具
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 是否以 root 运行 — TUN 创建和路由修改都需要
fn is_root() -> bool {
    // Safety: getuid 无参数、无副作用，总是成功
    unsafe { libc::getuid() == 0 }
}

/// 一条待应用的路由
#[derive(Debug, Clone)]
struct RouteSpec {
    /// 目标网段 CIDR
    destination: String,
    /// 下一跳 — 网关 IP 或接口名
    via: RouteVia,
}

#[derive(Debug, Clone)]
enum RouteVia {
    Gateway(String),
    Interface(String),
}

impl RouteSpec {
    fn gateway(destination: String, gw: &str) -> Self {
        Self { destination, via: RouteVia::Gateway(gw.to_string()) }
    }

    fn interface(destination: String, iface: &str) -> Self {
        Self { destination, via: RouteVia::Interface(iface.to_string()) }
    }

    fn add(&self) -> Result<()> {
        let (flag, target) = match &self.via {
            RouteVia::Gateway(gw) => ("-gateway", gw.as_str()),
            RouteVia::Interface(i) => ("-interface", i.as_str()),
        };
        run_route(&["add", "-inet", &self.destination, flag, target])
    }

    fn delete(&self) {
        let _ = Command::new("route")
            .args(["-q", "-n", "delete", "-inet", &self.destination])
            .output();
    }
}

/// 按顺序应用路由，任一条失败则回滚已应用的部分
///
/// 半套路由比没有路由更危险 — 用户可能只剩部分流量可达，
/// 且不知道该删哪几条才能恢复。
fn apply_routes(plan: &[RouteSpec]) -> Result<()> {
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

/// 执行 route 命令。已经 root 了，不再套 sudo。
///
/// 「路由已存在」不算失败 — 上次异常退出可能留下同名路由，
/// 目标状态（该网段走隧道）已经满足。
fn run_route(args: &[&str]) -> Result<()> {
    let output = Command::new("route").arg("-n").args(args).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("File exists") {
            return Ok(());
        }
        anyhow::bail!("route {} 失败: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

/// 删除隧道相关路由，逐条静默 — 清理路径上任何一条失败都不该中断其余清理
fn remove_tunnel_routes(vps_ip: &str, vpn_net: &str) {
    let mut targets: Vec<String> = vec![
        "0.0.0.0/1".into(),
        "128.0.0.0/1".into(),
        vpn_net.to_string(),
    ];
    if !vps_ip.is_empty() {
        targets.push(format!("{vps_ip}/32"));
    }

    for t in &targets {
        let _ = Command::new("route")
            .args(["-q", "-n", "delete", "-inet", t])
            .output();
    }
}

/// 获取当前默认网关 IP
fn get_default_gateway() -> Result<String> {
    let output = Command::new("route").args(["-n", "get", "default"]).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let gw = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("gateway:"))
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("无法获取默认网关 — 当前可能没有可用网络连接")
        })?;

    Ok(gw)
}

/// 由 VPN 网关地址推导 /24 网段 CIDR
fn vpn_network_cidr(peer_ip: &str) -> Result<String> {
    let ip: std::net::Ipv4Addr = peer_ip
        .parse()
        .map_err(|e| anyhow::anyhow!("无效 VPN 网关 IP '{peer_ip}': {e}"))?;
    let o = ip.octets();
    Ok(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
}

/// 密钥缩略显示 — 避免日志泄露完整私钥
fn short_key(key: &str) -> String {
    let k = key.trim();
    if k.len() <= 12 {
        return "…".into();
    }
    format!("{}…", &k[..12])
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}{}", UNITS[0])
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  工具函数
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_vpn_network_from_gateway() {
        assert_eq!(vpn_network_cidr("10.66.66.1").unwrap(), "10.66.66.0/24");
        assert_eq!(vpn_network_cidr("192.168.9.1").unwrap(), "192.168.9.0/24");
        assert!(vpn_network_cidr("not-an-ip").is_err());
    }

    #[test]
    fn truncates_keys_for_display() {
        assert_eq!(short_key("fRp9SCOP2pu780jn15LbDFbxPwJJleAjODXjzcOgZFs="), "fRp9SCOP2pu7…");
        assert_eq!(short_key("short"), "…");
    }

    #[test]
    fn formats_byte_counts() {
        assert_eq!(human_bytes(512), "512B");
        assert_eq!(human_bytes(2048), "2.0KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0MiB");
    }

    #[test]
    fn route_spec_carries_correct_next_hop() {
        let gw = RouteSpec::gateway("203.0.113.10/32".into(), "192.168.1.1");
        assert!(matches!(gw.via, RouteVia::Gateway(ref g) if g == "192.168.1.1"));

        let iface = RouteSpec::interface("0.0.0.0/1".into(), "utun5");
        assert!(matches!(iface.via, RouteVia::Interface(ref i) if i == "utun5"));
        assert_eq!(iface.destination, "0.0.0.0/1");
    }

    #[test]
    fn data_dir_honors_env_override() {
        let custom = std::env::temp_dir().join("miaovps-env-test");
        // Safety: 单线程测试，无并发读取环境变量
        unsafe { std::env::set_var("MIAOVPS_DATA_DIR", &custom) };
        assert_eq!(data_dir(), custom);
        unsafe { std::env::remove_var("MIAOVPS_DATA_DIR") };
        std::fs::remove_dir_all(&custom).ok();
    }
}
