//! MiaoVPS CLI — 命令行验证工具
//!
//! 串联所有后端 crate，验证端到端流程：
//!   添加服务器 → 环境检测 → 部署 WireGuard → 添加设备 → 导出配置

mod dns;
mod logging;
mod profile;

use anyhow::{Context, Result};
use miaovps_app::credentials::ServerCredential;
use miaovps_app::session::auth_type_hint;
use miaovps_app::tunnel::{TunnelMode, TunnelState, TunnelStatus};
use miaovps_app::AppService;
use miaovps_connect::native::NativeTunnel;
use miaovps_connect::tun::{TunConfig, TunInterface};
use miaovps_connect::ConnectionValidator;
use miaovps_core::{DeploymentStatus, DeploymentStep, Device, DeviceType, Server, SshAuthType};
use miaovps_provisioner::{DeploymentOptions, DetectStatus, StepEvent, StepResult};
use miaovps_storage::Database;
use miaovps_wireguard_config as wg;
use profile::{decode_key, derive_public_key, ConnectionProfile};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

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
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    // Only the actual tunnel process owns the diagnostic file, not elevation/daemon launchers.
    let dev = cmd == "connect"
        && args.iter().any(|a| a == "--dev")
        && is_root()
        && (!args.iter().any(|a| a == "--daemon") || std::env::var_os(DAEMON_MARKER).is_some());
    let log_dir = dev.then(data_dir);
    logging::init(log_dir.as_deref())?;

    match cmd {
        "add-server" => cmd_add_server(&args).await?,
        "remove-server" => cmd_remove_server(&args).await?,
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
        "__prepare-profile" => cmd_prepare_profile(&args).await?,
        "connect" => {
            let result = cmd_connect(&args).await;
            if let Err(error) = &result {
                tracing::error!(%error, "[连接] 连接失败");
            }
            result?;
        }
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
    println!("  remove-server <server-id>                删除本地 VPS 节点记录");
    println!("  list-servers                             列出所有服务器");
    println!("  inspect <server-id>                      环境检测");
    println!("  deploy <server-id> [--port <udp-port>]  一键部署/迁移 WireGuard 端口");
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
    println!("  connect [server-id] [--device <device-id>] [--full] [--port <udp-port>] [--skip-validate] [--daemon] [--dev] 建立隧道 (需 sudo)");
    println!("                                                --daemon 后台运行并写状态文件");
    println!("                                                --dev 追加详细日志到 ~/.miaovps/tunnel-dev.log（自动轮转）");
    println!("                                                Full Tunnel 会阻止公网 IPv6，避免未受保护的 IPv6 直连");
    println!("  disconnect                                    停止隧道并清理路由");
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

/// 打开应用服务层 —— 所有需要 SSH 的命令都从这里拿入口
async fn open_service() -> Result<AppService> {
    let dir = data_dir();
    let db = Database::open(dir.join("miaovps.db")).await?;
    Ok(AppService::new(db, dir.join("credentials")))
}

async fn cmd_add_server(args: &[String]) -> Result<()> {
    let positional: Vec<&String> = args
        .iter()
        .skip(2)
        .filter(|a| !a.starts_with("--"))
        .collect();
    let name = positional
        .first()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "My VPS".into());
    let Some(host) = positional.get(1).map(|s| s.to_string()) else {
        eprintln!(
            "用法: miaovps add-server <name> <host> [port] [user] --password <pw> | --key <path>"
        );
        std::process::exit(1);
    };
    let port: u16 = positional.get(2).and_then(|s| s.parse().ok()).unwrap_or(22);
    let user = positional
        .get(3)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "root".into());

    // 凭据必须给 —— 不给的话服务器记录建了也连不上，后面 inspect/deploy 全失败
    let password = flag_value(args, "--password");
    let key_path = flag_value(args, "--key");
    let passphrase = flag_value(args, "--passphrase");

    let (auth_type, credential) = match (password, key_path) {
        (Some(_), Some(_)) => {
            eprintln!("错误: --password 与 --key 只能选一个");
            std::process::exit(1);
        }
        (Some(pw), None) => (
            SshAuthType::Password,
            ServerCredential::Password { password: pw },
        ),
        (None, Some(path)) => (
            SshAuthType::PrivateKey,
            ServerCredential::PrivateKey {
                key_path: path,
                passphrase,
            },
        ),
        (None, None) => {
            eprintln!("错误: 需要提供 --password <pw> 或 --key <私钥路径>");
            eprintln!("      凭据存到 ~/.miaovps/credentials/<server-id>.json (0600)");
            std::process::exit(1);
        }
    };

    let svc = open_service().await?;
    let server = svc
        .add_server(
            name.clone(),
            host.clone(),
            port,
            user.clone(),
            auth_type,
            credential,
        )
        .await?;

    println!("✓ 服务器已添加");
    println!("  ID:   {}", server.id);
    println!("  名称: {}", name);
    println!("  地址: {}:{}", host, port);
    println!("  用户: {}", user);
    println!("  认证: {}", auth_type_hint(&server.auth_type));
    println!("\n下一步: miaovps inspect {}", &server.id[..8]);
    Ok(())
}

/// 删除本地节点记录、级联设备和本地 SSH 凭据；不连接远程服务器。
async fn cmd_remove_server(args: &[String]) -> Result<()> {
    let Some(prefix) = args.get(2) else {
        anyhow::bail!("用法: miaovps remove-server <server-id>");
    };
    let svc = open_service().await?;
    let server_id = resolve_server_id(&svc, prefix).await?;
    let server = svc
        .db
        .get_server(&server_id)
        .await?
        .context("服务器不存在")?;
    svc.db.delete_server(&server_id).await?;
    let credential_path = ServerCredential::path(&svc.cred_dir, &server_id);
    if credential_path.exists() {
        std::fs::remove_file(&credential_path)
            .with_context(|| format!("无法删除凭据文件 {}", credential_path.display()))?;
    }
    println!("✓ 已删除本地节点: {} ({})", server.name, server.host);
    println!("  远程服务器未被连接或修改");
    Ok(())
}

/// 取 `--flag value` 形式的参数值
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

/// 按 ID 前缀查服务器 —— 命令行里让用户敲完整 UUID 不现实
async fn resolve_server_id(svc: &AppService, prefix: &str) -> Result<String> {
    let servers = svc.list_servers().await?;
    let matches: Vec<&Server> = servers
        .iter()
        .filter(|s| s.id.starts_with(prefix))
        .collect();
    match matches.len() {
        0 => anyhow::bail!("服务器不存在: {prefix}（用 list-servers 查看）"),
        1 => Ok(matches[0].id.clone()),
        n => anyhow::bail!("{prefix} 匹配到 {n} 台服务器，请提供更长的 ID 前缀"),
    }
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
        println!(
            "  {}  {}  {}:{}  {}  {}",
            &s.id[..8],
            s.name,
            s.host,
            s.ssh_port,
            s.os_name.as_deref().unwrap_or("?"),
            status
        );
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  inspect — 环境检测
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_inspect(args: &[String]) -> Result<()> {
    let Some(prefix) = args.get(2) else {
        eprintln!("用法: miaovps inspect <server-id>");
        std::process::exit(1);
    };

    let svc = open_service().await?;
    let server_id = resolve_server_id(&svc, prefix).await?;
    let server = svc
        .list_servers()
        .await?
        .into_iter()
        .find(|s| s.id == server_id)
        .expect("resolve_server_id 已确认存在");

    println!(
        "正在检测 {} ({}:{})...\n",
        server.name, server.host, server.ssh_port
    );

    let report = svc.inspect_server(server_id).await?;

    for item in &report.items {
        let icon = match item.status {
            DetectStatus::Pass => "✅",
            DetectStatus::Warning => "⚠️ ",
            DetectStatus::Blocked => "❌",
        };
        println!("  {} {:<12} {}", icon, item.name, item.message);
        if let Some(sug) = &item.suggestion {
            println!("       → {}", sug);
        }
    }

    println!();
    if report.blocked {
        println!("❌ 存在阻塞项，部署前需要先解决上面标 ❌ 的问题。");
    } else if report.all_passed {
        println!("🎉 全部通过，可以部署: miaovps deploy {}", &prefix);
    } else {
        println!("⚠️  有警告项但不阻塞部署。");
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  deploy — 一键部署
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_deploy(args: &[String]) -> Result<()> {
    let Some(prefix) = args.get(2) else {
        eprintln!("用法: miaovps deploy <server-id> [--port <udp-port>]");
        std::process::exit(1);
    };

    let svc = open_service().await?;
    let server_id = resolve_server_id(&svc, prefix).await?;
    let server = svc
        .list_servers()
        .await?
        .into_iter()
        .find(|s| s.id == server_id)
        .expect("resolve_server_id 已确认存在");

    let mut options = DeploymentOptions::default();
    if let Some(port) = deploy_port_arg(args)? {
        options.wireguard_port = port;
    }
    let requested_wireguard_port = options.wireguard_port;
    println!("即将部署 WireGuard 到 {} ({})\n", server.name, server.host);
    println!("部署配置:");
    println!("  WireGuard 端口: {}", options.wireguard_port);
    println!("  VPN 子网:       {}", options.vpn_cidr);
    println!("  DNS:            {}", options.dns.join(", "));
    println!("  MTU:            {}", options.mtu.unwrap_or(1380));
    println!("\n开始部署 (共 9 步):");

    // 事件通道实时打印进度 —— 部署要跑几十秒，不能等结束才出结果
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<StepEvent>();
    let printer = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev.result {
                StepResult::Running => println!("  ⏳ {}", ev.step.label()),
                StepResult::Success => println!("  ✅ {}", ev.step.label()),
                StepResult::Warning(w) => println!("  ⚠️  {} — {}", ev.step.label(), w),
                StepResult::Failed(e) => println!("  ❌ {} — {}", ev.step.label(), e),
                StepResult::Pending => {}
            }
        }
    });

    let progress = svc
        .deploy_server(server_id, Some(options), Some(tx))
        .await?;
    // tx 已被 deploy_server 消费并 drop，printer 会自然收尾
    let _ = printer.await;

    println!();
    match progress.status {
        DeploymentStatus::Success => {
            println!("🎉 部署成功");
            if let Some(pk) = &progress.server_public_key {
                println!("  服务器公钥: {}", pk);
            }
            sync_profile_after_deploy(
                &server.host,
                requested_wireguard_port,
                progress.server_public_key.as_deref(),
            )?;
            println!("\n下一步: miaovps add-device {} <设备名>", prefix);
        }
        _ => {
            println!("❌ 部署未完成 (状态: {:?})", progress.status);
            for step in DeploymentStep::all_steps() {
                if let Some(StepResult::Failed(e)) = progress.steps.get(&step) {
                    println!("  失败步骤: {} — {}", step.label(), e);
                }
            }
        }
    }
    Ok(())
}

/// 部署成功后同步 CLI 共用的本地 profile，避免服务端端口变更而客户端仍
/// 连接旧端点。没有 profile（例如首次仅部署服务器）时保持正常，不创建
/// 一个没有设备密钥的伪配置。
fn sync_profile_after_deploy(
    server_host: &str,
    wireguard_port: u16,
    server_public_key: Option<&str>,
) -> Result<()> {
    let path = ConnectionProfile::path(&data_dir());
    if !path.exists() {
        return Ok(());
    }

    let mut profile = ConnectionProfile::load(&data_dir())?;
    let current = profile.server_addr()?;
    if current.ip().to_string() != server_host {
        println!(
            "  ⚠ 未同步 profile：当前端点 {} 与部署目标 {} 不一致",
            profile.server_endpoint, server_host
        );
        return Ok(());
    }

    let mut endpoint = current;
    endpoint.set_port(wireguard_port);
    profile.server_endpoint = endpoint.to_string();
    if let Some(public_key) = server_public_key {
        profile.server_public_key = public_key.to_string();
    }
    profile.save(&data_dir())?;
    println!("  ✓ 已同步本地连接端点: {}", profile.server_endpoint);
    Ok(())
}

/// WireGuard 是 UDP 协议；部分国内网络会对 51820 的回程流量做特殊处理。
/// 端口不是写死的：用户可在云防火墙放行后，以 `deploy --port 443` 进行
/// 事务化重部署。Provisioner 会保留运行中的 peer，成功后同步节点端口。
fn deploy_port_arg(args: &[String]) -> Result<Option<u16>> {
    let mut found = None;
    let mut index = 3;
    while index < args.len() {
        match args[index].as_str() {
            "--port" => {
                let raw = args
                    .get(index + 1)
                    .context("--port 需要一个 UDP 端口，例如 --port 443")?;
                let port = raw.parse::<u16>().context("--port 必须是 1-65535 的整数")?;
                if port == 0 {
                    anyhow::bail!("--port 必须是 1-65535 的整数");
                }
                if found.replace(port).is_some() {
                    anyhow::bail!("--port 只能指定一次");
                }
                index += 2;
            }
            unknown => anyhow::bail!("未知 deploy 参数: {unknown}"),
        }
    }
    Ok(found)
}

/// 连接时临时覆盖 WireGuard UDP 端口，不改 profile 文件。
/// WireGuard 使用 UDP，不支持 HTTP/SOCKS `--proxy`；需要的是端点端口覆盖。
fn connect_port_arg(args: &[String]) -> Result<Option<u16>> {
    let mut found = None;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            value if index == 2 && !value.starts_with("--") => index += 1,
            "--full" | "--skip-validate" | "--daemon" | "--dev" => index += 1,
            "--device" => {
                if args.get(index + 1).is_none() {
                    anyhow::bail!("--device 需要设备 ID 或前缀");
                }
                index += 2;
            }
            "--port" => {
                let raw = args
                    .get(index + 1)
                    .context("--port 需要一个 UDP 端口，例如 --port 443")?;
                let port = raw.parse::<u16>().context("--port 必须是 1-65535 的整数")?;
                if port == 0 {
                    anyhow::bail!("--port 必须是 1-65535 的整数");
                }
                if found.replace(port).is_some() {
                    anyhow::bail!("--port 只能指定一次");
                }
                index += 2;
            }
            "--proxy" => anyhow::bail!(
                "WireGuard 使用 UDP，不支持 HTTP/SOCKS --proxy；请使用 --port <udp-port>"
            ),
            unknown => anyhow::bail!("未知 connect 参数: {unknown}"),
        }
    }
    Ok(found)
}

/// 解析显式节点选择。设备 ID 用于确定客户端密钥；未指定设备时沿用当前 profile。
fn connect_target_args(args: &[String]) -> Result<(Option<String>, Option<String>)> {
    let server = args
        .get(2)
        .filter(|value| !value.starts_with("--"))
        .cloned();
    let mut device = None;
    let mut index = if server.is_some() { 3 } else { 2 };
    while index < args.len() {
        match args[index].as_str() {
            "--device" => {
                let value = args.get(index + 1).context("--device 需要设备 ID 或前缀")?;
                if device.replace(value.clone()).is_some() {
                    anyhow::bail!("--device 只能指定一次");
                }
                index += 2;
            }
            "--full" | "--skip-validate" | "--daemon" | "--dev" => index += 1,
            "--port" => index += 2,
            "--proxy" => anyhow::bail!(
                "WireGuard 使用 UDP，不支持 HTTP/SOCKS --proxy；请使用 --port <udp-port>"
            ),
            unknown => anyhow::bail!("未知 connect 参数: {unknown}"),
        }
    }
    Ok((server, device))
}

/// 在提权前把指定设备的 Keychain 配置物化为 root 可读的 profile.json。
/// sudo 进程不能直接读取当前用户的 macOS Keychain，因此必须先完成这一步。
async fn prepare_selected_profile(server_prefix: &str, device_prefix: Option<&str>) -> Result<()> {
    let Some(device_prefix) = device_prefix else {
        anyhow::bail!("显式连接节点时必须指定 --device <device-id>");
    };
    let svc = open_service().await?;
    let server_id = resolve_server_id(&svc, server_prefix).await?;
    let devices = svc.list_devices(server_id.clone()).await?;
    let matches: Vec<_> = devices
        .iter()
        .filter(|device| device.id.starts_with(device_prefix))
        .collect();
    let device = match matches.as_slice() {
        [device] => *device,
        [] => anyhow::bail!("设备不存在: {device_prefix}"),
        _ => anyhow::bail!("设备 ID 前缀不唯一: {device_prefix}"),
    };
    let config = svc.export_config(device.id.clone()).await?;
    let parsed = wg::parse_config(&config)
        .map_err(|error| anyhow::anyhow!("设备 WireGuard 配置解析失败: {error}"))?;
    let interface = parsed
        .interface
        .ok_or_else(|| anyhow::anyhow!("设备配置缺少 [Interface]"))?;
    let peer = parsed
        .peers
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("设备配置缺少 [Peer]"))?;
    let private_key = interface.private_key.context("设备配置缺少客户端私钥")?;
    let client_ip = interface
        .address
        .context("设备配置缺少客户端地址")?
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();
    let node = svc
        .db
        .get_wg_node(&server_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("节点尚未部署 WireGuard"))?;
    let profile = ConnectionProfile {
        client_public_key: derive_public_key(&decode_key(&private_key, "客户端私钥")?),
        client_private_key: private_key,
        server_public_key: peer.public_key.context("设备配置缺少服务器公钥")?,
        server_endpoint: peer.endpoint.context("设备配置缺少 VPS 端点")?,
        client_ip,
        peer_ip: gateway_from_cidr(&node.vpn_cidr)?,
        netmask: "255.255.255.0".into(),
        mtu: interface.mtu.or(node.mtu).unwrap_or(1380),
        dns: interface.dns,
    };
    let path = profile.save(&data_dir())?;
    println!("✓ 已选择节点 {} / 设备 {}", server_prefix, &device.id[..8]);
    println!("  连接 profile: {}", path.display());
    Ok(())
}

/// 以原始桌面用户身份准备显式节点 profile。
///
/// `sudo miaovps connect <server> --device ...` 会让当前进程一开始就
/// 处于 root 身份，无法读取桌面用户的 Keychain。通过一个只做 profile
/// 准备的内部子命令回到 SUDO_USER，完成后仍由当前 root 进程建立隧道。
fn prepare_selected_profile_as_user(
    server_prefix: &str,
    device_prefix: Option<&str>,
) -> Result<()> {
    let user = std::env::var("SUDO_USER")
        .ok()
        .filter(|value| !value.is_empty() && value != "root")
        .context("无法识别 sudo 调用用户；请不要以 root shell 直接运行显式节点连接")?;
    let device_prefix = device_prefix.context("显式连接节点时必须指定 --device")?;
    let exe = std::env::current_exe().context("无法获取 miaovps 可执行文件路径")?;
    let status = Command::new("sudo")
        .args(["-u", &user, "-H"])
        .arg(exe)
        .arg("__prepare-profile")
        .arg(server_prefix)
        .arg("--device")
        .arg(device_prefix)
        .status()
        .context("无法切换到桌面用户准备连接 profile")?;
    if !status.success() {
        anyhow::bail!("桌面用户 profile 准备失败，状态码 {:?}", status.code());
    }
    Ok(())
}

async fn cmd_prepare_profile(args: &[String]) -> Result<()> {
    let server_prefix = args
        .get(2)
        .filter(|value| !value.starts_with("--"))
        .context("内部命令缺少服务器 ID")?;
    let (_, device_prefix) = connect_target_args(args)?;
    prepare_selected_profile(server_prefix, device_prefix.as_deref()).await
}

fn gateway_from_cidr(cidr: &str) -> Result<String> {
    let (raw_ip, raw_prefix) = cidr.split_once('/').context("VPN 网段格式错误")?;
    let ip: std::net::Ipv4Addr = raw_ip.parse().context("VPN 网段地址无效")?;
    let prefix: u8 = raw_prefix.parse().context("VPN 网段前缀无效")?;
    if prefix > 30 {
        anyhow::bail!("VPN 网段前缀必须不大于 /30");
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(std::net::Ipv4Addr::from((u32::from(ip) & mask) + 1).to_string())
}

fn spawn_elevated(args: &[String]) -> Result<()> {
    let exe = std::env::current_exe().context("无法获取自身路径")?;
    let status = Command::new("sudo")
        .arg(exe)
        .args(&args[1..])
        .env("MIAOVPS_DATA_DIR", data_dir())
        .status()
        .context("无法通过 sudo 启动连接")?;
    if !status.success() {
        anyhow::bail!("sudo 连接进程退出，状态码 {:?}", status.code());
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  add-device
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_add_device(args: &[String]) -> Result<()> {
    let Some(prefix) = args.get(2) else {
        eprintln!("用法: miaovps add-device <server-id> <name> [type]");
        std::process::exit(1);
    };
    let name = args.get(3).cloned().unwrap_or_else(|| "My Device".into());
    let dtype = match args.get(4).map(|s| s.as_str()) {
        Some("mac") | Some("Mac") => DeviceType::Mac,
        Some("windows") | Some("Windows") => DeviceType::Windows,
        Some("iphone") | Some("iPhone") => DeviceType::IPhone,
        Some("android") | Some("Android") => DeviceType::Android,
        Some("linux") | Some("Linux") => DeviceType::Linux,
        _ => DeviceType::Other,
    };

    let svc = open_service().await?;
    let server_id = resolve_server_id(&svc, prefix).await?;
    let (device, config) = svc
        .add_device(server_id, name.clone(), dtype.clone())
        .await?;

    println!("✓ 设备已创建并注册为服务端 peer");
    println!("  ID:     {}", device.id);
    println!("  名称:   {}", name);
    println!("  类型:   {:?}", dtype);
    println!("  公钥:   {}", device.public_key);
    println!("  地址:   {}", device.vpn_address);
    println!("\nWireGuard 配置:\n");
    println!("{}", config);
    println!("私钥已存入系统 Keychain，可随时用以下命令重新导出:");
    println!("  miaovps export-config {}", &device.id[..8]);
    Ok(())
}

async fn cmd_list_devices(args: &[String]) -> Result<()> {
    let prefix = args.get(2).cloned().unwrap_or_else(|| {
        eprintln!("用法: miaovps list-devices <server-id>");
        std::process::exit(1);
    });

    // 与 status / add-device / inspect 保持一致：用户通常输入短 ID 前缀，
    // 不能把前缀直接当完整 server_id 交给存储层，否则查询只会得到空列表。
    let svc = open_service().await?;
    let server_id = resolve_server_id(&svc, &prefix).await?;
    let devices = svc.list_devices(server_id.clone()).await?;

    if devices.is_empty() {
        println!("节点 {} 暂无设备。", &server_id[..8]);
        return Ok(());
    }

    println!("设备列表 (节点 {}):", &server_id[..8]);
    for d in &devices {
        let status = d.status();
        println!(
            "  {}  {}  {}  {:?}  {}",
            &d.id[..8],
            d.name,
            d.vpn_address,
            status,
            d.public_key
        );
    }
    Ok(())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  status / export-config / generate-keypair
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async fn cmd_status(args: &[String]) -> Result<()> {
    let Some(prefix) = args.get(2) else {
        eprintln!("用法: miaovps status <server-id>");
        std::process::exit(1);
    };

    let svc = open_service().await?;
    let server_id = resolve_server_id(&svc, prefix).await?;
    let status = svc.server_status(server_id.clone()).await?;

    if status.contains("not-running") {
        println!("WireGuard 未运行。");
    } else {
        println!("{}", status.trim());
    }

    let devices = svc.list_devices(server_id).await?;
    if !devices.is_empty() {
        println!("\n已注册设备 ({} 台):", devices.len());
        for d in &devices {
            println!(
                "  {}  {:<16} {}  {:?}",
                &d.id[..8],
                d.name,
                d.vpn_address,
                d.status()
            );
        }
    }
    Ok(())
}

async fn cmd_export_config(args: &[String]) -> Result<()> {
    let Some(prefix) = args.get(2) else {
        eprintln!("用法: miaovps export-config <device-id>");
        std::process::exit(1);
    };

    let svc = open_service().await?;
    // 设备 ID 也支持前缀 —— 但需要遍历所有服务器的设备
    let servers = svc.list_servers().await?;
    let mut found: Option<Device> = None;
    for s in &servers {
        for d in svc.list_devices(s.id.clone()).await? {
            if d.id.starts_with(prefix.as_str()) {
                if found.is_some() {
                    anyhow::bail!("{prefix} 匹配到多台设备，请提供更长的 ID 前缀");
                }
                found = Some(d);
            }
        }
    }
    let Some(device) = found else {
        anyhow::bail!("设备不存在: {prefix}");
    };

    let config = svc.export_config(device.id).await?;
    println!("{}", config);
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
        eprintln!(
            "用法: miaovps validate <server-ip:port> <client-private-key> <server-public-key>"
        );
        eprintln!("示例: miaovps validate 203.0.113.10:51820 OGuo5... A2xHn...");
        std::process::exit(1);
    }

    let server_addr: SocketAddr = args[2]
        .parse()
        .map_err(|e| anyhow::anyhow!("服务器地址格式错误 (应为 IP:PORT): {e}"))?;
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

    let validator = ConnectionValidator::new(server_addr, client_private_key, server_public_key);

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

/// 标记环境变量 —— 区分「要派生 daemon 的父进程」和「已经是 daemon 的子进程」
const DAEMON_MARKER: &str = "MIAOVPS_DAEMON_CHILD";

/// daemon 日志文件名 —— 前端读它排查启动失败
const DAEMON_LOG: &str = "tunnel.log";

/// re-exec 自己进入后台
///
/// stdout/stderr 重定向到日志文件。osascript 会等 `do shell script` 的
/// 进程退出才返回，所以父进程必须立刻退出，否则授权框一直转圈。
fn spawn_daemon(args: &[String]) -> Result<()> {
    use std::process::Stdio;

    let exe = std::env::current_exe().context("无法获取自身路径")?;
    let log_path = data_dir().join(DAEMON_LOG);
    let log = std::fs::File::create(&log_path)
        .with_context(|| format!("无法创建日志 {}", log_path.display()))?;
    let log_err = log.try_clone()?;

    let child = Command::new(exe)
        .args(&args[1..]) // 保留 connect 及其后所有 flag（含 --daemon）
        .env(DAEMON_MARKER, "1")
        .env("MIAOVPS_DATA_DIR", data_dir())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .context("无法派生隧道进程")?;

    println!("✓ 隧道进程已启动 (pid {})", child.id());
    println!("  日志: {}", log_path.display());
    println!("  状态: {}", TunnelState::path(&data_dir()).display());
    Ok(())
}

/// 把隧道运行时状态刷进状态文件
fn publish_state(
    data_dir: &std::path::Path,
    profile: &ConnectionProfile,
    mode: TunnelMode,
    status: TunnelStatus,
    tunnel: &NativeTunnel,
    started_at: i64,
) {
    let (tx, rx, errs) = tunnel.stats().snapshot();
    let state = TunnelState {
        status,
        mode,
        pid: std::process::id(),
        server_endpoint: profile.server_endpoint.clone(),
        client_ip: profile.client_ip.clone(),
        started_at,
        updated_at: miaovps_app::tunnel::now_secs(),
        tx_bytes: tx,
        rx_bytes: rx,
        decrypt_errors: errs,
        session_churn: tunnel.stats().session_churn(),
        reconnects: tunnel.stats().reconnects(),
        session_alive: tunnel.stats().is_session_alive(),
        last_error: None,
    };
    if let Err(e) = state.save(data_dir) {
        // 状态写失败不该终止隧道 —— 隧道本身还在正常工作
        eprintln!("  ⚠ 状态文件写入失败: {e}");
    }
}

async fn cmd_connect(args: &[String]) -> Result<()> {
    let flags: Vec<&str> = args.iter().skip(2).map(|s| s.as_str()).collect();
    let (server_prefix, device_prefix) = connect_target_args(args)?;
    let port_override = connect_port_arg(args)?;
    if server_prefix.is_some() != device_prefix.is_some() {
        anyhow::bail!("显式连接节点时必须同时指定 server-id 和 --device <device-id>");
    }
    let skip_validate = flags.contains(&"--skip-validate");
    let full_tunnel = flags.contains(&"--full");
    let daemon = flags.contains(&"--daemon");

    // 权限先查 — 创建 TUN 和改路由都需要 root，
    // 没有权限就别让用户白等几秒验证
    if !is_root() {
        if let Some(server_prefix) = server_prefix.as_deref() {
            prepare_selected_profile(server_prefix, device_prefix.as_deref()).await?;
            return spawn_elevated(args);
        }
        anyhow::bail!(
            "创建 TUN 接口和修改路由需要 root 权限。\n\
             请使用: sudo miaovps connect{}{}",
            if full_tunnel { " --full" } else { "" },
            port_override
                .map(|port| format!(" --port {port}"))
                .unwrap_or_default()
        );
    }

    // 兼容用户直接写 `sudo miaovps connect <server> --device ...` 的用法。
    // 不能在 root 进程中直接访问原用户 Keychain，否则会沿用旧 profile。
    if let Some(server_prefix) = server_prefix.as_deref() {
        if std::env::var_os("SUDO_USER").is_some() {
            prepare_selected_profile_as_user(server_prefix, device_prefix.as_deref())?;
        } else {
            anyhow::bail!(
                "显式节点连接需要桌面用户的 Keychain。请以普通用户运行命令（CLI 会自动 sudo），\n\
                 或使用 `sudo` 从当前桌面用户启动，而不是在 root shell 中运行。"
            );
        }
    }

    // ── daemon 模式：父进程 re-exec 自己后立刻退出 ──
    //
    // 不用 fork()：tokio 运行时已经起了线程，fork 只复制调用线程，
    // 子进程里的 runtime 会带着半套线程状态死锁。re-exec 拿到干净进程。
    if daemon && std::env::var_os(DAEMON_MARKER).is_none() {
        return spawn_daemon(args);
    }

    let is_daemon_child = daemon && std::env::var_os(DAEMON_MARKER).is_some();

    let mut profile = ConnectionProfile::load(&data_dir())?;
    if let Some(port) = port_override {
        let mut endpoint = profile.server_addr()?;
        endpoint.set_port(port);
        profile.server_endpoint = endpoint.to_string();
    }
    let server_addr = profile.server_addr()?;
    tracing::info!(endpoint = %server_addr, full_tunnel, daemon, skip_validate, "[连接] 开始建立隧道");
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

    let tunnel_mode = if full_tunnel {
        TunnelMode::Full
    } else {
        TunnelMode::Split
    };
    let started_at = miaovps_app::tunnel::now_secs();

    // 必须在创建 utun 之前先写出归属状态。否则前端在
    // 「网卡已出现、状态文件尚未写」的窗口会误判为终端启动。
    if is_daemon_child {
        TunnelState::clear_stop_request(&data_dir());
        let state = TunnelState::connecting(
            tunnel_mode,
            profile.server_endpoint.clone(),
            profile.client_ip.clone(),
        );
        state.save(&data_dir()).context("无法写入隧道启动状态")?;
    }

    println!("🔗 MiaoVPS 隧道 → {}", server_addr);
    println!("  客户端公钥: {}", short_key(&profile.client_public_key));
    println!("  服务器公钥: {}", short_key(&profile.server_public_key));
    println!(
        "  模式: {}",
        if full_tunnel {
            "Full Tunnel (全局)"
        } else {
            "Split Tunnel (仅 VPN 网段)"
        }
    );
    println!();

    // ── 1. 验证 ──
    if skip_validate {
        println!("[1/4] ⏭ 跳过验证");
    } else {
        println!("[1/4] 验证链路...");
        let validator = ConnectionValidator::new(server_addr, client_priv, server_pub);
        for r in &validator.validate_all().await {
            println!(
                "  {} {} ({}ms)",
                if r.success { "✅" } else { "❌" },
                r.step,
                r.duration_ms
            );
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
    println!(
        "  {} — {} → {} mtu {}",
        tun_name, profile.client_ip, profile.peer_ip, profile.mtu
    );

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

    // 当前原生数据面只配置了 IPv4 地址与 IPv4 全局路由。Full Tunnel 不能
    // 让 IPv6 保持直连，否则支持 IPv6 的站点会绕过 VPN。这里故意不做半套
    // IPv6 隧道，而是只阻止公网 IPv6（2000::/3）；loopback、链路本地和局域网
    // 地址不受影响。规则由 marker 标记所有权，退出/回落时只删除本进程创建的
    // 规则，绝不触碰用户预先存在的路由。
    let mut overlay = if full_tunnel {
        let mut ov = FullTunnelOverlay::new(
            tun_name.clone(),
            profile.dns.clone(),
            dns_backup.clone(),
            data_dir(),
        );
        if let Err(e) = ov.enable_ipv6_leak_protection() {
            remove_tunnel_routes(&vps_ip, &vpn_net);
            return Err(e.context("无法阻止公网 IPv6，已回滚 IPv4 Full Tunnel 路由"));
        }
        println!("  IPv6:        已阻止公网 IPv6 直连（2000::/3）");
        Some(ov)
    } else {
        None
    };

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
            if let Some(ov) = overlay.as_mut() {
                ov.teardown();
            } else if let Some(b) = &dns_backup {
                let _ = b.restore(&data_dir());
            }
            remove_tunnel_routes(&vps_ip, &vpn_net);
            return Err(anyhow::anyhow!("隧道启动失败，已回滚路由: {e}"));
        }
    };

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "  ✅ 隧道已建立 ({})",
        if full_tunnel {
            "Full Tunnel"
        } else {
            "Split Tunnel"
        }
    );
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
    println!("  断线会自动重连（无限重试，不改动路由）。");
    println!();

    // daemon 模式向状态文件发布运行时状态供前端轮询
    if is_daemon_child {
        publish_state(
            &data_dir(),
            &profile,
            tunnel_mode,
            TunnelStatus::Connecting,
            &tunnel,
            started_at,
        );
    }

    // 网关看护 + 状态输出。网关检查要比状态输出频繁 ——
    // 它决定断线后能否恢复，而状态输出只是给人看的。
    let mut gw_guard = VpsRouteGuard::new(vps_ip.clone(), default_gw.clone());
    let mut ticks: u32 = 0;
    let mut outage_ticks: u32 = 0;
    const TICK: Duration = Duration::from_secs(5);
    const STATUS_EVERY: u32 = 6; // 30s
    /// 连续这么多 tick 无会话就回落直连。
    ///
    /// 6×5s=30s。boringtun 自己的重传窗口是 105s，但那期间隧道已经不通了 ——
    /// 没必要让用户断网等它。30s 足够滤掉瞬时抖动（切换 WiFi 本身只需几秒）。
    const OUTAGE_TICKS_BEFORE_FALLBACK: u32 = 6;

    // daemon 没有终端，Ctrl+C 收不到 —— 必须听 SIGTERM 才能被 disconnect 停掉
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("无法注册 SIGTERM 处理")?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => {
                println!("\n收到 SIGTERM，开始收尾");
                break;
            }
            _ = tokio::time::sleep(TICK) => {
                if is_daemon_child && TunnelState::stop_requested(&data_dir()) {
                    println!("\n收到前端停止请求，开始收尾");
                    break;
                }
                if let Some((old, new)) = gw_guard.reconcile() {
                    println!("  [网络] 默认网关 {old} → {new}，已重建 VPS 直连路由");
                    // 路由修好后立刻重绑定 —— 在此之前重绑定是无用功，
                    // 因为包没有可用的出口
                    tracing::info!(old_gateway = %old, new_gateway = %new, "[网络] 已修复 VPS 直连路由");
                    tunnel.notify_network_changed();
                }
                ticks += 1;
                if ticks.is_multiple_of(STATUS_EVERY) {
                    println!("  [状态] {}", tunnel.health_line());
                    tracing::debug!("[状态] {}", tunnel.health_line());
                }

                // ── 断线回落 / 恢复接管 ──
                //
                // 使用经过认证的收包新鲜度；空闲时由握手探测确认，不能只看本地密钥。
                if let Some(ov) = overlay.as_mut() {
                    let alive = tunnel.stats().is_session_alive();

                    if ov.is_engaged() && !alive {
                        outage_ticks += 1;
                        if outage_ticks >= OUTAGE_TICKS_BEFORE_FALLBACK {
                            println!();
                            println!("  ⚠ 隧道断开约 {}s 未恢复 —— 回落直连以保持网络可用",
                                outage_ticks * TICK.as_secs() as u32);
                            tracing::warn!("[连接] 认证链路持续不可用，回落直连");
                            ov.disengage();
                            println!("    全局路由已撤下。隧道继续重连，恢复后自动接管。");
                            println!("    此时流量不经 VPN（无隐私保护）。");
                            println!();
                        }
                    } else if !ov.is_engaged() && alive {
                        // 会话恢复 —— 重新接管
                        println!();
                        println!("  ✅ 隧道已恢复 —— 重新接管全局流量");
                        match ov.engage() {
                            Ok(()) => {
                                println!("    全局路由 + DNS 已恢复接管");
                                outage_ticks = 0;
                                tracing::info!("[连接] 认证链路恢复，重新接管全局流量");
                            }
                            Err(e) => {
                                eprintln!("    ⚠ 重新接管失败: {e}");
                                eprintln!("    仍为直连状态，可 Ctrl+C 后重连");
                            }
                        }
                        println!();
                    } else if alive {
                        outage_ticks = 0;
                    }
                }

                // 每 tick 刷一次状态文件 —— 前端轮询靠它
                if is_daemon_child {
                    let alive = tunnel.stats().is_session_alive();
                    let fallen_back = overlay.as_ref().is_some_and(|ov| !ov.is_engaged());
                    let status = match (alive, fallen_back) {
                        // 回落状态优先 —— 此时流量不经 VPN，必须让前端明确警示
                        (_, true) => TunnelStatus::FallbackDirect,
                        (true, false) => TunnelStatus::Connected,
                        (false, false) => TunnelStatus::Reconnecting,
                    };
                    publish_state(&data_dir(), &profile, tunnel_mode, status, &tunnel, started_at);
                }
            }
        }
    }
    println!("\n正在关闭...");
    tracing::info!("[连接] 正在关闭隧道");

    let (tx, rx, errs) = tunnel.stats().snapshot();
    let reconnects = tunnel.stats().reconnects();
    tracing::info!(
        tx_bytes = tx,
        rx_bytes = rx,
        rejected = errs,
        reconnects,
        "[连接] 隧道结束"
    );
    tunnel.shutdown();

    // Full Tunnel 的全局路由/DNS 由 overlay 负责 —— 它知道当前是接管还是
    // 已回落状态。回落时 DNS 早已还原，重复 restore 会写回过期备份。
    match overlay.as_mut() {
        Some(ov) => ov.teardown(),
        None => {
            // Split Tunnel 不接管 DNS，但防御性还原以防将来改动
            if let Some(backup) = &dns_backup {
                match backup.restore(&data_dir()) {
                    Ok(()) => println!("  DNS 已还原: {}", backup.describe()),
                    Err(e) => eprintln!("  ⚠ {e}"),
                }
            }
        }
    }
    remove_tunnel_routes(&vps_ip, &vpn_net);

    // 状态文件必须在路由清理后删 —— 中间崩溃时留着文件才能被识别为 Stale
    if is_daemon_child {
        TunnelState::clear(&data_dir());
        TunnelState::clear_stop_request(&data_dir());
    }

    println!(
        "  流量: ↑{} ↓{}{}{}",
        human_bytes(tx),
        human_bytes(rx),
        if reconnects > 0 {
            format!("  重连: {reconnects} 次")
        } else {
            String::new()
        },
        if errs > 0 {
            format!("  解密错误: {errs}")
        } else {
            String::new()
        }
    );
    println!("✅ 已断开");

    Ok(())
}

async fn cmd_disconnect(_args: &[String]) -> Result<()> {
    if !is_root() {
        anyhow::bail!("清理路由需要 root 权限，请使用: sudo miaovps disconnect");
    }

    println!("清理残留状态...");

    // 先停 daemon 隧道进程 —— 它还活着的话会把路由重新加回来
    // （VpsRouteGuard 每 5s 核对一次），先清路由就白清了
    stop_daemon_if_running()?;

    // 上次异常退出（kill -9 / 崩溃）可能留下被改写的 DNS，优先还原
    if let Some(desc) = dns::restore_if_pending(&data_dir()) {
        println!("  DNS 已从备份还原: {desc}");
    }

    // 只清理由 MiaoVPS marker 证明归属的 IPv6 防泄漏规则；当前或其他 VPN
    // 预先存在的同类规则不会被删除。
    if let Err(e) = Ipv6LeakGuard::cleanup_if_owned(&data_dir()) {
        eprintln!("  ⚠ IPv6 防泄漏规则清理失败: {e}");
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
    TunnelState::clear(&data_dir());
    println!("✅ 清理完成");
    Ok(())
}

/// 停掉 daemon 隧道进程并等它退出。
///
/// 隧道自己的 shutdown 会还原 DNS 并撤路由，比外部清理更准确
/// （它知道当前是接管还是已回落状态）。所以先发 SIGTERM 让它自己收尾；
/// 旧版 daemon 不响应 SIGTERM 时再升级为 SIGKILL，由本命令继续清理路由和 DNS。
fn stop_daemon_if_running() -> Result<()> {
    let state = TunnelState::load(&data_dir());
    if state.status == TunnelStatus::Disconnected || state.pid == 0 {
        return Ok(());
    }
    if state.status == TunnelStatus::Stale {
        println!("  上次隧道异常退出 (pid {} 已不存在)", state.pid);
        return Ok(());
    }

    // 状态文件中的 PID 可能因崩溃后长期未清理而被系统复用。发信号前必须
    // 核对完整进程参数，避免误杀无关进程。
    let Some(command) = process_command(state.pid)? else {
        println!("  隧道进程 {} 已退出", state.pid);
        return Ok(());
    };
    if !is_miaovps_daemon_command(&command) {
        anyhow::bail!(
            "状态文件中的 pid {} 已被其他进程占用，拒绝终止: {}",
            state.pid,
            command
        );
    }

    println!("  停止隧道进程 (pid {})...", state.pid);
    if !send_signal(state.pid, libc::SIGTERM)? {
        println!("  隧道进程已退出");
        return Ok(());
    }

    // 新版 daemon 会主动处理停止请求；这里仍保留 SIGTERM，兼容从终端启动的
    // 旧版 daemon。给正常 shutdown 5s 收尾时间。
    if wait_for_daemon_exit(state.pid, 50)? {
        println!("  隧道进程已退出");
        return Ok(());
    }

    // 再次核对命令，防止 TERM 后退出、PID 恰好被其他进程复用的极小竞态。
    let Some(command) = process_command(state.pid)? else {
        println!("  隧道进程已退出");
        return Ok(());
    };
    if !is_miaovps_daemon_command(&command) {
        println!("  隧道进程已退出 (pid 已被系统复用)");
        return Ok(());
    }

    println!("  ⚠ SIGTERM 无响应，正在强制终止隧道进程 {}", state.pid);
    if !send_signal(state.pid, libc::SIGKILL)? || wait_for_daemon_exit(state.pid, 50)? {
        println!("  隧道进程已强制终止");
        return Ok(());
    }

    anyhow::bail!("无法终止隧道进程 {}，已停止清理以避免误报", state.pid)
}

/// 读取指定 PID 的完整命令行；进程不存在时返回 None。
fn process_command(pid: u32) -> Result<Option<String>> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .context("无法核对隧道进程")?;
    if !output.status.success() {
        return Ok(None);
    }
    let command = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok((!command.is_empty()).then_some(command))
}

/// 只认可 `miaovps connect ... --daemon`，避免状态文件 PID 被复用时误杀。
fn is_miaovps_daemon_command(command: &str) -> bool {
    let mut words = command.split_whitespace();
    let Some(executable) = words.next() else {
        return false;
    };
    let executable_matches = std::path::Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        == Some("miaovps");
    let args: Vec<_> = words.collect();
    executable_matches && args.contains(&"connect") && args.contains(&"--daemon")
}

/// 返回 false 表示进程已经不存在。
fn send_signal(pid: u32, signal: i32) -> Result<bool> {
    // Safety: kill 仅向已核验 PID 投递信号，无内存操作。
    if unsafe { libc::kill(pid as i32, signal) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }
    Err(error).with_context(|| format!("无法向隧道进程 {pid} 发送停止信号"))
}

fn wait_for_daemon_exit(pid: u32, attempts: usize) -> Result<bool> {
    for _ in 0..attempts {
        std::thread::sleep(Duration::from_millis(100));
        match process_command(pid)? {
            None => return Ok(true),
            Some(command) if !is_miaovps_daemon_command(&command) => return Ok(true),
            Some(_) => {}
        }
    }
    Ok(false)
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
            println!(
                "  miaovps profile init <ip:port> <client-priv> <server-pub> [client-ip] [peer-ip]"
            );
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
    println!(
        "    sudo wg set wg0 peer {} allowed-ips {}/32",
        client_public_key, profile.client_ip
    );
    println!("  然后: sudo miaovps connect");

    Ok(())
}

fn cmd_profile_show() -> Result<()> {
    let profile = ConnectionProfile::load(&data_dir())?;
    println!(
        "连接配置 ({})",
        ConnectionProfile::path(&data_dir()).display()
    );
    println!("  服务器:     {}", profile.server_endpoint);
    println!("  服务器公钥: {}", profile.server_public_key);
    println!("  客户端公钥: {}", profile.client_public_key);
    println!(
        "  客户端私钥: {} (已隐藏)",
        short_key(&profile.client_private_key)
    );
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
        Self {
            destination,
            via: RouteVia::Gateway(gw.to_string()),
        }
    }

    fn interface(destination: String, iface: &str) -> Self {
        Self {
            destination,
            via: RouteVia::Interface(iface.to_string()),
        }
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
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let gw = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("gateway:"))
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
        .ok_or_else(|| anyhow::anyhow!("无法获取默认网关 — 当前可能没有可用网络连接"))?;

    Ok(gw)
}

/// Full Tunnel 的全局路由 + DNS 接管，可临时撤下再装回
///
/// ## 为什么需要
///
/// Full Tunnel 下 `0/1`+`128/1` 指向 utun、DNS 指向只能经隧道到达的地址。
/// 隧道断了但路由还在时，全局流量和 DNS 全进黑洞 —— macOS 的连通性探测
/// 失败，系统判定「已连接但无互联网」，用户看到的是 WiFi 坏了。
///
/// 所以长时间断线时把全局路由和 DNS 撤下（回落直连），隧道进程继续重连；
/// 会话恢复后再装回。VPN 的价值是隐私，但断网期间守着一个死隧道
/// 既没有隐私也没有网络。
struct FullTunnelOverlay {
    tun_name: String,
    dns_servers: Vec<String>,
    dns_backup: Option<dns::DnsBackup>,
    data_dir: PathBuf,
    /// 当前是否处于「已接管」状态
    engaged: bool,
    /// Full Tunnel 下显式阻止公网 IPv6，防止尚未实现 IPv6 隧道时旁路泄漏。
    ipv6_guard: Option<Ipv6LeakGuard>,
}

impl FullTunnelOverlay {
    /// 覆盖全局路由的两条半区路由 —— 比改 default 条目更容易精确回滚
    const GLOBAL_ROUTES: [&'static str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];

    fn new(
        tun_name: String,
        dns_servers: Vec<String>,
        dns_backup: Option<dns::DnsBackup>,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            tun_name,
            dns_servers,
            dns_backup,
            data_dir,
            engaged: true,
            ipv6_guard: None,
        }
    }

    /// 启用公网 IPv6 防泄漏。只应在 IPv4 Full Tunnel 已成功应用后调用。
    fn enable_ipv6_leak_protection(&mut self) -> Result<()> {
        if self.ipv6_guard.is_none() {
            self.ipv6_guard = Some(Ipv6LeakGuard::install(self.data_dir.clone())?);
        }
        Ok(())
    }

    fn disable_ipv6_leak_protection(&mut self) {
        if let Some(mut guard) = self.ipv6_guard.take() {
            if let Err(e) = guard.remove() {
                eprintln!("    ⚠ IPv6 防泄漏规则清理失败: {e}");
            }
        }
    }

    fn is_engaged(&self) -> bool {
        self.engaged
    }

    /// 撤下全局路由与 DNS，回落到直连
    fn disengage(&mut self) {
        if !self.engaged {
            return;
        }

        // 先还原 DNS 再删路由：反序会有一段时间 DNS 指向已失效的隧道
        if let Some(b) = &self.dns_backup {
            match b.restore(&self.data_dir) {
                Ok(()) => println!("    DNS 已还原: {}", b.describe()),
                Err(e) => eprintln!("    ⚠ DNS 还原失败: {e}"),
            }
        }
        for dest in Self::GLOBAL_ROUTES {
            let _ = Command::new("route")
                .args(["-q", "-n", "delete", "-inet", dest])
                .output();
        }
        // IPv4 全局路由已经撤下后，才允许公网 IPv6 恢复系统原状。
        self.disable_ipv6_leak_protection();
        self.engaged = false;
    }

    /// 重新接管全局路由与 DNS
    fn engage(&mut self) -> Result<()> {
        if self.engaged {
            return Ok(());
        }

        // DNS 备份要重新抓取 —— 回落期间用户可能换了网络，
        // 沿用旧备份会在下次还原时写回错误的 DNS
        self.dns_backup = match dns::DnsBackup::capture(&self.data_dir) {
            Ok(b) => Some(b),
            Err(e) => {
                println!("    ⚠ 无法备份 DNS，跳过 DNS 接管: {e}");
                None
            }
        };

        self.enable_ipv6_leak_protection()?;

        let plan: Vec<RouteSpec> = Self::GLOBAL_ROUTES
            .iter()
            .map(|d| RouteSpec::interface((*d).into(), &self.tun_name))
            .collect();
        if let Err(e) = apply_routes(&plan) {
            self.disable_ipv6_leak_protection();
            return Err(e);
        }

        if self.dns_backup.is_some() && !self.dns_servers.is_empty() {
            if let Err(e) = dns::apply(&self.dns_servers) {
                println!("    ⚠ DNS 接管失败（查询可能泄露给 ISP）: {e}");
            }
        }

        self.engaged = true;
        Ok(())
    }

    /// 退出时的清理：只在仍处于接管状态时才需要还原
    fn teardown(&mut self) {
        if self.engaged {
            self.disengage();
        } else {
            // 已回落 —— DNS 早已还原，只清理可能残留的路由
            for dest in Self::GLOBAL_ROUTES {
                let _ = Command::new("route")
                    .args(["-q", "-n", "delete", "-inet", dest])
                    .output();
            }
            self.disable_ipv6_leak_protection();
        }
    }
}

/// Full Tunnel 尚未实现 IPv6 数据面时的防泄漏保护。
///
/// `2000::/3` 覆盖所有公网可路由 IPv6 地址；比拦截 `::/0` 更精确，因而不会
/// 干扰 `::1`、`fe80::/10` 和局域网 ULA。使用 `-reject` 而非把流量送进 IPv4
/// TUN：调用者会立即收到不可达错误，不会在一个不能转发 IPv6 的接口上静默挂起。
///
/// marker 让异常退出后的 `miaovps disconnect` 能清理本程序留下的规则，同时保证
/// 不删除用户、系统或另一款 VPN 已存在的同类路由。
struct Ipv6LeakGuard {
    data_dir: PathBuf,
    owns_route: bool,
}

impl Ipv6LeakGuard {
    const PUBLIC_PREFIX: &'static str = "2000::/3";
    /// 仅用于确认路由查找实际命中 reject；不是媒体或服务商特判。
    const VERIFY_ADDRESS: &'static str = "2001:4860:4860::8888";
    const MARKER_FILE: &'static str = "ipv6-public-block.active";

    fn marker_path(data_dir: &std::path::Path) -> PathBuf {
        data_dir.join(Self::MARKER_FILE)
    }

    fn install(data_dir: PathBuf) -> Result<Self> {
        let marker = Self::marker_path(&data_dir);
        let marker_exists = marker.is_file();
        let output = Command::new("route")
            // macOS 的 RTF_REJECT 路由必须提供 loopback gateway；只给
            // destination 和 -reject 会出现命令成功但没有安装 reject 路由的假象。
            .args(["-n", "add", "-inet6", Self::PUBLIC_PREFIX, "::1", "-reject"])
            .output()
            .context("无法添加 IPv6 防泄漏路由")?;

        if output.status.success() {
            if let Err(e) = Self::verify_route() {
                let _ = Self::delete_route();
                return Err(e);
            }
            if let Err(e) = std::fs::write(&marker, b"MiaoVPS IPv6 leak protection\n") {
                // marker 写不出就无法保证未来只清自己的规则，立刻补偿回滚。
                let _ = Self::delete_route();
                return Err(e).with_context(|| {
                    format!("无法记录 IPv6 防泄漏路由归属: {}", marker.display())
                });
            }
            return Ok(Self {
                data_dir,
                owns_route: true,
            });
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("File exists") {
            // marker 已存在表示这是上一轮 MiaoVPS 异常退出留下的规则，当前
            // 会话接管其清理责任；无 marker 则尊重用户/其他 VPN 的既有规则。
            Self::verify_route().with_context(|| {
                format!(
                    "公网 IPv6 前缀 {} 已有路由，但不是有效的 REJECT 路由；为避免 IPv6 泄漏，拒绝建立 Full Tunnel",
                    Self::PUBLIC_PREFIX
                )
            })?;
            return Ok(Self {
                data_dir,
                owns_route: marker_exists,
            });
        }

        anyhow::bail!(
            "route add -inet6 {} ::1 -reject 失败: {}",
            Self::PUBLIC_PREFIX,
            stderr.trim()
        );
    }

    fn verify_route() -> Result<()> {
        let output = Command::new("route")
            .args(["-n", "get", "-inet6", Self::VERIFY_ADDRESS])
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

    fn delete_route() -> Result<()> {
        let output = Command::new("route")
            .args(["-q", "-n", "delete", "-inet6", Self::PUBLIC_PREFIX, "::1"])
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
        anyhow::bail!(
            "route delete -inet6 {} ::1 失败: {}",
            Self::PUBLIC_PREFIX,
            stderr.trim()
        );
    }

    fn remove(&mut self) -> Result<()> {
        if !self.owns_route {
            return Ok(());
        }
        Self::delete_route()?;
        std::fs::remove_file(Self::marker_path(&self.data_dir))
            .or_else(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .context("无法删除 IPv6 防泄漏归属标记")?;
        self.owns_route = false;
        Ok(())
    }

    fn cleanup_if_owned(data_dir: &std::path::Path) -> Result<()> {
        let marker = Self::marker_path(data_dir);
        if !marker.is_file() {
            return Ok(());
        }
        let mut guard = Self {
            data_dir: data_dir.to_path_buf(),
            owns_route: true,
        };
        guard.remove()
    }
}

/// VPS 直连路由的看护者 —— 网络切换后把它重新指向当前网关
///
/// ## 为什么必需
///
/// VPS 公网 IP 的主机路由在连接时被钉到当时的网关。WiFi 重连换网段
/// （或 WiFi↔有线切换）后网关变了，这条路由指向一个不可达的下一跳 ——
/// 握手包连出口都没有，隧道永远无法恢复。
///
/// Full Tunnel 下后果更严重：`0/1`+`128/1` 仍指向已死的 utun，
/// DNS 又指向只能经隧道到达的地址，于是系统的连通性探测（HTTP + DNS）
/// 全部进黑洞，macOS 判定「已连接但无互联网」—— 表现为 WiFi 连不上。
///
/// 物理默认路由与 `0/1`/`128/1` 并存（后者更具体但不覆盖 default 条目），
/// 所以 `get_default_gateway()` 在 Full Tunnel 下仍能读到真实网关。
struct VpsRouteGuard {
    vps_ip: String,
    /// 当前这条主机路由指向的网关
    pinned_gw: String,
}

impl VpsRouteGuard {
    fn new(vps_ip: String, gw: String) -> Self {
        Self {
            vps_ip,
            pinned_gw: gw,
        }
    }

    /// 检查网关是否变化；变了就重建 VPS 主机路由。
    ///
    /// 返回 `Some((旧网关, 新网关))` 表示做了重建。
    fn reconcile(&mut self) -> Option<(String, String)> {
        let current = get_default_gateway().ok()?;
        if current == self.pinned_gw {
            return None;
        }

        let old = std::mem::replace(&mut self.pinned_gw, current.clone());
        let dest = format!("{}/32", self.vps_ip);

        // 先删旧的，否则 add 会因 "File exists" 静默保留错误的下一跳
        let _ = Command::new("route")
            .args(["-q", "-n", "delete", "-inet", &dest])
            .output();

        match run_route(&["add", "-inet", &dest, "-gateway", &current]) {
            Ok(()) => Some((old, current)),
            Err(e) => {
                eprintln!("  ⚠ VPS 直连路由重建失败: {e}");
                None
            }
        }
    }
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

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flag_value_reads_following_token() {
        let args = argv(&[
            "miaovps",
            "add-server",
            "vps",
            "1.2.3.4",
            "--password",
            "pw",
        ]);
        assert_eq!(flag_value(&args, "--password").as_deref(), Some("pw"));
        assert_eq!(flag_value(&args, "--key"), None);
    }

    /// `--password --key x` 里 password 没给值，不能把 `--key` 当成密码
    #[test]
    fn flag_value_rejects_adjacent_flag_as_value() {
        let args = argv(&["miaovps", "add-server", "--password", "--key", "/tmp/id"]);
        assert_eq!(flag_value(&args, "--password"), None);
        assert_eq!(flag_value(&args, "--key").as_deref(), Some("/tmp/id"));
    }

    #[test]
    fn flag_value_at_end_without_value_is_none() {
        let args = argv(&["miaovps", "add-server", "vps", "1.2.3.4", "--password"]);
        assert_eq!(flag_value(&args, "--password"), None);
    }

    #[test]
    fn deploy_port_accepts_a_non_default_udp_port() {
        let args = argv(&["miaovps", "deploy", "server-1", "--port", "443"]);
        assert_eq!(deploy_port_arg(&args).unwrap(), Some(443));
    }

    #[test]
    fn deploy_port_rejects_missing_or_invalid_values() {
        assert!(deploy_port_arg(&argv(&["miaovps", "deploy", "server-1", "--port"])).is_err());
        assert!(deploy_port_arg(&argv(&["miaovps", "deploy", "server-1", "--port", "0"])).is_err());
        assert!(deploy_port_arg(&argv(&["miaovps", "deploy", "server-1", "--other"])).is_err());
    }

    #[test]
    fn connect_port_can_override_profile_without_proxy_semantics() {
        let args = argv(&["miaovps", "connect", "--full", "--port", "443", "--daemon"]);
        assert_eq!(connect_port_arg(&args).unwrap(), Some(443));
        assert!(connect_port_arg(&argv(&["miaovps", "connect", "--proxy", "http://x"])).is_err());
    }

    #[test]
    fn connect_accepts_explicit_server_and_device() {
        let args = argv(&[
            "miaovps", "connect", "77ce8561", "--device", "aabbccdd", "--full", "--port", "443",
        ]);
        assert_eq!(
            connect_target_args(&args).unwrap(),
            (Some("77ce8561".into()), Some("aabbccdd".into()))
        );
        assert_eq!(connect_port_arg(&args).unwrap(), Some(443));
    }

    #[test]
    fn gateway_from_cidr_uses_first_host() {
        assert_eq!(gateway_from_cidr("10.66.66.0/24").unwrap(), "10.66.66.1");
        assert!(gateway_from_cidr("10.0.0.0/31").is_err());
    }

    #[test]
    fn connect_port_rejects_missing_or_invalid_values() {
        assert!(connect_port_arg(&argv(&["miaovps", "connect", "--port"])).is_err());
        assert!(connect_port_arg(&argv(&["miaovps", "connect", "--port", "0"])).is_err());
        assert!(connect_port_arg(&argv(&[
            "miaovps", "connect", "--port", "443", "--port", "51820"
        ]))
        .is_err());
    }

    #[test]
    fn derives_vpn_network_from_gateway() {
        assert_eq!(vpn_network_cidr("10.66.66.1").unwrap(), "10.66.66.0/24");
        assert_eq!(vpn_network_cidr("192.168.9.1").unwrap(), "192.168.9.0/24");
        assert!(vpn_network_cidr("not-an-ip").is_err());
    }

    #[test]
    fn truncates_keys_for_display() {
        assert_eq!(
            short_key("fRp9SCOP2pu780jn15LbDFbxPwJJleAjODXjzcOgZFs="),
            "fRp9SCOP2pu7…"
        );
        assert_eq!(short_key("short"), "…");
    }

    #[test]
    fn formats_byte_counts() {
        assert_eq!(human_bytes(512), "512B");
        assert_eq!(human_bytes(2048), "2.0KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0MiB");
    }

    #[test]
    fn recognizes_only_miaovps_connect_daemons() {
        assert!(is_miaovps_daemon_command(
            "/Users/kerye/.cargo/bin/miaovps connect --full --daemon"
        ));
        assert!(is_miaovps_daemon_command(
            "/Applications/MiaoVPS.app/Contents/MacOS/miaovps connect --daemon"
        ));
        assert!(!is_miaovps_daemon_command("/bin/sleep 100"));
        assert!(!is_miaovps_daemon_command(
            "/tmp/not-miaovps connect --daemon"
        ));
        assert!(!is_miaovps_daemon_command(
            "/usr/local/bin/miaovps connect --full"
        ));
        assert!(!is_miaovps_daemon_command(
            "/usr/local/bin/miaovps deploy --daemon"
        ));
    }

    /// 构造一个不触碰真实系统的 overlay：没有 DNS 备份 → 不会调 networksetup；
    /// 路由操作在非 root 下失败但不 panic。只验证状态机。
    fn test_overlay() -> FullTunnelOverlay {
        FullTunnelOverlay::new(
            "utun-test-nonexistent".into(),
            vec![],
            None,
            std::env::temp_dir().join("miaovps-overlay-test"),
        )
    }

    #[test]
    fn overlay_starts_engaged() {
        assert!(
            test_overlay().is_engaged(),
            "Full Tunnel 建立后应处于接管状态"
        );
    }

    #[test]
    fn overlay_disengage_is_idempotent() {
        let mut ov = test_overlay();
        ov.disengage();
        assert!(!ov.is_engaged());
        // 重复调用不应改变状态或重复还原 DNS
        ov.disengage();
        assert!(!ov.is_engaged());
    }

    #[test]
    fn overlay_engage_noops_when_already_engaged() {
        let mut ov = test_overlay();
        // 已接管时 engage 应直接返回 Ok，不重新抓 DNS 备份、不重复加路由
        assert!(ov.engage().is_ok());
        assert!(ov.is_engaged());
    }

    #[test]
    fn overlay_teardown_from_disengaged_state_does_not_restore_dns() {
        let mut ov = test_overlay();
        ov.disengage();
        // 已回落状态下 teardown 只清路由 —— 若此时再 restore DNS，
        // 会把回落时抓的过期备份写回系统
        ov.teardown();
        assert!(!ov.is_engaged());
    }

    #[test]
    fn overlay_covers_full_ipv4_space() {
        // 0/1 + 128/1 必须完整覆盖 IPv4，漏掉一半会导致部分流量绕过隧道
        assert_eq!(
            FullTunnelOverlay::GLOBAL_ROUTES,
            ["0.0.0.0/1", "128.0.0.0/1"]
        );
    }

    #[test]
    fn ipv6_policy_blocks_only_public_unicast_space() {
        // 不用 ::/0：不能影响 loopback、链路本地或局域网 ULA；2000::/3
        // 正好覆盖所有公网可路由 IPv6 前缀，防止 Full Tunnel 发生 IPv6 泄漏。
        assert_eq!(Ipv6LeakGuard::PUBLIC_PREFIX, "2000::/3");
    }

    #[test]
    fn route_guard_noops_when_gateway_unchanged() {
        // 用当前真实网关构造，reconcile 应判定无变化且不碰路由表
        let gw = match get_default_gateway() {
            Ok(g) => g,
            Err(_) => return, // 无网络时跳过
        };
        let mut guard = VpsRouteGuard::new("203.0.113.1".into(), gw.clone());
        assert!(guard.reconcile().is_none(), "网关未变时不应重建路由");
        assert_eq!(guard.pinned_gw, gw);
    }

    #[test]
    fn route_guard_detects_stale_gateway() {
        // 构造一个不可能是当前网关的值，reconcile 应检测到差异。
        // 使用 TEST-NET-3 (RFC 5737) 保证不会误撞真实网关。
        let mut guard = VpsRouteGuard::new("203.0.113.1".into(), "203.0.113.254".into());
        if get_default_gateway().is_err() {
            return; // 无网络时跳过
        }
        // 会尝试重建路由；非 root 下 route add 失败返回 None，
        // 但 pinned_gw 必须已更新 —— 否则每 5s 都会重试同一个失效网关
        let _ = guard.reconcile();
        assert_ne!(guard.pinned_gw, "203.0.113.254", "检测到变化后必须更新记录");
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
    fn dev_flag_combines_with_all_connect_options() {
        let args = argv(&[
            "miaovps",
            "connect",
            "server",
            "--device",
            "device",
            "--full",
            "--dev",
            "--port",
            "443",
            "--daemon",
            "--skip-validate",
        ]);
        assert_eq!(connect_port_arg(&args).unwrap(), Some(443));
        assert_eq!(
            connect_target_args(&args).unwrap(),
            (Some("server".into()), Some("device".into()))
        );
        assert_eq!(
            connect_target_args(&argv(&["miaovps", "connect", "--dev"])).unwrap(),
            (None, None)
        );
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
