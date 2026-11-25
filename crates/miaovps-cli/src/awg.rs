use super::{data_dir, decode_key, open_service, resolve_server_id, wg};
use anyhow::{ensure, Context, Result};
use miaovps_app::session::open_provisioner;
use miaovps_storage::keychain::WgKeyStore;
use std::{net::Ipv4Addr, path::Path};

const DEFAULT_PORT: u16 = 52181;

pub(super) async fn deploy_default(args: &[String]) -> Result<()> {
    let prefix = args
        .get(2)
        .filter(|s| !s.starts_with("--"))
        .context("用法: miaovps deploy <server-id> [--port <udp-port>]")?;
    let requested = super::deploy_port_arg(args)?;
    let svc = open_service().await?;
    let id = resolve_server_id(&svc, prefix).await?;
    let server = svc.db.get_server(&id).await?.context("节点不存在")?;
    ensure!(server.status.permits_deployment(), "请先完成节点检测");
    let ip: Ipv4Addr = server.host.parse().context("AWG 节点地址须为 IPv4")?;
    let dir = data_dir();
    let path = dir.join(PROFILE_FILE);
    if path.try_exists()? {
        let (profile, framing) = load(&dir)?;
        ensure!(
            profile.server_ip()? == server.host,
            "已保存另一台 AWG 节点的配置；请先备份移走 {}",
            path.display()
        );
        if let Some(port) = requested {
            super::ensure_no_local_tunnel_for_port_change()?;
            super::change_listener(&svc, &server, &profile, framing, false, None, Some(port))
                .await?;
            println!("✓ AWG 服务端和本机配置已校对: UDP {port}");
        } else {
            let ssh = open_provisioner(&server, &svc.cred_dir, None).await?;
            let (key, port) = ssh.listener(false).await?;
            ensure!(
                key == profile.server_public_key && port == profile.server_addr()?.port(),
                "已保存 AWG 配置与远端不一致；用 status {prefix} 核对后指定 --port"
            );
            super::probe_listener(&profile, framing, port).await?;
            let _ = ssh.disconnect().await;
            println!("✓ AWG 已部署并通过握手验证: UDP {port}");
        }
        return Ok(());
    }
    let _lock = svc.deployment_lock()?;
    super::ensure_no_local_tunnel_for_port_change()?;
    // Keep the generated key across a failed install or an interrupted SSH response.
    let pending = dir.join(format!(".awg-{}.key", server.id));
    let keys = if pending.try_exists()? {
        wg::WgKeyPair::from_private_key(std::fs::read_to_string(&pending)?.trim())?
    } else {
        let keys = wg::generate_keypair();
        create_private(&pending, &keys.private_key)?;
        keys
    };
    let port = requested.unwrap_or(DEFAULT_PORT);
    let ssh = open_provisioner(&server, &svc.cred_dir, None).await?;
    let reply = ssh.deploy_awg_trial(port, &keys.public_key).await?;
    let config = client_config(&reply, keys.private_key, ip, port)?;
    let (profile, framing) = parse(&config)?;
    super::probe_listener(&profile, framing, port)
        .await
        .context("AWG 已启动但未通过客户端握手；检查 UDP 放行，再用同一命令重试")?;
    create_private(&path, &config)?;
    if let Err(error) = std::fs::remove_file(&pending) {
        tracing::warn!(%error, "AWG 配置已保存，无法移除安装暂存密钥");
    }
    let _ = ssh.disconnect().await;
    if let Err(error) = svc
        .db
        .update_server_status(&id, &miaovps_core::ServerStatus::Online)
        .await
    {
        tracing::warn!(%error, "AWG 已部署并保存，未能更新节点状态");
    }
    println!(
        "✓ AWG 已验证；配置已保存至 {}。可以运行 sudo miaovps connect --full。",
        path.display()
    );
    Ok(())
}

fn create_private(path: &Path, text: &str) -> Result<()> {
    let staged = super::profile::stage_private(path, text.as_bytes())?;
    std::fs::hard_link(staged.path(), path)
        .with_context(|| format!("无法创建 {}（不会覆盖现有文件）", path.display()))?;
    Ok(())
}

pub(super) fn stage_port(
    path: &Path,
    previous: &super::ConnectionProfile,
    port: u16,
) -> Result<super::profile::StagedPrivate> {
    let text = std::fs::read_to_string(path)?;
    let (profile, _) = parse(&text)?;
    ensure!(
        profile.client_public_key == previous.client_public_key
            && profile.server_public_key == previous.server_public_key
            && profile.server_addr()? == previous.server_addr()?,
        "AWG 配置在换口期间发生变化"
    );
    let mut endpoint = profile.server_addr()?;
    endpoint.set_port(port);
    let updated: String = text
        .split_inclusive('\n')
        .map(|line| {
            if line
                .split_once('=')
                .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("endpoint"))
            {
                format!("Endpoint = {endpoint}\n")
            } else {
                line.to_string()
            }
        })
        .collect();
    let (updated_profile, _) = parse(&updated)?;
    ensure!(
        updated_profile.server_addr()? == endpoint,
        "无法更新 AWG 端点"
    );
    super::profile::stage_private(path, updated.as_bytes())
}

pub(super) async fn add_device(args: &[String]) -> Result<()> {
    let [server, name, flag, output] = args else {
        anyhow::bail!("用法: miaovps add-device <server-id> <name> --output <new.conf>");
    };
    ensure!(
        flag == "--output" && !output.is_empty(),
        "请用 --output 指定配置文件"
    );
    ensure!(
        !name.trim().is_empty()
            && name.chars().count() <= 100
            && !name.chars().any(char::is_control)
            && !name.contains(['\u{2028}', '\u{2029}']),
        "设备名须为 1–100 个可见字符"
    );
    let output = Path::new(output);
    ensure!(
        output.extension().is_some_and(|ext| ext == "conf"),
        "输出配置文件须以 .conf 结尾"
    );
    let file = output.file_name().context("输出必须是新文件路径")?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let output = parent
        .canonicalize()
        .context("输出目录不存在或无法访问")?
        .join(file);
    let profile_path = data_dir().canonicalize()?.join(PROFILE_FILE);
    ensure!(
        output != profile_path,
        "请另选导出的配置文件，不要覆盖本机配置"
    );
    let svc = open_service().await?;
    let _lock = svc.deployment_lock()?;
    let id = resolve_server_id(&svc, server).await?;
    let server = svc.db.get_server(&id).await?.context("节点不存在")?;
    let ip: Ipv4Addr = server.host.parse().context("AWG 节点地址须为 IPv4")?;

    // Keep the key beside the requested output so an interrupted SSH call can be retried.
    let mut pending_path = output.as_os_str().to_os_string();
    pending_path.push(".pending");
    let pending_path = std::path::PathBuf::from(pending_path);
    let keys = enrollment_key(&output, &pending_path, &id, name)?;
    let ssh = open_provisioner(&server, &svc.cred_dir, None).await?;
    let reply = ssh
        .add_awg_peer(&keys.public_key, name)
        .await
        .context("添加 AWG 设备未完成；排除错误后用原命令重试，保留 .pending 文件")?;
    let (port, config_reply) = reply.split_once('\n').context("缺少 AWG 端口")?;
    let port: u16 = port.parse().context("AWG 端口无效")?;
    let config = client_config(config_reply, keys.private_key, ip, port)?;
    create_private(&output, &config)
        .context("设备已注册但配置未保存；保留 .pending 文件，用原命令重试")?;
    if let Err(error) = std::fs::remove_file(&pending_path) {
        tracing::warn!(%error, "设备配置已生成，无法删除暂存密钥 {}", pending_path.display());
    }
    let _ = ssh.disconnect().await;
    println!("✓ AWG 设备已添加，配置已保存至 {}。", output.display());
    println!("  请通过可信渠道把配置交给这一台设备（包含私钥）。");
    println!("  对方运行：miaovps profile import <device.conf>");
    println!("  然后运行：sudo miaovps connect --full");
    Ok(())
}

fn enrollment_key(
    output: &Path,
    pending: &Path,
    server: &str,
    name: &str,
) -> Result<wg::WgKeyPair> {
    ensure!(
        output
            .symlink_metadata()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "输出文件已存在或无法检查: {}",
        output.display()
    );
    if pending.symlink_metadata().is_ok() {
        use std::io::Read;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(pending)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.mode() & 0o077 == 0 && metadata.nlink() == 1,
            "暂存文件必须为私有普通文件: {}",
            pending.display()
        );
        let mut text = String::new();
        file.take(4096).read_to_string(&mut text)?;
        let [old_server, old_name, private] = text.lines().collect::<Vec<_>>()[..] else {
            anyhow::bail!("暂存文件无效: {}", pending.display());
        };
        ensure!(
            old_server == server && old_name == name,
            "暂存文件属于另一节点或设备；请用原命令重试，或另选输出路径"
        );
        return Ok(wg::WgKeyPair::from_private_key(private)?);
    }
    let keys = wg::generate_keypair();
    create_private(
        pending,
        &format!("{server}\n{name}\n{}\n", keys.private_key),
    )?;
    Ok(keys)
}

pub(super) async fn import(source: &Path) -> Result<()> {
    let dir = data_dir();
    ensure!(
        !miaovps_app::tunnel::TunnelState::load(&dir).occupies_tunnel(),
        "请先断开当前隧道，再导入配置"
    );
    import_with_probe(source, &dir, |profile, framing, port| async move {
        super::probe_listener(&profile, framing, port).await
    })
    .await
}

async fn import_with_probe<F, Fut>(source: &Path, dir: &Path, probe: F) -> Result<()>
where
    F: FnOnce(super::ConnectionProfile, miaovps_connect::awg::Framing, u16) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let path = dir.join(PROFILE_FILE);
    ensure!(
        path.symlink_metadata()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "已有 AWG 配置 {}，不会覆盖；如需切换，请先断开并备份移走旧配置",
        path.display()
    );
    let text = std::fs::read_to_string(source).context("无法读取要导入的 AWG 配置")?;
    let (profile, framing) = parse(&text)?;
    let port = profile.server_addr()?.port();
    probe(profile, framing, port)
        .await
        .context("导入握手失败，未保存配置；请向管理员核对节点地址、UDP 端口和放行规则")?;
    create_private(&path, &text)?;
    println!("✓ AWG 配置已验证并导入。可以运行 sudo miaovps connect --full。");
    Ok(())
}

pub(super) async fn list_device(args: &[String]) -> Result<()> {
    let [prefix] = args else {
        anyhow::bail!("用法: miaovps list-devices [--wg] <server-id>");
    };
    let svc = open_service().await?;
    let id = resolve_server_id(&svc, prefix).await?;
    let server = svc.db.get_server(&id).await?.context("节点不存在")?;
    let ssh = open_provisioner(&server, &svc.cred_dir, None).await?;
    print!("{}", ssh.list_awg_peers().await?);
    let _ = ssh.disconnect().await;
    Ok(())
}

pub(super) fn export(args: &[String]) -> Result<()> {
    ensure!(
        args.is_empty(),
        "用法: miaovps export-config（本机 AWG 配置）或 export-config --wg <device-id>"
    );
    let text = std::fs::read_to_string(data_dir().join(PROFILE_FILE))?;
    parse(&text)?;
    print!("{text}");
    Ok(())
}

pub(super) async fn deploy_trial(args: &[String]) -> Result<()> {
    let [server, device, port, output] = args else {
        anyhow::bail!("用法: miaovps deploy-awg <server-id> <device-id> <udp-port> <new.conf>");
    };
    let port: u16 = port.parse().context("UDP 端口必须为 1–65535")?;
    ensure!(port != 0, "端口不能为 0");
    ensure!(!Path::new(output).try_exists()?, "拒绝覆盖已有配置文件");
    ensure!(
        !device.is_empty() && !server.is_empty(),
        "必须指定节点和设备"
    );
    let svc = open_service().await?;
    let _lock = svc.deployment_lock()?;
    let id = resolve_server_id(&svc, server).await?;
    let server = svc.db.get_server(&id).await?.context("节点不存在")?;
    ensure!(server.status.permits_deployment(), "请先完成节点检测");
    let node = svc
        .db
        .get_wg_node(&id)
        .await?
        .context("请先部署原生 WG 节点")?;
    ensure!(node.listen_port != port, "试用端口不能与现有 WG 节点相同");
    let ip: Ipv4Addr = server.host.parse().context("试用节点地址须为公网 IPv4")?;
    let devices = svc.list_devices(id).await?;
    let mut matches = devices.iter().filter(|d| d.id.starts_with(device));
    let device = matches.next().context("设备不属于该节点或不存在")?;
    ensure!(
        matches.next().is_none() && device.enabled,
        "设备不唯一或未启用"
    );
    let private = WgKeyStore::load(
        device
            .private_key_ref
            .as_deref()
            .context("设备缺少密钥引用")?,
    )?;
    ensure!(
        wg::WgKeyPair::from_private_key(&private)?.public_key == device.public_key,
        "设备密钥不匹配"
    );

    let ssh = open_provisioner(&server, &svc.cred_dir, None).await?;
    let reply = ssh.deploy_awg_trial(port, &device.public_key).await?;
    if let Err(e) = ssh.disconnect().await {
        tracing::warn!("关闭部署 SSH 会话失败: {e}");
    }
    let config = client_config(&reply, private, ip, port)?;
    create_private(Path::new(output), &config)?;
    println!(
        "已生成 {output}（UDP {port}）。运行 miaovps profile import <device.conf> 导入，也可导入 AmneziaWG 客户端。"
    );
    Ok(())
}

pub use miaovps_app::tunnel::AWG_PROFILE_FILE as PROFILE_FILE;

pub(super) fn load(
    dir: &Path,
) -> Result<(super::ConnectionProfile, miaovps_connect::awg::Framing)> {
    let path = dir.join(PROFILE_FILE);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "无法读取 AWG 配置 {}。请运行 miaovps profile import <device.conf>，或由管理员部署 AWG。原生 WireGuard 请加 --wg。",
            path.display()
        )
    })?;
    parse(&text)
}

pub(super) async fn check_target(
    profile: &super::ConnectionProfile,
    server: &str,
    device: &str,
) -> Result<()> {
    let svc = open_service().await?;
    let id = resolve_server_id(&svc, server).await?;
    let node = svc.db.get_server(&id).await?.context("节点不存在")?;
    let devices = svc.list_devices(id).await?;
    let mut matches = devices.iter().filter(|d| d.id.starts_with(device));
    let peer = matches.next().context("设备不属于该节点或不存在")?;
    ensure!(
        matches.next().is_none() && peer.enabled,
        "设备不唯一或未启用"
    );
    ensure!(
        node.host == profile.server_ip()? && peer.public_key == profile.client_public_key,
        "当前 AWG 配置与指定节点或设备不匹配；请部署该设备的 AWG 配置，或加 --wg"
    );
    Ok(())
}

fn parse(text: &str) -> Result<(super::ConnectionProfile, miaovps_connect::awg::Framing)> {
    let mut fields = std::collections::HashMap::new();
    let mut section = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = Some(match (section, line) {
                (None, "[Interface]") => true,
                (Some(true), "[Peer]") => false,
                _ => anyhow::bail!("AWG 配置必须依次包含一个 [Interface] 和一个 [Peer]"),
            });
            continue;
        }
        let interface = section.context("AWG 配置缺少 [Interface]")?;
        let (k, v) = line.split_once('=').context("AWG 配置行缺少等号")?;
        let key = k.trim().to_ascii_lowercase();
        let value = v.trim();
        ensure!(
            matches!(
                (interface, key.as_str()),
                (
                    true,
                    "h1" | "h2"
                        | "h3"
                        | "h4"
                        | "s1"
                        | "s2"
                        | "jc"
                        | "jmin"
                        | "jmax"
                        | "address"
                        | "privatekey"
                        | "dns"
                        | "mtu"
                ) | (
                    false,
                    "publickey" | "endpoint" | "allowedips" | "persistentkeepalive"
                )
            ),
            "配置包含 MiaoVPS 不支持的字段"
        );
        ensure!(fields.insert(key, value).is_none(), "AWG 配置包含重复字段");
    }
    let value = |key: &str| {
        fields
            .get(key)
            .copied()
            .with_context(|| format!("缺少 AWG 参数 {key}"))
    };
    let awg = miaovps_connect::awg::Framing::amnezia(
        [
            value("h1")?.parse()?,
            value("h2")?.parse()?,
            value("h3")?.parse()?,
            value("h4")?.parse()?,
        ],
        [value("s1")?.parse()?, value("s2")?.parse()?],
        [
            value("jc")?.parse()?,
            value("jmin")?.parse()?,
            value("jmax")?.parse()?,
        ],
    )?;
    ensure!(section == Some(false), "缺少 AWG [Peer]");
    if let Some(allowed) = fields.get("allowedips") {
        ensure!(
            allowed.split(',').any(|net| net.trim() == "0.0.0.0/0"),
            "MiaoVPS AWG 配置须允许全部 IPv4，使用 connect --full 决定是否接管公网流量"
        );
    }
    if let Some(keepalive) = fields.get("persistentkeepalive") {
        keepalive.parse::<u16>().context("AWG 保活间隔无效")?;
    }
    let client_private_key = value("privatekey")?.to_owned();
    let client_public_key =
        super::derive_public_key(&decode_key(&client_private_key, "AWG 客户端私钥")?);
    let address: Ipv4Addr = value("address")?
        .strip_suffix("/32")
        .context("AWG 客户端地址必须是 /32")?
        .parse()?;
    let mut gateway = address.octets();
    // The first peer keeps its original /30. Extra peers use the same .1 gateway and the /24 pool.
    let expanded = gateway[3] != 2;
    ensure!(
        address.is_private() && (gateway[3] == 2 || (4..=254).contains(&gateway[3])),
        "AWG 客户端地址不符合 MiaoVPS 地址分配规则"
    );
    gateway[3] = 1;
    let dns: Vec<String> = fields.get("dns").map_or_else(Vec::new, |value| {
        value.split(',').map(|s| s.trim().to_owned()).collect()
    });
    ensure!(
        dns.iter()
            .all(|address| address.parse::<std::net::IpAddr>().is_ok()),
        "AWG DNS 地址无效"
    );
    let mtu: u16 = fields
        .get("mtu")
        .copied()
        .unwrap_or("1380")
        .parse()
        .context("AWG MTU 无效")?;
    ensure!((576..=1420).contains(&mtu), "AWG MTU 必须为 576–1420");
    let profile = super::ConnectionProfile {
        client_private_key,
        client_public_key,
        client_ip: address.to_string(),
        peer_ip: Ipv4Addr::from(gateway).to_string(),
        netmask: if expanded {
            "255.255.255.0"
        } else {
            "255.255.255.252"
        }
        .into(),
        mtu,
        dns,
        server_public_key: value("publickey")?.to_owned(),
        server_endpoint: value("endpoint")?.to_owned(),
    };
    ensure!(
        profile.server_addr()?.is_ipv4() && profile.server_addr()?.port() != 0,
        "AWG 端点必须为 IPv4 和非零端口"
    );
    profile.server_public_bytes()?;
    Ok((profile, awg))
}

fn client_config(reply: &str, private_key: String, ip: Ipv4Addr, port: u16) -> Result<String> {
    let mut lines = reply.lines();
    let public_key = lines.next().context("缺少 AWG 服务端公钥")?;
    decode_key(public_key, "AWG 公钥")?;
    let address: Ipv4Addr = lines
        .next()
        .and_then(|l| l.strip_suffix("/32"))
        .context("缺少设备 /32 地址")?
        .parse()?;
    ensure!(address.is_private(), "试用地址须为私网 IP");
    // Never copy arbitrary remote text (in particular quick hooks) into a client config.
    let mut framing = String::from("Jc = 4\nJmin = 48\nJmax = 128\n");
    for name in ["H1", "H2", "H3", "H4", "S1", "S2"] {
        let value: u32 = lines
            .next()
            .and_then(|l| l.strip_prefix(&format!("{name} = ")))
            .context("服务端 AWG 参数不完整")?
            .parse()?;
        framing.push_str(&format!("{name} = {value}\n"));
    }
    ensure!(lines.next().is_none(), "意外的 AWG 参数");
    let config = wg::generate_client_config(wg::ClientConfigParams {
        private_key,
        address: format!("{address}/32"),
        dns: vec!["1.1.1.1".into()],
        mtu: Some(1380),
        server_public_key: public_key.into(),
        server_endpoint: format!("{ip}:{port}"),
        allowed_ips: "0.0.0.0/0, ::/0".into(),
        persistent_keepalive: Some(25),
    });
    let config = config.replacen("\n[Peer]", &format!("{framing}\n[Peer]"), 1);
    parse(&config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(public: &str, address: &str) -> String {
        format!(
            "{public}\n{address}/32\nH1 = 120\nH2 = 240\nH3 = 360\nH4 = 480\nS1 = 20\nS2 = 24\n"
        )
    }

    #[tokio::test]
    async fn import_saves_only_after_handshake_and_never_overwrites() {
        use std::os::unix::fs::PermissionsExt;

        let keys = wg::generate_keypair();
        let text = client_config(
            &reply(&keys.public_key, "172.29.67.4"),
            keys.private_key,
            Ipv4Addr::LOCALHOST,
            52181,
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("miaovps-awg-import-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("new-device.conf");
        let path = dir.join(PROFILE_FILE);
        std::fs::write(&source, text.replace("S1 = 20", "PostUp = true\nS1 = 20")).unwrap();
        assert!(import_with_probe(&source, &dir, |_, _, _| async {
            panic!("invalid config must not probe")
        })
        .await
        .is_err());
        std::fs::write(&source, &text).unwrap();
        assert!(import_with_probe(&source, &dir, |_, _, _| async {
            anyhow::bail!("handshake failed")
        })
        .await
        .is_err());
        assert!(!path.exists());
        import_with_probe(&source, &dir, |profile, _, port| async move {
            assert_eq!(profile.client_ip, "172.29.67.4");
            assert_eq!(profile.peer_ip, "172.29.67.1");
            assert_eq!(profile.netmask, "255.255.255.0");
            assert_eq!(port, 52181);
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(import_with_probe(&source, &dir, |_, _, _| async {
            panic!("existing profile must not probe")
        })
        .await
        .is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        assert!(!dir.join("miaovps.db").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn enrollment_reuses_only_the_matching_pending_key() {
        let dir = std::env::temp_dir().join(format!("miaovps-awg-enroll-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let output = dir.join("new.conf");
        let pending = dir.join("new.conf.pending");
        let key = enrollment_key(&output, &pending, "node-id", "new device")
            .unwrap()
            .public_key;
        assert_eq!(
            enrollment_key(&output, &pending, "node-id", "new device")
                .unwrap()
                .public_key,
            key
        );
        assert!(enrollment_key(&output, &pending, "other-node", "new device").is_err());
        assert!(enrollment_key(&output, &pending, "node-id", "other device").is_err());
        std::os::unix::fs::symlink("missing", &output).unwrap();
        assert!(enrollment_key(&output, &pending, "node-id", "new device").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn staging_an_awg_port_does_not_touch_the_current_profile_until_install() {
        let keys = wg::generate_keypair();
        let reply = reply(&keys.public_key, "172.29.67.2");
        let text = client_config(&reply, keys.private_key, Ipv4Addr::LOCALHOST, 52181).unwrap();
        let dir = std::env::temp_dir().join(format!("miaovps-awg-port-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join(PROFILE_FILE);
        create_private(&path, &text).unwrap();
        assert!(create_private(&path, "bad config").is_err());
        let profile = parse(&text).unwrap().0;
        let trial = stage_port(&path, &profile, 52182).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        drop(trial);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        stage_port(&path, &profile, 52182)
            .unwrap()
            .install(&path)
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            text.replace("127.0.0.1:52181", "127.0.0.1:52182")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn export_keeps_matching_interface_framing_and_rejects_script_injection() {
        let keys = wg::generate_keypair();
        let reply = reply(&keys.public_key, "172.29.67.2");
        let export =
            |r: &str| client_config(r, keys.private_key.clone(), Ipv4Addr::LOCALHOST, 52181);
        let config = export(&reply).unwrap();
        let (iface, peer) = config.split_once("[Peer]").unwrap();
        assert!(iface.contains("Jc = 4\n") && iface.contains("H1 = 120\n"));
        assert!(iface.contains("Address = 172.29.67.2/32\n"));
        assert!(peer.contains("Endpoint = 127.0.0.1:52181"));
        let (profile, _) = parse(&config).ok().unwrap();
        assert_eq!(profile.peer_ip, "172.29.67.1");
        assert_eq!(profile.netmask, "255.255.255.252");
        assert!(parse(&config.replace("H1 = 120", "H1 = 240")).is_err());
        assert!(parse(&config.replace("S1 = 20", "S1 = 65535")).is_err());
        assert!(parse(&config.replace("S1 = 20", "PostUp = true\nS1 = 20")).is_err());
        assert!(export(&format!("{reply}PostUp = false")).is_err());
        assert!(export(&reply.replace("H1 = 120", "H1 = 120; echo bad")).is_err());
    }
}
