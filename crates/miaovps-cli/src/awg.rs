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

pub(super) async fn list_device(args: &[String]) -> Result<()> {
    let [prefix] = args else {
        anyhow::bail!("用法: miaovps list-devices [--wg] <server-id>");
    };
    let svc = open_service().await?;
    let id = resolve_server_id(&svc, prefix).await?;
    let server = svc.db.get_server(&id).await?.context("节点不存在")?;
    let dir = data_dir();
    if dir.join(PROFILE_FILE).try_exists()? {
        let (profile, _) = load(&dir)?;
        if profile.server_ip()? == server.host {
            println!(
                "AWG 本机设备: {}  {}/32",
                profile.client_public_key, profile.client_ip
            );
            return Ok(());
        }
    }
    println!("此节点没有已保存的本机 AWG 设备；请运行 miaovps deploy {prefix}");
    Ok(())
}

pub(super) fn export(args: &[String]) -> Result<()> {
    ensure!(
        args.is_empty(),
        "用法: miaovps export-config（AWG 单设备）或 export-config --wg <device-id>"
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
        "已生成 {output}（UDP {port}）。保存为数据目录下的 {PROFILE_FILE} 后，可运行 sudo miaovps connect；也可导入 AmneziaWG 客户端。"
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
            "无法读取 AWG 配置 {}。请部署 AWG 并将配置保存到该路径，或用 connect --wg。",
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
    let mut framing = std::collections::HashMap::new();
    let mut in_interface = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            ensure!(
                matches!(line, "[Interface]" | "[Peer]"),
                "不支持的 AWG 配置段"
            );
            in_interface = line == "[Interface]";
        } else if let Some((k, v)) = line.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            match (in_interface, key.as_str()) {
                (true, "h1" | "h2" | "h3" | "h4" | "s1" | "s2" | "jc" | "jmin" | "jmax") => {
                    ensure!(
                        framing.insert(key, v.trim()).is_none(),
                        "包含重复的 AWG 参数"
                    );
                }
                (true, "address" | "privatekey" | "dns" | "mtu")
                | (false, "publickey" | "endpoint" | "allowedips" | "persistentkeepalive") => {}
                _ => anyhow::bail!("配置包含 MiaoVPS 不支持的字段"),
            }
        }
    }
    let value = |key: &str| {
        framing
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
    let config = wg::parse_config(text)?;
    let iface = config.interface.context("缺少 AWG [Interface]")?;
    let [peer] = config.peers.as_slice() else {
        anyhow::bail!("AWG 配置必须仅有一个 peer")
    };
    let client_private_key = iface.private_key.context("缺少 AWG 客户端私钥")?;
    let client_public_key =
        super::derive_public_key(&decode_key(&client_private_key, "AWG 客户端私钥")?);
    let address: Ipv4Addr = iface
        .address
        .as_deref()
        .and_then(|s| s.strip_suffix("/32"))
        .context("AWG 客户端地址必须是 /32")?
        .parse()?;
    let mut gateway = address.octets();
    ensure!(
        address.is_private() && gateway[3] == 2,
        "AWG 客户端地址不符合 MiaoVPS /30 配置"
    );
    gateway[3] = 1;
    ensure!(
        iface
            .dns
            .iter()
            .all(|dns| dns.parse::<std::net::IpAddr>().is_ok()),
        "AWG DNS 地址无效"
    );
    let mtu = iface.mtu.unwrap_or(1380);
    ensure!((576..=1420).contains(&mtu), "AWG MTU 必须为 576–1420");
    let profile = super::ConnectionProfile {
        client_private_key,
        client_public_key,
        client_ip: address.to_string(),
        peer_ip: Ipv4Addr::from(gateway).to_string(),
        netmask: "255.255.255.252".into(),
        mtu,
        dns: iface.dns,
        server_public_key: peer.public_key.clone().context("缺少 AWG 服务端公钥")?,
        server_endpoint: peer.endpoint.clone().context("缺少 AWG 端点")?,
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

    #[test]
    fn staging_an_awg_port_does_not_touch_the_current_profile_until_install() {
        let keys = wg::generate_keypair();
        let reply = format!(
            "{}\n172.29.67.2/32\nH1 = 120\nH2 = 240\nH3 = 360\nH4 = 480\nS1 = 20\nS2 = 24\n",
            keys.public_key
        );
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
        let reply = format!(
            "{}\n172.29.67.2/32\nH1 = 120\nH2 = 240\nH3 = 360\nH4 = 480\nS1 = 20\nS2 = 24\n",
            keys.public_key
        );
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
