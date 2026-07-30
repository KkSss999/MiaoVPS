//! WireGuard 配置生成
//!
//! 纯计算模块，不依赖网络或 SSH。
//! 负责：密钥对生成、服务端/客户端配置生成、配置解析、二维码。

use base64::Engine;
use x25519_dalek::{PublicKey, StaticSecret};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  密钥
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// WireGuard 密钥对
#[derive(Debug, Clone)]
pub struct WgKeyPair {
    pub private_key: String,
    pub public_key: String,
}

impl WgKeyPair {
    /// 从私钥字符串解析
    pub fn from_private_key(private_key: &str) -> Result<Self, ConfigError> {
        let decoded = base64_decode_wg(private_key)?;
        if decoded.len() != 32 {
            return Err(ConfigError::InvalidKeyLength(decoded.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        let secret = StaticSecret::from(arr);
        let public = PublicKey::from(&secret);
        Ok(Self {
            private_key: private_key.into(),
            public_key: base64_encode_wg(public.as_bytes()),
        })
    }
}

/// 生成新的 Curve25519 密钥对
pub fn generate_keypair() -> WgKeyPair {
    use rand::rngs::OsRng;
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    WgKeyPair {
        private_key: base64_encode_wg(secret.as_bytes()),
        public_key: base64_encode_wg(public.as_bytes()),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  配置生成参数
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct ServerConfigParams {
    pub private_key: String,
    pub listen_port: u16,
    pub vpn_cidr: String,
    pub interface_name: String,
    pub peers: Vec<PeerEntry>,
    pub mtu: Option<u16>,
}

pub struct PeerEntry {
    pub public_key: String,
    pub allowed_ips: String,
}

pub struct ClientConfigParams {
    pub private_key: String,
    pub address: String,
    pub dns: Vec<String>,
    pub mtu: Option<u16>,
    pub server_public_key: String,
    pub server_endpoint: String,
    pub allowed_ips: String,
    pub persistent_keepalive: Option<u16>,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  配置生成
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 生成 WireGuard 服务端配置文件内容
pub fn generate_server_config(params: ServerConfigParams) -> String {
    let mut config = String::new();
    config.push_str(&format!(
        "[Interface]\nPrivateKey = {}\nListenPort = {}\nAddress = {}\n",
        params.private_key, params.listen_port, params.vpn_cidr
    ));
    if let Some(mtu) = params.mtu {
        config.push_str(&format!("MTU = {}\n", mtu));
    }
    config.push('\n');

    for peer in &params.peers {
        config.push_str(&format!(
            "[Peer]\nPublicKey = {}\nAllowedIPs = {}\n\n",
            peer.public_key, peer.allowed_ips
        ));
    }

    config
}

/// 生成 WireGuard 客户端配置文件内容
pub fn generate_client_config(params: ClientConfigParams) -> String {
    let mut config = String::new();
    config.push_str(&format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}\n",
        params.private_key, params.address
    ));
    if !params.dns.is_empty() {
        config.push_str(&format!("DNS = {}\n", params.dns.join(", ")));
    }
    if let Some(mtu) = params.mtu {
        config.push_str(&format!("MTU = {}\n", mtu));
    }
    config.push_str(&format!(
        "\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\n",
        params.server_public_key, params.server_endpoint, params.allowed_ips
    ));
    if let Some(ka) = params.persistent_keepalive {
        config.push_str(&format!("PersistentKeepalive = {}\n", ka));
    }

    config
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  配置解析
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 解析后的 WireGuard 配置
#[derive(Debug, Clone, Default)]
pub struct ParsedConfig {
    pub interface: Option<InterfaceSection>,
    pub peers: Vec<PeerSection>,
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceSection {
    pub private_key: Option<String>,
    pub address: Option<String>,
    pub listen_port: Option<u16>,
    pub dns: Vec<String>,
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerSection {
    pub public_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

/// 解析 WireGuard 配置文件
pub fn parse_config(content: &str) -> Result<ParsedConfig, ConfigError> {
    let mut result = ParsedConfig::default();
    let mut current_section: Option<&str> = None;
    let mut current_interface = InterfaceSection::default();
    let mut current_peer = PeerSection::default();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed == "[Interface]" {
            // 保存上一个 peer
            if current_section == Some("Peer") {
                result.peers.push(std::mem::take(&mut current_peer));
            }
            current_section = Some("Interface");
            continue;
        }
        if trimmed == "[Peer]" {
            if current_section == Some("Interface") {
                result.interface = Some(std::mem::take(&mut current_interface));
            }
            if current_section == Some("Peer") {
                result.peers.push(std::mem::take(&mut current_peer));
            }
            current_section = Some("Peer");
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = value.trim();

            match current_section {
                Some("Interface") => {
                    match key.as_str() {
                        "privatekey" => current_interface.private_key = Some(value.into()),
                        "address" => current_interface.address = Some(value.into()),
                        "listenport" => current_interface.listen_port = value.parse().ok(),
                        "dns" => current_interface.dns = value.split(',').map(|s| s.trim().into()).collect(),
                        "mtu" => current_interface.mtu = value.parse().ok(),
                        _ => {}
                    }
                }
                Some("Peer") => {
                    match key.as_str() {
                        "publickey" => current_peer.public_key = Some(value.into()),
                        "endpoint" => current_peer.endpoint = Some(value.into()),
                        "allowedips" => current_peer.allowed_ips = Some(value.into()),
                        "persistentkeepalive" => current_peer.persistent_keepalive = value.parse().ok(),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    // 保存最后的部分
    match current_section {
        Some("Interface") => result.interface = Some(current_interface),
        Some("Peer") => result.peers.push(current_peer),
        _ => {}
    }

    Ok(result)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  二维码
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 生成配置内容的二维码（UTF-8 终端输出或 SVG）
pub fn generate_qrcode_svg(content: &str) -> Result<String, ConfigError> {
    use qrcode::QrCode;
    use qrcode::render::svg;

    let code = QrCode::new(content.as_bytes()).map_err(|e| ConfigError::QrError(e.to_string()))?;
    Ok(code.render().min_dimensions(200, 200).dark_color(svg::Color("#000000")).light_color(svg::Color("#ffffff")).build())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  错误
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),

    #[error("Invalid key encoding: {0}")]
    InvalidKeyEncoding(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("QR generation failed: {0}")]
    QrError(String),
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  base64 helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use base64::engine::general_purpose::STANDARD as base64_engine;

fn base64_encode_wg(bytes: &[u8]) -> String {
    base64_engine.encode(bytes)
}

fn base64_decode_wg(s: &str) -> Result<Vec<u8>, ConfigError> {
    base64_engine
        .decode(s)
        .map_err(|e| ConfigError::InvalidKeyEncoding(e.to_string()))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let kp = generate_keypair();
        assert_eq!(kp.private_key.len(), 44); // 32 bytes base64
        assert_eq!(kp.public_key.len(), 44);
        assert_ne!(kp.private_key, kp.public_key);

        // 验证可以从私钥重建
        let kp2 = WgKeyPair::from_private_key(&kp.private_key).unwrap();
        assert_eq!(kp.public_key, kp2.public_key);
    }

    #[test]
    fn test_generate_server_config() {
        let params = ServerConfigParams {
            private_key: "PRIVATE_KEY".into(),
            listen_port: 51820,
            vpn_cidr: "10.66.66.1/24".into(),
            interface_name: "wg0".into(),
            peers: vec![PeerEntry {
                public_key: "PEER_KEY".into(),
                allowed_ips: "10.66.66.2/32".into(),
            }],
            mtu: Some(1380),
        };
        let config = generate_server_config(params);
        assert!(config.contains("PrivateKey = PRIVATE_KEY"));
        assert!(config.contains("ListenPort = 51820"));
        assert!(config.contains("Address = 10.66.66.1/24"));
        assert!(config.contains("PublicKey = PEER_KEY"));
    }

    #[test]
    fn test_generate_client_config() {
        let params = ClientConfigParams {
            private_key: "CLIENT_KEY".into(),
            address: "10.66.66.2/32".into(),
            dns: vec!["1.1.1.1".into()],
            mtu: Some(1380),
            server_public_key: "SERVER_KEY".into(),
            server_endpoint: "1.2.3.4:51820".into(),
            allowed_ips: "0.0.0.0/0, ::/0".into(),
            persistent_keepalive: Some(25),
        };
        let config = generate_client_config(params);
        assert!(config.contains("PrivateKey = CLIENT_KEY"));
        assert!(config.contains("DNS = 1.1.1.1"));
        assert!(config.contains("Endpoint = 1.2.3.4:51820"));
        assert!(config.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn test_parse_config() {
        let config = r#"
[Interface]
PrivateKey = abc123
Address = 10.66.66.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = xyz789
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#;
        let parsed = parse_config(config).unwrap();
        let iface = parsed.interface.unwrap();
        assert_eq!(iface.private_key.unwrap(), "abc123");
        assert_eq!(iface.address.unwrap(), "10.66.66.2/32");

        let peer = &parsed.peers[0];
        assert_eq!(peer.public_key.as_ref().unwrap(), "xyz789");
        assert_eq!(peer.persistent_keepalive.unwrap(), 25);
    }

    #[test]
    fn test_qrcode_generation() {
        let svg = generate_qrcode_svg("test").unwrap();
        assert!(svg.contains("<svg"));
    }
}
