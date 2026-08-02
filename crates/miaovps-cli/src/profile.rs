//! 连接配置持久化 — 客户端密钥必须跨进程稳定
//!
//! WireGuard 的服务端只接受 peer 列表里已注册的公钥。客户端每次连接
//! 必须复用**同一对**密钥，否则服务器静默丢弃握手包（表现为握手超时）。
//!
//! 存储位置是项目数据目录下的 `profile.json`，权限 0600。
//!
//! ## 为什么不用 Keychain
//!
//! `connect` 需要 root 创建 TUN 接口。sudo 下访问的是 root 的 Keychain，
//! 与用户 Keychain 不是同一个存储 — 用户态写入的密钥 root 读不到。
//! 文件存储对两种身份都可见，是这个场景下唯一可行的方案。

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 与服务端 provisioner 默认值一致
const DEFAULT_MTU: u16 = 1380;
const DEFAULT_NETMASK: &str = "255.255.255.0";

/// 连接配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionProfile {
    /// 客户端私钥 (base64) — 必须与服务端注册的 peer 公钥对应
    pub client_private_key: String,
    /// 客户端公钥 (base64) — 需在服务端 peer 列表中注册
    pub client_public_key: String,
    /// 服务器公钥 (base64)
    pub server_public_key: String,
    /// 服务器 WireGuard 端点 (IP:PORT)
    pub server_endpoint: String,
    /// 客户端 VPN 内网地址
    pub client_ip: String,
    /// VPN 网关地址（服务端 wg0 地址）
    pub peer_ip: String,
    /// 子网掩码
    #[serde(default = "default_netmask")]
    pub netmask: String,
    /// MTU — 必须与服务端 wg0 一致
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// DNS 服务器
    #[serde(default)]
    pub dns: Vec<String>,
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_netmask() -> String {
    DEFAULT_NETMASK.to_string()
}

impl ConnectionProfile {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("profile.json")
    }

    /// 从磁盘加载
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = Self::path(data_dir);
        let raw = std::fs::read_to_string(&path).with_context(|| {
            format!(
                "未找到连接配置 {}\n\
                 先运行: miaovps profile init <server-ip:port> <客户端私钥> <服务器公钥>",
                path.display()
            )
        })?;
        let profile: Self = serde_json::from_str(&raw)
            .with_context(|| format!("配置文件格式错误: {}", path.display()))?;
        profile.validate()?;
        Ok(profile)
    }

    /// 写入磁盘，权限 0600
    pub fn save(&self, data_dir: &Path) -> Result<PathBuf> {
        self.validate()?;
        let path = Self::path(data_dir);
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json).with_context(|| format!("无法写入 {}", path.display()))?;

        // 私钥文件必须限制权限
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("无法设置 {} 权限", path.display()))?;
        }

        Ok(path)
    }

    /// 校验字段可用性 — 早失败，避免带着坏配置去创建 TUN
    fn validate(&self) -> Result<()> {
        decode_key(&self.client_private_key, "客户端私钥")?;
        decode_key(&self.server_public_key, "服务器公钥")?;
        self.server_endpoint
            .parse::<std::net::SocketAddr>()
            .with_context(|| {
                format!(
                    "服务器端点格式错误 '{}'，应为 IP:PORT",
                    self.server_endpoint
                )
            })?;
        self.client_ip
            .parse::<std::net::Ipv4Addr>()
            .with_context(|| format!("客户端 IP 格式错误 '{}'", self.client_ip))?;
        self.peer_ip
            .parse::<std::net::Ipv4Addr>()
            .with_context(|| format!("VPN 网关 IP 格式错误 '{}'", self.peer_ip))?;
        Ok(())
    }

    pub fn server_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.server_endpoint.parse()?)
    }

    pub fn client_private_bytes(&self) -> Result<[u8; 32]> {
        decode_key(&self.client_private_key, "客户端私钥")
    }

    pub fn server_public_bytes(&self) -> Result<[u8; 32]> {
        decode_key(&self.server_public_key, "服务器公钥")
    }

    /// 服务器 IP（不含端口）— 用于设置直连路由
    pub fn server_ip(&self) -> Result<String> {
        Ok(self.server_addr()?.ip().to_string())
    }
}

/// 解码 base64 WireGuard 密钥到 32 字节
pub fn decode_key(b64: &str, label: &str) -> Result<[u8; 32]> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let bytes = STANDARD
        .decode(b64.trim())
        .with_context(|| format!("{label} base64 解码失败"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{label} 长度错误: 期望 32 字节，实际 {} 字节", bytes.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// 从私钥推导公钥 — 用于校验 profile 里的公钥是否自洽
pub fn derive_public_key(private_key: &[u8; 32]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use x25519_dalek::{PublicKey, StaticSecret};

    let sk: StaticSecret = (*private_key).into();
    STANDARD.encode(PublicKey::from(&sk).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConnectionProfile {
        let priv_key = "OGuo5H0lNQ1MJx6bYVdGYIWQDGvjkiRZDGCyIQwYVGM=";
        let priv_bytes = decode_key(priv_key, "test").unwrap();
        ConnectionProfile {
            client_public_key: derive_public_key(&priv_bytes),
            client_private_key: priv_key.into(),
            server_public_key: "fRp9SCOP2pu780jn15LbDFbxPwJJleAjODXjzcOgZFs=".into(),
            server_endpoint: "203.0.113.10:51820".into(),
            client_ip: "10.66.66.2".into(),
            peer_ip: "10.66.66.1".into(),
            netmask: DEFAULT_NETMASK.into(),
            mtu: DEFAULT_MTU,
            dns: vec!["1.1.1.1".into()],
        }
    }

    #[test]
    fn roundtrip_preserves_keys() {
        let dir = std::env::temp_dir().join(format!("miaovps-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let profile = sample();
        profile.save(&dir).unwrap();
        let loaded = ConnectionProfile::load(&dir).unwrap();

        assert_eq!(loaded.client_private_key, profile.client_private_key);
        assert_eq!(loaded.mtu, DEFAULT_MTU);
        assert_eq!(loaded.server_ip().unwrap(), "203.0.113.10");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn derives_public_key_from_private() {
        let profile = sample();
        let derived = derive_public_key(&profile.client_private_bytes().unwrap());
        assert_eq!(derived, profile.client_public_key);
    }

    #[test]
    fn rejects_bad_endpoint() {
        let mut profile = sample();
        profile.server_endpoint = "203.0.113.10".into(); // 缺端口
        assert!(profile.save(&std::env::temp_dir()).is_err());
    }

    #[test]
    fn rejects_short_key() {
        assert!(decode_key("c2hvcnQ=", "test").is_err());
    }
}
