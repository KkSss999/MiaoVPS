//! 本机连接配置 —— 把「已部署的设备」变成「本机可连接的隧道」
//!
//! CLI 里这一步要用户手工复制私钥跑 `profile init`。前端必须自动完成，
//! 否则「一键连接」名不副实。
//!
//! 结构与 `crates/miaovps-cli/src/profile.rs` 的 `ConnectionProfile`
//! 逐字段对齐 —— 两边读写同一个 `profile.json`，字段名错一个就连不上。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DEFAULT_MTU: u16 = 1380;
const DEFAULT_NETMASK: &str = "255.255.255.0";

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("配置读写失败: {0}")]
    Io(#[from] std::io::Error),
    #[error("配置格式错误: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
}

/// 与 CLI 共用的 profile.json 结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionProfile {
    pub client_private_key: String,
    pub client_public_key: String,
    pub server_public_key: String,
    pub server_endpoint: String,
    pub client_ip: String,
    pub peer_ip: String,
    #[serde(default = "default_netmask")]
    pub netmask: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub dns: Vec<String>,
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_netmask() -> String {
    DEFAULT_NETMASK.to_string()
}

/// 给前端的概要 —— 不含私钥
#[derive(Debug, Clone, Serialize)]
pub struct ProfileSummary {
    pub exists: bool,
    pub server_endpoint: String,
    pub client_ip: String,
    pub peer_ip: String,
    pub client_public_key: String,
    pub mtu: u16,
    pub dns: Vec<String>,
    /// 公私钥是否自洽 —— 不自洽时服务端会静默丢弃握手包
    pub key_consistent: bool,
}

impl ProfileSummary {
    pub fn missing() -> Self {
        Self {
            exists: false,
            server_endpoint: String::new(),
            client_ip: String::new(),
            peer_ip: String::new(),
            client_public_key: String::new(),
            mtu: DEFAULT_MTU,
            dns: Vec::new(),
            key_consistent: false,
        }
    }
}

impl ConnectionProfile {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("profile.json")
    }

    pub fn load(data_dir: &Path) -> Result<Self, ProfileError> {
        let raw = std::fs::read_to_string(Self::path(data_dir))?;
        Ok(serde_json::from_str(&raw)?)
    }

    /// 写盘，权限 0600 —— 文件里有客户端私钥
    pub fn save(&self, data_dir: &Path) -> Result<PathBuf, ProfileError> {
        let path = Self::path(data_dir);
        std::fs::write(&path, serde_json::to_vec_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(path)
    }

    pub fn summary(&self) -> ProfileSummary {
        ProfileSummary {
            exists: true,
            server_endpoint: self.server_endpoint.clone(),
            client_ip: self.client_ip.clone(),
            peer_ip: self.peer_ip.clone(),
            client_public_key: self.client_public_key.clone(),
            mtu: self.mtu,
            dns: self.dns.clone(),
            key_consistent: self.keys_consistent(),
        }
    }

    /// 校验记录的公钥确实由私钥推导得出
    fn keys_consistent(&self) -> bool {
        match derive_public_key(&self.client_private_key) {
            Ok(derived) => derived == self.client_public_key,
            Err(_) => false,
        }
    }
}

/// 从 base64 私钥推导公钥
pub fn derive_public_key(private_key_b64: &str) -> Result<String, ProfileError> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use x25519_dalek::{PublicKey, StaticSecret};

    let bytes = STANDARD
        .decode(private_key_b64.trim())
        .map_err(|e| ProfileError::Invalid(format!("私钥 base64 解码失败: {e}")))?;
    if bytes.len() != 32 {
        return Err(ProfileError::Invalid(format!(
            "私钥长度错误: 期望 32 字节，实际 {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    let sk: StaticSecret = key.into();
    Ok(STANDARD.encode(PublicKey::from(&sk).as_bytes()))
}

/// VPN 网段的网关地址 —— 取 `10.66.66.0/24` 的 `.1`
///
/// 服务端 wg0 固定用网段首个可用地址（见 provisioner 的配置模板）。
pub fn gateway_of(vpn_cidr: &str) -> Result<String, ProfileError> {
    let base = vpn_cidr.split('/').next().unwrap_or(vpn_cidr);
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() != 4 {
        return Err(ProfileError::Invalid(format!("网段格式错误: {vpn_cidr}")));
    }
    Ok(format!("{}.{}.{}.1", parts[0], parts[1], parts[2]))
}

/// 从 `10.66.66.3/32` 取出裸地址
pub fn strip_mask(addr: &str) -> &str {
    addr.split('/').next().unwrap_or(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIV: &str = "[REDACTED_WIREGUARD_PRIVATE_KEY]=";
    const PUB: &str = "855O3DODAuSGbktWe8BAjNUCQx1Tsuo7mqW/tXR0VHg=";

    fn sample() -> ConnectionProfile {
        ConnectionProfile {
            client_private_key: PRIV.into(),
            client_public_key: PUB.into(),
            server_public_key: "fRp9SCOP2pu780jn15LbDFbxPwJJleAjODXjzcOgZFs=".into(),
            server_endpoint: "203.0.113.10:51820".into(),
            client_ip: "10.66.66.3".into(),
            peer_ip: "10.66.66.1".into(),
            netmask: DEFAULT_NETMASK.into(),
            mtu: DEFAULT_MTU,
            dns: vec!["1.1.1.1".into()],
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("miaovps-prof-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 这个公私钥对是真机验证过的，推导必须一致
    #[test]
    fn derives_known_public_key() {
        assert_eq!(derive_public_key(PRIV).unwrap(), PUB);
    }

    #[test]
    fn rejects_short_key() {
        assert!(derive_public_key("c2hvcnQ=").is_err());
    }

    #[test]
    fn rejects_non_base64() {
        assert!(derive_public_key("!!!not base64!!!").is_err());
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let dir = tmp("roundtrip");
        sample().save(&dir).unwrap();
        let loaded = ConnectionProfile::load(&dir).unwrap();
        assert_eq!(loaded.client_private_key, PRIV);
        assert_eq!(loaded.client_ip, "10.66.66.3");
        assert_eq!(loaded.mtu, 1380);
        assert_eq!(loaded.dns, vec!["1.1.1.1"]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("perm");
        let path = sample().save(&dir).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "profile.json 含私钥，必须 0600");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn summary_omits_private_key() {
        let s = sample().summary();
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains(PRIV), "概要不能泄漏私钥");
        assert!(s.key_consistent);
        assert!(s.exists);
    }

    /// 不自洽的 profile 会表现为「握手超时」，极难排查 —— 必须能检出
    #[test]
    fn detects_inconsistent_keys() {
        let mut p = sample();
        p.client_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into();
        assert!(!p.summary().key_consistent);
    }

    #[test]
    fn gateway_is_first_host_of_cidr() {
        assert_eq!(gateway_of("10.66.66.0/24").unwrap(), "10.66.66.1");
        assert_eq!(gateway_of("10.7.0.0/24").unwrap(), "10.7.0.1");
        assert!(gateway_of("garbage").is_err());
    }

    #[test]
    fn strips_cidr_mask() {
        assert_eq!(strip_mask("10.66.66.3/32"), "10.66.66.3");
        assert_eq!(strip_mask("10.66.66.3"), "10.66.66.3");
    }

    #[test]
    fn missing_summary_is_marked_absent() {
        let s = ProfileSummary::missing();
        assert!(!s.exists);
        assert!(!s.key_consistent);
        assert_eq!(s.mtu, 1380);
    }

    #[test]
    fn load_missing_file_errors() {
        let dir = tmp("absent");
        std::fs::remove_file(ConnectionProfile::path(&dir)).ok();
        assert!(ConnectionProfile::load(&dir).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
