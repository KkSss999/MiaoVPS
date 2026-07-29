//! 系统 Keychain 安全存储
//!
//! 封装 keyring crate，用于存储 SSH 私钥、WireGuard 私钥等敏感凭据。
//! macOS: Keychain Services
//! Windows: Credential Manager
//! Linux: libsecret / keyutils

use keyring::Entry;

const SERVICE_NAME: &str = "miaovps";

/// 安全存储条目
pub struct SecureStore {
    entry: Entry,
}

impl SecureStore {
    /// 创建新的安全存储条目
    /// `key` 为标识符（如 server_id、device_id）
    pub fn new(key: &str) -> Result<Self, KeychainError> {
        Ok(Self {
            entry: Entry::new(SERVICE_NAME, key)?,
        })
    }

    /// 存储凭据
    pub fn set(&self, value: &str) -> Result<(), KeychainError> {
        self.entry.set_secret(value.as_bytes())?;
        Ok(())
    }

    /// 读取凭据
    pub fn get(&self) -> Result<String, KeychainError> {
        let secret = self.entry.get_secret()?;
        Ok(String::from_utf8_lossy(&secret).to_string())
    }

    /// 删除凭据
    pub fn delete(&self) -> Result<(), KeychainError> {
        self.entry.delete_credential()?;
        Ok(())
    }
}

/// SSH 凭据类型
pub enum SshCredential {
    Password(String),
    PrivateKey { key_content: String, passphrase: Option<String> },
}

impl SshCredential {
    /// 存储到 Keychain，返回引用标识
    pub fn store(&self, key: &str) -> Result<String, KeychainError> {
        let store = SecureStore::new(key)?;
        let json = serde_json::to_string(&self.serialize())?;
        store.set(&json)?;
        Ok(key.to_string())
    }

    /// 从 Keychain 读取
    pub fn load(key: &str) -> Result<Self, KeychainError> {
        let store = SecureStore::new(key)?;
        let json = store.get()?;
        Self::deserialize(&json)
    }

    fn serialize(&self) -> serde_json::Value {
        match self {
            SshCredential::Password(pwd) => serde_json::json!({
                "type": "password",
                "password": pwd
            }),
            SshCredential::PrivateKey { key_content, passphrase } => serde_json::json!({
                "type": "private_key",
                "key_content": key_content,
                "passphrase": passphrase
            }),
        }
    }

    fn deserialize(json: &str) -> Result<Self, KeychainError> {
        let v: serde_json::Value = serde_json::from_str(json)?;
        match v["type"].as_str().unwrap_or("") {
            "password" => Ok(SshCredential::Password(
                v["password"].as_str().unwrap_or("").into()
            )),
            "private_key" => Ok(SshCredential::PrivateKey {
                key_content: v["key_content"].as_str().unwrap_or("").into(),
                passphrase: v["passphrase"].as_str().map(|s| s.into()),
            }),
            _ => Err(KeychainError::InvalidFormat),
        }
    }
}

/// WireGuard 私钥存储
pub struct WgKeyStore;

impl WgKeyStore {
    /// 存储 WireGuard 私钥，返回引用标识
    pub fn store(device_id: &str, private_key: &str) -> Result<String, KeychainError> {
        let key = format!("wg-key-{}", device_id);
        let store = SecureStore::new(&key)?;
        store.set(private_key)?;
        Ok(key)
    }

    /// 读取 WireGuard 私钥
    pub fn load(key_ref: &str) -> Result<String, KeychainError> {
        let store = SecureStore::new(key_ref)?;
        store.get()
    }

    /// 删除 WireGuard 私钥
    pub fn delete(key_ref: &str) -> Result<(), KeychainError> {
        let store = SecureStore::new(key_ref)?;
        store.delete()
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  错误
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("Keychain error: {0}")]
    Keyring(#[from] keyring::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Invalid credential format")]
    InvalidFormat,
}
