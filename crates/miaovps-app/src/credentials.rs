//! SSH 凭据文件存储
//!
//! 开发阶段：凭据明文存入 ~/.miaovps/credentials/<server_id>.json (0600)
//! 与 profile.json 策略相同 —— sudo 下也可见，不依赖 Keychain。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerCredential {
    Password { password: String },
    PrivateKey { key_path: String, passphrase: Option<String> },
}

impl ServerCredential {
    pub fn save(&self, cred_dir: &Path, server_id: &str) -> Result<String, CredError> {
        std::fs::create_dir_all(cred_dir)?;
        let path = cred_dir.join(format!("{server_id}.json"));
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, &json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(path.to_string_lossy().to_string())
    }

    pub fn load(cred_dir: &Path, server_id: &str) -> Result<Self, CredError> {
        let path = cred_dir.join(format!("{server_id}.json"));
        let json = std::fs::read_to_string(&path)
            .map_err(|_| CredError::NotFound(server_id.to_string()))?;
        Ok(serde_json::from_str(&json)?)
    }

    pub fn path(cred_dir: &Path, server_id: &str) -> PathBuf {
        cred_dir.join(format!("{server_id}.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("miaovps-cred-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn password_roundtrip() {
        let dir = tmp_dir("pw");
        let cred = ServerCredential::Password { password: "s3cret".into() };
        cred.save(&dir, "srv-1").unwrap();

        match ServerCredential::load(&dir, "srv-1").unwrap() {
            ServerCredential::Password { password } => assert_eq!(password, "s3cret"),
            other => panic!("类型不对: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn private_key_roundtrip_keeps_passphrase() {
        let dir = tmp_dir("key");
        let cred = ServerCredential::PrivateKey {
            key_path: "~/.ssh/id_ed25519".into(),
            passphrase: Some("pp".into()),
        };
        cred.save(&dir, "srv-2").unwrap();

        match ServerCredential::load(&dir, "srv-2").unwrap() {
            ServerCredential::PrivateKey { key_path, passphrase } => {
                assert_eq!(key_path, "~/.ssh/id_ed25519");
                assert_eq!(passphrase.as_deref(), Some("pp"));
            }
            other => panic!("类型不对: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 凭据是明文的，权限必须是 0600 —— 同机其他用户不能读
    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("perm");
        ServerCredential::Password { password: "x".into() }
            .save(&dir, "srv-3")
            .unwrap();

        let path = ServerCredential::path(&dir, "srv-3");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "凭据文件权限应为 0600");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_credential_is_not_found_not_io_error() {
        let dir = tmp_dir("missing");
        std::fs::create_dir_all(&dir).unwrap();
        let err = ServerCredential::load(&dir, "nope").unwrap_err();
        assert!(matches!(err, CredError::NotFound(_)), "实际: {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CredError {
    #[error("凭据文件未找到: {0}")]
    NotFound(String),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("序列化错误: {0}")]
    Serde(#[from] serde_json::Error),
}
