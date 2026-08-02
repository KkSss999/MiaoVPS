//! 本地 SQLite 存储层
//!
//! 管理 servers、devices、deployments 表的迁移和 CRUD 操作。
//! 敏感凭据不存明文字段，只存 Keychain 引用标识。

pub mod keychain;

use miaovps_core::{Device, DeviceType, Server, ServerStatus, ServiceStatus, WireGuardNode};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::path::Path;
use tracing::info;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  数据库初始化
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// 打开或创建数据库，自动运行迁移
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        info!("数据库已打开并迁移完成");
        Ok(db)
    }

    /// 在内存中创建数据库（测试用）
    pub async fn open_in_memory() -> Result<Self, StorageError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS servers (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                host            TEXT NOT NULL,
                ssh_port        INTEGER NOT NULL DEFAULT 22,
                ssh_user        TEXT NOT NULL DEFAULT 'root',
                auth_type       TEXT NOT NULL DEFAULT 'password',
                credential_ref  TEXT,
                os_name         TEXT,
                os_version      TEXT,
                architecture    TEXT,
                public_ipv4     TEXT,
                status          TEXT NOT NULL DEFAULT 'added',
                vpn_cidr        TEXT,
                wg_port         INTEGER,
                server_pubkey   TEXT,
                dns             TEXT,
                mtu             INTEGER,
                created_at      INTEGER NOT NULL,
                updated_at      INTEGER NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS devices (
                id                  TEXT PRIMARY KEY,
                server_id           TEXT NOT NULL,
                name                TEXT NOT NULL,
                device_type         TEXT NOT NULL DEFAULT 'other',
                public_key          TEXT NOT NULL,
                private_key_ref     TEXT,
                vpn_address         TEXT NOT NULL,
                enabled             INTEGER NOT NULL DEFAULT 1,
                latest_handshake_at INTEGER,
                rx_bytes            INTEGER NOT NULL DEFAULT 0,
                tx_bytes            INTEGER NOT NULL DEFAULT 0,
                created_at          INTEGER NOT NULL,
                FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS deployments (
                id              TEXT PRIMARY KEY,
                server_id       TEXT NOT NULL,
                status          TEXT NOT NULL DEFAULT 'pending',
                current_step    TEXT,
                backup_path     TEXT,
                failure_reason  TEXT,
                started_at      INTEGER NOT NULL,
                completed_at    INTEGER,
                FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS wg_nodes (
                server_id           TEXT PRIMARY KEY,
                interface_name      TEXT NOT NULL DEFAULT 'wg0',
                listen_port         INTEGER NOT NULL,
                vpn_cidr            TEXT NOT NULL,
                server_public_key   TEXT NOT NULL,
                dns                 TEXT NOT NULL,
                mtu                 INTEGER,
                ipv6_enabled        INTEGER NOT NULL DEFAULT 0,
                service_status      TEXT NOT NULL DEFAULT 'unknown',
                FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Server CRUD
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl Database {
    pub async fn insert_server(&self, server: &Server) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO servers (id, name, host, ssh_port, ssh_user, auth_type, credential_ref,
                                 os_name, os_version, architecture, public_ipv4, status,
                                 created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
        )
        .bind(&server.id)
        .bind(&server.name)
        .bind(&server.host)
        .bind(server.ssh_port as i64)
        .bind(&server.ssh_user)
        .bind(serde_json::to_string(&server.auth_type).unwrap_or_default())
        .bind(&server.credential_ref)
        .bind(&server.os_name)
        .bind(&server.os_version)
        .bind(&server.architecture)
        .bind(&server.public_ipv4)
        .bind(serde_json::to_string(&server.status).unwrap_or_default())
        .bind(server.created_at)
        .bind(server.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_server(&self, id: &str) -> Result<Option<Server>, StorageError> {
        let row = sqlx::query("SELECT * FROM servers WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(row_to_server(&r)?)),
            None => Ok(None),
        }
    }

    pub async fn list_servers(&self) -> Result<Vec<Server>, StorageError> {
        let rows = sqlx::query("SELECT * FROM servers ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;

        rows.iter().map(row_to_server).collect()
    }

    pub async fn update_server_status(
        &self,
        id: &str,
        status: &ServerStatus,
    ) -> Result<(), StorageError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        sqlx::query("UPDATE servers SET status = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(serde_json::to_string(status).unwrap_or_default())
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_server(&self, server: &Server) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            UPDATE servers SET name = ?1, host = ?2, ssh_port = ?3, ssh_user = ?4,
                               auth_type = ?5, credential_ref = ?6, os_name = ?7,
                               os_version = ?8, architecture = ?9, public_ipv4 = ?10,
                               status = ?11, updated_at = ?12
            WHERE id = ?13
            "#,
        )
        .bind(&server.name)
        .bind(&server.host)
        .bind(server.ssh_port as i64)
        .bind(&server.ssh_user)
        .bind(serde_json::to_string(&server.auth_type).unwrap_or_default())
        .bind(&server.credential_ref)
        .bind(&server.os_name)
        .bind(&server.os_version)
        .bind(&server.architecture)
        .bind(&server.public_ipv4)
        .bind(serde_json::to_string(&server.status).unwrap_or_default())
        .bind(server.updated_at)
        .bind(&server.id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_server(&self, id: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM servers WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  WireGuardNode CRUD
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl Database {
    pub async fn upsert_wg_node(&self, node: &WireGuardNode) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO wg_nodes (server_id, interface_name, listen_port, vpn_cidr,
                                  server_public_key, dns, mtu, ipv6_enabled, service_status)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(server_id) DO UPDATE SET
                interface_name    = excluded.interface_name,
                listen_port       = excluded.listen_port,
                vpn_cidr          = excluded.vpn_cidr,
                server_public_key = excluded.server_public_key,
                dns               = excluded.dns,
                mtu               = excluded.mtu,
                ipv6_enabled      = excluded.ipv6_enabled,
                service_status    = excluded.service_status
            "#,
        )
        .bind(&node.server_id)
        .bind(&node.interface_name)
        .bind(node.listen_port as i64)
        .bind(&node.vpn_cidr)
        .bind(&node.server_public_key)
        .bind(serde_json::to_string(&node.dns).unwrap_or_default())
        .bind(node.mtu.map(|m| m as i64))
        .bind(node.ipv6_enabled as i64)
        .bind(match &node.service_status {
            ServiceStatus::Running => "running",
            ServiceStatus::Stopped => "stopped",
            ServiceStatus::Unknown => "unknown",
        })
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_wg_node(
        &self,
        server_id: &str,
    ) -> Result<Option<WireGuardNode>, StorageError> {
        let row = sqlx::query("SELECT * FROM wg_nodes WHERE server_id = ?1")
            .bind(server_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(row_to_wg_node(&r)?)),
            None => Ok(None),
        }
    }
}

impl Database {
    pub async fn insert_device(&self, device: &Device) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO devices (id, server_id, name, device_type, public_key, private_key_ref,
                                 vpn_address, enabled, latest_handshake_at, rx_bytes, tx_bytes, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
        )
        .bind(&device.id)
        .bind(&device.server_id)
        .bind(&device.name)
        .bind(device.device_type.as_str())
        .bind(&device.public_key)
        .bind(&device.private_key_ref)
        .bind(&device.vpn_address)
        .bind(device.enabled as i64)
        .bind(device.latest_handshake_at)
        .bind(device.rx_bytes as i64)
        .bind(device.tx_bytes as i64)
        .bind(device.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_devices(&self, server_id: &str) -> Result<Vec<Device>, StorageError> {
        let rows =
            sqlx::query("SELECT * FROM devices WHERE server_id = ?1 ORDER BY created_at ASC")
                .bind(server_id)
                .fetch_all(&self.pool)
                .await?;

        rows.iter().map(row_to_device).collect()
    }

    pub async fn get_device(&self, id: &str) -> Result<Option<Device>, StorageError> {
        let row = sqlx::query("SELECT * FROM devices WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => Ok(Some(row_to_device(&r)?)),
            None => Ok(None),
        }
    }

    pub async fn update_device_enabled(&self, id: &str, enabled: bool) -> Result<(), StorageError> {
        sqlx::query("UPDATE devices SET enabled = ?1 WHERE id = ?2")
            .bind(enabled as i64)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 按服务端 `wg show dump` 的真实值刷新设备运行状态。
    ///
    /// 握手为 0 时存为 NULL，避免把 Unix epoch 当成一次有效连接；字节数是
    /// WireGuard 自启动以来的累计值，直接覆盖而非累加。
    pub async fn update_device_runtime(
        &self,
        id: &str,
        latest_handshake_at: Option<i64>,
        rx_bytes: u64,
        tx_bytes: u64,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE devices SET latest_handshake_at = ?1, rx_bytes = ?2, tx_bytes = ?3 WHERE id = ?4",
        )
        .bind(latest_handshake_at)
        .bind(rx_bytes as i64)
        .bind(tx_bytes as i64)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete_device(&self, id: &str) -> Result<(), StorageError> {
        sqlx::query("DELETE FROM devices WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Deployment CRUD
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

impl Database {
    pub async fn insert_deployment(
        &self,
        id: &str,
        server_id: &str,
        started_at: i64,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO deployments (id, server_id, status, started_at) VALUES (?1, ?2, 'in_progress', ?3)",
        )
        .bind(id)
        .bind(server_id)
        .bind(started_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_deployment_status(
        &self,
        id: &str,
        status: &str,
        failure_reason: Option<&str>,
    ) -> Result<(), StorageError> {
        let completed_at = if status == "success" || status == "failed" || status == "rolled_back" {
            Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
            )
        } else {
            None
        };
        sqlx::query(
            "UPDATE deployments SET status = ?1, failure_reason = ?2, completed_at = ?3 WHERE id = ?4",
        )
        .bind(status)
        .bind(failure_reason)
        .bind(completed_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  行转换
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn row_to_wg_node(r: &sqlx::sqlite::SqliteRow) -> Result<WireGuardNode, StorageError> {
    use sqlx::Row;
    let dns_str: String = r.try_get("dns")?;
    let dns: Vec<String> = serde_json::from_str(&dns_str).unwrap_or_default();
    let service_status = match r.try_get::<&str, _>("service_status").unwrap_or("unknown") {
        "running" => ServiceStatus::Running,
        "stopped" => ServiceStatus::Stopped,
        _ => ServiceStatus::Unknown,
    };
    Ok(WireGuardNode {
        server_id: r.try_get("server_id")?,
        interface_name: r.try_get("interface_name")?,
        listen_port: r.try_get::<i64, _>("listen_port")? as u16,
        vpn_cidr: r.try_get("vpn_cidr")?,
        server_public_key: r.try_get("server_public_key")?,
        dns,
        mtu: r.try_get::<Option<i64>, _>("mtu")?.map(|m| m as u16),
        ipv6_enabled: r.try_get::<i64, _>("ipv6_enabled")? != 0,
        service_status,
    })
}

fn row_to_server(r: &sqlx::sqlite::SqliteRow) -> Result<Server, StorageError> {
    let auth_str: String = r.try_get("auth_type")?;
    let auth_type: miaovps_core::SshAuthType =
        serde_json::from_str(&auth_str).unwrap_or(miaovps_core::SshAuthType::Password);

    let status_str: String = r.try_get("status")?;
    let status: ServerStatus = serde_json::from_str(&status_str).unwrap_or(ServerStatus::Added);

    Ok(Server {
        id: r.try_get("id")?,
        name: r.try_get("name")?,
        host: r.try_get("host")?,
        ssh_port: r.try_get::<i64, _>("ssh_port")? as u16,
        ssh_user: r.try_get("ssh_user")?,
        auth_type,
        credential_ref: r.try_get("credential_ref")?,
        os_name: r.try_get("os_name")?,
        os_version: r.try_get("os_version")?,
        architecture: r.try_get("architecture")?,
        public_ipv4: r.try_get("public_ipv4")?,
        status,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

fn row_to_device(r: &sqlx::sqlite::SqliteRow) -> Result<Device, StorageError> {
    let dtype_str: String = r.try_get("device_type")?;
    let device_type = match dtype_str.as_str() {
        "Mac" => DeviceType::Mac,
        "Windows" => DeviceType::Windows,
        "iPhone" => DeviceType::IPhone,
        "Android" => DeviceType::Android,
        "Linux" => DeviceType::Linux,
        _ => DeviceType::Other,
    };

    Ok(Device {
        id: r.try_get("id")?,
        server_id: r.try_get("server_id")?,
        name: r.try_get("name")?,
        device_type,
        public_key: r.try_get("public_key")?,
        private_key_ref: r.try_get("private_key_ref")?,
        vpn_address: r.try_get("vpn_address")?,
        enabled: r.try_get::<i64, _>("enabled")? != 0,
        latest_handshake_at: r.try_get("latest_handshake_at")?,
        rx_bytes: r.try_get::<i64, _>("rx_bytes")? as u64,
        tx_bytes: r.try_get::<i64, _>("tx_bytes")? as u64,
        created_at: r.try_get("created_at")?,
    })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  错误
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Not found: {0}")]
    NotFound(String),
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;
    use miaovps_core::SshAuthType;

    fn test_server() -> Server {
        Server {
            id: "srv-1".into(),
            name: "Tokyo VPS".into(),
            host: "1.2.3.4".into(),
            ssh_port: 22,
            ssh_user: "root".into(),
            auth_type: SshAuthType::Password,
            credential_ref: None,
            os_name: Some("Ubuntu".into()),
            os_version: Some("24.04".into()),
            architecture: Some("x86_64".into()),
            public_ipv4: Some("1.2.3.4".into()),
            status: ServerStatus::Added,
            created_at: 1000,
            updated_at: 1000,
        }
    }

    fn test_device() -> Device {
        Device {
            id: "dev-1".into(),
            server_id: "srv-1".into(),
            name: "MacBook Pro".into(),
            device_type: DeviceType::Mac,
            public_key: "pubkey123".into(),
            private_key_ref: Some("keychain-ref-1".into()),
            vpn_address: "10.66.66.2".into(),
            enabled: true,
            latest_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
            created_at: 1000,
        }
    }

    #[tokio::test]
    async fn test_insert_and_get_server() {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_server(&test_server()).await.unwrap();

        let srv = db.get_server("srv-1").await.unwrap().unwrap();
        assert_eq!(srv.name, "Tokyo VPS");
        assert_eq!(srv.ssh_port, 22);
    }

    #[tokio::test]
    async fn test_list_servers() {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_server(&test_server()).await.unwrap();

        let mut srv2 = test_server();
        srv2.id = "srv-2".into();
        srv2.name = "Singapore VPS".into();
        db.insert_server(&srv2).await.unwrap();

        let servers = db.list_servers().await.unwrap();
        assert_eq!(servers.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_server_cascades_devices() {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_server(&test_server()).await.unwrap();
        db.insert_device(&test_device()).await.unwrap();

        db.delete_server("srv-1").await.unwrap();
        let devices = db.list_devices("srv-1").await.unwrap();
        assert!(devices.is_empty());
    }

    #[tokio::test]
    async fn update_server_persists_inspect_results() {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_server(&test_server()).await.unwrap();

        let mut srv = db.get_server("srv-1").await.unwrap().unwrap();
        srv.os_name = Some("Ubuntu 24.04".into());
        srv.public_ipv4 = Some("9.9.9.9".into());
        srv.status = ServerStatus::Online;
        srv.updated_at = 2000;
        db.update_server(&srv).await.unwrap();

        let reloaded = db.get_server("srv-1").await.unwrap().unwrap();
        assert_eq!(reloaded.os_name.as_deref(), Some("Ubuntu 24.04"));
        assert_eq!(reloaded.public_ipv4.as_deref(), Some("9.9.9.9"));
        assert_eq!(reloaded.status, ServerStatus::Online);
        assert_eq!(reloaded.updated_at, 2000);
    }

    /// 重复部署必须覆盖而不是报主键冲突 —— 服务端重新生成密钥后公钥会变
    #[tokio::test]
    async fn upsert_wg_node_overwrites_on_redeploy() {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_server(&test_server()).await.unwrap();

        let mut node = WireGuardNode::new(
            "srv-1".into(),
            51820,
            "10.66.66.0/24".into(),
            "pubkey-v1".into(),
            vec!["1.1.1.1".into()],
        );
        db.upsert_wg_node(&node).await.unwrap();

        node.server_public_key = "pubkey-v2".into();
        node.service_status = ServiceStatus::Running;
        db.upsert_wg_node(&node).await.unwrap();

        let got = db.get_wg_node("srv-1").await.unwrap().unwrap();
        assert_eq!(got.server_public_key, "pubkey-v2");
        assert_eq!(got.service_status, ServiceStatus::Running);
        assert_eq!(got.dns, vec!["1.1.1.1".to_string()]);
        assert_eq!(got.mtu, Some(1380));
    }

    #[tokio::test]
    async fn wg_node_absent_before_deploy() {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_server(&test_server()).await.unwrap();
        assert!(db.get_wg_node("srv-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_device_crud() {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_server(&test_server()).await.unwrap();
        db.insert_device(&test_device()).await.unwrap();

        let devices = db.list_devices("srv-1").await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "MacBook Pro");

        db.update_device_enabled("dev-1", false).await.unwrap();
        let dev = db.get_device("dev-1").await.unwrap().unwrap();
        assert!(!dev.enabled);

        db.delete_device("dev-1").await.unwrap();
        assert!(db.get_device("dev-1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn device_runtime_is_persisted_from_wireguard_counters() {
        let db = Database::open_in_memory().await.unwrap();
        db.insert_server(&test_server()).await.unwrap();
        db.insert_device(&test_device()).await.unwrap();

        db.update_device_runtime("dev-1", Some(1_785_495_944), 1_449_785, 1_068_600)
            .await
            .unwrap();

        let device = db.get_device("dev-1").await.unwrap().unwrap();
        assert_eq!(device.latest_handshake_at, Some(1_785_495_944));
        assert_eq!(device.rx_bytes, 1_449_785);
        assert_eq!(device.tx_bytes, 1_068_600);
    }
}
