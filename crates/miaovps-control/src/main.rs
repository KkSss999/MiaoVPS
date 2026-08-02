//! MiaoVPS 私有控制面。
//!
//! 仅提供桌面应用调用的 HTTPS JSON API：账号登录、会话、节点同步与新设备
//! 注册。它不代理 VPN 流量，也不保存任何客户端 WireGuard 私钥。

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{FromRef, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use std::{
    collections::HashSet,
    net::Ipv4Addr,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt},
    process::Command,
};
use tracing::info;
use uuid::Uuid;

const SESSION_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    wg_config_path: PathBuf,
    wg_interface: String,
}

impl FromRef<AppState> for SqlitePool {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

#[derive(Debug, Serialize)]
struct ApiError {
    code: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: "bad_request",
            message: message.into(),
        }
    }

    fn unauthorized() -> Self {
        Self {
            code: "unauthorized",
            message: "登录已失效，请重新登录".into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            code: "internal",
            message: format!("服务端错误: {error}"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match self.code {
            "bad_request" => StatusCode::BAD_REQUEST,
            "unauthorized" => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    expires_at: i64,
    user: UserDto,
}

#[derive(Serialize)]
struct UserDto {
    id: String,
    username: String,
}

#[derive(Serialize)]
struct SyncResponse {
    user: UserDto,
    nodes: Vec<NodeDto>,
    devices: Vec<DeviceDto>,
}

#[derive(Serialize)]
struct NodeDto {
    id: String,
    name: String,
    endpoint: String,
    listen_port: u16,
    vpn_cidr: String,
    gateway_ip: String,
    server_public_key: String,
    dns: Vec<String>,
    mtu: u16,
}

#[derive(Serialize)]
struct DeviceDto {
    id: String,
    node_id: String,
    name: String,
    device_type: String,
    public_key: String,
    vpn_address: String,
    created_at: i64,
}

#[derive(Deserialize)]
struct EnrollDeviceRequest {
    node_id: String,
    name: String,
    device_type: String,
    public_key: String,
}

#[derive(Serialize)]
struct EnrollDeviceResponse {
    device: DeviceDto,
    node: NodeDto,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("无法初始化 TLS 加密提供者"))?;
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    let config = Config::from_env()?;
    let db = open_database(&config.db_path).await?;
    migrate(&db).await?;
    if args.get(1).map(String::as_str) == Some("seed-user") {
        let username = args
            .get(2)
            .ok_or_else(|| anyhow::anyhow!("用法: seed-user <username>"))?;
        seed_user_from_stdin(&db, username).await?;
        seed_node(&db, &config).await?;
        import_existing_peers(&db, &config).await?;
        return Ok(());
    }

    seed_node(&db, &config).await?;
    import_existing_peers(&db, &config).await?;

    let state = AppState {
        db,
        wg_config_path: config.wg_config_path,
        wg_interface: config.wg_interface,
    };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/sync", get(sync))
        .route("/v1/devices", post(enroll_device))
        .with_state(state);

    let tls =
        axum_server::tls_rustls::RustlsConfig::from_pem_file(&config.cert_path, &config.key_path)
            .await?;
    info!(address = %config.listen_addr, "MiaoVPS 私有控制面已启动");
    axum_server::bind_rustls(config.listen_addr, tls)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

struct Config {
    db_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    wg_config_path: PathBuf,
    wg_interface: String,
    listen_addr: SocketAddr,
    node_name: String,
    endpoint: String,
    listen_port: u16,
    vpn_cidr: String,
    gateway_ip: String,
    server_public_key: String,
    dns: Vec<String>,
    mtu: u16,
}

impl Config {
    fn from_env() -> anyhow::Result<Self> {
        let required = |name: &str| -> anyhow::Result<String> {
            std::env::var(name).map_err(|_| anyhow::anyhow!("缺少环境变量 {name}"))
        };
        Ok(Self {
            db_path: std::env::var("MIAOVPS_CONTROL_DB")
                .unwrap_or_else(|_| "/var/lib/miaovps-control/control.db".into())
                .into(),
            cert_path: required("MIAOVPS_CONTROL_CERT")?.into(),
            key_path: required("MIAOVPS_CONTROL_KEY")?.into(),
            wg_config_path: std::env::var("MIAOVPS_WG_CONFIG")
                .unwrap_or_else(|_| "/etc/wireguard/wg0.conf".into())
                .into(),
            wg_interface: std::env::var("MIAOVPS_WG_INTERFACE").unwrap_or_else(|_| "wg0".into()),
            listen_addr: std::env::var("MIAOVPS_CONTROL_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8443".into())
                .parse()?,
            node_name: std::env::var("MIAOVPS_NODE_NAME").unwrap_or_else(|_| "我的 VPS".into()),
            endpoint: required("MIAOVPS_NODE_ENDPOINT")?,
            listen_port: std::env::var("MIAOVPS_WG_PORT")
                .unwrap_or_else(|_| "51820".into())
                .parse()?,
            vpn_cidr: std::env::var("MIAOVPS_WG_CIDR").unwrap_or_else(|_| "10.66.66.0/24".into()),
            gateway_ip: std::env::var("MIAOVPS_WG_GATEWAY").unwrap_or_else(|_| "10.66.66.1".into()),
            server_public_key: required("MIAOVPS_WG_SERVER_PUBLIC_KEY")?,
            dns: std::env::var("MIAOVPS_WG_DNS")
                .unwrap_or_else(|_| "1.1.1.1,8.8.8.8".into())
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            mtu: std::env::var("MIAOVPS_WG_MTU")
                .unwrap_or_else(|_| "1380".into())
                .parse()?,
        })
    }
}

async fn open_database(path: &Path) -> anyhow::Result<SqlitePool> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    Ok(SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?)
}

async fn migrate(db: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query("PRAGMA foreign_keys = ON").execute(db).await?;
    for statement in [
        "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)",
        "CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, endpoint TEXT NOT NULL, listen_port INTEGER NOT NULL, vpn_cidr TEXT NOT NULL, gateway_ip TEXT NOT NULL, server_public_key TEXT NOT NULL, dns_json TEXT NOT NULL, mtu INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)",
        "CREATE TABLE IF NOT EXISTS devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, node_id TEXT NOT NULL, name TEXT NOT NULL, device_type TEXT NOT NULL, public_key TEXT NOT NULL UNIQUE, vpn_address TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE)",
    ] {
        sqlx::query(statement).execute(db).await?;
    }
    Ok(())
}

async fn seed_node(db: &SqlitePool, config: &Config) -> anyhow::Result<()> {
    let owner =
        sqlx::query_scalar::<_, String>("SELECT id FROM users ORDER BY created_at ASC LIMIT 1")
            .fetch_optional(db)
            .await?;
    let Some(user_id) = owner else { return Ok(()) };
    let node_id = "node-primary";
    sqlx::query("INSERT INTO nodes (id, user_id, name, endpoint, listen_port, vpn_cidr, gateway_ip, server_public_key, dns_json, mtu) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id, name=excluded.name, endpoint=excluded.endpoint, listen_port=excluded.listen_port, vpn_cidr=excluded.vpn_cidr, gateway_ip=excluded.gateway_ip, server_public_key=excluded.server_public_key, dns_json=excluded.dns_json, mtu=excluded.mtu")
        .bind(node_id).bind(user_id).bind(&config.node_name).bind(&config.endpoint).bind(config.listen_port as i64).bind(&config.vpn_cidr).bind(&config.gateway_ip).bind(&config.server_public_key).bind(serde_json::to_string(&config.dns)?).bind(config.mtu as i64).execute(db).await?;
    Ok(())
}

/// 把控制面启用前就存在的 peer 纳入只含公钥的云端清单。私钥仍只保留在
/// 原设备，因此这里绝不会尝试导出、保存或重建它们。
async fn import_existing_peers(db: &SqlitePool, config: &Config) -> anyhow::Result<()> {
    let Some(user_id) =
        sqlx::query_scalar::<_, String>("SELECT id FROM users ORDER BY created_at ASC LIMIT 1")
            .fetch_optional(db)
            .await?
    else {
        return Ok(());
    };

    let output = Command::new("wg")
        .args(["show", &config.wg_interface, "allowed-ips"])
        .output()
        .await?;
    if !output.status.success() {
        anyhow::bail!("无法读取 WireGuard 运行状态");
    }

    for (index, line) in String::from_utf8_lossy(&output.stdout).lines().enumerate() {
        let mut columns = line.split_whitespace();
        let Some(public_key) = columns.next() else {
            continue;
        };
        let Some(allowed_ips) = columns.next() else {
            continue;
        };
        let Some(vpn_address) = allowed_ips.split(',').find_map(|ip| ip.strip_suffix("/32")) else {
            continue;
        };
        let fingerprint = &hash_token(public_key)[..24];
        let id = format!("imported-{fingerprint}");
        sqlx::query("INSERT OR IGNORE INTO devices (id, user_id, node_id, name, device_type, public_key, vpn_address, created_at) VALUES (?, ?, 'node-primary', ?, 'other', ?, ?, ?)")
            .bind(id)
            .bind(&user_id)
            .bind(format!("已迁移设备 {}", index + 1))
            .bind(public_key)
            .bind(vpn_address)
            .bind(now())
            .execute(db)
            .await?;
    }
    Ok(())
}

async fn seed_user_from_stdin(db: &SqlitePool, username: &str) -> anyhow::Result<()> {
    let mut line = String::new();
    tokio::io::BufReader::new(tokio::io::stdin())
        .read_line(&mut line)
        .await?;
    let password = line.trim_end();
    anyhow::ensure!(!password.is_empty(), "密码不能为空");
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("无法生成密码哈希: {e}"))?
        .to_string();
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash")
        .bind(id).bind(username).bind(hash).bind(now()).execute(db).await?;
    info!(username, "已写入单用户账号（仅保存 Argon2id 哈希）");
    Ok(())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    if req.username.trim().is_empty() || req.password.is_empty() {
        return Err(ApiError::bad_request("账号和密码不能为空"));
    }
    let row = sqlx::query_as::<_, (String, String, String)>(
        "SELECT id, username, password_hash FROM users WHERE username = ?",
    )
    .bind(req.username.trim())
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::internal)?;
    let Some((id, username, password_hash)) = row else {
        return Err(ApiError::unauthorized());
    };
    let parsed = PasswordHash::new(&password_hash).map_err(ApiError::internal)?;
    if Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed)
        .is_err()
    {
        return Err(ApiError::unauthorized());
    }
    let token = random_token();
    let expires_at = now() + SESSION_TTL_SECONDS;
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
        .bind(hash_token(&token))
        .bind(&id)
        .bind(expires_at)
        .execute(&state.db)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(LoginResponse {
        access_token: token,
        expires_at,
        user: UserDto { id, username },
    }))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let token = bearer_token(&headers).ok_or_else(ApiError::unauthorized)?;
    sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
        .bind(hash_token(token))
        .execute(&state.db)
        .await
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn sync(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<SyncResponse>> {
    let user = authenticated_user(&state.db, &headers).await?;
    let nodes = load_nodes(&state.db, &user.id).await?;
    let devices = load_devices(&state.db, &user.id).await?;
    Ok(Json(SyncResponse {
        user,
        nodes,
        devices,
    }))
}

async fn enroll_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<EnrollDeviceRequest>,
) -> ApiResult<Json<EnrollDeviceResponse>> {
    let user = authenticated_user(&state.db, &headers).await?;
    validate_peer(&req)?;
    let node = load_node(&state.db, &user.id, &req.node_id).await?;
    if let Some(existing) = load_device_by_key(&state.db, &user.id, &req.public_key).await? {
        return Ok(Json(EnrollDeviceResponse {
            device: existing,
            node,
        }));
    }
    let device_id = Uuid::new_v4().to_string();
    let vpn_address = allocate_vpn_address(&state, &node).await?;
    let allowed_ip = format!("{vpn_address}/32");

    let output = Command::new("wg")
        .args([
            "set",
            &state.wg_interface,
            "peer",
            &req.public_key,
            "allowed-ips",
            &allowed_ip,
        ])
        .output()
        .await
        .map_err(ApiError::internal)?;
    if !output.status.success() {
        return Err(ApiError {
            code: "internal",
            message: "WireGuard peer 注册失败".into(),
        });
    }
    let entry = format!(
        "\n# miaovps-device:{device_id}\n[Peer]\nPublicKey = {}\nAllowedIPs = {allowed_ip}\n",
        req.public_key
    );
    let persist_result = async {
        let mut file = tokio::fs::OpenOptions::new()
            .append(true)
            .open(&state.wg_config_path)
            .await?;
        file.write_all(entry.as_bytes()).await
    }
    .await;
    if let Err(error) = persist_result {
        let _ = Command::new("wg")
            .args([
                "set",
                &state.wg_interface,
                "peer",
                &req.public_key,
                "remove",
            ])
            .output()
            .await;
        return Err(ApiError::internal(error));
    }
    let device = DeviceDto {
        id: device_id.clone(),
        node_id: node.id.clone(),
        name: req.name.trim().into(),
        device_type: req.device_type,
        public_key: req.public_key,
        vpn_address,
        created_at: now(),
    };
    sqlx::query("INSERT INTO devices (id, user_id, node_id, name, device_type, public_key, vpn_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&device.id).bind(&user.id).bind(&device.node_id).bind(&device.name).bind(&device.device_type).bind(&device.public_key).bind(&device.vpn_address).bind(device.created_at).execute(&state.db).await.map_err(ApiError::internal)?;
    Ok(Json(EnrollDeviceResponse { device, node }))
}

async fn authenticated_user(db: &SqlitePool, headers: &HeaderMap) -> ApiResult<UserDto> {
    let token = bearer_token(headers).ok_or_else(ApiError::unauthorized)?;
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(now())
        .execute(db)
        .await
        .map_err(ApiError::internal)?;
    let user = sqlx::query_as::<_, (String, String)>("SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?")
        .bind(hash_token(token)).bind(now()).fetch_optional(db).await.map_err(ApiError::internal)?;
    user.map(|(id, username)| UserDto { id, username })
        .ok_or_else(ApiError::unauthorized)
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn hash_token(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
fn random_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn validate_peer(req: &EnrollDeviceRequest) -> ApiResult<()> {
    if req.name.trim().is_empty() || req.name.len() > 80 || req.device_type.len() > 32 {
        return Err(ApiError::bad_request("设备名称或类型无效"));
    }
    if req.public_key.len() != 44
        || !req.public_key.ends_with('=')
        || STANDARD
            .decode(req.public_key.as_bytes())
            .map_or(true, |bytes| bytes.len() != 32)
    {
        return Err(ApiError::bad_request("WireGuard 公钥格式无效"));
    }
    Ok(())
}

async fn load_nodes(db: &SqlitePool, user_id: &str) -> ApiResult<Vec<NodeDto>> {
    sqlx::query_as::<_, (String,String,String,i64,String,String,String,String,i64)>("SELECT id, name, endpoint, listen_port, vpn_cidr, gateway_ip, server_public_key, dns_json, mtu FROM nodes WHERE user_id = ? ORDER BY name").bind(user_id).fetch_all(db).await.map_err(ApiError::internal)?.into_iter().map(node_from_row).collect()
}
async fn load_node(db: &SqlitePool, user_id: &str, node_id: &str) -> ApiResult<NodeDto> {
    sqlx::query_as::<_, (String,String,String,i64,String,String,String,String,i64)>("SELECT id, name, endpoint, listen_port, vpn_cidr, gateway_ip, server_public_key, dns_json, mtu FROM nodes WHERE user_id = ? AND id = ?").bind(user_id).bind(node_id).fetch_optional(db).await.map_err(ApiError::internal)?.ok_or_else(ApiError::unauthorized).and_then(node_from_row)
}
fn node_from_row(
    row: (
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        i64,
    ),
) -> ApiResult<NodeDto> {
    let (id, name, endpoint, listen_port, vpn_cidr, gateway_ip, server_public_key, dns_json, mtu) =
        row;
    let dns = serde_json::from_str(&dns_json).map_err(ApiError::internal)?;
    Ok(NodeDto {
        id,
        name,
        endpoint,
        listen_port: listen_port as u16,
        vpn_cidr,
        gateway_ip,
        server_public_key,
        dns,
        mtu: mtu as u16,
    })
}
async fn load_devices(db: &SqlitePool, user_id: &str) -> ApiResult<Vec<DeviceDto>> {
    sqlx::query_as::<_, (String,String,String,String,String,String,i64)>("SELECT id, node_id, name, device_type, public_key, vpn_address, created_at FROM devices WHERE user_id = ? ORDER BY created_at").bind(user_id).fetch_all(db).await.map_err(ApiError::internal)?.into_iter().map(|(id,node_id,name,device_type,public_key,vpn_address,created_at)| Ok(DeviceDto{id,node_id,name,device_type,public_key,vpn_address,created_at})).collect()
}
async fn load_device_by_key(
    db: &SqlitePool,
    user_id: &str,
    public_key: &str,
) -> ApiResult<Option<DeviceDto>> {
    sqlx::query_as::<_, (String,String,String,String,String,String,i64)>("SELECT id, node_id, name, device_type, public_key, vpn_address, created_at FROM devices WHERE user_id = ? AND public_key = ?")
        .bind(user_id)
        .bind(public_key)
        .fetch_optional(db)
        .await
        .map_err(ApiError::internal)
        .map(|row| row.map(|(id,node_id,name,device_type,public_key,vpn_address,created_at)| DeviceDto{id,node_id,name,device_type,public_key,vpn_address,created_at}))
}

async fn allocate_vpn_address(state: &AppState, node: &NodeDto) -> ApiResult<String> {
    let (network, prefix) = parse_ipv4_cidr(&node.vpn_cidr)?;
    let usable = 1u32.checked_shl((32 - prefix) as u32).unwrap_or(0);
    if usable < 4 {
        return Err(ApiError::bad_request("VPN 子网没有可分配的客户端地址"));
    }

    let mut used: HashSet<String> =
        sqlx::query_scalar("SELECT vpn_address FROM devices WHERE node_id = ?")
            .bind(&node.id)
            .fetch_all(&state.db)
            .await
            .map_err(ApiError::internal)?
            .into_iter()
            .collect();
    used.insert(node.gateway_ip.clone());

    // 数据库可能尚未收录控制面启用前的 peer；实时状态才是地址占用的最终事实。
    let output = Command::new("wg")
        .args(["show", &state.wg_interface, "allowed-ips"])
        .output()
        .await
        .map_err(ApiError::internal)?;
    if !output.status.success() {
        return Err(ApiError {
            code: "internal",
            message: "无法读取 WireGuard 地址分配状态".into(),
        });
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        for cidr in line
            .split_whitespace()
            .skip(1)
            .flat_map(|field| field.split(','))
        {
            if let Some(ip) = cidr.strip_suffix("/32") {
                used.insert(ip.to_owned());
            }
        }
    }

    for host in 1..(usable - 1) {
        let candidate = Ipv4Addr::from(u32::from(network) + host).to_string();
        if !used.contains(&candidate) {
            return Ok(candidate);
        }
    }
    Err(ApiError {
        code: "internal",
        message: "VPN 地址已用尽".into(),
    })
}

fn parse_ipv4_cidr(cidr: &str) -> ApiResult<(Ipv4Addr, u8)> {
    let (ip, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| ApiError::bad_request("VPN 子网格式无效"))?;
    let ip = ip
        .parse::<Ipv4Addr>()
        .map_err(|_| ApiError::bad_request("VPN 子网格式无效"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| ApiError::bad_request("VPN 子网格式无效"))?;
    if prefix > 30 {
        return Err(ApiError::bad_request("VPN 子网必须至少包含两个可用地址"));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok((Ipv4Addr::from(u32::from(ip) & mask), prefix))
}
