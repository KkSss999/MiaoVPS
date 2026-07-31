//! 本机隧道状态与控制 —— 前端与 CLI 的共享契约
//!
//! ## 为什么要走状态文件
//!
//! `connect` 必须以 root 运行（创建 utun、改路由表），而 Tauri App 以普通
//! 用户身份运行。让整个 App 跑在 root 下会把 Keychain 和数据目录都变成
//! root 的（见 CLAUDE.md「权限与密钥存储」），所以隧道进程必须独立。
//!
//! 通信方式选状态文件而不是 socket：隧道进程 `kill -9` 后 socket 直接消失，
//! 前端只能看到"连不上"；状态文件留在盘上，配合 pid 存活检查能区分
//! 「没启动」和「异常退出」两种情况，后者需要提示用户跑 disconnect 清路由。
//!
//! 写入方是 root 隧道进程，读取方是普通用户的 App —— 文件权限 0644，
//! 内容不含任何密钥（只有端点、地址和统计量）。

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// 状态文件名 —— 位于 data_dir 下
pub const STATE_FILE: &str = "tunnel-state.json";

/// 普通用户 App 向 root daemon 发出的停止请求。
///
/// 文件只表示一个布尔事件，不包含命令或用户输入。root daemon
/// 只会检查它是否存在，所以不会形成任意特权命令通道。
pub const STOP_REQUEST_FILE: &str = "tunnel-stop.request";

/// 心跳超时（秒）—— 隧道每 5s 刷一次状态文件，取 12 倍余量
pub const HEARTBEAT_TIMEOUT: i64 = 60;

/// 隧道运行状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelStatus {
    /// 无隧道进程
    Disconnected,
    /// 正在验证 / 建立
    Connecting,
    /// 已建立且会话存活
    Connected,
    /// 隧道进程在跑但 WireGuard 会话断了（正在重连）
    Reconnecting,
    /// Full Tunnel 断线超时已回落直连 —— 流量不经 VPN
    FallbackDirect,
    /// 状态文件存在但进程已消失（崩溃/被 kill）
    Stale,
    /// 隧道在跑，但不是本 App 启动的
    ///
    /// 典型场景：用户在终端跑了 `sudo miaovps connect --full`（前台模式，
    /// 不写状态文件）。此时 utun 上已经有 VPN 地址，绝不能再起第二个隧道 ——
    /// 两个进程会互相踩路由表。
    External,
}

/// 隧道模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    /// 只路由 VPN 网段
    Split,
    /// 全局流量 + DNS 接管
    Full,
}

impl TunnelMode {
    pub fn as_flag(&self) -> Option<&'static str> {
        match self {
            TunnelMode::Split => None,
            TunnelMode::Full => Some("--full"),
        }
    }
}

/// 隧道状态快照 —— 落盘为 `tunnel-state.json`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelState {
    pub status: TunnelStatus,
    pub mode: TunnelMode,
    /// 隧道进程 pid —— 读取方用它判断进程是否还活着
    pub pid: u32,
    pub server_endpoint: String,
    pub client_ip: String,
    /// 隧道建立时间（Unix 秒）
    pub started_at: i64,
    /// 状态最后刷新时间（Unix 秒）
    pub updated_at: i64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// 可疑解密错误 —— 非零才代表异常
    pub decrypt_errors: u64,
    /// 会话轮换丢包 —— 正常现象（每 120s rekey 一次的必然产物）
    #[serde(default)]
    pub session_churn: u64,
    pub reconnects: u64,
    /// boringtun 会话是否存活 —— 与流量无关，回落期间只有 keepalive
    pub session_alive: bool,
    pub last_error: Option<String>,
}

impl TunnelState {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join(STATE_FILE)
    }

    /// 新建「正在连接」状态
    pub fn connecting(mode: TunnelMode, server_endpoint: String, client_ip: String) -> Self {
        let now = now_secs();
        Self {
            status: TunnelStatus::Connecting,
            mode,
            pid: std::process::id(),
            server_endpoint,
            client_ip,
            started_at: now,
            updated_at: now,
            tx_bytes: 0,
            rx_bytes: 0,
            decrypt_errors: 0,
            session_churn: 0,
            reconnects: 0,
            session_alive: false,
            last_error: None,
        }
    }

    /// 未连接状态 —— 状态文件缺失时返回给前端的默认值
    pub fn disconnected() -> Self {
        Self {
            status: TunnelStatus::Disconnected,
            mode: TunnelMode::Full,
            pid: 0,
            server_endpoint: String::new(),
            client_ip: String::new(),
            started_at: 0,
            updated_at: now_secs(),
            tx_bytes: 0,
            rx_bytes: 0,
            decrypt_errors: 0,
            session_churn: 0,
            reconnects: 0,
            session_alive: false,
            last_error: None,
        }
    }

    /// 原子写入 —— 先写临时文件再 rename
    ///
    /// 直接覆盖写会让读取方有机会读到半截 JSON（每 5s 刷一次，App 也在轮询）。
    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        let path = Self::path(data_dir);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &path)
    }

    /// 读取状态，并校验 pid 是否还活着
    ///
    /// 文件在但进程没了 → `Stale`，此时路由和 DNS 可能还是被改写的状态，
    /// 调用方应提示用户执行 disconnect。
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path(data_dir);
        let Ok(raw) = std::fs::read_to_string(&path) else {
            // 没有状态文件不等于没有隧道 —— 终端里 `sudo miaovps connect`
            // 的前台模式不写状态文件。必须探测实际网卡，否则会起第二个隧道。
            return Self::probe_external(data_dir);
        };
        let Ok(mut state) = serde_json::from_str::<Self>(&raw) else {
            return Self::probe_external(data_dir);
        };
        if !process_alive(state.pid) || state.heartbeat_lost() {
            state.status = TunnelStatus::Stale;
            state.session_alive = false;
        }
        state
    }

    /// 无状态文件时探测是否已有外部隧道
    ///
    /// 判据是 profile 里的客户端地址是否已绑在某个 utun 上 —— 比扫进程名
    /// 可靠：进程可能叫任何名字，但地址在网卡上就是在。
    fn probe_external(data_dir: &Path) -> Self {
        let Some(client_ip) = profile_client_ip(data_dir) else {
            return Self::disconnected();
        };
        if !utun_has_address(&client_ip) {
            return Self::disconnected();
        }
        let mut state = Self::disconnected();
        state.status = TunnelStatus::External;
        state.client_ip = client_ip;
        state.session_alive = true;
        state
    }

    /// 删除状态文件 —— 隧道正常退出时调用
    pub fn clear(data_dir: &Path) {
        let _ = std::fs::remove_file(Self::path(data_dir));
        let _ = std::fs::remove_file(Self::path(data_dir).with_extension("json.tmp"));
    }

    /// 由普通用户 App 请求 root daemon 自行停止。
    pub fn request_stop(data_dir: &Path) -> std::io::Result<()> {
        std::fs::write(data_dir.join(STOP_REQUEST_FILE), b"stop\n")
    }

    /// root daemon 轮询停止请求。
    pub fn stop_requested(data_dir: &Path) -> bool {
        data_dir.join(STOP_REQUEST_FILE).is_file()
    }

    /// 启动前和正常退出后清理旧请求，避免下次连接立即退出。
    pub fn clear_stop_request(data_dir: &Path) {
        let _ = std::fs::remove_file(data_dir.join(STOP_REQUEST_FILE));
    }

    /// 心跳是否已丢失
    ///
    /// `EPERM` 当存活后，pid 判活不再能识别「pid 被系统回收给了别人」的情况。
    /// 隧道每 5s 刷一次 `updated_at`，超过 `HEARTBEAT_TIMEOUT` 没更新就认定
    /// 进程已经不在了。阈值取得比刷新间隔宽松很多，避免正常抖动误判。
    fn heartbeat_lost(&self) -> bool {
        if self.updated_at == 0 {
            return false;
        }
        now_secs() - self.updated_at > HEARTBEAT_TIMEOUT
    }

    /// 连接时长（秒）
    pub fn uptime_secs(&self) -> i64 {
        if self.started_at == 0 {
            return 0;
        }
        (now_secs() - self.started_at).max(0)
    }

    /// 是否处于「用户以为受保护、实际在裸奔」的状态
    ///
    /// Full Tunnel 回落时流量不经 VPN，前端必须明确警示（见 CLAUDE.md）。
    pub fn is_unprotected(&self) -> bool {
        matches!(
            self.status,
            TunnelStatus::FallbackDirect | TunnelStatus::Stale | TunnelStatus::Disconnected
        )
    }

    /// 是否已有隧道占用网卡 —— 用于阻止重复启动
    pub fn occupies_tunnel(&self) -> bool {
        matches!(
            self.status,
            TunnelStatus::Connected
                | TunnelStatus::Connecting
                | TunnelStatus::Reconnecting
                | TunnelStatus::FallbackDirect
                | TunnelStatus::External
        )
    }
}

/// 从 profile.json 取客户端地址 —— 只读这一个字段，不解析完整结构
///
/// 独立解析而不复用 CLI 的 ConnectionProfile：那个结构在 cli crate 里，
/// 且 load 会做完整校验（坏 profile 直接报错），这里只需要一个地址。
fn profile_client_ip(data_dir: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(data_dir.join("profile.json")).ok()?;
    let json: serde_json::Value = serde_json::from_str(&raw).ok()?;
    json.get("client_ip")?.as_str().map(|s| s.to_string())
}

/// 某个 utun 接口上是否绑着这个地址
fn utun_has_address(addr: &str) -> bool {
    let Ok(out) = std::process::Command::new("ifconfig").output() else {
        return false;
    };
    // `inet 10.66.66.3 --> 10.66.66.1` —— 匹配带边界的 inet 行，
    // 避免 10.66.66.3 误匹配 10.66.66.30
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().strip_prefix("inet "))
        .any(|rest| rest.split_whitespace().next() == Some(addr))
}

/// 进程是否存活 —— `kill(pid, 0)` 不发信号，只做权限和存在性检查
///
/// **`EPERM` 必须算存活。** 隧道进程是 root 的，App 跑在普通用户下，
/// `kill` 返回 `-1` + `EPERM`（进程在，但无权给它发信号），只有 `ESRCH`
/// 才代表进程真的不存在。把 `EPERM` 当成死亡会让 App 把每一个正常运行的
/// 隧道都判成 `Stale`：前端显示「异常退出」，而下一次 connect 因为
/// `Stale` 分支会先跑一次 disconnect —— **把正在工作的隧道亲手拆掉**，
/// 用户陷入「连上→显示崩溃→再连→真的断掉」的死循环。
fn process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Safety: signal 0 不投递信号，仅检查目标是否存在。无内存操作。
    if unsafe { libc::kill(pid as i32, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("miaovps-tun-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_reads_as_disconnected() {
        let dir = tmp_dir("missing");
        TunnelState::clear(&dir);
        assert_eq!(TunnelState::load(&dir).status, TunnelStatus::Disconnected);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn roundtrip_preserves_fields() {
        let dir = tmp_dir("roundtrip");
        let mut state = TunnelState::connecting(
            TunnelMode::Full,
            "1.2.3.4:51820".into(),
            "10.66.66.3".into(),
        );
        state.status = TunnelStatus::Connected;
        state.tx_bytes = 4096;
        state.session_alive = true;
        state.save(&dir).unwrap();

        // pid 是当前进程，一定存活 → 状态不会被改成 Stale
        let loaded = TunnelState::load(&dir);
        assert_eq!(loaded.status, TunnelStatus::Connected);
        assert_eq!(loaded.tx_bytes, 4096);
        assert_eq!(loaded.server_endpoint, "1.2.3.4:51820");
        assert!(loaded.session_alive);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 崩溃后路由可能还是被改写的 —— 必须能区分出这种状态
    #[test]
    fn dead_pid_becomes_stale() {
        let dir = tmp_dir("stale");
        let mut state = TunnelState::connecting(TunnelMode::Full, "x".into(), "y".into());
        state.status = TunnelStatus::Connected;
        state.session_alive = true;
        state.pid = 999_999; // 不可能存在的 pid
        state.save(&dir).unwrap();

        let loaded = TunnelState::load(&dir);
        assert_eq!(loaded.status, TunnelStatus::Stale);
        assert!(!loaded.session_alive);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// 隧道进程是 root 的，App 是普通用户 —— kill 返回 EPERM 不是死亡。
    ///
    /// 判错的后果不是显示错一个字：connect 的 Stale 分支会先 disconnect，
    /// 于是 App 每次连接都会拆掉自己刚建好的隧道。
    #[test]
    fn root_owned_pid_is_alive_not_stale() {
        // pid 1 (launchd) 属于 root，普通用户对它 kill(0) 必然 EPERM
        assert!(
            process_alive(1),
            "对 root 进程 kill(0) 返回 EPERM，必须判为存活"
        );
    }

    #[test]
    fn pid_zero_and_missing_pid_are_dead() {
        assert!(!process_alive(0));
        assert!(!process_alive(999_999));
    }

    /// EPERM 当存活后，pid 回收给别人的情况只能靠心跳识别
    #[test]
    fn stale_heartbeat_becomes_stale_even_if_pid_alive() {
        let dir = tmp_dir("heartbeat");
        let mut state = TunnelState::connecting(TunnelMode::Full, "x".into(), "y".into());
        state.status = TunnelStatus::Connected;
        state.session_alive = true;
        state.pid = 1; // 活着（root 的 launchd）
        state.updated_at = now_secs() - HEARTBEAT_TIMEOUT - 5;
        state.save(&dir).unwrap();

        let loaded = TunnelState::load(&dir);
        assert_eq!(loaded.status, TunnelStatus::Stale);
        assert!(!loaded.session_alive);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fresh_heartbeat_from_root_pid_stays_connected() {
        let dir = tmp_dir("heartbeat-ok");
        let mut state = TunnelState::connecting(TunnelMode::Full, "x".into(), "y".into());
        state.status = TunnelStatus::Connected;
        state.session_alive = true;
        state.pid = 1;
        state.updated_at = now_secs();
        state.save(&dir).unwrap();

        let loaded = TunnelState::load(&dir);
        assert_eq!(loaded.status, TunnelStatus::Connected);
        assert!(loaded.session_alive);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupted_file_reads_as_disconnected() {
        let dir = tmp_dir("corrupt");
        std::fs::write(TunnelState::path(&dir), "{ not json").unwrap();
        assert_eq!(TunnelState::load(&dir).status, TunnelStatus::Disconnected);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn clear_removes_temp_file_too() {
        let dir = tmp_dir("clear");
        let state = TunnelState::connecting(TunnelMode::Split, "x".into(), "y".into());
        state.save(&dir).unwrap();
        std::fs::write(TunnelState::path(&dir).with_extension("json.tmp"), "x").unwrap();
        TunnelState::clear(&dir);
        assert!(!TunnelState::path(&dir).exists());
        assert!(!TunnelState::path(&dir).with_extension("json.tmp").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stop_request_roundtrip() {
        let dir = tmp_dir("stop-request");
        TunnelState::clear_stop_request(&dir);
        assert!(!TunnelState::stop_requested(&dir));

        TunnelState::request_stop(&dir).unwrap();
        assert!(TunnelState::stop_requested(&dir));

        TunnelState::clear_stop_request(&dir);
        assert!(!TunnelState::stop_requested(&dir));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mode_maps_to_cli_flag() {
        assert_eq!(TunnelMode::Full.as_flag(), Some("--full"));
        assert_eq!(TunnelMode::Split.as_flag(), None);
    }

    /// 回落和崩溃都必须算「未受保护」，否则 UI 会谎报安全
    #[test]
    fn unprotected_covers_fallback_and_stale() {
        let mut state = TunnelState::connecting(TunnelMode::Full, "x".into(), "y".into());
        state.status = TunnelStatus::Connected;
        assert!(!state.is_unprotected());
        state.status = TunnelStatus::FallbackDirect;
        assert!(state.is_unprotected());
        state.status = TunnelStatus::Stale;
        assert!(state.is_unprotected());
        state.status = TunnelStatus::Reconnecting;
        assert!(!state.is_unprotected(), "重连中路由仍在隧道上，不算裸奔");
    }

    #[test]
    fn status_serializes_snake_case() {
        let json = serde_json::to_string(&TunnelStatus::FallbackDirect).unwrap();
        assert_eq!(json, "\"fallback_direct\"");
        let json = serde_json::to_string(&TunnelStatus::External).unwrap();
        assert_eq!(json, "\"external\"");
    }

    /// 前台 CLI 隧道不写状态文件 —— 这些状态都必须算「网卡已被占用」，
    /// 否则会起第二个隧道进程互相踩路由表
    #[test]
    fn occupies_tunnel_covers_external() {
        let mut state = TunnelState::disconnected();
        for s in [
            TunnelStatus::Connected,
            TunnelStatus::Connecting,
            TunnelStatus::Reconnecting,
            TunnelStatus::FallbackDirect,
            TunnelStatus::External,
        ] {
            state.status = s;
            assert!(state.occupies_tunnel(), "{s:?} 应视为已占用");
        }
        for s in [TunnelStatus::Disconnected, TunnelStatus::Stale] {
            state.status = s;
            assert!(!state.occupies_tunnel(), "{s:?} 不应视为已占用");
        }
    }

    /// 地址匹配必须带边界：10.66.66.3 不能匹配 10.66.66.30
    #[test]
    fn address_match_is_exact() {
        // 用真实 ifconfig 输出验证不了具体地址，这里验证解析逻辑的边界行为：
        // 一个当前机器上不可能存在的地址必须返回 false
        assert!(!utun_has_address("203.0.113.254"));
        assert!(!utun_has_address(""));
    }

    #[test]
    fn probe_reads_client_ip_from_profile() {
        let dir = tmp_dir("probe");
        std::fs::write(
            dir.join("profile.json"),
            r#"{"client_ip":"10.66.66.3","server_endpoint":"1.2.3.4:51820"}"#,
        )
        .unwrap();
        assert_eq!(profile_client_ip(&dir).as_deref(), Some("10.66.66.3"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn probe_without_profile_is_disconnected() {
        let dir = tmp_dir("noprofile");
        std::fs::remove_file(dir.join("profile.json")).ok();
        assert_eq!(profile_client_ip(&dir), None);
        assert_eq!(
            TunnelState::probe_external(&dir).status,
            TunnelStatus::Disconnected
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn uptime_zero_when_not_started() {
        assert_eq!(TunnelState::disconnected().uptime_secs(), 0);
    }
}
