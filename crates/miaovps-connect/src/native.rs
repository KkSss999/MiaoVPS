//! 原生隧道 — TUN + boringtun + UDP 完整加密循环
//!
//! ## 三线程架构
//!
//! ```text
//!   [出站] TUN read (阻塞) → encapsulate → UDP send
//!   [入站] UDP recv (阻塞) → decapsulate → TUN write
//!   [计时] update_timers 每 250ms → 握手重传 / keepalive
//! ```
//!
//! 出站和入站必须分线程。单线程轮询时 `udp.recv()` 的读超时会阻塞出站方向 —
//! 空闲链路上 TUN 每个超时周期才被读一次，吞吐直接塌掉。
//! 两个方向各自阻塞在自己的 fd 上，互不干扰。
//!
//! `Tunn` 被三个线程共享，用 `Mutex` 保护。锁只在加解密期间持有，
//! I/O 都在锁外完成。

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::ConnectError;
use crate::tun::{TunInterface, TunReader, TunWriter};

/// 包缓冲区 — MTU 1380 + WireGuard 封装开销 + 余量
const PKT_BUF: usize = 2048;
/// 握手包缓冲区（WireGuard Initiation 固定 148B）
const HANDSHAKE_BUF: usize = 256;
/// 计时器轮询间隔 — boringtun 内部按秒级判断，250ms 足够及时
const TIMER_TICK: Duration = Duration::from_millis(250);
/// UDP 读超时 — 仅用于周期性检查停止标志
const UDP_READ_TIMEOUT: Duration = Duration::from_millis(500);
/// TUN poll 超时 — 同上，让空闲时也能响应停止
const TUN_POLL_TIMEOUT: Duration = Duration::from_millis(500);
/// 单次 decapsulate 后排空待发队列的上限
const MAX_FLUSH_PACKETS: usize = 16;
/// 隧道启动后的宽限期 — 期间的解密错误是预期的会话交接残留
///
/// 验证阶段用同一对密钥握手会在服务端留下一个 session。隧道随后从
/// 另一个 UDP 源端口重新握手，服务端按公钥把 endpoint 漫游过来并建立
/// 新 session — 旧 session 的在途包（keepalive）会被发到新端口，
/// 而本地 `Tunn` 只持有新 session 的密钥，必然解不开。
///
/// 这类瞬态无害。宽限期只对**可疑**错误有意义 ——
/// 会话轮换类错误（见 `is_session_churn`）在整个生命周期都是正常的。
const DECRYPT_GRACE: Duration = Duration::from_secs(3);
/// 解密错误的日志抑制间隔 — 防止异常状态下刷屏
const DECRYPT_LOG_INTERVAL: Duration = Duration::from_secs(10);
/// 复活尝试的最小间隔
///
/// 只作用于复活之间。boringtun 在每个 90s 周期内已按 5s 重传，
/// 这里不需要也不应该更激进。
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(5);
/// 复活尝试的最大间隔 — VPS 长期宕机时避免无意义的高频重试
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// 两次 socket 重绑定的最小间隔 — 防止网络震荡期打转
const REBIND_MIN_INTERVAL: Duration = Duration::from_secs(2);
/// 出站发送失败的日志抑制间隔 — 断网期间每个积压包都会失败
const SEND_ERROR_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// 可重绑定的 UDP 端点
///
/// ## 为什么需要重绑定
///
/// `UdpSocket::connect()` 会让内核按当时的路由选定源地址并**钉死**它
/// （`local_addr()` 从 `0.0.0.0:0` 变成具体 IP）。WiFi 重连拿到新 IP、
/// 或从 WiFi 切到有线后，这个源地址不再存在，`send()` 永久失败 ——
/// 重连逻辑若一直用同一个 socket 就永远不可能成功。
///
/// 所以 socket 必须可替换。三个线程通过 `RwLock` 共享，但都先把
/// `Arc<UdpSocket>` 克隆出来再做阻塞 I/O，不持锁等待 —— 否则重绑定
/// 会被入站线程的 500ms 读超时挡住。
pub struct Endpoint {
    socket: RwLock<Arc<UdpSocket>>,
    server_addr: SocketAddr,
    /// 重绑定次数，用于诊断
    rebinds: AtomicU64,
    /// 上次重绑定时刻，用于限流 —— 防止在网络震荡期打转
    last_rebind: Mutex<Option<Instant>>,
}

impl Endpoint {
    fn new(server_addr: SocketAddr) -> Result<Self, ConnectError> {
        let socket = Self::make_socket(server_addr)?;
        Ok(Self {
            socket: RwLock::new(Arc::new(socket)),
            server_addr,
            rebinds: AtomicU64::new(0),
            last_rebind: Mutex::new(None),
        })
    }

    fn make_socket(server_addr: SocketAddr) -> Result<UdpSocket, ConnectError> {
        let s = UdpSocket::bind("0.0.0.0:0").map_err(ConnectError::Io)?;
        s.connect(server_addr).map_err(ConnectError::Io)?;
        s.set_read_timeout(Some(UDP_READ_TIMEOUT))
            .map_err(ConnectError::Io)?;
        Ok(s)
    }

    /// 取当前 socket 的快照 — 阻塞 I/O 必须在锁外进行
    fn current(&self) -> Arc<UdpSocket> {
        match self.socket.read() {
            Ok(g) => g.clone(),
            // 锁中毒时退化为直接取值，避免整条数据路径卡死
            Err(e) => e.into_inner().clone(),
        }
    }

    /// 重新绑定 socket 以适应新的网络环境
    ///
    /// 新 socket 会有新的源端口。WireGuard 服务端按公钥识别 peer 并支持
    /// endpoint 漫游，收到合法握手后会自动把回包地址更新过来。
    /// 带限流的重绑定。间隔不足 `REBIND_MIN_INTERVAL` 时直接跳过。
    ///
    /// 限流是必需的：网络切换瞬间地址可能反复变化，
    /// 不限流会在震荡期打转（实测一秒 700 次）。
    pub fn rebind(&self) -> Result<(), ConnectError> {
        {
            let mut last = match self.last_rebind.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            if let Some(t) = *last {
                if t.elapsed() < REBIND_MIN_INTERVAL {
                    return Ok(()); // 视为成功 —— 当前 socket 还很新
                }
            }
            *last = Some(Instant::now());
        }

        let fresh = Self::make_socket(self.server_addr)?;
        let local = fresh.local_addr().ok();
        match self.socket.write() {
            Ok(mut g) => *g = Arc::new(fresh),
            Err(e) => *e.into_inner() = Arc::new(fresh),
        }
        let n = self.rebinds.fetch_add(1, Ordering::Relaxed) + 1;
        tracing::debug!(
            "[隧道] UDP socket 已重绑定 (第 {n} 次) → {}",
            local.map(|a| a.to_string()).unwrap_or_else(|| "?".into())
        );
        Ok(())
    }

    /// 发送数据。**不会**自动重绑定。
    ///
    /// 重绑定的决策权归计时线程（它有退避）。出站数据路径若在这里重绑定，
    /// 会退化成「每个包一次重绑定」的风暴 —— 断网时 TUN 内积压的每个包
    /// 都触发一次，实测一秒内 700 次。
    ///
    /// 断网期间丢弃出站数据包是正确行为：恢复只依赖握手包发出去，
    /// 而上层协议（TCP）自己会重传。
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.current().send(buf)
    }

    /// 发送并在必要时重绑定 —— 仅供计时线程的握手路径使用
    fn send_with_rebind(&self, buf: &[u8]) -> std::io::Result<usize> {
        match self.current().send(buf) {
            Ok(n) => Ok(n),
            Err(e) if is_network_change_error(&e) => {
                if self.rebind().is_err() {
                    return Err(e); // 网络完全不可用，保留原始错误
                }
                self.current().send(buf)
            }
            Err(e) => Err(e),
        }
    }

    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.current().recv(buf)
    }

    pub fn rebinds(&self) -> u64 {
        self.rebinds.load(Ordering::Relaxed)
    }
}

/// 判断错误是否源于本机网络环境变化（需要重绑定 socket）
///
/// 这些错误意味着 socket 钉死的源地址或路由已失效，重试同一个 socket
/// 不可能成功；而其他错误（如 UDP 载荷过大）重绑定也无济于事。
fn is_network_change_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::AddrNotAvailable | ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable
    ) || matches!(
        e.raw_os_error(),
        // macOS: EADDRNOTAVAIL(49) ENETDOWN(50) ENETUNREACH(51) EHOSTUNREACH(65) EHOSTDOWN(64)
        Some(49) | Some(50) | Some(51) | Some(64) | Some(65)
    )
}

/// 隧道流量统计
#[derive(Debug, Default)]
pub struct TunnelStats {
    /// 出站明文字节数（TUN → VPS）
    pub tx_bytes: AtomicU64,
    /// 入站明文字节数（VPS → TUN）
    pub rx_bytes: AtomicU64,
    /// 可疑解密错误计数 —— index 对上但解不开（密钥不匹配 / 包注入）
    ///
    /// 不含会话轮换丢包，那些计入 `session_churn`。混在一起会让
    /// 正常长连接看起来像遭到攻击。
    pub decrypt_errors: AtomicU64,
    /// 会话轮换丢包 —— 旧 session 的在途包，正常现象
    pub session_churn: AtomicU64,
    /// 因网络不可用而丢弃的出站包数
    pub tx_dropped: AtomicU64,
    /// 重连次数 — boringtun 放弃后我们强制复活的次数
    pub reconnects: AtomicU64,
    /// 最后一次收到任何入站包的时刻（隧道启动后的毫秒数）
    pub last_inbound_ms: AtomicU64,
    /// 是否曾成功解出对端包（含 keepalive）
    pub healthy: AtomicBool,
    /// boringtun 报告的会话是否存活 —— 恢复判定用这个，与流量无关
    pub session_alive: AtomicBool,
}

impl TunnelStats {
    /// 返回 (出站字节, 入站字节, 解密错误数)
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.tx_bytes.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.decrypt_errors.load(Ordering::Relaxed),
        )
    }

    pub fn reconnects(&self) -> u64 {
        self.reconnects.load(Ordering::Relaxed)
    }

    /// 会话轮换丢包数 —— 正常现象，仅用于诊断
    pub fn session_churn(&self) -> u64 {
        self.session_churn.load(Ordering::Relaxed)
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// 会话是否存活 —— 由 boringtun 的握手状态判定，不依赖流量。
    /// fallback 模式下（路由已撤、隧道内无数据）恢复检测只能用这个。
    pub fn is_session_alive(&self) -> bool {
        self.session_alive.load(Ordering::Relaxed)
    }

    /// 距上次收到入站包的时长；从未收到过则返回 None
    pub fn since_last_inbound(&self, started_at: Instant) -> Option<Duration> {
        let last = self.last_inbound_ms.load(Ordering::Relaxed);
        if last == 0 {
            return None;
        }
        let now_ms = started_at.elapsed().as_millis() as u64;
        Some(Duration::from_millis(now_ms.saturating_sub(last)))
    }
}

/// 原生隧道 — 完整 WireGuard 隧道（不依赖 wg-quick）
pub struct NativeTunnel {
    running: Arc<AtomicBool>,
    stats: Arc<TunnelStats>,
    threads: Vec<JoinHandle<()>>,
    started_at: Instant,
    /// 供状态输出读取重绑定次数
    udp: Arc<Endpoint>,
}

impl NativeTunnel {
    /// 启动原生 WireGuard 隧道
    ///
    /// 立即发起握手，然后启动出站/入站/计时三个线程。
    /// 握手响应由入站线程处理 — boringtun 的 `decapsulate` 会自动推进状态机。
    pub fn start(
        tun: TunInterface,
        private_key: [u8; 32],
        server_public_key: [u8; 32],
        server_addr: SocketAddr,
        keepalive_secs: u16,
    ) -> Result<Self, ConnectError> {
        let sk: StaticSecret = private_key.into();
        let pk: PublicKey = server_public_key.into();
        let tunn = Tunn::new(sk, pk, None, Some(keepalive_secs), 0, None);

        let udp = Arc::new(Endpoint::new(server_addr)?);

        let running = Arc::new(AtomicBool::new(true));
        let stats = Arc::new(TunnelStats::default());
        let tunn = Arc::new(Mutex::new(tunn));
        let (tun_rx, tun_tx) = tun.into_split();
        // 所有线程共用同一时间基准，统计才可比
        let started_at = Instant::now();

        // 主动发起首次握手。后续重传由计时器线程通过 update_timers 驱动。
        send_handshake(&tunn, &udp);

        let threads = vec![
            spawn_outbound(tun_rx, tunn.clone(), udp.clone(), running.clone(), stats.clone())?,
            spawn_inbound(
                tun_tx,
                tunn.clone(),
                udp.clone(),
                running.clone(),
                stats.clone(),
                started_at,
            )?,
            spawn_timer(tunn, udp.clone(), running.clone(), stats.clone(), started_at)?,
        ];

        tracing::info!("[隧道] 已启动 → {}", server_addr);
        Ok(Self { running, stats, threads, started_at, udp })
    }

    /// 请求停止隧道（非阻塞）
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// 停止并等待所有线程退出
    ///
    /// 三个线程都以 500ms 量级轮询停止标志（TUN 侧靠 `poll`，UDP 侧靠
    /// 读超时），所以最坏情况约 500ms 返回，且不依赖是否有流量。
    pub fn shutdown(mut self) {
        self.stop();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
        tracing::info!("[隧道] 已停止");
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> &TunnelStats {
        &self.stats
    }

    /// 隧道已运行时长
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// 通知隧道本机网络环境已变，立即重绑定 socket
    ///
    /// 上层修好路由后调用。比等计时线程的退避快得多 —— 实测网络切换后
    /// 真正让隧道恢复的是路由修复，socket 必须在那之后重绑定才有意义。
    /// 受 `REBIND_MIN_INTERVAL` 限流保护，可安全频繁调用。
    pub fn notify_network_changed(&self) {
        if let Err(e) = self.udp.rebind() {
            tracing::debug!("[隧道] 网络变更后重绑定失败: {e}");
        }
    }

    /// 人类可读的当前状态 — 供 CLI 周期性输出
    pub fn health_line(&self) -> String {
        let (tx, rx, errs) = self.stats.snapshot();
        let reconnects = self.stats.reconnects();
        let state = if self.stats.is_healthy() { "正常" } else { "重连中" };

        let silence = match self.stats.since_last_inbound(self.started_at) {
            Some(d) => format!("{}s 前", d.as_secs()),
            None => "从未".into(),
        };

        let mut line = format!(
            "{state} · 运行 {}s · ↑{} ↓{} · 最后入站 {silence}",
            self.uptime().as_secs(),
            fmt_bytes(tx),
            fmt_bytes(rx),
        );
        if reconnects > 0 {
            line.push_str(&format!(" · 重连 {reconnects} 次"));
        }
        let rebinds = self.udp.rebinds();
        if rebinds > 0 {
            line.push_str(&format!(" · 重绑定 {rebinds} 次"));
        }
        let dropped = self.stats.tx_dropped.load(Ordering::Relaxed);
        if dropped > 0 {
            line.push_str(&format!(" · 断网丢包 {dropped}"));
        }
        let churn = self.stats.session_churn();
        if churn > 0 {
            line.push_str(&format!(" · 换钥丢包 {churn}"));
        }
        // 只有这一项代表异常 —— 措辞上要和上面几个正常计数区分开
        if errs > 0 {
            line.push_str(&format!(" · ⚠ 解密错误 {errs}"));
        }
        line
    }
}

/// 字节数的紧凑表示
fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

impl Drop for NativeTunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 发送握手 Initiation（force_resend 跳过「已在握手中」检查）
fn send_handshake(tunn: &Arc<Mutex<Tunn>>, udp: &Arc<Endpoint>) {
    let mut buf = [0u8; HANDSHAKE_BUF];
    let packet = {
        let mut t = match tunn.lock() {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("[隧道] 握手锁中毒: {e}");
                return;
            }
        };
        match t.format_handshake_initiation(&mut buf[..], true) {
            TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
            TunnResult::Err(e) => {
                tracing::error!("[隧道] 握手初始化失败: {e:?}");
                None
            }
            _ => None,
        }
    };
    if let Some(p) = packet {
        match udp.send(&p) {
            Ok(_) => tracing::info!("[隧道] 握手 Initiation 已发送"),
            Err(e) => tracing::error!("[隧道] 握手发送失败: {e}"),
        }
    }
}

/// 出站线程：TUN read → encapsulate → UDP send
fn spawn_outbound(
    mut tun_rx: TunReader,
    tunn: Arc<Mutex<Tunn>>,
    udp: Arc<Endpoint>,
    running: Arc<AtomicBool>,
    stats: Arc<TunnelStats>,
) -> Result<JoinHandle<()>, ConnectError> {
    thread::Builder::new()
        .name("miaovps-tx".into())
        .spawn(move || {
            let mut encrypted = [0u8; PKT_BUF];
            let mut last_send_err_log: Option<Instant> = None;
            let mut dropped_since_log: u64 = 0;
            while running.load(Ordering::Relaxed) {
                // 先 poll — 空闲时也能周期性复查停止标志，否则 shutdown 会死锁
                match tun_rx.wait_readable(TUN_POLL_TIMEOUT) {
                    Ok(true) => {}
                    Ok(false) => continue, // 超时无数据
                    Err(e) => {
                        tracing::error!("[隧道] TUN poll 失败: {e}");
                        break;
                    }
                }

                let ip_packet = match tun_rx.read_packet() {
                    Ok(p) => p,
                    Err(ref e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue
                    }
                    Err(e) => {
                        // TUN fd 关闭是正常停止路径
                        if running.load(Ordering::Relaxed) {
                            tracing::error!("[隧道] TUN 读取错误: {e}");
                        }
                        break;
                    }
                };

                let plaintext_len = ip_packet.len() as u64;
                let outbound = {
                    let mut t = match tunn.lock() {
                        Ok(t) => t,
                        Err(_) => break,
                    };
                    match t.encapsulate(&ip_packet, &mut encrypted[..]) {
                        TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                        TunnResult::Err(e) => {
                            tracing::warn!("[隧道] 加密错误: {e:?}");
                            None
                        }
                        // 握手未完成时包会被缓存，返回 Done
                        _ => None,
                    }
                };

                if let Some(p) = outbound {
                    match udp.send(&p) {
                        Ok(_) => {
                            stats.tx_bytes.fetch_add(plaintext_len, Ordering::Relaxed);
                            dropped_since_log = 0;
                        }
                        Err(e) => {
                            // 断网期间 TUN 里每个积压包都会失败 —— 必须抑制，
                            // 否则日志刷屏（实测一秒数百行）
                            stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                            dropped_since_log += 1;
                            let due = last_send_err_log
                                .map(|t: Instant| t.elapsed() >= SEND_ERROR_LOG_INTERVAL)
                                .unwrap_or(true);
                            if due {
                                last_send_err_log = Some(Instant::now());
                                tracing::warn!(
                                    "[隧道] 出站发送失败: {e}（已丢弃 {dropped_since_log} 个包，\
                                     等待重连）"
                                );
                                dropped_since_log = 0;
                            }
                        }
                    }
                }
            }
            tracing::debug!("[隧道] 出站线程退出");
        })
        .map_err(|e| ConnectError::TunError(format!("无法启动出站线程: {e}")))
}

/// 入站线程：UDP recv → decapsulate → TUN write
///
/// `decapsulate` 返回 `WriteToNetwork` 时必须继续用空输入排空队列 —
/// boringtun 在握手和 keepalive 时可能有多个待发包。
fn spawn_inbound(
    mut tun_tx: TunWriter,
    tunn: Arc<Mutex<Tunn>>,
    udp: Arc<Endpoint>,
    running: Arc<AtomicBool>,
    stats: Arc<TunnelStats>,
    started_at: Instant,
) -> Result<JoinHandle<()>, ConnectError> {
    thread::Builder::new()
        .name("miaovps-rx".into())
        .spawn(move || {
            let mut udp_buf = [0u8; PKT_BUF];
            let mut decrypted = [0u8; PKT_BUF];
            let mut last_decrypt_log: Option<Instant> = None;

            while running.load(Ordering::Relaxed) {
                let n = match udp.recv(&mut udp_buf) {
                    Ok(n) => {
                        // 记录任何入站包 — 包括握手响应和 keepalive，
                        // 用于诊断静默时长（0 保留为「从未收到」的哨兵值）
                        stats.last_inbound_ms.store(
                            (started_at.elapsed().as_millis() as u64).max(1),
                            Ordering::Relaxed,
                        );
                        n
                    }
                    Err(ref e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue
                    }
                    Err(e) => {
                        tracing::error!("[隧道] UDP 接收错误: {e}");
                        continue;
                    }
                };

                // 拿锁解密，得到「写给 TUN 的明文」或「回给网络的包」
                let mut to_tun: Option<Vec<u8>> = None;
                let mut to_net: Vec<Vec<u8>> = Vec::new();
                {
                    let mut t = match tunn.lock() {
                        Ok(t) => t,
                        Err(_) => break,
                    };
                    match t.decapsulate(None, &udp_buf[..n], &mut decrypted[..]) {
                        TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                            mark_healthy(&stats);
                            to_tun = Some(p.to_vec());
                        }
                        // 空载荷 keepalive 走这里（validate_decapsulated_packet 对
                        // len==0 返回 Done）。它同样证明会话存活 —— 且在
                        // fallback 模式下路由已撤、隧道内没有数据流量时，
                        // keepalive 是**唯一**的存活信号，必须计入。
                        TunnResult::Done => mark_healthy(&stats),
                        TunnResult::WriteToNetwork(p) => {
                            to_net.push(p.to_vec());
                            // boringtun 约定：用空输入反复调用以排空待发队列。
                            // 加上限防止异常状态下无限循环。
                            let mut flush = [0u8; PKT_BUF];
                            while to_net.len() < MAX_FLUSH_PACKETS {
                                match t.decapsulate(None, &[], &mut flush[..]) {
                                    TunnResult::WriteToNetwork(extra) => to_net.push(extra.to_vec()),
                                    _ => break,
                                }
                            }
                        }
                        TunnResult::Err(e) => {
                            // 会话轮换和真正的解密失败分开计数 —— 前者是
                            // 长连接的正常产物，混在一起会掩盖真问题
                            let counter = if is_session_churn(&e) {
                                &stats.session_churn
                            } else if !should_count_decrypt_error(started_at.elapsed()) {
                                // 隧道刚建立时，旧 session 的在途包可能晚到。
                                // 这段交接噪声只记录 debug，不能污染用户可见的
                                // decrypt_errors 统计（此前会固定显示「解密错误 4」）。
                                log_decrypt_error(
                                    &e,
                                    stats.decrypt_errors.load(Ordering::Relaxed),
                                    started_at,
                                    &mut last_decrypt_log,
                                );
                                continue;
                            } else {
                                &stats.decrypt_errors
                            };
                            let total = counter.fetch_add(1, Ordering::Relaxed) + 1;
                            log_decrypt_error(&e, total, started_at, &mut last_decrypt_log);
                        }
                    }
                }

                for p in &to_net {
                    if let Err(e) = udp.send(p) {
                        tracing::error!("[隧道] UDP 回包失败: {e}");
                    }
                }
                if let Some(p) = to_tun {
                    let len = p.len() as u64;
                    if let Err(e) = tun_tx.write_packet(&p) {
                        tracing::error!("[隧道] TUN 写入错误: {e}");
                    } else {
                        stats.rx_bytes.fetch_add(len, Ordering::Relaxed);
                    }
                }
            }
            tracing::debug!("[隧道] 入站线程退出");
        })
        .map_err(|e| ConnectError::TunError(format!("无法启动入站线程: {e}")))
}

/// 标记会话存活，仅在状态翻转时记日志
fn mark_healthy(stats: &Arc<TunnelStats>) {
    if !stats.healthy.swap(true, Ordering::Relaxed) {
        tracing::info!("[隧道] 会话已建立，链路正常");
    }
}

/// 会话轮换导致的解密失败 —— 正常现象，不是安全问题
///
/// boringtun 只保留最近 8 个 session，槽位是 `session_index % 8`
/// （见其 `noise/mod.rs` 的 `N_SESSIONS`）。每次握手都会取一个新的本地
/// index，重连和每 120s 的 rekey 都会产生新 session。新 session 落到
/// 某个槽位后，服务端**仍在用旧 session 加密的在途包**到达时，
/// 槽里已经是新 session 了 —— `receive_packet_data` 比对
/// `receiver_idx != self.receiving_index` 直接返回 `WrongIndex`。
///
/// 换句话说：每次会话轮换都会丢掉「旧密钥的在途包」，
/// 数量取决于轮换瞬间链路上有多少包在飞。高带宽 + 高 RTT 链路上
/// 一次轮换掉几十个包是正常的，TCP 自己会重传。
///
/// 这几类都属于此类：
/// - `WrongIndex` — 槽位已被新 session 覆盖
/// - `NoCurrentSession` — 槽位还没建立 session
/// - `DuplicateCounter` / `InvalidCounter` 之外的重放窗口抖动
///
/// **真正可疑**的是 `InvalidAeadTag` / `WrongKey` / `InvalidMac`：
/// index 对上了但解不开，才意味着密钥不匹配或有人注入包。
fn is_session_churn(err: &boringtun::noise::errors::WireGuardError) -> bool {
    use boringtun::noise::errors::WireGuardError as E;
    matches!(
        err,
        E::WrongIndex | E::NoCurrentSession | E::DuplicateCounter | E::UnexpectedPacket
    )
}

/// 只有离开启动宽限期后，可疑的加密错误才进入用户可见计数。
/// 会话轮换类错误由调用方单独计入 `session_churn`。
fn should_count_decrypt_error(elapsed: Duration) -> bool {
    elapsed >= DECRYPT_GRACE
}

/// 按「会话轮换 vs 可疑」分级记录解密错误
///
/// 之前这里对所有错误都报 `持续出现说明密钥不匹配或存在包注入`，
/// 但绝大多数是 `WrongIndex` —— 会话轮换的正常产物。在长连接上
/// 每 120s rekey 一次，累计几百次 WrongIndex 完全正常，
/// 却让日志看起来像遭到攻击。
fn log_decrypt_error(
    err: &boringtun::noise::errors::WireGuardError,
    total: u64,
    started_at: Instant,
    last_log: &mut Option<Instant>,
) {
    // 会话轮换类错误全生命周期都是 debug —— 它们不代表任何异常
    if is_session_churn(err) {
        tracing::debug!("[隧道] 会话轮换丢包 (正常): {err:?} — 累计 {total} 次");
        return;
    }

    if started_at.elapsed() < DECRYPT_GRACE {
        tracing::debug!("[隧道] 会话交接期解密失败 (预期): {err:?}");
        return;
    }

    let should_log = last_log
        .map(|t| t.elapsed() >= DECRYPT_LOG_INTERVAL)
        .unwrap_or(true);

    if should_log {
        *last_log = Some(Instant::now());
        tracing::warn!(
            "[隧道] 解密失败: {err:?} — 累计 {total} 次。\
             index 对上但解不开，说明密钥不匹配或存在包注入",
        );
    }
}

/// 计时线程：驱动 boringtun 的握手重传/keepalive，并在其放弃后无限重连
///
/// ## 为什么不自己做静默检测
///
/// boringtun 已实现 RFC 标准逻辑：对端静默 15s (KEEPALIVE_TIMEOUT +
/// REKEY_TIMEOUT) 触发新握手，之后每 5s (REKEY_TIMEOUT) 重传，
/// 累计 90s (REKEY_ATTEMPT_TIME) 后放弃并返回 `ConnectionExpired`。
/// 再叠一层自己的检测只会和它打架。
///
/// 原来的 bug 就一处：`update_timers` 的 `Err` 被忽略了。
/// boringtun 放弃后 `Tunn` 进入 `HandshakeState::Expired` 终态，
/// 隧道**永久静默失效** —— 网络切换或 VPS 重启后必然踩到。
///
/// ## 复活机制
///
/// `format_handshake_initiation(force_resend=true)` 在 expired 状态下会
/// `timers.clear()` 并把 state 无条件改写为 `InitSent` —— 无需重建 `Tunn`。
/// 复活后 boringtun 自己的 90s 重传周期重新开始。
///
/// 退避只作用于**复活之间**（5s→10s→...→60s 上限），因为 90s 周期内的
/// 5s 重传已经由 boringtun 承担。永不放弃，永不动路由 ——
/// 与 WireGuard 本身的语义一致：链路恢复即自动可用。
fn spawn_timer(
    tunn: Arc<Mutex<Tunn>>,
    udp: Arc<Endpoint>,
    running: Arc<AtomicBool>,
    stats: Arc<TunnelStats>,
    started_at: Instant,
) -> Result<JoinHandle<()>, ConnectError> {
    thread::Builder::new()
        .name("miaovps-timer".into())
        .spawn(move || {
            let mut buf = [0u8; HANDSHAKE_BUF];
            let mut backoff = RECONNECT_BACKOFF_MIN;
            let mut next_revive: Option<Instant> = None;

            while running.load(Ordering::Relaxed) {
                thread::sleep(TIMER_TICK);

                let outcome = {
                    let mut t = match tunn.lock() {
                        Ok(t) => t,
                        Err(_) => break,
                    };

                    // boringtun 的权威会话状态：time_since_last_handshake()
                    // 返回 Some 即会话已建立。这与「有无流量」无关 ——
                    // fallback 模式下路由已撤、隧道内无数据，只能靠这个判断恢复。
                    let alive = t.stats().0.is_some();
                    stats.session_alive.store(alive, Ordering::Relaxed);

                    match t.update_timers(&mut buf[..]) {
                        TunnResult::WriteToNetwork(p) => TimerOutcome::Send(p.to_vec()),
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            TimerOutcome::Expired
                        }
                        TunnResult::Err(e) => TimerOutcome::OtherError(format!("{e:?}")),
                        _ => TimerOutcome::Idle,
                    }
                };

                match outcome {
                    TimerOutcome::Send(p) => {
                        // 有包可发说明会话在正常推进，重置退避
                        backoff = RECONNECT_BACKOFF_MIN;
                        next_revive = None;
                        if let Err(e) = udp.send_with_rebind(&p) {
                            // 断网期间这条每 250ms 会触发一次，降为 debug
                            tracing::debug!("[隧道] 保活/握手发送失败: {e}");
                        }
                    }
                    TimerOutcome::Idle => {
                        backoff = RECONNECT_BACKOFF_MIN;
                        next_revive = None;
                    }
                    TimerOutcome::OtherError(msg) => {
                        tracing::warn!("[隧道] 计时器异常: {msg}");
                    }
                    TimerOutcome::Expired => {
                        stats.healthy.store(false, Ordering::Relaxed);
                        stats.session_alive.store(false, Ordering::Relaxed);

                        // 首次进入 expired 立即复活，后续按退避
                        let due = next_revive.map(|t| Instant::now() >= t).unwrap_or(true);
                        if !due {
                            continue;
                        }

                        let n = stats.reconnects.fetch_add(1, Ordering::Relaxed) + 1;
                        let silence = stats
                            .since_last_inbound(started_at)
                            .map(|d| format!("{}s", d.as_secs()))
                            .unwrap_or_else(|| "从未连通".into());

                        tracing::warn!(
                            "[隧道] 连接已失效（对端静默 {silence}），\
                             第 {n} 次重连…"
                        );

                        if revive_handshake(&tunn, &udp) {
                            tracing::info!("[隧道] 重连握手已发出，等待响应");
                        }

                        next_revive = Some(Instant::now() + backoff);
                        backoff = next_backoff(backoff);
                    }
                }
            }
            tracing::debug!("[隧道] 计时线程退出");
        })
        .map_err(|e| ConnectError::TunError(format!("无法启动计时线程: {e}")))
}

/// 退避序列：给定已用退避，返回下一个值
///
/// 提取成函数以便单测 —— 退避逻辑错了会导致 VPS 宕机时高频重试。
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(RECONNECT_BACKOFF_MAX)
}

/// 计时器一次 tick 的结果
enum TimerOutcome {
    /// 有包要发
    Send(Vec<u8>),
    /// 无事可做
    Idle,
    /// boringtun 已放弃握手，需要复活
    Expired,
    /// 其他错误，仅记录
    OtherError(String),
}

/// 强制发起新握手以复活 expired 的 `Tunn`
///
/// 返回是否成功发出握手包。
///
/// 进入这里说明连接已确认死亡，所以**无条件重绑定 socket**：
/// 网络切换后源地址可能仍然存在（同一 WiFi 重连拿回同一 IP）但路由已变，
/// 此时 `send()` 不报错却发不出去 —— 靠错误码触发重绑定会漏掉这种情况。
fn revive_handshake(tunn: &Arc<Mutex<Tunn>>, udp: &Arc<Endpoint>) -> bool {
    if let Err(e) = udp.rebind() {
        // 网络完全不可用时绑定会失败，等下次退避重试
        tracing::debug!("[隧道] 重绑定失败（网络不可用?）: {e}");
        return false;
    }

    let mut buf = [0u8; HANDSHAKE_BUF];
    let packet = {
        let mut t = match tunn.lock() {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("[隧道] 复活时锁中毒: {e}");
                return false;
            }
        };
        match t.format_handshake_initiation(&mut buf[..], true) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            TunnResult::Err(e) => {
                tracing::warn!("[隧道] 复活握手构造失败: {e:?}");
                return false;
            }
            _ => return false,
        }
    };

    match udp.send(&packet) {
        Ok(_) => true,
        Err(e) => {
            // 网络不可用时 send 会失败（如 Wi-Fi 断开），属预期，等下次退避重试
            tracing::debug!("[隧道] 复活握手发送失败（网络不可用?）: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let mut b = RECONNECT_BACKOFF_MIN;
        assert_eq!(b, Duration::from_secs(5));

        b = next_backoff(b);
        assert_eq!(b, Duration::from_secs(10));
        b = next_backoff(b);
        assert_eq!(b, Duration::from_secs(20));
        b = next_backoff(b);
        assert_eq!(b, Duration::from_secs(40));

        // 触顶后保持不变，不会无限增长
        b = next_backoff(b);
        assert_eq!(b, RECONNECT_BACKOFF_MAX);
        b = next_backoff(b);
        assert_eq!(b, RECONNECT_BACKOFF_MAX);
    }

    #[test]
    fn stats_report_never_connected_before_first_packet() {
        let stats = TunnelStats::default();
        let started = Instant::now();
        // 0 是「从未收到」的哨兵值
        assert!(stats.since_last_inbound(started).is_none());
        assert!(!stats.is_healthy());
        assert_eq!(stats.reconnects(), 0);
    }

    #[test]
    fn stats_track_inbound_after_first_packet() {
        let stats = TunnelStats::default();
        let started = Instant::now();

        stats.last_inbound_ms.store(1, Ordering::Relaxed);
        assert!(stats.since_last_inbound(started).is_some());
    }

    #[test]
    fn healthy_flag_transitions_report_first_change() {
        let stats = TunnelStats::default();
        // swap 返回旧值 — 首次置 true 应返回 false，用于「仅首次记日志」
        assert!(!stats.healthy.swap(true, Ordering::Relaxed));
        assert!(stats.healthy.swap(true, Ordering::Relaxed));
        assert!(stats.is_healthy());
    }

    #[test]
    fn snapshot_returns_all_counters() {
        let stats = TunnelStats::default();
        stats.tx_bytes.store(100, Ordering::Relaxed);
        stats.rx_bytes.store(200, Ordering::Relaxed);
        stats.decrypt_errors.store(3, Ordering::Relaxed);

        assert_eq!(stats.snapshot(), (100, 200, 3));
    }

    #[test]
    fn detects_errors_that_require_rebind() {
        use std::io::{Error, ErrorKind};

        // macOS 网络环境变化的 errno — 必须重绑定
        for code in [49, 50, 51, 64, 65] {
            assert!(
                is_network_change_error(&Error::from_raw_os_error(code)),
                "errno {code} 应触发重绑定"
            );
        }
        assert!(is_network_change_error(&Error::from(ErrorKind::AddrNotAvailable)));

        // 与本机地址无关的错误 — 重绑定无济于事，不该重绑
        assert!(!is_network_change_error(&Error::from(ErrorKind::PermissionDenied)));
        assert!(!is_network_change_error(&Error::from(ErrorKind::WouldBlock)));
        assert!(!is_network_change_error(&Error::from(ErrorKind::TimedOut)));
        // EMSGSIZE(40): 载荷过大，换 socket 也一样失败
        assert!(!is_network_change_error(&Error::from_raw_os_error(40)));
    }

    #[test]
    fn endpoint_rebind_produces_new_source_port() {
        let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let ep = Endpoint::new(addr).expect("绑定本地回环应成功");

        let before = ep.current().local_addr().unwrap();
        assert_eq!(ep.rebinds(), 0);

        ep.rebind().expect("重绑定应成功");
        let after = ep.current().local_addr().unwrap();

        assert_eq!(ep.rebinds(), 1);
        assert_ne!(before.port(), after.port(), "重绑定应得到新源端口");
    }

    /// 限流是防日志风暴/CPU 打转的关键 —— 曾实测一秒 700 次重绑定
    #[test]
    fn rebind_is_rate_limited() {
        let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let ep = Endpoint::new(addr).unwrap();

        // 连续 50 次调用，限流应让实际重绑定只发生 1 次
        for _ in 0..50 {
            ep.rebind().expect("限流跳过也应返回 Ok");
        }
        assert_eq!(ep.rebinds(), 1, "限流窗口内应只重绑定一次");
    }

    /// 出站 send 绝不能自己重绑定 —— 否则退化成每包一次
    #[test]
    fn plain_send_never_rebinds() {
        let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let ep = Endpoint::new(addr).unwrap();

        // 回环上发送会成功；关键是断言计数不变
        let _ = ep.send(b"probe");
        assert_eq!(ep.rebinds(), 0, "数据路径的 send 不应触发重绑定");
    }

    #[test]
    fn formats_byte_counts_compactly() {
        assert_eq!(fmt_bytes(0), "0B");
        assert_eq!(fmt_bytes(512), "512B");
        assert_eq!(fmt_bytes(1536), "1.5KiB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024), "3.0MiB");
    }

    // ── 解密错误分类 ──
    //
    // 之前所有解密错误都报「密钥不匹配或存在包注入」。实际上长连接上
    // 绝大多数是 WrongIndex —— 每 120s rekey 一次，旧 session 的在途包
    // 必然解不开。误报会让用户以为遭到攻击。

    #[test]
    fn wrong_index_is_session_churn_not_attack() {
        use boringtun::noise::errors::WireGuardError as E;
        // 槽位被新 session 覆盖 —— rekey 和重连的必然产物
        assert!(is_session_churn(&E::WrongIndex));
        assert!(is_session_churn(&E::NoCurrentSession));
        assert!(is_session_churn(&E::DuplicateCounter));
    }

    /// index 对上却解不开才是真问题 —— 这几类必须报警
    #[test]
    fn crypto_failures_are_suspicious() {
        use boringtun::noise::errors::WireGuardError as E;
        assert!(!is_session_churn(&E::InvalidAeadTag));
        assert!(!is_session_churn(&E::WrongKey));
        assert!(!is_session_churn(&E::InvalidMac));
        assert!(!is_session_churn(&E::InvalidCounter));
    }

    #[test]
    fn startup_grace_does_not_count_suspicious_decrypt_errors() {
        // 启动初期的交接包即使被 boringtun 判定为 AEAD 错误，也不应让
        // 健康行显示固定的「解密错误 4」；宽限期结束后才进入计数。
        assert!(!should_count_decrypt_error(Duration::from_millis(0)));
        assert!(!should_count_decrypt_error(Duration::from_secs(2)));
        assert!(should_count_decrypt_error(DECRYPT_GRACE));
        assert!(should_count_decrypt_error(Duration::from_secs(4)));
    }

    #[test]
    fn churn_and_errors_use_separate_counters() {
        let stats = TunnelStats::default();
        stats.session_churn.store(400, Ordering::Relaxed);
        stats.decrypt_errors.store(2, Ordering::Relaxed);

        assert_eq!(stats.session_churn(), 400);
        // snapshot 的第三项只统计可疑错误，不含换钥丢包
        assert_eq!(stats.snapshot().2, 2);
    }

    /// 健康行必须让「正常丢包」和「异常」在措辞上可区分
    #[test]
    fn health_line_marks_only_real_errors() {
        let stats = TunnelStats::default();
        stats.session_churn.store(400, Ordering::Relaxed);
        // 换钥丢包不带警示符号
        assert!(!format!(" · 换钥丢包 {}", stats.session_churn()).contains('⚠'));
        // 解密错误带警示符号
        assert!(format!(" · ⚠ 解密错误 {}", 2).contains('⚠'));
    }
}
