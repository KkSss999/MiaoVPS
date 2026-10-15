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
/// 从上次双向确认起计时，单向握手请求不能推迟探测。
const LINK_PROBE_INTERVAL: Duration = Duration::from_secs(30);
/// 探测留出 15s 响应窗口，再将链路标为不可用。
const LINK_STALE_AFTER: Duration = Duration::from_secs(45);
/// 隧道启动后的宽限期 — 期间的解密错误是预期的会话交接残留
///
/// 验证阶段用同一对密钥握手会在服务端留下一个 session。隧道随后从
/// 另一个 UDP 源端口重新握手，服务端按公钥把 endpoint 漫游过来并建立
/// 新 session — 旧 session 的在途包（keepalive）会被发到新端口，
/// 而本地 `Tunn` 只持有新 session 的密钥，必然解不开。
///
/// 启动交接期只保留诊断日志；宽限期之后的持续拒收必须计数并限频告警，
/// 不能仅凭错误类型归因为正常换钥。
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
        let mut last = match self.last_rebind.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if last.is_some_and(|t| t.elapsed() < REBIND_MIN_INTERVAL) {
            return Ok(());
        }
        let fresh = Self::make_socket(self.server_addr)?;
        let local = fresh.local_addr().ok();
        match self.socket.write() {
            Ok(mut g) => *g = Arc::new(fresh),
            Err(e) => *e.into_inner() = Arc::new(fresh),
        }
        *last = Some(Instant::now());
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
    ) || cfg!(target_os = "macos")
        && matches!(
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
    /// 启动宽限期之后的所有协议/解密拒收计数。不能仅凭错误类型认定原因。
    pub decrypt_errors: AtomicU64,
    /// 会话/重放拒收计数（兼容原 session_churn 字段，不表示已确认换钥原因）
    pub session_churn: AtomicU64,
    /// 因网络不可用而丢弃的出站包数
    pub tx_dropped: AtomicU64,
    /// 重连次数 — boringtun 放弃后我们强制复活的次数
    pub reconnects: AtomicU64,
    /// 最后一次收到任何入站包的时刻（隧道启动后的毫秒数）
    pub last_inbound_ms: AtomicU64,
    /// 最后一次双向确认：解出 transport 数据/keepalive，或验证本机握手的响应
    pub last_authenticated_ms: AtomicU64,
    /// 接受的对端握手请求总数；请求本身不能证明对方接受了本机回应
    pub peer_handshake_requests: AtomicU64,
    /// WrongIndex 原始拒收数（独立于日志抑制与启动宽限期）
    pub wrong_index: AtomicU64,
    /// 当前链路是否通过认证且未超出探测响应窗口
    pub healthy: AtomicBool,
    /// 本地会话存在且双向确认未过期；未确认的对端请求不延长存活
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

    /// 会话/重放拒收数，保留兼容接口
    pub fn session_churn(&self) -> u64 {
        self.session_churn.load(Ordering::Relaxed)
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// 链路是否仍可用；包含握手探测新鲜度，不能只看本地密钥是否存在。
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
            spawn_outbound(
                tun_rx,
                tunn.clone(),
                udp.clone(),
                running.clone(),
                stats.clone(),
            )?,
            spawn_inbound(
                tun_tx,
                tunn.clone(),
                udp.clone(),
                running.clone(),
                stats.clone(),
                started_at,
            )?,
            spawn_timer(
                tunn,
                udp.clone(),
                running.clone(),
                stats.clone(),
                started_at,
            )?,
        ];

        tracing::info!("[隧道] 已启动 → {}", server_addr);
        Ok(Self {
            running,
            stats,
            threads,
            started_at,
            udp,
        })
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
        let state = if self.stats.is_healthy() {
            "正常"
        } else {
            "重连中"
        };

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
            line.push_str(&format!(" · 会话/重放拒收 {churn}"));
        }
        // 不从计数直接推断密钥错误或攻击。
        if errs > 0 {
            line.push_str(&format!(" · ⚠ 协议拒收 {errs}"));
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
                            stats
                                .tx_bytes
                                .fetch_add(network_plaintext_len(&p), Ordering::Relaxed);
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
                    let result = t.decapsulate(None, &udp_buf[..n], &mut decrypted[..]);
                    record_link_progress(&stats, started_at.elapsed(), &udp_buf[..n], &result);
                    match result {
                        TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                            to_tun = Some(p.to_vec());
                        }
                        TunnResult::Done => {}
                        TunnResult::WriteToNetwork(p) => {
                            to_net.push(p.to_vec());
                            drain_queued_packets(&mut t, &mut to_net);
                        }
                        TunnResult::Err(e) => {
                            if matches!(e, WireGuardError::WrongIndex) {
                                stats.wrong_index.fetch_add(1, Ordering::Relaxed);
                            }
                            if is_session_rejection(&e) {
                                stats.session_churn.fetch_add(1, Ordering::Relaxed);
                            }
                            let total = if should_count_decrypt_error(started_at.elapsed()) {
                                stats.decrypt_errors.fetch_add(1, Ordering::Relaxed) + 1
                            } else {
                                stats.decrypt_errors.load(Ordering::Relaxed)
                            };
                            log_decrypt_error(&e, total, started_at, &mut last_decrypt_log);
                        }
                    }
                }

                for p in &to_net {
                    match udp.send(p) {
                        Ok(_) => {
                            stats
                                .tx_bytes
                                .fetch_add(network_plaintext_len(p), Ordering::Relaxed);
                        }
                        Err(e) => {
                            stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!("[隧道] UDP 回包失败: {e}");
                        }
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

/// WireGuard transport data has a 16-byte header and a 16-byte authentication tag.
/// Handshake packets carry no tunnel plaintext.
fn network_plaintext_len(packet: &[u8]) -> u64 {
    if packet.starts_with(&4u32.to_le_bytes()) {
        packet.len().saturating_sub(32) as u64
    } else {
        0
    }
}

/// boringtun's queue is bounded to 256 packets. Drain it to Done so no backlog
/// is stranded until an unrelated later handshake. I/O remains outside the lock.
fn drain_queued_packets(tunn: &mut Tunn, packets: &mut Vec<Vec<u8>>) {
    let mut buf = [0u8; PKT_BUF];
    loop {
        match tunn.decapsulate(None, &[], &mut buf) {
            TunnResult::WriteToNetwork(p) => packets.push(p.to_vec()),
            TunnResult::Err(e) => {
                tracing::warn!("[隧道] 积压队列处理失败: {e:?}");
                break;
            }
            _ => break,
        }
    }
    if packets.len() > 1 {
        tracing::debug!(packets = packets.len() - 1, "[隧道] 积压队列已排空");
    }
}

/// Only completed protocol progress proves both directions. A verified request
/// proves the peer can reach us, but not that it received/accepted our response.
fn record_link_progress(
    stats: &TunnelStats,
    elapsed: Duration,
    packet: &[u8],
    result: &TunnResult<'_>,
) {
    let confirmed = match (packet.get(..4), result) {
        (
            Some([4, 0, 0, 0]),
            TunnResult::Done | TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..),
        ) => true,
        (Some([2, 0, 0, 0]), TunnResult::WriteToNetwork(reply)) => {
            reply.starts_with(&4u32.to_le_bytes())
        }
        _ => false,
    };
    if confirmed {
        stats
            .last_authenticated_ms
            .store((elapsed.as_millis() as u64).max(1), Ordering::Relaxed);
    } else if let (Some([1, 0, 0, 0]), TunnResult::WriteToNetwork(reply)) =
        (packet.get(..4), result)
    {
        if reply.starts_with(&2u32.to_le_bytes()) {
            let n = stats
                .peer_handshake_requests
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            tracing::debug!(
                requests = n,
                "[隧道] 已回应对端握手，等待双向确认（不刷新链路健康）"
            );
        }
    }
}

/// Separate recovery scheduling from raw input/handshake activity. In particular,
/// repeated peer initiations must not starve probes when they abort local retries.
#[derive(Default)]
struct LinkProbeSchedule {
    last_probe: Duration,
}

impl LinkProbeSchedule {
    fn due(&mut self, elapsed: Duration, last_confirmed_ms: u64, expired: bool) -> bool {
        if !expired
            && elapsed
                .as_millis()
                .saturating_sub(last_confirmed_ms as u128)
                >= LINK_PROBE_INTERVAL.as_millis()
            && elapsed.saturating_sub(self.last_probe) >= LINK_PROBE_INTERVAL
        {
            self.last_probe = elapsed;
            true
        } else {
            false
        }
    }
}

fn link_is_fresh(session_exists: bool, elapsed: Duration, last_authenticated_ms: u64) -> bool {
    session_exists
        && last_authenticated_ms != 0
        && elapsed
            .as_millis()
            .saturating_sub(last_authenticated_ms as u128)
            < LINK_STALE_AFTER.as_millis()
}

/// These errors identify rejection classes, not their cause. In particular,
/// normal rekey retains the previous session and should not itself cause loss.
fn is_session_rejection(err: &WireGuardError) -> bool {
    matches!(
        err,
        WireGuardError::WrongIndex
            | WireGuardError::NoCurrentSession
            | WireGuardError::DuplicateCounter
            | WireGuardError::UnexpectedPacket
    )
}

/// 离开启动宽限期后，所有协议拒收都进入用户可见错误计数。
/// 会话/重放错误同时保留兼容性分类计数。
fn should_count_decrypt_error(elapsed: Duration) -> bool {
    elapsed >= DECRYPT_GRACE
}

/// Rate-limit warnings without treating persistent session rejection as normal rekey.
fn log_decrypt_error(
    err: &boringtun::noise::errors::WireGuardError,
    total: u64,
    started_at: Instant,
    last_log: &mut Option<Instant>,
) {
    tracing::debug!(error = ?err, total, uptime_ms = started_at.elapsed().as_millis(), "[隧道] 收包被拒绝");
    if started_at.elapsed() < DECRYPT_GRACE {
        tracing::debug!("[隧道] 会话交接期解密失败 (预期): {err:?}");
        return;
    }

    let should_log = last_log
        .map(|t| t.elapsed() >= DECRYPT_LOG_INTERVAL)
        .unwrap_or(true);

    if should_log {
        *last_log = Some(Instant::now());
        tracing::warn!("[隧道] 协议/解密拒收: {err:?} — 累计 {total} 次（原因尚未确认）",);
    }
}

/// 计时线程：驱动 boringtun 的握手重传/keepalive，并在其放弃后无限重连
///
/// boringtun owns handshake retransmission and expiry. The host additionally
/// probes after 30s without authenticated input, because keepalive does not
/// require a reply and a cached local key cannot prove that the path is live.
/// The probe never forces/restarts an in-flight handshake.
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
            let mut probe_schedule = LinkProbeSchedule::default();
            let mut last_diagnostic = Duration::ZERO;

            while running.load(Ordering::Relaxed) {
                thread::sleep(TIMER_TICK);

                let outcome = {
                    let mut t = match tunn.lock() {
                        Ok(t) => t,
                        Err(_) => break,
                    };

                    match t.update_timers(&mut buf[..]) {
                        TunnResult::WriteToNetwork(p) => TimerOutcome::Send(p.to_vec()),
                        TunnResult::Err(WireGuardError::ConnectionExpired) => TimerOutcome::Expired,
                        TunnResult::Err(e) => TimerOutcome::OtherError(format!("{e:?}")),
                        _ => TimerOutcome::Idle,
                    }
                };

                let elapsed = started_at.elapsed();
                let last_auth = stats.last_authenticated_ms.load(Ordering::Relaxed);
                let (session_exists, handshake_age) = match tunn.lock() {
                    Ok(t) => (t.stats().0.is_some(), t.stats().0),
                    Err(_) => break,
                };
                let alive = link_is_fresh(session_exists, elapsed, last_auth);
                stats.session_alive.store(alive, Ordering::Relaxed);
                if stats.healthy.swap(alive, Ordering::Relaxed) != alive {
                    tracing::info!(
                        alive,
                        last_authenticated_ms = last_auth,
                        "[隧道] 认证链路状态变化"
                    );
                }
                if elapsed.saturating_sub(last_diagnostic) >= Duration::from_secs(5) {
                    last_diagnostic = elapsed;
                    tracing::debug!(uptime_ms = elapsed.as_millis(), alive, session_exists,
                        handshake_age_ms = ?handshake_age.map(|d| d.as_millis()),
                        last_authenticated_ms = last_auth,
                        peer_handshake_requests = stats.peer_handshake_requests.load(Ordering::Relaxed),
                        wrong_index = stats.wrong_index.load(Ordering::Relaxed),
                        confirmed_silence_ms = elapsed.as_millis().saturating_sub(last_auth as u128),
                        last_inbound_ms = stats.last_inbound_ms.load(Ordering::Relaxed),
                        tx_bytes = stats.tx_bytes.load(Ordering::Relaxed),
                        rx_bytes = stats.rx_bytes.load(Ordering::Relaxed),
                        tx_dropped = stats.tx_dropped.load(Ordering::Relaxed),
                        rejected = stats.decrypt_errors.load(Ordering::Relaxed),
                        session_rejected = stats.session_churn(), rebinds = udp.rebinds(),
                        reconnects = stats.reconnects(), "[隧道] 诊断快照");
                }
                // Peer requests are intentionally excluded from the confirmation clock:
                // they can arrive forever while our response path is broken.
                if probe_schedule.due(elapsed, last_auth, matches!(outcome, TimerOutcome::Expired)) {
                    tracing::warn!(confirmed_silence_ms = elapsed.as_millis().saturating_sub(last_auth as u128),
                        "[隧道] 双向确认停滞，重绑定并探测链路");
                    probe_link(&tunn, &udp);
                }

                match outcome {
                    TimerOutcome::Send(p) => {
                        // Only authenticated recovery resets backoff, not an unanswered send.
                        if alive {
                            backoff = RECONNECT_BACKOFF_MIN;
                            next_revive = None;
                        }
                        if let Err(e) = udp.send_with_rebind(&p) {
                            // 断网期间这条每 250ms 会触发一次，降为 debug
                            tracing::debug!("[隧道] 保活/握手发送失败: {e}");
                        }
                    }
                    TimerOutcome::Idle => {
                        if alive {
                            backoff = RECONNECT_BACKOFF_MIN;
                            next_revive = None;
                        }
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

/// Rebind at most once per probe interval to recover stale local/NAT paths.
/// Never force a new handshake while boringtun is already retrying one.
fn probe_link(tunn: &Arc<Mutex<Tunn>>, udp: &Arc<Endpoint>) {
    if let Err(e) = udp.rebind() {
        tracing::debug!("[隧道] 链路探测重绑定失败: {e}");
        return;
    }
    let mut buf = [0u8; HANDSHAKE_BUF];
    let packet = {
        let Ok(mut t) = tunn.lock() else { return };
        match t.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
            TunnResult::Err(e) => {
                tracing::debug!("[隧道] 链路探测失败: {e:?}");
                None
            }
            _ => None,
        }
    };
    if let Some(p) = packet {
        tracing::debug!("[隧道] 双向确认静默，发起链路探测");
        if let Err(e) = udp.send(&p) {
            tracing::debug!("[隧道] 链路探测发送失败: {e}");
        }
    }
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
        for code in if cfg!(target_os = "macos") {
            vec![49, 50, 51, 64, 65]
        } else {
            vec![]
        } {
            assert!(
                is_network_change_error(&Error::from_raw_os_error(code)),
                "errno {code} 应触发重绑定"
            );
        }
        assert!(is_network_change_error(&Error::from(
            ErrorKind::AddrNotAvailable
        )));

        // 与本机地址无关的错误 — 重绑定无济于事，不该重绑
        assert!(!is_network_change_error(&Error::from(
            ErrorKind::PermissionDenied
        )));
        assert!(!is_network_change_error(&Error::from(
            ErrorKind::WouldBlock
        )));
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

    #[test]
    fn session_rejections_do_not_prove_rekey_or_attack() {
        assert!(is_session_rejection(&WireGuardError::WrongIndex));
        assert!(is_session_rejection(&WireGuardError::DuplicateCounter));
        assert!(!is_session_rejection(&WireGuardError::InvalidAeadTag));
        assert!(should_count_decrypt_error(DECRYPT_GRACE));
        assert!(!should_count_decrypt_error(Duration::ZERO));
    }

    #[test]
    fn cached_key_and_unauthenticated_traffic_do_not_prove_liveness() {
        assert!(!link_is_fresh(true, Duration::from_secs(1), 0));
        assert!(link_is_fresh(true, Duration::from_secs(40), 1));
        assert!(!link_is_fresh(true, Duration::from_secs(46), 1));
        assert!(!link_is_fresh(false, Duration::from_secs(1), 1));
        assert!(link_is_fresh(true, Duration::from_secs(46), 45_000));
    }
    fn paired_tunnels() -> (Tunn, Tunn) {
        let a = StaticSecret::from([1u8; 32]);
        let b = StaticSecret::from([2u8; 32]);
        let ap = PublicKey::from(&a);
        let bp = PublicKey::from(&b);
        (
            Tunn::new(a, bp, None, None, 0, None),
            Tunn::new(b, ap, None, None, 0, None),
        )
    }

    fn network_packet(result: TunnResult<'_>) -> Vec<u8> {
        match result {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected network packet, got {other:?}"),
        }
    }

    fn handshake(a: &mut Tunn, b: &mut Tunn) {
        let mut buf = [0u8; PKT_BUF];
        let init = network_packet(a.format_handshake_initiation(&mut buf, true));
        let response = network_packet(b.decapsulate(None, &init, &mut buf));
        let confirmation = network_packet(a.decapsulate(None, &response, &mut buf));
        assert!(matches!(
            b.decapsulate(None, &confirmation, &mut buf),
            TunnResult::Done
        ));
    }

    fn ipv4_packet() -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[3] = 20;
        p[12] = 10;
        p[16] = 10;
        p
    }

    #[test]
    fn old_inflight_data_survives_rekey() {
        let (mut a, mut b) = paired_tunnels();
        handshake(&mut a, &mut b);
        let mut buf = [0u8; PKT_BUF];
        let old = network_packet(b.encapsulate(&ipv4_packet(), &mut buf));
        handshake(&mut a, &mut b);
        assert!(matches!(
            a.decapsulate(None, &old, &mut buf),
            TunnResult::WriteToTunnelV4(..)
        ));
    }

    #[test]
    fn handshake_backlog_is_fully_drained_and_delivered() {
        let (mut a, mut b) = paired_tunnels();
        let mut buf = [0u8; PKT_BUF];
        for _ in 0..256 {
            a.encapsulate(&ipv4_packet(), &mut buf);
        }
        handshake(&mut a, &mut b);
        let mut pending = Vec::new();
        drain_queued_packets(&mut a, &mut pending);
        assert_eq!(pending.len(), 256);
        for p in pending {
            assert!(matches!(
                b.decapsulate(None, &p, &mut buf),
                TunnResult::WriteToTunnelV4(..)
            ));
        }
        assert!(matches!(
            a.decapsulate(None, &[], &mut buf),
            TunnResult::Done
        ));
    }

    #[test]
    fn idle_probe_preserves_an_inflight_handshake() {
        let (mut a, mut b) = paired_tunnels();
        let mut buf = [0u8; PKT_BUF];
        let init = network_packet(a.format_handshake_initiation(&mut buf, true));
        let response = network_packet(b.decapsulate(None, &init, &mut buf));
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp = Arc::new(Endpoint::new(listener.local_addr().unwrap()).unwrap());
        let tunn = Arc::new(Mutex::new(a));
        probe_link(&tunn, &udp);
        assert_eq!(udp.rebinds(), 1);
        assert!(matches!(
            tunn.lock().unwrap().decapsulate(None, &response, &mut buf),
            TunnResult::WriteToNetwork(_)
        ));
    }
    #[test]
    fn unconfirmed_peer_rekeys_cannot_starve_recovery() {
        let (mut client, mut server) = paired_tunnels();
        handshake(&mut client, &mut server);
        let stats = TunnelStats::default();
        let mut buf = [0u8; PKT_BUF];
        let data = network_packet(server.encapsulate(&ipv4_packet(), &mut buf));
        let result = client.decapsulate(None, &data, &mut buf);
        record_link_progress(&stats, Duration::from_secs(1), &data, &result);
        assert_eq!(stats.last_authenticated_ms.load(Ordering::Relaxed), 1000);

        let mut schedule = LinkProbeSchedule::default();
        let mut due_at = Vec::new();
        for retry in 1..=8 {
            let elapsed = Duration::from_secs(1 + retry * 5);
            let request = network_packet(server.format_handshake_initiation(&mut buf, true));
            let result = client.decapsulate(None, &request, &mut buf);
            assert!(matches!(result, TunnResult::WriteToNetwork(_)));
            // Intentionally discard the response, matching the stalled confirmation path.
            record_link_progress(&stats, elapsed, &request, &result);
            let confirmed = stats.last_authenticated_ms.load(Ordering::Relaxed);
            assert_eq!(confirmed, 1000, "peer requests must not refresh health");
            if schedule.due(elapsed, confirmed, false) {
                due_at.push(elapsed.as_secs());
            }
        }
        assert_eq!(stats.peer_handshake_requests.load(Ordering::Relaxed), 8);
        assert_eq!(
            due_at,
            vec![31],
            "probe must fire despite five-second peer requests"
        );
        let old = network_packet(server.encapsulate(&ipv4_packet(), &mut buf));
        let rejected = client.decapsulate(None, &old, &mut buf);
        assert!(matches!(
            rejected,
            TunnResult::Err(WireGuardError::WrongIndex)
        ));
        record_link_progress(&stats, Duration::from_secs(44), &old, &rejected);
        assert!(!link_is_fresh(
            client.stats().0.is_some(),
            Duration::from_secs(46),
            stats.last_authenticated_ms.load(Ordering::Relaxed)
        ));
        assert!(!schedule.due(Duration::from_secs(46), 1000, false));
        assert!(schedule.due(Duration::from_secs(61), 1000, false));

        // Execute the actual recovery sender and complete its handshake over a new socket.
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let udp = Arc::new(Endpoint::new(listener.local_addr().unwrap()).unwrap());
        let tunn = Arc::new(Mutex::new(client));
        probe_link(&tunn, &udp);
        assert_eq!(udp.rebinds(), 1);
        let n = listener.recv(&mut buf).unwrap();
        let request = buf[..n].to_vec();
        assert!(request.starts_with(&1u32.to_le_bytes()));
        let response = network_packet(server.decapsulate(None, &request, &mut buf));
        let mut client = tunn.lock().unwrap();
        let result = client.decapsulate(None, &response, &mut buf);
        record_link_progress(&stats, Duration::from_secs(62), &response, &result);
        let confirmation = network_packet(result);
        assert!(matches!(
            server.decapsulate(None, &confirmation, &mut buf),
            TunnResult::Done
        ));
        assert!(link_is_fresh(
            client.stats().0.is_some(),
            Duration::from_secs(62),
            stats.last_authenticated_ms.load(Ordering::Relaxed)
        ));
        let data = network_packet(server.encapsulate(&ipv4_packet(), &mut buf));
        let result = client.decapsulate(None, &data, &mut buf);
        assert!(matches!(result, TunnResult::WriteToTunnelV4(..)));
        record_link_progress(&stats, Duration::from_secs(63), &data, &result);
        assert_eq!(stats.last_authenticated_ms.load(Ordering::Relaxed), 63_000);
    }

    #[test]
    fn cookies_invalid_data_and_queued_output_do_not_confirm_link() {
        let stats = TunnelStats::default();
        record_link_progress(
            &stats,
            Duration::from_secs(30),
            &[3, 0, 0, 0],
            &TunnResult::Done,
        );
        record_link_progress(
            &stats,
            Duration::from_secs(30),
            &[4, 0, 0, 0],
            &TunnResult::Err(WireGuardError::WrongIndex),
        );
        let mut transport_header = [4, 0, 0, 0];
        record_link_progress(
            &stats,
            Duration::from_secs(30),
            &[],
            &TunnResult::WriteToNetwork(&mut transport_header),
        );
        assert_eq!(stats.last_authenticated_ms.load(Ordering::Relaxed), 0);
        // An authenticated empty transport packet (keepalive) is sufficient even when idle.
        record_link_progress(
            &stats,
            Duration::from_secs(31),
            &[4, 0, 0, 0],
            &TunnResult::Done,
        );
        assert_eq!(stats.last_authenticated_ms.load(Ordering::Relaxed), 31_000);
    }

    #[test]
    fn recovery_schedule_is_rate_limited_and_expiry_keeps_its_own_backoff() {
        let mut schedule = LinkProbeSchedule::default();
        assert!(!schedule.due(Duration::from_secs(29), 0, false));
        assert!(schedule.due(Duration::from_secs(30), 0, false));
        assert!(!schedule.due(Duration::from_secs(30), 0, false));
        assert!(!schedule.due(Duration::from_secs(60), 0, true));
        assert!(schedule.due(Duration::from_secs(60), 0, false));
        // Fresh confirmed traffic defers probing, but unconfirmed requests never enter this clock.
        assert!(!schedule.due(Duration::from_secs(90), 89_000, false));
        assert!(schedule.due(Duration::from_secs(119), 89_000, false));
    }
}
