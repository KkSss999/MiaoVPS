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
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

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
/// 这类瞬态无害。但**持续**的解密错误意味着密钥不匹配或包注入，
/// 必须能和瞬态区分开，所以宽限期后升级为 warn。
const DECRYPT_GRACE: Duration = Duration::from_secs(3);
/// 解密错误的日志抑制间隔 — 防止异常状态下刷屏
const DECRYPT_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// 隧道流量统计
#[derive(Debug, Default)]
pub struct TunnelStats {
    /// 出站明文字节数（TUN → VPS）
    pub tx_bytes: AtomicU64,
    /// 入站明文字节数（VPS → TUN）
    pub rx_bytes: AtomicU64,
    /// 解密错误计数
    pub decrypt_errors: AtomicU64,
}

impl TunnelStats {
    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.tx_bytes.load(Ordering::Relaxed),
            self.rx_bytes.load(Ordering::Relaxed),
            self.decrypt_errors.load(Ordering::Relaxed),
        )
    }
}

/// 原生隧道 — 完整 WireGuard 隧道（不依赖 wg-quick）
pub struct NativeTunnel {
    running: Arc<AtomicBool>,
    stats: Arc<TunnelStats>,
    threads: Vec<JoinHandle<()>>,
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

        let udp = UdpSocket::bind("0.0.0.0:0").map_err(ConnectError::Io)?;
        udp.connect(server_addr).map_err(ConnectError::Io)?;
        udp.set_read_timeout(Some(UDP_READ_TIMEOUT))
            .map_err(ConnectError::Io)?;

        let running = Arc::new(AtomicBool::new(true));
        let stats = Arc::new(TunnelStats::default());
        let tunn = Arc::new(Mutex::new(tunn));
        let udp = Arc::new(udp);
        let (tun_rx, tun_tx) = tun.into_split();

        // 主动发起首次握手。后续重传由计时器线程通过 update_timers 驱动。
        send_handshake(&tunn, &udp);

        let threads = vec![
            spawn_outbound(tun_rx, tunn.clone(), udp.clone(), running.clone(), stats.clone())?,
            spawn_inbound(tun_tx, tunn.clone(), udp.clone(), running.clone(), stats.clone())?,
            spawn_timer(tunn, udp, running.clone())?,
        ];

        tracing::info!("[隧道] 已启动 → {}", server_addr);
        Ok(Self { running, stats, threads })
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
}

impl Drop for NativeTunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 发送握手 Initiation（force_resend 跳过「已在握手中」检查）
fn send_handshake(tunn: &Arc<Mutex<Tunn>>, udp: &Arc<UdpSocket>) {
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
    udp: Arc<UdpSocket>,
    running: Arc<AtomicBool>,
    stats: Arc<TunnelStats>,
) -> Result<JoinHandle<()>, ConnectError> {
    thread::Builder::new()
        .name("miaovps-tx".into())
        .spawn(move || {
            let mut encrypted = [0u8; PKT_BUF];
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
                    if let Err(e) = udp.send(&p) {
                        tracing::error!("[隧道] UDP 发送失败: {e}");
                    } else {
                        stats.tx_bytes.fetch_add(plaintext_len, Ordering::Relaxed);
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
    udp: Arc<UdpSocket>,
    running: Arc<AtomicBool>,
    stats: Arc<TunnelStats>,
) -> Result<JoinHandle<()>, ConnectError> {
    thread::Builder::new()
        .name("miaovps-rx".into())
        .spawn(move || {
            let mut udp_buf = [0u8; PKT_BUF];
            let mut decrypted = [0u8; PKT_BUF];
            let started_at = Instant::now();
            let mut last_decrypt_log: Option<Instant> = None;

            while running.load(Ordering::Relaxed) {
                let n = match udp.recv(&mut udp_buf) {
                    Ok(n) => n,
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
                            to_tun = Some(p.to_vec());
                        }
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
                            let total =
                                stats.decrypt_errors.fetch_add(1, Ordering::Relaxed) + 1;
                            log_decrypt_error(
                                &e,
                                total,
                                started_at,
                                &mut last_decrypt_log,
                            );
                        }
                        TunnResult::Done => {}
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

/// 按「瞬态 vs 持续」分级记录解密错误
///
/// 宽限期内降为 debug（会话交接残留），之后按间隔抑制地报 warn 并带上累计数 —
/// 累计数是判断「一次性残留」还是「密钥不匹配」的关键信息。
fn log_decrypt_error(
    err: &boringtun::noise::errors::WireGuardError,
    total: u64,
    started_at: Instant,
    last_log: &mut Option<Instant>,
) {
    let elapsed = started_at.elapsed();

    if elapsed < DECRYPT_GRACE {
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
             持续出现说明密钥不匹配或存在包注入",
        );
    }
}

/// 计时线程：驱动握手重传和 keepalive
fn spawn_timer(
    tunn: Arc<Mutex<Tunn>>,
    udp: Arc<UdpSocket>,
    running: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, ConnectError> {
    thread::Builder::new()
        .name("miaovps-timer".into())
        .spawn(move || {
            let mut buf = [0u8; HANDSHAKE_BUF];
            while running.load(Ordering::Relaxed) {
                thread::sleep(TIMER_TICK);
                let packet = {
                    let mut t = match tunn.lock() {
                        Ok(t) => t,
                        Err(_) => break,
                    };
                    match t.update_timers(&mut buf[..]) {
                        TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                        TunnResult::Err(e) => {
                            tracing::warn!("[隧道] 计时器: {e:?}");
                            None
                        }
                        _ => None,
                    }
                };
                if let Some(p) = packet {
                    if let Err(e) = udp.send(&p) {
                        tracing::error!("[隧道] 保活发送失败: {e}");
                    }
                }
            }
            tracing::debug!("[隧道] 计时线程退出");
        })
        .map_err(|e| ConnectError::TunError(format!("无法启动计时线程: {e}")))
}
