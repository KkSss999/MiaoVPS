//! 原生隧道 — TUN + boringtun + UDP 完整加密循环
//!
//! 运行于独立线程，阻塞 I/O 循环：
//!   TUN read → boringtun encrypt → UDP send
//!   UDP recv → boringtun decrypt → TUN write

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::ConnectError;
use crate::tun::TunInterface;

/// 原生隧道 — 完整 WireGuard 隧道（不依赖 wg-quick）
pub struct NativeTunnel {
    running: Arc<AtomicBool>,
}

impl NativeTunnel {
    /// 启动原生 WireGuard 隧道（阻塞循环在独立线程）
    ///
    /// 返回 running flag，drop 前设置 false 即可停止
    pub fn start(
        tun: TunInterface,
        private_key: [u8; 32],
        server_public_key: [u8; 32],
        server_addr: SocketAddr,
        keepalive_secs: u16,
    ) -> Result<Self, ConnectError> {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();

        let sk: StaticSecret = private_key.into();
        let pk: PublicKey = server_public_key.into();
        let tunn = Tunn::new(sk, pk, None, Some(keepalive_secs), 0, None);

        // 绑定 UDP socket
        let udp = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| ConnectError::Io(e))?;
        udp.connect(server_addr)
            .map_err(|e| ConnectError::Io(e))?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| ConnectError::Io(e))?;

        let mut tun = tun;
        let mut tunn = tunn;

        thread::Builder::new()
            .name("miaovps-tunnel".into())
            .spawn(move || {
                tracing::info!("[隧道] 开始运行 → {}", server_addr);

                while running_clone.load(Ordering::Relaxed) {
                    // ── TUN → WG → UDP ──
                    match tun.read_packet() {
                        Ok(ip_packet) => {
                            let mut encrypted = [0u8; 2048];
                            match tunn.encapsulate(&ip_packet, &mut encrypted[..]) {
                                TunnResult::WriteToNetwork(packet) => {
                                    if let Err(e) = udp.send(packet) {
                                        tracing::error!("[隧道] UDP 发送失败: {e}");
                                    }
                                }
                                TunnResult::Err(e) => {
                                    tracing::warn!("[隧道] 加密错误: {e:?}");
                                }
                                _ => {}
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Non-blocking — no data from TUN, continue
                        }
                        Err(e) => {
                            tracing::error!("[隧道] TUN 读取错误: {e}");
                            break;
                        }
                    }

                    // ── UDP → WG → TUN ──
                    let mut udp_buf = [0u8; 2048];
                    match udp.recv(&mut udp_buf) {
                        Ok(n) => {
                            let mut decrypted = [0u8; 2048];
                            match tunn.decapsulate(None, &udp_buf[..n], &mut decrypted[..]) {
                                TunnResult::WriteToTunnelV4(packet, _) => {
                                    if let Err(e) = tun.write_packet(packet) {
                                        tracing::error!("[隧道] TUN 写入错误: {e}");
                                    }
                                }
                                TunnResult::WriteToTunnelV6(packet, _) => {
                                    if let Err(e) = tun.write_packet(packet) {
                                        tracing::error!("[隧道] TUN 写入错误: {e}");
                                    }
                                }
                                TunnResult::WriteToNetwork(reply) => {
                                    let _ = udp.send(reply);
                                }
                                TunnResult::Err(e) => {
                                    tracing::warn!("[隧道] 解密错误: {e:?}");
                                }
                                _ => {}
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(e) => {
                            tracing::error!("[隧道] UDP 接收错误: {e}");
                        }
                    }

                    // ── Timer tick ──
                    let mut timer_buf = [0u8; 148];
                    match tunn.update_timers(&mut timer_buf[..]) {
                        TunnResult::WriteToNetwork(packet) => {
                            let _ = udp.send(packet);
                        }
                        _ => {}
                    }

                    // 小睡避免 CPU 空转
                    thread::sleep(Duration::from_millis(1));
                }

                tracing::info!("[隧道] 已停止");
            })
            .map_err(|e| ConnectError::TunError(format!("无法启动隧道线程: {e}")))?;

        Ok(Self { running })
    }

    /// 停止隧道
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// 是否运行中
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}
