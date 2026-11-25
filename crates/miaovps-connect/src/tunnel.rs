//! WireGuard 隧道核心 — boringtun 协议 + TUN 接口 + UDP 传输
//!
//! 架构:
//!   TUN (utun) ←→ boringtun Tunnel ←→ UDP Socket ←→ VPS:51820
//!
//!   1. TUN 读取 IP 包 → encapsulate → UDP 发出
//!   2. UDP 收到加密包 → decapsulate → TUN 写入

use awgtun::noise::{Tunn, TunnResult};

use crate::awg::{outgoing, Framing};
use awgtun::x25519::{PublicKey, StaticSecret};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::warn;

use crate::error::ConnectError;

/// 包缓冲区 — 覆盖最大 MTU + WireGuard 封装开销
const PKT_BUF: usize = 2048;
/// 握手包缓冲区（Initiation 固定 148B）
const HANDSHAKE_BUF: usize = 256;
/// 单次握手等待响应的超时
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  WireGuard 握手器 — 用于验证阶段的纯握手测试（不使用 TUN）
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// WireGuard 握手器 — 发送 Initiation，等待 Response
///
/// 每次 `try_handshake` 都新建 `Tunn` 和 socket。`Tunn` 内部持有握手状态
/// 和限流计数，跨重试复用会让第二次之后的尝试在无效状态下发包 —
/// 表现为首次成功、重试全部超时。
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("等待认证握手响应超时 — 检查 UDP {0} 和协议参数")]
    Timeout(u16),
    #[error("{0}")]
    Other(String),
}

pub struct WireGuardHandshaker {
    private_key: [u8; 32],
    server_public_key: [u8; 32],
    server_addr: SocketAddr,
    framing: Framing,
}

impl WireGuardHandshaker {
    pub fn new(
        private_key: [u8; 32],
        server_public_key: [u8; 32],
        server_addr: SocketAddr,
    ) -> Self {
        Self {
            private_key,
            server_public_key,
            server_addr,
            framing: Framing::default(),
        }
    }

    pub fn with_framing(mut self, framing: Framing) -> Self {
        self.framing = framing;
        self
    }

    /// 尝试一次握手：Initiation → 等待 Response → decapsulate
    ///
    /// 成功的判定是**收到并解密了服务器的 Response**，这同时验证了
    /// 密钥匹配、UDP 双向连通和服务端 WireGuard 在线。
    pub async fn try_handshake(&self) -> Result<(), HandshakeError> {
        let mut tunn = self
            .framing
            .tunnel(self.private_key, self.server_public_key, None);

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| HandshakeError::Other(format!("无法绑定本地端口: {e}")))?;
        socket
            .connect(self.server_addr)
            .await
            .map_err(|e| HandshakeError::Other(format!("无法连接 {}: {e}", self.server_addr)))?;

        let mut buf = [0u8; HANDSHAKE_BUF];
        let init = tunn.format_handshake_initiation(&mut buf, true);
        if !matches!(init, TunnResult::WriteToNetwork(_)) {
            return Err(HandshakeError::Other(format!("握手初始化失败: {init:?}")));
        }
        for packet in outgoing(&mut tunn, init) {
            socket
                .send(&packet)
                .await
                .map_err(|e| HandshakeError::Other(format!("发送握手包失败: {e}")))?;
        }

        let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
        let mut recv_buf = [0u8; PKT_BUF];
        let mut tmp = [0u8; PKT_BUF];
        loop {
            let n = tokio::time::timeout_at(deadline, socket.recv(&mut recv_buf))
                .await
                .map_err(|_| HandshakeError::Timeout(self.server_addr.port()))?
                .map_err(|e| HandshakeError::Other(format!("接收失败: {e}")))?;
            let packet = &recv_buf[..n];
            // Cookie replies can trigger resending an initiation; only a verified response completes validation.
            let result = tunn.decapsulate(None, packet, &mut tmp);
            let confirmed = self.framing.packet_type(packet) == 2
                && matches!(result, TunnResult::WriteToNetwork(ref reply) if self.framing.packet_type(reply) == 4);
            for reply in outgoing(&mut tunn, result) {
                socket
                    .send(&reply)
                    .await
                    .map_err(|e| HandshakeError::Other(format!("握手回包失败: {e}")))?;
            }
            if confirmed {
                return Ok(());
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  WireGuard 隧道 — boringtun + TUN + UDP 完整循环
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// WireGuard 隧道控制句柄
pub struct TunnelHandle {
    /// boringtun 隧道实例
    tunn: Arc<Mutex<Tunn>>,
    /// UDP socket 连接
    udp: Arc<UdpSocket>,
    /// 服务器地址
    _server_addr: SocketAddr,
    /// 是否运行中
    running: Arc<Mutex<bool>>,
}

impl TunnelHandle {
    /// 创建新隧道
    pub async fn new(
        private_key: [u8; 32],
        server_public_key: [u8; 32],
        server_addr: SocketAddr,
        persistent_keepalive: Option<u16>,
    ) -> Result<Self, ConnectError> {
        let sk: StaticSecret = private_key.into();
        let pk: PublicKey = server_public_key.into();

        let tunn = Tunn::new(sk, pk, None, persistent_keepalive, 0, None);

        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(ConnectError::Io)?;
        udp.connect(server_addr).await.map_err(ConnectError::Io)?;

        Ok(Self {
            tunn: Arc::new(Mutex::new(tunn)),
            udp: Arc::new(udp),
            _server_addr: server_addr,
            running: Arc::new(Mutex::new(false)),
        })
    }

    /// 获取 UDP socket 引用（供外部读取 TUN 解包后的数据）
    pub fn udp_socket(&self) -> Arc<UdpSocket> {
        self.udp.clone()
    }

    /// 标记隧道为运行中
    pub async fn set_running(&self, running: bool) {
        *self.running.lock().await = running;
    }

    /// 发送 WireGuard 包（从 TUN 读到的 IP 包加密后发出）
    pub async fn send_encrypted(&self, ip_packet: &[u8]) -> Result<(), ConnectError> {
        let mut tunn = self.tunn.lock().await;
        let mut encrypted = [0u8; 1500];
        match tunn.encapsulate(ip_packet, &mut encrypted[..]) {
            TunnResult::WriteToNetwork(packet) => {
                self.udp.send(packet).await.map_err(ConnectError::Io)?;
                Ok(())
            }
            TunnResult::Done => Ok(()),
            TunnResult::Err(e) => Err(ConnectError::WireGuardError(format!("{e:?}"))),
            other => {
                warn!("send_encrypted: 意外结果: {other:?}");
                Ok(())
            }
        }
    }

    /// 接收并解密 WireGuard 包，返回解密的 IP 包
    pub async fn recv_decrypted(&self, raw: &[u8]) -> Result<Option<Vec<u8>>, ConnectError> {
        let mut tunn = self.tunn.lock().await;
        let mut decrypted = [0u8; 1500];
        match tunn.decapsulate(None, raw, &mut decrypted[..]) {
            TunnResult::WriteToTunnelV4(packet, _addr) => Ok(Some(packet.to_vec())),
            TunnResult::WriteToTunnelV6(packet, _addr) => Ok(Some(packet.to_vec())),
            TunnResult::WriteToNetwork(packet) => {
                // 需要回包（握手响应等）
                self.udp.send(packet).await.map_err(ConnectError::Io)?;
                Ok(None)
            }
            TunnResult::Done => Ok(None),
            TunnResult::Err(e) => Err(ConnectError::WireGuardError(format!("{e:?}"))),
        }
    }

    /// 刷新计时器 — 获取待发送的保活/握手包
    pub async fn tick(&self) -> Result<(), ConnectError> {
        let mut tunn = self.tunn.lock().await;
        let mut buf = [0u8; HANDSHAKE_BUF];
        match tunn.update_timers(&mut buf[..]) {
            TunnResult::WriteToNetwork(packet) => {
                self.udp.send(packet).await.map_err(ConnectError::Io)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[tokio::test]
    async fn validates_awg_after_sending_junk_before_the_authenticated_handshake() {
        let framing = Framing::amnezia([101, 202, 303, 404], [24, 40], [4, 48, 80]).unwrap();
        let client = StaticSecret::from([11u8; 32]);
        let server = StaticSecret::from([22u8; 32]);
        let mut peer = framing.tunnel(server.to_bytes(), PublicKey::from(&client).to_bytes(), None);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handshaker = WireGuardHandshaker::new(
            client.to_bytes(),
            PublicKey::from(&server).to_bytes(),
            socket.local_addr().unwrap(),
        )
        .with_framing(framing);
        let responder = async {
            let mut buf = [0; PKT_BUF];
            let mut output = [0; PKT_BUF];
            for _ in 0..4 {
                let (len, _) = socket.recv_from(&mut buf).await.unwrap();
                assert!((48..=80).contains(&len));
            }
            let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
            assert_eq!(len, 148 + 24);
            assert_eq!(framing.packet_type(&buf[..len]), 1);
            let TunnResult::WriteToNetwork(reply) =
                peer.decapsulate(None, &buf[..len], &mut output)
            else {
                panic!("expected AWG response")
            };
            socket.send_to(&[0; 32], addr).await.unwrap();
            socket.send_to(reply, addr).await.unwrap();
            let (len, _) = socket.recv_from(&mut buf).await.unwrap();
            assert!(matches!(
                peer.decapsulate(None, &buf[..len], &mut output),
                TunnResult::Done
            ));
        };
        let (verified, ()) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(handshaker.try_handshake(), responder)
        })
        .await
        .unwrap();
        verified.unwrap();
    }

    #[test]
    fn test_handshaker_creation() {
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let _server_pub = PublicKey::from(&server_secret);

        let addr: SocketAddr = "127.0.0.1:51820".parse().unwrap();
        let _h = WireGuardHandshaker::new(client_secret.to_bytes(), server_secret.to_bytes(), addr);
    }
}
