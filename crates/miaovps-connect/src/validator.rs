//! 连接前分步验证 — 确保链路健康后才切路由
//!
//! 验证流程：
//!   1. UDP 端口可达 — UDP socket 发送探测包，超时 3s
//!   2. WireGuard 握手  — 发送 Initiation 包，等待 Response
//!   3. NAT 路由检查    — 确认服务器 NAT 规则存在
//!   4. 出口 IP 验证    — Split Tunnel 切 VPS 后验证出口 IP

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::tunnel::WireGuardHandshaker;

/// 验证结果
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub step: String,
    pub success: bool,
    pub detail: String,
    pub duration_ms: u64,
}

/// 连接验证器 — 分步测试链路
pub struct ConnectionValidator {
    server_addr: SocketAddr,
    client_private_key: [u8; 32],
    server_public_key: [u8; 32],
}

impl ConnectionValidator {
    pub fn new(
        server_addr: SocketAddr,
        client_private_key: [u8; 32],
        server_public_key: [u8; 32],
    ) -> Self {
        Self {
            server_addr,
            client_private_key,
            server_public_key,
        }
    }

    /// 执行全部验证步骤，返回结果列表
    pub async fn validate_all(&self) -> Vec<ValidationResult> {
        let mut results = Vec::new();

        // Step 1: UDP 端口可达
        results.push(self.check_udp_reachable().await);

        // Step 2: WireGuard 握手
        if results.last().map(|r| r.success).unwrap_or(false) {
            results.push(self.check_wireguard_handshake().await);
        } else {
            results.push(ValidationResult {
                step: "WireGuard 握手".into(),
                success: false,
                detail: "跳过 — UDP 不可达".into(),
                duration_ms: 0,
            });
        }

        results
    }

    /// UDP 出站可达性：确认能绑定本地端口并把包送出去
    ///
    /// 这一步**不能**判定服务器可达。WireGuard 是静默协议，对非法包不回复，
    /// 所以「发了没回」是正常现象，不是故障。真正的连通性判定在握手步骤。
    /// 这里只捕获本地故障：无法绑定端口、无路由、地址族不匹配。
    async fn check_udp_reachable(&self) -> ValidationResult {
        let start = std::time::Instant::now();
        let step = "UDP 出站可达";

        debug!("[验证] {} — 目标: {}", step, self.server_addr);

        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                return ValidationResult {
                    step: step.into(),
                    success: false,
                    detail: format!("无法绑定本地 UDP 端口: {e}"),
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        if let Err(e) = socket.connect(self.server_addr).await {
            return ValidationResult {
                step: step.into(),
                success: false,
                detail: format!("无法路由到 {}: {e}（检查本机网络/残留路由）", self.server_addr),
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        // 发一个空包确认出站路径通畅。服务器不会回复，这是预期行为。
        if let Err(e) = socket.send(&[]).await {
            return ValidationResult {
                step: step.into(),
                success: false,
                detail: format!("UDP 发送失败: {e}"),
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        let local = socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());

        info!("[验证] ✅ {} — 出站路径就绪 ({local})", step);
        ValidationResult {
            step: step.into(),
            success: true,
            detail: format!("出站路径就绪 {local} → {}", self.server_addr),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// WireGuard 握手测试
    async fn check_wireguard_handshake(&self) -> ValidationResult {
        let start = std::time::Instant::now();
        let step = "WireGuard 握手";

        debug!("[验证] {} — 发起握手...", step);

        // 每次调用内部新建 Tunn — 见 WireGuardHandshaker 文档
        let handshaker = WireGuardHandshaker::new(
            self.client_private_key,
            self.server_public_key,
            self.server_addr,
        );

        const MAX_RETRIES: u32 = 3;
        let mut last_error = String::new();

        for attempt in 1..=MAX_RETRIES {
            // 外层超时留出余量，让内层的具体错误信息能返回
            match timeout(Duration::from_secs(6), handshaker.try_handshake()).await {
                Ok(Ok(())) => {
                    info!("[验证] ✅ {} — 成功 (第 {attempt} 次尝试)", step);
                    return ValidationResult {
                        step: step.into(),
                        success: true,
                        detail: format!("握手成功 ({attempt}/{MAX_RETRIES} 次尝试)"),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
                Ok(Err(e)) => {
                    warn!("[验证] {step} — 第 {attempt} 次失败: {e}");
                    last_error = e;
                }
                Err(_) => {
                    warn!("[验证] {step} — 第 {attempt} 次整体超时");
                    last_error = "握手整体超时".into();
                }
            }

            if attempt < MAX_RETRIES {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        ValidationResult {
            step: step.into(),
            success: false,
            detail: format!("{MAX_RETRIES} 次尝试均失败: {last_error}"),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::state::{ConnectionState, ValidationStep};

    #[test]
    fn test_validation_step_display() {
        assert_eq!(ValidationStep::CreateTun.to_string(), "创建虚拟网卡");
        assert_eq!(ValidationStep::Handshake.to_string(), "WireGuard 握手");
        assert_eq!(ValidationStep::Complete.to_string(), "全部通过");
    }

    #[test]
    fn test_connection_state_progress() {
        let s = ConnectionState::Disconnected;
        assert_eq!(s.progress_pct(), 0);

        let s = ConnectionState::FullTunnel;
        assert_eq!(s.progress_pct(), 100);

        let s = ConnectionState::Validating {
            step: ValidationStep::Handshake,
            step_num: 3,
            total_steps: 5,
            description: "测试".into(),
        };
        assert_eq!(s.progress_pct(), 60);
    }
}
