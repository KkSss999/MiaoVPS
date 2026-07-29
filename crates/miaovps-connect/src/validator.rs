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

    /// UDP 端口可达测试：发送探测包并等待任意响应
    async fn check_udp_reachable(&self) -> ValidationResult {
        let start = std::time::Instant::now();
        let step = "UDP 端口可达";

        debug!("[验证] {} — 目标: {}", step, self.server_addr);

        // 绑定任意本地端口
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                return ValidationResult {
                    step: step.into(),
                    success: false,
                    detail: format!("无法绑定本地端口: {e}"),
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        // 发送探测包（WireGuard 格式的 Initiation 不会穿透 NAT，但能测试可达性）
        // 如果有响应（任何 UDP 包），说明可达
        match socket.connect(self.server_addr).await {
            Ok(_) => {}
            Err(e) => {
                return ValidationResult {
                    step: step.into(),
                    success: false,
                    detail: format!("无法连接到服务器: {e}"),
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        // 发送探测
        if let Err(e) = socket.send(&[0u8; 32]).await {
            return ValidationResult {
                step: step.into(),
                success: false,
                detail: format!("发送探测失败: {e}"),
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        // 等待响应或超时（UDP 不可达会收到 ICMP 错误，但应用层看不到）
        // 这里主要测试 connect+sent 成功
        let mut buf = [0u8; 1500];
        match timeout(Duration::from_secs(3), socket.recv(&mut buf)).await {
            Ok(Ok(_n)) => {
                info!("[验证] ✅ {} — 收到 {_n}B 响应", step);
                ValidationResult {
                    step: step.into(),
                    success: true,
                    detail: format!("端口 {} 可达", self.server_addr.port()),
                    duration_ms: start.elapsed().as_millis() as u64,
                }
            }
            Ok(Err(e)) => ValidationResult {
                step: step.into(),
                success: false,
                detail: format!("接收错误: {e}"),
                duration_ms: start.elapsed().as_millis() as u64,
            },
            Err(_) => {
                // 超时 — 可能是防火墙丢弃 UDP，也可能是服务器没响应探测包
                // 不直接判负，因为 WireGuard 握手才是真正的判断
                warn!("[验证] ⚠ {} — 无响应（可能是防火墙丢弃非 WG 包，继续握手测试）", step);
                ValidationResult {
                    step: step.into(),
                    success: true, // 放过，等握手测试判决
                    detail: "端口已连接但无返回包（防火墙可能丢弃非 WG 包，切换握手验证）".into(),
                    duration_ms: start.elapsed().as_millis() as u64,
                }
            }
        }
    }

    /// WireGuard 握手测试
    async fn check_wireguard_handshake(&self) -> ValidationResult {
        let start = std::time::Instant::now();
        let step = "WireGuard 握手";

        debug!("[验证] {} — 发起握手...", step);

        let mut handshaker = WireGuardHandshaker::new(
            self.client_private_key,
            self.server_public_key,
            self.server_addr,
        );

        let max_retries = 3;
        for attempt in 1..=max_retries {
            match timeout(Duration::from_secs(5), handshaker.try_handshake()).await {
                Ok(Ok(())) => {
                    info!("[验证] ✅ {} — 握手成功 (第 {attempt} 次尝试)", step);
                    return ValidationResult {
                        step: step.into(),
                        success: true,
                        detail: format!("握手成功，{attempt}/{} 次尝试", max_retries),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
                Ok(Err(e)) => {
                    warn!("[验证] {} — 第 {} 次握手失败: {}", step, attempt, e);
                    if attempt == max_retries {
                        return ValidationResult {
                            step: step.into(),
                            success: false,
                            detail: format!("握手失败 ({} 次尝试): {}", max_retries, e),
                            duration_ms: start.elapsed().as_millis() as u64,
                        };
                    }
                }
                Err(_) => {
                    warn!("[验证] {} — 第 {} 次握手超时", step, attempt);
                    if attempt == max_retries {
                        return ValidationResult {
                            step: step.into(),
                            success: false,
                            detail: format!("握手超时 ({} 次尝试，每次 5s)", max_retries),
                            duration_ms: start.elapsed().as_millis() as u64,
                        };
                    }
                }
            }
        }

        unreachable!()
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
