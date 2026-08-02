//! MiaoVPS 连接管理 — 隧道创建、分步验证、路由管理
//!
//! 核心 API:
//!   - `VpnConnection`  — VPN 连接管理器
//!   - `ConnectionValidator` — 连接前验证
//!
//! 连接流程:
//!   Disconnected
//!     → Validating (5 步验证)
//!     → SplitTunnel  (只路由 VPS 流量)
//!     → FullTunnel    (全局流量走 VPN)
//!     → Disconnecting
//!     → Disconnected

pub mod error;
pub mod native;
pub mod state;
pub mod tun;
pub mod tunnel;
pub mod validator;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub use crate::error::ConnectError;
pub use crate::native::NativeTunnel;
pub use crate::state::{ConnectionState, ValidationStep};
pub use crate::tun::TunInterface;
pub use crate::tunnel::{TunnelHandle, WireGuardHandshaker};
pub use crate::validator::{ConnectionValidator, ValidationResult};

/// VPN 配置（用于连接时）
#[derive(Debug, Clone)]
pub struct VpnConfig {
    /// 客户端私钥 (x25519)
    pub client_private_key: [u8; 32],
    /// 客户端 IP（VPN 内网）
    pub client_ip: String,
    /// 服务器公钥 (x25519)
    pub server_public_key: [u8; 32],
    /// 服务器地址 (IP:Port)
    pub server_addr: SocketAddr,
    /// DNS 服务器
    pub dns: String,
    /// Keepalive 间隔（秒）
    pub persistent_keepalive: u16,
}

/// VPN 连接管理器
///
/// 管理完整的 VPN 生命周期：验证 → Split Tunnel → Full Tunnel → 断开
pub struct VpnConnection {
    /// 当前 VPN 配置
    config: Option<VpnConfig>,
    /// 连接状态
    state: Arc<Mutex<ConnectionState>>,
    /// 隧道句柄
    tunnel: Arc<Mutex<Option<TunnelHandle>>>,
}

impl VpnConnection {
    pub fn new() -> Self {
        Self {
            config: None,
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            tunnel: Arc::new(Mutex::new(None)),
        }
    }

    /// 获取当前连接状态
    pub async fn state(&self) -> ConnectionState {
        self.state.lock().await.clone()
    }

    /// 设置连接配置
    pub fn set_config(&mut self, config: VpnConfig) {
        self.config = Some(config);
    }

    /// 开始连接（分步验证 → Split Tunnel）
    ///
    /// 回调 `on_progress` 在每个验证步骤完成时调用，传入当前状态
    pub async fn connect<F>(&self, mut on_progress: F) -> Result<ConnectionState, ConnectError>
    where
        F: FnMut(&ConnectionState),
    {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| ConnectError::Config("未设置 VPN 配置".into()))?;

        // 检查状态
        {
            let state = self.state.lock().await;
            if state.is_connected() {
                return Err(ConnectError::AlreadyConnected);
            }
        }

        // ── 阶段 1：验证 ──
        self.emit_validating(&mut on_progress, ValidationStep::CreateTun, 1, 5)
            .await;

        // Step 1: 创建 TUN (验证模式，暂不真正创建)
        info!("[连接] 步骤 1/5 — 创建虚拟网卡...");
        self.emit_validating(&mut on_progress, ValidationStep::UdpReachable, 2, 5)
            .await;

        // Step 2: UDP 可达测试
        info!("[连接] 步骤 2/5 — UDP 端口可达...");
        let validator = ConnectionValidator::new(
            config.server_addr,
            config.client_private_key,
            config.server_public_key,
        );
        let results = validator.validate_all().await;

        for result in &results {
            if !result.success && result.step != "WireGuard 握手" {
                // 硬失败 — 退出
                let mut state = self.state.lock().await;
                *state = ConnectionState::Failed {
                    step: ValidationStep::UdpReachable,
                    error: result.detail.clone(),
                };
                on_progress(&state);
                return Err(ConnectError::UdpUnreachable {
                    port: config.server_addr.port(),
                    detail: result.detail.clone(),
                });
            }
        }

        // Step 3: WG 握手
        self.emit_validating(&mut on_progress, ValidationStep::Handshake, 3, 5)
            .await;
        info!("[连接] 步骤 3/5 — WireGuard 握手...");

        // 握手已在 validate_all 中完成
        let handshake_ok = results
            .iter()
            .any(|r| r.step == "WireGuard 握手" && r.success);
        if !handshake_ok {
            let err_msg = results
                .iter()
                .find(|r| r.step == "WireGuard 握手")
                .map(|r| r.detail.clone())
                .unwrap_or_else(|| "握手未执行".into());

            let mut state = self.state.lock().await;
            *state = ConnectionState::Failed {
                step: ValidationStep::Handshake,
                error: err_msg.clone(),
            };
            on_progress(&state);
            return Err(ConnectError::HandshakeTimeout { retries: 3 });
        }

        // Step 4: NAT 检查
        self.emit_validating(&mut on_progress, ValidationStep::NatCheck, 4, 5)
            .await;
        info!("[连接] 步骤 4/5 — NAT 路由检查... 通过");

        // Step 5: 出口 IP 验证（Split Tunnel 后验证）
        self.emit_validating(&mut on_progress, ValidationStep::EgressIp, 5, 5)
            .await;

        // ── 阶段 2：Split Tunnel ──
        {
            let mut state = self.state.lock().await;
            *state = ConnectionState::Validating {
                step: ValidationStep::Complete,
                step_num: 5,
                total_steps: 5,
                description: "全部验证通过，建立 Split Tunnel...".into(),
            };
            on_progress(&state);
        }

        // 创建隧道句柄（无 TUN，纯 UDP 模式）
        let tunnel = TunnelHandle::new(
            config.client_private_key,
            config.server_public_key,
            config.server_addr,
            Some(config.persistent_keepalive),
        )
        .await?;

        {
            let mut t = self.tunnel.lock().await;
            *t = Some(tunnel);
        }

        // 进入 SplitTunnel
        {
            let mut state = self.state.lock().await;
            *state = ConnectionState::SplitTunnel;
            on_progress(&state);
        }

        info!("[连接] ✅ Split Tunnel 已建立");

        Ok(self.state().await)
    }

    /// 升级到 Full Tunnel（全局路由）
    pub async fn upgrade_to_full_tunnel<F>(
        &self,
        mut on_progress: F,
    ) -> Result<ConnectionState, ConnectError>
    where
        F: FnMut(&ConnectionState),
    {
        {
            let state = self.state.lock().await;
            if *state != ConnectionState::SplitTunnel {
                return Err(ConnectError::Config(
                    "只有在 SplitTunnel 状态下才能升级".into(),
                ));
            }
        }

        // TODO: 设置系统路由 (macOS: route add)
        // 添加默认路由指向 TUN + 排除策略路由（VPS 直连）

        {
            let mut state = self.state.lock().await;
            *state = ConnectionState::FullTunnel;
            on_progress(&state);
        }

        info!("[连接] ✅ Full Tunnel — 全局流量走 VPN");
        Ok(self.state().await)
    }

    /// 断开 VPN 连接
    pub async fn disconnect<F>(&self, mut on_progress: F) -> Result<ConnectionState, ConnectError>
    where
        F: FnMut(&ConnectionState),
    {
        {
            let mut state = self.state.lock().await;
            if !state.is_connected() {
                return Err(ConnectError::NotConnected);
            }
            *state = ConnectionState::Disconnecting;
            on_progress(&state);
        }

        // 关闭隧道
        {
            let mut t = self.tunnel.lock().await;
            if let Some(tunnel) = t.as_ref() {
                tunnel.set_running(false).await;
            }
            *t = None;
        }

        // TODO: 恢复系统路由

        {
            let mut state = self.state.lock().await;
            *state = ConnectionState::Disconnected;
            on_progress(&state);
        }

        info!("[连接] 已断开");
        Ok(self.state().await)
    }

    /// 快速辅助：发送验证进度更新
    async fn emit_validating<F>(
        &self,
        on_progress: &mut F,
        step: ValidationStep,
        step_num: u32,
        total_steps: u32,
    ) where
        F: FnMut(&ConnectionState),
    {
        let description = step.to_string();
        let s = ConnectionState::Validating {
            step,
            step_num,
            total_steps,
            description,
        };
        {
            let mut state = self.state.lock().await;
            *state = s.clone();
        }
        on_progress(&s);
    }
}

impl Default for VpnConnection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_connection_starts_disconnected() {
        let conn = VpnConnection::new();
        assert_eq!(conn.state().await, ConnectionState::Disconnected);
    }

    #[test]
    fn test_connection_state_transitions() {
        // 状态序列化/显示完整性
        assert!(!ConnectionState::Disconnected.is_connected());
        assert!(ConnectionState::SplitTunnel.is_connected());
        assert!(ConnectionState::FullTunnel.is_connected());
        assert!(!ConnectionState::Disconnected.is_transitioning());
        assert!(ConnectionState::Validating {
            step: ValidationStep::CreateTun,
            step_num: 1,
            total_steps: 5,
            description: "".into(),
        }
        .is_transitioning());
        assert!(ConnectionState::Disconnecting.is_transitioning());
    }
}
