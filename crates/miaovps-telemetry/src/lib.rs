//! 实时遥测客户端
//!
//! Rust 侧 WebSocket 客户端，连接 VPS Agent 获取实时状态。
//! 不暴露在 WebView 层，通过 Tauri Events 向前端推送。

use serde::{Deserialize, Serialize};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  WebSocket 协议消息
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 客户端请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRequest {
    pub version: u8,
    pub id: String,
    #[serde(rename = "type")]
    pub msg_type: String,
    pub timestamp: i64,
    pub payload: serde_json::Value,
}

/// 服务端响应 / 推送
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub version: u8,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub msg_type: String,
    #[serde(default)]
    pub sequence: Option<u64>,
    pub timestamp: i64,
    pub payload: serde_json::Value,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  节点快照
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeSnapshot {
    pub cpu_usage: f64,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub load_average: Vec<f64>,
    pub uptime_seconds: u64,
    pub wireguard: Option<WireGuardSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WireGuardSnapshot {
    pub interface: String,
    pub running: bool,
    pub listen_port: u16,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Peer 更新
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerUpdate {
    pub peer_id: String,
    pub latest_handshake_at: Option<i64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub endpoint: String,
    pub online: bool,
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Telemetry 客户端
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// 重连退避配置
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            initial_delay_ms: 1000,
            max_delay_ms: 30_000,
            multiplier: 2.0,
        }
    }
}

/// 遥测客户端状态
#[derive(Debug, Clone, PartialEq)]
pub enum TelemetryState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32, next_delay_ms: u64 },
}

/// 遥测客户端（框架）
///
/// 实际 WebSocket 连接使用 tokio-tungstenite，
/// 通过 Tauri events 将数据推送到前端。
pub struct TelemetryClient {
    pub agent_url: String,
    pub state: TelemetryState,
    pub last_sequence: Option<u64>,
    retry_config: RetryConfig,
}

impl TelemetryClient {
    pub fn new(agent_url: String) -> Self {
        Self {
            agent_url,
            state: TelemetryState::Disconnected,
            last_sequence: None,
            retry_config: RetryConfig::default(),
        }
    }

    /// 计算下次重连延迟
    pub fn next_retry_delay(&self, attempt: u32) -> u64 {
        let delay = self.retry_config.initial_delay_ms as f64
            * self.retry_config.multiplier.powi(attempt as i32);
        (delay as u64).min(self.retry_config.max_delay_ms)
    }

    /// 检查序列号是否连续
    pub fn is_sequence_contiguous(&self, new_seq: u64) -> bool {
        match self.last_sequence {
            None => true,
            Some(last) => new_seq == last + 1,
        }
    }

    fn current_timestamp() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    /// 构建请求消息
    pub fn build_request(&self, msg_type: &str, payload: serde_json::Value) -> TelemetryRequest {
        TelemetryRequest {
            version: 1,
            id: uuid::Uuid::new_v4().to_string(),
            msg_type: msg_type.into(),
            timestamp: Self::current_timestamp(),
            payload,
        }
    }

    /// 构建 ping 消息
    pub fn build_ping(&self) -> TelemetryRequest {
        self.build_request("ping", serde_json::json!({}))
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  tests
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_backoff() {
        let client = TelemetryClient::new("wss://10.66.66.1:7443/v1/stream".into());
        assert_eq!(client.next_retry_delay(0), 1000);
        assert_eq!(client.next_retry_delay(1), 2000);
        assert_eq!(client.next_retry_delay(2), 4000);
        assert_eq!(client.next_retry_delay(3), 8000);
        // Should cap at max
        assert_eq!(client.next_retry_delay(10), 30000);
    }

    #[test]
    fn test_sequence_check() {
        let mut client = TelemetryClient::new("ws://test".into());
        assert!(client.is_sequence_contiguous(1));

        client.last_sequence = Some(5);
        assert!(client.is_sequence_contiguous(6));
        assert!(!client.is_sequence_contiguous(8)); // gap
        assert!(!client.is_sequence_contiguous(5)); // duplicate
    }

    #[test]
    fn test_build_request() {
        let client = TelemetryClient::new("ws://test".into());
        let req = client.build_request("get_snapshot", serde_json::json!({}));
        assert_eq!(req.version, 1);
        assert_eq!(req.msg_type, "get_snapshot");
    }
}
