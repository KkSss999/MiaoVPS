//! 部署状态机
//!
//! 9 步 WireGuard 部署流程，支持幂等、备份、回滚。

use miaovps_core::{DeploymentStatus, DeploymentStep};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 单步执行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StepResult {
    Pending,
    Running,
    Success,
    Warning(String),
    Failed(String),
}

/// 单步状态变更事件 —— 部署过程中实时推送
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepEvent {
    pub step: DeploymentStep,
    pub result: StepResult,
}

/// 步骤事件发送端 —— 由调用方创建并传入 `deploy`
pub type StepSender = tokio::sync::mpsc::UnboundedSender<StepEvent>;

/// 步骤事件接收端 —— CLI 打印进度，前端转发为 Tauri event
pub type StepReceiver = tokio::sync::mpsc::UnboundedReceiver<StepEvent>;

/// 部署步骤状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentProgress {
    pub deployment_id: String,
    pub status: DeploymentStatus,
    pub current_step: Option<DeploymentStep>,
    pub steps: HashMap<DeploymentStep, StepResult>,
    /// 服务器 WireGuard 公钥 —— 客户端连接必需，部署成功后必然有值
    pub server_public_key: Option<String>,
    /// 事件推送端。不参与序列化 —— 它是进程内通道，跨 IPC 无意义。
    ///
    /// 挂在这里而不是让 `deploy()` 显式回调每一步：9 步流程里的
    /// `update_step` / `fail` 调用点有二十余处，漏一处就少一个事件。
    /// 由 `update_step` 统一发送，新增步骤自动获得事件。
    #[serde(skip)]
    sink: Option<StepSender>,
}

impl DeploymentProgress {
    pub fn new(deployment_id: String) -> Self {
        let mut steps = HashMap::new();
        for step in DeploymentStep::all_steps() {
            steps.insert(step, StepResult::Pending);
        }
        Self {
            deployment_id,
            status: DeploymentStatus::Pending,
            current_step: None,
            steps,
            server_public_key: None,
            sink: None,
        }
    }

    /// 挂上事件推送端
    ///
    /// 用 unbounded 通道：部署步骤总数固定（9 步 × 若干状态变更），
    /// 且发送方在 async 上下文里不能阻塞在满通道上。
    pub fn set_sink(&mut self, sink: StepSender) {
        self.sink = Some(sink);
    }

    pub fn update_step(&mut self, step: DeploymentStep, result: StepResult) {
        self.steps.insert(step.clone(), result.clone());
        self.current_step = Some(step.clone());
        if let Some(tx) = &self.sink {
            // 接收端提前 drop 不是错误 —— 调用方可能只关心最终结果
            let _ = tx.send(StepEvent { step, result });
        }
    }

    pub fn fail(&mut self, step: DeploymentStep, reason: String) {
        self.update_step(step.clone(), StepResult::Failed(reason.clone()));
        self.status = DeploymentStatus::Failed;
    }

    pub fn complete(&mut self) {
        self.status = DeploymentStatus::Success;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_progress_starts_all_pending() {
        let p = DeploymentProgress::new("d1".into());
        assert_eq!(p.steps.len(), 9);
        assert!(p.steps.values().all(|r| matches!(r, StepResult::Pending)));
        assert!(p.current_step.is_none());
        assert!(p.server_public_key.is_none());
    }

    #[test]
    fn update_step_emits_event_when_sink_attached() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut p = DeploymentProgress::new("d1".into());
        p.set_sink(tx);

        p.update_step(DeploymentStep::Connect, StepResult::Running);
        p.update_step(DeploymentStep::Connect, StepResult::Success);

        let first = rx.try_recv().unwrap();
        assert_eq!(first.step, DeploymentStep::Connect);
        assert!(matches!(first.result, StepResult::Running));

        let second = rx.try_recv().unwrap();
        assert!(matches!(second.result, StepResult::Success));
    }

    /// `fail` 走 update_step，所以失败也必须发事件 —— 否则前端看不到哪一步炸了
    #[test]
    fn fail_emits_event_and_sets_failed_status() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut p = DeploymentProgress::new("d1".into());
        p.set_sink(tx);

        p.fail(DeploymentStep::StartService, "systemd 起不来".into());

        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.step, DeploymentStep::StartService);
        match ev.result {
            StepResult::Failed(reason) => assert_eq!(reason, "systemd 起不来"),
            other => panic!("应为 Failed，实际 {other:?}"),
        }
        assert_eq!(p.status, DeploymentStatus::Failed);
    }

    /// 没挂 sink 时不能 panic —— `deploy()` 就是这条路径
    #[test]
    fn update_step_without_sink_is_silent() {
        let mut p = DeploymentProgress::new("d1".into());
        p.update_step(DeploymentStep::Verify, StepResult::Success);
        assert_eq!(p.current_step, Some(DeploymentStep::Verify));
    }

    /// 接收端提前 drop 只是没人听，不能让部署失败
    #[test]
    fn dropped_receiver_does_not_break_updates() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut p = DeploymentProgress::new("d1".into());
        p.set_sink(tx);
        drop(rx);

        p.update_step(DeploymentStep::Backup, StepResult::Success);
        p.complete();
        assert_eq!(p.status, DeploymentStatus::Success);
    }

    /// sink 不参与序列化 —— 它是进程内通道，跨 IPC 传不了
    #[test]
    fn progress_serializes_without_sink() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut p = DeploymentProgress::new("d1".into());
        p.set_sink(tx);
        p.server_public_key = Some("pk".into());

        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("sink"));

        let back: DeploymentProgress = serde_json::from_str(&json).unwrap();
        assert_eq!(back.server_public_key.as_deref(), Some("pk"));
    }
}

/// 部署选项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentOptions {
    pub wireguard_port: u16,
    pub vpn_cidr: String,
    pub dns: Vec<String>,
    pub mtu: Option<u16>,
    pub ipv6_enabled: bool,
    pub allow_peer_communication: bool,
}

impl Default for DeploymentOptions {
    fn default() -> Self {
        Self {
            wireguard_port: 51820,
            vpn_cidr: "10.66.66.0/24".into(),
            dns: vec!["1.1.1.1".into()],
            mtu: Some(1380),
            ipv6_enabled: false,
            allow_peer_communication: false,
        }
    }
}
