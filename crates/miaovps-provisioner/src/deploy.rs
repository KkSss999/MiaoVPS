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

/// 部署步骤状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentProgress {
    pub deployment_id: String,
    pub status: DeploymentStatus,
    pub current_step: Option<DeploymentStep>,
    pub steps: HashMap<DeploymentStep, StepResult>,
    /// 服务器 WireGuard 公钥 —— 客户端连接必需，部署成功后必然有值
    pub server_public_key: Option<String>,
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
        }
    }

    pub fn update_step(&mut self, step: DeploymentStep, result: StepResult) {
        self.steps.insert(step.clone(), result.clone());
        self.current_step = Some(step);
    }

    pub fn fail(&mut self, step: DeploymentStep, reason: String) {
        self.update_step(step.clone(), StepResult::Failed(reason.clone()));
        self.status = DeploymentStatus::Failed;
    }

    pub fn complete(&mut self) {
        self.status = DeploymentStatus::Success;
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
