//! Recovery policy shared by the real connection supervisor and deterministic tests.
use std::time::Duration;

pub const RECONNECT_WRONG_INDEX: u64 = 2;
pub const RETRY_STABLE_FOR: Duration = Duration::from_secs(30);
pub const RETRY_CONFIRM_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExit {
    Stopped,
    Restart,
    RetryFailed,
}

#[derive(Debug, Default)]
pub struct RecoveryPolicy {
    pub retrying: bool,
    failures: u8,
}
impl RecoveryPolicy {
    /// True requests a port migration. A successful transport session starts a
    /// new incident; a handshake response alone never resets failed retries.
    pub fn ended(&mut self, outcome: SessionExit) -> bool {
        match outcome {
            SessionExit::Stopped => false,
            SessionExit::Restart => {
                self.retrying = true;
                self.failures = 0;
                false
            }
            SessionExit::RetryFailed => {
                self.failures = self.failures.saturating_add(1);
                self.failures >= 2
            }
        }
    }
    pub fn migrated(&mut self) {
        self.failures = 0;
    }
}

pub fn session_exit(
    wrong_index: u64,
    retrying: bool,
    transport_received: bool,
    stable: bool,
    uptime: Duration,
) -> Option<SessionExit> {
    if retrying && !transport_received && uptime >= RETRY_CONFIRM_TIMEOUT {
        Some(SessionExit::RetryFailed)
    } else if wrong_index >= RECONNECT_WRONG_INDEX {
        Some(if retrying && !stable {
            SessionExit::RetryFailed
        } else {
            SessionExit::Restart
        })
    } else {
        None
    }
}

pub fn deployment_options(
    node: &miaovps_core::WireGuardNode,
    profile_mtu: u16,
    port: u16,
) -> miaovps_provisioner::DeploymentOptions {
    miaovps_provisioner::DeploymentOptions {
        wireguard_port: port,
        vpn_cidr: node.vpn_cidr.clone(),
        dns: node.dns.clone(),
        mtu: node.mtu.or(Some(profile_mtu)),
        ipv6_enabled: node.ipv6_enabled,
        ..miaovps_provisioner::DeploymentOptions::default()
    }
}

pub fn next_port(port: u16) -> anyhow::Result<u16> {
    port.checked_add(1)
        .filter(|p| *p != 0)
        .ok_or_else(|| anyhow::anyhow!("端口已达 65535，无法继续自动增加"))
}

pub fn with_port(args: &[String], port: u16) -> Vec<String> {
    let mut updated = args.to_vec();
    if let Some(i) = updated.iter().position(|a| a == "--port") {
        updated[i + 1] = port.to_string();
    } else {
        updated.extend(["--port".to_string(), port.to_string()]);
    }
    updated
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn two_wrong_indices_request_a_full_restart() {
        assert_eq!(
            session_exit(1, false, true, true, Duration::from_secs(700)),
            None
        );
        assert_eq!(
            session_exit(2, false, true, true, Duration::from_secs(700)),
            Some(SessionExit::Restart)
        );
    }
    #[test]
    fn only_two_failed_retries_migrate_and_a_working_session_resets_failures() {
        let mut p = RecoveryPolicy::default();
        assert!(!p.ended(SessionExit::Restart));
        assert!(p.retrying);
        assert!(!p.ended(SessionExit::RetryFailed));
        assert!(p.ended(SessionExit::RetryFailed));
        p.migrated();
        assert!(!p.ended(SessionExit::RetryFailed));
        assert!(!p.ended(SessionExit::Restart));
        assert!(!p.ended(SessionExit::RetryFailed));
        assert!(p.ended(SessionExit::RetryFailed));
    }
    #[test]
    fn handshake_without_transport_does_not_pass_retry_deadline() {
        assert_eq!(
            session_exit(0, true, false, false, Duration::from_secs(44)),
            None
        );
        assert_eq!(
            session_exit(0, true, false, false, Duration::from_secs(45)),
            Some(SessionExit::RetryFailed)
        );
        assert_eq!(
            session_exit(0, true, true, true, Duration::from_secs(45)),
            None
        );
    }
    #[test]
    fn port_increment_preserves_connect_flags_and_never_wraps() {
        let args: Vec<String> = [
            "miaovps", "connect", "server", "--device", "device", "--dev", "--port", "168",
            "--daemon",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let updated = with_port(&args, next_port(168).unwrap());
        assert_eq!(updated[7], "169");
        assert!(updated.contains(&"--dev".into()));
        assert!(updated.contains(&"--daemon".into()));
        assert!(next_port(65535).is_err());
        let minimal = vec!["miaovps".into(), "connect".into()];
        assert_eq!(&with_port(&minimal, 169)[2..], &["--port", "169"]);
    }
    #[test]
    fn immediate_relapse_is_a_failed_retry_even_if_some_data_arrived() {
        assert_eq!(
            session_exit(2, true, true, false, Duration::from_secs(10)),
            Some(SessionExit::RetryFailed)
        );
        assert_eq!(
            session_exit(2, true, true, true, Duration::from_secs(120)),
            Some(SessionExit::Restart)
        );
    }
    #[test]
    fn migration_preserves_node_network_settings() {
        let mut node = miaovps_core::WireGuardNode::new(
            "server".into(),
            168,
            "10.77.0.0/24".into(),
            "public".into(),
            vec!["9.9.9.9".into()],
        );
        node.mtu = Some(1280);
        node.ipv6_enabled = true;
        let options = deployment_options(&node, 1380, 169);
        assert_eq!(options.wireguard_port, 169);
        assert_eq!(options.vpn_cidr, node.vpn_cidr);
        assert_eq!(options.dns, node.dns);
        assert_eq!(options.mtu, Some(1280));
        assert!(options.ipv6_enabled);
        assert_eq!(node.listen_port, 168);
    }
}
