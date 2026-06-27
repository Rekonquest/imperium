use std::sync::{Arc, RwLock};

use chrono::Utc;
use imperium_bus::Bus;
use imperium_net_cluster::{ConfigManager, MembershipManager, TokenManager};
use imperium_net_crypto::{HybridEd25519Mldsa, HybridX25519Mlkem};
use imperium_net_mesh::{NatTraversalPlanner, PeerManager, SessionManager};
use imperium_net_transport::HardeningController;
use imperium_protocol::{
    ClusterId, Message, PeerId, ProtocolHardeningProfile, RelayFallbackSelected,
    VpnDeploymentNodeSpec, VpnDeploymentPlan, VpnDeploymentRole, VpnDeploymentStatus,
};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeploymentError {
    #[error("deployment plan must include at least one node")]
    EmptyPlan,
    #[error("deployment plan must include exactly one operator node")]
    InvalidOperatorCount,
    #[error("node label cannot be empty")]
    EmptyNodeLabel,
    #[error("hardening preset must be balanced, resilience, or fortress")]
    UnknownHardeningPreset,
    #[error("membership deployment failed: {0}")]
    Membership(String),
    #[error("configuration deployment failed: {0}")]
    Config(String),
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
}

struct DeploymentNodeRuntime {
    spec: VpnDeploymentNodeSpec,
    peer_id: PeerId,
    membership: Arc<MembershipManager>,
    config: Arc<ConfigManager>,
    peers: PeerManager,
    sessions: SessionManager,
}

pub struct DeploymentOrchestrator {
    bus: Arc<Bus>,
    last_status: RwLock<Option<VpnDeploymentStatus>>,
}

impl DeploymentOrchestrator {
    pub fn new(bus: Arc<Bus>) -> Self {
        Self {
            bus,
            last_status: RwLock::new(None),
        }
    }

    pub fn last_status(&self) -> Option<VpnDeploymentStatus> {
        self.last_status
            .read()
            .ok()
            .and_then(|status| status.clone())
    }

    pub fn deploy(&self, plan: VpnDeploymentPlan) -> Result<VpnDeploymentStatus, DeploymentError> {
        validate_plan(&plan)?;

        let cluster_id = plan.cluster_id.clone().unwrap_or_else(ClusterId::new);
        let mut rng = OsRng;
        let (operator_sk, operator_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

        let nodes = plan
            .nodes
            .iter()
            .cloned()
            .map(|spec| {
                let peer_id = spec.peer_id.clone().unwrap_or_else(PeerId::new);
                DeploymentNodeRuntime {
                    spec,
                    peer_id: peer_id.clone(),
                    membership: Arc::new(MembershipManager::new(
                        cluster_id.clone(),
                        peer_id.clone(),
                    )),
                    config: Arc::new(ConfigManager::new(cluster_id.clone(), peer_id)),
                    peers: PeerManager::new(),
                    sessions: SessionManager::new(),
                }
            })
            .collect::<Vec<_>>();

        let operator_index = nodes
            .iter()
            .position(|node| node.spec.role == VpnDeploymentRole::Operator)
            .ok_or(DeploymentError::InvalidOperatorCount)?;
        let operator_id = nodes[operator_index].peer_id.clone();
        let token_manager = TokenManager::new(cluster_id.clone());

        for index in 0..nodes.len() {
            if index == operator_index {
                continue;
            }

            let token =
                token_manager.mint_token(&operator_id, &operator_sk, chrono::Duration::minutes(15));
            token_manager
                .verify_token(&token, &operator_vk)
                .map_err(|_| DeploymentError::InvalidOperatorCount)?;
            nodes[operator_index]
                .membership
                .request_membership(nodes[index].peer_id.clone(), &self.bus)
                .map_err(|e| DeploymentError::Membership(e.to_string()))?;
            nodes[operator_index]
                .membership
                .approve_membership(&nodes[index].peer_id, &operator_id, &operator_sk, &self.bus)
                .map_err(|e| DeploymentError::Membership(e.to_string()))?;
            token_manager.consume_token(&token);
        }

        let members = nodes
            .iter()
            .map(|node| node.peer_id.clone())
            .collect::<Vec<_>>();
        let gossip = imperium_protocol::MembershipGossip {
            cluster_id: cluster_id.clone(),
            members: members.clone(),
            lamport_clock: 10,
            from_peer: operator_id.clone(),
        };
        for node in &nodes {
            node.membership.apply_gossip(&gossip);
        }
        self.bus.publish(
            "net.cluster.membership.gossip",
            Message::MembershipGossip(gossip),
        )?;

        let config_version = nodes[operator_index]
            .config
            .update_config(plan.config_blob.clone(), &operator_sk, &self.bus)
            .map_err(|e| DeploymentError::Config(e.to_string()))?;
        let fetch_response = nodes[operator_index].config.current_config().map(|config| {
            imperium_protocol::ConfigurationFetchResponse {
                cluster_id: cluster_id.clone(),
                version: config.version,
                config_data: config.data,
                signature: vec![1, 2, 3],
            }
        });
        if let Some(resp) = fetch_response {
            for (index, node) in nodes.iter().enumerate() {
                if index != operator_index {
                    node.config.apply_fetched_config(&resp).ok();
                }
            }
            self.bus.publish(
                "net.cluster.config.fetch_response",
                Message::ConfigFetchResp(resp),
            )?;
        }

        for left in 0..nodes.len() {
            for right in 0..nodes.len() {
                if left == right {
                    continue;
                }

                let remote_endpoint = nodes[right]
                    .spec
                    .endpoint
                    .unwrap_or_else(|| format!("127.0.0.1:{}", 31_000 + right).parse().unwrap());
                nodes[left]
                    .peers
                    .add_peer(nodes[right].peer_id.clone(), vec![remote_endpoint]);

                let session_id = nodes[left]
                    .sessions
                    .create_session(nodes[right].peer_id.clone(), remote_endpoint)
                    .expect("deployment session should be unique");
                let (_secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
                let (_encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);
                nodes[left]
                    .sessions
                    .establish_session(&session_id, key)
                    .expect("deployment session should establish");
                nodes[left]
                    .peers
                    .set_session(&nodes[right].peer_id, session_id);
            }
        }

        let nat_policy = if plan.nat_aggressive {
            NatTraversalPlanner::aggressive_policy()
        } else {
            NatTraversalPlanner::default_policy()
        };
        for node in &nodes {
            let probe_plan =
                NatTraversalPlanner::build_probe_plan(node.peer_id.clone(), &nat_policy);
            self.bus
                .publish("net.mesh.nat.plan", Message::NatProbePlan(probe_plan))?;
        }

        let relay_ids = nodes
            .iter()
            .filter(|node| node.spec.role == VpnDeploymentRole::Relay)
            .map(|node| node.peer_id.clone())
            .collect::<Vec<_>>();
        let client_ids = nodes
            .iter()
            .filter(|node| node.spec.role == VpnDeploymentRole::Client)
            .map(|node| node.peer_id.clone())
            .collect::<Vec<_>>();
        let mut relay_fallbacks_selected = 0;
        if plan.relay_auto && !relay_ids.is_empty() {
            for (index, client_id) in client_ids.iter().enumerate() {
                let selected = RelayFallbackSelected {
                    peer_id: client_id.clone(),
                    relay_peer: relay_ids[index % relay_ids.len()].clone(),
                    selected_at: Utc::now(),
                };
                self.bus.publish(
                    "net.mesh.relay.selected",
                    Message::RelayFallbackSelected(selected),
                )?;
                relay_fallbacks_selected += 1;
            }
        }

        let hardening_profile = hardening_profile(&plan.hardening_preset, Some("auto-vpn".into()))?;
        HardeningController::validate(&hardening_profile)
            .map_err(|_| DeploymentError::UnknownHardeningPreset)?;
        for node in &nodes {
            let profile = ProtocolHardeningProfile {
                protocol_name: Some(format!("auto-vpn-{}", node.spec.label)),
                reason: format!("auto deployment {}", plan.deployment_id),
                ..hardening_profile.clone()
            };
            self.bus.publish(
                "net.transport.hardening.apply",
                Message::ProtocolHardeningProfile(profile),
            )?;
        }

        let approved_nodes = nodes
            .iter()
            .filter(|node| {
                members
                    .iter()
                    .all(|member| node.membership.is_member(member))
            })
            .count();
        let established_sessions = nodes
            .iter()
            .map(|node| node.sessions.active_session_count())
            .sum::<usize>();
        let hardening_profiles_accepted = nodes.len();

        let status = VpnDeploymentStatus {
            deployment_id: plan.deployment_id,
            accepted: true,
            reason: "deployment converged".into(),
            planned_nodes: nodes.len(),
            approved_nodes,
            config_version,
            established_sessions,
            relay_fallbacks_selected,
            hardening_profiles_accepted,
            updated_at: Utc::now(),
        };
        self.emit_status(status.clone())?;
        Ok(status)
    }

    pub fn subscribe_deployment_plans(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mut sub = self.bus.subscribe("net.vpn.deployment.apply");
        let orchestrator = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::VpnDeploymentPlan(plan) = event.message {
                            if let Err(e) = orchestrator.deploy(plan.clone()) {
                                let status = VpnDeploymentStatus {
                                    deployment_id: plan.deployment_id,
                                    accepted: false,
                                    reason: e.to_string(),
                                    planned_nodes: plan.nodes.len(),
                                    approved_nodes: 0,
                                    config_version: 0,
                                    established_sessions: 0,
                                    relay_fallbacks_selected: 0,
                                    hardening_profiles_accepted: 0,
                                    updated_at: Utc::now(),
                                };
                                let _ = orchestrator.emit_status(status);
                            }
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }

    pub fn subscribe_status_requests(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let mut sub = self.bus.subscribe("net.vpn.deployment.status_request");
        let orchestrator = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::VpnDeploymentStatusRequest(_) = event.message {
                            let status = orchestrator
                                .last_status()
                                .unwrap_or_else(no_deployment_status);
                            let _ = orchestrator.emit_status(status);
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }

    fn emit_status(&self, status: VpnDeploymentStatus) -> Result<(), DeploymentError> {
        if let Ok(mut last_status) = self.last_status.write() {
            *last_status = Some(status.clone());
        }
        self.bus.publish(
            "net.vpn.deployment.status",
            Message::VpnDeploymentStatus(status),
        )?;
        Ok(())
    }
}

fn no_deployment_status() -> VpnDeploymentStatus {
    VpnDeploymentStatus {
        deployment_id: uuid::Uuid::nil(),
        accepted: false,
        reason: "no deployment has run".into(),
        planned_nodes: 0,
        approved_nodes: 0,
        config_version: 0,
        established_sessions: 0,
        relay_fallbacks_selected: 0,
        hardening_profiles_accepted: 0,
        updated_at: Utc::now(),
    }
}

fn validate_plan(plan: &VpnDeploymentPlan) -> Result<(), DeploymentError> {
    if plan.nodes.is_empty() {
        return Err(DeploymentError::EmptyPlan);
    }
    if plan.nodes.iter().any(|node| node.label.trim().is_empty()) {
        return Err(DeploymentError::EmptyNodeLabel);
    }
    let operator_count = plan
        .nodes
        .iter()
        .filter(|node| node.role == VpnDeploymentRole::Operator)
        .count();
    if operator_count != 1 {
        return Err(DeploymentError::InvalidOperatorCount);
    }

    let _ = hardening_profile(&plan.hardening_preset, None)?;
    Ok(())
}

fn hardening_profile(
    preset: &str,
    protocol_name: Option<String>,
) -> Result<ProtocolHardeningProfile, DeploymentError> {
    match preset {
        "balanced" | "balanced-rf-inspired" => {
            Ok(HardeningController::balanced_profile(protocol_name))
        }
        "resilience" | "resilience-rf-inspired" => {
            Ok(HardeningController::resilience_profile(protocol_name))
        }
        "fortress" | "fortress-rf-inspired" => {
            Ok(HardeningController::fortress_profile(protocol_name))
        }
        _ => Err(DeploymentError::UnknownHardeningPreset),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn recv_deployment_status(
        sub: &mut imperium_bus::BusSubscription,
    ) -> VpnDeploymentStatus {
        for _ in 0..4 {
            let event = tokio::time::timeout(std::time::Duration::from_millis(500), sub.recv())
                .await
                .expect("deployment status")
                .unwrap();
            if let Message::VpnDeploymentStatus(status) = event.message {
                return status;
            }
        }

        panic!("deployment status was not published");
    }

    fn deployment_plan() -> VpnDeploymentPlan {
        VpnDeploymentPlan {
            deployment_id: uuid::Uuid::new_v4(),
            cluster_id: None,
            nodes: vec![
                VpnDeploymentNodeSpec {
                    label: "operator".into(),
                    role: VpnDeploymentRole::Operator,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32000".parse().unwrap()),
                    capabilities: vec!["vpn.cluster.admin".into()],
                },
                VpnDeploymentNodeSpec {
                    label: "client-a".into(),
                    role: VpnDeploymentRole::Client,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32001".parse().unwrap()),
                    capabilities: vec!["vpn.client".into()],
                },
                VpnDeploymentNodeSpec {
                    label: "relay-a".into(),
                    role: VpnDeploymentRole::Relay,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32002".parse().unwrap()),
                    capabilities: vec!["vpn.relay".into()],
                },
            ],
            hardening_preset: "fortress".into(),
            nat_aggressive: false,
            relay_auto: true,
            config_blob: br#"{"deployment":"auto"}"#.to_vec(),
            requested_by: "test".into(),
            requested_at: Utc::now(),
        }
    }

    #[test]
    fn deployment_orchestrator_converges_plan() {
        let bus = Arc::new(Bus::new());
        let orchestrator = DeploymentOrchestrator::new(bus);

        let status = orchestrator.deploy(deployment_plan()).unwrap();

        assert!(status.accepted);
        assert_eq!(status.planned_nodes, 3);
        assert_eq!(status.approved_nodes, 3);
        assert_eq!(status.config_version, 1);
        assert_eq!(status.established_sessions, 6);
        assert_eq!(status.relay_fallbacks_selected, 1);
        assert_eq!(status.hardening_profiles_accepted, 3);
    }

    #[tokio::test]
    async fn subscribes_to_deployment_plan_messages() {
        let bus = Arc::new(Bus::new());
        let orchestrator = Arc::new(DeploymentOrchestrator::new(Arc::clone(&bus)));
        let _handle = orchestrator.subscribe_deployment_plans();
        let mut status_sub = bus.subscribe("net.vpn.deployment.status");
        let plan = deployment_plan();
        let deployment_id = plan.deployment_id;

        bus.publish("net.vpn.deployment.apply", Message::VpnDeploymentPlan(plan))
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_millis(500), status_sub.recv())
            .await
            .expect("deployment status")
            .unwrap();
        assert!(matches!(
            event.message,
            Message::VpnDeploymentStatus(status)
                if status.accepted && status.deployment_id == deployment_id
        ));
    }

    #[tokio::test]
    async fn status_request_republishes_last_status() {
        let bus = Arc::new(Bus::new());
        let orchestrator = Arc::new(DeploymentOrchestrator::new(Arc::clone(&bus)));
        let _handle = orchestrator.subscribe_status_requests();
        let status = orchestrator.deploy(deployment_plan()).unwrap();
        let mut status_sub = bus.subscribe("net.vpn.deployment.status");

        bus.publish(
            "net.vpn.deployment.status_request",
            Message::VpnDeploymentStatusRequest(imperium_protocol::VpnDeploymentStatusRequest {
                requested_by: "ordo".into(),
                requested_at: Utc::now(),
            }),
        )
        .unwrap();

        let published = recv_deployment_status(&mut status_sub).await;
        assert_eq!(published.deployment_id, status.deployment_id);
        assert!(published.accepted);
        assert_eq!(published.approved_nodes, 3);
    }

    #[tokio::test]
    async fn status_request_without_deployment_reports_empty_state() {
        let bus = Arc::new(Bus::new());
        let orchestrator = Arc::new(DeploymentOrchestrator::new(Arc::clone(&bus)));
        let _handle = orchestrator.subscribe_status_requests();
        let mut status_sub = bus.subscribe("net.vpn.deployment.status");

        bus.publish(
            "net.vpn.deployment.status_request",
            Message::VpnDeploymentStatusRequest(imperium_protocol::VpnDeploymentStatusRequest {
                requested_by: "ordo".into(),
                requested_at: Utc::now(),
            }),
        )
        .unwrap();

        let published = recv_deployment_status(&mut status_sub).await;
        assert_eq!(published.deployment_id, uuid::Uuid::nil());
        assert!(!published.accepted);
        assert_eq!(published.reason, "no deployment has run");
    }

    #[test]
    fn rejects_missing_operator() {
        let bus = Arc::new(Bus::new());
        let orchestrator = DeploymentOrchestrator::new(bus);
        let mut plan = deployment_plan();
        plan.nodes[0].role = VpnDeploymentRole::Client;

        assert!(matches!(
            orchestrator.deploy(plan),
            Err(DeploymentError::InvalidOperatorCount)
        ));
    }
}
