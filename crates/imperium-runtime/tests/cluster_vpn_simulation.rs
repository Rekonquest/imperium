use std::sync::Arc;
use std::time::Duration;

use imperium_bus::Bus;
use imperium_net_cluster::{AccessPolicy, ConfigManager, MembershipManager, TokenManager};
use imperium_net_crypto::{HybridEd25519Mldsa, HybridX25519Mlkem};
use imperium_net_mesh::{NatTraversalPlanner, PeerManager, PeerState, SessionManager};
use imperium_net_transport::{
    HardeningController, Orchestrator, OrchestratorConfig, OrchestratorPolicy,
};
use imperium_protocol::{
    ClusterId, IdentityCapabilityGrant, Message, NatTraversalMode, OrchestratorDecision,
    OrchestratorState, PathMetrics, PeerId, ProtocolEvent, ProtocolEventKind,
    ProtocolHardeningProfile, ProtocolRole, ProtocolStatus, RelayFallbackRequest,
    RelayFallbackSelected, SuggestedAction, ThreatAssessment, ThreatSource,
};
use rand::rngs::OsRng;

struct SimClusterNode {
    id: PeerId,
    membership: Arc<MembershipManager>,
    config: Arc<ConfigManager>,
    peers: PeerManager,
    sessions: SessionManager,
}

impl SimClusterNode {
    fn new(cluster_id: ClusterId, id: PeerId) -> Self {
        Self {
            id: id.clone(),
            membership: Arc::new(MembershipManager::new(cluster_id.clone(), id.clone())),
            config: Arc::new(ConfigManager::new(cluster_id, id.clone())),
            peers: PeerManager::new(),
            sessions: SessionManager::new(),
        }
    }

    fn endpoint(&self, port: u16) -> std::net::SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeploymentRole {
    Operator,
    Client,
    Relay,
}

struct DeploymentNode {
    role: DeploymentRole,
    port: u16,
    node: SimClusterNode,
}

#[derive(Debug, Default)]
struct AutoDeploymentReport {
    planned_nodes: usize,
    approved_nodes: usize,
    config_version: u64,
    established_sessions: usize,
    relay_fallbacks_selected: usize,
    hardening_profiles_accepted: usize,
    denied_shutdown_capabilities: usize,
    default_nat_plans: usize,
    aggressive_nat_plans: usize,
}

fn establish_mesh_session(
    node: &SimClusterNode,
    peer_id: PeerId,
    remote_addr: std::net::SocketAddr,
) {
    let session_id = node
        .sessions
        .create_session(peer_id.clone(), remote_addr)
        .unwrap();
    let mut rng = OsRng;
    let (_secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
    let (_encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);

    node.sessions.establish_session(&session_id, key).unwrap();
    node.peers.set_session(&peer_id, session_id);
}

fn deployment_capabilities(role: DeploymentRole) -> Vec<String> {
    match role {
        DeploymentRole::Operator => vec![
            "vpn.control".into(),
            "vpn.hardening.apply".into(),
            "vpn.cluster.admin".into(),
        ],
        DeploymentRole::Client => vec!["vpn.control".into(), "vpn.client".into()],
        DeploymentRole::Relay => vec!["vpn.relay".into(), "vpn.client".into()],
    }
}

async fn distribute_latest_config(
    bus: &Arc<Bus>,
    operator: &DeploymentNode,
    nodes: &[DeploymentNode],
    signing_key: &imperium_net_crypto::HybridSigningKey,
) {
    let mut fetch_sub = bus.subscribe("net.cluster.config.fetch_request");

    for node in nodes
        .iter()
        .filter(|node| node.role != DeploymentRole::Operator)
    {
        node.node.config.request_config(bus).unwrap();
    }

    for _ in nodes
        .iter()
        .filter(|node| node.role != DeploymentRole::Operator)
    {
        let fetch_event = tokio::time::timeout(Duration::from_millis(250), fetch_sub.recv())
            .await
            .expect("config fetch request")
            .unwrap();
        if let Message::ConfigFetchReq(req) = fetch_event.message {
            operator
                .node
                .config
                .handle_fetch_request(&req, signing_key, bus)
                .unwrap();
        } else {
            panic!("expected ConfigFetchReq");
        }
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn run_auto_cluster_deployment() -> AutoDeploymentReport {
    let bus = Arc::new(Bus::new());
    let cluster_id = ClusterId::new();
    let mut rng = OsRng;
    let (operator_sk, operator_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    let token_manager = TokenManager::new(cluster_id.clone());

    let nodes = vec![
        DeploymentNode {
            role: DeploymentRole::Operator,
            port: 31_000,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new()),
        },
        DeploymentNode {
            role: DeploymentRole::Client,
            port: 31_001,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new()),
        },
        DeploymentNode {
            role: DeploymentRole::Client,
            port: 31_002,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new()),
        },
        DeploymentNode {
            role: DeploymentRole::Relay,
            port: 31_003,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new()),
        },
        DeploymentNode {
            role: DeploymentRole::Relay,
            port: 31_004,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new()),
        },
    ];

    for node in &nodes {
        let _grant_sub = node.node.membership.subscribe_membership_grants(&bus);
        let _config_sub = node.node.config.subscribe_config_responses(&bus);
    }

    let operator_index = nodes
        .iter()
        .position(|node| node.role == DeploymentRole::Operator)
        .unwrap();
    let operator_id = nodes[operator_index].node.id.clone();
    let mut gossip_sub = bus.subscribe("net.cluster.membership.gossip");

    for node in nodes
        .iter()
        .filter(|node| node.role != DeploymentRole::Operator)
    {
        let token =
            token_manager.mint_token(&operator_id, &operator_sk, chrono::Duration::minutes(15));
        token_manager.verify_token(&token, &operator_vk).unwrap();
        nodes[operator_index]
            .node
            .membership
            .request_membership(node.node.id.clone(), &bus)
            .unwrap();
        nodes[operator_index]
            .node
            .membership
            .approve_membership(&node.node.id, &operator_id, &operator_sk, &bus)
            .unwrap();
        token_manager.consume_token(&token);
        assert!(token_manager.verify_token(&token, &operator_vk).is_err());
    }

    for _ in nodes
        .iter()
        .filter(|node| node.role != DeploymentRole::Operator)
    {
        let gossip_event = tokio::time::timeout(Duration::from_millis(250), gossip_sub.recv())
            .await
            .expect("membership gossip")
            .unwrap();
        if let Message::MembershipGossip(gossip) = gossip_event.message {
            for node in &nodes {
                node.node.membership.apply_gossip(&gossip);
            }
        } else {
            panic!("expected MembershipGossip");
        }
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut report = AutoDeploymentReport {
        planned_nodes: nodes.len(),
        ..AutoDeploymentReport::default()
    };
    report.approved_nodes = nodes
        .iter()
        .filter(|node| {
            nodes
                .iter()
                .all(|candidate| node.node.membership.is_member(&candidate.node.id))
        })
        .count();

    let mut version_sub = bus.subscribe("net.cluster.config.updated");
    report.config_version = nodes[operator_index]
        .node
        .config
        .update_config(
            br#"{"deployment":"auto","vpn":"imperium","profile":"fortress-rf-inspired","nat":"default","relay":"auto"}"#.to_vec(),
            &operator_sk,
            &bus,
        )
        .unwrap();
    let version_event = tokio::time::timeout(Duration::from_millis(250), version_sub.recv())
        .await
        .expect("config version")
        .unwrap();
    if let Message::ConfigVersion(version) = version_event.message {
        assert_eq!(version.version, report.config_version);
        for node in nodes
            .iter()
            .filter(|node| node.role != DeploymentRole::Operator)
        {
            assert!(node.node.config.handle_version_announcement(&version));
        }
    } else {
        panic!("expected ConfigVersion");
    }

    distribute_latest_config(&bus, &nodes[operator_index], &nodes, &operator_sk).await;

    for node in &nodes {
        assert_eq!(node.node.config.current_version(), report.config_version);
    }

    let grants = nodes
        .iter()
        .map(|node| IdentityCapabilityGrant {
            identity_id: node.node.id.clone(),
            capabilities: deployment_capabilities(node.role),
            issued_by: operator_id.clone(),
            issued_at: chrono::Utc::now(),
            expires_at: None,
            signature: vec![node.port as u8],
        })
        .collect::<Vec<_>>();
    let access = AccessPolicy::new(grants);
    for node in &nodes {
        if !access.decide(&node.node.id, "vpn.shutdown").allowed {
            report.denied_shutdown_capabilities += 1;
        }
        match node.role {
            DeploymentRole::Operator => {
                assert!(access.decide(&node.node.id, "vpn.cluster.admin").allowed);
            }
            DeploymentRole::Client => {
                assert!(access.decide(&node.node.id, "vpn.control").allowed);
                assert!(!access.decide(&node.node.id, "vpn.relay").allowed);
            }
            DeploymentRole::Relay => {
                assert!(access.decide(&node.node.id, "vpn.relay").allowed);
            }
        }
    }

    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i == j {
                continue;
            }
            let peer_id = nodes[j].node.id.clone();
            nodes[i]
                .node
                .peers
                .add_peer(peer_id.clone(), vec![nodes[j].node.endpoint(nodes[j].port)]);
        }
    }

    for node in &nodes {
        let default_plan = NatTraversalPlanner::build_probe_plan(
            node.node.id.clone(),
            &NatTraversalPlanner::default_policy(),
        );
        assert!(!default_plan
            .modes
            .iter()
            .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));
        report.default_nat_plans += 1;

        let aggressive_plan = NatTraversalPlanner::build_probe_plan(
            node.node.id.clone(),
            &NatTraversalPlanner::aggressive_policy(),
        );
        assert!(aggressive_plan
            .modes
            .iter()
            .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));
        report.aggressive_nat_plans += 1;
    }

    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i == j {
                continue;
            }
            establish_mesh_session(
                &nodes[i].node,
                nodes[j].node.id.clone(),
                nodes[j].node.endpoint(nodes[j].port),
            );
        }
    }
    report.established_sessions = nodes
        .iter()
        .map(|node| node.node.sessions.active_session_count())
        .sum();

    let relay_ids = nodes
        .iter()
        .filter(|node| node.role == DeploymentRole::Relay)
        .map(|node| node.node.id.clone())
        .collect::<Vec<_>>();
    let client_ids = nodes
        .iter()
        .filter(|node| node.role == DeploymentRole::Client)
        .map(|node| node.node.id.clone())
        .collect::<Vec<_>>();

    let mut relay_selected_sub = bus.subscribe("net.mesh.relay.selected");
    for (index, client_id) in client_ids.iter().enumerate() {
        bus.publish(
            "net.mesh.relay.selected",
            Message::RelayFallbackSelected(RelayFallbackSelected {
                peer_id: client_id.clone(),
                relay_peer: relay_ids[index % relay_ids.len()].clone(),
                selected_at: chrono::Utc::now(),
            }),
        )
        .unwrap();
    }
    for _ in &client_ids {
        let selected = tokio::time::timeout(Duration::from_millis(250), relay_selected_sub.recv())
            .await
            .expect("relay selected")
            .unwrap();
        assert!(matches!(
            selected.message,
            Message::RelayFallbackSelected(RelayFallbackSelected { .. })
        ));
        report.relay_fallbacks_selected += 1;
    }

    let hardening = Arc::new(HardeningController::new(Arc::clone(&bus)));
    let _hardening_sub = hardening.subscribe_hardening_profiles(&bus);
    let mut hardening_status_sub = bus.subscribe("net.transport.hardening.status");

    for node in &nodes {
        bus.publish(
            "net.transport.hardening.apply",
            Message::ProtocolHardeningProfile(ProtocolHardeningProfile {
                protocol_name: Some(format!("auto-vpn-{}", node.port)),
                reason: "auto cluster deployment".into(),
                ..HardeningController::fortress_profile(None)
            }),
        )
        .unwrap();
        let status = tokio::time::timeout(Duration::from_millis(250), hardening_status_sub.recv())
            .await
            .expect("hardening status")
            .unwrap();
        assert!(matches!(
            status.message,
            Message::ProtocolHardeningStatus(status) if status.accepted
        ));
        report.hardening_profiles_accepted += 1;
    }

    report
}

#[tokio::test]
async fn auto_vpn_cluster_deployment_converges_all_nodes() {
    let report = run_auto_cluster_deployment().await;

    assert_eq!(report.planned_nodes, 5);
    assert_eq!(report.approved_nodes, report.planned_nodes);
    assert_eq!(report.config_version, 1);
    assert_eq!(report.denied_shutdown_capabilities, report.planned_nodes);
    assert_eq!(report.default_nat_plans, report.planned_nodes);
    assert_eq!(report.aggressive_nat_plans, report.planned_nodes);
    assert_eq!(
        report.established_sessions,
        report.planned_nodes * (report.planned_nodes - 1)
    );
    assert_eq!(report.relay_fallbacks_selected, 2);
    assert_eq!(report.hardening_profiles_accepted, report.planned_nodes);
}

#[tokio::test]
async fn cluster_vpn_three_peer_control_and_relay_simulation_holds() {
    let bus = Arc::new(Bus::new());
    let cluster_id = ClusterId::new();
    let operator_id = PeerId::new();
    let mobile_id = PeerId::new();
    let relay_id = PeerId::new();

    let operator = SimClusterNode::new(cluster_id.clone(), operator_id.clone());
    let mobile = SimClusterNode::new(cluster_id.clone(), mobile_id.clone());
    let relay = SimClusterNode::new(cluster_id.clone(), relay_id.clone());

    let _operator_grants = operator.membership.subscribe_membership_grants(&bus);
    let _mobile_grants = mobile.membership.subscribe_membership_grants(&bus);
    let _relay_grants = relay.membership.subscribe_membership_grants(&bus);
    let _mobile_config = mobile.config.subscribe_config_responses(&bus);
    let _relay_config = relay.config.subscribe_config_responses(&bus);

    let mut rng = OsRng;
    let (operator_sk, operator_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

    let token_manager = TokenManager::new(cluster_id.clone());
    let token = token_manager.mint_token(&operator_id, &operator_sk, chrono::Duration::minutes(30));
    assert!(token_manager.verify_token(&token, &operator_vk).is_ok());

    let mut gossip_sub = bus.subscribe("net.cluster.membership.gossip");

    operator
        .membership
        .request_membership(mobile_id.clone(), &bus)
        .unwrap();
    operator
        .membership
        .approve_membership(&mobile_id, &operator_id, &operator_sk, &bus)
        .unwrap();
    let first_gossip = tokio::time::timeout(Duration::from_millis(250), gossip_sub.recv())
        .await
        .expect("first membership gossip")
        .unwrap();

    operator
        .membership
        .request_membership(relay_id.clone(), &bus)
        .unwrap();
    operator
        .membership
        .approve_membership(&relay_id, &operator_id, &operator_sk, &bus)
        .unwrap();
    let second_gossip = tokio::time::timeout(Duration::from_millis(250), gossip_sub.recv())
        .await
        .expect("second membership gossip")
        .unwrap();

    for event in [first_gossip, second_gossip] {
        if let Message::MembershipGossip(gossip) = event.message {
            operator.membership.apply_gossip(&gossip);
            mobile.membership.apply_gossip(&gossip);
            relay.membership.apply_gossip(&gossip);
        } else {
            panic!("expected membership gossip");
        }
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    for node in [&operator, &mobile, &relay] {
        assert!(node.membership.is_member(&operator_id));
        assert!(node.membership.is_member(&mobile_id));
        assert!(node.membership.is_member(&relay_id));
        assert_eq!(node.membership.member_count(), 3);
    }

    let mut version_sub = bus.subscribe("net.cluster.config.updated");
    let mut fetch_sub = bus.subscribe("net.cluster.config.fetch_request");
    let version = operator
        .config
        .update_config(
            br#"{"vpn":"imperium","profile":"fortress-rf-inspired","relay":"required"}"#.to_vec(),
            &operator_sk,
            &bus,
        )
        .unwrap();
    assert_eq!(version, 1);

    let version_event = tokio::time::timeout(Duration::from_millis(250), version_sub.recv())
        .await
        .expect("config version")
        .unwrap();
    let version_msg = match version_event.message {
        Message::ConfigVersion(version) => version,
        other => panic!("expected ConfigVersion, got {other:?}"),
    };
    assert!(mobile.config.handle_version_announcement(&version_msg));
    mobile.config.request_config(&bus).unwrap();

    let fetch_event = tokio::time::timeout(Duration::from_millis(250), fetch_sub.recv())
        .await
        .expect("fetch request")
        .unwrap();
    if let Message::ConfigFetchReq(req) = fetch_event.message {
        operator
            .config
            .handle_fetch_request(&req, &operator_sk, &bus)
            .unwrap();
    } else {
        panic!("expected ConfigFetchReq");
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(mobile.config.current_version(), 1);
    assert_eq!(relay.config.current_version(), 1);

    let access = AccessPolicy::new(vec![
        IdentityCapabilityGrant {
            identity_id: mobile_id.clone(),
            capabilities: vec!["vpn.control".into(), "vpn.hardening.apply".into()],
            issued_by: operator_id.clone(),
            issued_at: chrono::Utc::now(),
            expires_at: None,
            signature: vec![1, 2, 3],
        },
        IdentityCapabilityGrant {
            identity_id: relay_id.clone(),
            capabilities: vec!["vpn.relay".into()],
            issued_by: operator_id.clone(),
            issued_at: chrono::Utc::now(),
            expires_at: None,
            signature: vec![4, 5, 6],
        },
    ]);
    assert!(access.decide(&mobile_id, "vpn.control").allowed);
    assert!(access.decide(&mobile_id, "vpn.hardening.apply").allowed);
    assert!(!access.decide(&mobile_id, "vpn.shutdown").allowed);
    assert!(access.decide(&relay_id, "vpn.relay").allowed);

    operator
        .peers
        .add_peer(mobile_id.clone(), vec![mobile.endpoint(30_001)]);
    operator
        .peers
        .add_peer(relay_id.clone(), vec![relay.endpoint(30_002)]);
    mobile
        .peers
        .add_peer(operator_id.clone(), vec![operator.endpoint(30_000)]);
    mobile
        .peers
        .add_peer(relay_id.clone(), vec![relay.endpoint(30_002)]);
    relay
        .peers
        .add_peer(operator_id.clone(), vec![operator.endpoint(30_000)]);
    relay
        .peers
        .add_peer(mobile_id.clone(), vec![mobile.endpoint(30_001)]);

    establish_mesh_session(&operator, mobile_id.clone(), mobile.endpoint(30_001));
    establish_mesh_session(&operator, relay_id.clone(), relay.endpoint(30_002));
    establish_mesh_session(&mobile, operator_id.clone(), operator.endpoint(30_000));
    establish_mesh_session(&mobile, relay_id.clone(), relay.endpoint(30_002));
    establish_mesh_session(&relay, operator_id.clone(), operator.endpoint(30_000));
    establish_mesh_session(&relay, mobile_id.clone(), mobile.endpoint(30_001));

    assert_eq!(operator.sessions.active_session_count(), 2);
    assert_eq!(mobile.sessions.active_session_count(), 2);
    assert_eq!(relay.sessions.active_session_count(), 2);
    assert_eq!(
        operator.peers.get_state(&mobile_id),
        Some(PeerState::Connected)
    );
    assert_eq!(
        mobile.peers.get_state(&relay_id),
        Some(PeerState::Connected)
    );

    let default_plan = NatTraversalPlanner::build_probe_plan(
        mobile_id.clone(),
        &NatTraversalPlanner::default_policy(),
    );
    assert_eq!(default_plan.estimated_probe_count, 32);
    assert!(default_plan.relay_fallback_enabled);
    assert!(!default_plan
        .modes
        .iter()
        .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));

    let mut relay_request_sub = bus.subscribe("net.mesh.relay.request");
    let mut relay_selected_sub = bus.subscribe("net.mesh.relay.selected");
    bus.publish(
        "net.mesh.relay.request",
        Message::RelayFallbackRequest(RelayFallbackRequest {
            peer_id: mobile_id.clone(),
            reason: "default NAT traversal exhausted direct UDP/STUN/coordinated probes".into(),
            requested_at: chrono::Utc::now(),
        }),
    )
    .unwrap();
    let relay_request = tokio::time::timeout(Duration::from_millis(250), relay_request_sub.recv())
        .await
        .expect("relay request")
        .unwrap();
    assert!(matches!(
        relay_request.message,
        Message::RelayFallbackRequest(RelayFallbackRequest { .. })
    ));
    bus.publish(
        "net.mesh.relay.selected",
        Message::RelayFallbackSelected(RelayFallbackSelected {
            peer_id: mobile_id.clone(),
            relay_peer: relay_id.clone(),
            selected_at: chrono::Utc::now(),
        }),
    )
    .unwrap();
    let relay_selected =
        tokio::time::timeout(Duration::from_millis(250), relay_selected_sub.recv())
            .await
            .expect("relay selected")
            .unwrap();
    if let Message::RelayFallbackSelected(selected) = relay_selected.message {
        assert_eq!(selected.peer_id, mobile_id);
        assert_eq!(selected.relay_peer, relay_id);
    } else {
        panic!("expected RelayFallbackSelected");
    }

    let hardening = Arc::new(HardeningController::new(Arc::clone(&bus)));
    let _hardening_sub = hardening.subscribe_hardening_profiles(&bus);
    let mut hardening_status_sub = bus.subscribe("net.transport.hardening.status");
    bus.publish(
        "net.transport.hardening.apply",
        Message::ProtocolHardeningProfile(ProtocolHardeningProfile {
            reason: "cluster relay path selected".into(),
            ..HardeningController::fortress_profile(Some("cluster-vpn".into()))
        }),
    )
    .unwrap();
    let hardening_status =
        tokio::time::timeout(Duration::from_millis(250), hardening_status_sub.recv())
            .await
            .expect("hardening status")
            .unwrap();
    assert!(matches!(
        hardening_status.message,
        Message::ProtocolHardeningStatus(status)
            if status.accepted && status.profile_id == "fortress-rf-inspired"
    ));
    assert_eq!(
        hardening.active_profile().unwrap().protocol_name.as_deref(),
        Some("cluster-vpn")
    );

    let orchestrator = Arc::new(Orchestrator::new(
        OrchestratorConfig {
            active_protocol: "xray-direct".into(),
            standby_protocol: "masque-relay".into(),
            policy: OrchestratorPolicy::default(),
        },
        Arc::clone(&bus),
    ));
    let _threat_sub = orchestrator.subscribe_threat_assessments();
    let _protocol_sub = orchestrator.subscribe_protocol_events();
    let mut decision_sub = bus.subscribe("net.transport.decision");

    bus.publish(
        "net.sensors.threat",
        Message::ThreatAssessment(ThreatAssessment {
            source: ThreatSource::Heuristic {
                name: "cluster-path-burn".into(),
            },
            confidence: 0.91,
            description: "direct path fingerprint pressure during relay fallback".into(),
            remote_addr: Some(operator.endpoint(30_000)),
            timestamp: chrono::Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        }),
    )
    .unwrap();
    let promote = tokio::time::timeout(Duration::from_millis(250), decision_sub.recv())
        .await
        .expect("promote decision")
        .unwrap();
    assert!(matches!(
        promote.message,
        Message::OrchestratorDecision(OrchestratorDecision::PromoteStandby { protocol_name })
            if protocol_name == "masque-relay"
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(orchestrator.state(), OrchestratorState::Healing);
    assert_eq!(orchestrator.active_protocol(), "masque-relay");

    bus.publish(
        "net.transport.event",
        Message::ProtocolEvt(ProtocolEvent {
            protocol_name: "xray-direct".into(),
            role: ProtocolRole::Quarantined,
            status: ProtocolStatus::Running,
            event: ProtocolEventKind::HealingSucceeded,
            timestamp: chrono::Utc::now(),
        }),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(orchestrator.state(), OrchestratorState::Steady);

    let path_metrics = PathMetrics {
        path_id: "mobile->relay->operator".into(),
        rtt_ms: 42,
        jitter_ms: 7,
        loss_ppm: 1_000,
        burn_score: 0.02,
        handshake_success_ppm: 995_000,
        relay_required: true,
        observed_at: chrono::Utc::now(),
    };
    assert!(path_metrics.relay_required);
    assert_eq!(path_metrics.path_id, "mobile->relay->operator");
}
