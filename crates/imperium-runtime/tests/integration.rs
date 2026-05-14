use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use imperium_bus::Bus;
use imperium_protocol::*;

// ---------------------------------------------------------------------------
// Test 1: Emergency shutdown end-to-end
//
// Blueprint acceptance criterion (Phase 2):
//   "If active fails before healing produces a new standby, the orchestrator
//    triggers emergency shutdown: both protocols torn down, vault sealed,
//    operator notified, manual recovery required."
//
// FIXED (Round 4.A): Orchestrator now publishes to
//   "emergency.transport.double_degraded" which matches the coordinator's
//   "emergency" prefix subscription.
//
// FIXED (Round 4.B): Vault is sealed by RuntimeCoordinator::shutdown_all()
//   via the with_vault() hook.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_1_emergency_shutdown_end_to_end() {
    use imperium_net_transport::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};

    let bus = Arc::new(Bus::new());

    let config = OrchestratorConfig {
        active_protocol: "xray".into(),
        standby_protocol: "amneziawg".into(),
        policy: OrchestratorPolicy::default(),
    };

    let orch = Arc::new(Orchestrator::new(config, Arc::clone(&bus)));
    let _sub_handle = orch.subscribe_protocol_events();

    let mut emergency_sub = bus.subscribe("emergency.transport.double_degraded");
    let mut decision_sub = bus.subscribe("net.transport.decision");

    // Drive: crash active protocol → failover, then crash new active → emergency
    let crash_active = ProtocolEvent {
        protocol_name: "xray".into(),
        role: ProtocolRole::Active,
        status: ProtocolStatus::Failed,
        event: ProtocolEventKind::Crashed {
            reason: "test crash 1".into(),
        },
        timestamp: chrono::Utc::now(),
    };
    bus.publish("net.transport.event", Message::ProtocolEvt(crash_active)).unwrap();

    // Wait for failover to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: orchestrator transitioned to Healing, standby promoted
    assert_eq!(orch.state(), OrchestratorState::Healing);
    assert_eq!(orch.active_protocol(), "amneziawg");

    // Verify decisions were published: PromoteStandby, QuarantineActive, BeginHealing
    let d1 = tokio::time::timeout(Duration::from_millis(100), decision_sub.recv())
        .await.unwrap().unwrap();
    assert!(matches!(d1.message, Message::OrchestratorDecision(OrchestratorDecision::PromoteStandby { .. })));

    let d2 = tokio::time::timeout(Duration::from_millis(100), decision_sub.recv())
        .await.unwrap().unwrap();
    assert!(matches!(d2.message, Message::OrchestratorDecision(OrchestratorDecision::QuarantineActive { .. })));

    let d3 = tokio::time::timeout(Duration::from_millis(100), decision_sub.recv())
        .await.unwrap().unwrap();
    assert!(matches!(d3.message, Message::OrchestratorDecision(OrchestratorDecision::BeginHealing { .. })));

    // Now crash the new active (amneziawg) — triggers double-degraded → emergency
    let crash_new_active = ProtocolEvent {
        protocol_name: "amneziawg".into(),
        role: ProtocolRole::Active,
        status: ProtocolStatus::Failed,
        event: ProtocolEventKind::Crashed {
            reason: "test crash 2".into(),
        },
        timestamp: chrono::Utc::now(),
    };
    bus.publish("net.transport.event", Message::ProtocolEvt(crash_new_active)).unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: orchestrator is now in Emergency state
    assert_eq!(orch.state(), OrchestratorState::Emergency);

    // Verify: EmergencyShutdown event published on "emergency.transport.double_degraded"
    let emergency = tokio::time::timeout(Duration::from_millis(100), emergency_sub.recv())
        .await.unwrap().unwrap();
    if let Message::EmergencyShutdown(es) = &emergency.message {
        assert!(es.reason.contains("crashed during healing"));
    } else {
        panic!("expected EmergencyShutdown message, got {:?}", emergency.message);
    }

    // Verify: topic follows convention and matches coordinator's "emergency" prefix
    let topic = &*emergency.topic;
    assert_eq!(topic, "emergency.transport.double_degraded");
    assert!(
        topic.starts_with("emergency"),
        "topic must match the coordinator's 'emergency' prefix subscription"
    );

    // Verify: vault is sealed when coordinator processes emergency shutdown
    use imperium_runtime::RuntimeCoordinator;
    use std::sync::Mutex;

    let vault = Arc::new(Mutex::new(
        imperium_secrets_vault::Vault::new(imperium_store::Store::in_memory()),
    ));
    assert!(!vault.lock().unwrap().is_sealed());

    let coord = RuntimeCoordinator::new()
        .with_vault(Arc::clone(&vault));

    let coord_bus = coord.bus();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        coord_bus.publish(
            "emergency.transport.double_degraded",
            Message::EmergencyShutdown(EmergencyShutdown {
                reason: "test vault seal".into(),
                triggered_at: chrono::Utc::now(),
                active_protocol: None,
                standby_protocol: None,
            }),
        ).unwrap();
    });

    let reason = coord.run().await;
    assert!(matches!(reason, imperium_runtime::ShutdownReason::EmergencyShutdown { .. }));
    assert!(vault.lock().unwrap().is_sealed(), "vault must be sealed after emergency shutdown");
}

// ---------------------------------------------------------------------------
// Test 2: Two-node cluster formation via bus
//
// Blueprint acceptance criterion (Phase 1):
//   "Operator mints a bootstrap token. New node imports it. Operator approves.
//    MembershipGrant signed and gossiped. New node is a full cluster member."
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_2_cluster_formation_via_bus() {
    use imperium_net_cluster::{MembershipManager, TokenManager};
    use imperium_net_crypto::HybridEd25519Mldsa;
    use rand::rngs::OsRng;

    let bus = Arc::new(Bus::new());

    let cluster_id = ClusterId::new();
    let node_a_id = PeerId::new();
    let node_b_id = PeerId::new();

    let mut rng = OsRng;
    let (operator_sk, operator_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

    // Node A: operator node with full membership
    let mgr_a = Arc::new(MembershipManager::new(cluster_id.clone(), node_a_id.clone()));
    let _grant_sub_a = mgr_a.subscribe_membership_grants(&bus);

    // Node B: joining node
    let mgr_b = Arc::new(MembershipManager::new(cluster_id.clone(), node_b_id.clone()));
    let _grant_sub_b = mgr_b.subscribe_membership_grants(&bus);

    // Third observer on the bus to verify gossip propagation
    let mut gossip_sub = bus.subscribe("net.cluster.membership.gossip");

    // Step 1: Operator mints a bootstrap token
    let token_mgr = TokenManager::new(cluster_id.clone());
    let token = token_mgr.mint_token(
        &node_a_id,
        &operator_sk,
        chrono::Duration::hours(1),
    );

    // Step 2: Token verifies
    assert!(token_mgr.verify_token(&token, &operator_vk).is_ok());

    // Step 3: Node B requests membership via bus
    mgr_a.request_membership(node_b_id.clone(), &bus).unwrap();

    // Step 4: Operator approves on Node A
    let grant = mgr_a.approve_membership(
        &node_b_id,
        &node_a_id,
        &operator_sk,
        &bus,
    ).unwrap();

    // Wait for bus propagation
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: grant signature is non-empty (signed by operator)
    assert!(!grant.signature.is_empty());

    // Verify: Node A knows Node B is approved
    assert!(mgr_a.is_member(&node_b_id));
    assert_eq!(mgr_a.member_count(), 2); // self + node_b

    // Verify: Node B received the grant via bus and applied it
    assert!(mgr_b.is_member(&node_b_id));

    // Verify: token is single-use
    token_mgr.consume_token(&token);
    assert!(matches!(
        token_mgr.verify_token(&token, &operator_vk),
        Err(_)
    ));

    // Verify: gossip propagated — third subscriber sees membership update
    let gossip = tokio::time::timeout(Duration::from_millis(100), gossip_sub.recv())
        .await.unwrap().unwrap();
    if let Message::MembershipGossip(g) = &gossip.message {
        assert_eq!(g.members.len(), 2);
        assert!(g.members.contains(&node_a_id));
        assert!(g.members.contains(&node_b_id));
    } else {
        panic!("expected MembershipGossip");
    }
}

// ---------------------------------------------------------------------------
// Test 3: Failover via bus
//
// Blueprint acceptance criterion (Phase 2):
//   "Active crashes → standby promoted → healing begins.
//    No premature Emergency unless healing also fails."
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_3_failover_via_bus() {
    use imperium_net_transport::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};

    let bus = Arc::new(Bus::new());

    let config = OrchestratorConfig {
        active_protocol: "xray".into(),
        standby_protocol: "amneziawg".into(),
        policy: OrchestratorPolicy::default(),
    };

    let orch = Arc::new(Orchestrator::new(config, Arc::clone(&bus)));
    let _sub = orch.subscribe_protocol_events();

    let mut decision_sub = bus.subscribe("net.transport.decision");

    // Drive: active protocol crashes
    let crash = ProtocolEvent {
        protocol_name: "xray".into(),
        role: ProtocolRole::Active,
        status: ProtocolStatus::Failed,
        event: ProtocolEventKind::Crashed {
            reason: "connection reset".into(),
        },
        timestamp: chrono::Utc::now(),
    };
    bus.publish("net.transport.event", Message::ProtocolEvt(crash)).unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: orchestrator transitioned through Failover to Healing
    assert_eq!(orch.state(), OrchestratorState::Healing);

    // Verify: new active is amneziawg (standby was promoted)
    assert_eq!(orch.active_protocol(), "amneziawg");

    // Verify: PromoteStandby decision published
    let d1 = tokio::time::timeout(Duration::from_millis(100), decision_sub.recv())
        .await.unwrap().unwrap();
    assert!(matches!(
        d1.message,
        Message::OrchestratorDecision(OrchestratorDecision::PromoteStandby { .. })
    ));

    // Verify: no Emergency state — healing has NOT failed yet
    assert_ne!(orch.state(), OrchestratorState::Emergency);

    // Drive: healing succeeds
    let heal = ProtocolEvent {
        protocol_name: "xray".into(),
        role: ProtocolRole::Standby,
        status: ProtocolStatus::Running,
        event: ProtocolEventKind::HealingSucceeded,
        timestamp: chrono::Utc::now(),
    };
    bus.publish("net.transport.event", Message::ProtocolEvt(heal)).unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: back to Steady
    assert_eq!(orch.state(), OrchestratorState::Steady);
}

// ---------------------------------------------------------------------------
// Test 4: Strainer engagement via bus — rejection lands in memory log
//
// Blueprint acceptance criterion (Phase 3):
//   "StrainerRejection events have full provenance (strainer_id, stack_id,
//    shape_failed, source_identifier, timestamp) and are recorded in the
//    memory log."
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_4_strainer_rejection_to_memory_log() {
    use imperium_memory_log::MemoryLog;
    use imperium_net_strainer::{
        AuthShapeOuterStrainer, StrainerInput, StrainerStack,
    };

    let bus = Arc::new(Bus::new());

    let log = Arc::new(MemoryLog::new(1000));
    let _log_sub = log.subscribe_strainer_rejections(&bus);

    // Build a strainer stack with an auth-outer strainer (max 128 bytes)
    let mut stack = StrainerStack::new("auth_stack", "test_protocol")
        .with_bus(Arc::clone(&bus));
    stack.add_stage(Arc::new(AuthShapeOuterStrainer::new(128)));

    // Drive: feed oversized input → triggers rejection
    let input = StrainerInput {
        data: vec![0u8; 256],
        source: Some("192.168.1.100:9999".parse().unwrap()),
        context: HashMap::new(),
        timestamp: chrono::Utc::now(),
    };

    let output = stack.apply(input);
    assert!(output.is_rejected());

    // Wait for bus delivery
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: memory log recorded the rejection
    let entries = log.entries_since(0);
    assert_eq!(entries.len(), 1, "expected one log entry from the rejection");

    let entry = &entries[0];
    if let Message::StrainerRejection(ref rej) = entry.event.message {
        // Verify all five provenance fields are populated
        assert!(!rej.strainer_id.is_empty(), "strainer_id must be populated");
        assert_eq!(rej.stack_id, "auth_stack");
        assert!(!rej.shape_failed.is_empty(), "shape_failed must be populated");
        assert!(rej.source_identifier.is_some(), "source_identifier must be populated");
        assert_eq!(
            rej.source_identifier.unwrap().to_string(),
            "192.168.1.100:9999"
        );
        // timestamp is always populated by construction
    } else {
        panic!("expected StrainerRejection in log, got {:?}", entry.event.message);
    }
}

// ---------------------------------------------------------------------------
// Test 5: Two-phase signature activation
//
// Blueprint acceptance criterion (Phase 6):
//   "Operator reviews and approves signature candidates. Only approved
//    signatures join the active database."
//
// Verifies the full two-phase activation path: candidate persisted in store,
// operator approves via staging, engine fetches from store, compiles YARA rule,
// loads it into the scan pipeline, and publishes SignatureActivated.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_5_signature_approval_triggers_engine_notification() {
    use imperium_net_sensors::SignatureEngineSensor;
    use imperium_net_signatures::StagingArea;
    use imperium_net_crypto::HybridEd25519Mldsa;
    use imperium_store::Store;
    use rand::rngs::OsRng;

    let bus = Arc::new(Bus::new());
    let store = Store::in_memory();

    // Create and persist the candidate in the store BEFORE approval
    let candidate = SignatureCandidate {
        id: uuid::Uuid::new_v4(),
        rule_text: r#"rule test_sig { strings: $a = { CA FE BA BE } condition: $a }"#.into(),
        description: "test candidate".into(),
        source_events: vec![EventId::new()],
        extracted_at: chrono::Utc::now(),
        confidence: 0.9,
    };
    let candidate_id = candidate.id;
    let key = format!("signature_candidate:{}", candidate_id);
    store.put(&key, serde_json::to_vec(&candidate).unwrap()).unwrap();

    let engine = Arc::new(
        SignatureEngineSensor::new(Arc::clone(&bus)).with_store(store),
    );
    let _engine_sub = engine.subscribe_signature_approvals(&bus);

    let mut activation_sub = bus.subscribe("net.signatures.activated");

    let staging = StagingArea::new(Arc::clone(&bus));

    staging.submit(candidate).unwrap();
    assert_eq!(staging.pending_count(), 1);

    // Operator approves
    let mut rng = OsRng;
    let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    let operator = PeerId::new();

    let approved = staging.approve(candidate_id, &operator, &sk).unwrap();
    assert_eq!(approved.candidate_id, candidate_id);
    assert_eq!(staging.pending_count(), 0);

    // Verify: engine received the approval and published SignatureActivated
    let activated = tokio::time::timeout(Duration::from_millis(200), activation_sub.recv())
        .await.unwrap().unwrap();

    if let Message::SignatureActivated(ref act) = activated.message {
        assert_eq!(act.candidate_id, candidate_id);
    } else {
        panic!("expected SignatureActivated, got {:?}", activated.message);
    }

    // Two-phase activation: the engine has compiled and loaded the rule.
    // A scan against CAFEBABE data MUST match.
    let data = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let matches = engine.scan(&data).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "Two-phase activation should load the approved rule into the engine"
    );
}

// ---------------------------------------------------------------------------
// Test 6: System operates normally without watchtower
//
// Blueprint acceptance criterion (Phase 5):
//   "Optional capabilities (watchtower) are clearly optional and the system
//    functions correctly without them."
//
// Runs simplified versions of tests 1-4 WITHOUT any watchtower subsystem.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_6_system_without_watchtower() {
    use imperium_memory_log::MemoryLog;
    use imperium_net_cluster::MembershipManager;
    use imperium_net_crypto::HybridEd25519Mldsa;
    use imperium_net_strainer::{AuthShapeOuterStrainer, StrainerInput, StrainerStack};
    use imperium_net_transport::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};
    use rand::rngs::OsRng;

    let bus = Arc::new(Bus::new());

    // --- Orchestrator (no watchtower registered) ---
    let orch_config = OrchestratorConfig {
        active_protocol: "xray".into(),
        standby_protocol: "amneziawg".into(),
        policy: OrchestratorPolicy::default(),
    };
    let orch = Arc::new(Orchestrator::new(orch_config, Arc::clone(&bus)));
    let _orch_sub = orch.subscribe_protocol_events();

    // --- Memory log ---
    let log = Arc::new(MemoryLog::new(1000));
    let _log_rej_sub = log.subscribe_strainer_rejections(&bus);
    let _log_proto_sub = log.subscribe_protocol_events(&bus);

    // --- Cluster ---
    let cluster_id = ClusterId::new();
    let local_id = PeerId::new();
    let mut rng = OsRng;
    let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

    let membership = Arc::new(MembershipManager::new(cluster_id.clone(), local_id.clone()));
    let _member_sub = membership.subscribe_membership_grants(&bus);

    // --- Strainer ---
    let mut stack = StrainerStack::new("auth_stack", "xray")
        .with_bus(Arc::clone(&bus));
    stack.add_stage(Arc::new(AuthShapeOuterStrainer::new(128)));

    // Test A: Failover works without watchtower
    let crash = ProtocolEvent {
        protocol_name: "xray".into(),
        role: ProtocolRole::Active,
        status: ProtocolStatus::Failed,
        event: ProtocolEventKind::Crashed {
            reason: "test".into(),
        },
        timestamp: chrono::Utc::now(),
    };
    bus.publish("net.transport.event", Message::ProtocolEvt(crash)).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(orch.state(), OrchestratorState::Healing);

    // Test B: Cluster formation works without watchtower
    let joining_peer = PeerId::new();
    membership.request_membership(joining_peer.clone(), &bus).unwrap();
    let _grant = membership.approve_membership(&joining_peer, &local_id, &sk, &bus).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(membership.is_member(&joining_peer));

    // Test C: Strainer rejection works without watchtower
    let input = StrainerInput {
        data: vec![0u8; 256],
        source: Some("10.0.0.1:1234".parse().unwrap()),
        context: HashMap::new(),
        timestamp: chrono::Utc::now(),
    };
    let output = stack.apply(input);
    assert!(output.is_rejected());
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: log has entries (at minimum the strainer rejection)
    let entries = log.entries_since(0);
    assert!(!entries.is_empty(), "memory log should have recorded events without watchtower");

    // Verify: no errors about missing watchtower in any subscriber
    // (This is verified implicitly — if any subscriber blocked on a
    // watchtower event, the test would time out.)
}

// ---------------------------------------------------------------------------
// Test 7: Closed-loop signature extraction end-to-end
//
// Blueprint acceptance criterion (Phase 6):
//   "Extraction → staging → approval → engine activation → traffic match"
//
// Full pipeline: a strainer rejection lands in the memory log. An extraction
// request triggers the extraction loop, which pulls event data, extracts a
// YARA candidate, persists it to the store, and submits to staging. Operator
// approves. Two-phase activation fetches from store, compiles, loads. Scan
// matches.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_7_closed_loop_extraction_to_engine_match() {
    use imperium_memory_log::MemoryLog;
    use imperium_net_crypto::HybridEd25519Mldsa;
    use imperium_net_sensors::SignatureEngineSensor;
    use imperium_net_signatures::{ExtractionLoop, StagingArea};
    use imperium_store::Store;
    use rand::rngs::OsRng;

    let bus = Arc::new(Bus::new());
    let store = Arc::new(Store::in_memory());
    let memory_log = Arc::new(MemoryLog::new(10_000));
    let staging = Arc::new(StagingArea::new(Arc::clone(&bus)));

    // Wire the extraction loop
    let extraction_loop = Arc::new(ExtractionLoop::new(
        Arc::clone(&bus),
        Arc::clone(&store),
        Arc::clone(&memory_log),
        Arc::clone(&staging),
    ));
    let _extraction_handle = extraction_loop.subscribe_extraction_requests(&bus);

    // Step 1: Simulate a strainer rejection entering the memory log
    let rejection_event = BusEvent::new(
        "net.strainer.rejection",
        Message::StrainerRejection(StrainerRejection {
            strainer_id: "auth_outer".into(),
            stack_id: "xray_stack".into(),
            shape_failed: "oversized".into(),
            source_identifier: Some("10.0.0.99:31337".parse().unwrap()),
            timestamp: chrono::Utc::now(),
        }),
    );
    let trigger_event_id = rejection_event.id.clone();
    memory_log.append(rejection_event);

    // Step 2: Publish extraction request (simulating CLI)
    let mut pending_sub = bus.subscribe("net.signatures.candidate_pending");

    bus.publish(
        "net.signatures.extraction_request",
        Message::ExtractionRequest(ExtractionRequest {
            triggering_event_ids: vec![trigger_event_id],
            reason: "suspicious probe pattern".into(),
            requested_by: "test_operator".into(),
        }),
    ).unwrap();

    // Wait for candidate_pending notification
    let pending_event = tokio::time::timeout(
        Duration::from_millis(500),
        pending_sub.recv(),
    ).await.unwrap().unwrap();

    let candidate_id = if let Message::SignatureCandidatePending(ref pending) = pending_event.message {
        assert_eq!(pending.requested_by, "test_operator");
        pending.candidate_id
    } else {
        panic!("expected SignatureCandidatePending, got {:?}", pending_event.message);
    };

    // Verify candidate is in the store
    let key = format!("signature_candidate:{}", candidate_id);
    assert!(store.exists(&key), "candidate must be in store before approval");

    // Step 3: Copy candidate data into a store the engine owns
    // (engine takes Store by value; extraction loop holds Arc<Store>)
    let candidate_data = store.get(&key).unwrap();
    let engine_store = Store::in_memory();
    engine_store.put(&key, candidate_data).unwrap();

    // Step 4: Wire the signature engine with two-phase activation
    let engine = Arc::new(
        SignatureEngineSensor::new(Arc::clone(&bus)).with_store(engine_store),
    );
    let _engine_handle = engine.subscribe_signature_approvals(&bus);

    let mut activated_sub = bus.subscribe("net.signatures.activated");

    // Step 5: Operator approves the candidate
    let mut rng = OsRng;
    let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    let operator = PeerId::new();

    let approved = staging.approve(candidate_id, &operator, &sk).unwrap();
    assert_eq!(approved.candidate_id, candidate_id);

    // Wait for activation
    let activated_event = tokio::time::timeout(
        Duration::from_millis(500),
        activated_sub.recv(),
    ).await.unwrap().unwrap();

    if let Message::SignatureActivated(ref act) = activated_event.message {
        assert_eq!(act.candidate_id, candidate_id);
    } else {
        panic!("expected SignatureActivated, got {:?}", activated_event.message);
    }

    // Step 6: Verify the engine loaded the rule and can match traffic
    assert_eq!(engine.extracted_count(), 1, "engine should have loaded the extracted rule");

    // The extracted YARA rule contains a hex pattern derived from the serialized
    // event data. The extractor's frequency filter strips common bytes (like `"`
    // in JSON), so the pattern is a subsequence of the original serialization.
    // Construct probe data that contains the pattern bytes contiguously.
    let candidate: SignatureCandidate = serde_json::from_slice(
        &store.get(&key).unwrap()
    ).unwrap();

    // Extract the hex string from the rule text: `$a = { HEX } condition`
    let hex_start = candidate.rule_text.find("$a = { ").unwrap() + 7;
    let hex_end = candidate.rule_text[hex_start..].find(" }").unwrap() + hex_start;
    let hex_str = &candidate.rule_text[hex_start..hex_end];
    let pattern_bytes: Vec<u8> = hex_str
        .split(' ')
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect();

    // Embed the pattern in realistic-looking traffic data
    let mut probe = vec![0x00; 16];
    probe.extend_from_slice(&pattern_bytes);
    probe.extend_from_slice(&[0xFF; 16]);

    let matches = engine.scan(&probe).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "engine should match traffic containing the extracted pattern"
    );
    assert_eq!(matches[0].confidence, 1.0);
}
