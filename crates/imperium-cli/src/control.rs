use std::collections::HashMap;
use std::sync::Arc;

use imperium_bus::Bus;
use imperium_net_signatures::{CandidateStatus, StagingArea};
use imperium_protocol::{
    KillSwitchCommand, KillSwitchState, MasqueTunnelConfig, Message, PolicyApplyRequest,
    ProfileRotationRequest, ProtocolCommand, ProtocolCommandKind, ProtocolHardeningProfile,
    ToolActivationRequest, TransportActiveRequest, VpnDeploymentPlan, VpnDeploymentStatusRequest,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

const PIPE_NAME: &str = r"\\.\pipe\imperium-control";

#[derive(Clone)]
struct ControlState {
    bus: Arc<Bus>,
    staging: Option<Arc<StagingArea>>,
}

impl ControlState {
    fn new(bus: Arc<Bus>, staging: Option<Arc<StagingArea>>) -> Self {
        Self { bus, staging }
    }
}

pub async fn serve_with_staging(bus: Arc<Bus>, staging: Arc<StagingArea>) {
    serve_inner(Arc::new(ControlState::new(bus, Some(staging)))).await;
}

async fn serve_inner(state: Arc<ControlState>) {
    loop {
        let server = match ServerOptions::new()
            .pipe_mode(PipeMode::Message)
            .first_pipe_instance(false)
            .create(PIPE_NAME)
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to create named pipe");
                return;
            }
        };

        if let Err(e) = server.connect().await {
            tracing::error!(error = %e, "named pipe connect failed");
            continue;
        }

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            handle_connection(server, state).await;
        });
    }
}

async fn handle_connection(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    state: Arc<ControlState>,
) {
    let (reader, mut writer) = tokio::io::split(pipe);
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let response = dispatch_command_with_staging(&line, &state.bus, state.staging.as_deref());
        let msg = format!("{}\n", response);
        if writer.write_all(msg.as_bytes()).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
fn dispatch_command(line: &str, bus: &Bus) -> String {
    dispatch_command_with_staging(line, bus, None)
}

fn dispatch_command_with_staging(line: &str, bus: &Bus, staging: Option<&StagingArea>) -> String {
    let parts: Vec<&str> = line.trim().splitn(4, ' ').collect();
    match parts.as_slice() {
        ["cluster", "status"] => {
            format!("{{\"status\":\"ok\",\"message\":\"cluster status requested\"}}")
        }
        ["vpn", "health"] => {
            format!("{{\"status\":\"ok\",\"message\":\"vpn health requested\"}}")
        }
        ["vpn", "profile", "rotate"] => {
            publish_profile_rotation(bus, None, "operator requested profile rotation")
        }
        ["vpn", "profile", "rotate", protocol_name] => publish_profile_rotation(
            bus,
            Some((*protocol_name).to_string()),
            "operator requested profile rotation",
        ),
        ["vpn", "transport", "set-active", protocol_name] => {
            if protocol_name.trim().is_empty() {
                return format!(
                    "{{\"status\":\"error\",\"message\":\"protocol cannot be empty\"}}"
                );
            }
            let now = chrono::Utc::now();
            let _ = bus.publish(
                "net.transport.active_request",
                Message::TransportActiveRequest(TransportActiveRequest {
                    protocol_name: (*protocol_name).to_string(),
                    requested_at: now,
                }),
            );
            let _ = bus.publish(
                "net.transport.command",
                Message::ProtocolCmd(ProtocolCommand {
                    protocol_name: (*protocol_name).to_string(),
                    command: ProtocolCommandKind::PromoteToActive,
                    issued_at: now,
                }),
            );
            format!(
                "{{\"status\":\"ok\",\"message\":\"active transport requested: {}\"}}",
                protocol_name
            )
        }
        ["vpn", "policy", "apply", policy_id] => {
            if policy_id.trim().is_empty() {
                return format!(
                    "{{\"status\":\"error\",\"message\":\"policy id cannot be empty\"}}"
                );
            }
            let _ = bus.publish(
                "net.cluster.policy.apply",
                Message::PolicyApplyRequest(PolicyApplyRequest {
                    policy_id: (*policy_id).to_string(),
                    config_blob: Vec::new(),
                    requested_at: chrono::Utc::now(),
                }),
            );
            format!(
                "{{\"status\":\"ok\",\"message\":\"policy apply requested: {}\"}}",
                policy_id
            )
        }
        ["vpn", "nat", "aggressive", setting] => {
            let policy = match *setting {
                "on" => imperium_net_mesh::NatTraversalPlanner::aggressive_policy(),
                "off" => imperium_net_mesh::NatTraversalPlanner::default_policy(),
                _ => return format!("{{\"status\":\"error\",\"message\":\"expected on or off\"}}"),
            };
            let _ = bus.publish("net.mesh.nat.policy", Message::NatTraversalPolicy(policy));
            format!(
                "{{\"status\":\"ok\",\"message\":\"aggressive NAT probing {}\"}}",
                setting
            )
        }
        ["vpn", "killswitch", state] => {
            publish_kill_switch(bus, state, "operator requested killswitch change")
        }
        ["vpn", "killswitch", state, reason] => publish_kill_switch(bus, state, reason),
        ["vpn", "masque", "configure", json] => {
            match serde_json::from_str::<MasqueTunnelConfig>(json) {
                Ok(config) => {
                    let tunnel_id = config.tunnel_id.clone();
                    let _ = bus.publish(
                        "net.transport.masque.configure",
                        Message::MasqueTunnelConfig(config),
                    );
                    format!(
                        "{{\"status\":\"ok\",\"message\":\"MASQUE config dispatched: {}\"}}",
                        tunnel_id
                    )
                }
                Err(e) => format!(
                    "{{\"status\":\"error\",\"message\":\"invalid MASQUE config: {}\"}}",
                    e
                ),
            }
        }
        ["vpn", "deployment", "status"] => {
            let _ = bus.publish(
                "net.vpn.deployment.status_request",
                Message::VpnDeploymentStatusRequest(VpnDeploymentStatusRequest {
                    requested_by: "control_pipe".to_string(),
                    requested_at: chrono::Utc::now(),
                }),
            );
            format!("{{\"status\":\"ok\",\"message\":\"deployment status requested\"}}")
        }
        ["vpn", "deployment", "apply"] => {
            format!("{{\"status\":\"error\",\"message\":\"deployment plan json is required\"}}")
        }
        ["vpn", "deployment", "apply", json] => publish_deployment_plan(bus, json),
        ["vpn", "hardening", "preset"] => {
            format!("{{\"status\":\"error\",\"message\":\"hardening preset is required\"}}")
        }
        ["vpn", "hardening", "preset", request] => publish_hardening_preset(bus, request),
        ["vpn", "hardening", "apply"] => {
            format!("{{\"status\":\"error\",\"message\":\"hardening profile json is required\"}}")
        }
        ["vpn", "hardening", "apply", json] => publish_hardening_profile(bus, json),
        ["vpn", "toolkit", "activate"] => {
            format!("{{\"status\":\"error\",\"message\":\"tool name is required\"}}")
        }
        ["vpn", "toolkit", "activate", request] => publish_toolkit_activation(bus, request),
        ["signatures", "pending"] => render_pending_signatures(staging),
        ["signatures", "approve", id] => match uuid::Uuid::parse_str(id) {
            Ok(uuid) => {
                let _ = bus.publish(
                    "net.signatures.approve_request",
                    Message::SubsystemReady {
                        name: format!("cli-approve:{}", uuid),
                    },
                );
                format!(
                    "{{\"status\":\"ok\",\"message\":\"approval request dispatched for {}\"}}",
                    id
                )
            }
            Err(_) => format!("{{\"status\":\"error\",\"message\":\"invalid UUID\"}}"),
        },
        ["signatures", "reject", id] => match uuid::Uuid::parse_str(id) {
            Ok(uuid) => {
                let _ = bus.publish(
                    "net.signatures.reject_request",
                    Message::SignatureRejected(imperium_protocol::SignatureRejected {
                        candidate_id: uuid,
                        rejected_by: imperium_protocol::PeerId::new(),
                        rejected_at: chrono::Utc::now(),
                        reason: "operator rejected".to_string(),
                    }),
                );
                format!(
                    "{{\"status\":\"ok\",\"message\":\"rejection dispatched for {}\"}}",
                    uuid
                )
            }
            Err(_) => format!("{{\"status\":\"error\",\"message\":\"invalid UUID\"}}"),
        },
        ["signatures", "reject", id, reason] => match uuid::Uuid::parse_str(id) {
            Ok(uuid) => {
                let _ = bus.publish(
                    "net.signatures.reject_request",
                    Message::SignatureRejected(imperium_protocol::SignatureRejected {
                        candidate_id: uuid,
                        rejected_by: imperium_protocol::PeerId::new(),
                        rejected_at: chrono::Utc::now(),
                        reason: reason.to_string(),
                    }),
                );
                format!(
                    "{{\"status\":\"ok\",\"message\":\"rejection dispatched for {}\"}}",
                    uuid
                )
            }
            Err(_) => format!("{{\"status\":\"error\",\"message\":\"invalid UUID\"}}"),
        },
        ["signatures", "extract", ids_arg, ..] => {
            let event_ids_str: Vec<&str> = ids_arg.split(',').map(|s| s.trim()).collect();
            let mut event_ids = Vec::new();
            for id_str in &event_ids_str {
                match uuid::Uuid::parse_str(id_str) {
                    Ok(uuid) => event_ids.push(imperium_protocol::EventId(uuid)),
                    Err(_) => {
                        return format!(
                            "{{\"status\":\"error\",\"message\":\"invalid event UUID: {}\"}}",
                            id_str
                        )
                    }
                }
            }
            let _ = bus.publish(
                "net.signatures.extraction_request",
                Message::ExtractionRequest(imperium_protocol::ExtractionRequest {
                    triggering_event_ids: event_ids,
                    reason: "operator requested via control pipe".into(),
                    requested_by: "operator".into(),
                }),
            );
            format!(
                "{{\"status\":\"ok\",\"message\":\"extraction requested for {} events\"}}",
                event_ids_str.len()
            )
        }
        ["signatures", "show", id] => match uuid::Uuid::parse_str(id) {
            Ok(uuid) => render_signature_candidate(uuid, staging),
            Err(_) => format!("{{\"status\":\"error\",\"message\":\"invalid UUID\"}}"),
        },
        ["shutdown"] => {
            let _ = bus.publish(
                "emergency.cli.operator_shutdown",
                Message::EmergencyShutdown(imperium_protocol::EmergencyShutdown {
                    reason: "operator requested shutdown via control pipe".into(),
                    triggered_at: chrono::Utc::now(),
                    active_protocol: None,
                    standby_protocol: None,
                }),
            );
            format!("{{\"status\":\"ok\",\"message\":\"shutdown initiated\"}}")
        }
        _ => format!("{{\"status\":\"error\",\"message\":\"unknown command\"}}"),
    }
}

fn render_signature_candidate(uuid: uuid::Uuid, staging: Option<&StagingArea>) -> String {
    let Some(staging) = staging else {
        return serde_json::json!({
            "status": "error",
            "candidate_id": uuid,
            "message": "signature staging unavailable"
        })
        .to_string();
    };

    match staging.candidate(uuid) {
        Some(snapshot) => serde_json::json!({
            "status": "ok",
            "candidate_status": candidate_status_label(&snapshot.status),
            "candidate": snapshot.candidate,
            "rejection_reason": snapshot.rejection_reason
        })
        .to_string(),
        None => serde_json::json!({
            "status": "error",
            "candidate_id": uuid,
            "message": "candidate not found"
        })
        .to_string(),
    }
}

fn render_pending_signatures(staging: Option<&StagingArea>) -> String {
    let Some(staging) = staging else {
        return serde_json::json!({
            "status": "error",
            "message": "signature staging unavailable"
        })
        .to_string();
    };

    let candidates = staging.pending_candidates();
    serde_json::json!({
        "status": "ok",
        "pending_count": candidates.len(),
        "candidates": candidates
    })
    .to_string()
}

fn candidate_status_label(status: &CandidateStatus) -> &'static str {
    match status {
        CandidateStatus::Pending => "pending",
        CandidateStatus::Approved => "approved",
        CandidateStatus::Rejected => "rejected",
    }
}

fn publish_deployment_plan(bus: &Bus, json: &str) -> String {
    match serde_json::from_str::<VpnDeploymentPlan>(json) {
        Ok(plan) => {
            let deployment_id = plan.deployment_id;
            let _ = bus.publish("net.vpn.deployment.apply", Message::VpnDeploymentPlan(plan));
            format!(
                "{{\"status\":\"ok\",\"message\":\"deployment plan dispatched: {}\"}}",
                deployment_id
            )
        }
        Err(e) => format!(
            "{{\"status\":\"error\",\"message\":\"invalid deployment plan: {}\"}}",
            e
        ),
    }
}

fn publish_profile_rotation(bus: &Bus, protocol_name: Option<String>, reason: &str) -> String {
    let target = protocol_name.clone().unwrap_or_else(|| "all".to_string());
    let _ = bus.publish(
        "net.transport.profile.rotate",
        Message::ProfileRotationRequest(ProfileRotationRequest {
            protocol_name,
            reason: reason.to_string(),
            requested_at: chrono::Utc::now(),
        }),
    );
    format!(
        "{{\"status\":\"ok\",\"message\":\"profile rotation requested: {}\"}}",
        target
    )
}

fn publish_kill_switch(bus: &Bus, state: &str, reason: &str) -> String {
    let state = match state {
        "disarm" | "disarmed" => KillSwitchState::Disarmed,
        "arm" | "armed" => KillSwitchState::Armed,
        "engage" | "engaged" => KillSwitchState::Engaged,
        _ => return format!("{{\"status\":\"error\",\"message\":\"unknown killswitch state\"}}"),
    };

    let _ = bus.publish(
        "net.transport.killswitch.command",
        Message::KillSwitchCommand(KillSwitchCommand {
            state,
            reason: reason.to_string(),
            issued_at: chrono::Utc::now(),
        }),
    );
    format!("{{\"status\":\"ok\",\"message\":\"killswitch command dispatched\"}}")
}

fn publish_hardening_preset(bus: &Bus, request: &str) -> String {
    let mut parts = request.trim().splitn(2, ' ');
    let Some(preset) = parts.next().filter(|preset| !preset.trim().is_empty()) else {
        return format!("{{\"status\":\"error\",\"message\":\"hardening preset is required\"}}");
    };
    let protocol_name = parts
        .next()
        .filter(|protocol| !protocol.trim().is_empty())
        .map(ToString::to_string);

    let profile = match preset {
        "balanced" => imperium_net_transport::HardeningController::balanced_profile(protocol_name),
        "resilience" => {
            imperium_net_transport::HardeningController::resilience_profile(protocol_name)
        }
        "fortress" => imperium_net_transport::HardeningController::fortress_profile(protocol_name),
        _ => return format!("{{\"status\":\"error\",\"message\":\"unknown hardening preset\"}}"),
    };

    publish_valid_hardening_profile(bus, profile)
}

fn publish_hardening_profile(bus: &Bus, json: &str) -> String {
    match serde_json::from_str::<ProtocolHardeningProfile>(json) {
        Ok(profile) => publish_valid_hardening_profile(bus, profile),
        Err(e) => format!(
            "{{\"status\":\"error\",\"message\":\"invalid hardening profile: {}\"}}",
            e
        ),
    }
}

fn publish_valid_hardening_profile(bus: &Bus, profile: ProtocolHardeningProfile) -> String {
    if let Err(e) = imperium_net_transport::HardeningController::validate(&profile) {
        return format!(
            "{{\"status\":\"error\",\"message\":\"invalid hardening profile: {}\"}}",
            e
        );
    }

    let profile_id = profile.profile_id.clone();
    let _ = bus.publish(
        "net.transport.hardening.apply",
        Message::ProtocolHardeningProfile(profile),
    );

    format!(
        "{{\"status\":\"ok\",\"message\":\"hardening profile dispatched: {}\"}}",
        profile_id
    )
}

fn publish_toolkit_activation(bus: &Bus, request: &str) -> String {
    let mut parts = request.trim().splitn(2, ' ');
    let Some(tool_name) = parts.next().filter(|name| !name.trim().is_empty()) else {
        return format!("{{\"status\":\"error\",\"message\":\"tool name is required\"}}");
    };
    let trigger = parts
        .next()
        .filter(|trigger| !trigger.trim().is_empty())
        .unwrap_or("operator.manual_toolkit_activation");

    let mut context = HashMap::new();
    context.insert("requested_by".to_string(), "control_pipe".to_string());

    let _ = bus.publish(
        "net.toolkit.request",
        Message::ToolActivationReq(ToolActivationRequest {
            tool_name: tool_name.to_string(),
            trigger: trigger.to_string(),
            context,
            timestamp: chrono::Utc::now(),
        }),
    );

    format!(
        "{{\"status\":\"ok\",\"message\":\"toolkit activation requested: {}\"}}",
        tool_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_cluster_status() {
        let bus = Bus::new();
        let resp = dispatch_command("cluster status", &bus);
        assert!(resp.contains("cluster status requested"));
    }

    #[test]
    fn dispatch_vpn_profile_rotate() {
        let bus = Bus::new();
        let resp = dispatch_command("vpn profile rotate xray", &bus);
        assert!(resp.contains("profile rotation requested"));
    }

    #[test]
    fn dispatch_vpn_nat_aggressive_on() {
        let bus = Bus::new();
        let resp = dispatch_command("vpn nat aggressive on", &bus);
        assert!(resp.contains("aggressive NAT probing on"));
    }

    #[test]
    fn dispatch_vpn_killswitch_engage() {
        let bus = Bus::new();
        let resp = dispatch_command("vpn killswitch engage dns leak", &bus);
        assert!(resp.contains("killswitch command dispatched"));
    }

    #[test]
    fn dispatch_vpn_hardening_preset() {
        let bus = Bus::new();
        let resp = dispatch_command("vpn hardening preset balanced masque", &bus);
        assert!(resp.contains("hardening profile dispatched"));
    }

    #[test]
    fn dispatch_vpn_hardening_apply_rejects_bad_json() {
        let bus = Bus::new();
        let resp = dispatch_command("vpn hardening apply {}", &bus);
        assert!(resp.contains("invalid hardening profile"));
    }

    #[test]
    fn dispatch_vpn_toolkit_activate() {
        let bus = Bus::new();
        let resp = dispatch_command(
            "vpn toolkit activate transport.diagnostics manual check",
            &bus,
        );
        assert!(resp.contains("toolkit activation requested"));
    }

    #[test]
    fn dispatch_vpn_deployment_apply() {
        let bus = Bus::new();
        let plan = imperium_protocol::VpnDeploymentPlan {
            deployment_id: uuid::Uuid::new_v4(),
            cluster_id: None,
            nodes: vec![
                imperium_protocol::VpnDeploymentNodeSpec {
                    label: "operator".into(),
                    role: imperium_protocol::VpnDeploymentRole::Operator,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32000".parse().unwrap()),
                    capabilities: vec!["vpn.cluster.admin".into()],
                },
                imperium_protocol::VpnDeploymentNodeSpec {
                    label: "client".into(),
                    role: imperium_protocol::VpnDeploymentRole::Client,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32001".parse().unwrap()),
                    capabilities: vec!["vpn.client".into()],
                },
            ],
            hardening_preset: "fortress".into(),
            nat_aggressive: false,
            relay_auto: true,
            config_blob: br#"{"deployment":"auto"}"#.to_vec(),
            requested_by: "test".into(),
            requested_at: chrono::Utc::now(),
        };
        let resp = dispatch_command(
            &format!(
                "vpn deployment apply {}",
                serde_json::to_string(&plan).unwrap()
            ),
            &bus,
        );

        assert!(resp.contains("deployment plan dispatched"));
    }

    #[tokio::test]
    async fn dispatch_vpn_deployment_status() {
        let bus = Bus::new();
        let mut sub = bus.subscribe("net.vpn.deployment.status_request");
        let resp = dispatch_command("vpn deployment status", &bus);

        assert!(resp.contains("deployment status requested"));
        let event = tokio::time::timeout(std::time::Duration::from_millis(100), sub.recv())
            .await
            .expect("deployment status request")
            .unwrap();
        assert!(matches!(
            event.message,
            Message::VpnDeploymentStatusRequest(request)
                if request.requested_by == "control_pipe"
        ));
    }

    #[test]
    fn dispatch_signatures_pending() {
        let bus = Bus::new();
        let resp = dispatch_command("signatures pending", &bus);
        assert!(resp.contains("signature staging unavailable"));
    }

    #[test]
    fn dispatch_signatures_pending_with_staging_returns_candidates() {
        let bus = Arc::new(Bus::new());
        let staging = StagingArea::new(Arc::clone(&bus));
        let candidate = imperium_protocol::SignatureCandidate {
            id: uuid::Uuid::new_v4(),
            rule_text: "rule pending { condition: true }".into(),
            description: "pending candidate".into(),
            source_events: vec![imperium_protocol::EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.91,
        };
        let id = staging.submit(candidate).unwrap();

        let resp = dispatch_command_with_staging("signatures pending", &bus, Some(&staging));
        let value: serde_json::Value = serde_json::from_str(&resp).unwrap();

        assert_eq!(value["status"], "ok");
        assert_eq!(value["pending_count"], 1);
        assert_eq!(value["candidates"][0]["id"], id.to_string());
    }

    #[test]
    fn dispatch_signatures_approve_valid_uuid() {
        let bus = Bus::new();
        let id = uuid::Uuid::new_v4();
        let cmd = format!("signatures approve {}", id);
        let resp = dispatch_command(&cmd, &bus);
        assert!(resp.contains("approval request dispatched"));
    }

    #[test]
    fn dispatch_signatures_approve_invalid_uuid() {
        let bus = Bus::new();
        let resp = dispatch_command("signatures approve not-a-uuid", &bus);
        assert!(resp.contains("invalid UUID"));
    }

    #[test]
    fn dispatch_signatures_reject_valid_uuid() {
        let bus = Bus::new();
        let id = uuid::Uuid::new_v4();
        let cmd = format!("signatures reject {} false positive", id);
        let resp = dispatch_command(&cmd, &bus);
        assert!(resp.contains("rejection dispatched"));
    }

    #[test]
    fn dispatch_signatures_extract_valid_ids() {
        let bus = Bus::new();
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        let cmd = format!("signatures extract {},{}", id1, id2);
        let resp = dispatch_command(&cmd, &bus);
        assert!(resp.contains("extraction requested for 2 events"));
    }

    #[test]
    fn dispatch_signatures_extract_invalid_id() {
        let bus = Bus::new();
        let resp = dispatch_command("signatures extract bad-id", &bus);
        assert!(resp.contains("invalid event UUID"));
    }

    #[test]
    fn dispatch_signatures_show_valid_uuid() {
        let bus = Bus::new();
        let id = uuid::Uuid::new_v4();
        let cmd = format!("signatures show {}", id);
        let resp = dispatch_command(&cmd, &bus);
        assert!(resp.contains(&id.to_string()));
        assert!(resp.contains("signature staging unavailable"));
    }

    #[test]
    fn dispatch_signatures_show_with_staging_returns_candidate() {
        let bus = Arc::new(Bus::new());
        let staging = StagingArea::new(Arc::clone(&bus));
        let candidate = imperium_protocol::SignatureCandidate {
            id: uuid::Uuid::new_v4(),
            rule_text: "rule quoted { condition: true }".into(),
            description: "operator staged candidate".into(),
            source_events: vec![imperium_protocol::EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.88,
        };
        let id = staging.submit(candidate).unwrap();
        let cmd = format!("signatures show {}", id);

        let resp = dispatch_command_with_staging(&cmd, &bus, Some(&staging));
        let value: serde_json::Value = serde_json::from_str(&resp).unwrap();

        assert_eq!(value["status"], "ok");
        assert_eq!(value["candidate_status"], "pending");
        assert_eq!(value["candidate"]["id"], id.to_string());
        assert_eq!(
            value["candidate"]["description"],
            "operator staged candidate"
        );
    }

    #[test]
    fn dispatch_shutdown() {
        let bus = Bus::new();
        let resp = dispatch_command("shutdown", &bus);
        assert!(resp.contains("shutdown initiated"));
    }

    #[test]
    fn dispatch_unknown_command() {
        let bus = Bus::new();
        let resp = dispatch_command("foo bar", &bus);
        assert!(resp.contains("unknown command"));
    }

    #[test]
    fn pipe_name_is_valid() {
        assert!(PIPE_NAME.starts_with(r"\\.\pipe\"));
    }

    #[test]
    fn dispatch_no_dead_cli_topics() {
        let bus = Bus::new();
        let id = uuid::Uuid::new_v4();
        let resp = dispatch_command(&format!("signatures approve {}", id), &bus);
        assert!(resp.contains("approval request dispatched"));
        assert!(!resp.contains("cli.signatures"));
    }
}
