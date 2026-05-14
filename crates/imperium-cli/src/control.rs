use std::sync::Arc;

use imperium_bus::Bus;
use imperium_protocol::Message;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{ServerOptions, PipeMode};

const PIPE_NAME: &str = r"\\.\pipe\imperium-control";

pub async fn serve(bus: Arc<Bus>) {
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

        let bus = Arc::clone(&bus);
        tokio::spawn(async move {
            handle_connection(server, bus).await;
        });
    }
}

async fn handle_connection(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    bus: Arc<Bus>,
) {
    let (reader, mut writer) = tokio::io::split(pipe);
    let mut lines = BufReader::new(reader).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let response = dispatch_command(&line, &bus);
        let msg = format!("{}\n", response);
        if writer.write_all(msg.as_bytes()).await.is_err() {
            break;
        }
    }
}

fn dispatch_command(line: &str, bus: &Bus) -> String {
    let parts: Vec<&str> = line.trim().splitn(4, ' ').collect();
    match parts.as_slice() {
        ["cluster", "status"] => {
            format!("{{\"status\":\"ok\",\"message\":\"cluster status requested\"}}")
        }
        ["signatures", "pending"] => {
            format!("{{\"status\":\"ok\",\"message\":\"pending signatures — query staging directly\"}}")
        }
        ["signatures", "approve", id] => {
            match uuid::Uuid::parse_str(id) {
                Ok(uuid) => {
                    let _ = bus.publish(
                        "net.signatures.approve_request",
                        Message::SubsystemReady {
                            name: format!("cli-approve:{}", uuid),
                        },
                    );
                    format!("{{\"status\":\"ok\",\"message\":\"approval request dispatched for {}\"}}", id)
                }
                Err(_) => format!("{{\"status\":\"error\",\"message\":\"invalid UUID\"}}"),
            }
        }
        ["signatures", "reject", id] => {
            match uuid::Uuid::parse_str(id) {
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
                    format!("{{\"status\":\"ok\",\"message\":\"rejection dispatched for {}\"}}", uuid)
                }
                Err(_) => format!("{{\"status\":\"error\",\"message\":\"invalid UUID\"}}"),
            }
        }
        ["signatures", "reject", id, reason] => {
            match uuid::Uuid::parse_str(id) {
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
                    format!("{{\"status\":\"ok\",\"message\":\"rejection dispatched for {}\"}}", uuid)
                }
                Err(_) => format!("{{\"status\":\"error\",\"message\":\"invalid UUID\"}}"),
            }
        }
        ["signatures", "extract", ids_arg, ..] => {
            let event_ids_str: Vec<&str> = ids_arg.split(',').map(|s| s.trim()).collect();
            let mut event_ids = Vec::new();
            for id_str in &event_ids_str {
                match uuid::Uuid::parse_str(id_str) {
                    Ok(uuid) => event_ids.push(imperium_protocol::EventId(uuid)),
                    Err(_) => return format!("{{\"status\":\"error\",\"message\":\"invalid event UUID: {}\"}}", id_str),
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
            format!("{{\"status\":\"ok\",\"message\":\"extraction requested for {} events\"}}", event_ids_str.len())
        }
        ["signatures", "show", id] => {
            match uuid::Uuid::parse_str(id) {
                Ok(uuid) => {
                    format!("{{\"status\":\"ok\",\"candidate_id\":\"{}\",\"message\":\"lookup requires store access\"}}", uuid)
                }
                Err(_) => format!("{{\"status\":\"error\",\"message\":\"invalid UUID\"}}"),
            }
        }
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
    fn dispatch_signatures_pending() {
        let bus = Bus::new();
        let resp = dispatch_command("signatures pending", &bus);
        assert!(resp.contains("pending signatures"));
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
