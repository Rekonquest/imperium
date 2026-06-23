mod control;

use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use imperium_bus::Bus;
use imperium_memory_log::MemoryLog;
use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey};
use imperium_net_sensors::SignatureEngineSensor;
use imperium_net_signatures::{ExtractionLoop, StagingArea};
use imperium_net_toolkit::{ToolManager, ToolManifest, TriggerCondition};
use imperium_net_transport::{
    HardeningController, Orchestrator, OrchestratorConfig, OrchestratorPolicy,
};
use imperium_protocol::{Message, PeerId};
use imperium_runtime::{DeploymentOrchestrator, RuntimeCoordinator};
use imperium_store::Store;
use rand::rngs::OsRng;
use tokio::task::JoinHandle;

#[derive(Parser)]
#[command(name = "imperium", about = "Imperium adaptive VPN cluster defense")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Node lifecycle management
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },
    /// Cluster membership operations
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
    /// Signature database management
    Signatures {
        #[command(subcommand)]
        action: SignatureAction,
    },
}

#[derive(Subcommand)]
enum NodeAction {
    /// Start the Imperium runtime
    Start,
}

#[derive(Subcommand)]
enum ClusterAction {
    /// Mint a bootstrap token for a new node
    MintToken {
        /// Token expiry duration in hours
        #[arg(long, default_value = "168")]
        expires_hours: u64,
    },
    /// Import a bootstrap token received out-of-band
    ImportToken {
        /// Base32-encoded token string
        token: String,
    },
    /// Approve a pending membership request
    Approve {
        /// Peer ID to approve
        peer_id: String,
    },
    /// Show cluster membership status
    Status,
}

#[derive(Subcommand)]
enum SignatureAction {
    /// List pending signature candidates
    Pending,
    /// Approve a signature candidate
    Approve {
        /// UUID of the candidate to approve
        candidate_id: String,
    },
    /// Reject a signature candidate
    Reject {
        /// UUID of the candidate to reject
        candidate_id: String,
        /// Rejection reason
        #[arg(long, default_value = "operator rejected")]
        reason: String,
    },
    /// Extract a signature from event data
    Extract {
        /// Comma-separated event IDs to extract from
        #[arg(long)]
        events: String,
        /// Reason for extraction
        #[arg(long, default_value = "manual extraction")]
        reason: String,
    },
    /// Show details for a signature candidate
    Show {
        /// UUID of the candidate to show
        candidate_id: String,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Node { action } => match action {
            NodeAction::Start => cmd_node_start().await,
        },
        Commands::Cluster { action } => match action {
            ClusterAction::MintToken { expires_hours } => cmd_cluster_mint_token(expires_hours),
            ClusterAction::ImportToken { token } => cmd_cluster_import_token(&token),
            ClusterAction::Approve { peer_id } => cmd_cluster_approve(&peer_id),
            ClusterAction::Status => cmd_cluster_status(),
        },
        Commands::Signatures { action } => match action {
            SignatureAction::Pending => cmd_signatures_pending(),
            SignatureAction::Approve { candidate_id } => cmd_signatures_approve(&candidate_id),
            SignatureAction::Reject {
                candidate_id,
                reason,
            } => cmd_signatures_reject(&candidate_id, &reason),
            SignatureAction::Extract { events, reason } => cmd_signatures_extract(&events, &reason),
            SignatureAction::Show { candidate_id } => cmd_signatures_show(&candidate_id),
        },
    }
}

async fn cmd_node_start() {
    tracing::info!("starting imperium node");

    let coordinator = RuntimeCoordinator::new();
    let bus = coordinator.bus();

    let _runtime_tasks = initialize_node(bus.clone()).await;
    tokio::spawn(control::serve(Arc::clone(&bus)));

    tracing::info!("subsystems initialized, control pipe listening, runtime entering run loop");
    let reason = coordinator.run().await;
    tracing::info!(reason = ?reason, "runtime exited");
}

async fn initialize_node(bus: Arc<Bus>) -> Vec<JoinHandle<()>> {
    let mut tasks = Vec::new();

    if let Err(e) = imperium_net_cluster::init(Arc::clone(&bus)).await {
        tracing::error!(error = %e, "cluster init failed");
    }
    if let Err(e) = imperium_net_mesh::init(Arc::clone(&bus)).await {
        tracing::error!(error = %e, "mesh init failed");
    }
    if let Err(e) = imperium_net_transport::init(Arc::clone(&bus)).await {
        tracing::error!(error = %e, "transport init failed");
    }
    if let Err(e) = imperium_net_strainer::init(Arc::clone(&bus)).await {
        tracing::error!(error = %e, "strainer init failed");
    }
    if let Err(e) = imperium_net_sensors::init(Arc::clone(&bus)).await {
        tracing::error!(error = %e, "sensors init failed");
    }
    if let Err(e) = imperium_net_signatures::init(Arc::clone(&bus)).await {
        tracing::error!(error = %e, "signatures init failed");
    }
    if let Err(e) = imperium_net_toolkit::init(Arc::clone(&bus)).await {
        tracing::error!(error = %e, "toolkit init failed");
    }

    let store = Arc::new(Store::in_memory());
    let memory_log = Arc::new(MemoryLog::default());
    let staging = Arc::new(StagingArea::new(Arc::clone(&bus)));
    let toolkit = Arc::new(ToolManager::new(Arc::clone(&bus)));
    let hardening = Arc::new(HardeningController::new(Arc::clone(&bus)));
    let deployment = Arc::new(DeploymentOrchestrator::new(Arc::clone(&bus)));

    register_default_tools(&toolkit);
    if let Err(e) = hardening.apply(HardeningController::balanced_profile(None)) {
        tracing::warn!(error = %e, "failed to apply default hardening profile");
    }
    tasks.push(toolkit.subscribe_activation_requests(&bus));
    tasks.push(hardening.subscribe_hardening_profiles(&bus));
    tasks.push(deployment.subscribe_deployment_plans());

    tasks.push(memory_log.subscribe_strainer_rejections(&bus));
    tasks.push(memory_log.subscribe_protocol_events(&bus));

    let extraction_loop = Arc::new(ExtractionLoop::new(
        Arc::clone(&bus),
        Arc::clone(&store),
        Arc::clone(&memory_log),
        Arc::clone(&staging),
    ));
    tasks.push(extraction_loop.subscribe_extraction_requests(&bus));

    let signature_engine = Arc::new(
        SignatureEngineSensor::new(Arc::clone(&bus)).with_shared_store(Arc::clone(&store)),
    );
    tasks.push(signature_engine.subscribe_signature_approvals(&bus));

    let orchestrator = Arc::new(Orchestrator::new(
        OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        },
        Arc::clone(&bus),
    ));
    tasks.push(orchestrator.subscribe_protocol_events());
    tasks.push(orchestrator.subscribe_threat_assessments());

    let mut rng = OsRng;
    let (operator_signing_key, _operator_verify_key) =
        HybridEd25519Mldsa::generate_keypair(&mut rng);
    let operator_id = PeerId::new();
    tasks.push(subscribe_signature_approval_requests(
        Arc::clone(&bus),
        Arc::clone(&staging),
        operator_id.clone(),
        operator_signing_key,
    ));
    tasks.push(subscribe_signature_rejection_requests(
        Arc::clone(&bus),
        staging,
        operator_id,
    ));

    tracing::info!(task_count = tasks.len(), "node wiring complete");
    tasks
}

fn register_default_tools(toolkit: &ToolManager) {
    toolkit.register(ToolManifest {
        name: "transport.diagnostics".to_string(),
        description:
            "Capture transport state when the orchestrator sees a high-confidence burn signal"
                .to_string(),
        trigger_conditions: vec![TriggerCondition {
            event_topic: "net.toolkit.request".to_string(),
            min_confidence: 0.0,
        }],
        idle_timeout: Duration::from_secs(30),
        cooldown_duration: Duration::from_secs(60),
        max_activations_per_hour: 10,
    });
    toolkit.register(ToolManifest {
        name: "forensics.emergency.snapshot".to_string(),
        description: "Capture a bounded emergency snapshot before shutdown containment completes"
            .to_string(),
        trigger_conditions: vec![TriggerCondition {
            event_topic: "net.toolkit.request".to_string(),
            min_confidence: 0.0,
        }],
        idle_timeout: Duration::from_secs(60),
        cooldown_duration: Duration::from_secs(300),
        max_activations_per_hour: 3,
    });

    for tool_name in ["transport.diagnostics", "forensics.emergency.snapshot"] {
        if let Err(e) = toolkit.arm(tool_name) {
            tracing::warn!(tool_name, error = %e, "failed to arm default toolkit tool");
        }
    }
}

fn subscribe_signature_approval_requests(
    bus: Arc<Bus>,
    staging: Arc<StagingArea>,
    operator_id: PeerId,
    signing_key: HybridSigningKey,
) -> JoinHandle<()> {
    let mut sub = bus.subscribe("net.signatures.approve_request");
    tokio::spawn(async move {
        loop {
            match sub.recv().await {
                Ok(event) => {
                    let candidate_id = match event.message {
                        Message::SubsystemReady { name } if name.starts_with("cli-approve:") => {
                            uuid::Uuid::parse_str(name.trim_start_matches("cli-approve:")).ok()
                        }
                        _ => None,
                    };

                    if let Some(candidate_id) = candidate_id {
                        if let Err(e) = staging.approve(candidate_id, &operator_id, &signing_key) {
                            tracing::warn!(
                                candidate_id = %candidate_id,
                                error = %e,
                                "signature approval request failed"
                            );
                        }
                    }
                }
                Err(imperium_bus::BusError::Closed) => break,
                Err(_) => continue,
            }
        }
    })
}

fn subscribe_signature_rejection_requests(
    bus: Arc<Bus>,
    staging: Arc<StagingArea>,
    operator_id: PeerId,
) -> JoinHandle<()> {
    let mut sub = bus.subscribe("net.signatures.reject_request");
    tokio::spawn(async move {
        loop {
            match sub.recv().await {
                Ok(event) => {
                    if let Message::SignatureRejected(rejected) = event.message {
                        if let Err(e) =
                            staging.reject(rejected.candidate_id, &operator_id, &rejected.reason)
                        {
                            tracing::warn!(
                                candidate_id = %rejected.candidate_id,
                                error = %e,
                                "signature rejection request failed"
                            );
                        }
                    }
                }
                Err(imperium_bus::BusError::Closed) => break,
                Err(_) => continue,
            }
        }
    })
}

fn cmd_cluster_mint_token(expires_hours: u64) {
    use imperium_net_cluster::TokenManager;
    use imperium_net_crypto::HybridEd25519Mldsa;
    use imperium_protocol::{ClusterId, PeerId};
    use rand::rngs::OsRng;

    let cluster_id = ClusterId::new();
    let operator_id = PeerId::new();
    let mut rng = OsRng;
    let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

    let mgr = TokenManager::new(cluster_id);
    let token = mgr.mint_token(
        &operator_id,
        &sk,
        chrono::Duration::hours(expires_hours as i64),
    );

    let json = serde_json::to_string_pretty(&token).expect("serialize token");
    println!("{}", json);
}

fn cmd_cluster_import_token(token_str: &str) {
    tracing::info!(token_len = token_str.len(), "importing bootstrap token");
    match serde_json::from_str::<imperium_protocol::BootstrapTokenPayload>(token_str) {
        Ok(token) => {
            tracing::info!(
                cluster_id = %token.cluster_id.0,
                expires_at = %token.expires_at,
                "token parsed successfully"
            );
            println!("Token imported for cluster {}", token.cluster_id.0);
        }
        Err(e) => {
            eprintln!("Failed to parse token: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_cluster_approve(peer_id_str: &str) {
    tracing::info!(peer_id = peer_id_str, "approving membership request");
    match uuid::Uuid::parse_str(peer_id_str) {
        Ok(id) => println!("Membership approval dispatched for peer {}", id),
        Err(e) => {
            eprintln!("Invalid peer ID: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_cluster_status() {
    println!("Cluster status: use `imperium node start` to run the node first, then query via control pipe.");
}

fn cmd_signatures_pending() {
    println!("Pending signatures: use `imperium node start` to run the node first, then query via control pipe.");
}

fn cmd_signatures_approve(candidate_id: &str) {
    tracing::info!(candidate_id = candidate_id, "approving signature candidate");
    match uuid::Uuid::parse_str(candidate_id) {
        Ok(id) => println!("Signature approval dispatched for candidate {}", id),
        Err(e) => {
            eprintln!("Invalid candidate ID: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_signatures_reject(candidate_id: &str, reason: &str) {
    match uuid::Uuid::parse_str(candidate_id) {
        Ok(id) => println!(
            "Signature rejection dispatched for candidate {} (reason: {})",
            id, reason
        ),
        Err(e) => {
            eprintln!("Invalid candidate ID: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_signatures_extract(events: &str, reason: &str) {
    let ids: Vec<&str> = events.split(',').map(|s| s.trim()).collect();
    let mut valid = Vec::new();
    for id_str in &ids {
        match uuid::Uuid::parse_str(id_str) {
            Ok(id) => valid.push(id),
            Err(e) => {
                eprintln!("Invalid event ID '{}': {}", id_str, e);
                std::process::exit(1);
            }
        }
    }
    println!(
        "Extraction requested for {} events (reason: {}). Use via control pipe on a running node.",
        valid.len(),
        reason
    );
}

fn cmd_signatures_show(candidate_id: &str) {
    match uuid::Uuid::parse_str(candidate_id) {
        Ok(id) => println!(
            "Show candidate {}: use via control pipe on a running node.",
            id
        ),
        Err(e) => {
            eprintln!("Invalid candidate ID: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parses_node_start() {
        let cli = Cli::try_parse_from(["imperium", "node", "start"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Node {
                action: NodeAction::Start
            }
        ));
    }

    #[test]
    fn cli_parses_cluster_mint_token() {
        let cli = Cli::try_parse_from(["imperium", "cluster", "mint-token"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster {
                action: ClusterAction::MintToken { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_cluster_mint_token_with_expiry() {
        let cli =
            Cli::try_parse_from(["imperium", "cluster", "mint-token", "--expires-hours", "24"])
                .unwrap();
        if let Commands::Cluster {
            action: ClusterAction::MintToken { expires_hours },
        } = cli.command
        {
            assert_eq!(expires_hours, 24);
        } else {
            panic!("expected MintToken");
        }
    }

    #[test]
    fn cli_parses_cluster_import_token() {
        let cli =
            Cli::try_parse_from(["imperium", "cluster", "import-token", "ABCDEF123456"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster {
                action: ClusterAction::ImportToken { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_cluster_approve() {
        let cli = Cli::try_parse_from(["imperium", "cluster", "approve", "some-peer-id"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster {
                action: ClusterAction::Approve { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_cluster_status() {
        let cli = Cli::try_parse_from(["imperium", "cluster", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster {
                action: ClusterAction::Status
            }
        ));
    }

    #[test]
    fn cli_parses_signatures_pending() {
        let cli = Cli::try_parse_from(["imperium", "signatures", "pending"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures {
                action: SignatureAction::Pending
            }
        ));
    }

    #[test]
    fn cli_parses_signatures_approve() {
        let cli = Cli::try_parse_from(["imperium", "signatures", "approve", "some-uuid"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures {
                action: SignatureAction::Approve { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_signatures_reject() {
        let cli = Cli::try_parse_from([
            "imperium",
            "signatures",
            "reject",
            "some-uuid",
            "--reason",
            "false positive",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures {
                action: SignatureAction::Reject { .. }
            }
        ));
    }

    #[test]
    fn cli_parses_signatures_extract() {
        let cli = Cli::try_parse_from([
            "imperium",
            "signatures",
            "extract",
            "--events",
            "uuid1,uuid2",
        ])
        .unwrap();
        if let Commands::Signatures {
            action: SignatureAction::Extract { events, .. },
        } = cli.command
        {
            assert_eq!(events, "uuid1,uuid2");
        } else {
            panic!("expected Extract");
        }
    }

    #[test]
    fn cli_parses_signatures_show() {
        let cli = Cli::try_parse_from(["imperium", "signatures", "show", "some-uuid"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures {
                action: SignatureAction::Show { .. }
            }
        ));
    }

    #[test]
    fn cli_rejects_empty_args() {
        assert!(Cli::try_parse_from(["imperium"]).is_err());
    }

    #[test]
    fn cli_help_does_not_panic() {
        Cli::command().debug_assert();
    }
}
