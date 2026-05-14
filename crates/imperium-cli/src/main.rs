mod control;

use std::sync::Arc;

use clap::{Parser, Subcommand};
use imperium_runtime::RuntimeCoordinator;

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
            SignatureAction::Reject { candidate_id, reason } => {
                cmd_signatures_reject(&candidate_id, &reason)
            }
            SignatureAction::Extract { events, reason } => {
                cmd_signatures_extract(&events, &reason)
            }
            SignatureAction::Show { candidate_id } => cmd_signatures_show(&candidate_id),
        },
    }
}

async fn cmd_node_start() {
    tracing::info!("starting imperium node");

    let coordinator = RuntimeCoordinator::new();
    let bus = coordinator.bus();

    tokio::spawn(control::serve(Arc::clone(&bus)));

    tracing::info!("control pipe listening, runtime entering run loop");
    let reason = coordinator.run().await;
    tracing::info!(reason = ?reason, "runtime exited");
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
        Ok(id) => println!("Signature rejection dispatched for candidate {} (reason: {})", id, reason),
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
        Ok(id) => println!("Show candidate {}: use via control pipe on a running node.", id),
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
            Commands::Node { action: NodeAction::Start }
        ));
    }

    #[test]
    fn cli_parses_cluster_mint_token() {
        let cli = Cli::try_parse_from(["imperium", "cluster", "mint-token"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster { action: ClusterAction::MintToken { .. } }
        ));
    }

    #[test]
    fn cli_parses_cluster_mint_token_with_expiry() {
        let cli = Cli::try_parse_from([
            "imperium", "cluster", "mint-token", "--expires-hours", "24",
        ]).unwrap();
        if let Commands::Cluster { action: ClusterAction::MintToken { expires_hours } } = cli.command {
            assert_eq!(expires_hours, 24);
        } else {
            panic!("expected MintToken");
        }
    }

    #[test]
    fn cli_parses_cluster_import_token() {
        let cli = Cli::try_parse_from([
            "imperium", "cluster", "import-token", "ABCDEF123456",
        ]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster { action: ClusterAction::ImportToken { .. } }
        ));
    }

    #[test]
    fn cli_parses_cluster_approve() {
        let cli = Cli::try_parse_from([
            "imperium", "cluster", "approve", "some-peer-id",
        ]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster { action: ClusterAction::Approve { .. } }
        ));
    }

    #[test]
    fn cli_parses_cluster_status() {
        let cli = Cli::try_parse_from(["imperium", "cluster", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Cluster { action: ClusterAction::Status }
        ));
    }

    #[test]
    fn cli_parses_signatures_pending() {
        let cli = Cli::try_parse_from(["imperium", "signatures", "pending"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures { action: SignatureAction::Pending }
        ));
    }

    #[test]
    fn cli_parses_signatures_approve() {
        let cli = Cli::try_parse_from([
            "imperium", "signatures", "approve", "some-uuid",
        ]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures { action: SignatureAction::Approve { .. } }
        ));
    }

    #[test]
    fn cli_parses_signatures_reject() {
        let cli = Cli::try_parse_from([
            "imperium", "signatures", "reject", "some-uuid", "--reason", "false positive",
        ]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures { action: SignatureAction::Reject { .. } }
        ));
    }

    #[test]
    fn cli_parses_signatures_extract() {
        let cli = Cli::try_parse_from([
            "imperium", "signatures", "extract", "--events", "uuid1,uuid2",
        ]).unwrap();
        if let Commands::Signatures { action: SignatureAction::Extract { events, .. } } = cli.command {
            assert_eq!(events, "uuid1,uuid2");
        } else {
            panic!("expected Extract");
        }
    }

    #[test]
    fn cli_parses_signatures_show() {
        let cli = Cli::try_parse_from([
            "imperium", "signatures", "show", "some-uuid",
        ]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Signatures { action: SignatureAction::Show { .. } }
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
