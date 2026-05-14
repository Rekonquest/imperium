//! Cloakwise - Adaptive VPN Cluster Defense System
//!
//! An intelligent VPN node that uses AI to evade state-level censorship
//! by dynamically switching traffic profiles to avoid detection.

// Allow unused during development - these are all wired up incrementally
#![allow(unused_imports, unused_variables, dead_code, unused_mut, unused_assignments)]

mod bigmomma;
mod confidence;
mod config;
mod core;
mod enforcers;
mod fallback;
mod orchestrator;
mod sdr;
mod security;
mod specialists;
mod telemetry;
mod deploy;
mod mesh;
mod ui;
mod vpn;

use crate::config::Config;
use crate::orchestrator::Orchestrator;
use crate::telemetry::{channel, HealthChecker, TelemetryCollector};
use crate::vpn::profiles::ProfileTemplates;
use crate::vpn::TrafficProfile;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Command line arguments
#[derive(Debug)]
struct Args {
    /// Path to configuration file
    config: PathBuf,
    /// Run in verbose mode
    verbose: bool,
    /// Run in daemon mode
    daemon: bool,
}

impl Args {
    fn parse() -> Self {
        let args: Vec<String> = std::env::args().collect();

        #[cfg(windows)]
        let mut config = PathBuf::from("./configs/default.yaml");
        #[cfg(not(windows))]
        let mut config = PathBuf::from("/etc/cloakwise/cloakwise.yaml");
        let mut verbose = false;
        let mut daemon = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-c" | "--config" => {
                    if i + 1 < args.len() {
                        config = PathBuf::from(&args[i + 1]);
                        i += 1;
                    }
                }
                "-v" | "--verbose" => {
                    verbose = true;
                }
                "-d" | "--daemon" => {
                    daemon = true;
                }
                "-h" | "--help" => {
                    Self::print_help();
                    std::process::exit(0);
                }
                "-V" | "--version" => {
                    println!("cloakwise {}", env!("CARGO_PKG_VERSION"));
                    std::process::exit(0);
                }
                _ => {
                    eprintln!("Unknown argument: {}", args[i]);
                    Self::print_help();
                    std::process::exit(1);
                }
            }
            i += 1;
        }

        Self {
            config,
            verbose,
            daemon,
        }
    }

    fn print_help() {
        println!(
            r#"Cloakwise - Adaptive VPN Cluster Defense System

USAGE:
    cloakwise [OPTIONS]

OPTIONS:
    -c, --config <FILE>    Path to configuration file [default: /etc/cloakwise/cloakwise.yaml]
    -v, --verbose          Enable verbose logging
    -d, --daemon           Run in daemon mode (detach from terminal)
    -h, --help             Print help information
    -V, --version          Print version information

EXAMPLES:
    cloakwise -c /path/to/config.yaml
    cloakwise -v -c ./configs/default.yaml
"#
        );
    }
}

/// Initialize logging
fn init_logging(config: &Config, verbose: bool) -> Result<()> {
    let level = if verbose {
        Level::DEBUG
    } else {
        match config.logging.level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" | "warning" => Level::WARN,
            "error" => Level::ERROR,
            _ => Level::INFO,
        }
    };

    let filter = EnvFilter::from_default_env()
        .add_directive(format!("cloakwise={}", level).parse()?)
        .add_directive("hyper=warn".parse()?)
        .add_directive("reqwest=warn".parse()?);

    // Create log directory if needed
    if let Some(parent) = config.logging.file.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Set up file appender
    let file_appender = tracing_appender::rolling::daily(
        config.logging.file.parent().unwrap_or(&PathBuf::from(".")),
        config
            .logging
            .file
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("cloakwise.log")),
    );

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    if config.logging.json_format {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json().with_writer(non_blocking))
            .with(fmt::layer().with_writer(std::io::stderr))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_writer(non_blocking))
            .with(fmt::layer().with_writer(std::io::stderr))
            .init();
    }

    Ok(())
}

/// Main entry point
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Load configuration
    let config = if args.config.exists() {
        Config::load(&args.config).context(format!("Failed to load config from {:?}", args.config))?
    } else {
        warn!(
            "Config file {:?} not found, using defaults",
            args.config
        );
        // Use a minimal default config
        create_default_config()?
    };

    // Initialize logging
    init_logging(&config, args.verbose)?;

    info!("Starting Cloakwise v{}", env!("CARGO_PKG_VERSION"));
    info!("Node ID: {}", config.node.id);
    info!("Config loaded from: {:?}", args.config);

    // Daemonize if requested
    if args.daemon {
        #[cfg(unix)]
        {
            use nix::unistd::{fork, ForkResult};
            match unsafe { fork() } {
                Ok(ForkResult::Parent { .. }) => {
                    info!("Daemon started");
                    std::process::exit(0);
                }
                Ok(ForkResult::Child) => {
                    // Continue as child
                }
                Err(e) => {
                    error!("Fork failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(unix))]
        {
            warn!("Daemon mode not supported on this platform");
        }
    }

    let profiles_store = profiles_store_from_config(&config);

    // Create telemetry channel
    let (telemetry_tx, telemetry_rx) = channel(1000);

    // Create orchestrator (shares profile map with UI / API)
    let orchestrator = Orchestrator::new(config.clone(), profiles_store.clone())?;
    let shutdown_rx = orchestrator.shutdown_receiver();

    // Start telemetry collector
    let collector = TelemetryCollector::new(
        config.telemetry.clone(),
        telemetry_tx.clone(),
        shutdown_rx.clone(),
    );

    // Start health checker
    let health_checker = HealthChecker::new(
        config.fallback.health_check_endpoints.clone(),
        telemetry_tx.clone(),
        config.fallback.health_check_interval_secs,
        shutdown_rx.clone(),
    );

    let mesh_hub = if config.mesh.enabled {
        if let Err(e) = mesh::apply_overlay(&config.mesh).await {
            warn!("Mesh overlay (Headscale/tailscale): {}", e);
        }
        let h = mesh::MeshHub::new(config.node.id.clone(), &config.mesh);
        let h_run = Arc::clone(&h);
        let mesh_cfg = config.mesh.clone();
        let mesh_id = config.node.id.clone();
        let mesh_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            mesh::run_mesh(mesh_cfg, mesh_id, h_run, mesh_shutdown).await;
        });
        Some(h)
    } else {
        None
    };

    let ui_state = Arc::new(ui::AppState::new(
        config.node.id.clone(),
        profiles_store.clone(),
        config.deploy.clone(),
        config.models.clone(),
        mesh_hub,
    ));

    let (action_tx, action_rx) = tokio::sync::mpsc::unbounded_channel();
    *ui_state.action_tx.write() = Some(action_tx);

    orchestrator.link_ui(ui_state.clone(), action_rx).await;

    // Spawn background tasks
    let collector_handle = tokio::spawn(async move {
        if let Err(e) = collector.run().await {
            error!("Telemetry collector error: {}", e);
        }
    });

    let health_handle = tokio::spawn(async move {
        if let Err(e) = health_checker.run().await {
            error!("Health checker error: {}", e);
        }
    });

    // Start UI server
    let ui_shutdown_rx = shutdown_rx.clone();
    let ui_state_clone = ui_state.clone();
    let ui_port = config.clients.config_api_port;
    let ui_bind = config.clients.api_bind_address;
    let ui_handle = tokio::spawn(async move {
        ui::start_server(ui_state_clone, ui_port, ui_bind, ui_shutdown_rx).await;
    });

    info!("UI dashboard available at http://0.0.0.0:{}", ui_port);

    let shutdown_tx = orchestrator.shutdown_sender();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to register SIGTERM handler");

            tokio::select! {
                _ = signal::ctrl_c() => {
                    info!("Received SIGINT, shutting down");
                    let _ = shutdown_tx.send(true);
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, shutting down");
                    let _ = shutdown_tx.send(true);
                }
            }
        }

        #[cfg(not(unix))]
        {
            let _ = signal::ctrl_c().await;
            info!("Received SIGINT, shutting down");
            let _ = shutdown_tx.send(true);
        }
    });

    // Run orchestrator (main loop)
    let orchestrator_result = orchestrator.run(telemetry_rx).await;

    // Wait for background tasks to complete
    let _ = collector_handle.await;
    let _ = health_handle.await;
    let _ = ui_handle.await;

    info!("Cloakwise shutting down");

    orchestrator_result
}

fn profiles_store_from_config(
    config: &Config,
) -> Arc<parking_lot::RwLock<HashMap<String, TrafficProfile>>> {
    let store = Arc::new(parking_lot::RwLock::new(HashMap::new()));
    {
        let mut w = store.write();
        for (id, profile_config) in &config.profiles {
            w.insert(
                id.clone(),
                TrafficProfile::from_config(id, profile_config),
            );
        }
        for template in ProfileTemplates::all() {
            w.entry(template.id.clone()).or_insert(template);
        }
    }
    store
}

/// Create a minimal default configuration
fn create_default_config() -> Result<Config> {
    use std::collections::HashMap;

    Ok(Config {
        node: config::NodeConfig {
            id: format!("cloakwise-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            admin_contact: "admin@example.com".to_string(),
            cluster_peers: vec![],
        },
        models: config::ModelsConfig {
            specialists_dir: PathBuf::from("./models/specialists/"),
            big_momma: PathBuf::from("./models/big_momma.gguf"),
            inference: config::InferenceConfig {
                threads: 4,
                context_size: 2048,
                batch_size: 512,
                temperature: 0.1,
                max_tokens: 256,
            },
            api_endpoint: None,
            api_model: None,
        },
        confidence: config::ConfidenceConfig {
            specialist_threshold: 0.95,
            escalation_timeout_ms: 5000,
            min_specialists_for_consensus: 3,
        },
        fallback: config::FallbackConfig {
            timed_rotation_hours: 4,
            failure_threshold: 50,
            failure_window_minutes: 10,
            health_check_interval_secs: 60,
            health_check_endpoints: vec![
                "https://www.google.com".to_string(),
                "https://cloudflare.com/cdn-cgi/trace".to_string(),
            ],
            profile_rotation_order: vec![
                "https_clone".to_string(),
                "video_call".to_string(),
                "websocket".to_string(),
                "gaming".to_string(),
            ],
            safe_mode_profile: "https_clone".to_string(),
            safe_mode_lock_minutes: 30,
        },
        profiles: {
            let mut map = HashMap::new();
            map.insert(
                "https_clone".to_string(),
                config::ProfileConfig {
                    protocol: config::Protocol::Cloak,
                    port: 443,
                    obfuscation: Some(config::ObfuscationType::Tls1_3),
                    timing: Some(config::TimingPattern::WebBrowsing),
                    padding: Some(config::PaddingType::Variable),
                    max_concurrent: 100,
                    custom_config: HashMap::new(),
                },
            );
            map.insert(
                "video_call".to_string(),
                config::ProfileConfig {
                    protocol: config::Protocol::Amneziawg,
                    port: 443,
                    obfuscation: None,
                    timing: Some(config::TimingPattern::WebrtcPattern),
                    padding: Some(config::PaddingType::Variable),
                    max_concurrent: 10,
                    custom_config: HashMap::new(),
                },
            );
            map
        },
        vpn: config::VpnConfig {
            interface: "wg0".to_string(),
            #[cfg(windows)]
            config_dir: PathBuf::from("./configs/vpn/"),
            #[cfg(not(windows))]
            config_dir: PathBuf::from("/etc/wireguard/"),
            reload_command: "wg syncconf wg0 <(wg-quick strip wg0)".to_string(),
            pre_switch_hook: None,
            post_switch_hook: None,
        },
        clients: config::ClientsConfig {
            config_api_port: 8080,
            push_notifications: false,
            api_bind_address: None,
            api_auth_token: None,
        },
        telemetry: config::TelemetryConfig {
            capture_method: config::CaptureMethod::VpnLogs,
            #[cfg(windows)]
            log_path: PathBuf::from("./logs/vpn/"),
            #[cfg(not(windows))]
            log_path: PathBuf::from("/var/log/wireguard/"),
            sample_rate: 1.0,
            packet_capture_interface: None,
        },
        logging: config::LoggingConfig {
            level: "info".to_string(),
            #[cfg(windows)]
            file: PathBuf::from("./logs/cloakwise.log"),
            #[cfg(not(windows))]
            file: PathBuf::from("/var/log/cloakwise/cloakwise.log"),
            json_format: false,
            max_size_mb: 100,
            max_files: 5,
        },
        deploy: config::DeployConfig::default(),
        mesh: config::MeshConfig::default(),
    })
}
