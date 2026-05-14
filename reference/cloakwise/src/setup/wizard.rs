//! Interactive Setup Wizard
//!
//! Guides users through Cloakwise configuration with hardware detection,
//! protocol selection, and AI configuration based on detected capabilities.

use std::fs;
use std::path::PathBuf;

use super::config_builder::*;
use super::hardware_detect::{HardwareProfile, HardwareTier};
use super::prompts::*;

/// Run the interactive setup wizard
pub fn run_wizard() -> Result<SetupChoices, WizardError> {
    clear_screen();
    print_banner();

    println!();
    print_info("Welcome to Cloakwise Setup Wizard");
    print_info("This wizard will help you configure your adaptive VPN defense system.");
    println!();

    wait_for_enter("Ready to begin?");

    // Step 1: Hardware Detection
    let hardware = run_hardware_detection()?;

    // Step 2: Basic Configuration
    let (node_id, admin_email) = get_basic_config()?;

    // Step 3: Hardware Tier Selection
    let tier = select_hardware_tier(&hardware)?;

    // Step 4: Protocol Selection
    let protocols = select_protocols(&tier)?;

    // Step 5: AI Configuration
    let ai_config = configure_ai(&tier)?;

    // Step 6: Security Tools
    let security_tools = select_security_tools(&tier)?;

    // Step 7: SDR Configuration (if hardware detected)
    let sdr_config = configure_sdr(&hardware)?;

    // Step 8: Network Configuration
    let network_config = configure_network()?;

    // Step 9: Logging Configuration
    let logging_config = configure_logging()?;

    // Build choices
    let choices = SetupChoices {
        node_id,
        admin_email,
        hardware_tier: Some(tier),
        protocols,
        ai_config,
        security_tools,
        sdr_config,
        network_config,
        logging_config,
    };

    // Step 10: Review and Confirm
    review_and_save(&choices)?;

    Ok(choices)
}

/// Wizard error types
#[derive(Debug)]
pub enum WizardError {
    Cancelled,
    IoError(std::io::Error),
    ConfigError(String),
}

impl std::fmt::Display for WizardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WizardError::Cancelled => write!(f, "Setup cancelled by user"),
            WizardError::IoError(e) => write!(f, "IO error: {}", e),
            WizardError::ConfigError(s) => write!(f, "Configuration error: {}", s),
        }
    }
}

impl std::error::Error for WizardError {}

impl From<std::io::Error> for WizardError {
    fn from(err: std::io::Error) -> Self {
        WizardError::IoError(err)
    }
}

/// Step 1: Run hardware detection
fn run_hardware_detection() -> Result<HardwareProfile, WizardError> {
    print_section("Hardware Detection");
    print_info("Scanning system capabilities...");
    println!();

    let hardware = HardwareProfile::detect();

    // Display results
    println!("  {}", hardware.summary());
    println!();

    // Show detailed info
    println!("  {}Detected Components:{}", colors::BOLD, colors::RESET);
    println!("    RAM:        {} MB", hardware.ram_mb);
    println!("    CPU Cores:  {}", hardware.cpu_cores);
    if let Some(mhz) = hardware.cpu_mhz {
        println!("    CPU Speed:  {} MHz", mhz);
    }
    println!("    GPU:        {}", if hardware.gpu_available { "Yes" } else { "No" });
    println!("    TPM:        {}", if hardware.tpm_available { "Yes" } else { "No" });
    println!("    Disk:       {} MB available", hardware.disk_mb);

    if !hardware.sdr_devices.is_empty() {
        println!();
        println!("  {}SDR Devices Found:{}", colors::BOLD, colors::RESET);
        for dev in &hardware.sdr_devices {
            println!("    - {} at {}", dev.device_type, dev.device_path);
            println!("      Capabilities: {}", dev.capabilities.join(", "));
        }
    }

    if !hardware.network_interfaces.is_empty() {
        println!();
        println!("  {}Network Interfaces:{}", colors::BOLD, colors::RESET);
        for iface in &hardware.network_interfaces {
            println!("    - {}", iface);
        }
    }

    println!();
    print_success(&format!(
        "Recommended tier: {} - {}",
        hardware.recommended_tier.name(),
        hardware.recommended_tier.description()
    ));

    wait_for_enter("");

    Ok(hardware)
}

/// Step 2: Get basic configuration
fn get_basic_config() -> Result<(String, String), WizardError> {
    print_section("Basic Configuration");

    // Generate default node ID
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "node".to_string());
    let default_id = format!("{}-{}", hostname, &uuid::Uuid::new_v4().to_string()[..8]);

    let node_id = prompt_text("Node ID:", Some(&default_id));
    let admin_email = prompt_text("Admin contact email:", Some("admin@localhost"));

    println!();
    print_success(&format!("Node ID: {}", node_id));
    print_success(&format!("Admin: {}", admin_email));

    Ok((node_id, admin_email))
}

/// Step 3: Select hardware tier
fn select_hardware_tier(hardware: &HardwareProfile) -> Result<HardwareTier, WizardError> {
    print_section("Hardware Tier Selection");

    print_info("Select the configuration tier for your hardware:");
    print_info(&format!(
        "Based on your system, we recommend: {}",
        hardware.recommended_tier.name()
    ));

    let options = [
        (HardwareTier::Minimal.name(), HardwareTier::Minimal.description()),
        (HardwareTier::Standard.name(), HardwareTier::Standard.description()),
        (HardwareTier::Enhanced.name(), HardwareTier::Enhanced.description()),
        (HardwareTier::Lab.name(), HardwareTier::Lab.description()),
    ];

    let default_idx = match hardware.recommended_tier {
        HardwareTier::Minimal => 0,
        HardwareTier::Standard => 1,
        HardwareTier::Enhanced => 2,
        HardwareTier::Lab => 3,
    };

    let selection = prompt_menu("Select hardware tier:", &options, default_idx);

    let tier = match selection {
        0 => HardwareTier::Minimal,
        1 => HardwareTier::Standard,
        2 => HardwareTier::Enhanced,
        3 => HardwareTier::Lab,
        _ => hardware.recommended_tier,
    };

    println!();
    print_success(&format!("Selected tier: {}", tier.name()));

    if tier != hardware.recommended_tier {
        print_warning("Note: Selected tier differs from recommended. Performance may vary.");
    }

    Ok(tier)
}

/// Step 4: Select protocols
fn select_protocols(tier: &HardwareTier) -> Result<Vec<ProtocolChoice>, WizardError> {
    print_section("Protocol Selection");

    print_info("Select which VPN protocols to enable:");
    print_info("Protocols with higher stealth are recommended for censored regions.");

    let all_protocols = Protocol::all();
    let recommended = Protocol::recommended_stealth();

    let options: Vec<(&str, &str, bool)> = all_protocols
        .iter()
        .map(|p| {
            let is_recommended = recommended.contains(p);
            (p.name(), p.description(), is_recommended)
        })
        .collect();

    // Convert to the format prompt_multi_select expects
    let options_refs: Vec<(&str, &str, bool)> = options
        .iter()
        .map(|(n, d, r)| (*n, *d, *r))
        .collect();

    let selected_indices = prompt_multi_select("Enable protocols:", &options_refs);

    let mut protocols: Vec<ProtocolChoice> = Vec::new();
    for (i, protocol) in all_protocols.iter().enumerate() {
        let enabled = selected_indices.contains(&i);
        if enabled {
            protocols.push(ProtocolChoice {
                protocol: *protocol,
                enabled: true,
                port: protocol.default_port(),
                priority: (i as u8) + 1,
            });
        }
    }

    // Ensure at least one protocol is selected
    if protocols.is_empty() {
        print_warning("No protocols selected. Enabling Xray as default.");
        protocols.push(ProtocolChoice {
            protocol: Protocol::Xray,
            enabled: true,
            port: Protocol::Xray.default_port(),
            priority: 1,
        });
    }

    println!();
    print_success(&format!("{} protocol(s) enabled:", protocols.len()));
    for p in &protocols {
        println!(
            "  - {} (port {}, stealth: {}/10)",
            p.protocol.name(),
            p.port,
            p.protocol.stealth_level()
        );
    }

    // Ask about port customization
    if prompt_yes_no("Customize protocol ports?", false) {
        for p in &mut protocols {
            let new_port = prompt_number(
                &format!("{} port:", p.protocol.name()),
                p.port as u32,
                1,
                65535,
            );
            p.port = new_port as u16;
        }
    }

    Ok(protocols)
}

/// Step 5: Configure AI
fn configure_ai(tier: &HardwareTier) -> Result<AiConfig, WizardError> {
    print_section("AI Configuration");

    if !tier.supports_ai() {
        print_info("Your hardware tier (Minimal) doesn't support AI features.");
        print_info("The system will use rule-based fallback decisions.");
        wait_for_enter("");
        return Ok(AiConfig::disabled());
    }

    print_info("AI-powered decision making provides faster threat response.");
    print_info("Micro-models run locally and don't require internet.");

    let enable_ai = prompt_yes_no("Enable AI decision making?", true);

    if !enable_ai {
        println!();
        print_success("AI disabled. Using rule-based fallback.");
        return Ok(AiConfig::disabled());
    }

    // Select AI level based on tier
    let options = if tier.supports_big_momma() {
        vec![
            ("Micro-Models Only", "3x ~0.5B models for fast reflex decisions (~200MB)"),
            ("Full AI", "Micro-models + optional strategic reasoning (~1GB)"),
        ]
    } else {
        vec![
            ("Micro-Models Only", "3x ~0.5B models for fast reflex decisions (~200MB)"),
        ]
    };

    let selection = prompt_menu("Select AI configuration:", &options, 0);

    let ai_config = match selection {
        0 => AiConfig::micro_models(),
        1 => AiConfig::full(),
        _ => AiConfig::micro_models(),
    };

    // Configure individual models
    println!();
    print_info("Micro-model configuration:");

    let threat_detector = prompt_yes_no("  Enable Threat Detector? (identifies attack patterns)", true);
    let pattern_matcher = prompt_yes_no("  Enable Pattern Matcher? (classifies traffic)", true);
    let action_selector = prompt_yes_no("  Enable Action Selector? (chooses responses)", true);

    let timeout = prompt_number("Decision timeout (ms):", ai_config.timeout_ms, 50, 1000);

    let confidence_str = prompt_text(
        "Confidence threshold (0.0-1.0):",
        Some(&format!("{:.1}", ai_config.confidence_threshold)),
    );
    let confidence: f32 = confidence_str.parse().unwrap_or(ai_config.confidence_threshold);

    let final_config = AiConfig {
        enabled: true,
        threat_detector,
        pattern_matcher,
        action_selector,
        timeout_ms: timeout,
        confidence_threshold: confidence.clamp(0.0, 1.0),
        models_dir: ai_config.models_dir,
    };

    println!();
    print_success("AI configuration complete:");
    println!("  Threat Detector: {}", if final_config.threat_detector { "Enabled" } else { "Disabled" });
    println!("  Pattern Matcher: {}", if final_config.pattern_matcher { "Enabled" } else { "Disabled" });
    println!("  Action Selector: {}", if final_config.action_selector { "Enabled" } else { "Disabled" });
    println!("  Timeout: {}ms", final_config.timeout_ms);
    println!("  Confidence: {:.0}%", final_config.confidence_threshold * 100.0);

    Ok(final_config)
}

/// Step 6: Select security tools
fn select_security_tools(tier: &HardwareTier) -> Result<Vec<SecurityToolChoice>, WizardError> {
    print_section("Security Tools");

    print_info("Select security tools to enable:");
    print_info("These tools help detect and respond to threats.");

    let recommended = SecurityTool::recommended();

    let options: Vec<(&str, &str, bool)> = vec![
        (SecurityTool::PacketCapture.name(), SecurityTool::PacketCapture.description(), false),
        (SecurityTool::DeepCapture.name(), SecurityTool::DeepCapture.description(), false),
        (SecurityTool::FlowCollector.name(), SecurityTool::FlowCollector.description(), false),
        (SecurityTool::Suricata.name(), SecurityTool::Suricata.description(), tier.supports_ai()),
        (SecurityTool::YaraScanner.name(), SecurityTool::YaraScanner.description(), false),
        (SecurityTool::DpiDetector.name(), SecurityTool::DpiDetector.description(), true),
        (SecurityTool::ProbeDetector.name(), SecurityTool::ProbeDetector.description(), true),
        (SecurityTool::RateLimiter.name(), SecurityTool::RateLimiter.description(), true),
        (SecurityTool::IpBlocker.name(), SecurityTool::IpBlocker.description(), false),
        (SecurityTool::GeoBlocker.name(), SecurityTool::GeoBlocker.description(), false),
    ];

    let all_tools = vec![
        SecurityTool::PacketCapture,
        SecurityTool::DeepCapture,
        SecurityTool::FlowCollector,
        SecurityTool::Suricata,
        SecurityTool::YaraScanner,
        SecurityTool::DpiDetector,
        SecurityTool::ProbeDetector,
        SecurityTool::RateLimiter,
        SecurityTool::IpBlocker,
        SecurityTool::GeoBlocker,
    ];

    let selected_indices = prompt_multi_select("Enable security tools:", &options);

    let mut tools: Vec<SecurityToolChoice> = Vec::new();
    for (i, tool) in all_tools.iter().enumerate() {
        let enabled = selected_indices.contains(&i);
        if enabled {
            let auto_activate = recommended.contains(tool);
            tools.push(SecurityToolChoice {
                tool: *tool,
                enabled: true,
                auto_activate,
            });
        }
    }

    println!();
    print_success(&format!("{} security tool(s) enabled", tools.len()));

    Ok(tools)
}

/// Step 7: Configure SDR (if available)
fn configure_sdr(hardware: &HardwareProfile) -> Result<Option<SdrConfig>, WizardError> {
    if hardware.sdr_devices.is_empty() {
        return Ok(None);
    }

    print_section("SDR Radio Bridge Configuration");

    print_info(&format!(
        "Detected {} SDR device(s). Radio bridge enables communication during internet blackouts.",
        hardware.sdr_devices.len()
    ));

    let enable_sdr = prompt_yes_no("Enable SDR radio bridge?", true);

    if !enable_sdr {
        return Ok(None);
    }

    let protocol_options = vec![
        ("LoRa", "Long range, low power (recommended for most cases)"),
        ("AX.25", "Amateur radio packet protocol"),
        ("JS8", "Weak signal keyboard-to-keyboard"),
        ("APRS", "Automatic Packet Reporting System"),
    ];

    let protocol_idx = prompt_menu("Primary radio protocol:", &protocol_options, 0);
    let primary_protocol = match protocol_idx {
        0 => "lora",
        1 => "ax25",
        2 => "js8",
        3 => "aprs",
        _ => "lora",
    }.to_string();

    let callsign = prompt_text("Callsign (if licensed, or 'NOCALL'):", Some("NOCALL"));
    let auto_activate = prompt_yes_no("Auto-activate on internet blackout?", true);
    let mesh_enabled = prompt_yes_no("Enable mesh networking with nearby nodes?", true);

    let config = SdrConfig {
        enabled: true,
        primary_protocol,
        callsign,
        auto_activate_on_blackout: auto_activate,
        mesh_enabled,
    };

    println!();
    print_success("SDR configuration complete");

    Ok(Some(config))
}

/// Step 8: Configure network
fn configure_network() -> Result<NetworkConfig, WizardError> {
    print_section("Network Configuration");

    let mut config = NetworkConfig::default();

    let customize = prompt_yes_no("Customize network settings?", false);

    if customize {
        config.api_port = prompt_number("API port:", config.api_port as u32, 1024, 65535) as u16;

        let bind_options = vec![
            ("127.0.0.1", "Localhost only (most secure)"),
            ("0.0.0.0", "All interfaces (needed for remote access)"),
        ];
        let bind_idx = prompt_menu("API bind address:", &bind_options, 0);
        config.api_bind = match bind_idx {
            0 => "127.0.0.1".to_string(),
            1 => "0.0.0.0".to_string(),
            _ => "127.0.0.1".to_string(),
        };

        config.enable_dashboard = prompt_yes_no("Enable web dashboard?", true);
        config.vpn_interface = prompt_text("VPN interface name:", Some("wg0"));
    }

    println!();
    print_success("Network configuration:");
    println!("  API: {}:{}", config.api_bind, config.api_port);
    println!("  Dashboard: {}", if config.enable_dashboard { "Enabled" } else { "Disabled" });
    println!("  VPN Interface: {}", config.vpn_interface);

    Ok(config)
}

/// Step 9: Configure logging
fn configure_logging() -> Result<LoggingConfig, WizardError> {
    print_section("Logging Configuration");

    let mut config = LoggingConfig::default();

    let customize = prompt_yes_no("Customize logging settings?", false);

    if customize {
        let level_options = vec![
            ("error", "Errors only"),
            ("warn", "Warnings and errors"),
            ("info", "Normal operation (recommended)"),
            ("debug", "Detailed debugging"),
            ("trace", "Very verbose (performance impact)"),
        ];
        let level_idx = prompt_menu("Log level:", &level_options, 2);
        config.level = match level_idx {
            0 => "error",
            1 => "warn",
            2 => "info",
            3 => "debug",
            4 => "trace",
            _ => "info",
        }.to_string();

        config.json_format = prompt_yes_no("Use JSON log format?", false);

        let log_path = prompt_text(
            "Log file path:",
            Some(config.log_file.to_str().unwrap_or("/var/log/cloakwise/cloakwise.log")),
        );
        config.log_file = PathBuf::from(log_path);
    }

    println!();
    print_success("Logging configuration:");
    println!("  Level: {}", config.level);
    println!("  Format: {}", if config.json_format { "JSON" } else { "Plain text" });
    println!("  File: {}", config.log_file.display());

    Ok(config)
}

/// Step 10: Review and save configuration
fn review_and_save(choices: &SetupChoices) -> Result<(), WizardError> {
    print_section("Configuration Review");

    println!("{}Configuration Summary:{}", colors::BOLD, colors::RESET);
    println!();
    println!("  Node: {} ({})", choices.node_id, choices.admin_email);
    println!(
        "  Tier: {}",
        choices.hardware_tier.map(|t| t.name()).unwrap_or("Default")
    );
    println!("  Protocols: {}", choices.protocols.len());
    for p in &choices.protocols {
        println!("    - {} on port {}", p.protocol.name(), p.port);
    }
    println!("  AI: {}", if choices.ai_config.enabled { "Enabled" } else { "Disabled" });
    if choices.ai_config.enabled {
        println!("    Timeout: {}ms", choices.ai_config.timeout_ms);
    }
    println!("  Security Tools: {}", choices.security_tools.len());
    println!(
        "  SDR: {}",
        choices
            .sdr_config
            .as_ref()
            .map(|s| format!("Enabled ({})", s.primary_protocol))
            .unwrap_or_else(|| "Disabled".to_string())
    );
    println!("  API: {}:{}", choices.network_config.api_bind, choices.network_config.api_port);

    println!();

    if !prompt_yes_no("Save this configuration?", true) {
        return Err(WizardError::Cancelled);
    }

    // Generate YAML
    let yaml = build_config_yaml(choices);

    // Determine config path
    let config_dir = PathBuf::from("/etc/cloakwise");
    let config_path = config_dir.join("config.yaml");

    // Try to create directory and write file
    let write_result = (|| -> std::io::Result<()> {
        fs::create_dir_all(&config_dir)?;
        fs::write(&config_path, &yaml)?;
        Ok(())
    })();

    match write_result {
        Ok(()) => {
            print_success(&format!("Configuration saved to {}", config_path.display()));
        }
        Err(e) => {
            print_warning(&format!(
                "Could not write to {} ({})",
                config_path.display(),
                e
            ));
            print_info("Attempting to save to current directory...");

            let local_path = PathBuf::from("./cloakwise-config.yaml");
            fs::write(&local_path, &yaml)?;
            print_success(&format!("Configuration saved to {}", local_path.display()));
            print_info("Move this file to /etc/cloakwise/config.yaml when running as root.");
        }
    }

    // Show config preview
    if prompt_yes_no("Show generated configuration?", false) {
        println!();
        println!("{}--- config.yaml ---{}", colors::DIM, colors::RESET);
        println!("{}", yaml);
        println!("{}--- end ---{}", colors::DIM, colors::RESET);
    }

    println!();
    print_section("Setup Complete!");
    print_success("Cloakwise has been configured successfully.");
    println!();
    print_info("Next steps:");
    println!("  1. Review the configuration file");
    println!("  2. Download/train AI models (if enabled):");
    println!("     cloakwise models download");
    println!("  3. Start the service:");
    println!("     sudo systemctl start cloakwise");
    println!("  4. Check status:");
    println!("     cloakwise status");
    println!();

    Ok(())
}

/// Run wizard and return generated config path
pub fn run() -> Result<PathBuf, WizardError> {
    let choices = run_wizard()?;

    // Return the config path
    let config_path = if PathBuf::from("/etc/cloakwise/config.yaml").exists() {
        PathBuf::from("/etc/cloakwise/config.yaml")
    } else {
        PathBuf::from("./cloakwise-config.yaml")
    };

    Ok(config_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wizard_error_display() {
        let err = WizardError::Cancelled;
        assert_eq!(format!("{}", err), "Setup cancelled by user");
    }
}
