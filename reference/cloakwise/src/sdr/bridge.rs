//! SDR Radio Bridge
//!
//! Bridges IP traffic over radio frequencies when internet is unavailable.
//! Supports multiple radio protocols and can automatically failover between them.

use super::protocols::{RadioProtocol, ProtocolConfig};
use super::hardware::{SdrDevice, DeviceCapability};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tokio::sync::mpsc;

/// Bridge state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeState {
    /// Bridge is dormant (zero resource usage)
    Dormant,
    /// Bridge is initializing hardware
    Initializing,
    /// Bridge is scanning for peers
    Scanning,
    /// Bridge is active and relaying traffic
    Active,
    /// Bridge encountered an error
    Error,
    /// Bridge is shutting down
    ShuttingDown,
}

impl Default for BridgeState {
    fn default() -> Self {
        Self::Dormant
    }
}

/// Radio bridge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioBridgeConfig {
    /// Primary protocol to use
    pub primary_protocol: RadioProtocol,
    /// Fallback protocols in order of preference
    pub fallback_protocols: Vec<RadioProtocol>,
    /// SDR device path
    pub device_path: Option<String>,
    /// Callsign for amateur radio protocols
    pub callsign: Option<String>,
    /// Encryption key for over-the-air encryption
    pub encryption_key: Option<String>,
    /// Maximum transmit power in dBm
    pub max_power_dbm: i32,
    /// Frequency bands allowed (MHz)
    pub allowed_bands: Vec<(f64, f64)>,
    /// Enable automatic frequency selection
    pub auto_frequency: bool,
    /// Beacon interval in seconds
    pub beacon_interval: u32,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Timeout for peer discovery
    pub discovery_timeout: Duration,
    /// Data directory for state and logs
    pub data_dir: PathBuf,
    /// Known peer addresses/callsigns
    pub known_peers: Vec<String>,
    /// Enable mesh networking
    pub mesh_enabled: bool,
    /// Maximum hop count for mesh
    pub max_hops: u8,
}

impl Default for RadioBridgeConfig {
    fn default() -> Self {
        Self {
            primary_protocol: RadioProtocol::LoRa,
            fallback_protocols: vec![
                RadioProtocol::Ax25,
                RadioProtocol::JsEight,
                RadioProtocol::FreeDv,
            ],
            device_path: None,
            callsign: None,
            encryption_key: None,
            max_power_dbm: 20,
            allowed_bands: vec![
                (433.0, 434.8),   // 70cm amateur
                (868.0, 870.0),   // EU ISM
                (902.0, 928.0),   // US ISM
                (144.0, 148.0),   // 2m amateur
            ],
            auto_frequency: true,
            beacon_interval: 60,
            max_retries: 3,
            discovery_timeout: Duration::from_secs(30),
            data_dir: PathBuf::from("/var/lib/cloakwise/radio"),
            known_peers: vec![],
            mesh_enabled: true,
            max_hops: 5,
        }
    }
}

/// Radio peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadioPeer {
    /// Peer identifier (callsign or address)
    pub id: String,
    /// Protocol used to communicate
    pub protocol: RadioProtocol,
    /// Signal strength (RSSI)
    pub rssi: i32,
    /// Signal-to-noise ratio
    pub snr: f32,
    /// Frequency in MHz
    pub frequency: f64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Estimated distance in km
    pub distance_km: Option<f32>,
    /// Hop count (for mesh)
    pub hop_count: u8,
    /// Peer capabilities
    pub capabilities: Vec<String>,
}

/// Radio bridge statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeStats {
    /// Total packets transmitted
    pub packets_tx: u64,
    /// Total packets received
    pub packets_rx: u64,
    /// Total bytes transmitted
    pub bytes_tx: u64,
    /// Total bytes received
    pub bytes_rx: u64,
    /// Transmission errors
    pub tx_errors: u64,
    /// Reception errors
    pub rx_errors: u64,
    /// Average RSSI
    pub avg_rssi: f32,
    /// Average SNR
    pub avg_snr: f32,
    /// Current bitrate in bps
    pub bitrate: u32,
    /// Active protocol
    pub active_protocol: Option<RadioProtocol>,
    /// Active frequency in MHz
    pub active_frequency: Option<f64>,
    /// Number of connected peers
    pub peer_count: usize,
    /// Uptime in seconds
    pub uptime_secs: u64,
}

/// Event from the radio bridge
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    /// State changed
    StateChanged(BridgeState),
    /// New peer discovered
    PeerDiscovered(RadioPeer),
    /// Peer lost connection
    PeerLost(String),
    /// Data received from peer
    DataReceived { peer: String, data: Vec<u8> },
    /// Transmission completed
    TransmitComplete { peer: String, bytes: usize },
    /// Error occurred
    Error(String),
    /// Protocol switched
    ProtocolSwitched(RadioProtocol),
    /// Frequency changed
    FrequencyChanged(f64),
}

/// Radio bridge handle for external control
pub struct RadioBridge {
    /// Configuration
    config: RwLock<RadioBridgeConfig>,
    /// Current state
    state: RwLock<BridgeState>,
    /// Connected peers
    peers: RwLock<HashMap<String, RadioPeer>>,
    /// Statistics
    stats: RwLock<BridgeStats>,
    /// Event sender
    event_tx: Option<mpsc::Sender<BridgeEvent>>,
    /// Start time
    started_at: RwLock<Option<Instant>>,
    /// Active SDR device
    device: RwLock<Option<Arc<dyn SdrDevice>>>,
}

impl RadioBridge {
    /// Create a new dormant radio bridge
    pub fn new(config: RadioBridgeConfig) -> Self {
        Self {
            config: RwLock::new(config),
            state: RwLock::new(BridgeState::Dormant),
            peers: RwLock::new(HashMap::new()),
            stats: RwLock::new(BridgeStats::default()),
            event_tx: None,
            started_at: RwLock::new(None),
            device: RwLock::new(None),
        }
    }

    /// Check if bridge is dormant (zero resource usage)
    pub fn is_dormant(&self) -> bool {
        *self.state.read() == BridgeState::Dormant
    }

    /// Check if bridge is active
    pub fn is_active(&self) -> bool {
        *self.state.read() == BridgeState::Active
    }

    /// Get current state
    pub fn state(&self) -> BridgeState {
        *self.state.read()
    }

    /// Get statistics
    pub fn stats(&self) -> BridgeStats {
        let mut stats = self.stats.read().clone();
        if let Some(started) = *self.started_at.read() {
            stats.uptime_secs = started.elapsed().as_secs();
        }
        stats.peer_count = self.peers.read().len();
        stats
    }

    /// Get connected peers
    pub fn peers(&self) -> Vec<RadioPeer> {
        self.peers.read().values().cloned().collect()
    }

    /// Activate the radio bridge
    pub async fn activate(&self, reason: &str) -> Result<()> {
        let current_state = *self.state.read();
        if current_state != BridgeState::Dormant {
            tracing::warn!("Radio bridge is not dormant, current state: {:?}", current_state);
            return Ok(());
        }

        tracing::info!("Activating radio bridge: {}", reason);
        *self.state.write() = BridgeState::Initializing;

        // Create data directory
        let data_dir = self.config.read().data_dir.clone();
        tokio::fs::create_dir_all(&data_dir).await?;

        // Initialize SDR hardware
        self.initialize_hardware().await?;

        // Start scanning for peers
        *self.state.write() = BridgeState::Scanning;
        self.scan_for_peers().await?;

        // Activate
        *self.state.write() = BridgeState::Active;
        *self.started_at.write() = Some(Instant::now());

        tracing::info!("Radio bridge activated");
        Ok(())
    }

    /// Deactivate the radio bridge
    pub async fn deactivate(&self, reason: &str) -> Result<()> {
        let current_state = *self.state.read();
        if current_state == BridgeState::Dormant {
            return Ok(());
        }

        tracing::info!("Deactivating radio bridge: {}", reason);
        *self.state.write() = BridgeState::ShuttingDown;

        // Stop all radio operations
        self.stop_radio().await?;

        // Clear peers
        self.peers.write().clear();

        // Reset to dormant
        *self.state.write() = BridgeState::Dormant;
        *self.started_at.write() = None;
        *self.device.write() = None;

        tracing::info!("Radio bridge dormant");
        Ok(())
    }

    /// Initialize SDR hardware
    async fn initialize_hardware(&self) -> Result<()> {
        tracing::info!("Initializing SDR hardware");

        // Check for available devices
        let device_path = self.config.read().device_path.clone();

        // Try to detect and initialize SDR
        // In a real implementation, this would probe for RTL-SDR, HackRF, etc.
        if let Some(ref path) = device_path {
            tracing::info!("Using SDR device: {}", path);
        } else {
            tracing::info!("Auto-detecting SDR device");
        }

        Ok(())
    }

    /// Scan for radio peers
    async fn scan_for_peers(&self) -> Result<()> {
        let config = self.config.read();
        let timeout = config.discovery_timeout;
        let protocol = config.primary_protocol;

        tracing::info!("Scanning for peers using {:?} protocol", protocol);

        // In a real implementation, this would:
        // 1. Set SDR to receive mode
        // 2. Listen on known frequencies
        // 3. Send beacon packets
        // 4. Collect peer responses

        // Simulate peer discovery
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(())
    }

    /// Stop radio operations
    async fn stop_radio(&self) -> Result<()> {
        tracing::info!("Stopping radio operations");
        // In a real implementation, this would stop SDR device
        Ok(())
    }

    /// Send data to a specific peer
    pub async fn send_to_peer(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        if !self.is_active() {
            anyhow::bail!("Radio bridge is not active");
        }

        let peer = self.peers.read().get(peer_id).cloned();
        if peer.is_none() {
            anyhow::bail!("Peer not found: {}", peer_id);
        }

        tracing::debug!("Sending {} bytes to peer {}", data.len(), peer_id);

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.packets_tx += 1;
            stats.bytes_tx += data.len() as u64;
        }

        Ok(())
    }

    /// Broadcast data to all peers
    pub async fn broadcast(&self, data: &[u8]) -> Result<()> {
        if !self.is_active() {
            anyhow::bail!("Radio bridge is not active");
        }

        let peer_ids: Vec<String> = self.peers.read().keys().cloned().collect();
        for peer_id in peer_ids {
            self.send_to_peer(&peer_id, data).await?;
        }

        Ok(())
    }

    /// Add a known peer
    pub fn add_known_peer(&self, peer_id: impl Into<String>) {
        self.config.write().known_peers.push(peer_id.into());
    }

    /// Switch to a different protocol
    pub async fn switch_protocol(&self, protocol: RadioProtocol) -> Result<()> {
        if !self.is_active() {
            anyhow::bail!("Radio bridge is not active");
        }

        tracing::info!("Switching to {:?} protocol", protocol);

        {
            let mut stats = self.stats.write();
            stats.active_protocol = Some(protocol);
        }

        Ok(())
    }

    /// Set transmit frequency
    pub async fn set_frequency(&self, freq_mhz: f64) -> Result<()> {
        let config = self.config.read();

        // Check if frequency is in allowed bands
        let allowed = config.allowed_bands.iter()
            .any(|(low, high)| freq_mhz >= *low && freq_mhz <= *high);

        if !allowed {
            anyhow::bail!("Frequency {} MHz is not in allowed bands", freq_mhz);
        }

        tracing::info!("Setting frequency to {} MHz", freq_mhz);

        {
            let mut stats = self.stats.write();
            stats.active_frequency = Some(freq_mhz);
        }

        Ok(())
    }
}

/// Create a dormant tool entry for the radio bridge
pub fn create_radio_bridge_tool() -> crate::security::toolkit::DormantTool {
    use crate::security::toolkit::{DormantTool, ResourceBudget, ToolCategory, AutoTriggerConfig};

    DormantTool {
        id: "radio_bridge".to_string(),
        name: "SDR Radio Bridge".to_string(),
        category: ToolCategory::RadioBridge,
        description: "Software Defined Radio bridge for communication when internet is unavailable. Supports LoRa, AX.25, and mesh networking.".to_string(),
        binary: PathBuf::from("/usr/local/bin/cloakwise-radio"),
        args_template: vec![
            "--config".to_string(),
            "/etc/cloakwise/radio.yaml".to_string(),
        ],
        env_vars: HashMap::new(),
        work_dir: Some(PathBuf::from("/var/lib/cloakwise/radio")),
        budget: ResourceBudget {
            max_memory_mb: 256,
            max_cpu_percent: 30,
            max_disk_mb: 512,
            max_bandwidth_kbps: Some(100), // Radio is slow
            max_runtime: None, // Run as long as needed
        },
        dependencies: vec![],
        idle_timeout: None, // Don't timeout - critical infrastructure
        auto_triggers: vec![
            AutoTriggerConfig {
                trigger_type: "radio_fallback".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("internet_status".to_string(), serde_json::json!("down"));
                    m.insert("duration_minutes".to_string(), serde_json::json!(5));
                    m
                },
                enabled: true,
            },
            AutoTriggerConfig {
                trigger_type: "big_momma_decision".to_string(),
                conditions: {
                    let mut m = HashMap::new();
                    m.insert("action".to_string(), serde_json::json!("radio_fallback"));
                    m
                },
                enabled: true,
            },
        ],
        state: crate::security::toolkit::ToolState::Dormant,
        pid: None,
        activated_at: None,
        last_activity: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bridge_lifecycle() {
        let config = RadioBridgeConfig::default();
        let bridge = RadioBridge::new(config);

        assert!(bridge.is_dormant());
        assert!(!bridge.is_active());
        assert_eq!(bridge.stats().peer_count, 0);
    }
}
