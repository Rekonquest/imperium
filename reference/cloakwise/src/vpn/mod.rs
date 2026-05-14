//! VPN control module
//!
//! Provides abstractions for controlling various VPN protocols.

pub mod profiles;
pub mod wireguard;
pub mod amneziawg;
pub mod cloak;
pub mod shadowsocks;
pub mod v2ray;
pub mod trojango;
pub mod hysteria2;
pub mod naiveproxy;
pub mod snowflake;
pub mod iodine;
pub mod briar;

pub use profiles::*;
pub use wireguard::WireGuardController;
pub use amneziawg::AmneziaWgController;
pub use cloak::CloakController;
pub use shadowsocks::ShadowsocksController;
pub use v2ray::V2RayController;
pub use trojango::TrojanGoController;
pub use hysteria2::Hysteria2Controller;
pub use naiveproxy::NaiveProxyController;
pub use snowflake::SnowflakeController;
pub use iodine::IodineController;
pub use briar::BriarController;

use crate::config::Protocol;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

/// Trait for VPN protocol controllers
#[async_trait]
pub trait VpnController: Send + Sync {
    /// Get the protocol type
    fn protocol(&self) -> Protocol;

    /// Check if the VPN is currently running
    async fn is_running(&self) -> Result<bool>;

    /// Start the VPN service
    async fn start(&self) -> Result<()>;

    /// Stop the VPN service
    async fn stop(&self) -> Result<()>;

    /// Reload configuration without dropping connections
    async fn reload(&self) -> Result<()>;

    /// Apply a traffic profile to this controller
    async fn apply_profile(&self, profile: &TrafficProfile) -> Result<()>;

    /// Get current connection count
    async fn connection_count(&self) -> Result<u32>;

    /// Get service status information
    async fn status(&self) -> Result<VpnStatus>;
}

/// VPN service status
#[derive(Debug, Clone)]
pub struct VpnStatus {
    pub running: bool,
    pub uptime_secs: Option<u64>,
    pub connections: u32,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_handshake: Option<u64>,
    pub current_profile: Option<ProfileId>,
}

impl Default for VpnStatus {
    fn default() -> Self {
        Self {
            running: false,
            uptime_secs: None,
            connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            last_handshake: None,
            current_profile: None,
        }
    }
}

/// Factory for creating VPN controllers
pub struct VpnControllerFactory;

impl VpnControllerFactory {
    /// Create a controller for the specified protocol
    pub fn create(
        protocol: Protocol,
        interface: &str,
        config_dir: &std::path::Path,
    ) -> Arc<dyn VpnController> {
        match protocol {
            Protocol::Wireguard => Arc::new(WireGuardController::new(interface, config_dir)),
            Protocol::Amneziawg => Arc::new(AmneziaWgController::new(interface, config_dir)),
            Protocol::Cloak => Arc::new(CloakController::new(config_dir)),
            Protocol::Shadowsocks | Protocol::Outline => {
                Arc::new(ShadowsocksController::new(config_dir))
            }
            Protocol::V2ray => Arc::new(V2RayController::v2ray(config_dir)),
            Protocol::Xray => Arc::new(V2RayController::xray(config_dir)),
            Protocol::TrojanGo => Arc::new(TrojanGoController::new(config_dir)),
            Protocol::Hysteria2 => Arc::new(Hysteria2Controller::new(config_dir)),
            Protocol::NaiveProxy => Arc::new(NaiveProxyController::new(config_dir)),
            Protocol::Snowflake => Arc::new(SnowflakeController::new(config_dir)),
            Protocol::Iodine => Arc::new(IodineController::new(config_dir)),
            Protocol::Briar => Arc::new(BriarController::new(config_dir)),
        }
    }
}

/// Manager for multiple VPN controllers
pub struct VpnManager {
    controllers: std::collections::HashMap<Protocol, Arc<dyn VpnController>>,
    active_protocol: parking_lot::RwLock<Option<Protocol>>,
    active_profile: parking_lot::RwLock<Option<TrafficProfile>>,
}

impl VpnManager {
    pub fn new() -> Self {
        Self {
            controllers: std::collections::HashMap::new(),
            active_protocol: parking_lot::RwLock::new(None),
            active_profile: parking_lot::RwLock::new(None),
        }
    }

    /// Register a controller for a protocol
    pub fn register(&mut self, controller: Arc<dyn VpnController>) {
        let protocol = controller.protocol();
        self.controllers.insert(protocol, controller);
    }

    /// Get the controller for a protocol
    pub fn get(&self, protocol: Protocol) -> Option<&Arc<dyn VpnController>> {
        self.controllers.get(&protocol)
    }

    /// Get the currently active controller
    pub fn active_controller(&self) -> Option<Arc<dyn VpnController>> {
        let protocol = self.active_protocol.read();
        protocol.and_then(|p| self.controllers.get(&p).cloned())
    }

    /// Switch to a new profile
    pub async fn switch_profile(&self, profile: &TrafficProfile) -> Result<()> {
        tracing::info!("Switching to profile: {} ({:?})", profile.name, profile.protocol);

        // Stop current protocol if different
        let current_protocol = *self.active_protocol.read();
        if let Some(current) = current_protocol {
            if current != profile.protocol {
                if let Some(controller) = self.controllers.get(&current) {
                    tracing::debug!("Stopping current protocol: {:?}", current);
                    controller.stop().await?;
                }
            }
        }

        // Get new controller
        let controller = self
            .controllers
            .get(&profile.protocol)
            .ok_or_else(|| anyhow::anyhow!("No controller for protocol: {:?}", profile.protocol))?;

        // Apply profile and start if needed
        controller.apply_profile(profile).await?;

        if !controller.is_running().await? {
            controller.start().await?;
        } else {
            controller.reload().await?;
        }

        // Update active state
        *self.active_protocol.write() = Some(profile.protocol);
        *self.active_profile.write() = Some(profile.clone());

        tracing::info!("Successfully switched to profile: {}", profile.name);
        Ok(())
    }

    /// Get current active profile
    pub fn active_profile(&self) -> Option<TrafficProfile> {
        self.active_profile.read().clone()
    }

    /// Get status of all controllers
    pub async fn all_status(&self) -> std::collections::HashMap<Protocol, VpnStatus> {
        let mut statuses = std::collections::HashMap::new();
        for (protocol, controller) in &self.controllers {
            if let Ok(status) = controller.status().await {
                statuses.insert(*protocol, status);
            }
        }
        statuses
    }
}

impl Default for VpnManager {
    fn default() -> Self {
        Self::new()
    }
}
