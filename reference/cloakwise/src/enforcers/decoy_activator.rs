//! Decoy Activator Enforcer
//!
//! Activates decoy services to confuse probing attempts.

use super::{EnforcementResult, Enforcer};
use crate::specialists::Action;
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Decoy service types
#[derive(Debug, Clone)]
pub enum DecoyType {
    /// Fake HTTPS server
    HttpsServer,
    /// Fake DNS responder
    DnsResponder,
    /// Fake WebSocket endpoint
    WebSocket,
    /// Custom decoy
    Custom(String),
}

/// Decoy status
#[derive(Debug, Clone)]
pub struct DecoyStatus {
    pub decoy_type: DecoyType,
    pub active: bool,
    pub port: u16,
    pub start_time: Option<u64>,
}

/// Decoy activator enforcer
pub struct DecoyActivator {
    decoys: RwLock<Vec<DecoyStatus>>,
    /// Whether decoy mode is globally active
    active: RwLock<bool>,
}

impl DecoyActivator {
    pub fn new() -> Self {
        Self {
            decoys: RwLock::new(Vec::new()),
            active: RwLock::new(false),
        }
    }

    /// Register a decoy service
    pub fn register_decoy(&self, decoy_type: DecoyType, port: u16) {
        let mut decoys = self.decoys.write();
        decoys.push(DecoyStatus {
            decoy_type,
            active: false,
            port,
            start_time: None,
        });
    }

    /// Activate all decoys
    fn activate_all(&self) -> EnforcementResult {
        let timestamp = crate::telemetry::current_timestamp();

        {
            let mut decoys = self.decoys.write();
            for decoy in decoys.iter_mut() {
                if !decoy.active {
                    decoy.active = true;
                    decoy.start_time = Some(timestamp);
                    info!("Activated decoy: {:?} on port {}", decoy.decoy_type, decoy.port);

                    // In production, this would actually start the decoy service
                    // For now, we just mark it as active
                }
            }
        }

        *self.active.write() = true;

        let count = self.decoys.read().iter().filter(|d| d.active).count();

        EnforcementResult::success(format!("Activated {} decoy services", count))
    }

    /// Deactivate all decoys
    fn deactivate_all(&self) -> EnforcementResult {
        {
            let mut decoys = self.decoys.write();
            for decoy in decoys.iter_mut() {
                if decoy.active {
                    decoy.active = false;
                    decoy.start_time = None;
                    info!("Deactivated decoy: {:?} on port {}", decoy.decoy_type, decoy.port);
                }
            }
        }

        *self.active.write() = false;

        EnforcementResult::success("All decoy services deactivated")
    }

    /// Check if decoys are active
    pub fn is_active(&self) -> bool {
        *self.active.read()
    }

    /// Get active decoy count
    pub fn active_count(&self) -> usize {
        self.decoys.read().iter().filter(|d| d.active).count()
    }

    /// Get status of all decoys
    pub fn status(&self) -> Vec<DecoyStatus> {
        self.decoys.read().clone()
    }
}

impl Default for DecoyActivator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Enforcer for DecoyActivator {
    fn can_handle(&self, action: &Action) -> bool {
        matches!(action, Action::ActivateDecoy)
    }

    async fn enforce(&self, action: &Action) -> Result<EnforcementResult> {
        match action {
            Action::ActivateDecoy => Ok(self.activate_all()),
            _ => Ok(EnforcementResult::failure(
                "Action not supported by DecoyActivator",
            )),
        }
    }

    async fn rollback(&self, _action: &Action) -> Result<EnforcementResult> {
        Ok(self.deactivate_all())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_activate_decoys() {
        let activator = DecoyActivator::new();

        // Register some decoys
        activator.register_decoy(DecoyType::HttpsServer, 443);
        activator.register_decoy(DecoyType::DnsResponder, 53);

        // Activate
        let result = activator.enforce(&Action::ActivateDecoy).await.unwrap();
        assert!(result.success);
        assert!(activator.is_active());
        assert_eq!(activator.active_count(), 2);
    }

    #[tokio::test]
    async fn test_rollback_decoys() {
        let activator = DecoyActivator::new();
        activator.register_decoy(DecoyType::WebSocket, 8080);

        // Activate then rollback
        activator.enforce(&Action::ActivateDecoy).await.unwrap();
        assert!(activator.is_active());

        activator.rollback(&Action::None).await.unwrap();
        assert!(!activator.is_active());
        assert_eq!(activator.active_count(), 0);
    }
}
