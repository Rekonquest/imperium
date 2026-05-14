//! Enforcers module
//!
//! Enforces decisions by executing actions on VPN infrastructure.

pub mod profile_switcher;
pub mod connection_throttler;
pub mod decoy_activator;
pub mod client_notifier;

pub use profile_switcher::ProfileSwitcher;
pub use connection_throttler::ConnectionThrottler;
pub use decoy_activator::DecoyActivator;
pub use client_notifier::ClientNotifier;

use crate::specialists::Action;
use anyhow::Result;
use async_trait::async_trait;

/// Result of enforcing an action
#[derive(Debug, Clone)]
pub struct EnforcementResult {
    /// Whether the action was executed successfully
    pub success: bool,
    /// Description of what was done
    pub description: String,
    /// Time taken to execute
    pub duration_ms: u64,
    /// Any side effects or follow-up actions needed
    pub follow_up: Option<Action>,
}

impl EnforcementResult {
    pub fn success(description: impl Into<String>) -> Self {
        Self {
            success: true,
            description: description.into(),
            duration_ms: 0,
            follow_up: None,
        }
    }

    pub fn failure(description: impl Into<String>) -> Self {
        Self {
            success: false,
            description: description.into(),
            duration_ms: 0,
            follow_up: None,
        }
    }

    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = ms;
        self
    }

    pub fn with_follow_up(mut self, action: Action) -> Self {
        self.follow_up = Some(action);
        self
    }
}

/// Trait for action enforcers
#[async_trait]
pub trait Enforcer: Send + Sync {
    /// Check if this enforcer can handle the given action
    fn can_handle(&self, action: &Action) -> bool;

    /// Execute the action
    async fn enforce(&self, action: &Action) -> Result<EnforcementResult>;

    /// Rollback a previous action (if possible)
    async fn rollback(&self, action: &Action) -> Result<EnforcementResult>;
}

/// Coordinator for all enforcers
pub struct EnforcerCoordinator {
    enforcers: Vec<Box<dyn Enforcer>>,
}

impl EnforcerCoordinator {
    pub fn new() -> Self {
        Self {
            enforcers: Vec::new(),
        }
    }

    /// Register an enforcer
    pub fn register(&mut self, enforcer: Box<dyn Enforcer>) {
        self.enforcers.push(enforcer);
    }

    /// Execute an action using the appropriate enforcer
    pub async fn execute(&self, action: &Action) -> Result<EnforcementResult> {
        let start = std::time::Instant::now();

        for enforcer in &self.enforcers {
            if enforcer.can_handle(action) {
                let mut result = enforcer.enforce(action).await?;
                result.duration_ms = start.elapsed().as_millis() as u64;
                return Ok(result);
            }
        }

        Ok(EnforcementResult::failure(format!(
            "No enforcer found for action: {:?}",
            action
        )))
    }

    /// Execute multiple actions in sequence
    pub async fn execute_sequence(&self, actions: &[Action]) -> Vec<Result<EnforcementResult>> {
        let mut results = Vec::new();

        for action in actions {
            results.push(self.execute(action).await);
        }

        results
    }
}

impl Default for EnforcerCoordinator {
    fn default() -> Self {
        Self::new()
    }
}
