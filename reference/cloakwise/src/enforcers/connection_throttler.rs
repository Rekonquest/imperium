//! Connection Throttler Enforcer
//!
//! Handles connection rate limiting and jitter injection.

use super::{EnforcementResult, Enforcer};
use crate::specialists::Action;
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::{debug, info};

/// Throttle configuration
#[derive(Debug, Clone)]
pub struct ThrottleConfig {
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Minimum jitter (ms)
    pub jitter_min_ms: u32,
    /// Maximum jitter (ms)
    pub jitter_max_ms: u32,
    /// Whether throttling is active
    pub active: bool,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            max_connections: u32::MAX,
            jitter_min_ms: 0,
            jitter_max_ms: 0,
            active: false,
        }
    }
}

/// Connection throttler enforcer
pub struct ConnectionThrottler {
    config: RwLock<ThrottleConfig>,
    /// Callback for applying throttle (in production, this would control iptables/tc)
    on_throttle_change: Option<Box<dyn Fn(&ThrottleConfig) + Send + Sync>>,
}

impl ConnectionThrottler {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(ThrottleConfig::default()),
            on_throttle_change: None,
        }
    }

    /// Set a callback for when throttle config changes
    pub fn set_change_callback<F>(&mut self, callback: F)
    where
        F: Fn(&ThrottleConfig) + Send + Sync + 'static,
    {
        self.on_throttle_change = Some(Box::new(callback));
    }

    /// Apply throttle settings
    fn apply_config(&self) {
        let config = self.config.read();
        if let Some(ref callback) = self.on_throttle_change {
            callback(&config);
        }
    }

    /// Get current throttle configuration
    pub fn current_config(&self) -> ThrottleConfig {
        self.config.read().clone()
    }

    /// Check if throttling is active
    pub fn is_active(&self) -> bool {
        self.config.read().active
    }

    /// Set maximum connections
    fn set_max_connections(&self, max: u32) -> EnforcementResult {
        {
            let mut config = self.config.write();
            config.max_connections = max;
            config.active = true;
        }

        self.apply_config();

        info!("Connection throttle set: max {} connections", max);

        EnforcementResult::success(format!("Throttled connections to max {}", max))
    }

    /// Set jitter parameters
    fn set_jitter(&self, min_ms: u32, max_ms: u32) -> EnforcementResult {
        {
            let mut config = self.config.write();
            config.jitter_min_ms = min_ms;
            config.jitter_max_ms = max_ms;
            config.active = true;
        }

        self.apply_config();

        info!("Jitter injection set: {}ms - {}ms", min_ms, max_ms);

        EnforcementResult::success(format!("Jitter set to {}ms - {}ms", min_ms, max_ms))
    }

    /// Clear all throttling
    fn clear_throttle(&self) -> EnforcementResult {
        *self.config.write() = ThrottleConfig::default();

        self.apply_config();

        info!("Throttling cleared");

        EnforcementResult::success("Throttling cleared")
    }

    /// Generate random jitter within configured range
    pub fn get_jitter(&self) -> u32 {
        let config = self.config.read();
        if config.jitter_max_ms == 0 {
            return 0;
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen_range(config.jitter_min_ms..=config.jitter_max_ms)
    }

    /// Check if a new connection should be allowed
    pub fn should_allow_connection(&self, current_count: u32) -> bool {
        let config = self.config.read();
        !config.active || current_count < config.max_connections
    }
}

impl Default for ConnectionThrottler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Enforcer for ConnectionThrottler {
    fn can_handle(&self, action: &Action) -> bool {
        matches!(
            action,
            Action::ThrottleConnections { .. } | Action::AddJitter { .. }
        )
    }

    async fn enforce(&self, action: &Action) -> Result<EnforcementResult> {
        match action {
            Action::ThrottleConnections { max } => Ok(self.set_max_connections(*max)),
            Action::AddJitter { min_ms, max_ms } => Ok(self.set_jitter(*min_ms, *max_ms)),
            _ => Ok(EnforcementResult::failure(
                "Action not supported by ConnectionThrottler",
            )),
        }
    }

    async fn rollback(&self, _action: &Action) -> Result<EnforcementResult> {
        Ok(self.clear_throttle())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_throttle_connections() {
        let throttler = ConnectionThrottler::new();

        let result = throttler
            .enforce(&Action::ThrottleConnections { max: 50 })
            .await
            .unwrap();

        assert!(result.success);
        assert!(throttler.is_active());
        assert_eq!(throttler.current_config().max_connections, 50);
    }

    #[tokio::test]
    async fn test_add_jitter() {
        let throttler = ConnectionThrottler::new();

        let result = throttler
            .enforce(&Action::AddJitter {
                min_ms: 10,
                max_ms: 100,
            })
            .await
            .unwrap();

        assert!(result.success);
        assert!(throttler.is_active());

        let config = throttler.current_config();
        assert_eq!(config.jitter_min_ms, 10);
        assert_eq!(config.jitter_max_ms, 100);
    }

    #[tokio::test]
    async fn test_rollback() {
        let throttler = ConnectionThrottler::new();

        // Set some throttling
        throttler
            .enforce(&Action::ThrottleConnections { max: 50 })
            .await
            .unwrap();

        // Rollback
        let result = throttler.rollback(&Action::None).await.unwrap();
        assert!(result.success);
        assert!(!throttler.is_active());
    }

    #[test]
    fn test_connection_allowance() {
        let throttler = ConnectionThrottler::new();

        // No throttling - always allow
        assert!(throttler.should_allow_connection(1000));

        // Set throttle
        throttler.set_max_connections(50);
        assert!(throttler.should_allow_connection(49));
        assert!(!throttler.should_allow_connection(50));
    }

    #[test]
    fn test_jitter_generation() {
        let throttler = ConnectionThrottler::new();
        throttler.set_jitter(10, 100);

        for _ in 0..100 {
            let jitter = throttler.get_jitter();
            assert!(jitter >= 10);
            assert!(jitter <= 100);
        }
    }
}
