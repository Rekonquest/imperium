//! Fallback algorithms for profile rotation
//!
//! These algorithms provide deterministic behavior when AI specialists
//! are unavailable or uncertain.

use crate::config::FallbackConfig;
use crate::telemetry::{HealthCheckEvent, TelemetryEvent};
use crate::vpn::ProfileId;
use anyhow::Result;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Result from a fallback decision
#[derive(Debug, Clone)]
pub enum FallbackDecision {
    /// Continue with current profile
    NoAction,
    /// Rotate to the next profile in sequence
    RotateProfile { target: ProfileId, reason: String },
    /// Enter safe mode
    EnterSafeMode { reason: String },
    /// Alert administrator
    AlertAdmin { message: String },
}

/// Fallback controller that manages deterministic rotation
pub struct FallbackController {
    config: FallbackConfig,
    /// Current profile index in rotation order
    current_profile_index: usize,
    /// Last rotation time
    last_rotation: Instant,
    /// Recent failure count
    failure_window: VecDeque<Instant>,
    /// Recent health check results
    health_history: VecDeque<HealthCheckEvent>,
    /// Whether we're in safe mode
    in_safe_mode: bool,
    /// Time when safe mode was entered
    safe_mode_entered: Option<Instant>,
    /// Consecutive health check failures
    consecutive_health_failures: u32,
}

impl FallbackController {
    pub fn new(config: FallbackConfig) -> Self {
        Self {
            config,
            current_profile_index: 0,
            last_rotation: Instant::now(),
            failure_window: VecDeque::new(),
            health_history: VecDeque::with_capacity(100),
            in_safe_mode: false,
            safe_mode_entered: None,
            consecutive_health_failures: 0,
        }
    }

    /// Process a telemetry event and return any fallback decision
    pub fn process_event(&mut self, event: &TelemetryEvent) -> FallbackDecision {
        match event {
            TelemetryEvent::Connection(conn) if !conn.success => {
                self.record_failure();
                self.check_failure_threshold()
            }
            TelemetryEvent::HealthCheck(health) => {
                self.record_health_check(health.clone());
                self.check_health_status()
            }
            TelemetryEvent::InfraError(err) if !err.recoverable => {
                warn!("Non-recoverable infrastructure error: {}", err.message);
                self.enter_safe_mode("Non-recoverable infrastructure error")
            }
            _ => FallbackDecision::NoAction,
        }
    }

    /// Check if timed rotation is due
    pub fn check_timed_rotation(&mut self) -> FallbackDecision {
        if self.in_safe_mode {
            // Check if we should exit safe mode
            if let Some(entered) = self.safe_mode_entered {
                let lock_duration = Duration::from_secs(self.config.safe_mode_lock_minutes as u64 * 60);
                if entered.elapsed() >= lock_duration {
                    info!("Safe mode lock period expired, resuming normal operation");
                    self.in_safe_mode = false;
                    self.safe_mode_entered = None;
                    return self.rotate_to_next("Safe mode period ended");
                }
            }
            return FallbackDecision::NoAction;
        }

        let rotation_interval = Duration::from_secs(self.config.timed_rotation_hours as u64 * 3600);

        if self.last_rotation.elapsed() >= rotation_interval {
            self.rotate_to_next("Scheduled rotation")
        } else {
            FallbackDecision::NoAction
        }
    }

    /// Record a connection failure
    fn record_failure(&mut self) {
        self.failure_window.push_back(Instant::now());
        self.cleanup_failure_window();
    }

    /// Remove old failures outside the window
    fn cleanup_failure_window(&mut self) {
        let window_duration = Duration::from_secs(self.config.failure_window_minutes as u64 * 60);
        let cutoff = Instant::now() - window_duration;

        while let Some(front) = self.failure_window.front() {
            if *front < cutoff {
                self.failure_window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Check if failure threshold has been reached
    fn check_failure_threshold(&mut self) -> FallbackDecision {
        self.cleanup_failure_window();

        let failure_count = self.failure_window.len() as u32;

        if failure_count >= self.config.failure_threshold {
            info!(
                "Failure threshold reached: {} failures in {} minutes",
                failure_count, self.config.failure_window_minutes
            );

            // Clear the window to reset counting
            self.failure_window.clear();

            // If we've rotated through all profiles, enter safe mode
            if self.current_profile_index >= self.config.profile_rotation_order.len() - 1 {
                return self.enter_safe_mode("All profiles exhausted after failure threshold");
            }

            self.rotate_to_next("Failure threshold exceeded")
        } else {
            FallbackDecision::NoAction
        }
    }

    /// Record a health check result
    fn record_health_check(&mut self, event: HealthCheckEvent) {
        self.health_history.push_back(event.clone());

        // Keep only last 100 health checks
        while self.health_history.len() > 100 {
            self.health_history.pop_front();
        }

        // Track consecutive failures
        if event.reachable {
            self.consecutive_health_failures = 0;
        } else {
            self.consecutive_health_failures += 1;
        }
    }

    /// Check health status and decide on action
    fn check_health_status(&mut self) -> FallbackDecision {
        // If all health checks are failing, we might be blocked
        let consecutive_threshold = 5;

        if self.consecutive_health_failures >= consecutive_threshold {
            warn!(
                "Consecutive health check failures: {}",
                self.consecutive_health_failures
            );

            // Check if we're being blocked
            let recent_health: Vec<_> = self
                .health_history
                .iter()
                .rev()
                .take(10)
                .collect();

            let all_failing = recent_health.iter().all(|h| !h.reachable);

            if all_failing {
                // Reset counter
                self.consecutive_health_failures = 0;

                if self.in_safe_mode {
                    return FallbackDecision::AlertAdmin {
                        message: "All health checks failing even in safe mode".to_string(),
                    };
                }

                return self.rotate_to_next("All health checks failing - possible block");
            }
        }

        FallbackDecision::NoAction
    }

    /// Rotate to the next profile in sequence
    fn rotate_to_next(&mut self, reason: &str) -> FallbackDecision {
        self.current_profile_index =
            (self.current_profile_index + 1) % self.config.profile_rotation_order.len();

        let target = self.config.profile_rotation_order[self.current_profile_index].clone();

        self.last_rotation = Instant::now();

        info!("Rotating to profile: {} (reason: {})", target, reason);

        FallbackDecision::RotateProfile {
            target,
            reason: reason.to_string(),
        }
    }

    /// Enter safe mode
    fn enter_safe_mode(&mut self, reason: &str) -> FallbackDecision {
        if self.in_safe_mode {
            return FallbackDecision::NoAction;
        }

        warn!("Entering safe mode: {}", reason);
        self.in_safe_mode = true;
        self.safe_mode_entered = Some(Instant::now());

        FallbackDecision::EnterSafeMode {
            reason: reason.to_string(),
        }
    }

    /// Get current profile
    pub fn current_profile(&self) -> &ProfileId {
        if self.in_safe_mode {
            &self.config.safe_mode_profile
        } else {
            &self.config.profile_rotation_order[self.current_profile_index]
        }
    }

    /// Check if in safe mode
    pub fn is_safe_mode(&self) -> bool {
        self.in_safe_mode
    }

    /// Force a rotation (for testing or manual intervention)
    pub fn force_rotation(&mut self) -> FallbackDecision {
        self.rotate_to_next("Manual rotation")
    }

    /// Force safe mode exit
    pub fn exit_safe_mode(&mut self) {
        if self.in_safe_mode {
            info!("Exiting safe mode (manual)");
            self.in_safe_mode = false;
            self.safe_mode_entered = None;
        }
    }

    /// Get statistics
    pub fn stats(&self) -> FallbackStats {
        FallbackStats {
            current_profile: self.current_profile().clone(),
            current_profile_index: self.current_profile_index,
            failures_in_window: self.failure_window.len(),
            time_until_rotation: self.time_until_rotation(),
            in_safe_mode: self.in_safe_mode,
            consecutive_health_failures: self.consecutive_health_failures,
        }
    }

    /// Time until next scheduled rotation
    fn time_until_rotation(&self) -> Duration {
        let rotation_interval = Duration::from_secs(self.config.timed_rotation_hours as u64 * 3600);
        let elapsed = self.last_rotation.elapsed();

        if elapsed >= rotation_interval {
            Duration::ZERO
        } else {
            rotation_interval - elapsed
        }
    }
}

/// Statistics about fallback state
#[derive(Debug, Clone)]
pub struct FallbackStats {
    pub current_profile: ProfileId,
    pub current_profile_index: usize,
    pub failures_in_window: usize,
    pub time_until_rotation: Duration,
    pub in_safe_mode: bool,
    pub consecutive_health_failures: u32,
}

/// Timed rotation ticker
pub struct RotationTicker {
    interval: tokio::time::Interval,
}

impl RotationTicker {
    pub fn new(interval_hours: u32) -> Self {
        let duration = Duration::from_secs(interval_hours as u64 * 3600);
        Self {
            interval: tokio::time::interval(duration),
        }
    }

    /// Wait for the next tick
    pub async fn tick(&mut self) {
        self.interval.tick().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> FallbackConfig {
        FallbackConfig {
            timed_rotation_hours: 1,
            failure_threshold: 5,
            failure_window_minutes: 10,
            health_check_interval_secs: 60,
            health_check_endpoints: vec!["https://test.com".to_string()],
            profile_rotation_order: vec![
                "profile1".to_string(),
                "profile2".to_string(),
                "profile3".to_string(),
            ],
            safe_mode_profile: "safe".to_string(),
            safe_mode_lock_minutes: 30,
        }
    }

    #[test]
    fn test_failure_threshold() {
        let mut controller = FallbackController::new(test_config());

        // Record failures
        for _ in 0..4 {
            controller.record_failure();
            let decision = controller.check_failure_threshold();
            assert!(matches!(decision, FallbackDecision::NoAction));
        }

        // 5th failure should trigger rotation
        controller.record_failure();
        let decision = controller.check_failure_threshold();
        assert!(matches!(decision, FallbackDecision::RotateProfile { .. }));
    }

    #[test]
    fn test_profile_rotation() {
        let mut controller = FallbackController::new(test_config());

        assert_eq!(controller.current_profile(), "profile1");

        controller.force_rotation();
        assert_eq!(controller.current_profile(), "profile2");

        controller.force_rotation();
        assert_eq!(controller.current_profile(), "profile3");

        // Should wrap around
        controller.force_rotation();
        assert_eq!(controller.current_profile(), "profile1");
    }

    #[test]
    fn test_safe_mode() {
        let mut controller = FallbackController::new(test_config());

        let decision = controller.enter_safe_mode("test");
        assert!(matches!(decision, FallbackDecision::EnterSafeMode { .. }));
        assert!(controller.is_safe_mode());
        assert_eq!(controller.current_profile(), "safe");

        controller.exit_safe_mode();
        assert!(!controller.is_safe_mode());
    }

    #[test]
    fn test_health_check_tracking() {
        let mut controller = FallbackController::new(test_config());

        // Successful health checks
        for _ in 0..3 {
            let event = HealthCheckEvent::new("https://test.com", true);
            controller.record_health_check(event);
        }

        assert_eq!(controller.consecutive_health_failures, 0);

        // Failed health checks
        for _ in 0..3 {
            let event = HealthCheckEvent::new("https://test.com", false);
            controller.record_health_check(event);
        }

        assert_eq!(controller.consecutive_health_failures, 3);

        // Successful check resets counter
        let event = HealthCheckEvent::new("https://test.com", true);
        controller.record_health_check(event);
        assert_eq!(controller.consecutive_health_failures, 0);
    }
}
