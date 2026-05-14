//! Health Monitor Specialist
//!
//! Monitors service health and detects connectivity issues.

use super::{Action, Assessment, Specialist, SpecialistType, SpecialistVote, ThreatType};
use crate::telemetry::{HealthCheckEvent, InfraErrorEvent, TelemetryEvent};
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{debug, warn};

/// Health status per endpoint
#[derive(Debug, Clone)]
struct EndpointHealth {
    /// Total checks
    total_checks: u32,
    /// Successful checks
    successful_checks: u32,
    /// Average latency (ms)
    avg_latency: f32,
    /// Last check success
    last_success: bool,
    /// Consecutive failures
    consecutive_failures: u32,
}

impl Default for EndpointHealth {
    fn default() -> Self {
        Self {
            total_checks: 0,
            successful_checks: 0,
            avg_latency: 0.0,
            last_success: true,
            consecutive_failures: 0,
        }
    }
}

impl EndpointHealth {
    fn success_rate(&self) -> f32 {
        if self.total_checks == 0 {
            return 1.0;
        }
        self.successful_checks as f32 / self.total_checks as f32
    }

    fn update(&mut self, success: bool, latency: Option<u32>) {
        self.total_checks += 1;
        if success {
            self.successful_checks += 1;
            self.consecutive_failures = 0;
            self.last_success = true;
            if let Some(lat) = latency {
                // Running average
                self.avg_latency = (self.avg_latency * (self.successful_checks - 1) as f32
                    + lat as f32)
                    / self.successful_checks as f32;
            }
        } else {
            self.consecutive_failures += 1;
            self.last_success = false;
        }
    }
}

/// Health monitor specialist
pub struct HealthMonitor {
    /// Health status per endpoint
    endpoints: RwLock<HashMap<String, EndpointHealth>>,
    /// Infrastructure error count
    infra_errors: RwLock<u32>,
    /// Failure threshold for degraded assessment
    degraded_threshold: f32,
    /// Failure threshold for threat assessment
    threat_threshold: f32,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            endpoints: RwLock::new(HashMap::new()),
            infra_errors: RwLock::new(0),
            degraded_threshold: 0.2, // 20% failure rate = degraded
            threat_threshold: 0.5,   // 50% failure rate = possible blocking
        }
    }

    /// Analyze health events
    fn analyze_health(&self, events: &[TelemetryEvent]) -> (Assessment, f32, Option<Action>) {
        // Process health check events
        for event in events {
            match event {
                TelemetryEvent::HealthCheck(health) => {
                    let mut endpoints = self.endpoints.write();
                    let entry = endpoints
                        .entry(health.endpoint.clone())
                        .or_insert_with(EndpointHealth::default);
                    entry.update(health.reachable, health.latency_ms);
                }
                TelemetryEvent::InfraError(err) => {
                    if !err.recoverable {
                        *self.infra_errors.write() += 1;
                    }
                }
                _ => {}
            }
        }

        // Calculate overall health
        let endpoints = self.endpoints.read();
        let infra_errors = *self.infra_errors.read();

        if endpoints.is_empty() && infra_errors == 0 {
            return (Assessment::Normal, 0.9, None);
        }

        // Calculate aggregate metrics
        let total_endpoints = endpoints.len();
        let failing_endpoints: Vec<_> = endpoints
            .iter()
            .filter(|(_, h)| h.success_rate() < 0.5 || h.consecutive_failures >= 3)
            .collect();

        let all_failing = !endpoints.is_empty()
            && endpoints.values().all(|h| h.consecutive_failures >= 2);

        let avg_success_rate: f32 = if endpoints.is_empty() {
            1.0
        } else {
            endpoints.values().map(|h| h.success_rate()).sum::<f32>() / total_endpoints as f32
        };

        let failure_rate = 1.0 - avg_success_rate;

        // Determine assessment
        let (assessment, confidence, action) = if all_failing || failure_rate >= self.threat_threshold {
            warn!(
                "Health crisis: all endpoints failing or {:.0}% failure rate",
                failure_rate * 100.0
            );
            (
                Assessment::Threat {
                    threat_type: ThreatType::Blocking,
                },
                0.9,
                Some(Action::RotateProfile),
            )
        } else if failure_rate >= self.degraded_threshold || infra_errors >= 3 {
            let severity = ((failure_rate / self.threat_threshold) * 10.0).min(10.0) as u8;
            (
                Assessment::Degraded { severity },
                0.8,
                Some(Action::AlertAdmin {
                    message: format!(
                        "Service degraded: {:.0}% failure rate, {} infra errors",
                        failure_rate * 100.0,
                        infra_errors
                    ),
                }),
            )
        } else if !failing_endpoints.is_empty() {
            (
                Assessment::Suspicious {
                    reason: format!(
                        "{}/{} endpoints experiencing issues",
                        failing_endpoints.len(),
                        total_endpoints
                    ),
                },
                0.7,
                None,
            )
        } else {
            (Assessment::Normal, 0.95, None)
        };

        (assessment, confidence, action)
    }

    /// Get health summary
    pub fn summary(&self) -> HealthSummary {
        let endpoints = self.endpoints.read();
        let infra_errors = *self.infra_errors.read();

        let healthy = endpoints.values().filter(|h| h.success_rate() >= 0.9).count();
        let degraded = endpoints
            .values()
            .filter(|h| h.success_rate() >= 0.5 && h.success_rate() < 0.9)
            .count();
        let unhealthy = endpoints.values().filter(|h| h.success_rate() < 0.5).count();

        let avg_latency = if endpoints.is_empty() {
            0.0
        } else {
            endpoints.values().map(|h| h.avg_latency).sum::<f32>() / endpoints.len() as f32
        };

        HealthSummary {
            total_endpoints: endpoints.len(),
            healthy,
            degraded,
            unhealthy,
            avg_latency,
            infra_errors,
        }
    }

    /// Reset error counters
    pub fn reset_errors(&self) {
        *self.infra_errors.write() = 0;
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Health summary statistics
#[derive(Debug, Clone)]
pub struct HealthSummary {
    pub total_endpoints: usize,
    pub healthy: usize,
    pub degraded: usize,
    pub unhealthy: usize,
    pub avg_latency: f32,
    pub infra_errors: u32,
}

#[async_trait]
impl Specialist for HealthMonitor {
    fn specialist_type(&self) -> SpecialistType {
        SpecialistType::HealthMonitor
    }

    async fn analyze(&self, events: &[TelemetryEvent]) -> Result<SpecialistVote> {
        let (assessment, confidence, action) = self.analyze_health(events);

        let mut vote = SpecialistVote::new(SpecialistType::HealthMonitor, assessment, confidence);

        if let Some(action) = action {
            vote = vote.with_action(action);
        }

        let summary = self.summary();
        vote = vote.with_reasoning(format!(
            "Endpoints: {}/{} healthy, avg latency: {:.0}ms, {} errors",
            summary.healthy, summary.total_endpoints, summary.avg_latency, summary.infra_errors
        ));

        Ok(vote)
    }

    fn can_handle(&self, event: &TelemetryEvent) -> bool {
        matches!(
            event,
            TelemetryEvent::HealthCheck(_) | TelemetryEvent::InfraError(_)
        )
    }

    async fn is_ready(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_healthy_service() {
        let monitor = HealthMonitor::new();

        let events = vec![
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test.com", true).with_latency(50)),
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test2.com", true).with_latency(60)),
        ];

        let vote = monitor.analyze(&events).await.unwrap();
        assert!(matches!(vote.assessment, Assessment::Normal));
    }

    #[tokio::test]
    async fn test_degraded_service() {
        let monitor = HealthMonitor::new();

        // Mix of passing and failing
        let events = vec![
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test.com", true)),
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test.com", false)),
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test.com", false)),
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test.com", false)),
        ];

        let vote = monitor.analyze(&events).await.unwrap();
        assert!(matches!(
            vote.assessment,
            Assessment::Degraded { .. } | Assessment::Threat { .. }
        ));
    }

    #[tokio::test]
    async fn test_all_failing() {
        let monitor = HealthMonitor::new();

        let events = vec![
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test.com", false)),
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test.com", false)),
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test2.com", false)),
            TelemetryEvent::HealthCheck(HealthCheckEvent::new("https://test2.com", false)),
        ];

        let vote = monitor.analyze(&events).await.unwrap();
        assert!(matches!(vote.assessment, Assessment::Threat { .. }));
    }

    #[test]
    fn test_endpoint_health() {
        let mut health = EndpointHealth::default();
        health.update(true, Some(50));
        health.update(true, Some(60));
        health.update(false, None);

        assert_eq!(health.total_checks, 3);
        assert_eq!(health.successful_checks, 2);
        assert!((health.success_rate() - 0.666).abs() < 0.01);
    }
}
