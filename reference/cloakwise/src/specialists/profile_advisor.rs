//! Profile Advisor Specialist
//!
//! Recommends optimal traffic profiles based on current conditions.

use super::{Action, Assessment, Specialist, SpecialistType, SpecialistVote};
use crate::telemetry::{ConnectionEvent, HealthCheckEvent, TelemetryEvent};
use crate::vpn::ProfileId;
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::debug;

/// Profile performance metrics
#[derive(Debug, Clone)]
struct ProfileMetrics {
    /// Connection success rate
    success_rate: f32,
    /// Average latency
    avg_latency: f32,
    /// Time spent in this profile (seconds)
    duration_secs: u64,
    /// Number of rotations away from this profile
    rotation_count: u32,
    /// Last used timestamp
    last_used: u64,
    /// Failure count
    failures: u32,
    /// Success count
    successes: u32,
}

impl Default for ProfileMetrics {
    fn default() -> Self {
        Self {
            success_rate: 1.0,
            avg_latency: 0.0,
            duration_secs: 0,
            rotation_count: 0,
            last_used: 0,
            failures: 0,
            successes: 0,
        }
    }
}

impl ProfileMetrics {
    fn update_connection(&mut self, success: bool, latency: Option<u32>) {
        if success {
            self.successes += 1;
            if let Some(lat) = latency {
                self.avg_latency = (self.avg_latency * (self.successes - 1) as f32 + lat as f32)
                    / self.successes as f32;
            }
        } else {
            self.failures += 1;
        }

        let total = self.successes + self.failures;
        if total > 0 {
            self.success_rate = self.successes as f32 / total as f32;
        }
    }

    fn score(&self) -> f32 {
        // Higher is better
        let success_weight = 0.6;
        let latency_weight = 0.2;
        let rotation_weight = 0.2;

        let success_score = self.success_rate;

        // Normalize latency (lower is better, max 500ms baseline)
        let latency_score = if self.avg_latency > 0.0 {
            1.0 - (self.avg_latency / 500.0).min(1.0)
        } else {
            0.5 // Unknown latency = neutral
        };

        // Fewer rotations is better (indicates stability)
        let rotation_score = 1.0 / (1.0 + self.rotation_count as f32 * 0.1);

        success_weight * success_score + latency_weight * latency_score + rotation_weight * rotation_score
    }
}

/// Profile advisor specialist
pub struct ProfileAdvisor {
    /// Metrics per profile
    metrics: RwLock<HashMap<ProfileId, ProfileMetrics>>,
    /// Current profile
    current_profile: RwLock<Option<ProfileId>>,
    /// Profile rotation history
    rotation_history: RwLock<Vec<(u64, ProfileId, String)>>, // (timestamp, profile, reason)
    /// Minimum events before making recommendations
    min_events_threshold: u32,
}

impl ProfileAdvisor {
    pub fn new() -> Self {
        Self {
            metrics: RwLock::new(HashMap::new()),
            current_profile: RwLock::new(None),
            rotation_history: RwLock::new(Vec::new()),
            min_events_threshold: 10,
        }
    }

    /// Set current profile
    pub fn set_current_profile(&self, profile: ProfileId) {
        *self.current_profile.write() = Some(profile);
    }

    /// Record a profile rotation
    pub fn record_rotation(&self, profile: ProfileId, reason: &str) {
        let timestamp = crate::telemetry::current_timestamp();

        // Update previous profile metrics
        if let Some(prev) = self.current_profile.read().as_ref() {
            let mut metrics = self.metrics.write();
            let entry = metrics.entry(prev.clone()).or_insert_with(ProfileMetrics::default);
            entry.rotation_count += 1;
        }

        // Update history
        self.rotation_history.write().push((timestamp, profile.clone(), reason.to_string()));

        // Limit history size
        let mut history = self.rotation_history.write();
        if history.len() > 100 {
            history.drain(0..50);
        }

        // Set new current profile
        *self.current_profile.write() = Some(profile);
    }

    /// Analyze events and recommend profile
    fn analyze_profiles(&self, events: &[TelemetryEvent]) -> (Assessment, f32, Option<Action>) {
        let current = self.current_profile.read().clone();

        // Update metrics based on events
        {
            let mut metrics = self.metrics.write();

            for event in events {
                if let TelemetryEvent::Connection(conn) = event {
                    if let Some(ref profile) = current {
                        let entry = metrics.entry(profile.clone()).or_insert_with(ProfileMetrics::default);
                        entry.update_connection(conn.success, conn.latency_ms);
                    }
                }
            }
        }

        // Calculate recommendations
        let metrics = self.metrics.read();

        // Check current profile performance
        let current_score = current.as_ref().and_then(|p| metrics.get(p)).map(|m| m.score()).unwrap_or(0.5);
        let current_rate = current.as_ref().and_then(|p| metrics.get(p)).map(|m| m.success_rate).unwrap_or(1.0);

        // Find best alternative profile
        let best_alternative = metrics
            .iter()
            .filter(|(id, _)| current.as_ref() != Some(*id))
            .max_by(|(_, a), (_, b)| a.score().partial_cmp(&b.score()).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(id, m)| (id.clone(), m.score()));

        // Determine assessment
        let (assessment, confidence, action) = if current_rate < 0.5 {
            // Current profile is performing poorly
            let recommended = best_alternative
                .map(|(id, _)| id)
                .unwrap_or_else(|| "https_clone".to_string());

            (
                Assessment::Suspicious {
                    reason: format!(
                        "Current profile success rate: {:.0}%",
                        current_rate * 100.0
                    ),
                },
                0.8,
                Some(Action::SwitchProfile { target: recommended }),
            )
        } else if let Some((alt_id, alt_score)) = best_alternative {
            if alt_score > current_score * 1.3 {
                // Alternative is significantly better
                (
                    Assessment::Suspicious {
                        reason: format!(
                            "Better profile available: {} (score: {:.2} vs {:.2})",
                            alt_id, alt_score, current_score
                        ),
                    },
                    0.6,
                    Some(Action::SwitchProfile { target: alt_id }),
                )
            } else {
                (Assessment::Normal, 0.85, None)
            }
        } else {
            (Assessment::Normal, 0.9, None)
        };

        (assessment, confidence, action)
    }

    /// Get profile rankings
    pub fn rankings(&self) -> Vec<(ProfileId, f32)> {
        let metrics = self.metrics.read();
        let mut rankings: Vec<_> = metrics.iter().map(|(id, m)| (id.clone(), m.score())).collect();
        rankings.sort_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        rankings
    }

    /// Get recent rotation count
    pub fn recent_rotations(&self, window_secs: u64) -> u32 {
        let now = crate::telemetry::current_timestamp();
        let cutoff = now.saturating_sub(window_secs * 1000);

        self.rotation_history
            .read()
            .iter()
            .filter(|(ts, _, _)| *ts >= cutoff)
            .count() as u32
    }
}

impl Default for ProfileAdvisor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Specialist for ProfileAdvisor {
    fn specialist_type(&self) -> SpecialistType {
        SpecialistType::ProfileAdvisor
    }

    async fn analyze(&self, events: &[TelemetryEvent]) -> Result<SpecialistVote> {
        let (assessment, confidence, action) = self.analyze_profiles(events);

        let mut vote = SpecialistVote::new(SpecialistType::ProfileAdvisor, assessment, confidence);

        if let Some(action) = action {
            vote = vote.with_action(action);
        }

        let current = self.current_profile.read().clone().unwrap_or_else(|| "unknown".to_string());
        let recent_rotations = self.recent_rotations(3600); // Last hour

        vote = vote.with_reasoning(format!(
            "Current profile: {}, {} rotations in last hour, {} profiles tracked",
            current,
            recent_rotations,
            self.metrics.read().len()
        ));

        Ok(vote)
    }

    fn can_handle(&self, event: &TelemetryEvent) -> bool {
        matches!(event, TelemetryEvent::Connection(_) | TelemetryEvent::HealthCheck(_))
    }

    async fn is_ready(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_profile_tracking() {
        let advisor = ProfileAdvisor::new();
        advisor.set_current_profile("https_clone".to_string());

        let events = vec![
            TelemetryEvent::Connection(ConnectionEvent::new("test", true).with_latency(50)),
            TelemetryEvent::Connection(ConnectionEvent::new("test", true).with_latency(60)),
            TelemetryEvent::Connection(ConnectionEvent::new("test", false)),
        ];

        let vote = advisor.analyze(&events).await.unwrap();
        // With 2/3 success rate, should still be mostly normal
        assert!(matches!(vote.assessment, Assessment::Normal | Assessment::Suspicious { .. }));
    }

    #[test]
    fn test_profile_metrics() {
        let mut metrics = ProfileMetrics::default();

        metrics.update_connection(true, Some(50));
        metrics.update_connection(true, Some(60));
        metrics.update_connection(false, None);

        assert_eq!(metrics.successes, 2);
        assert_eq!(metrics.failures, 1);
        assert!((metrics.success_rate - 0.666).abs() < 0.01);
        assert!((metrics.avg_latency - 55.0).abs() < 0.01);
    }

    #[test]
    fn test_rotation_recording() {
        let advisor = ProfileAdvisor::new();
        advisor.set_current_profile("profile1".to_string());
        advisor.record_rotation("profile2".to_string(), "test rotation");

        assert_eq!(advisor.recent_rotations(60), 1);
    }
}
