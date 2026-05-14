//! Traffic Analyzer Specialist
//!
//! Analyzes traffic patterns to detect fingerprinting attempts.

use super::{Action, Assessment, Specialist, SpecialistType, SpecialistVote, ThreatType};
use crate::telemetry::{PacketPatternEvent, TelemetryEvent};
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::debug;

/// Traffic pattern statistics
#[derive(Debug, Clone, Default)]
struct PatternStats {
    /// Average packet size
    avg_size: f32,
    /// Size variance
    size_variance: f32,
    /// Average interval
    avg_interval: f32,
    /// Interval variance
    interval_variance: f32,
    /// Total packets analyzed
    packet_count: u64,
}

impl PatternStats {
    fn from_event(event: &PacketPatternEvent) -> Self {
        if event.sizes.is_empty() {
            return Self::default();
        }

        let sizes: Vec<f32> = event.sizes.iter().map(|&s| s as f32).collect();
        let intervals: Vec<f32> = event.intervals_ms.iter().map(|&i| i as f32).collect();

        let avg_size = sizes.iter().sum::<f32>() / sizes.len() as f32;
        let avg_interval = if intervals.is_empty() {
            0.0
        } else {
            intervals.iter().sum::<f32>() / intervals.len() as f32
        };

        let size_variance = if sizes.len() > 1 {
            sizes.iter().map(|s| (s - avg_size).powi(2)).sum::<f32>() / (sizes.len() - 1) as f32
        } else {
            0.0
        };

        let interval_variance = if intervals.len() > 1 {
            intervals.iter().map(|i| (i - avg_interval).powi(2)).sum::<f32>()
                / (intervals.len() - 1) as f32
        } else {
            0.0
        };

        Self {
            avg_size,
            size_variance,
            avg_interval,
            interval_variance,
            packet_count: sizes.len() as u64,
        }
    }
}

/// Traffic analyzer specialist
pub struct TrafficAnalyzer {
    /// Historical baseline stats
    baseline: RwLock<Option<PatternStats>>,
    /// Deviation threshold for suspicious traffic
    deviation_threshold: f32,
}

impl TrafficAnalyzer {
    pub fn new() -> Self {
        Self {
            baseline: RwLock::new(None),
            deviation_threshold: 2.5, // Standard deviations
        }
    }

    /// Analyze traffic patterns for fingerprinting indicators
    fn analyze_patterns(&self, events: &[TelemetryEvent]) -> (Assessment, f32, Option<String>) {
        let pattern_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                TelemetryEvent::PacketPattern(pattern) => Some(pattern),
                _ => None,
            })
            .collect();

        if pattern_events.is_empty() {
            return (Assessment::Normal, 0.9, None);
        }

        // Calculate current stats
        let mut combined_stats = PatternStats::default();
        let mut total_packets = 0u64;

        for event in &pattern_events {
            let stats = PatternStats::from_event(event);
            // Weighted average
            let weight = stats.packet_count as f32;
            combined_stats.avg_size = (combined_stats.avg_size * total_packets as f32
                + stats.avg_size * weight)
                / (total_packets as f32 + weight);
            combined_stats.avg_interval = (combined_stats.avg_interval * total_packets as f32
                + stats.avg_interval * weight)
                / (total_packets as f32 + weight);
            total_packets += stats.packet_count;
        }

        combined_stats.packet_count = total_packets;

        // Check for fingerprinting indicators
        let mut suspicion_score = 0.0f32;
        let mut reasons = Vec::new();

        // 1. Check for very regular packet sizes (potential fingerprint)
        if combined_stats.size_variance < 100.0 && combined_stats.packet_count > 10 {
            suspicion_score += 0.3;
            reasons.push("Low size variance - possible fingerprinting".to_string());
        }

        // 2. Check for very regular intervals (potential fingerprint)
        if combined_stats.interval_variance < 5.0 && combined_stats.packet_count > 10 {
            suspicion_score += 0.3;
            reasons.push("Low interval variance - possible fingerprinting".to_string());
        }

        // 3. Check against baseline if available
        let baseline = self.baseline.read();
        if let Some(ref base) = *baseline {
            let size_deviation =
                (combined_stats.avg_size - base.avg_size).abs() / (base.size_variance.sqrt() + 1.0);
            let interval_deviation = (combined_stats.avg_interval - base.avg_interval).abs()
                / (base.interval_variance.sqrt() + 1.0);

            if size_deviation > self.deviation_threshold {
                suspicion_score += 0.2;
                reasons.push(format!(
                    "Size deviation: {:.1} std devs",
                    size_deviation
                ));
            }

            if interval_deviation > self.deviation_threshold {
                suspicion_score += 0.2;
                reasons.push(format!(
                    "Interval deviation: {:.1} std devs",
                    interval_deviation
                ));
            }
        }

        // 4. Check for WireGuard-specific patterns
        // WireGuard has characteristic packet sizes (148, 92, etc.)
        let wg_sizes = [148u16, 92, 32, 80];
        let wg_pattern_count = pattern_events
            .iter()
            .flat_map(|e| &e.sizes)
            .filter(|&&s| wg_sizes.contains(&s))
            .count();

        let total_packets_check: usize = pattern_events.iter().map(|e| e.sizes.len()).sum();
        if total_packets_check > 0 {
            let wg_ratio = wg_pattern_count as f32 / total_packets_check as f32;
            if wg_ratio > 0.5 {
                suspicion_score += 0.2;
                reasons.push(format!(
                    "High WireGuard signature ratio: {:.0}%",
                    wg_ratio * 100.0
                ));
            }
        }

        // Determine assessment
        let (assessment, confidence) = if suspicion_score >= 0.7 {
            (
                Assessment::Threat {
                    threat_type: ThreatType::Fingerprinting,
                },
                0.85,
            )
        } else if suspicion_score >= 0.4 {
            (
                Assessment::Suspicious {
                    reason: reasons.join("; "),
                },
                0.7,
            )
        } else {
            (Assessment::Normal, 0.9 - suspicion_score)
        };

        let reasoning = if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        };

        (assessment, confidence, reasoning)
    }

    /// Update baseline with new observations
    pub fn update_baseline(&self, events: &[TelemetryEvent]) {
        let pattern_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                TelemetryEvent::PacketPattern(pattern) => Some(pattern),
                _ => None,
            })
            .collect();

        if pattern_events.is_empty() {
            return;
        }

        let mut combined = PatternStats::default();
        let mut total = 0u64;

        for event in &pattern_events {
            let stats = PatternStats::from_event(event);
            let weight = stats.packet_count as f32;
            combined.avg_size =
                (combined.avg_size * total as f32 + stats.avg_size * weight) / (total as f32 + weight);
            combined.avg_interval = (combined.avg_interval * total as f32
                + stats.avg_interval * weight)
                / (total as f32 + weight);
            combined.size_variance = (combined.size_variance * total as f32
                + stats.size_variance * weight)
                / (total as f32 + weight);
            combined.interval_variance = (combined.interval_variance * total as f32
                + stats.interval_variance * weight)
                / (total as f32 + weight);
            total += stats.packet_count;
        }

        combined.packet_count = total;
        *self.baseline.write() = Some(combined);
    }
}

impl Default for TrafficAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Specialist for TrafficAnalyzer {
    fn specialist_type(&self) -> SpecialistType {
        SpecialistType::TrafficAnalyzer
    }

    async fn analyze(&self, events: &[TelemetryEvent]) -> Result<SpecialistVote> {
        let (assessment, confidence, reasoning) = self.analyze_patterns(events);

        let mut vote = SpecialistVote::new(SpecialistType::TrafficAnalyzer, assessment.clone(), confidence);

        // Recommend action based on assessment
        match &assessment {
            Assessment::Threat { .. } => {
                vote = vote.with_action(Action::SwitchProfile {
                    target: "video_call".to_string(), // More variable traffic pattern
                });
            }
            Assessment::Suspicious { .. } => {
                vote = vote.with_action(Action::AddJitter {
                    min_ms: 5,
                    max_ms: 50,
                });
            }
            _ => {}
        }

        if let Some(reason) = reasoning {
            vote = vote.with_reasoning(reason);
        }

        Ok(vote)
    }

    fn can_handle(&self, event: &TelemetryEvent) -> bool {
        matches!(event, TelemetryEvent::PacketPattern(_))
    }

    async fn is_ready(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::Direction;

    #[tokio::test]
    async fn test_normal_traffic() {
        let analyzer = TrafficAnalyzer::new();
        let events: Vec<TelemetryEvent> = vec![];

        let vote = analyzer.analyze(&events).await.unwrap();
        assert!(matches!(vote.assessment, Assessment::Normal));
    }

    #[tokio::test]
    async fn test_suspicious_pattern() {
        let analyzer = TrafficAnalyzer::new();

        // Create pattern with very regular sizes (potential fingerprint)
        let events = vec![TelemetryEvent::PacketPattern(PacketPatternEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: 0,
            client_id: None,
            direction: Direction::Both,
            sizes: vec![148; 20], // All same size
            intervals_ms: vec![10; 19], // Very regular
            total_bytes: 2960,
            duration_ms: 190,
        })];

        let vote = analyzer.analyze(&events).await.unwrap();
        // Should detect the suspicious pattern
        assert!(matches!(
            vote.assessment,
            Assessment::Suspicious { .. } | Assessment::Threat { .. }
        ));
    }
}
