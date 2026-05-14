//! Timing Anomaly Detector Specialist
//!
//! Detects statistical anomalies in packet timing that could indicate detection.

use super::{Action, Assessment, Specialist, SpecialistType, SpecialistVote, ThreatType};
use crate::telemetry::{ConnectionEvent, PacketPatternEvent, TelemetryEvent};
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::VecDeque;
use tracing::debug;

/// Timing statistics window
#[derive(Debug, Clone)]
struct TimingWindow {
    /// Latencies in ms
    latencies: VecDeque<u32>,
    /// Max window size
    max_size: usize,
}

impl TimingWindow {
    fn new(max_size: usize) -> Self {
        Self {
            latencies: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    fn add(&mut self, latency: u32) {
        if self.latencies.len() >= self.max_size {
            self.latencies.pop_front();
        }
        self.latencies.push_back(latency);
    }

    fn mean(&self) -> f64 {
        if self.latencies.is_empty() {
            return 0.0;
        }
        self.latencies.iter().map(|&l| l as f64).sum::<f64>() / self.latencies.len() as f64
    }

    fn std_dev(&self) -> f64 {
        if self.latencies.len() < 2 {
            return 0.0;
        }
        let mean = self.mean();
        let variance = self
            .latencies
            .iter()
            .map(|&l| (l as f64 - mean).powi(2))
            .sum::<f64>()
            / (self.latencies.len() - 1) as f64;
        variance.sqrt()
    }

    fn percentile(&self, p: f64) -> u32 {
        if self.latencies.is_empty() {
            return 0;
        }
        let mut sorted: Vec<_> = self.latencies.iter().copied().collect();
        sorted.sort();
        let idx = ((sorted.len() as f64 - 1.0) * p / 100.0).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }
}

/// Timing anomaly detector
pub struct TimingAnomalyDetector {
    /// Historical timing window
    history: RwLock<TimingWindow>,
    /// Z-score threshold for anomaly detection
    z_threshold: f64,
    /// Consecutive anomalies needed for alert
    anomaly_threshold: u32,
    /// Current consecutive anomaly count
    anomaly_count: RwLock<u32>,
}

impl TimingAnomalyDetector {
    pub fn new() -> Self {
        Self {
            history: RwLock::new(TimingWindow::new(1000)),
            z_threshold: 3.0,
            anomaly_threshold: 5,
            anomaly_count: RwLock::new(0),
        }
    }

    /// Analyze timing for anomalies
    fn analyze_timing(&self, events: &[TelemetryEvent]) -> (Assessment, f32, Option<Action>) {
        let mut anomalies = Vec::new();
        let mut normal_count = 0u32;

        // Get current stats
        let (mean, std_dev) = {
            let history = self.history.read();
            (history.mean(), history.std_dev())
        };

        // Process connection events
        for event in events {
            if let TelemetryEvent::Connection(conn) = event {
                if let Some(latency) = conn.latency_ms {
                    // Add to history
                    self.history.write().add(latency);

                    // Check for anomaly
                    if std_dev > 1e-9 {
                        let z_score = (latency as f64 - mean).abs() / std_dev;
                        if z_score > self.z_threshold {
                            anomalies.push((latency, z_score));
                        } else {
                            normal_count += 1;
                        }
                    } else if (latency as f64 - mean).abs() > 1.0 {
                        // Constant baseline (std_dev ~ 0): large deviation is still anomalous
                        anomalies.push((latency, 10.0));
                    } else {
                        normal_count += 1;
                    }
                }
            }
        }

        // Process packet pattern events
        for event in events {
            if let TelemetryEvent::PacketPattern(pattern) = event {
                // Check interval timing
                if pattern.intervals_ms.len() > 2 {
                    let avg_interval: f64 =
                        pattern.intervals_ms.iter().map(|&i| i as f64).sum::<f64>()
                            / pattern.intervals_ms.len() as f64;

                    let variance: f64 = pattern
                        .intervals_ms
                        .iter()
                        .map(|&i| (i as f64 - avg_interval).powi(2))
                        .sum::<f64>()
                        / (pattern.intervals_ms.len() - 1) as f64;

                    // Very low variance might indicate detection (traffic is being shaped)
                    let cv = variance.sqrt() / (avg_interval + 0.1); // Coefficient of variation
                    if cv < 0.05 && pattern.intervals_ms.len() > 10 {
                        anomalies.push((0, 5.0)); // Artificial high z-score
                    }
                }
            }
        }

        // Update anomaly counter
        let mut count = self.anomaly_count.write();
        if anomalies.is_empty() {
            *count = count.saturating_sub(1);
        } else {
            *count += anomalies.len() as u32;
        }

        let current_count = *count;
        drop(count);

        // Determine assessment
        let (assessment, confidence, action) = if current_count >= self.anomaly_threshold * 2 {
            (
                Assessment::Threat {
                    threat_type: ThreatType::Throttling,
                },
                0.9,
                Some(Action::RotateProfile),
            )
        } else if current_count >= self.anomaly_threshold {
            (
                Assessment::Suspicious {
                    reason: format!(
                        "{} timing anomalies detected (z-score > {})",
                        anomalies.len(),
                        self.z_threshold
                    ),
                },
                0.75,
                Some(Action::AddJitter {
                    min_ms: 10,
                    max_ms: 100,
                }),
            )
        } else if !anomalies.is_empty() {
            (
                Assessment::Suspicious {
                    reason: format!("{} timing anomalies detected", anomalies.len()),
                },
                0.6,
                None,
            )
        } else {
            (Assessment::Normal, 0.9, None)
        };

        (assessment, confidence, action)
    }

    /// Get current timing statistics
    pub fn stats(&self) -> TimingStats {
        let history = self.history.read();
        TimingStats {
            mean_latency: history.mean(),
            std_dev: history.std_dev(),
            p50: history.percentile(50.0),
            p95: history.percentile(95.0),
            p99: history.percentile(99.0),
            sample_count: history.latencies.len(),
        }
    }
}

impl Default for TimingAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Timing statistics
#[derive(Debug, Clone)]
pub struct TimingStats {
    pub mean_latency: f64,
    pub std_dev: f64,
    pub p50: u32,
    pub p95: u32,
    pub p99: u32,
    pub sample_count: usize,
}

#[async_trait]
impl Specialist for TimingAnomalyDetector {
    fn specialist_type(&self) -> SpecialistType {
        SpecialistType::TimingAnomaly
    }

    async fn analyze(&self, events: &[TelemetryEvent]) -> Result<SpecialistVote> {
        let (assessment, confidence, action) = self.analyze_timing(events);

        let mut vote = SpecialistVote::new(SpecialistType::TimingAnomaly, assessment, confidence);

        if let Some(action) = action {
            vote = vote.with_action(action);
        }

        let stats = self.stats();
        vote = vote.with_reasoning(format!(
            "Mean latency: {:.1}ms, StdDev: {:.1}ms, P95: {}ms ({} samples)",
            stats.mean_latency, stats.std_dev, stats.p95, stats.sample_count
        ));

        Ok(vote)
    }

    fn can_handle(&self, event: &TelemetryEvent) -> bool {
        matches!(
            event,
            TelemetryEvent::Connection(_) | TelemetryEvent::PacketPattern(_)
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
    async fn test_normal_timing() {
        let detector = TimingAnomalyDetector::new();

        // Add some baseline data
        {
            let mut history = detector.history.write();
            for latency in [50, 55, 48, 52, 51, 49, 53, 50, 52, 48] {
                history.add(latency);
            }
        }

        // Create normal events
        let events = vec![TelemetryEvent::Connection(ConnectionEvent::new("test", true).with_latency(51))];

        let vote = detector.analyze(&events).await.unwrap();
        assert!(matches!(vote.assessment, Assessment::Normal));
    }

    #[tokio::test]
    async fn test_anomaly_detection() {
        let detector = TimingAnomalyDetector::new();

        // Add baseline with low variance
        {
            let mut history = detector.history.write();
            for _ in 0..100 {
                history.add(50);
            }
        }

        // Create anomalous event (way outside normal)
        let events = vec![TelemetryEvent::Connection(ConnectionEvent::new("test", true).with_latency(500))];

        let vote = detector.analyze(&events).await.unwrap();
        // Should detect some suspicion
        assert!(matches!(vote.assessment, Assessment::Suspicious { .. }));
    }

    #[test]
    fn test_timing_window() {
        let mut window = TimingWindow::new(10);
        for i in 1..=10 {
            window.add(i * 10);
        }

        assert!((window.mean() - 55.0).abs() < 0.01);
        assert!(window.std_dev() > 0.0);
    }
}
