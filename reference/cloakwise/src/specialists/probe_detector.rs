//! Probe Detector Specialist
//!
//! Detects active probing attempts from DPI systems like TSPU.

use super::{Action, Assessment, Specialist, SpecialistType, SpecialistVote, ThreatType};
use crate::telemetry::{ProbeSignature, TelemetryEvent};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{debug, warn};

/// Known probe source patterns (IPs, ASNs, etc.)
#[derive(Debug, Clone)]
struct ProbePattern {
    /// Known DPI probe source IP ranges
    known_probe_ips: Vec<ipnet::IpNet>,
    /// Probe signature weights
    signature_weights: HashMap<String, f32>,
    /// Recent probe sources
    recent_sources: Vec<IpAddr>,
}

impl Default for ProbePattern {
    fn default() -> Self {
        let mut signature_weights = HashMap::new();
        signature_weights.insert("tspu_active".to_string(), 0.95);
        signature_weights.insert("tls_fingerprint".to_string(), 0.7);
        signature_weights.insert("wireguard_probe".to_string(), 0.85);
        signature_weights.insert("port_scan".to_string(), 0.3);
        signature_weights.insert("reset_injection".to_string(), 0.9);
        signature_weights.insert("replay_attack".to_string(), 0.95);

        Self {
            known_probe_ips: Vec::new(),
            signature_weights,
            recent_sources: Vec::new(),
        }
    }
}

/// Probe detector specialist
pub struct ProbeDetector {
    patterns: RwLock<ProbePattern>,
    /// Minimum confidence to report as threat
    threat_threshold: f32,
    /// Minimum confidence to report as suspicious
    suspicious_threshold: f32,
}

impl ProbeDetector {
    pub fn new() -> Self {
        Self {
            patterns: RwLock::new(ProbePattern::default()),
            threat_threshold: 0.8,
            suspicious_threshold: 0.5,
        }
    }

    /// Analyze probe events
    fn analyze_probes(&self, events: &[TelemetryEvent]) -> (Assessment, f32, Option<Action>) {
        let probe_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                TelemetryEvent::ProbeAttempt(probe) => Some(probe),
                _ => None,
            })
            .collect();

        if probe_events.is_empty() {
            return (Assessment::Normal, 0.95, None);
        }

        let patterns = self.patterns.read();
        let mut max_threat_score = 0.0f32;
        let mut threat_reasons = Vec::new();

        for probe in &probe_events {
            // Get base weight from signature
            let signature_key = match &probe.signature {
                ProbeSignature::TspuActive => "tspu_active",
                ProbeSignature::TlsFingerprint => "tls_fingerprint",
                ProbeSignature::WireguardProbe => "wireguard_probe",
                ProbeSignature::PortScan => "port_scan",
                ProbeSignature::ResetInjection => "reset_injection",
                ProbeSignature::ReplayAttack => "replay_attack",
                ProbeSignature::Unknown { .. } => "unknown",
            };

            let base_weight = patterns.signature_weights.get(signature_key).unwrap_or(&0.5);
            let score = base_weight * probe.confidence;

            if score > max_threat_score {
                max_threat_score = score;
            }

            if score > self.suspicious_threshold {
                threat_reasons.push(format!(
                    "{:?} from {} (score: {:.2})",
                    probe.signature, probe.source_ip, score
                ));
            }
        }

        // Determine assessment
        let (assessment, action) = if max_threat_score >= self.threat_threshold {
            (
                Assessment::Threat {
                    threat_type: ThreatType::ActiveProbe,
                },
                Some(Action::RotateProfile),
            )
        } else if max_threat_score >= self.suspicious_threshold {
            (
                Assessment::Suspicious {
                    reason: threat_reasons.join("; "),
                },
                Some(Action::AlertAdmin {
                    message: format!("Suspicious probe activity detected: {}", threat_reasons.join("; ")),
                }),
            )
        } else {
            (Assessment::Normal, None)
        };

        // Confidence in our assessment
        let confidence = if probe_events.is_empty() {
            0.9 // High confidence when no probes
        } else {
            max_threat_score.max(0.6) // At least 60% confident when we see probes
        };

        (assessment, confidence, action)
    }

    /// Check for probe patterns in connection failures
    fn analyze_connection_patterns(&self, events: &[TelemetryEvent]) -> Option<(Assessment, f32)> {
        let connection_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                TelemetryEvent::Connection(conn) => Some(conn),
                _ => None,
            })
            .collect();

        if connection_events.is_empty() {
            return None;
        }

        // Count rapid failures from same source
        let mut failure_sources: HashMap<Option<IpAddr>, u32> = HashMap::new();
        for conn in &connection_events {
            if !conn.success {
                *failure_sources.entry(conn.source_ip).or_insert(0) += 1;
            }
        }

        // Check for probing patterns
        for (source, count) in &failure_sources {
            if *count >= 5 {
                // Multiple rapid failures from same source
                warn!("Multiple connection failures from {:?}: {}", source, count);
                return Some((
                    Assessment::Suspicious {
                        reason: format!("Multiple failures from {:?}", source),
                    },
                    0.7,
                ));
            }
        }

        None
    }
}

impl Default for ProbeDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Specialist for ProbeDetector {
    fn specialist_type(&self) -> SpecialistType {
        SpecialistType::ProbeDetector
    }

    async fn analyze(&self, events: &[TelemetryEvent]) -> Result<SpecialistVote> {
        // Analyze direct probe events
        let (probe_assessment, probe_confidence, probe_action) = self.analyze_probes(events);

        // Also check connection patterns
        let connection_analysis = self.analyze_connection_patterns(events);

        // Combine analyses
        let (assessment, confidence, action) = match (&probe_assessment, &connection_analysis) {
            (Assessment::Threat { .. }, _) => (probe_assessment, probe_confidence, probe_action),
            (_, Some((conn_assessment, conn_confidence))) if *conn_confidence > probe_confidence => {
                (conn_assessment.clone(), *conn_confidence, None)
            }
            _ => (probe_assessment, probe_confidence, probe_action),
        };

        let mut vote = SpecialistVote::new(SpecialistType::ProbeDetector, assessment, confidence);

        if let Some(action) = action {
            vote = vote.with_action(action);
        }

        vote = vote.with_reasoning(format!(
            "Analyzed {} events, {} probe attempts detected",
            events.len(),
            events.iter().filter(|e| matches!(e, TelemetryEvent::ProbeAttempt(_))).count()
        ));

        Ok(vote)
    }

    fn can_handle(&self, event: &TelemetryEvent) -> bool {
        matches!(
            event,
            TelemetryEvent::ProbeAttempt(_) | TelemetryEvent::Connection(_)
        )
    }

    async fn is_ready(&self) -> bool {
        true // Rule-based, always ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::ProbeAttemptEvent;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_probe_detection() {
        let detector = ProbeDetector::new();

        let events = vec![TelemetryEvent::ProbeAttempt(
            ProbeAttemptEvent::new(
                IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                443,
                ProbeSignature::TspuActive,
            )
            .with_confidence(0.9),
        )];

        let vote = detector.analyze(&events).await.unwrap();
        assert!(matches!(vote.assessment, Assessment::Threat { .. }));
        assert!(vote.confidence > 0.8);
    }

    #[tokio::test]
    async fn test_normal_traffic() {
        let detector = ProbeDetector::new();
        let events: Vec<TelemetryEvent> = vec![];

        let vote = detector.analyze(&events).await.unwrap();
        assert!(matches!(vote.assessment, Assessment::Normal));
    }
}
