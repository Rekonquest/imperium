//! Protocol Detector Specialist
//!
//! Detects attempts to identify/classify the VPN protocol.

use super::{Action, Assessment, Specialist, SpecialistType, SpecialistVote, ThreatType};
use crate::telemetry::{ConnectionEvent, PacketPatternEvent, ProbeSignature, TelemetryEvent};
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{debug, warn};

/// Protocol classification detection state
#[derive(Debug, Clone)]
struct ClassificationState {
    /// Detected classification attempts
    classification_attempts: u32,
    /// Confidence that protocol has been identified
    identification_confidence: f32,
    /// Specific protocols that may have been identified
    identified_protocols: Vec<String>,
}

impl Default for ClassificationState {
    fn default() -> Self {
        Self {
            classification_attempts: 0,
            identification_confidence: 0.0,
            identified_protocols: Vec::new(),
        }
    }
}

/// Protocol detector specialist
pub struct ProtocolDetector {
    /// Classification state
    state: RwLock<ClassificationState>,
    /// Known protocol fingerprints (packet size patterns)
    protocol_fingerprints: HashMap<String, Vec<u16>>,
}

impl ProtocolDetector {
    pub fn new() -> Self {
        let mut fingerprints = HashMap::new();

        // WireGuard handshake sizes
        fingerprints.insert("wireguard".to_string(), vec![148, 92, 32, 80, 64]);

        // OpenVPN patterns
        fingerprints.insert("openvpn".to_string(), vec![42, 54, 64, 72]);

        // Shadowsocks patterns (varies by cipher)
        fingerprints.insert("shadowsocks".to_string(), vec![50, 66, 82]);

        Self {
            state: RwLock::new(ClassificationState::default()),
            protocol_fingerprints: fingerprints,
        }
    }

    /// Analyze events for protocol classification attempts
    fn analyze_classification(&self, events: &[TelemetryEvent]) -> (Assessment, f32, Option<Action>) {
        let mut state = self.state.write();
        let mut classification_indicators = Vec::new();

        for event in events {
            match event {
                TelemetryEvent::ProbeAttempt(probe) => {
                    // Check for protocol-specific probes
                    match &probe.signature {
                        ProbeSignature::WireguardProbe => {
                            state.classification_attempts += 1;
                            state.identified_protocols.push("wireguard".to_string());
                            classification_indicators.push("WireGuard probe detected");
                        }
                        ProbeSignature::TlsFingerprint => {
                            state.classification_attempts += 1;
                            classification_indicators.push("TLS fingerprinting attempt");
                        }
                        ProbeSignature::TspuActive => {
                            state.classification_attempts += 2; // More severe
                            classification_indicators.push("TSPU active classification");
                        }
                        _ => {}
                    }
                }
                TelemetryEvent::PacketPattern(pattern) => {
                    // Check if packet sizes match known protocols
                    for (protocol, fingerprint) in &self.protocol_fingerprints {
                        let match_count = pattern
                            .sizes
                            .iter()
                            .filter(|s| fingerprint.contains(s))
                            .count();

                        let match_ratio = match_count as f32 / pattern.sizes.len().max(1) as f32;

                        if match_ratio > 0.5 && pattern.sizes.len() >= 5 {
                            warn!(
                                "High {} fingerprint match: {:.0}%",
                                protocol,
                                match_ratio * 100.0
                            );
                            state.identification_confidence = state.identification_confidence.max(match_ratio);
                            if !state.identified_protocols.contains(protocol) {
                                state.identified_protocols.push(protocol.clone());
                            }
                            classification_indicators.push("Protocol fingerprint matched");
                        }
                    }
                }
                TelemetryEvent::Connection(conn) => {
                    // Check for connection patterns that suggest classification
                    if !conn.success {
                        if let Some(ref reason) = conn.failure_reason {
                            match reason {
                                crate::telemetry::ConnectionFailure::Rejected => {
                                    // Might indicate protocol was identified and blocked
                                    state.classification_attempts += 1;
                                    classification_indicators.push("Connection rejected (possible protocol block)");
                                }
                                crate::telemetry::ConnectionFailure::Blocked => {
                                    state.classification_attempts += 2;
                                    state.identification_confidence = 0.9;
                                    classification_indicators.push("Connection blocked");
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Update identification confidence based on attempts
        if state.classification_attempts > 0 {
            let attempt_confidence = (state.classification_attempts as f32 / 10.0).min(0.8);
            state.identification_confidence = state.identification_confidence.max(attempt_confidence);
        }

        // Determine assessment
        let (assessment, confidence, action) = if state.identification_confidence >= 0.8 {
            (
                Assessment::Threat {
                    threat_type: ThreatType::Fingerprinting,
                },
                0.9,
                Some(Action::SwitchProfile {
                    target: "https_clone".to_string(), // Switch to most obfuscated
                }),
            )
        } else if state.identification_confidence >= 0.5 || state.classification_attempts >= 5 {
            (
                Assessment::Suspicious {
                    reason: format!(
                        "Protocol classification suspected: {} attempts, {:.0}% confidence",
                        state.classification_attempts,
                        state.identification_confidence * 100.0
                    ),
                },
                0.75,
                Some(Action::AddJitter {
                    min_ms: 20,
                    max_ms: 200,
                }),
            )
        } else if !classification_indicators.is_empty() {
            (
                Assessment::Suspicious {
                    reason: classification_indicators.join("; "),
                },
                0.6,
                None,
            )
        } else {
            (Assessment::Normal, 0.9, None)
        };

        (assessment, confidence, action)
    }

    /// Reset classification state (e.g., after profile switch)
    pub fn reset(&self) {
        *self.state.write() = ClassificationState::default();
    }

    /// Get current classification state
    pub fn classification_state(&self) -> (u32, f32, Vec<String>) {
        let state = self.state.read();
        (
            state.classification_attempts,
            state.identification_confidence,
            state.identified_protocols.clone(),
        )
    }
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Specialist for ProtocolDetector {
    fn specialist_type(&self) -> SpecialistType {
        SpecialistType::ProtocolDetector
    }

    async fn analyze(&self, events: &[TelemetryEvent]) -> Result<SpecialistVote> {
        let (assessment, confidence, action) = self.analyze_classification(events);

        let mut vote = SpecialistVote::new(SpecialistType::ProtocolDetector, assessment, confidence);

        if let Some(action) = action {
            vote = vote.with_action(action);
        }

        let (attempts, id_confidence, protocols) = self.classification_state();
        let protocols_str = if protocols.is_empty() {
            "none".to_string()
        } else {
            protocols.join(", ")
        };

        vote = vote.with_reasoning(format!(
            "Classification attempts: {}, ID confidence: {:.0}%, Identified: {}",
            attempts,
            id_confidence * 100.0,
            protocols_str
        ));

        Ok(vote)
    }

    fn can_handle(&self, event: &TelemetryEvent) -> bool {
        matches!(
            event,
            TelemetryEvent::ProbeAttempt(_)
                | TelemetryEvent::PacketPattern(_)
                | TelemetryEvent::Connection(_)
        )
    }

    async fn is_ready(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{Direction, ProbeAttemptEvent};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_no_classification() {
        let detector = ProtocolDetector::new();
        let events: Vec<TelemetryEvent> = vec![];

        let vote = detector.analyze(&events).await.unwrap();
        assert!(matches!(vote.assessment, Assessment::Normal));
    }

    #[tokio::test]
    async fn test_wireguard_probe_detection() {
        let detector = ProtocolDetector::new();

        let events = vec![TelemetryEvent::ProbeAttempt(ProbeAttemptEvent::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            51820,
            ProbeSignature::WireguardProbe,
        ))];

        let vote = detector.analyze(&events).await.unwrap();
        assert!(matches!(vote.assessment, Assessment::Suspicious { .. }));
    }

    #[tokio::test]
    async fn test_fingerprint_detection() {
        let detector = ProtocolDetector::new();

        // Create pattern that matches WireGuard fingerprint
        let events = vec![TelemetryEvent::PacketPattern(PacketPatternEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: 0,
            client_id: None,
            direction: Direction::Both,
            sizes: vec![148, 92, 148, 32, 80, 148, 92], // WireGuard-like
            intervals_ms: vec![10, 20, 10, 15, 10, 20],
            total_bytes: 740,
            duration_ms: 85,
        })];

        let vote = detector.analyze(&events).await.unwrap();
        // Should detect the fingerprint
        let (_, confidence, protocols) = detector.classification_state();
        assert!(confidence > 0.0 || !protocols.is_empty());
    }

    #[test]
    fn test_reset() {
        let detector = ProtocolDetector::new();

        // Simulate some detection
        {
            let mut state = detector.state.write();
            state.classification_attempts = 5;
            state.identification_confidence = 0.7;
        }

        detector.reset();

        let (attempts, confidence, _) = detector.classification_state();
        assert_eq!(attempts, 0);
        assert_eq!(confidence, 0.0);
    }
}
