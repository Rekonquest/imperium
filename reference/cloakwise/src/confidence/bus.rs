//! Confidence Bus
//!
//! Aggregates specialist votes and determines if consensus is reached
//! or if escalation to Big Momma is needed.

use crate::config::ConfidenceConfig;
use crate::specialists::{Action, Assessment, SpecialistType, SpecialistVote};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::info;

/// Result of consensus evaluation
#[derive(Debug, Clone)]
pub enum ConsensusResult {
    /// Consensus reached - execute the action
    Consensus {
        action: Action,
        confidence: f32,
        contributing_specialists: Vec<SpecialistType>,
    },
    /// No consensus - escalate to Big Momma
    Escalate {
        reason: String,
        votes: Vec<SpecialistVote>,
    },
    /// No action needed - all specialists agree things are normal
    NoAction {
        confidence: f32,
    },
    /// Conflict between specialists
    Conflict {
        conflicting_assessments: Vec<(SpecialistType, Assessment)>,
    },
}

/// The confidence bus aggregates votes and makes routing decisions
pub struct ConfidenceBus {
    config: ConfidenceConfig,
    /// Recent votes for analysis
    recent_votes: parking_lot::RwLock<Vec<(Instant, SpecialistVote)>>,
    /// Vote history window
    history_window: Duration,
}

impl ConfidenceBus {
    pub fn new(config: ConfidenceConfig) -> Self {
        Self {
            config,
            recent_votes: parking_lot::RwLock::new(Vec::new()),
            history_window: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Submit a vote from a specialist
    pub fn submit_vote(&self, vote: SpecialistVote) {
        let mut votes = self.recent_votes.write();
        votes.push((Instant::now(), vote));

        // Cleanup old votes
        let cutoff = Instant::now() - self.history_window;
        votes.retain(|(time, _)| *time > cutoff);
    }

    /// Evaluate votes and determine action
    pub fn evaluate(&self, votes: &[SpecialistVote]) -> ConsensusResult {
        if votes.is_empty() {
            return ConsensusResult::NoAction { confidence: 1.0 };
        }

        // Store votes for history
        for vote in votes {
            self.submit_vote(vote.clone());
        }

        // Check for minimum specialists
        if votes.len() < self.config.min_specialists_for_consensus as usize {
            return ConsensusResult::Escalate {
                reason: format!(
                    "Insufficient specialists: {} < {}",
                    votes.len(),
                    self.config.min_specialists_for_consensus
                ),
                votes: votes.to_vec(),
            };
        }

        // Categorize votes by assessment type
        let mut threat_votes = Vec::new();
        let mut suspicious_votes = Vec::new();
        let mut normal_votes = Vec::new();
        let mut degraded_votes = Vec::new();

        for vote in votes {
            match &vote.assessment {
                Assessment::Threat { .. } => threat_votes.push(vote),
                Assessment::Suspicious { .. } => suspicious_votes.push(vote),
                Assessment::Normal => normal_votes.push(vote),
                Assessment::Degraded { .. } => degraded_votes.push(vote),
                Assessment::Inconclusive { .. } => {} // Ignore inconclusive
            }
        }

        // Check for threat consensus
        if !threat_votes.is_empty() {
            let avg_confidence = threat_votes.iter().map(|v| v.confidence).sum::<f32>()
                / threat_votes.len() as f32;

            if avg_confidence >= self.config.specialist_threshold {
                // Threat consensus - take action
                let action = self.determine_action(threat_votes.iter().map(|v| *v).collect());
                return ConsensusResult::Consensus {
                    action,
                    confidence: avg_confidence,
                    contributing_specialists: threat_votes.iter().map(|v| v.specialist).collect(),
                };
            } else {
                // Possible threat but not confident enough
                return ConsensusResult::Escalate {
                    reason: format!(
                        "Threat detected but confidence {:.2} < threshold {:.2}",
                        avg_confidence, self.config.specialist_threshold
                    ),
                    votes: votes.to_vec(),
                };
            }
        }

        // Check for suspicious consensus
        if suspicious_votes.len() >= 2 {
            let avg_confidence = suspicious_votes.iter().map(|v| v.confidence).sum::<f32>()
                / suspicious_votes.len() as f32;

            if avg_confidence >= self.config.specialist_threshold * 0.9 {
                // Lower threshold for suspicious
                let action = self.determine_action(suspicious_votes.iter().map(|v| *v).collect());
                return ConsensusResult::Consensus {
                    action,
                    confidence: avg_confidence,
                    contributing_specialists: suspicious_votes.iter().map(|v| v.specialist).collect(),
                };
            }
        }

        // Check for degraded consensus
        if !degraded_votes.is_empty() {
            let avg_severity: u8 = degraded_votes
                .iter()
                .filter_map(|v| match &v.assessment {
                    Assessment::Degraded { severity } => Some(*severity),
                    _ => None,
                })
                .sum::<u8>()
                / degraded_votes.len() as u8;

            if avg_severity >= 5 {
                return ConsensusResult::Escalate {
                    reason: format!("Service degradation severity {} >= 5", avg_severity),
                    votes: votes.to_vec(),
                };
            }
        }

        // Check for normal consensus
        if normal_votes.len() >= votes.len() / 2 {
            let avg_confidence =
                normal_votes.iter().map(|v| v.confidence).sum::<f32>() / normal_votes.len() as f32;

            return ConsensusResult::NoAction {
                confidence: avg_confidence,
            };
        }

        // Check for conflicts
        let has_threat = !threat_votes.is_empty();
        let has_normal = !normal_votes.is_empty();
        let has_suspicious = !suspicious_votes.is_empty();

        if (has_threat && has_normal) || (has_threat && has_suspicious && has_normal) {
            let conflicts: Vec<_> = votes
                .iter()
                .map(|v| (v.specialist, v.assessment.clone()))
                .collect();

            return ConsensusResult::Conflict {
                conflicting_assessments: conflicts,
            };
        }

        // Default: escalate when uncertain
        ConsensusResult::Escalate {
            reason: "No clear consensus reached".to_string(),
            votes: votes.to_vec(),
        }
    }

    /// Determine the best action from multiple votes
    fn determine_action(&self, votes: Vec<&SpecialistVote>) -> Action {
        // Collect all recommended actions with their confidence weights
        let mut action_weights: HashMap<String, (Action, f32)> = HashMap::new();

        for vote in &votes {
            if let Some(ref action) = vote.recommended_action {
                let key = action_key(action);
                let entry = action_weights.entry(key).or_insert((action.clone(), 0.0));
                entry.1 += vote.confidence;
            }
        }

        // Find highest weighted action
        action_weights
            .into_values()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(action, _)| action)
            .unwrap_or(Action::None)
    }

    /// Get recent vote statistics
    pub fn stats(&self) -> ConsensusStats {
        let votes = self.recent_votes.read();

        let mut by_specialist: HashMap<SpecialistType, u32> = HashMap::new();
        let mut by_assessment: HashMap<String, u32> = HashMap::new();
        let mut total_confidence = 0.0f32;

        for (_, vote) in votes.iter() {
            *by_specialist.entry(vote.specialist).or_insert(0) += 1;
            *by_assessment
                .entry(assessment_key(&vote.assessment))
                .or_insert(0) += 1;
            total_confidence += vote.confidence;
        }

        let avg_confidence = if votes.is_empty() {
            0.0
        } else {
            total_confidence / votes.len() as f32
        };

        ConsensusStats {
            total_votes: votes.len(),
            votes_by_specialist: by_specialist,
            votes_by_assessment: by_assessment,
            avg_confidence,
            window_duration: self.history_window,
        }
    }

    /// Clear vote history
    pub fn clear_history(&self) {
        self.recent_votes.write().clear();
    }
}

/// Generate a key for action comparison
fn action_key(action: &Action) -> String {
    match action {
        Action::SwitchProfile { target } => format!("switch:{}", target),
        Action::RotateProfile => "rotate".to_string(),
        Action::ActivateDecoy => "decoy".to_string(),
        Action::ThrottleConnections { max } => format!("throttle:{}", max),
        Action::AddJitter { min_ms, max_ms } => format!("jitter:{}-{}", min_ms, max_ms),
        Action::AlertAdmin { .. } => "alert".to_string(),
        Action::EnterSafeMode => "safemode".to_string(),
        Action::None => "none".to_string(),
    }
}

/// Generate a key for assessment comparison
fn assessment_key(assessment: &Assessment) -> String {
    match assessment {
        Assessment::Normal => "normal".to_string(),
        Assessment::Suspicious { .. } => "suspicious".to_string(),
        Assessment::Threat { .. } => "threat".to_string(),
        Assessment::Degraded { severity } => format!("degraded:{}", severity),
        Assessment::Inconclusive { .. } => "inconclusive".to_string(),
    }
}

/// Consensus statistics
#[derive(Debug, Clone)]
pub struct ConsensusStats {
    pub total_votes: usize,
    pub votes_by_specialist: HashMap<SpecialistType, u32>,
    pub votes_by_assessment: HashMap<String, u32>,
    pub avg_confidence: f32,
    pub window_duration: Duration,
}

/// Voting session for collecting specialist votes
pub struct VotingSession {
    votes: Vec<SpecialistVote>,
    started: Instant,
    timeout: Duration,
}

impl VotingSession {
    pub fn new(timeout: Duration) -> Self {
        Self {
            votes: Vec::new(),
            started: Instant::now(),
            timeout,
        }
    }

    /// Add a vote to the session
    pub fn add_vote(&mut self, vote: SpecialistVote) {
        self.votes.push(vote);
    }

    /// Check if session has timed out
    pub fn is_expired(&self) -> bool {
        self.started.elapsed() >= self.timeout
    }

    /// Get all votes
    pub fn votes(&self) -> &[SpecialistVote] {
        &self.votes
    }

    /// Take votes (consume session)
    pub fn take_votes(self) -> Vec<SpecialistVote> {
        self.votes
    }

    /// Number of votes collected
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::specialists::ThreatType;

    fn test_config() -> ConfidenceConfig {
        ConfidenceConfig {
            specialist_threshold: 0.95,
            escalation_timeout_ms: 5000,
            min_specialists_for_consensus: 3,
        }
    }

    #[test]
    fn test_threat_consensus() {
        let bus = ConfidenceBus::new(test_config());

        let votes = vec![
            SpecialistVote::new(
                SpecialistType::ProbeDetector,
                Assessment::Threat {
                    threat_type: ThreatType::ActiveProbe,
                },
                0.98,
            )
            .with_action(Action::RotateProfile),
            SpecialistVote::new(
                SpecialistType::TrafficAnalyzer,
                Assessment::Threat {
                    threat_type: ThreatType::Fingerprinting,
                },
                0.96,
            )
            .with_action(Action::RotateProfile),
            SpecialistVote::new(
                SpecialistType::ProtocolDetector,
                Assessment::Threat {
                    threat_type: ThreatType::Fingerprinting,
                },
                0.97,
            )
            .with_action(Action::RotateProfile),
        ];

        let result = bus.evaluate(&votes);
        assert!(matches!(result, ConsensusResult::Consensus { .. }));
    }

    #[test]
    fn test_normal_consensus() {
        let bus = ConfidenceBus::new(test_config());

        let votes = vec![
            SpecialistVote::new(SpecialistType::ProbeDetector, Assessment::Normal, 0.95),
            SpecialistVote::new(SpecialistType::TrafficAnalyzer, Assessment::Normal, 0.92),
            SpecialistVote::new(SpecialistType::HealthMonitor, Assessment::Normal, 0.98),
        ];

        let result = bus.evaluate(&votes);
        assert!(matches!(result, ConsensusResult::NoAction { .. }));
    }

    #[test]
    fn test_escalation_low_confidence() {
        let bus = ConfidenceBus::new(test_config());

        let votes = vec![
            SpecialistVote::new(
                SpecialistType::ProbeDetector,
                Assessment::Threat {
                    threat_type: ThreatType::ActiveProbe,
                },
                0.7, // Below threshold
            ),
            SpecialistVote::new(
                SpecialistType::TrafficAnalyzer,
                Assessment::Threat {
                    threat_type: ThreatType::Fingerprinting,
                },
                0.75,
            ),
            SpecialistVote::new(SpecialistType::HealthMonitor, Assessment::Normal, 0.9),
        ];

        let result = bus.evaluate(&votes);
        assert!(matches!(result, ConsensusResult::Escalate { .. }));
    }

    #[test]
    fn test_insufficient_specialists() {
        let bus = ConfidenceBus::new(test_config());

        let votes = vec![
            SpecialistVote::new(SpecialistType::ProbeDetector, Assessment::Normal, 0.95),
            SpecialistVote::new(SpecialistType::TrafficAnalyzer, Assessment::Normal, 0.92),
            // Only 2, need 3
        ];

        let result = bus.evaluate(&votes);
        assert!(matches!(result, ConsensusResult::Escalate { .. }));
    }

    #[test]
    fn test_voting_session() {
        let mut session = VotingSession::new(Duration::from_secs(5));

        session.add_vote(SpecialistVote::new(
            SpecialistType::ProbeDetector,
            Assessment::Normal,
            0.9,
        ));
        session.add_vote(SpecialistVote::new(
            SpecialistType::TrafficAnalyzer,
            Assessment::Normal,
            0.85,
        ));

        assert_eq!(session.vote_count(), 2);
        assert!(!session.is_expired());
    }
}
