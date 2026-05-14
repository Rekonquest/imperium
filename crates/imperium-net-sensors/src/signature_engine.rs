use std::sync::Arc;

use chrono::Utc;
use imperium_bus::Bus;
use imperium_protocol::{
    ExtractedSignatureActivated, Message, SignatureActivationFailed,
    SignatureCandidate, SuggestedAction, ThreatAssessment, ThreatSource,
};
use imperium_store::Store;
use parking_lot::RwLock;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SignatureEngineError {
    #[error("no signatures loaded")]
    NoSignatures,
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
    #[error("yara compile error: {0}")]
    YaraCompile(String),
    #[error("yara scan error: {0}")]
    YaraScan(String),
}

#[derive(Clone, Debug)]
pub struct SignatureRule {
    pub id: String,
    pub rule_text: String,
    pub description: String,
    pub layer: SignatureLayer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureLayer {
    Bundled,
    Extracted,
}

pub struct SignatureEngineSensor {
    bundled_rules: Arc<RwLock<Vec<SignatureRule>>>,
    extracted_rules: Arc<RwLock<Vec<SignatureRule>>>,
    bus: Arc<Bus>,
    store: Option<Store>,
}

impl SignatureEngineSensor {
    pub fn new(bus: Arc<Bus>) -> Self {
        Self {
            bundled_rules: Arc::new(RwLock::new(Vec::new())),
            extracted_rules: Arc::new(RwLock::new(Vec::new())),
            bus,
            store: None,
        }
    }

    pub fn with_store(mut self, store: Store) -> Self {
        self.store = Some(store);
        self
    }

    pub fn load_bundled_rules(&self, rules: Vec<SignatureRule>) {
        *self.bundled_rules.write() = rules;
        tracing::info!(count = self.bundled_count(), "loaded bundled signature rules");
    }

    pub fn load_extracted_rules(&self, rules: Vec<SignatureRule>) {
        *self.extracted_rules.write() = rules;
        tracing::info!(count = self.extracted_count(), "loaded extracted signature rules");
    }

    pub fn add_extracted_rule(&self, rule: SignatureRule) {
        self.extracted_rules.write().push(rule);
    }

    pub fn remove_extracted_rule(&self, id: &str) -> bool {
        let mut rules = self.extracted_rules.write();
        let before = rules.len();
        rules.retain(|r| r.id != id);
        rules.len() < before
    }

    pub fn scan(&self, data: &[u8]) -> Result<Vec<ThreatAssessment>, SignatureEngineError> {
        let all_rules: Vec<SignatureRule> = {
            let bundled = self.bundled_rules.read();
            let extracted = self.extracted_rules.read();
            bundled.iter().chain(extracted.iter()).cloned().collect()
        };

        if all_rules.is_empty() {
            return Ok(Vec::new());
        }

        let mut compiler = yara_x::Compiler::new();
        let mut rule_map: Vec<(String, String)> = Vec::new();

        for rule in &all_rules {
            if let Err(e) = compiler.add_source(rule.rule_text.as_str()) {
                tracing::warn!(rule_id = %rule.id, error = %e, "failed to compile YARA rule, skipping");
                continue;
            }
            rule_map.push((rule.id.clone(), rule.description.clone()));
        }

        let rules = compiler.build();
        let mut scanner = yara_x::Scanner::new(&rules);
        let scan_results = scanner.scan(data)
            .map_err(|e| SignatureEngineError::YaraScan(e.to_string()))?;

        let mut matches = Vec::new();
        for matched_rule in scan_results.matching_rules() {
            let rule_name = matched_rule.identifier();
            let description = rule_map
                .iter()
                .find(|(id, _)| id == rule_name)
                .map(|(_, d)| d.clone())
                .unwrap_or_else(|| format!("YARA match: {}", rule_name));

            let assessment = ThreatAssessment {
                source: ThreatSource::SignatureEngine,
                confidence: 1.0,
                description,
                remote_addr: None,
                timestamp: Utc::now(),
                suggested_action: SuggestedAction::TriggerFailover,
            };

            let _ = self.bus.publish(
                "net.sensors.signature_match",
                Message::ThreatAssessment(assessment.clone()),
            );

            matches.push(assessment);
        }

        Ok(matches)
    }

    pub fn bundled_count(&self) -> usize {
        self.bundled_rules.read().len()
    }

    pub fn extracted_count(&self) -> usize {
        self.extracted_rules.read().len()
    }

    pub fn total_rules(&self) -> usize {
        self.bundled_count() + self.extracted_count()
    }

    pub fn subscribe_signature_approvals(
        self: &Arc<Self>,
        bus: &Bus,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = bus.subscribe("net.signatures.approved");
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if let Message::SignatureApproved(ref approved) = event.message {
                            engine.activate_candidate(approved.candidate_id);
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }

    fn activate_candidate(&self, candidate_id: Uuid) {
        let store = match &self.store {
            Some(s) => s,
            None => {
                tracing::error!(
                    candidate_id = %candidate_id,
                    "no store configured — cannot fetch candidate for activation"
                );
                self.publish_activation_failed(
                    candidate_id,
                    "no store configured".into(),
                );
                return;
            }
        };

        let key = format!("signature_candidate:{}", candidate_id);
        let raw = match store.get(&key) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(
                    candidate_id = %candidate_id,
                    error = %e,
                    "failed to fetch candidate from store"
                );
                self.publish_activation_failed(
                    candidate_id,
                    format!("store fetch failed: {}", e),
                );
                return;
            }
        };

        let candidate: SignatureCandidate = match serde_json::from_slice(&raw) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    candidate_id = %candidate_id,
                    error = %e,
                    "failed to deserialize candidate"
                );
                self.publish_activation_failed(
                    candidate_id,
                    format!("deserialization failed: {}", e),
                );
                return;
            }
        };

        let mut compiler = yara_x::Compiler::new();
        if let Err(e) = compiler.add_source(candidate.rule_text.as_str()) {
            tracing::warn!(
                candidate_id = %candidate_id,
                error = %e,
                "YARA rule failed to compile"
            );
            self.publish_activation_failed(
                candidate_id,
                format!("YARA compile error: {}", e),
            );
            return;
        }
        let _rules = compiler.build();

        let signature_id = Uuid::new_v4();
        let rule = SignatureRule {
            id: format!("extracted_{}", candidate_id),
            rule_text: candidate.rule_text,
            description: candidate.description,
            layer: SignatureLayer::Extracted,
        };
        self.add_extracted_rule(rule);

        tracing::info!(
            candidate_id = %candidate_id,
            signature_id = %signature_id,
            "signature activated — rule loaded into engine"
        );

        let _ = self.bus.publish(
            "net.signatures.activated",
            Message::SignatureActivated(ExtractedSignatureActivated {
                candidate_id,
                signature_id,
                activated_at: Utc::now(),
            }),
        );
    }

    fn publish_activation_failed(&self, candidate_id: Uuid, compile_error: String) {
        let _ = self.bus.publish(
            "net.signatures.activation_failed",
            Message::SignatureActivationFailed(SignatureActivationFailed {
                candidate_id,
                compile_error,
                failed_at: Utc::now(),
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> SignatureEngineSensor {
        let bus = Arc::new(Bus::new());
        SignatureEngineSensor::new(bus)
    }

    fn deadbeef_rule() -> SignatureRule {
        SignatureRule {
            id: "deadbeef".into(),
            rule_text: r#"rule deadbeef { strings: $a = { DE AD BE EF } condition: $a }"#.into(),
            description: "deadbeef pattern".into(),
            layer: SignatureLayer::Bundled,
        }
    }

    #[test]
    fn loads_bundled_rules() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![deadbeef_rule()]);
        assert_eq!(engine.bundled_count(), 1);
    }

    #[test]
    fn matches_yara_pattern() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![deadbeef_rule()]);

        let data = vec![0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF];
        let matches = engine.scan(&data).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, 1.0);
    }

    #[test]
    fn no_match_returns_empty() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![deadbeef_rule()]);

        let matches = engine.scan(&[0x00, 0x01, 0x02]).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn extracted_rules_separate_from_bundled() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![SignatureRule {
            id: "b1".into(),
            rule_text: r#"rule b1 { strings: $a = { AA } condition: $a }"#.into(),
            description: "bundled".into(),
            layer: SignatureLayer::Bundled,
        }]);
        engine.add_extracted_rule(SignatureRule {
            id: "e1".into(),
            rule_text: r#"rule e1 { strings: $a = { BB } condition: $a }"#.into(),
            description: "extracted".into(),
            layer: SignatureLayer::Extracted,
        });

        assert_eq!(engine.bundled_count(), 1);
        assert_eq!(engine.extracted_count(), 1);
        assert_eq!(engine.total_rules(), 2);

        engine.remove_extracted_rule("e1");
        assert_eq!(engine.extracted_count(), 0);
        assert_eq!(engine.bundled_count(), 1);
    }

    #[test]
    fn scan_with_both_rule_layers() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![SignatureRule {
            id: "bundled_rule".into(),
            rule_text: r#"rule bundled_rule { strings: $a = { AA BB } condition: $a }"#.into(),
            description: "bundled match".into(),
            layer: SignatureLayer::Bundled,
        }]);
        engine.add_extracted_rule(SignatureRule {
            id: "extracted_rule".into(),
            rule_text: r#"rule extracted_rule { strings: $a = { CC DD } condition: $a }"#.into(),
            description: "extracted match".into(),
            layer: SignatureLayer::Extracted,
        });

        let data = vec![0xAA, 0xBB, 0x00, 0xCC, 0xDD];
        let matches = engine.scan(&data).unwrap();
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn scan_empty_data_no_matches() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![deadbeef_rule()]);
        let matches = engine.scan(&[]).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_no_rules_returns_empty() {
        let engine = test_engine();
        let matches = engine.scan(&[0xDE, 0xAD]).unwrap();
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn two_phase_activation_valid_rule() {
        use imperium_protocol::{EventId, PeerId, SignatureApproved, SignatureCandidate};
        use imperium_store::Store;
        use uuid::Uuid;

        let bus = Arc::new(Bus::new());
        let store = Store::in_memory();

        let candidate_id = Uuid::new_v4();
        let candidate = SignatureCandidate {
            id: candidate_id,
            rule_text: r#"rule activated_test { strings: $a = { CA FE } condition: $a }"#.into(),
            description: "two-phase test".into(),
            source_events: vec![EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.9,
        };
        let key = format!("signature_candidate:{}", candidate_id);
        store.put(&key, serde_json::to_vec(&candidate).unwrap()).unwrap();

        let engine = Arc::new(
            SignatureEngineSensor::new(Arc::clone(&bus)).with_store(store),
        );

        let mut activation_sub = bus.subscribe("net.signatures.activated");
        let _handle = engine.subscribe_signature_approvals(&bus);

        let approval = SignatureApproved {
            candidate_id,
            approved_by: PeerId::new(),
            approved_at: chrono::Utc::now(),
            signature: vec![1, 2, 3],
        };
        bus.publish(
            "net.signatures.approved",
            Message::SignatureApproved(approval.clone()),
        ).unwrap();

        let event = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            activation_sub.recv(),
        ).await.unwrap().unwrap();

        if let Message::SignatureActivated(activated) = event.message {
            assert_eq!(activated.candidate_id, candidate_id);
        } else {
            panic!("expected SignatureActivated message");
        }

        assert_eq!(engine.extracted_count(), 1);

        let data = vec![0xCA, 0xFE];
        let matches = engine.scan(&data).unwrap();
        assert_eq!(matches.len(), 1);
    }

    #[tokio::test]
    async fn two_phase_activation_invalid_rule_publishes_failure() {
        use imperium_protocol::{EventId, PeerId, SignatureApproved, SignatureCandidate};
        use imperium_store::Store;
        use uuid::Uuid;

        let bus = Arc::new(Bus::new());
        let store = Store::in_memory();

        let candidate_id = Uuid::new_v4();
        let candidate = SignatureCandidate {
            id: candidate_id,
            rule_text: "rule bad_syntax { this is not valid yara }".into(),
            description: "bad rule".into(),
            source_events: vec![EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.5,
        };
        let key = format!("signature_candidate:{}", candidate_id);
        store.put(&key, serde_json::to_vec(&candidate).unwrap()).unwrap();

        let engine = Arc::new(
            SignatureEngineSensor::new(Arc::clone(&bus)).with_store(store),
        );

        let mut failure_sub = bus.subscribe("net.signatures.activation_failed");
        let _handle = engine.subscribe_signature_approvals(&bus);

        let approval = SignatureApproved {
            candidate_id,
            approved_by: PeerId::new(),
            approved_at: chrono::Utc::now(),
            signature: vec![1, 2, 3],
        };
        bus.publish(
            "net.signatures.approved",
            Message::SignatureApproved(approval),
        ).unwrap();

        let event = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            failure_sub.recv(),
        ).await.unwrap().unwrap();

        if let Message::SignatureActivationFailed(failed) = event.message {
            assert_eq!(failed.candidate_id, candidate_id);
            assert!(!failed.compile_error.is_empty());
        } else {
            panic!("expected SignatureActivationFailed message");
        }

        assert_eq!(engine.extracted_count(), 0);
    }

    #[tokio::test]
    async fn two_phase_activation_missing_candidate_publishes_failure() {
        use imperium_protocol::{PeerId, SignatureApproved};
        use imperium_store::Store;
        use uuid::Uuid;

        let bus = Arc::new(Bus::new());
        let store = Store::in_memory();
        let engine = Arc::new(
            SignatureEngineSensor::new(Arc::clone(&bus)).with_store(store),
        );

        let mut failure_sub = bus.subscribe("net.signatures.activation_failed");
        let _handle = engine.subscribe_signature_approvals(&bus);

        let candidate_id = Uuid::new_v4();
        bus.publish(
            "net.signatures.approved",
            Message::SignatureApproved(SignatureApproved {
                candidate_id,
                approved_by: PeerId::new(),
                approved_at: chrono::Utc::now(),
                signature: vec![],
            }),
        ).unwrap();

        let event = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            failure_sub.recv(),
        ).await.unwrap().unwrap();

        if let Message::SignatureActivationFailed(failed) = event.message {
            assert_eq!(failed.candidate_id, candidate_id);
            assert!(failed.compile_error.contains("store fetch failed"));
        } else {
            panic!("expected SignatureActivationFailed message");
        }
    }
}
