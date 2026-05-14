//! Big Momma Reasoner
//!
//! Handles complex decisions that specialists cannot resolve.
//! Supports two inference backends:
//!   1. OpenAI-compatible API (LM Studio, ollama, vLLM, etc.)
//!   2. Heuristic fallback (no model required)

use crate::config::InferenceConfig;
use crate::specialists::{Action, Assessment, SpecialistVote, ThreatType};
use crate::telemetry::TelemetryEvent;
use anyhow::Result;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

/// Decision from Big Momma
#[derive(Debug, Clone)]
pub struct BigMommaDecision {
    /// Recommended action
    pub action: Action,
    /// Confidence in decision
    pub confidence: f32,
    /// Reasoning explanation
    pub reasoning: String,
    /// Processing time
    pub processing_time: Duration,
    /// Whether this was from cache/heuristics vs full inference
    pub from_inference: bool,
}

/// LLM response parsed from JSON
#[derive(Debug, serde::Deserialize)]
struct LlmDecision {
    action: String,
    confidence: f32,
    reasoning: String,
}

/// OpenAI-compatible chat completion request
#[derive(Debug, serde::Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Debug, serde::Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

/// OpenAI-compatible chat completion response
#[derive(Debug, serde::Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, serde::Deserialize)]
struct ChatChoice {
    message: ChatMessageResponse,
}

#[derive(Debug, serde::Deserialize)]
struct ChatMessageResponse {
    content: String,
}

/// Big Momma - the complex decision maker
pub struct BigMomma {
    config: InferenceConfig,
    /// Timeout for inference
    timeout: Duration,
    /// Whether real model is available
    model_available: bool,
    /// HTTP client for API calls
    http_client: reqwest::Client,
    /// API endpoint (e.g. "http://localhost:1234/v1")
    api_endpoint: Option<String>,
    /// Model name for API requests
    api_model: String,
    /// Decision cache for quick responses
    decision_cache: parking_lot::RwLock<Vec<(String, BigMommaDecision)>>,
}

impl BigMomma {
    pub fn new(config: InferenceConfig, timeout_ms: u64) -> Self {
        Self {
            config,
            timeout: Duration::from_millis(timeout_ms),
            model_available: false,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_millis(timeout_ms))
                .build()
                .unwrap_or_default(),
            api_endpoint: None,
            api_model: "default".to_string(),
            decision_cache: parking_lot::RwLock::new(Vec::new()),
        }
    }

    /// Initialize Big Momma - probe API endpoint if configured
    pub async fn initialize(&mut self) -> Result<()> {
        if let Some(ref endpoint) = self.api_endpoint {
            // Probe the API to see if it's reachable
            let models_url = format!("{}/models", endpoint);
            match self.http_client.get(&models_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!(
                        "Big Momma connected to LLM API at {} (model: {})",
                        endpoint, self.api_model
                    );
                    self.model_available = true;
                }
                Ok(resp) => {
                    warn!(
                        "Big Momma LLM API returned status {} - falling back to heuristics",
                        resp.status()
                    );
                    self.model_available = false;
                }
                Err(e) => {
                    warn!(
                        "Big Momma cannot reach LLM API at {}: {} - falling back to heuristics",
                        endpoint, e
                    );
                    self.model_available = false;
                }
            }
        } else {
            info!("Big Momma initializing (heuristic mode - no API endpoint configured)");
            self.model_available = false;
        }
        Ok(())
    }

    /// Configure the API endpoint
    pub fn set_api_endpoint(&mut self, endpoint: String, model: Option<String>) {
        self.api_endpoint = Some(endpoint);
        if let Some(m) = model {
            self.api_model = m;
        }
    }

    /// Process an escalated decision
    pub async fn decide(
        &self,
        votes: &[SpecialistVote],
        events: &[TelemetryEvent],
        reason: &str,
    ) -> Result<BigMommaDecision> {
        let start = Instant::now();

        info!("Big Momma processing escalation: {}", reason);
        debug!("Input: {} votes, {} events", votes.len(), events.len());

        // Check cache first
        let cache_key = self.generate_cache_key(votes, reason);
        if let Some(cached) = self.check_cache(&cache_key) {
            debug!("Cache hit for escalation");
            return Ok(cached);
        }

        // Decide using model or heuristics
        let decision = if self.model_available {
            match self.decide_with_model(votes, events, reason).await {
                Ok(d) => d,
                Err(e) => {
                    error!("Model inference failed: {} - falling back to heuristics", e);
                    self.decide_with_heuristics(votes, events, reason)
                }
            }
        } else {
            self.decide_with_heuristics(votes, events, reason)
        };

        let mut decision = decision;
        decision.processing_time = start.elapsed();

        // Cache the decision
        self.cache_decision(&cache_key, &decision);

        info!(
            "Big Momma decision: {:?} (confidence: {:.2}, inference: {}, took: {:?})",
            decision.action, decision.confidence, decision.from_inference, decision.processing_time
        );

        Ok(decision)
    }

    /// Make decision using LLM API
    async fn decide_with_model(
        &self,
        votes: &[SpecialistVote],
        events: &[TelemetryEvent],
        reason: &str,
    ) -> Result<BigMommaDecision> {
        let endpoint = self
            .api_endpoint
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No API endpoint configured"))?;

        let system_prompt = self.build_system_prompt();
        let user_prompt = self.build_user_prompt(votes, events, reason);

        let request = ChatRequest {
            model: self.api_model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system_prompt,
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user_prompt,
                },
            ],
            temperature: self.config.temperature,
            max_tokens: self.config.max_tokens,
        };

        let url = format!("{}/chat/completions", endpoint);
        debug!("Sending inference request to {}", url);

        let response = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("LLM API returned {}: {}", status, body);
        }

        let chat_response: ChatResponse = response.json().await?;
        let content = chat_response
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default();

        debug!("LLM raw response: {}", content);

        // Parse JSON from response - handle markdown code blocks
        let json_str = extract_json(&content);
        let llm_decision: LlmDecision = serde_json::from_str(json_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse LLM JSON: {} (raw: {})", e, content))?;

        // Map string action to Action enum
        let action = match llm_decision.action.to_lowercase().as_str() {
            "none" | "monitor" | "continue" => Action::None,
            "rotate" | "rotate_profile" | "switch" => Action::RotateProfile,
            "jitter" | "add_jitter" => Action::AddJitter {
                min_ms: 10,
                max_ms: 100,
            },
            "alert" | "alert_admin" => Action::AlertAdmin {
                message: llm_decision.reasoning.clone(),
            },
            "safemode" | "safe_mode" | "enter_safe_mode" => Action::EnterSafeMode,
            other => {
                warn!("Unknown LLM action '{}', defaulting to None", other);
                Action::None
            }
        };

        Ok(BigMommaDecision {
            action,
            confidence: llm_decision.confidence.clamp(0.0, 1.0),
            reasoning: llm_decision.reasoning,
            processing_time: Duration::ZERO, // Will be set by caller
            from_inference: true,
        })
    }

    /// System prompt for the LLM
    fn build_system_prompt(&self) -> String {
        r#"You are Big Momma, the strategic AI decision-maker for Cloakwise, an adaptive VPN defense system protecting users from state-level censorship and surveillance.

Your job: analyze threat assessments from specialist detectors and decide the best defensive action.

AVAILABLE ACTIONS:
- "none": No action needed, continue monitoring
- "rotate": Switch to a different traffic profile to avoid detection
- "jitter": Add random timing delays to disrupt traffic analysis
- "alert": Alert the admin about a potential threat
- "safemode": Enter safe mode (maximum stealth, minimal functionality)

RESPOND ONLY with valid JSON (no markdown, no explanation outside JSON):
{"action": "none|rotate|jitter|alert|safemode", "confidence": 0.0-1.0, "reasoning": "brief explanation"}

DECISION PRINCIPLES:
- Err on the side of protecting the user's safety
- Multiple threat detections = take action immediately
- Single suspicious signal = monitor, don't overreact
- Active probes or fingerprinting = rotate profile NOW
- Blocking detected = enter safe mode
- When in doubt, add jitter (low cost, buys time)"#
            .to_string()
    }

    /// User prompt with the current situation
    fn build_user_prompt(
        &self,
        votes: &[SpecialistVote],
        events: &[TelemetryEvent],
        reason: &str,
    ) -> String {
        let votes_summary: Vec<String> = votes
            .iter()
            .map(|v| {
                format!(
                    "- {} (confidence {:.0}%): {:?}",
                    v.specialist, v.confidence * 100.0, v.assessment
                )
            })
            .collect();

        format!(
            "ESCALATION REASON: {}\n\nSPECIALIST VOTES:\n{}\n\nTELEMETRY: {} events in current window\n\nWhat action should we take?",
            reason,
            votes_summary.join("\n"),
            events.len()
        )
    }

    /// Make decision using heuristic rules
    fn decide_with_heuristics(
        &self,
        votes: &[SpecialistVote],
        _events: &[TelemetryEvent],
        reason: &str,
    ) -> BigMommaDecision {
        let threat_count = votes
            .iter()
            .filter(|v| matches!(v.assessment, Assessment::Threat { .. }))
            .count();
        let suspicious_count = votes
            .iter()
            .filter(|v| matches!(v.assessment, Assessment::Suspicious { .. }))
            .count();
        let normal_count = votes
            .iter()
            .filter(|v| matches!(v.assessment, Assessment::Normal))
            .count();

        let avg_confidence: f32 =
            votes.iter().map(|v| v.confidence).sum::<f32>() / votes.len().max(1) as f32;

        let (action, confidence, reasoning) = if threat_count >= 2 {
            let threat_types: Vec<_> = votes
                .iter()
                .filter_map(|v| match &v.assessment {
                    Assessment::Threat { threat_type } => Some(threat_type),
                    _ => None,
                })
                .collect();

            let action = if threat_types.iter().any(|t| matches!(t, ThreatType::Blocking)) {
                Action::EnterSafeMode
            } else if threat_types
                .iter()
                .any(|t| matches!(t, ThreatType::ActiveProbe | ThreatType::Fingerprinting))
            {
                Action::RotateProfile
            } else {
                Action::AlertAdmin {
                    message: format!("Multiple threats detected: {:?}", threat_types),
                }
            };

            (
                action,
                avg_confidence.max(0.8),
                format!(
                    "[heuristic] Multiple threats detected ({} threat votes). Taking defensive action.",
                    threat_count
                ),
            )
        } else if suspicious_count >= 3 {
            (
                Action::AddJitter { min_ms: 10, max_ms: 100 },
                0.7,
                "[heuristic] High suspicion level - adding timing jitter".to_string(),
            )
        } else if threat_count == 1 && normal_count >= 2 {
            (
                Action::AlertAdmin {
                    message: "Single specialist detected potential threat - monitoring".to_string(),
                },
                0.6,
                "[heuristic] Isolated threat detection - alerting for review".to_string(),
            )
        } else if suspicious_count > normal_count {
            (
                Action::AddJitter { min_ms: 5, max_ms: 50 },
                0.65,
                "[heuristic] Elevated suspicion - adding minor jitter".to_string(),
            )
        } else if reason.contains("timeout") || reason.contains("Timeout") {
            (
                Action::None,
                0.5,
                "[heuristic] Escalated due to timeout - no action without more data".to_string(),
            )
        } else {
            (
                Action::None,
                0.6,
                "[heuristic] Situation unclear - continuing normal monitoring".to_string(),
            )
        };

        BigMommaDecision {
            action,
            confidence,
            reasoning,
            processing_time: Duration::ZERO,
            from_inference: false,
        }
    }

    fn generate_cache_key(&self, votes: &[SpecialistVote], reason: &str) -> String {
        let threat_count = votes
            .iter()
            .filter(|v| matches!(v.assessment, Assessment::Threat { .. }))
            .count();
        let suspicious_count = votes
            .iter()
            .filter(|v| matches!(v.assessment, Assessment::Suspicious { .. }))
            .count();
        format!("{}:t{}:s{}", reason, threat_count, suspicious_count)
    }

    fn check_cache(&self, key: &str) -> Option<BigMommaDecision> {
        let cache = self.decision_cache.read();
        cache.iter().find(|(k, _)| k == key).map(|(_, d)| d.clone())
    }

    fn cache_decision(&self, key: &str, decision: &BigMommaDecision) {
        let mut cache = self.decision_cache.write();
        if cache.len() >= 100 {
            cache.drain(0..50);
        }
        cache.push((key.to_string(), decision.clone()));
    }

    pub fn clear_cache(&self) {
        self.decision_cache.write().clear();
    }

    pub fn is_model_available(&self) -> bool {
        self.model_available
    }

    pub fn stats(&self) -> BigMommaStats {
        let cache_size = self.decision_cache.read().len();
        BigMommaStats {
            model_available: self.model_available,
            cache_size,
            timeout_ms: self.timeout.as_millis() as u64,
        }
    }
}

/// Extract JSON from a string that may contain markdown code blocks
fn extract_json(s: &str) -> &str {
    let trimmed = s.trim();
    // Strip ```json ... ``` wrapper
    if let Some(start) = trimmed.find('{') {
        if let Some(end) = trimmed.rfind('}') {
            return &trimmed[start..=end];
        }
    }
    trimmed
}

/// Big Momma statistics
#[derive(Debug, Clone)]
pub struct BigMommaStats {
    pub model_available: bool,
    pub cache_size: usize,
    pub timeout_ms: u64,
}

/// Timeout wrapper for Big Momma decisions
pub async fn decide_with_timeout(
    big_momma: &BigMomma,
    votes: &[SpecialistVote],
    events: &[TelemetryEvent],
    reason: &str,
    timeout: Duration,
) -> Result<Option<BigMommaDecision>> {
    let decision_future = big_momma.decide(votes, events, reason);

    match tokio::time::timeout(timeout, decision_future).await {
        Ok(result) => result.map(Some),
        Err(_) => {
            warn!("Big Momma decision timed out after {:?}", timeout);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::specialists::SpecialistType;

    fn test_config() -> InferenceConfig {
        InferenceConfig {
            threads: 4,
            context_size: 2048,
            batch_size: 512,
            temperature: 0.1,
            max_tokens: 256,
        }
    }

    #[test]
    fn test_extract_json() {
        assert_eq!(
            extract_json(r#"```json
{"action":"none","confidence":0.5,"reasoning":"test"}
```"#),
            r#"{"action":"none","confidence":0.5,"reasoning":"test"}"#
        );
        assert_eq!(
            extract_json(r#"{"action":"rotate","confidence":0.8,"reasoning":"threat"}"#),
            r#"{"action":"rotate","confidence":0.8,"reasoning":"threat"}"#
        );
    }

    #[tokio::test]
    async fn test_heuristic_decision_threat() {
        let big_momma = BigMomma::new(test_config(), 5000);

        let votes = vec![
            SpecialistVote::new(
                SpecialistType::ProbeDetector,
                Assessment::Threat {
                    threat_type: ThreatType::ActiveProbe,
                },
                0.9,
            ),
            SpecialistVote::new(
                SpecialistType::ProtocolDetector,
                Assessment::Threat {
                    threat_type: ThreatType::Fingerprinting,
                },
                0.85,
            ),
        ];

        let decision = big_momma
            .decide(&votes, &[], "Test escalation")
            .await
            .unwrap();

        assert!(!matches!(decision.action, Action::None));
        assert!(decision.confidence > 0.7);
        assert!(!decision.from_inference);
    }

    #[tokio::test]
    async fn test_heuristic_decision_normal() {
        let big_momma = BigMomma::new(test_config(), 5000);

        let votes = vec![
            SpecialistVote::new(SpecialistType::ProbeDetector, Assessment::Normal, 0.9),
            SpecialistVote::new(SpecialistType::HealthMonitor, Assessment::Normal, 0.95),
            SpecialistVote::new(
                SpecialistType::TrafficAnalyzer,
                Assessment::Suspicious {
                    reason: "Minor anomaly".to_string(),
                },
                0.6,
            ),
        ];

        let decision = big_momma
            .decide(&votes, &[], "Uncertainty escalation")
            .await
            .unwrap();

        assert!(decision.confidence < 0.9);
    }

    #[test]
    fn test_cache() {
        let big_momma = BigMomma::new(test_config(), 5000);

        let key = "test:t2:s1";
        let decision = BigMommaDecision {
            action: Action::RotateProfile,
            confidence: 0.8,
            reasoning: "Test".to_string(),
            processing_time: Duration::from_millis(100),
            from_inference: false,
        };

        big_momma.cache_decision(key, &decision);
        let cached = big_momma.check_cache(key);
        assert!(cached.is_some());
        assert!(matches!(cached.unwrap().action, Action::RotateProfile));
    }
}
