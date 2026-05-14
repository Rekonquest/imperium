use std::sync::Arc;

use chrono::Utc;
use imperium_bus::Bus;
use imperium_protocol::{
    Message, SuggestedAction, WatchtowerObservation, WatchtowerUnavailable,
    WatchtowerUnavailableReason,
};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::projection::ProjectionResult;

#[derive(Debug, Error)]
pub enum WatchtowerError {
    #[error("model not loaded")]
    ModelNotLoaded,
    #[error("model hash mismatch: expected {expected}, got {actual}")]
    ModelHashMismatch { expected: String, actual: String },
    #[error("watchtower disabled")]
    Disabled,
    #[error("bus error: {0}")]
    Bus(#[from] imperium_bus::BusError),
}

#[derive(Clone, Debug)]
pub struct WatchtowerConfig {
    pub enabled: bool,
    pub model_path: Option<String>,
    pub trusted_model_hash: Option<String>,
    pub observation_interval_secs: u64,
}

impl Default for WatchtowerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: None,
            trusted_model_hash: None,
            observation_interval_secs: 60,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchtowerState {
    Disabled,
    Loading,
    Active,
    Unavailable(String),
}

pub struct Watchtower {
    config: WatchtowerConfig,
    state: Arc<RwLock<WatchtowerState>>,
    bus: Arc<Bus>,
}

impl Watchtower {
    pub fn new(config: WatchtowerConfig, bus: Arc<Bus>) -> Self {
        let initial_state = if config.enabled {
            WatchtowerState::Loading
        } else {
            WatchtowerState::Disabled
        };

        Self {
            config,
            state: Arc::new(RwLock::new(initial_state)),
            bus,
        }
    }

    pub fn state(&self) -> WatchtowerState {
        self.state.read().clone()
    }

    pub fn initialize(&self) -> Result<(), WatchtowerError> {
        if !self.config.enabled {
            self.emit_unavailable(WatchtowerUnavailableReason::Disabled)?;
            return Ok(());
        }

        if self.config.model_path.is_none() {
            *self.state.write() = WatchtowerState::Unavailable("no model configured".into());
            self.emit_unavailable(WatchtowerUnavailableReason::ModelNotLoaded)?;
            return Err(WatchtowerError::ModelNotLoaded);
        }

        if let (Some(ref path), Some(ref expected_hash)) =
            (&self.config.model_path, &self.config.trusted_model_hash)
        {
            let actual_hash = self.compute_model_hash(path);
            if actual_hash != *expected_hash {
                *self.state.write() =
                    WatchtowerState::Unavailable("model hash mismatch".into());
                self.emit_unavailable(WatchtowerUnavailableReason::ModelHashMismatch)?;
                return Err(WatchtowerError::ModelHashMismatch {
                    expected: expected_hash.clone(),
                    actual: actual_hash,
                });
            }
        }

        *self.state.write() = WatchtowerState::Active;
        tracing::info!("watchtower active");
        Ok(())
    }

    pub fn observe(
        &self,
        projection: &ProjectionResult,
    ) -> Result<Option<WatchtowerObservation>, WatchtowerError> {
        if self.state() != WatchtowerState::Active {
            return Ok(None);
        }

        if projection.event_count == 0 {
            return Ok(None);
        }

        let confidence = (projection.event_count as f64 / 100.0).clamp(0.0, 1.0);

        if confidence < 0.3 {
            return Ok(None);
        }

        let observation = WatchtowerObservation {
            pattern_id: format!("pattern_{}", projection.computed_at.timestamp()),
            description: projection.summary.clone(),
            confidence,
            evidence: vec![],
            timestamp: Utc::now(),
            suggested_action: if confidence > 0.7 {
                SuggestedAction::TriggerFailover
            } else {
                SuggestedAction::IncreaseMonitoring
            },
        };

        self.bus.publish(
            "net.watchtower.observation",
            Message::WatchtowerObservation(observation.clone()),
        )?;

        Ok(Some(observation))
    }

    fn emit_unavailable(
        &self,
        reason: WatchtowerUnavailableReason,
    ) -> Result<(), WatchtowerError> {
        let unavailable = WatchtowerUnavailable {
            reason,
            timestamp: Utc::now(),
        };

        self.bus.publish(
            "net.watchtower.unavailable",
            Message::WatchtowerUnavailable(unavailable),
        )?;

        Ok(())
    }

    fn compute_model_hash(&self, _path: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"placeholder-model-content");
        format!("{:x}", hasher.finalize())
    }

    pub fn is_active(&self) -> bool {
        self.state() == WatchtowerState::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection::ProjectionTask;

    #[test]
    fn disabled_watchtower_stays_disabled() {
        let bus = Arc::new(Bus::new());
        let wt = Watchtower::new(WatchtowerConfig::default(), bus);
        wt.initialize().unwrap();
        assert_eq!(wt.state(), WatchtowerState::Disabled);
        assert!(!wt.is_active());
    }

    #[test]
    fn enabled_without_model_is_unavailable() {
        let bus = Arc::new(Bus::new());
        let config = WatchtowerConfig {
            enabled: true,
            model_path: None,
            ..Default::default()
        };
        let wt = Watchtower::new(config, bus);
        assert!(wt.initialize().is_err());
    }

    #[test]
    fn observation_skipped_when_inactive() {
        let bus = Arc::new(Bus::new());
        let wt = Watchtower::new(WatchtowerConfig::default(), bus);

        let task = ProjectionTask::SummarizeThreatActivity {
            window_start: Utc::now(),
            window_end: Utc::now(),
        };
        let proj = ProjectionResult {
            task,
            summary: "test".into(),
            event_count: 50,
            computed_at: Utc::now(),
        };

        let result = wt.observe(&proj).unwrap();
        assert!(result.is_none());
    }
}
