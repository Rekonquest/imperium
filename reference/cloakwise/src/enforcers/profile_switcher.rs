//! Profile Switcher Enforcer
//!
//! Handles switching traffic profiles.

use super::{EnforcementResult, Enforcer};
use crate::specialists::Action;
use crate::vpn::{TrafficProfile, VpnManager};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Profile switcher enforcer
pub struct ProfileSwitcher {
    vpn_manager: Arc<VpnManager>,
    /// Shared with the UI and orchestrator so API-generated profiles are visible here.
    profiles: Arc<parking_lot::RwLock<HashMap<String, TrafficProfile>>>,
    current_profile: parking_lot::RwLock<Option<String>>,
}

impl ProfileSwitcher {
    pub fn new(
        vpn_manager: Arc<VpnManager>,
        profiles: Arc<parking_lot::RwLock<HashMap<String, TrafficProfile>>>,
    ) -> Self {
        Self {
            vpn_manager,
            profiles,
            current_profile: parking_lot::RwLock::new(None),
        }
    }

    /// Get a profile by ID
    pub fn get_profile(&self, id: &str) -> Option<TrafficProfile> {
        self.profiles.read().get(id).cloned()
    }

    /// Get current profile ID
    pub fn current(&self) -> Option<String> {
        self.current_profile.read().clone()
    }

    /// Switch to a specific profile
    async fn switch_to(&self, target: &str) -> Result<EnforcementResult> {
        let profile = self
            .profiles
            .read()
            .get(target)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Profile not found: {}", target))?;

        info!("Switching to profile: {} ({})", target, profile.description());

        match self.vpn_manager.switch_profile(&profile).await {
            Ok(()) => {
                *self.current_profile.write() = Some(target.to_string());
                Ok(EnforcementResult::success(format!(
                    "Switched to profile: {}",
                    target
                )))
            }
            Err(e) => {
                error!("Failed to switch profile: {}", e);
                Ok(EnforcementResult::failure(format!(
                    "Failed to switch to {}: {}",
                    target, e
                )))
            }
        }
    }

    /// Rotate to the next profile in a predefined sequence
    async fn rotate(&self, rotation_order: &[String]) -> Result<EnforcementResult> {
        let current = self.current_profile.read().clone();

        let next_idx = if let Some(ref curr) = current {
            let curr_idx = rotation_order.iter().position(|p| p == curr).unwrap_or(0);
            (curr_idx + 1) % rotation_order.len()
        } else {
            0
        };

        let next_profile = &rotation_order[next_idx];
        info!("Rotating profile: {:?} -> {}", current, next_profile);

        self.switch_to(next_profile).await
    }
}

#[async_trait]
impl Enforcer for ProfileSwitcher {
    fn can_handle(&self, action: &Action) -> bool {
        matches!(action, Action::SwitchProfile { .. } | Action::RotateProfile)
    }

    async fn enforce(&self, action: &Action) -> Result<EnforcementResult> {
        match action {
            Action::SwitchProfile { target } => self.switch_to(target).await,
            Action::RotateProfile => {
                let order: Vec<String> = self.profiles.read().keys().cloned().collect();
                if order.is_empty() {
                    Ok(EnforcementResult::failure("No profiles available for rotation"))
                } else {
                    self.rotate(&order).await
                }
            }
            _ => Ok(EnforcementResult::failure("Action not supported by ProfileSwitcher")),
        }
    }

    async fn rollback(&self, action: &Action) -> Result<EnforcementResult> {
        // Can't really rollback a profile switch, but we could switch to safe mode
        warn!("Profile switch rollback requested - switching to first available profile");

        let first_key = self.profiles.read().keys().next().cloned();
        if let Some(ref profile) = first_key {
            self.switch_to(profile).await
        } else {
            Ok(EnforcementResult::failure("No profiles available for rollback"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::ProfileTemplates;

    #[test]
    fn test_shared_profiles() {
        let manager = Arc::new(VpnManager::new());
        let store = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        for p in ProfileTemplates::all() {
            store.write().insert(p.id.clone(), p);
        }
        let switcher = ProfileSwitcher::new(manager, store);

        assert!(switcher.get_profile("https_clone").is_some());
        assert!(switcher.get_profile("video_call").is_some());
    }

    #[test]
    fn test_can_handle() {
        let manager = Arc::new(VpnManager::new());
        let store = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let switcher = ProfileSwitcher::new(manager, store);

        assert!(switcher.can_handle(&Action::SwitchProfile {
            target: "test".to_string()
        }));
        assert!(switcher.can_handle(&Action::RotateProfile));
        assert!(!switcher.can_handle(&Action::AlertAdmin {
            message: "test".to_string()
        }));
    }
}
