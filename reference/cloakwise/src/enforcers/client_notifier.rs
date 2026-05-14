//! Client Notifier Enforcer
//!
//! Handles alerting administrators and notifying clients of changes.

use super::{EnforcementResult, Enforcer};
use crate::specialists::Action;
use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tracing::{debug, error, info, warn};

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// An alert record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub timestamp: u64,
    pub severity: AlertSeverity,
    pub message: String,
    pub acknowledged: bool,
}

/// Client notifier enforcer
pub struct ClientNotifier {
    /// Alert history
    alerts: RwLock<VecDeque<Alert>>,
    /// Max alerts to keep
    max_alerts: usize,
    /// Webhook URL for notifications (optional)
    webhook_url: RwLock<Option<String>>,
    /// Admin contact email
    admin_contact: RwLock<Option<String>>,
}

impl ClientNotifier {
    pub fn new() -> Self {
        Self {
            alerts: RwLock::new(VecDeque::new()),
            max_alerts: 100,
            webhook_url: RwLock::new(None),
            admin_contact: RwLock::new(None),
        }
    }

    /// Set webhook URL for alerts
    pub fn set_webhook(&self, url: impl Into<String>) {
        *self.webhook_url.write() = Some(url.into());
    }

    /// Set admin contact
    pub fn set_admin_contact(&self, contact: impl Into<String>) {
        *self.admin_contact.write() = Some(contact.into());
    }

    /// Send an alert
    async fn send_alert(&self, message: &str, severity: AlertSeverity) -> EnforcementResult {
        let alert = Alert {
            timestamp: crate::telemetry::current_timestamp(),
            severity,
            message: message.to_string(),
            acknowledged: false,
        };

        // Store alert
        {
            let mut alerts = self.alerts.write();
            alerts.push_back(alert.clone());
            while alerts.len() > self.max_alerts {
                alerts.pop_front();
            }
        }

        // Log alert
        match severity {
            AlertSeverity::Info => info!("ALERT [INFO]: {}", message),
            AlertSeverity::Warning => warn!("ALERT [WARNING]: {}", message),
            AlertSeverity::Critical => error!("ALERT [CRITICAL]: {}", message),
        }

        // Try to send via webhook (clone URL to avoid holding guard across await)
        let webhook_url = self.webhook_url.read().clone();
        if let Some(url) = webhook_url {
            if let Err(e) = self.send_webhook(&url, &alert).await {
                warn!("Failed to send webhook alert: {}", e);
            }
        }

        EnforcementResult::success(format!("Alert sent: {}", message))
    }

    /// Send alert via webhook
    async fn send_webhook(&self, url: &str, alert: &Alert) -> Result<()> {
        let client = reqwest::Client::new();

        let payload = serde_json::json!({
            "timestamp": alert.timestamp,
            "severity": format!("{:?}", alert.severity),
            "message": alert.message,
            "source": "cloakwise"
        });

        let response = client
            .post(url)
            .json(&payload)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Webhook returned status: {}", response.status());
        }

        debug!("Webhook alert sent successfully");
        Ok(())
    }

    /// Get recent alerts
    pub fn recent_alerts(&self, limit: usize) -> Vec<Alert> {
        let alerts = self.alerts.read();
        alerts.iter().rev().take(limit).cloned().collect()
    }

    /// Get unacknowledged alert count
    pub fn unacknowledged_count(&self) -> usize {
        self.alerts.read().iter().filter(|a| !a.acknowledged).count()
    }

    /// Acknowledge all alerts
    pub fn acknowledge_all(&self) {
        let mut alerts = self.alerts.write();
        for alert in alerts.iter_mut() {
            alert.acknowledged = true;
        }
    }

    /// Clear all alerts
    pub fn clear(&self) {
        self.alerts.write().clear();
    }
}

impl Default for ClientNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Enforcer for ClientNotifier {
    fn can_handle(&self, action: &Action) -> bool {
        matches!(action, Action::AlertAdmin { .. } | Action::EnterSafeMode)
    }

    async fn enforce(&self, action: &Action) -> Result<EnforcementResult> {
        match action {
            Action::AlertAdmin { message } => {
                // Determine severity from message content
                let severity = if message.to_lowercase().contains("critical")
                    || message.to_lowercase().contains("threat")
                    || message.to_lowercase().contains("blocked")
                {
                    AlertSeverity::Critical
                } else if message.to_lowercase().contains("warning")
                    || message.to_lowercase().contains("suspicious")
                    || message.to_lowercase().contains("degraded")
                {
                    AlertSeverity::Warning
                } else {
                    AlertSeverity::Info
                };

                Ok(self.send_alert(message, severity).await)
            }
            Action::EnterSafeMode => {
                // Safe mode is critical
                let result = self
                    .send_alert("Entering SAFE MODE - manual review required", AlertSeverity::Critical)
                    .await;

                // Follow up with profile switch to safe profile
                Ok(result.with_follow_up(Action::SwitchProfile {
                    target: "https_clone".to_string(), // Default safe profile
                }))
            }
            _ => Ok(EnforcementResult::failure(
                "Action not supported by ClientNotifier",
            )),
        }
    }

    async fn rollback(&self, _action: &Action) -> Result<EnforcementResult> {
        // Can't really rollback alerts, just acknowledge
        self.acknowledge_all();
        Ok(EnforcementResult::success("Alerts acknowledged"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_alert_admin() {
        let notifier = ClientNotifier::new();

        let result = notifier
            .enforce(&Action::AlertAdmin {
                message: "Test alert".to_string(),
            })
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(notifier.unacknowledged_count(), 1);
    }

    #[tokio::test]
    async fn test_safe_mode_alert() {
        let notifier = ClientNotifier::new();

        let result = notifier.enforce(&Action::EnterSafeMode).await.unwrap();

        assert!(result.success);
        assert!(result.follow_up.is_some());

        let alerts = notifier.recent_alerts(1);
        assert_eq!(alerts[0].severity, AlertSeverity::Critical);
    }

    #[test]
    fn test_alert_acknowledgment() {
        let notifier = ClientNotifier::new();

        // Add some alerts
        {
            let mut alerts = notifier.alerts.write();
            alerts.push_back(Alert {
                timestamp: 0,
                severity: AlertSeverity::Warning,
                message: "Test".to_string(),
                acknowledged: false,
            });
        }

        assert_eq!(notifier.unacknowledged_count(), 1);

        notifier.acknowledge_all();
        assert_eq!(notifier.unacknowledged_count(), 0);
    }
}
