//! Desktop notifications for the AntiCheat service.

use serde::{Deserialize, Serialize};
use tracing::info;

/// Severity of a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationLevel {
    Info,
    Warning,
    Critical,
}

/// A notification to display to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub title: String,
    pub body: String,
    pub level: NotificationLevel,
}

/// Notification dispatcher. Currently logs to tracing; future versions will
/// integrate with platform-specific notification APIs.
#[derive(Debug, Default, Clone)]
pub struct Notifier;

impl Notifier {
    pub fn new() -> Self {
        Self
    }

    /// Send a notification.
    pub fn notify(&self, n: &Notification) {
        match n.level {
            NotificationLevel::Info => {
                info!(title = %n.title, body = %n.body, "notification: info");
            }
            NotificationLevel::Warning => {
                tracing::warn!(title = %n.title, body = %n.body, "notification: warning");
            }
            NotificationLevel::Critical => {
                tracing::error!(title = %n.title, body = %n.body, "notification: critical");
            }
        }
    }

    /// Convenience: notify about a detected threat.
    pub fn notify_threat(&self, file_path: &str, threat_name: &str) {
        self.notify(&Notification {
            title: "AntiCheat: Threat Detected".to_string(),
            body: format!("{}: {}", threat_name, file_path),
            level: NotificationLevel::Critical,
        });
    }
}
