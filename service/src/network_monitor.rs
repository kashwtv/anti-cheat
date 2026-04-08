use tokio::task::JoinHandle;
use tracing::info;

/// Network connection monitor (stub).
///
/// Future versions will integrate with OS APIs to monitor
/// outbound connections and detect suspicious network activity.
pub struct NetworkMonitor;

impl NetworkMonitor {
    /// Start the network monitor in a background task.
    pub fn start(
        mut shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("network monitor starting (stub - monitoring not yet implemented)");

            // Wait for shutdown signal
            let _ = shutdown.recv().await;
            info!("network monitor shutting down");
        })
    }
}
