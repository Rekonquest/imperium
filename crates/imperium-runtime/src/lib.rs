use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use imperium_bus::Bus;
use imperium_protocol::Message;
use imperium_secrets_vault::Vault;
use tokio::sync::Notify;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("subsystem failed to initialize: {0}")]
    InitFailed(String),
    #[error("subsystem already registered: {0}")]
    AlreadyRegistered(String),
    #[error("shutdown error in subsystem '{0}': {1}")]
    ShutdownFailed(String, String),
    #[error("shutdown timed out after {0:?}")]
    ShutdownTimeout(Duration),
}

#[async_trait]
pub trait Subsystem: Send + Sync {
    fn name(&self) -> &str;
    async fn init(&self, bus: Arc<Bus>) -> Result<(), RuntimeError>;
    async fn shutdown(&self) -> Result<(), RuntimeError>;
}

pub struct Runtime {
    bus: Arc<Bus>,
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            bus: Arc::new(Bus::new()),
        }
    }

    pub fn bus(&self) -> Arc<Bus> {
        Arc::clone(&self.bus)
    }

    pub async fn register(&self, subsystem: &dyn Subsystem) -> Result<(), RuntimeError> {
        subsystem.init(Arc::clone(&self.bus)).await?;
        self.bus
            .publish(
                format!("runtime.subsystem.ready.{}", subsystem.name()),
                Message::SubsystemReady {
                    name: subsystem.name().to_string(),
                },
            )
            .map_err(|e| RuntimeError::InitFailed(e.to_string()))?;
        tracing::info!(subsystem = subsystem.name(), "subsystem registered");
        Ok(())
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub enum ShutdownReason {
    EmergencyShutdown { reason: String },
    Signal,
    Manual,
}

pub struct RuntimeCoordinator {
    bus: Arc<Bus>,
    subsystems: Vec<Arc<dyn Subsystem>>,
    shutdown_timeout: Duration,
    shutdown_notify: Arc<Notify>,
    vault: Option<Arc<Mutex<Vault>>>,
}

impl RuntimeCoordinator {
    pub fn new() -> Self {
        Self {
            bus: Arc::new(Bus::new()),
            subsystems: Vec::new(),
            shutdown_timeout: Duration::from_secs(10),
            shutdown_notify: Arc::new(Notify::new()),
            vault: None,
        }
    }

    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    pub fn with_vault(mut self, vault: Arc<Mutex<Vault>>) -> Self {
        self.vault = Some(vault);
        self
    }

    pub fn bus(&self) -> Arc<Bus> {
        Arc::clone(&self.bus)
    }

    pub fn shutdown_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.shutdown_notify)
    }

    pub fn subsystem_count(&self) -> usize {
        self.subsystems.len()
    }

    pub async fn register(&mut self, subsystem: Arc<dyn Subsystem>) -> Result<(), RuntimeError> {
        let name = subsystem.name().to_string();

        if self.subsystems.iter().any(|s| s.name() == name) {
            return Err(RuntimeError::AlreadyRegistered(name));
        }

        subsystem.init(Arc::clone(&self.bus)).await?;
        self.bus
            .publish(
                format!("runtime.subsystem.ready.{}", name),
                Message::SubsystemReady {
                    name: name.clone(),
                },
            )
            .map_err(|e| RuntimeError::InitFailed(e.to_string()))?;

        tracing::info!(subsystem = %name, "subsystem registered");
        self.subsystems.push(subsystem);
        Ok(())
    }

    pub async fn shutdown_all(&self) -> Vec<(String, Result<(), RuntimeError>)> {
        if let Some(vault) = &self.vault {
            match vault.lock() {
                Ok(mut v) => {
                    v.seal();
                    tracing::info!("vault sealed");
                }
                Err(_) => {
                    tracing::error!("vault mutex poisoned, cannot seal — continuing shutdown");
                }
            }
        }

        let mut results = Vec::new();

        for subsystem in self.subsystems.iter().rev() {
            let name = subsystem.name().to_string();
            let sub = Arc::clone(subsystem);
            let timeout = self.shutdown_timeout;

            let result = tokio::time::timeout(timeout, sub.shutdown()).await;

            match result {
                Ok(Ok(())) => {
                    tracing::info!(subsystem = %name, "subsystem shut down");
                    results.push((name, Ok(())));
                }
                Ok(Err(e)) => {
                    tracing::error!(subsystem = %name, error = %e, "subsystem shutdown failed");
                    results.push((name, Err(e)));
                }
                Err(_) => {
                    tracing::error!(subsystem = %name, "subsystem shutdown timed out");
                    results.push((name, Err(RuntimeError::ShutdownTimeout(timeout))));
                }
            }
        }

        results
    }

    pub async fn run(&self) -> ShutdownReason {
        let mut emergency_sub = self.bus.subscribe("emergency");
        let notify = Arc::clone(&self.shutdown_notify);

        let reason = tokio::select! {
            event = emergency_sub.recv() => {
                match event {
                    Ok(e) => {
                        let reason_text = match &e.message {
                            Message::EmergencyShutdown(es) => es.reason.clone(),
                            _ => "unknown".to_string(),
                        };
                        tracing::warn!(reason = %reason_text, "emergency shutdown received");
                        ShutdownReason::EmergencyShutdown { reason: reason_text }
                    }
                    Err(_) => ShutdownReason::EmergencyShutdown { reason: "bus closed".into() },
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received SIGINT/SIGTERM, initiating shutdown");
                ShutdownReason::Signal
            }
            _ = notify.notified() => {
                tracing::info!("manual shutdown requested");
                ShutdownReason::Manual
            }
        };

        self.shutdown_all().await;
        reason
    }

    pub fn subsystem_names(&self) -> Vec<String> {
        self.subsystems.iter().map(|s| s.name().to_string()).collect()
    }
}

impl Default for RuntimeCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_protocol::EmergencyShutdown;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct GoodSubsystem;

    #[async_trait]
    impl Subsystem for GoodSubsystem {
        fn name(&self) -> &str {
            "good"
        }
        async fn init(&self, _bus: Arc<Bus>) -> Result<(), RuntimeError> {
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), RuntimeError> {
            Ok(())
        }
    }

    struct FailingSubsystem;

    #[async_trait]
    impl Subsystem for FailingSubsystem {
        fn name(&self) -> &str {
            "failing"
        }
        async fn init(&self, _bus: Arc<Bus>) -> Result<(), RuntimeError> {
            Err(RuntimeError::InitFailed("intentional".into()))
        }
        async fn shutdown(&self) -> Result<(), RuntimeError> {
            Ok(())
        }
    }

    struct BusPublishingSubsystem;

    #[async_trait]
    impl Subsystem for BusPublishingSubsystem {
        fn name(&self) -> &str {
            "publisher"
        }
        async fn init(&self, bus: Arc<Bus>) -> Result<(), RuntimeError> {
            bus.publish(
                "custom.init",
                Message::SubsystemReady {
                    name: "from-init".into(),
                },
            )
            .map_err(|e| RuntimeError::InitFailed(e.to_string()))?;
            Ok(())
        }
        async fn shutdown(&self) -> Result<(), RuntimeError> {
            Ok(())
        }
    }

    // --- Original Runtime tests ---

    #[tokio::test]
    async fn register_publishes_ready_event() {
        let rt = Runtime::new();
        let mut sub = rt.bus().subscribe("runtime.subsystem.ready");

        let result = rt.register(&GoodSubsystem).await;
        assert!(result.is_ok());

        let event = tokio::time::timeout(
            Duration::from_millis(100),
            sub.recv(),
        )
        .await
        .expect("timed out")
        .expect("recv failed");

        assert_eq!(&*event.topic, "runtime.subsystem.ready.good");
    }

    #[tokio::test]
    async fn register_failing_subsystem_returns_error() {
        let rt = Runtime::new();
        let result = rt.register(&FailingSubsystem).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            RuntimeError::InitFailed(msg) => assert_eq!(msg, "intentional"),
            other => panic!("wrong error variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn failing_register_does_not_publish_ready() {
        let rt = Runtime::new();
        let mut sub = rt.bus().subscribe_all();

        let _ = rt.register(&FailingSubsystem).await;

        let result = tokio::time::timeout(
            Duration::from_millis(50),
            sub.recv(),
        )
        .await;
        assert!(result.is_err(), "no event should be published on init failure");
    }

    #[tokio::test]
    async fn subsystem_receives_bus_during_init() {
        let rt = Runtime::new();
        let mut sub = rt.bus().subscribe("custom.");

        rt.register(&BusPublishingSubsystem).await.unwrap();

        let event = tokio::time::timeout(
            Duration::from_millis(100),
            sub.recv(),
        )
        .await
        .expect("timed out")
        .expect("recv failed");

        assert_eq!(&*event.topic, "custom.init");
    }

    #[tokio::test]
    async fn multiple_subsystems_register() {
        let rt = Runtime::new();
        let mut sub = rt.bus().subscribe("runtime.subsystem.ready");

        rt.register(&GoodSubsystem).await.unwrap();
        rt.register(&BusPublishingSubsystem).await.unwrap();

        let e1 = tokio::time::timeout(
            Duration::from_millis(100),
            sub.recv(),
        )
        .await
        .unwrap()
        .unwrap();

        let e2 = tokio::time::timeout(
            Duration::from_millis(100),
            sub.recv(),
        )
        .await
        .unwrap()
        .unwrap();

        let topics: Vec<String> = vec![e1.topic.to_string(), e2.topic.to_string()];
        assert!(topics.contains(&"runtime.subsystem.ready.good".to_string()));
        assert!(topics.contains(&"runtime.subsystem.ready.publisher".to_string()));
    }

    #[test]
    fn default_runtime_creates_bus() {
        let rt = Runtime::default();
        let _ = rt.bus();
    }

    #[tokio::test]
    async fn bus_is_shared_across_clones() {
        let rt = Runtime::new();
        let bus1 = rt.bus();
        let bus2 = rt.bus();
        assert!(Arc::ptr_eq(&bus1, &bus2));
    }

    // --- RuntimeCoordinator tests ---

    #[tokio::test]
    async fn coordinator_register_and_count() {
        let mut coord = RuntimeCoordinator::new();
        assert_eq!(coord.subsystem_count(), 0);
        coord.register(Arc::new(GoodSubsystem)).await.unwrap();
        assert_eq!(coord.subsystem_count(), 1);
        assert_eq!(coord.subsystem_names(), vec!["good"]);
    }

    #[tokio::test]
    async fn coordinator_rejects_duplicate_name() {
        let mut coord = RuntimeCoordinator::new();
        coord.register(Arc::new(GoodSubsystem)).await.unwrap();
        let err = coord.register(Arc::new(GoodSubsystem)).await.unwrap_err();
        assert!(matches!(err, RuntimeError::AlreadyRegistered(name) if name == "good"));
    }

    #[tokio::test]
    async fn coordinator_shutdown_reverse_order() {
        static ORDER: AtomicU32 = AtomicU32::new(0);

        struct OrderedSub {
            name: &'static str,
            expected_position: u32,
        }

        #[async_trait]
        impl Subsystem for OrderedSub {
            fn name(&self) -> &str {
                self.name
            }
            async fn init(&self, _bus: Arc<Bus>) -> Result<(), RuntimeError> {
                Ok(())
            }
            async fn shutdown(&self) -> Result<(), RuntimeError> {
                let pos = ORDER.fetch_add(1, Ordering::SeqCst);
                assert_eq!(pos, self.expected_position, "subsystem {} shut down out of order", self.name);
                Ok(())
            }
        }

        ORDER.store(0, Ordering::SeqCst);

        let mut coord = RuntimeCoordinator::new();
        // Registered in order: alpha(0), beta(1), gamma(2)
        // Shutdown reverse: gamma(0), beta(1), alpha(2)
        coord.register(Arc::new(OrderedSub { name: "alpha", expected_position: 2 })).await.unwrap();
        coord.register(Arc::new(OrderedSub { name: "beta", expected_position: 1 })).await.unwrap();
        coord.register(Arc::new(OrderedSub { name: "gamma", expected_position: 0 })).await.unwrap();

        let results = coord.shutdown_all().await;
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, "gamma");
        assert_eq!(results[1].0, "beta");
        assert_eq!(results[2].0, "alpha");
        assert!(results.iter().all(|(_, r)| r.is_ok()));
    }

    #[tokio::test]
    async fn coordinator_emergency_shutdown_triggers_run_exit() {
        let mut coord = RuntimeCoordinator::new();
        coord.register(Arc::new(GoodSubsystem)).await.unwrap();

        let bus = coord.bus();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            bus.publish(
                "emergency.shutdown",
                Message::EmergencyShutdown(EmergencyShutdown {
                    reason: "test trigger".into(),
                    triggered_at: chrono::Utc::now(),
                    active_protocol: None,
                    standby_protocol: None,
                }),
            )
            .unwrap();
        });

        let reason = coord.run().await;
        match reason {
            ShutdownReason::EmergencyShutdown { reason } => {
                assert_eq!(reason, "test trigger");
            }
            other => panic!("expected EmergencyShutdown, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn coordinator_manual_shutdown_via_notify() {
        let mut coord = RuntimeCoordinator::new();
        coord.register(Arc::new(GoodSubsystem)).await.unwrap();

        let notify = coord.shutdown_notify();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            notify.notify_one();
        });

        let reason = coord.run().await;
        assert!(matches!(reason, ShutdownReason::Manual));
    }

    #[tokio::test]
    async fn coordinator_shutdown_timeout_enforcement() {
        struct SlowSubsystem;

        #[async_trait]
        impl Subsystem for SlowSubsystem {
            fn name(&self) -> &str {
                "slow"
            }
            async fn init(&self, _bus: Arc<Bus>) -> Result<(), RuntimeError> {
                Ok(())
            }
            async fn shutdown(&self) -> Result<(), RuntimeError> {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(())
            }
        }

        let mut coord = RuntimeCoordinator::new()
            .with_shutdown_timeout(Duration::from_millis(100));
        coord.register(Arc::new(SlowSubsystem)).await.unwrap();

        let results = coord.shutdown_all().await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "slow");
        assert!(matches!(&results[0].1, Err(RuntimeError::ShutdownTimeout(_))));
    }

    #[tokio::test]
    async fn coordinator_publishes_ready_events() {
        let mut coord = RuntimeCoordinator::new();
        let mut sub = coord.bus().subscribe("runtime.subsystem.ready");

        coord.register(Arc::new(GoodSubsystem)).await.unwrap();

        let event = tokio::time::timeout(Duration::from_millis(100), sub.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&*event.topic, "runtime.subsystem.ready.good");
    }

    #[tokio::test]
    async fn coordinator_failed_init_not_added() {
        let mut coord = RuntimeCoordinator::new();
        let _ = coord.register(Arc::new(FailingSubsystem)).await;
        assert_eq!(coord.subsystem_count(), 0);
    }

    #[tokio::test]
    async fn coordinator_shutdown_seals_vault() {
        let vault = Arc::new(Mutex::new(Vault::new(imperium_store::Store::in_memory())));
        assert!(!vault.lock().unwrap().is_sealed());

        let mut coord = RuntimeCoordinator::new()
            .with_vault(Arc::clone(&vault));
        coord.register(Arc::new(GoodSubsystem)).await.unwrap();

        coord.shutdown_all().await;
        assert!(vault.lock().unwrap().is_sealed());
    }

    #[tokio::test]
    async fn coordinator_shutdown_without_vault_does_not_panic() {
        let mut coord = RuntimeCoordinator::new();
        coord.register(Arc::new(GoodSubsystem)).await.unwrap();

        let results = coord.shutdown_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok());
    }

    #[tokio::test]
    async fn coordinator_shutdown_continues_when_vault_mutex_poisoned() {
        let vault = Arc::new(Mutex::new(Vault::new(imperium_store::Store::in_memory())));
        let vault_clone = Arc::clone(&vault);

        let _ = std::thread::spawn(move || {
            let _guard = vault_clone.lock().unwrap();
            panic!("intentional poison");
        })
        .join();

        assert!(vault.lock().is_err(), "mutex should be poisoned");

        let mut coord = RuntimeCoordinator::new()
            .with_vault(Arc::clone(&vault));
        coord.register(Arc::new(GoodSubsystem)).await.unwrap();

        let results = coord.shutdown_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok(), "subsystem shutdown must succeed even with poisoned vault");
    }
}
