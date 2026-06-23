use std::collections::HashMap;
use std::sync::Arc;

use imperium_protocol::{BusEvent, Message};
use parking_lot::RwLock;
use tokio::sync::broadcast;

const DEFAULT_CAPACITY: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum BusError {
    #[error("no active subscribers on topic")]
    NoSubscribers,
    #[error("subscription lagged by {0} messages")]
    Lagged(u64),
    #[error("bus channel closed")]
    Closed,
}

struct TopicChannel {
    tx: broadcast::Sender<BusEvent>,
}

pub struct Bus {
    global_tx: broadcast::Sender<BusEvent>,
    topics: Arc<RwLock<HashMap<String, TopicChannel>>>,
}

impl Bus {
    pub fn new() -> Self {
        let (global_tx, _) = broadcast::channel(DEFAULT_CAPACITY);
        Self {
            global_tx,
            topics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let (global_tx, _) = broadcast::channel(capacity);
        Self {
            global_tx,
            topics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn publish(&self, topic: impl Into<Arc<str>>, message: Message) -> Result<(), BusError> {
        let event = BusEvent::new(topic, message);
        let topic_key = event.topic.to_string();

        // Always send on the global channel
        let _ = self.global_tx.send(event.clone());

        // Send on topic-specific channel if it exists
        let topics = self.topics.read();
        if let Some(ch) = topics.get(&topic_key) {
            let _ = ch.tx.send(event);
        }

        Ok(())
    }

    pub fn subscribe_all(&self) -> BusSubscription {
        BusSubscription {
            rx: self.global_tx.subscribe(),
            topic_prefix: None,
        }
    }

    pub fn subscribe(&self, topic_prefix: &str) -> BusSubscription {
        let prefix = topic_prefix.to_string();

        // Ensure topic channel exists
        {
            let mut topics = self.topics.write();
            topics.entry(prefix.clone()).or_insert_with(|| {
                let (tx, _) = broadcast::channel(DEFAULT_CAPACITY);
                TopicChannel { tx }
            });
        }

        BusSubscription {
            rx: self.global_tx.subscribe(),
            topic_prefix: Some(prefix),
        }
    }
}

impl Default for Bus {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BusSubscription {
    rx: broadcast::Receiver<BusEvent>,
    topic_prefix: Option<String>,
}

impl BusSubscription {
    pub async fn recv(&mut self) -> Result<BusEvent, BusError> {
        loop {
            match self.rx.recv().await {
                Ok(event) => {
                    if let Some(ref prefix) = self.topic_prefix {
                        if event.topic.starts_with(prefix.as_str()) {
                            return Ok(event);
                        }
                        continue;
                    }
                    return Ok(event);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(lagged = n, "bus subscription lagged");
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(BusError::Closed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_and_receive() {
        let bus = Bus::new();
        let mut sub = bus.subscribe_all();

        bus.publish(
            "test.hello",
            Message::SubsystemReady {
                name: "test".into(),
            },
        )
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_millis(100), sub.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&*event.topic, "test.hello");
    }

    #[tokio::test]
    async fn topic_filter() {
        let bus = Bus::new();
        let mut sub = bus.subscribe("net.");

        bus.publish("ui.update", Message::SubsystemReady { name: "ui".into() })
            .unwrap();

        bus.publish(
            "net.cluster.ready",
            Message::SubsystemReady {
                name: "cluster".into(),
            },
        )
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_millis(100), sub.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(&*event.topic, "net.cluster.ready");
    }
}
