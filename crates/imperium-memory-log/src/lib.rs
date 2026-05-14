use std::collections::VecDeque;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_bus::Bus;
use imperium_protocol::{BusEvent, Message};
use parking_lot::RwLock;

#[derive(Clone)]
pub struct LogEntry {
    pub event: BusEvent,
    pub logged_at: DateTime<Utc>,
    pub sequence: u64,
}

pub struct MemoryLog {
    entries: RwLock<VecDeque<LogEntry>>,
    next_seq: RwLock<u64>,
    max_entries: usize,
}

impl MemoryLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max_entries)),
            next_seq: RwLock::new(0),
            max_entries,
        }
    }

    pub fn append(&self, event: BusEvent) -> u64 {
        let mut seq = self.next_seq.write();
        let sequence = *seq;
        *seq += 1;

        let entry = LogEntry {
            event,
            logged_at: Utc::now(),
            sequence,
        };

        let mut entries = self.entries.write();
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
        sequence
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    pub fn entries_since(&self, since_seq: u64) -> Vec<LogEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.sequence >= since_seq)
            .cloned()
            .collect()
    }

    pub fn get_by_event_id(&self, event_id: &imperium_protocol::EventId) -> Option<LogEntry> {
        self.entries
            .read()
            .iter()
            .find(|e| e.event.id.0 == event_id.0)
            .cloned()
    }
}

impl MemoryLog {
    pub fn subscribe_strainer_rejections(
        self: &Arc<Self>,
        bus: &Bus,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = bus.subscribe("net.strainer.rejection");
        let log = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if matches!(event.message, Message::StrainerRejection(_)) {
                            log.append(event);
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }

    pub fn subscribe_protocol_events(
        self: &Arc<Self>,
        bus: &Bus,
    ) -> tokio::task::JoinHandle<()> {
        let mut sub = bus.subscribe("net.transport.");
        let log = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match sub.recv().await {
                    Ok(event) => {
                        if matches!(event.message, Message::ProtocolEvt(_)) {
                            log.append(event);
                        }
                    }
                    Err(imperium_bus::BusError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
    }
}

impl Default for MemoryLog {
    fn default() -> Self {
        Self::new(100_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_protocol::{EmergencyShutdown, Message};
    use std::sync::Arc;
    use std::thread;

    fn make_event(topic: &str) -> BusEvent {
        BusEvent::new(
            topic.to_string(),
            Message::EmergencyShutdown(EmergencyShutdown {
                reason: "test".into(),
                triggered_at: Utc::now(),
                active_protocol: None,
                standby_protocol: None,
            }),
        )
    }

    #[test]
    fn append_returns_monotonic_sequences() {
        let log = MemoryLog::new(100);
        let s0 = log.append(make_event("a"));
        let s1 = log.append(make_event("b"));
        let s2 = log.append(make_event("c"));
        assert_eq!(s0, 0);
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
    }

    #[test]
    fn len_and_is_empty() {
        let log = MemoryLog::new(100);
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        log.append(make_event("x"));
        assert!(!log.is_empty());
        assert_eq!(log.len(), 1);
    }

    fn seqs(entries: &[LogEntry]) -> Vec<u64> {
        entries.iter().map(|e| e.sequence).collect()
    }

    #[test]
    fn overflow_evicts_oldest() {
        let log = MemoryLog::new(3);
        let _s0 = log.append(make_event("a"));
        let _s1 = log.append(make_event("b"));
        let _s2 = log.append(make_event("c"));
        assert_eq!(log.len(), 3);

        let _s3 = log.append(make_event("d"));
        assert_eq!(log.len(), 3);

        let entries = log.entries_since(0);
        assert_eq!(seqs(&entries), vec![1, 2, 3]);
    }

    #[test]
    fn entries_since_filters_correctly() {
        let log = MemoryLog::new(100);
        for _ in 0..5 {
            log.append(make_event("t"));
        }
        assert_eq!(seqs(&log.entries_since(3)), vec![3, 4]);
        assert_eq!(seqs(&log.entries_since(0)), vec![0, 1, 2, 3, 4]);
        assert!(log.entries_since(100).is_empty());
    }

    #[test]
    fn entries_since_on_empty_log() {
        let log = MemoryLog::new(100);
        assert!(log.entries_since(0).is_empty());
    }

    #[test]
    fn entries_since_returns_full_entries() {
        let log = MemoryLog::new(100);
        log.append(make_event("topic.a"));
        log.append(make_event("topic.b"));

        let entries = log.entries_since(0);
        assert_eq!(entries.len(), 2);
        assert_eq!(&*entries[0].event.topic, "topic.a");
        assert_eq!(&*entries[1].event.topic, "topic.b");
        assert_eq!(entries[0].sequence, 0);
        assert_eq!(entries[1].sequence, 1);
    }

    #[test]
    fn entries_since_releases_lock() {
        let log = MemoryLog::new(100);
        log.append(make_event("first"));

        let entries = log.entries_since(0);
        assert_eq!(entries.len(), 1);

        // If the lock were held, this append would deadlock
        log.append(make_event("second"));
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn default_capacity() {
        let log = MemoryLog::default();
        assert_eq!(log.max_entries, 100_000);
        assert!(log.is_empty());
    }

    #[test]
    fn logged_at_is_populated() {
        let log = MemoryLog::new(10);
        let before = Utc::now();
        log.append(make_event("t"));
        let after = Utc::now();

        let entries = log.entries.read();
        let entry = &entries[0];
        assert!(entry.logged_at >= before);
        assert!(entry.logged_at <= after);
    }

    #[test]
    fn event_content_preserved() {
        let log = MemoryLog::new(10);
        log.append(make_event("my.topic"));

        let entries = log.entries.read();
        let entry = &entries[0];
        assert_eq!(&*entry.event.topic, "my.topic");
        match &entry.event.message {
            Message::EmergencyShutdown(es) => {
                assert_eq!(es.reason, "test");
            }
            other => panic!("unexpected message variant: {:?}", other),
        }
    }

    #[test]
    fn concurrent_appends_no_sequence_collision() {
        let log = Arc::new(MemoryLog::new(10_000));
        let mut handles = vec![];

        for _ in 0..4 {
            let log = Arc::clone(&log);
            handles.push(thread::spawn(move || {
                let mut seqs = vec![];
                for _ in 0..250 {
                    seqs.push(log.append(make_event("concurrent")));
                }
                seqs
            }));
        }

        let mut all_seqs: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        all_seqs.sort();
        all_seqs.dedup();
        assert_eq!(all_seqs.len(), 1000, "all sequences must be unique");
        assert_eq!(log.len(), 1000);
    }

    #[test]
    fn overflow_under_concurrency() {
        let log = Arc::new(MemoryLog::new(50));
        let mut handles = vec![];

        for _ in 0..4 {
            let log = Arc::clone(&log);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    log.append(make_event("flood"));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(log.len(), 50, "capacity must be respected under concurrency");
    }

    #[test]
    fn get_by_event_id_returns_matching_entry() {
        let log = MemoryLog::new(100);
        let event = make_event("test.topic");
        let target_id = event.id.clone();
        log.append(make_event("other"));
        log.append(event);
        log.append(make_event("other2"));

        let found = log.get_by_event_id(&target_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().event.id.0, target_id.0);

        let missing = log.get_by_event_id(&imperium_protocol::EventId::new());
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn subscribe_strainer_rejections_records_events() {
        use imperium_protocol::StrainerRejection;

        let bus = Arc::new(Bus::new());
        let log = Arc::new(MemoryLog::new(100));

        let _handle = log.subscribe_strainer_rejections(&bus);

        bus.publish(
            "net.strainer.rejection",
            Message::StrainerRejection(StrainerRejection {
                strainer_id: "timing".into(),
                stack_id: "xray_stack".into(),
                shape_failed: "too slow".into(),
                source_identifier: None,
                timestamp: Utc::now(),
            }),
        ).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(log.len(), 1);
        let entries = log.entries_since(0);
        assert!(matches!(entries[0].event.message, Message::StrainerRejection(_)));
    }

    #[tokio::test]
    async fn subscribe_protocol_events_records_events() {
        use imperium_protocol::{ProtocolEvent, ProtocolEventKind, ProtocolRole, ProtocolStatus};

        let bus = Arc::new(Bus::new());
        let log = Arc::new(MemoryLog::new(100));

        let _handle = log.subscribe_protocol_events(&bus);

        bus.publish(
            "net.transport.event",
            Message::ProtocolEvt(ProtocolEvent {
                protocol_name: "xray".into(),
                role: ProtocolRole::Active,
                status: ProtocolStatus::Running,
                event: ProtocolEventKind::Started,
                timestamp: Utc::now(),
            }),
        ).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(log.len(), 1);
        let entries = log.entries_since(0);
        assert!(matches!(entries[0].event.message, Message::ProtocolEvt(_)));
    }
}
