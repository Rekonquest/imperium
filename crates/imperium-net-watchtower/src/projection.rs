use chrono::{DateTime, Utc};
use imperium_protocol::EventId;

#[derive(Clone, Debug)]
pub enum ProjectionTask {
    ClassifyPatternAround {
        event_id: EventId,
    },
    SummarizeThreatActivity {
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    },
    ListEpisodesMatchingTrigger {
        trigger_pattern: String,
    },
    CorrelateSourceActivity {
        source_id: String,
    },
}

#[derive(Clone, Debug)]
pub struct ProjectionResult {
    pub task: ProjectionTask,
    pub summary: String,
    pub event_count: usize,
    pub computed_at: DateTime<Utc>,
}

impl ProjectionResult {
    pub fn empty(task: ProjectionTask) -> Self {
        Self {
            task,
            summary: String::new(),
            event_count: 0,
            computed_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_projection_result() {
        let task = ProjectionTask::SummarizeThreatActivity {
            window_start: Utc::now(),
            window_end: Utc::now(),
        };
        let result = ProjectionResult::empty(task);
        assert_eq!(result.event_count, 0);
        assert!(result.summary.is_empty());
    }
}
