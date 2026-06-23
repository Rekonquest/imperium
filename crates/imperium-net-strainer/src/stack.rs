use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use imperium_bus::Bus;
use imperium_protocol::{Message, StrainerRejection};
use parking_lot::RwLock;

use crate::{Strainer, StrainerInput, StrainerOutput};

pub struct StrainerStack {
    name: String,
    protocol_context: String,
    stages: Vec<Arc<dyn Strainer>>,
    bus: Option<Arc<Bus>>,
}

impl StrainerStack {
    pub fn new(name: impl Into<String>, protocol_context: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            protocol_context: protocol_context.into(),
            stages: Vec::new(),
            bus: None,
        }
    }

    pub fn with_bus(mut self, bus: Arc<Bus>) -> Self {
        self.bus = Some(bus);
        self
    }

    pub fn add_stage(&mut self, strainer: Arc<dyn Strainer>) {
        self.stages.push(strainer);
    }

    pub fn apply(&self, input: StrainerInput) -> StrainerOutput {
        let mut current_data = input.data.clone();

        for stage in &self.stages {
            let stage_input = StrainerInput {
                data: current_data,
                source: input.source,
                context: input.context.clone(),
                timestamp: input.timestamp,
            };

            match stage.apply(stage_input) {
                StrainerOutput::Passed(data) => {
                    current_data = data;
                }
                StrainerOutput::Degraded { data, method } => {
                    current_data = data;
                    tracing::debug!(
                        strainer = stage.id(),
                        method = %method,
                        "strainer degraded response"
                    );
                }
                StrainerOutput::Rejected { reason } => {
                    self.emit_rejection(stage.id(), &reason, input.source);
                    return StrainerOutput::Rejected { reason };
                }
            }
        }

        StrainerOutput::Passed(current_data)
    }

    fn emit_rejection(
        &self,
        strainer_id: &str,
        reason: &str,
        source: Option<std::net::SocketAddr>,
    ) {
        if let Some(ref bus) = self.bus {
            let rejection = StrainerRejection {
                strainer_id: strainer_id.to_string(),
                stack_id: self.name.clone(),
                shape_failed: reason.to_string(),
                source_identifier: source,
                timestamp: Utc::now(),
            };

            let _ = bus.publish(
                "net.strainer.rejection",
                Message::StrainerRejection(rejection),
            );
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn protocol_context(&self) -> &str {
        &self.protocol_context
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

pub struct StrainerRegistry {
    strainers: Arc<RwLock<HashMap<String, Arc<dyn Strainer>>>>,
}

impl StrainerRegistry {
    pub fn new() -> Self {
        Self {
            strainers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register(&self, strainer: Arc<dyn Strainer>) {
        self.strainers
            .write()
            .insert(strainer.id().to_string(), strainer);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Strainer>> {
        self.strainers.read().get(id).cloned()
    }

    pub fn build_stack(
        &self,
        name: impl Into<String>,
        protocol_context: impl Into<String>,
        stage_ids: &[&str],
    ) -> Option<StrainerStack> {
        let mut stack = StrainerStack::new(name, protocol_context);

        for id in stage_ids {
            let strainer = self.get(id)?;
            stack.add_stage(strainer);
        }

        Some(stack)
    }
}

impl Default for StrainerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strainers::TruncationStrainer;

    #[test]
    fn stack_applies_stages_in_order() {
        let trunc = Arc::new(TruncationStrainer::new(10));
        let mut stack = StrainerStack::new("test_stack", "test");
        stack.add_stage(trunc);

        let input = StrainerInput {
            data: vec![0u8; 20],
            source: None,
            context: HashMap::new(),
            timestamp: Utc::now(),
        };

        let output = stack.apply(input);
        assert!(output.is_passed());
        assert_eq!(output.data().unwrap().len(), 10);
    }

    #[test]
    fn registry_builds_stack() {
        let registry = StrainerRegistry::new();
        registry.register(Arc::new(TruncationStrainer::new(10)));

        let stack = registry.build_stack("test", "proto", &["truncation"]);
        assert!(stack.is_some());
        assert_eq!(stack.unwrap().stage_count(), 1);
    }

    #[test]
    fn registry_missing_strainer_returns_none() {
        let registry = StrainerRegistry::new();
        let stack = registry.build_stack("test", "proto", &["nonexistent"]);
        assert!(stack.is_none());
    }
}
