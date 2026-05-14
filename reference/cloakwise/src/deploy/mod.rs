//! Autonomous deployment agent: LLM tool-calling to write Docker/cluster artifacts.

mod agent;
mod executor;
mod llm_client;
mod tools;

pub use agent::{run_autonomous_deploy, DeploySessionResult, DeployStepLog};
pub use tools::deployment_tool_definitions;
