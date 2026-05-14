//! Multi-turn LLM agent that drives deployment tools.

use crate::config::{DeployConfig, ModelsConfig};
use crate::deploy::executor::DeployExecutor;
use crate::deploy::llm_client::{AssistantOutput, DeployLlmClient, ToolCallBody};
use crate::deploy::tools::{deployment_tool_definitions, DEPLOY_SYSTEM_PROMPT};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize)]
pub struct DeployStepLog {
    pub round: u32,
    pub tool: Option<String>,
    pub arguments_preview: Option<String>,
    pub result_preview: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploySessionResult {
    pub ok: bool,
    pub summary: String,
    pub rounds: u32,
    pub steps: Vec<DeployStepLog>,
    pub error: Option<String>,
}

/// Run the autonomous deployment loop. `execute_docker` gates real `docker compose` (AND config.allow_docker_exec).
pub async fn run_autonomous_deploy(
    goal: &str,
    deploy: &DeployConfig,
    models: &ModelsConfig,
    execute_docker: bool,
) -> Result<DeploySessionResult> {
    let endpoint = models
        .api_endpoint
        .clone()
        .context("models.api_endpoint is required for autonomous deploy")?;

    let model = models
        .api_model
        .clone()
        .unwrap_or_else(|| "gpt-4o-mini".to_string());

    std::fs::create_dir_all(&deploy.workspace_dir).with_context(|| {
        format!(
            "create deploy workspace {}",
            deploy.workspace_dir.display()
        )
    })?;

    let workspace = deploy
        .workspace_dir
        .canonicalize()
        .unwrap_or_else(|_| deploy.workspace_dir.clone());

    let docker_cli = deploy
        .docker_cli
        .clone()
        .unwrap_or_else(|| "docker".to_string());

    let docker_allowed = deploy.allow_docker_exec && execute_docker;
    let executor = DeployExecutor::new(workspace.clone(), docker_cli, docker_allowed);

    let client = DeployLlmClient::new(
        endpoint,
        model,
        Duration::from_secs(300),
        models.inference.temperature,
        deploy.max_completion_tokens,
    )?;

    let tools = deployment_tool_definitions();
    let mut messages: Vec<Value> = vec![
        json!({"role": "system", "content": DEPLOY_SYSTEM_PROMPT}),
        json!({"role": "user", "content": format!(
            "Deployment goal:\n{}\n\nWorkspace root on server: {}\nDocker execution allowed this request: {}\nConfig allow_docker_exec: {}",
            goal,
            workspace.display(),
            execute_docker,
            deploy.allow_docker_exec
        )}),
    ];

    let mut steps: Vec<DeployStepLog> = Vec::new();
    let mut round: u32 = 0;
    let mut finished_summary: Option<String> = None;

    while round < deploy.max_tool_rounds {
        round += 1;
        let output = client
            .complete(messages.clone(), tools.clone())
            .await
            .with_context(|| format!("LLM round {}", round))?;

        match output {
            AssistantOutput::Text(text) => {
                if text.is_empty() {
                    finished_summary = Some("(no content)".into());
                    break;
                }
                info!("Deploy agent text (round {}): {}", round, text);
                finished_summary = Some(text);
                break;
            }
            AssistantOutput::ToolCalls(calls) => {
                let assistant_msg = build_assistant_tool_message(&calls);
                messages.push(assistant_msg);

                let mut saw_finish = false;
                for tc in &calls {
                    let name = tc.function.name.clone();
                    let args = tc.function.arguments.clone();
                    let preview = if args.len() > 400 {
                        format!("{}…", &args[..400])
                    } else {
                        args.clone()
                    };

                    if name == "finish_deployment" {
                        saw_finish = true;
                        if let Ok(v) = serde_json::from_str::<Value>(&args) {
                            if let Some(s) = v.get("summary").and_then(|x| x.as_str()) {
                                finished_summary = Some(s.to_string());
                            }
                        }
                    }

                    let result = executor.run_tool(&name, &args).await;
                    let res_preview = if result.len() > 800 {
                        format!("{}…", &result[..800])
                    } else {
                        result.clone()
                    };

                    steps.push(DeployStepLog {
                        round,
                        tool: Some(name.clone()),
                        arguments_preview: Some(preview),
                        result_preview: res_preview,
                    });

                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result
                    }));
                }

                if saw_finish {
                    break;
                }
            }
        }
    }

    if round >= deploy.max_tool_rounds {
        warn!("Deploy agent stopped at max_tool_rounds");
    }

    let summary = finished_summary.unwrap_or_else(|| "Agent stopped without finish_deployment summary.".into());

    Ok(DeploySessionResult {
        ok: true,
        summary,
        rounds: round,
        steps,
        error: None,
    })
}

fn build_assistant_tool_message(calls: &[ToolCallBody]) -> Value {
    let tool_calls: Vec<Value> = calls
        .iter()
        .map(|tc| {
            json!({
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments
                }
            })
        })
        .collect();

    json!({
        "role": "assistant",
        "content": "",
        "tool_calls": tool_calls
    })
}
