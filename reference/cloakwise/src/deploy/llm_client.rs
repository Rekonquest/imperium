//! OpenAI-compatible chat completions with tool calling.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<Value>,
    pub tools: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    pub temperature: f32,
    pub max_tokens: u32,
}

#[derive(Debug, Deserialize)]
pub struct ChatCompletionResponse {
    pub choices: Vec<ChoiceBody>,
}

#[derive(Debug, Deserialize)]
pub struct ChoiceBody {
    pub message: ResponseMessage,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ResponseMessage {
    pub role: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<ToolCallBody>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ToolCallBody {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    pub function: FunctionCallBody,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FunctionCallBody {
    pub name: String,
    pub arguments: String,
}

pub enum AssistantOutput {
    Text(String),
    ToolCalls(Vec<ToolCallBody>),
}

pub struct DeployLlmClient {
    pub endpoint: String,
    pub model: String,
    pub http: reqwest::Client,
    pub temperature: f32,
    pub max_tokens: u32,
}

impl DeployLlmClient {
    pub fn new(
        endpoint: String,
        model: String,
        timeout: Duration,
        temperature: f32,
        max_tokens: u32,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .context("reqwest client")?;
        Ok(Self {
            endpoint,
            model,
            http,
            temperature,
            max_tokens,
        })
    }

    pub async fn complete(
        &self,
        messages: Vec<Value>,
        tools: Vec<Value>,
    ) -> Result<AssistantOutput> {
        let url = format!("{}/chat/completions", self.endpoint.trim_end_matches('/'));
        let body = ChatCompletionRequest {
            model: self.model.clone(),
            messages,
            tools,
            tool_choice: Some(json!("auto")),
            temperature: self.temperature,
            max_tokens: self.max_tokens,
        };

        let response = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("LLM request")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("LLM {}: {}", status, text);
        }

        let parsed: ChatCompletionResponse = response.json().await.context("parse LLM JSON")?;
        let msg = parsed
            .choices
            .into_iter()
            .next()
            .map(|c| c.message)
            .context("no choices")?;

        if !msg.tool_calls.is_empty() {
            return Ok(AssistantOutput::ToolCalls(msg.tool_calls));
        }

        Ok(AssistantOutput::Text(
            msg.content.unwrap_or_default().trim().to_string(),
        ))
    }
}
