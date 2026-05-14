//! OpenAI-style function definitions for the deployment agent.

use serde_json::{json, Value};

/// Tool specs passed to the chat/completions API.
pub fn deployment_tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "type": "function",
            "function": {
                "name": "write_deploy_file",
                "description": "Create or overwrite a file under the deployment workspace (relative path only). Use for docker-compose.yml, Cloakwise config fragments, README, or env files.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "relative_path": { "type": "string", "description": "Path relative to workspace, e.g. cluster/docker-compose.yml" },
                        "content": { "type": "string", "description": "Full file contents" }
                    },
                    "required": ["relative_path", "content"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "read_deploy_file",
                "description": "Read a text file from the deployment workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "relative_path": { "type": "string" }
                    },
                    "required": ["relative_path"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "list_deploy_files",
                "description": "List files under a subdirectory of the workspace (recursive, max depth 6).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "relative_dir": { "type": "string", "description": "Subdirectory relative to workspace; use empty string for root" }
                    },
                    "required": ["relative_dir"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "docker_compose",
                "description": "Run `docker compose` against a compose file in the workspace. Requires allow_docker_exec=true in server config and execute=true on the API request, or only simulates.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "compose_relative_path": { "type": "string", "description": "Compose file relative to workspace" },
                        "args": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Subcommand + flags after `docker compose -f <file>`, e.g. [\"config\"], [\"pull\"], [\"up\", \"-d\", \"--build\"]"
                        }
                    },
                    "required": ["compose_relative_path", "args"]
                }
            }
        }),
        json!({
            "type": "function",
            "function": {
                "name": "finish_deployment",
                "description": "Call when done. Summarize what was created and any manual steps for the operator.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "summary": { "type": "string" },
                        "next_steps": { "type": "array", "items": { "type": "string" } }
                    },
                    "required": ["summary"]
                }
            }
        }),
    ]
}

pub const DEPLOY_SYSTEM_PROMPT: &str = r#"You are Cloakwise Deploy, an infrastructure agent that prepares self-hosted VPN cluster deployments using Docker Compose.

Rules:
- Only use tool paths inside the deployment workspace; never use absolute paths or parent segments (..).
- Prefer a layout like: cluster/docker-compose.yml, cluster/.env.example, cluster/README.md, configs/node-01.yaml snippets.
- Produce production-minded Compose: services for cloakwise nodes, shared networks, volumes for /etc/cloakwise and logs, published API ports.
- Use the finish_deployment tool when the file set is coherent and you would hand off to a human operator.
- If Docker execution is disabled, still write compose files and explain `docker compose up -d` for the operator.

You do not have shell access beyond the docker_compose tool."#;
