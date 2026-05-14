//! Sandboxed execution of deployment tool calls.

use serde_json::{json, Value};
use std::path::{Component, Path, PathBuf};
use tokio::process::Command;
use tracing::{info, warn};

/// Runs tool calls with workspace confinement.
pub struct DeployExecutor {
    workspace_root: PathBuf,
    docker_cli: String,
    /// Effective allow: config && !dry_run
    docker_allowed: bool,
}

impl DeployExecutor {
    pub fn new(workspace_root: PathBuf, docker_cli: String, docker_allowed: bool) -> Self {
        Self {
            workspace_root,
            docker_cli,
            docker_allowed,
        }
    }

    pub async fn run_tool(&self, name: &str, arguments_json: &str) -> String {
        let args: Value = match serde_json::from_str(arguments_json) {
            Ok(v) => v,
            Err(e) => return format!(r#"{{"ok":false,"error":"invalid JSON arguments: {}"}}"#, e),
        };

        match name {
            "write_deploy_file" => self.tool_write(&args),
            "read_deploy_file" => self.tool_read(&args).await,
            "list_deploy_files" => self.tool_list(&args),
            "docker_compose" => self.tool_docker_compose(&args).await,
            "finish_deployment" => serde_json::to_string(&json!({
                "ok": true,
                "finished": true,
                "payload": args
            }))
            .unwrap_or_else(|_| r#"{"ok":true,"finished":true}"#.to_string()),
            _ => format!(r#"{{"ok":false,"error":"unknown tool {}"}}"#, name),
        }
    }

    fn tool_write(&self, args: &Value) -> String {
        let rel = match args.get("relative_path").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return r#"{"ok":false,"error":"missing relative_path"}"#.to_string(),
        };
        let content = match args.get("content").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return r#"{"ok":false,"error":"missing content"}"#.to_string(),
        };

        match self.resolve_path(rel) {
            Ok(path) => {
                if let Some(parent) = path.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        return format!(r#"{{"ok":false,"error":"mkdir: {}"}}"#, e);
                    }
                }
                match std::fs::write(&path, content) {
                    Ok(()) => {
                        info!("Deploy wrote {}", path.display());
                        format!(
                            r#"{{"ok":true,"path":"{}","bytes":{}}}"#,
                            path.display(),
                            content.len()
                        )
                    }
                    Err(e) => format!(r#"{{"ok":false,"error":"write failed: {}"}}"#, e),
                }
            }
            Err(e) => format!(r#"{{"ok":false,"error":"{}"}}"#, e),
        }
    }

    async fn tool_read(&self, args: &Value) -> String {
        let rel = match args.get("relative_path").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return r#"{"ok":false,"error":"missing relative_path"}"#.to_string(),
        };
        match self.resolve_path(rel) {
            Ok(path) => match tokio::fs::read_to_string(&path).await {
                Ok(text) => serde_json::to_string(&json!({
                    "ok": true,
                    "path": path.to_string_lossy(),
                    "content": text
                }))
                .unwrap_or_else(|_| r#"{"ok":false,"error":"serialize"}"#.to_string()),
                Err(e) => format!(r#"{{"ok":false,"error":"read: {}"}}"#, e),
            },
            Err(e) => format!(r#"{{"ok":false,"error":"{}"}}"#, e),
        }
    }

    fn tool_list(&self, args: &Value) -> String {
        let rel = args
            .get("relative_dir")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let base = match self.resolve_path(if rel.is_empty() { "." } else { rel }) {
            Ok(p) => p,
            Err(e) => return format!(r#"{{"ok":false,"error":"{}"}}"#, e),
        };

        if !base.exists() {
            return serde_json::to_string(&json!({ "ok": true, "files": [] }))
                .unwrap_or_default();
        }

        let mut out = Vec::new();
        if let Err(e) = self.walk_list(&base, 0, 6, &mut out) {
            return format!(r#"{{"ok":false,"error":"{}"}}"#, e);
        }
        serde_json::to_string(&json!({ "ok": true, "files": out })).unwrap_or_default()
    }

    fn walk_list(
        &self,
        dir: &Path,
        depth: u32,
        max_depth: u32,
        acc: &mut Vec<String>,
    ) -> std::io::Result<()> {
        if depth > max_depth {
            return Ok(());
        }
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let rel = match p.strip_prefix(&self.workspace_root) {
                Ok(r) => r.to_string_lossy().replace('\\', "/"),
                Err(_) => p.to_string_lossy().replace('\\', "/"),
            };
            acc.push(rel);
            if p.is_dir() {
                self.walk_list(&p, depth + 1, max_depth, acc)?;
            }
        }
        Ok(())
    }

    async fn tool_docker_compose(&self, args: &Value) -> String {
        let compose_rel = match args.get("compose_relative_path").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return r#"{"ok":false,"error":"missing compose_relative_path"}"#.to_string(),
        };
        let extra: Vec<String> = args
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let compose_path = match self.resolve_path(compose_rel) {
            Ok(p) => p,
            Err(e) => return format!(r#"{{"ok":false,"error":"{}"}}"#, e),
        };

        let project_dir = compose_path
            .parent()
            .unwrap_or(&self.workspace_root)
            .to_path_buf();

        if !self.docker_allowed {
            warn!(
                "docker_compose dry-run: {} compose -f {:?} {:?}",
                self.docker_cli, compose_path, extra
            );
            return serde_json::to_string(&json!({
                "ok": true,
                "simulated": true,
                "command": format!("{} compose -f {} {}", self.docker_cli, compose_path.display(), extra.join(" "))
            }))
            .unwrap_or_default();
        }

        let mut cmd = Command::new(&self.docker_cli);
        cmd.arg("compose")
            .arg("-f")
            .arg(&compose_path)
            .args(&extra)
            .current_dir(&project_dir)
            .kill_on_drop(true);

        match cmd.output().await {
            Ok(out) => {
                let code = out.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                serde_json::to_string(&json!({
                    "ok": out.status.success(),
                    "exit_code": code,
                    "stdout": stdout,
                    "stderr": stderr
                }))
                .unwrap_or_default()
            }
            Err(e) => format!(r#"{{"ok":false,"error":"spawn docker: {}"}}"#, e),
        }
    }

    fn resolve_path(&self, relative: &str) -> Result<PathBuf, String> {
        let trimmed = relative.trim().replace('\\', "/");
        if trimmed.is_empty() {
            return Err("empty path".into());
        }
        if trimmed.contains("..") {
            return Err("path must not contain ..".into());
        }
        let p = Path::new(&trimmed);
        for c in p.components() {
            match c {
                Component::ParentDir => return Err("invalid path component".into()),
                Component::RootDir | Component::Prefix(_) => {
                    return Err("absolute paths not allowed".into())
                }
                _ => {}
            }
        }
        Ok(self.workspace_root.join(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn resolve_rejects_parent_dir() {
        let dir = tempdir().unwrap();
        let ex = DeployExecutor::new(dir.path().to_path_buf(), "docker".to_string(), false);
        assert!(ex.resolve_path("../etc/passwd").is_err());
        assert!(ex.resolve_path("foo/../../bar").is_err());
    }

    #[tokio::test]
    async fn write_and_read_roundtrip() {
        let dir = tempdir().unwrap();
        let ex = DeployExecutor::new(dir.path().to_path_buf(), "docker".to_string(), false);
        let w = ex
            .run_tool(
                "write_deploy_file",
                r#"{"relative_path":"a/b.txt","content":"hello"}"#,
            )
            .await;
        assert!(w.contains("ok"));
        let p = dir.path().join("a/b.txt");
        assert_eq!(fs::read_to_string(p).unwrap(), "hello");
    }
}
