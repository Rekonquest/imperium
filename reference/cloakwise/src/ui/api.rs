//! REST API for the Cloakwise UI
//!
//! Provides endpoints for monitoring, profile management, and LLM-driven generation.

use crate::config::Protocol;
use crate::deploy::run_autonomous_deploy;
use crate::mesh::MeshSnapshot;
use crate::ui::profile_generator::{
    GeneratedProfile, MimicTarget, ProfileConstraints, ProfileGenerationRequest, ProfileGenerator,
};
use crate::ui::state::AppState;
use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info};

// ─── Response types ─────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Json<Self> {
        Json(Self {
            success: true,
            data: Some(data),
            error: None,
        })
    }

    pub fn err(message: impl Into<String>) -> (StatusCode, Json<Self>) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Self {
                success: false,
                data: None,
                error: Some(message.into()),
            }),
        )
    }
}

// ─── System Status ──────────────────────────────────────────

#[derive(Serialize)]
pub struct SystemStatus {
    pub node_id: String,
    pub state: String,
    pub uptime_secs: u64,
    pub active_profile: Option<ProfileSummary>,
    pub events_processed: u64,
    pub decisions_made: u64,
    pub profile_switches: u64,
    pub escalations: u64,
    pub fallback_activations: u64,
    pub safe_mode_entries: u64,
    pub specialist_count: usize,
    pub ai_model_available: bool,
    pub profiles_available: usize,
    pub burned_profiles: usize,
    pub mesh: MeshSnapshot,
}

#[derive(Serialize, Clone)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub obfuscation: String,
}

/// GET /api/status
pub async fn get_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stats = state.stats.read().clone();
    let active = state.active_profile.read().as_ref().map(|p| ProfileSummary {
        id: p.id.clone(),
        name: p.name.clone(),
        protocol: format!("{:?}", p.protocol),
        port: p.port,
        obfuscation: format!("{:?}", p.obfuscation),
    });

    let gen = state.profile_generator.read();

    ApiResponse::ok(SystemStatus {
        node_id: state.node_id.clone(),
        state: format!("{:?}", *state.orchestrator_state.read()),
        uptime_secs: stats.uptime_secs,
        active_profile: active,
        events_processed: stats.events_processed,
        decisions_made: stats.decisions_made,
        profile_switches: stats.profile_switches,
        escalations: stats.escalations_to_bigmomma,
        fallback_activations: stats.fallback_activations,
        safe_mode_entries: stats.safe_mode_entries,
        specialist_count: stats.specialist_count,
        ai_model_available: stats.ai_model_available,
        profiles_available: state.profiles.read().len(),
        burned_profiles: gen.burned().len(),
        mesh: state
            .mesh
            .as_ref()
            .map(|m| m.snapshot())
            .unwrap_or_else(|| MeshSnapshot::disabled(state.node_id.clone())),
    })
}

// ─── Profile Listing ────────────────────────────────────────

#[derive(Serialize)]
pub struct ProfileListItem {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub port: u16,
    pub obfuscation: String,
    pub max_concurrent: u32,
    pub is_active: bool,
    pub is_dynamic: bool,
}

/// GET /api/profiles
pub async fn list_profiles(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let profiles = state.profiles.read();
    let active_id = state
        .active_profile
        .read()
        .as_ref()
        .map(|p| p.id.clone());

    let items: Vec<ProfileListItem> = profiles
        .values()
        .map(|p| ProfileListItem {
            id: p.id.clone(),
            name: p.name.clone(),
            protocol: format!("{:?}", p.protocol),
            port: p.port,
            obfuscation: format!("{:?}", p.obfuscation),
            max_concurrent: p.max_concurrent,
            is_active: active_id.as_deref() == Some(&p.id),
            is_dynamic: p.id.starts_with("dyn_"),
        })
        .collect();

    ApiResponse::ok(items)
}

/// GET /api/profiles/:id
pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let profiles = state.profiles.read();
    match profiles.get(&id) {
        Some(profile) => (StatusCode::OK, ApiResponse::ok(serde_json::to_value(profile).unwrap())),
        None => ApiResponse::<serde_json::Value>::err(format!("Profile '{}' not found", id)),
    }
}

// ─── Profile Generation ─────────────────────────────────────

#[derive(Deserialize)]
pub struct GenerateProfileRequest {
    pub intent: String,
    pub protocol: String,
    #[serde(default)]
    pub mimic_service: Option<String>,
    #[serde(default)]
    pub threat_level: Option<u8>,
    #[serde(default)]
    pub evolve_from: Option<String>,
    #[serde(default)]
    pub require_tls: Option<bool>,
    #[serde(default)]
    pub banned_ports: Option<Vec<u16>>,
    #[serde(default)]
    pub max_concurrent: Option<u32>,
}

#[derive(Serialize)]
pub struct GenerateProfileResponse {
    pub profile: ProfileSummary,
    pub evasion_confidence: f32,
    pub reasoning: String,
    pub estimated_lifespan_hours: u32,
    pub lineage: Vec<String>,
    pub llm_prompt: Option<LlmPromptResponse>,
}

#[derive(Serialize)]
pub struct LlmPromptResponse {
    pub system: String,
    pub user: String,
}

/// POST /api/profiles/generate
pub async fn generate_profile(
    State(state): State<Arc<AppState>>,
    Json(body): Json<GenerateProfileRequest>,
) -> impl IntoResponse {
    let protocol = match body.protocol.to_lowercase().as_str() {
        "wireguard" => Protocol::Wireguard,
        "amneziawg" => Protocol::Amneziawg,
        "cloak" => Protocol::Cloak,
        "shadowsocks" => Protocol::Shadowsocks,
        "outline" => Protocol::Outline,
        "v2ray" => Protocol::V2ray,
        "xray" => Protocol::Xray,
        "trojan-go" | "trojango" => Protocol::TrojanGo,
        "hysteria2" | "hysteria" => Protocol::Hysteria2,
        "naiveproxy" | "naive" => Protocol::NaiveProxy,
        "snowflake" => Protocol::Snowflake,
        "iodine" | "dns-tunnel" => Protocol::Iodine,
        "briar" => Protocol::Briar,
        _ => return ApiResponse::<GenerateProfileResponse>::err(format!("Unknown protocol: {}", body.protocol)),
    };

    let mimic = body.mimic_service.as_deref().and_then(parse_mimic_target);

    let request = ProfileGenerationRequest {
        intent: body.intent,
        protocol,
        mimic_service: mimic,
        threat_level: body.threat_level.unwrap_or(5),
        evolve_from: body.evolve_from,
        constraints: ProfileConstraints {
            require_tls: body.require_tls.unwrap_or(false),
            banned_ports: body.banned_ports.unwrap_or_default(),
            max_concurrent: body.max_concurrent,
            ..Default::default()
        },
    };

    // Build LLM prompt
    let llm_prompt = {
        let gen = state.profile_generator.read();
        let prompt = gen.build_llm_prompt(&request);
        Some(LlmPromptResponse {
            system: prompt.system,
            user: prompt.user,
        })
    };

    // Generate profile
    let generated = {
        let gen = state.profile_generator.read();
        match gen.generate(&request) {
            Ok(g) => g,
            Err(e) => {
                error!("Profile generation failed: {}", e);
                return ApiResponse::<GenerateProfileResponse>::err(e.to_string());
            }
        }
    };

    // Register the profile
    {
        let mut profiles = state.profiles.write();
        profiles.insert(generated.profile.id.clone(), generated.profile.clone());
    }

    info!("Dynamic profile '{}' registered via API", generated.profile.id);

    let response = GenerateProfileResponse {
        profile: ProfileSummary {
            id: generated.profile.id.clone(),
            name: generated.profile.name.clone(),
            protocol: format!("{:?}", generated.profile.protocol),
            port: generated.profile.port,
            obfuscation: format!("{:?}", generated.profile.obfuscation),
        },
        evasion_confidence: generated.evasion_confidence,
        reasoning: generated.reasoning,
        estimated_lifespan_hours: generated.estimated_lifespan_hours,
        lineage: generated.lineage,
        llm_prompt,
    };

    (StatusCode::CREATED, ApiResponse::ok(response))
}

/// POST /api/profiles/:id/mutate
#[derive(Deserialize)]
pub struct MutateRequest {
    #[serde(default = "default_mutation_strength")]
    pub strength: f32,
}

fn default_mutation_strength() -> f32 {
    0.3
}

pub async fn mutate_profile(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<MutateRequest>,
) -> impl IntoResponse {
    let source_profile = {
        let profiles = state.profiles.read();
        match profiles.get(&id) {
            Some(p) => p.clone(),
            None => return ApiResponse::<GenerateProfileResponse>::err(format!("Profile '{}' not found", id)),
        }
    };

    let generated = {
        let gen = state.profile_generator.read();
        match gen.mutate(&source_profile, body.strength) {
            Ok(g) => g,
            Err(e) => return ApiResponse::<GenerateProfileResponse>::err(e.to_string()),
        }
    };

    // Register
    {
        let mut profiles = state.profiles.write();
        profiles.insert(generated.profile.id.clone(), generated.profile.clone());
    }

    let response = GenerateProfileResponse {
        profile: ProfileSummary {
            id: generated.profile.id.clone(),
            name: generated.profile.name.clone(),
            protocol: format!("{:?}", generated.profile.protocol),
            port: generated.profile.port,
            obfuscation: format!("{:?}", generated.profile.obfuscation),
        },
        evasion_confidence: generated.evasion_confidence,
        reasoning: generated.reasoning,
        estimated_lifespan_hours: generated.estimated_lifespan_hours,
        lineage: generated.lineage,
        llm_prompt: None,
    };

    (StatusCode::CREATED, ApiResponse::ok(response))
}

/// POST /api/profiles/:id/activate
pub async fn activate_profile(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let profile = {
        let profiles = state.profiles.read();
        match profiles.get(&id) {
            Some(p) => p.clone(),
            None => {
                return ApiResponse::<serde_json::Value>::err(format!(
                    "Profile '{}' not found",
                    id
                ))
            }
        }
    };

    // Send activation through the action channel
    if let Some(ref tx) = *state.action_tx.read() {
        let _ = tx.send(crate::specialists::Action::SwitchProfile {
            target: profile.id.clone(),
        });
        info!("Profile '{}' activation requested via API", id);
    }

    *state.active_profile.write() = Some(profile.clone());

    (
        StatusCode::OK,
        ApiResponse::ok(serde_json::json!({"activated": id})),
    )
}

/// POST /api/profiles/:id/burn
#[derive(Deserialize)]
pub struct BurnRequest {
    pub reason: String,
}

pub async fn burn_profile(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<BurnRequest>,
) -> impl IntoResponse {
    let profile = {
        let profiles = state.profiles.read();
        match profiles.get(&id) {
            Some(p) => p.clone(),
            None => {
                return ApiResponse::<serde_json::Value>::err(format!(
                    "Profile '{}' not found",
                    id
                ))
            }
        }
    };

    {
        let gen = state.profile_generator.read();
        gen.burn_profile(&profile, &body.reason);
    }

    // Remove from active profiles
    {
        let mut profiles = state.profiles.write();
        profiles.remove(&id);
    }

    info!("Profile '{}' burned via API: {}", id, body.reason);

    (
        StatusCode::OK,
        ApiResponse::ok(serde_json::json!({"burned": id, "reason": body.reason})),
    )
}

// ─── LLM Prompt Builder ─────────────────────────────────────

/// POST /api/llm/prompt — Build an LLM prompt for profile generation
pub async fn build_llm_prompt(
    State(state): State<Arc<AppState>>,
    Json(body): Json<GenerateProfileRequest>,
) -> impl IntoResponse {
    let protocol = match body.protocol.to_lowercase().as_str() {
        "wireguard" => Protocol::Wireguard,
        "amneziawg" => Protocol::Amneziawg,
        "cloak" => Protocol::Cloak,
        "shadowsocks" => Protocol::Shadowsocks,
        "outline" => Protocol::Outline,
        "v2ray" => Protocol::V2ray,
        "xray" => Protocol::Xray,
        "trojan-go" | "trojango" => Protocol::TrojanGo,
        "hysteria2" | "hysteria" => Protocol::Hysteria2,
        "naiveproxy" | "naive" => Protocol::NaiveProxy,
        "snowflake" => Protocol::Snowflake,
        "iodine" | "dns-tunnel" => Protocol::Iodine,
        "briar" => Protocol::Briar,
        _ => return ApiResponse::<LlmPromptResponse>::err(format!("Unknown protocol: {}", body.protocol)),
    };

    let mimic = body.mimic_service.as_deref().and_then(parse_mimic_target);

    let request = ProfileGenerationRequest {
        intent: body.intent,
        protocol,
        mimic_service: mimic,
        threat_level: body.threat_level.unwrap_or(5),
        evolve_from: body.evolve_from,
        constraints: ProfileConstraints {
            require_tls: body.require_tls.unwrap_or(false),
            banned_ports: body.banned_ports.unwrap_or_default(),
            max_concurrent: body.max_concurrent,
            ..Default::default()
        },
    };

    let gen = state.profile_generator.read();
    let prompt = gen.build_llm_prompt(&request);

    (
        StatusCode::OK,
        ApiResponse::ok(LlmPromptResponse {
            system: prompt.system,
            user: prompt.user,
        }),
    )
}

// ─── Generation History ─────────────────────────────────────

#[derive(Serialize)]
pub struct HistoryItem {
    pub profile_id: String,
    pub evasion_confidence: f32,
    pub estimated_lifespan_hours: u32,
    pub lineage_depth: usize,
    pub reasoning: String,
}

/// GET /api/profiles/history
pub async fn generation_history(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let gen = state.profile_generator.read();
    let history: Vec<HistoryItem> = gen
        .history()
        .iter()
        .map(|g| HistoryItem {
            profile_id: g.profile.id.clone(),
            evasion_confidence: g.evasion_confidence,
            estimated_lifespan_hours: g.estimated_lifespan_hours,
            lineage_depth: g.lineage.len(),
            reasoning: g.reasoning.clone(),
        })
        .collect();

    ApiResponse::ok(history)
}

/// GET /api/profiles/burned
pub async fn burned_profiles(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let gen = state.profile_generator.read();
    ApiResponse::ok(gen.burned())
}

// ─── Events / Telemetry ─────────────────────────────────────

#[derive(Serialize)]
pub struct RecentEvents {
    pub count: usize,
    pub events: Vec<serde_json::Value>,
}

/// GET /api/events/recent
pub async fn recent_events(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let events = state.recent_events.read();
    let serialized: Vec<serde_json::Value> = events
        .iter()
        .rev()
        .take(50)
        .filter_map(|e| serde_json::to_value(e).ok())
        .collect();

    ApiResponse::ok(RecentEvents {
        count: serialized.len(),
        events: serialized,
    })
}

// ─── Alerts ─────────────────────────────────────────────────

/// GET /api/alerts
pub async fn get_alerts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let alerts = state.alerts.read();
    ApiResponse::ok(alerts.clone())
}

// ─── Autonomous cluster / Docker deploy (LLM tool loop) ─────

#[derive(Deserialize)]
pub struct DeployAutonomousRequest {
    pub goal: String,
    #[serde(default)]
    pub execute_docker: bool,
}

/// POST /api/deploy/autonomous — requires `models.api_endpoint`; may take minutes.
pub async fn deploy_autonomous(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeployAutonomousRequest>,
) -> impl IntoResponse {
    let goal = body.goal.trim();
    if goal.is_empty() {
        return ApiResponse::<serde_json::Value>::err("goal is required".to_string()).into_response();
    }

    let deploy = state.deploy.read().clone();
    let models = state.models.clone();

    match run_autonomous_deploy(goal, &deploy, &models, body.execute_docker).await {
        Ok(result) => match serde_json::to_value(&result) {
            Ok(v) => (StatusCode::OK, ApiResponse::ok(v)).into_response(),
            Err(e) => ApiResponse::<serde_json::Value>::err(e.to_string()).into_response(),
        },
        Err(e) => ApiResponse::<serde_json::Value>::err(e.to_string()).into_response(),
    }
}

// ─── Helpers ────────────────────────────────────────────────

fn parse_mimic_target(s: &str) -> Option<MimicTarget> {
    match s.to_lowercase().as_str() {
        "youtube" => Some(MimicTarget::Youtube),
        "netflix" => Some(MimicTarget::Netflix),
        "zoom" => Some(MimicTarget::Zoom),
        "teams" => Some(MimicTarget::Teams),
        "discord" => Some(MimicTarget::Discord),
        "steam" => Some(MimicTarget::Steam),
        "telegram" => Some(MimicTarget::Telegram),
        "whatsapp" => Some(MimicTarget::Whatsapp),
        "https" | "generic_https" => Some(MimicTarget::GenericHttps),
        "websocket" | "generic_websocket" => Some(MimicTarget::GenericWebsocket),
        _ => None,
    }
}
