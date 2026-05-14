//! Axum web server for the Cloakwise UI.

use crate::ui::api;
use crate::ui::dashboard::DASHBOARD_HTML;
use crate::ui::state::AppState;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info};

/// Build the Axum router with all routes
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Dashboard
        .route("/", get(serve_dashboard))
        // System
        .route("/api/status", get(api::get_status))
        // Profiles
        .route("/api/profiles", get(api::list_profiles))
        .route("/api/profiles/history", get(api::generation_history))
        .route("/api/profiles/burned", get(api::burned_profiles))
        .route("/api/profiles/generate", post(api::generate_profile))
        .route("/api/profiles/{id}", get(api::get_profile))
        .route("/api/profiles/{id}/activate", post(api::activate_profile))
        .route("/api/profiles/{id}/mutate", post(api::mutate_profile))
        .route("/api/profiles/{id}/burn", post(api::burn_profile))
        // LLM
        .route("/api/llm/prompt", post(api::build_llm_prompt))
        // Autonomous deploy (LLM + Docker tools)
        .route("/api/deploy/autonomous", post(api::deploy_autonomous))
        // Events
        .route("/api/events/recent", get(api::recent_events))
        // Alerts
        .route("/api/alerts", get(api::get_alerts))
        .with_state(state)
}

/// Serve the embedded dashboard HTML
async fn serve_dashboard() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(DASHBOARD_HTML),
    )
}

/// Start the UI server
pub async fn start_server(
    state: Arc<AppState>,
    port: u16,
    bind_addr: Option<std::net::IpAddr>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let addr = SocketAddr::new(
        bind_addr.unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        port,
    );

    let app = build_router(state);

    info!("Cloakwise UI server listening on http://{}", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind UI server on {}: {}", addr, e);
            return;
        }
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        })
        .await
        .unwrap_or_else(|e| error!("UI server error: {}", e));

    info!("UI server stopped");
}
