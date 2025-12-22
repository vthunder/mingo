//! HTTP server for web-based auth
//!
//! Exposes the sign request flow over HTTP for browser-based apps.
//! Listens on localhost:7890 by default.

use std::sync::Arc;
use tokio::sync::RwLock;

use axum::{
    extract::{Path, State},
    http::{header, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::CorsLayer;
use serde::{Deserialize, Serialize};

use crate::ipc::{SignRequest, SignRequestStatus};

/// Shared state for HTTP handlers
pub type HttpState<S> = Arc<RwLock<S>>;

/// Request to create a new auth request
#[derive(Debug, Deserialize)]
pub struct AuthRequestBody {
    /// Origin of the requesting app (e.g., "https://sandmill.org")
    pub app_origin: String,
    /// Random challenge from the app
    pub challenge: String,
    /// Optional: specific email to authenticate as
    pub email: Option<String>,
    /// Optional: human-readable purpose
    pub purpose: Option<String>,
}

/// Response when creating an auth request
#[derive(Debug, Serialize)]
pub struct AuthRequestResponse {
    pub request_id: String,
}

/// Response when polling auth status
#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_jwt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_binding_jwt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Trait for accessing sign requests from state
pub trait SignRequestStore: Send + Sync + 'static {
    fn create_sign_request(&mut self, request: SignRequest) -> String;
    fn get_sign_request(&self, request_id: &str) -> Option<&SignRequest>;
}

/// Create the HTTP router
pub fn create_router<S: SignRequestStore>(state: HttpState<S>) -> Router {
    // CORS configuration - allow wallet.sandmill.org and localhost for dev
    let cors = CorsLayer::new()
        .allow_origin([
            "https://wallet.sandmill.org".parse().unwrap(),
            "http://localhost:3000".parse().unwrap(),
            "http://127.0.0.1:3000".parse().unwrap(),
        ])
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

    Router::new()
        .route("/auth/request", post(create_auth_request::<S>))
        .route("/auth/status/:request_id", get(get_auth_status::<S>))
        .route("/health", get(health_check))
        .layer(cors)
        .with_state(state)
}

/// POST /auth/request - Create a new auth request
async fn create_auth_request<S: SignRequestStore>(
    State(state): State<HttpState<S>>,
    Json(body): Json<AuthRequestBody>,
) -> impl IntoResponse {
    let request_id = generate_request_id();

    let app_origin = body.app_origin;
    let app_name = extract_app_name(&app_origin);

    let request = SignRequest {
        request_id: request_id.clone(),
        app_name,
        app_origin: Some(app_origin.clone()),
        email: body.email,
        challenge: body.challenge,
        purpose: body.purpose,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        status: SignRequestStatus::Pending,
        assertion_jwt: None,
        session_binding_jwt: None,
        rejection_reason: None,
    };

    {
        let mut state = state.write().await;
        state.create_sign_request(request);
    }

    tracing::info!("HTTP: Created auth request {} for {}", request_id, app_origin);

    (StatusCode::OK, Json(AuthRequestResponse { request_id }))
}

/// GET /auth/status/:request_id - Poll for auth status
async fn get_auth_status<S: SignRequestStore>(
    State(state): State<HttpState<S>>,
    Path(request_id): Path<String>,
) -> impl IntoResponse {
    let state = state.read().await;

    match state.get_sign_request(&request_id) {
        Some(request) => {
            let response = AuthStatusResponse {
                status: match request.status {
                    SignRequestStatus::Pending => "pending".to_string(),
                    SignRequestStatus::Approved => "approved".to_string(),
                    SignRequestStatus::Rejected => "rejected".to_string(),
                    SignRequestStatus::Expired => "expired".to_string(),
                },
                assertion_jwt: request.assertion_jwt.clone(),
                session_binding_jwt: request.session_binding_jwt.clone(),
                reason: request.rejection_reason.clone(),
            };
            (StatusCode::OK, Json(response))
        }
        None => {
            let response = AuthStatusResponse {
                status: "not_found".to_string(),
                assertion_jwt: None,
                session_binding_jwt: None,
                reason: Some("Request not found or expired".to_string()),
            };
            (StatusCode::NOT_FOUND, Json(response))
        }
    }
}

/// GET /health - Health check endpoint
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Generate a random request ID
fn generate_request_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}

/// Extract app name from origin URL
fn extract_app_name(origin: &str) -> String {
    origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin)
        .split('/')
        .next()
        .unwrap_or(origin)
        .to_string()
}

/// Start the HTTP server
pub async fn run_server<S: SignRequestStore>(state: HttpState<S>, port: u16) -> anyhow::Result<()> {
    let router = create_router(state);
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    tracing::info!("HTTP server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;

    Ok(())
}
