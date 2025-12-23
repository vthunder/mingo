//! HTTP server for web-based auth
//!
//! Exposes the sign request flow over HTTP for browser-based apps.
//! Listens on localhost:7890 by default.

use std::sync::Arc;
use tokio::sync::RwLock;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::CorsLayer;
use tower_http::set_header::SetResponseHeaderLayer;
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

/// Query params for the auth popup page
#[derive(Debug, Deserialize)]
pub struct AuthPopupParams {
    /// Origin of the requesting app
    pub origin: String,
    /// Challenge from the app
    pub challenge: String,
    /// Optional email
    pub email: Option<String>,
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
        .allow_headers([
            header::CONTENT_TYPE,
            HeaderName::from_static("access-control-request-private-network"),
        ])
        .expose_headers([
            HeaderName::from_static("access-control-allow-private-network"),
        ]);

    // Private Network Access header - required for public sites to access localhost
    let private_network = SetResponseHeaderLayer::overriding(
        HeaderName::from_static("access-control-allow-private-network"),
        HeaderValue::from_static("true"),
    );

    // Layer order matters: cors handles OPTIONS, then private_network adds header to all responses
    Router::new()
        .route("/auth", get(auth_popup_page::<S>))
        .route("/auth/request", post(create_auth_request::<S>))
        .route("/auth/status/:request_id", get(get_auth_status::<S>))
        .route("/health", get(health_check))
        .layer(cors)
        .layer(private_network)  // Apply to all responses including CORS preflight
        .with_state(state)
}

/// GET /auth - Serve the auth popup page
async fn auth_popup_page<S: SignRequestStore>(
    State(state): State<HttpState<S>>,
    Query(params): Query<AuthPopupParams>,
) -> impl IntoResponse {
    // Create the auth request immediately
    let request_id = generate_request_id();
    let app_name = extract_app_name(&params.origin);

    let request = SignRequest {
        request_id: request_id.clone(),
        app_name: app_name.clone(),
        app_origin: Some(params.origin.clone()),
        email: params.email.clone(),
        challenge: params.challenge.clone(),
        purpose: None,
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

    tracing::info!("HTTP: Created auth popup request {} for {}", request_id, params.origin);

    // Serve HTML page that polls and sends result back to opener
    let html = format!(r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SBO Auth</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }}
        .card {{
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 400px;
        }}
        h1 {{ margin: 0 0 10px 0; font-size: 24px; }}
        .app {{ color: #2563eb; font-weight: 600; }}
        .status {{ margin: 20px 0; color: #666; }}
        .command {{
            background: #1e293b;
            color: #e2e8f0;
            padding: 12px 16px;
            border-radius: 8px;
            font-family: monospace;
            margin: 15px 0;
        }}
        .success {{ color: #059669; }}
        .error {{ color: #dc2626; }}
        .spinner {{
            width: 24px;
            height: 24px;
            border: 3px solid #e2e8f0;
            border-top-color: #2563eb;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <div class="card">
        <h1>SBO Auth</h1>
        <p><span class="app">{app_name}</span> wants to authenticate you</p>
        <div id="status" class="status">
            <div class="spinner"></div>
            <p>Waiting for approval...</p>
        </div>
        <div class="command">sbo auth approve {request_id}</div>
        <p style="font-size: 13px; color: #94a3b8;">Run this command in your terminal</p>
    </div>
    <script>
        const REQUEST_ID = "{request_id}";
        const ORIGIN = "{origin}";

        async function poll() {{
            try {{
                const res = await fetch('/auth/status/' + REQUEST_ID);
                const data = await res.json();

                if (data.status === 'approved') {{
                    document.getElementById('status').innerHTML =
                        '<p class="success">✓ Approved!</p><p>Closing...</p>';

                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: 'sbo:response',
                            payload: {{
                                assertion: data.assertion_jwt,
                                session: data.session_binding_jwt
                            }}
                        }}, ORIGIN);
                    }}

                    setTimeout(() => window.close(), 1000);
                    return;
                }}

                if (data.status === 'rejected') {{
                    document.getElementById('status').innerHTML =
                        '<p class="error">✗ Rejected</p><p>' + (data.reason || '') + '</p>';

                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: 'sbo:error',
                            error: {{ code: 'rejected', message: data.reason || 'Request rejected' }}
                        }}, ORIGIN);
                    }}

                    setTimeout(() => window.close(), 2000);
                    return;
                }}

                if (data.status === 'expired' || data.status === 'not_found') {{
                    document.getElementById('status').innerHTML =
                        '<p class="error">Request expired</p>';

                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: 'sbo:error',
                            error: {{ code: 'expired', message: 'Request expired' }}
                        }}, ORIGIN);
                    }}

                    setTimeout(() => window.close(), 2000);
                    return;
                }}

                // Still pending, continue polling
                setTimeout(poll, 2000);
            }} catch (e) {{
                console.error('Poll error:', e);
                setTimeout(poll, 2000);
            }}
        }}

        // Start polling
        poll();

        // Handle window close
        window.addEventListener('beforeunload', () => {{
            if (window.opener) {{
                window.opener.postMessage({{
                    type: 'sbo:error',
                    error: {{ code: 'closed', message: 'User closed the window' }}
                }}, ORIGIN);
            }}
        }});
    </script>
</body>
</html>"#,
        app_name = html_escape(&app_name),
        request_id = html_escape(&request_id),
        origin = html_escape(&params.origin),
    );

    Html(html)
}

/// Escape HTML special characters
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
