//! HTTP server for web-based auth
//!
//! Exposes the sign request flow over HTTP for browser-based apps.
//! Listens on localhost:7890 by default.

use std::sync::Arc;
use tokio::sync::RwLock;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use serde::{Deserialize, Serialize};

use crate::ipc::{SignRequest, SignRequestStatus};

/// Shared state for HTTP handlers
pub type HttpState<S> = Arc<RwLock<S>>;

// ===========================================================================
// Phase 7.3 — browser read + submit API (`/v1/*`)
//
// A thin HTTP surface over the daemon's confirmed state and DA submit path, so
// a browser client can read objects/lists, fetch SBOQ proofs, submit signed
// wire bytes, and check freshness — without the Unix-socket IPC. The data
// operations are abstracted behind [`RepoApi`], implemented by the daemon's
// concrete state in `main.rs` (it owns the repo set + the DA client).
// ===========================================================================

/// An error from a `/v1/*` data operation, carrying the HTTP status to return.
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
}

impl ApiError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::NOT_FOUND, message: msg.into() }
    }
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, message: msg.into() }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, message: msg.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}

/// A confirmed object rendered for the browser. `value` is the parsed JSON
/// payload when the content is `application/json`; `payload_text` is the raw
/// (lossy-UTF-8) payload, useful for JWT identities/domains. `sboq` is present
/// only when a proof was requested.
#[derive(Debug, Serialize)]
pub struct ObjectView {
    pub path: String,
    pub id: String,
    pub creator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_ref: Option<String>,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_schema: Option<String>,
    pub block: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hlc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    pub object_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    pub payload_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sboq: Option<String>,
}

/// What a list query selects: objects under a path prefix, or by content schema.
pub enum ListSelector {
    Prefix(String),
    Schema(String),
}

/// Latest `(block, state_root)` for freshness checks.
#[derive(Debug, Serialize)]
pub struct StateRootView {
    pub block: u64,
    pub state_root: String,
}

/// Result of a successful DA submission.
#[derive(Debug, Serialize)]
pub struct SubmitResultView {
    pub submission_id: String,
}

/// Data operations the `/v1/*` routes need from the daemon's state. `repo` (the
/// repo's URI or local path) selects which followed repo to serve; when `None`
/// the daemon uses its sole repo (an error if it follows several).
#[async_trait::async_trait]
pub trait RepoApi: Send + Sync + 'static {
    fn get_object(
        &self,
        repo: Option<&str>,
        path: &str,
        id: &str,
        with_proof: bool,
    ) -> Result<ObjectView, ApiError>;

    fn list_objects(
        &self,
        repo: Option<&str>,
        selector: &ListSelector,
    ) -> Result<Vec<ObjectView>, ApiError>;

    fn state_root(&self, repo: Option<&str>) -> Result<StateRootView, ApiError>;

    async fn submit(&self, data: Vec<u8>) -> Result<SubmitResultView, ApiError>;
}

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
pub fn create_router<S: SignRequestStore + RepoApi>(state: HttpState<S>) -> Router {
    // CORS: the daemon is a localhost convenience server with no credentialed
    // requests, so reflect any origin — the browser client may be served from
    // any dev origin or the Mingo site. Reads/submit carry no cookies.
    let cors = CorsLayer::new()
        .allow_origin(Any)
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
        .route("/v1/object", get(get_object_v1::<S>))
        .route("/v1/list", get(list_objects_v1::<S>))
        .route("/v1/submit", post(submit_v1::<S>))
        .route("/v1/state-root", get(state_root_v1::<S>))
        .layer(cors)
        .layer(private_network)  // Apply to all responses including CORS preflight
        .with_state(state)
}

/// Query params for `GET /v1/object`.
#[derive(Debug, Deserialize)]
pub struct ObjectQuery {
    /// The object's prefix path (with trailing slash), e.g. `/communities/cooks/`.
    pub path: String,
    /// The object id, e.g. `community`.
    pub id: String,
    /// Optional repo selector (URI or local path); defaults to the sole repo.
    pub repo: Option<String>,
    /// `1`/`true` to include the SBOQ proof.
    pub proof: Option<String>,
}

/// `GET /v1/object?path=&id=&repo=&proof=` — read one confirmed object.
async fn get_object_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    Query(q): Query<ObjectQuery>,
) -> Result<Json<ObjectView>, ApiError> {
    let with_proof = matches!(q.proof.as_deref(), Some("1") | Some("true"));
    let state = state.read().await;
    let view = state.get_object(q.repo.as_deref(), &q.path, &q.id, with_proof)?;
    Ok(Json(view))
}

/// Query params for `GET /v1/list` (exactly one of `prefix`/`schema`).
#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub prefix: Option<String>,
    pub schema: Option<String>,
    pub repo: Option<String>,
}

/// `GET /v1/list?prefix=` or `?schema=` — enumerate confirmed objects.
async fn list_objects_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    Query(q): Query<ListParams>,
) -> Result<Json<Vec<ObjectView>>, ApiError> {
    let selector = match (q.prefix, q.schema) {
        (Some(p), None) => ListSelector::Prefix(p),
        (None, Some(s)) => ListSelector::Schema(s),
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request("provide exactly one of `prefix` or `schema`"))
        }
        (None, None) => {
            return Err(ApiError::bad_request("`prefix` or `schema` query is required"))
        }
    };
    let state = state.read().await;
    let views = state.list_objects(q.repo.as_deref(), &selector)?;
    Ok(Json(views))
}

/// `POST /v1/submit` — submit raw signed wire bytes to the DA layer. The body
/// is the wire-format envelope(s); the daemon forwards it unchanged.
async fn submit_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    body: Bytes,
) -> Result<Json<SubmitResultView>, ApiError> {
    if body.is_empty() {
        return Err(ApiError::bad_request("empty submit body"));
    }
    let state = state.read().await;
    let result = state.submit(body.to_vec()).await?;
    Ok(Json(result))
}

/// Query params for `GET /v1/state-root`.
#[derive(Debug, Deserialize)]
pub struct StateRootParams {
    pub repo: Option<String>,
}

/// `GET /v1/state-root?repo=` — latest `(block, state_root)` for freshness.
async fn state_root_v1<S: RepoApi>(
    State(state): State<HttpState<S>>,
    Query(q): Query<StateRootParams>,
) -> Result<Json<StateRootView>, ApiError> {
    let state = state.read().await;
    let view = state.state_root(q.repo.as_deref())?;
    Ok(Json(view))
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

/// Start the HTTP server. Binds `127.0.0.1:<port>` by default; override the full
/// bind address with `SBO_HTTP_BIND` (e.g. `0.0.0.0:7890` to reach it over a
/// LAN/tailnet — CORS is already permissive, so only do this on a trusted
/// network).
pub async fn run_server<S: SignRequestStore + RepoApi>(state: HttpState<S>, port: u16) -> anyhow::Result<()> {
    let router = create_router(state);
    let bind = std::env::var("SBO_HTTP_BIND").unwrap_or_else(|_| format!("127.0.0.1:{port}"));

    tracing::info!("HTTP server listening on http://{}", bind);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use tower::ServiceExt; // for `oneshot`

    /// A mock state implementing both traits the router requires, so we can
    /// exercise routing + (de)serialization of the `/v1/*` surface in isolation.
    #[derive(Default)]
    struct MockState {
        requests: HashMap<String, SignRequest>,
    }

    impl SignRequestStore for MockState {
        fn create_sign_request(&mut self, request: SignRequest) -> String {
            let id = request.request_id.clone();
            self.requests.insert(id.clone(), request);
            id
        }
        fn get_sign_request(&self, request_id: &str) -> Option<&SignRequest> {
            self.requests.get(request_id)
        }
    }

    fn sample_view() -> ObjectView {
        ObjectView {
            path: "/communities/cooks/".to_string(),
            id: "community".to_string(),
            creator: "sys".to_string(),
            owner_ref: None,
            content_type: "application/json".to_string(),
            content_schema: Some("community.v1".to_string()),
            block: 7,
            hlc: None,
            prev: None,
            object_hash: "00".repeat(32),
            value: Some(serde_json::json!({ "name": "Cooks" })),
            payload_text: "{\"name\":\"Cooks\"}".to_string(),
            sboq: None,
        }
    }

    #[async_trait::async_trait]
    impl RepoApi for MockState {
        fn get_object(
            &self,
            _repo: Option<&str>,
            path: &str,
            id: &str,
            with_proof: bool,
        ) -> Result<ObjectView, ApiError> {
            if id == "missing" {
                return Err(ApiError::not_found("object not found"));
            }
            let mut v = sample_view();
            v.path = path.to_string();
            v.id = id.to_string();
            if with_proof {
                v.sboq = Some("SBOQ/0.2".to_string());
            }
            Ok(v)
        }
        fn list_objects(
            &self,
            _repo: Option<&str>,
            selector: &ListSelector,
        ) -> Result<Vec<ObjectView>, ApiError> {
            match selector {
                ListSelector::Prefix(_) | ListSelector::Schema(_) => Ok(vec![sample_view()]),
            }
        }
        fn state_root(&self, _repo: Option<&str>) -> Result<StateRootView, ApiError> {
            Ok(StateRootView { block: 7, state_root: "ab".repeat(32) })
        }
        async fn submit(&self, _data: Vec<u8>) -> Result<SubmitResultView, ApiError> {
            Ok(SubmitResultView { submission_id: "sub-123".to_string() })
        }
    }

    fn router() -> Router {
        create_router(Arc::new(RwLock::new(MockState::default())))
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn get_object_returns_view() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/object?path=/communities/cooks/&id=community")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["id"], "community");
        assert_eq!(json["content_schema"], "community.v1");
        assert!(json.get("sboq").is_none(), "no proof unless requested");
    }

    #[tokio::test]
    async fn get_object_with_proof_includes_sboq() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/object?path=/x/&id=y&proof=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["sboq"], "SBOQ/0.2");
    }

    #[tokio::test]
    async fn get_missing_object_is_404() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/object?path=/x/&id=missing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_requires_exactly_one_selector() {
        // neither
        let resp = router()
            .oneshot(Request::builder().uri("/v1/list").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // both
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/list?prefix=/communities/&schema=community.v1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_by_prefix_returns_array() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/list?prefix=/communities/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json.is_array());
        assert_eq!(json.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn submit_returns_submission_id() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/submit")
                    .body(Body::from(vec![1u8, 2, 3]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["submission_id"], "sub-123");
    }

    #[tokio::test]
    async fn empty_submit_is_400() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/v1/submit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn state_root_returns_block_and_root() {
        let resp = router()
            .oneshot(
                Request::builder()
                    .uri("/v1/state-root")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["block"], 7);
        assert_eq!(json["state_root"].as_str().unwrap().len(), 64);
    }
}
