//! mingo-poster delegated signing (mingo-3f3i) — TEMPORARILY DISABLED.
//!
//! The poster flow (per-user agent cert + external warrant request to the
//! broker + server-side SBO write assembly) was built on the classic
//! BrowserID protocol (provisioning-cert chain, identity-key warrants), which
//! the device-cert cutover removed. It returns once re-built on the device
//! model: an agent DEVICE cert for `mingo-poster@mingo.place`, warrants via
//! the broker's device-shaped `/warrant/request` + `/warrant/poll`, and the
//! 4-object presentation in the SBO write path. Until then every endpoint
//! reports the migration clearly instead of half-working.
//!
//! The store's `poster_warrants` rows are retained untouched.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tower_cookies::Cookies;

use crate::routes::Shared;

const DISABLED_REASON: &str =
    "posting-as-you is temporarily unavailable while mingo migrates to the browserid device-cert model";

fn disabled() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": DISABLED_REASON })),
    )
        .into_response()
}

/// POST /poster/enable — disabled during the device-cert migration.
pub async fn enable(State(_st): State<Shared>, _cookies: Cookies) -> Response {
    disabled()
}

/// POST /poster/poll — disabled during the device-cert migration.
pub async fn poll(State(_st): State<Shared>, _cookies: Cookies) -> Response {
    disabled()
}

/// GET /poster/status — reports the capability as unavailable (the SPA shows
/// its enable affordance only when this says enabled, so it degrades cleanly).
pub async fn status(State(_st): State<Shared>, _cookies: Cookies) -> Response {
    Json(serde_json::json!({
        "enabled": false,
        "available": false,
        "reason": DISABLED_REASON,
    }))
    .into_response()
}

/// POST /poster/disable — disabled during the device-cert migration.
pub async fn disable(State(_st): State<Shared>, _cookies: Cookies) -> Response {
    disabled()
}

/// POST /poster/submit — disabled during the device-cert migration.
pub async fn submit(State(_st): State<Shared>, _cookies: Cookies) -> Response {
    disabled()
}
