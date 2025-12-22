# Auth Spec Compliance Implementation Plan

*Implementing SBO Auth Specification v0.1 in the reference implementation*

## Overview

Update the reference implementation to comply with the updated auth spec:
- Nested JWT model (user delegation wrapped by domain session binding)
- Unified two-phase session binding flow (request → poll)
- DNS format update (`v=sbo1 r=... h=...`)
- Service discovery via `.well-known/sbo`

**Not in scope:** Domain-hosted endpoints (`.well-known/sbo`, provisioning, login page)

## Architecture Decisions

1. **Daemon role:** Proxy between CLI ↔ domain endpoints, rendezvous between app ↔ CLI
2. **Signing:** CLI signs with permanent key (user delegation) and ephemeral key (assertions)
3. **Session storage:** CLI stores ephemeral keys + session bindings locally in `~/.sbo/sessions/`
4. **Flow:** Same UX as current (app submits challenge → user approves → app gets result)

## Implementation Order

### Phase 1: Core Types

#### 1.1 JWT Types (`sbo-core/src/jwt.rs`)

Add new claim structs:

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct UserDelegationClaims {
    pub iss: String,           // "ed25519:<user_public_key>"
    pub delegate_to: String,   // "ed25519:<ephemeral_key>"
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionBindingClaims {
    pub iss: String,              // "domain:<domain>"
    pub sub: String,              // email
    pub user_delegation: String,  // nested JWT
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthAssertionClaims {
    pub iss: String,    // email
    pub aud: String,    // app origin
    pub nonce: String,  // challenge
    pub iat: u64,
}
```

Add functions:
- `create_user_delegation(user_keypair, ephemeral_pubkey, expiry) -> JWT`
- `create_auth_assertion(ephemeral_keypair, email, aud, nonce) -> JWT`
- `verify_session_binding(session_jwt, domain_key) -> Result<SessionBindingClaims>`
- `verify_auth_assertion(assertion, session_binding, expected_aud, expected_nonce) -> Result<VerifiedAuth>`

#### 1.2 DNS Updates (`sbo-core/src/dns.rs`)

Update `SboRecord`:
```rust
pub struct SboRecord {
    pub repository_uri: String,           // "sbo+raw://avail:turing:506/"
    pub discovery_host: Option<String>,   // None = use domain itself
}
```

Update `parse_record()` for new format:
```
v=sbo1 r=sbo+raw://avail:turing:506/ h=https://auth.example.com
```

Update `resolve_uri()` to use `repository_uri` directly.

Add discovery document types:
```rust
pub struct DiscoveryDocument {
    pub version: String,
    pub authentication: String,   // "/login"
    pub provisioning: String,     // "/.well-known/sbo/session"
    pub authority: Option<String>,
}

pub async fn fetch_discovery(host: &str, domain: &str) -> Result<DiscoveryDocument>
```

**Note:** `_sbo-id` and `resolve_email()` unchanged for now (deferred).

### Phase 2: IPC Updates

#### 2.1 Message Types (`sbo-daemon/src/ipc.rs`)

Update `ApproveSignRequest`:
```rust
pub struct ApproveSignRequest {
    pub request_id: String,
    pub assertion_jwt: String,
    pub session_binding_jwt: String,
}
```

Update response type:
```rust
pub struct SignRequestResult {
    pub status: String,  // "pending" | "approved" | "rejected"
    pub assertion_jwt: Option<String>,
    pub session_binding_jwt: Option<String>,
    pub rejection_reason: Option<String>,
}
```

Add domain proxy messages:
```rust
pub struct RequestSessionBinding {
    pub email: String,
    pub ephemeral_public_key: String,
    pub user_delegation_jwt: Option<String>,
}

pub struct SessionBindingResponse {
    pub request_id: String,
    pub verification_uri: String,
    pub expires_in: u64,
}

pub struct PollSessionBinding {
    pub request_id: String,
}

pub struct PollSessionBindingResponse {
    pub status: String,  // "pending" | "complete" | "expired"
    pub session_binding: Option<String>,
}
```

Remove `SignedAssertion` struct.

### Phase 3: Daemon Handlers

#### 3.1 Update Existing (`sbo-daemon/src/main.rs`)

`handle_approve_sign_request`:
- Accept `assertion_jwt` + `session_binding_jwt`
- Store both JWTs

`handle_get_sign_request_result`:
- Return JWTs instead of old struct

#### 3.2 Add Proxy Handlers

`handle_request_session_binding`:
1. Resolve discovery host from DNS (`h=` field or domain itself)
2. Fetch `.well-known/sbo?domain=X`
3. Follow `authority` delegation if present
4. POST to `{provisioning}?domain=X`
5. Return `{ request_id, verification_uri, expires_in }`

`handle_poll_session_binding`:
1. POST to `{provisioning}/poll?domain=X`
2. Return status + session_binding if complete

Add state for tracking in-flight requests:
```rust
session_requests: HashMap<String, SessionRequest>
```

### Phase 4: CLI Session Storage

#### 4.1 New Module (`sbo-cli/src/session.rs`)

Session file format (`~/.sbo/sessions/{email}.json`):
```json
{
  "session_binding": "<jwt>",
  "ephemeral_private_key": "<hex>",
  "expires_at": 1703087634
}
```

Functions:
- `get_session(email) -> Option<Session>`
- `save_session(email, session_binding, ephemeral_key, expires_at)`
- `is_session_valid(session) -> bool`
- `generate_ephemeral_keypair() -> (PublicKey, SecretKey)`

### Phase 5: CLI Auth Rewrite

#### 5.1 Update `approve` Command (`sbo-cli/src/commands/auth.rs`)

New flow:
1. Fetch request details from daemon
2. Resolve identity for email (existing keyring logic)
3. Check local session storage
   - If valid: reuse
   - If expired/missing: obtain new session binding
4. Sign assertion JWT with ephemeral key
5. Send `ApproveSignRequest { assertion_jwt, session_binding_jwt }` to daemon

Obtaining new session binding:
1. Generate ephemeral keypair
2. Create user delegation JWT (sign with permanent key)
3. Send `RequestSessionBinding` to daemon
4. Print verification URL for user
5. Poll until complete or timeout
6. Store session locally

### Phase 6: Demo App (Last)

#### 6.1 Update Verification (`sbo-auth-demo/src/main.rs`)

Replace old verification with:
1. Decode session binding (outer JWT)
2. Fetch domain key, verify signature
3. Decode user delegation (inner JWT), verify signature
4. Verify user key exists on-chain
5. Decode assertion, verify ephemeral key matches `delegate_to`
6. Verify claims (aud, nonce, iat, email)

## Testing Strategy

- **Unit tests:** JWT creation/verification functions
- **Integration:** Mock domain endpoints or test server
- **Manual:** Full flow with real domain (requires domain implementation)

## Files Modified

| File | Changes |
|------|---------|
| `sbo-core/src/jwt.rs` | +3 claim types, +4 functions |
| `sbo-core/src/dns.rs` | Update SboRecord, parse_record, resolve_uri, add discovery fetch |
| `sbo-daemon/src/ipc.rs` | Update message types, remove SignedAssertion |
| `sbo-daemon/src/main.rs` | Update handlers, add proxy handlers |
| `sbo-cli/src/session.rs` | New file for session storage |
| `sbo-cli/src/commands/auth.rs` | Rewrite approve command |
| `sbo-auth-demo/src/main.rs` | Update verification logic |
