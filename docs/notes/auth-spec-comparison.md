# Auth Spec vs Current Implementation

*Temporary note - comparison of SBO Auth Specification v0.1 with current sbo-auth-demo implementation*

## Current Implementation (CLI-based)

**Assertion Format:** Simple string `identity_uri:email:challenge:timestamp` with Ed25519 signature (not JWT)

**Flow:**
1. App → Daemon: `SubmitSignRequest` (app_name, origin, email, challenge)
2. User runs `sbo auth approve <id>` in CLI
3. CLI signs with **permanent user key** from keyring
4. App polls daemon, receives signed assertion
5. App verifies signature against on-chain identity

---

## Final Design: Nested JWT with Unified Flow

### Service Discovery

```
DNS: _sbo.example.com TXT "v=sbo1 r=sbo+raw://avail:turing:506/ h=https://auth.example.com"

GET https://auth.example.com/.well-known/sbo
{
  "version": "1",
  "authentication": "/login",
  "provisioning": "/.well-known/sbo/session"
}
```

Multi-tenant hosts use `?domain=example.com` on all endpoints.

### Session Binding Flow (Unified for Browser + CLI)

```
1. POST /.well-known/sbo/session?domain=example.com
   { email, ephemeral_public_key, user_delegation? }

   → { request_id, verification_uri, expires_in }

2. Client directs user to verification_uri
   - Browser: opens popup
   - CLI: prints URL for user

3. User authenticates at domain (if needed)

4. Client polls:
   POST /.well-known/sbo/session/poll?domain=example.com
   { request_id }

   → { status: "pending" } or { status: "complete", session_binding: "..." }
```

**Key insight:** Single implementation on domain side. Browser vs CLI difference is only in how verification URL is presented to user.

### Nested JWT Structure

```
┌────────────────────────────────────────────────────────────────┐
│  Session Binding Certificate (signed by DOMAIN_KEY)            │
│  { iss: "domain:X", sub: "email", user_delegation: "..." }     │
│                                                                │
│   ┌────────────────────────────────────────────────────────┐   │
│   │  User Delegation (signed by USER_KEY)                  │   │
│   │  { iss: "ed25519:X", delegate_to: "ed25519:ephemeral" }│   │
│   └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

### Custody Modes

| Mode | Who signs user delegation |
|------|---------------------------|
| Domain-custodied | Domain (using custodied user key) |
| Self-custody | User themselves |

---

## What Needs to Change/Build

| Component | Current | Needs |
|-----------|---------|-------|
| **Assertion Format** | Custom string format | JWT (RFC 7519, EdDSA) |
| **Session Binding** | Not implemented | Nested JWT + two-phase flow |
| **Verification** | Single signature check | Unwrap nested JWTs, verify both signatures |
| **CLI `sbo auth`** | Signs assertion directly | Request session binding via poll flow |
| **Daemon IPC** | `SignedAssertion` struct | Update for nested JWT structure |

## New Components to Build

### 1. Discovery Document (`/.well-known/sbo`)
- JSON document with authentication + provisioning paths
- Delegation support (authority field)
- Served from discovery host (DNS `h=` field)

### 2. Session Endpoint (`/.well-known/sbo/session`)
- Two-phase: request → poll
- Returns verification_uri for user auth
- Single implementation serves both browser and CLI
- Multi-tenant via `?domain=` parameter

### 3. Browser Polyfill (`sbo-auth-polyfill.js`)
- Fetch discovery document
- Post to provisioning, get verification_uri
- Open popup for user auth
- Poll for session binding
- Store in iframe, sign assertions

### 4. CLI Auth Command
- Same flow as browser
- Print verification URL for user
- Poll until complete

### 5. sbo-core JWT additions
- `UserDelegationClaims` struct
- `SessionBindingClaims` struct
- `AuthAssertionClaims` struct
- Nested JWT verification function

## Reference Files
- Spec: `/Users/thunder/src/sbo/specs/SBO Auth Specification v0.1.md`
- Identity Spec: `/Users/thunder/src/sbo/specs/SBO Identity Specification v0.1.md`
- Current demo: `/Users/thunder/src/sbo/reference_impl/sbo-auth-demo/src/main.rs`
- Current CLI auth: `/Users/thunder/src/sbo/reference_impl/sbo-cli/src/commands/auth.rs`
- JWT implementation: `/Users/thunder/src/sbo/reference_impl/sbo-core/src/jwt.rs`
