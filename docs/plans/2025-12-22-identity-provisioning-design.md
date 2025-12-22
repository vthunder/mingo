# Domain-Certified Identity Provisioning Design

## Overview

This design describes how users create domain-certified SBO identities. Unlike self-signed identities where users sign their own identity claims, domain-certified identities are signed by the domain's key, establishing that the domain vouches for the binding between an email address and a public key.

## Use Case

A user with email `alice@sandmill.org` wants to create an SBO identity. The domain (sandmill.org) certifies that this public key belongs to this email address.

## Discovery Document

The discovery document at `/.well-known/sbo` is extended with identity provisioning endpoints:

```json
{
  "version": "1",
  "authentication": "/sbo/login",
  "session": "/sbo/session",
  "session_poll": "/sbo/session/poll",
  "identity": "/sbo/identity",
  "identity_poll": "/sbo/identity/poll"
}
```

## CLI Interface

```bash
# Domain-certified identity (new)
sbo id create --email alice@sandmill.org

# Self-signed identity (existing behavior)
sbo id create alice sbo://sandmill.org/
```

When `--email` is provided, the domain-certified flow is triggered.

## Flow

```
┌──────────┐                              ┌──────────────┐
│   CLI    │                              │  domain.com  │
└────┬─────┘                              └──────┬───────┘
     │                                           │
     │  1. Discovery                             │
     │     GET /.well-known/sbo                  │
     │  ─────────────────────────────────────────>
     │                                           │
     │  2. Generate keypair locally              │
     │                                           │
     │  3. Request identity                      │
     │     POST /sbo/identity                    │
     │     { email, public_key }                 │
     │  ─────────────────────────────────────────>
     │                                           │
     │  4a. If logged in: immediate success      │
     │      { status: "complete",                │
     │        identity_jwt: "..." }              │
     │  <─────────────────────────────────────────
     │                                           │
     │  4b. If not logged in: pending            │
     │      { status: "pending",                 │
     │        request_id, verification_uri,      │
     │        expires_in }                       │
     │  <─────────────────────────────────────────
     │                                           │
     │  5. Print verification_uri for user       │
     │     User visits, logs in at domain        │
     │                                           │
     │  6. Poll for result                       │
     │     POST /sbo/identity/poll               │
     │     { request_id }                        │
     │  ─────────────────────────────────────────>
     │                                           │
     │  7. Receive identity_jwt                  │
     │     { status: "complete",                 │
     │       identity_jwt: "..." }               │
     │  <─────────────────────────────────────────
     │                                           │
     │  8. Wrap JWT in SBO message               │
     │     Post to /sys/names/{local_part}       │
     │                                           │
     │  9. Store key in keyring                  │
     │     Associate with identity               │
     │                                           │
```

## Endpoint Specifications

### POST /sbo/identity

Initiates identity provisioning request.

**Request:**
```json
{
  "email": "alice@sandmill.org",
  "public_key": "ed25519:abc123..."
}
```

**Response (already authenticated):**
```json
{
  "status": "complete",
  "identity_jwt": "eyJhbGciOiJFZERTQSJ9..."
}
```

**Response (needs authentication):**
```json
{
  "status": "pending",
  "request_id": "id-xyz789",
  "verification_uri": "https://sandmill.org/sbo/login?req=id-xyz789",
  "expires_in": 300
}
```

### POST /sbo/identity/poll

Polls for identity provisioning completion.

**Request:**
```json
{
  "request_id": "id-xyz789"
}
```

**Response (pending):**
```json
{
  "status": "pending"
}
```

**Response (complete):**
```json
{
  "status": "complete",
  "identity_jwt": "eyJhbGciOiJFZERTQSJ9..."
}
```

**Response (expired):**
```json
{
  "status": "expired"
}
```

## Identity JWT Format

The domain signs a JWT with the following payload:

```json
{
  "iss": "domain:sandmill.org",
  "sub": "alice@sandmill.org",
  "public_key": "ed25519:abc123...",
  "iat": 1703001234
}
```

- `iss`: Domain issuer in `domain:{domain}` format
- `sub`: Full email address
- `public_key`: User's public key with algorithm prefix
- `iat`: Issued-at timestamp

The JWT is signed with the domain's Ed25519 key (from `/sys/domains/sandmill.org`).

## On-Chain Storage

The identity is stored at `/sys/names/{local_part}` where `local_part` is extracted from the email (e.g., `alice` from `alice@sandmill.org`).

The full email is preserved in the JWT's `sub` field, and the domain certification is indicated by the `iss` field.

## Authentication Page

The authentication page (`/sbo/login`) is shared between:
- Session binding requests
- Identity provisioning requests

The domain looks up the request by ID and displays appropriate UI. After successful authentication, the corresponding poll endpoint returns the signed result.

## Implementation Scope

### Reference Implementation (sbo)
- Update `DiscoveryDocument` struct with `identity` and `identity_poll` fields
- Add `sbo id create --email` flow
- Add daemon handlers for identity provisioning proxy (similar to session binding)

### Domain Implementation (sandmill.org)
- Add `/sbo/identity` endpoint
- Add `/sbo/identity/poll` endpoint
- Update authentication page to handle identity requests
- Add identity JWT signing logic

## Out of Scope

- Domain-custodied keys (user doesn't hold private key) - deferred due to chicken-and-egg problem with posting to chain
- Batch identity creation
- Identity revocation via domain
