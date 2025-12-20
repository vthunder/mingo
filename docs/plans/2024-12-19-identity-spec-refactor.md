# SBO Identity Spec Refactor Design

## Problem

Identity-related content is scattered across multiple specs (Auth, Genesis, Name Resolution, Profile). The current model conflates email-based auth with identity in general, and the sys bootstrap uses a "deprecated" schema.

## Design Decisions

### 1. Single Identity Schema (`identity.v1`)

All identities use JWT format with typed `iss` field:

```json
{
  "iss": "self" | "domain:<domain>",
  "sub": "<identifier>",
  "public_key": "ed25519:<hex>",
  "iat": <unix-timestamp>
}
```

- `iss: "self"` → self-signed (sys, sovereign users)
- `iss: "domain:example.com"` → domain-certified (email users)

Verification:
- Self-signed: JWT signature matches `public_key` in payload
- Domain-certified: JWT signature matches key from `/sys/domains/<domain>`

### 2. Multiple Domains (`/sys/domains/{domain}`)

Domain objects at `/sys/domains/{domain}` using `domain.v1` schema:

```json
{
  "iss": "self",
  "sub": "example.com",
  "public_key": "ed25519:<DOMAIN_KEY>",
  "iat": 1234567890
}
```

- Always self-signed
- Policy controls who can create domains (default: sys only)

### 3. Two Genesis Modes

**Mode A: Self-signed sys** (personal repos)
```
1. POST /sys/names/sys      (iss: "self")
2. POST /sys/policies/root  (signed by sys)
```

**Mode B: Domain-certified sys** (organizations)
```
1. POST /sys/domains/org.com  (iss: "self")
2. POST /sys/names/sys        (iss: "domain:org.com")
3. POST /sys/policies/root    (signed by sys)
```

### 4. Identity Links to Profile

Identity has optional `profile` field pointing to profile location:

```json
{
  "iss": "self",
  "sub": "alice",
  "public_key": "ed25519:...",
  "profile": "/alice/profile",
  "iat": 1234567890
}
```

Profile is just display data (no back-link needed):

```json
{
  "display_name": "Alice Smith",
  "bio": "...",
  "avatar": "/alice/avatar.png",
  "links": { ... }
}
```

Verification: profile must be signed by the identity's `public_key`.

### 5. Spec Reorganization

| Spec | Content |
|------|---------|
| **SBO Identity Specification** (new) | identity.v1, domain.v1, profile.v1, resolution semantics |
| **SBO Auth Specification** | Session bindings, auth assertions, browser integration |
| **SBO Genesis Specification** | Bootstrap rules only, references Identity spec |

**Delete:**
- SBO Name Resolution Specification (merged into Identity)
- SBO Profile Schema (merged into Identity)

## Implementation Steps

1. Write new SBO Identity Specification
2. Update SBO Auth Specification (remove identity content, reference Identity spec)
3. Update SBO Genesis Specification (reference Identity spec, two modes)
4. Delete Name Resolution and Profile Schema specs
5. Remove legacy/migration notes from all specs
