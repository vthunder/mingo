//! Mingo community builders and the aggregated Mingo genesis batch.
//!
//! These compose the generic SBO genesis primitives (`sbo_core::presets`,
//! `sbo_core::jwt`) into Mingo's specific on-chain layout: a domain-certified
//! `sys`, a pinned broker, a set of starter communities (each a `community.v1`
//! descriptor + an open community-scoped `policy.v2` + a `spaces/general`
//! collection config), and the hub root policy. Nothing here is part of SBO
//! itself — it is the Mingo application's genesis.

use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::presets::{collection_config, set_trust_brokers, signed_object};
use sbo_core::wire;

/// Build a `community.v1` descriptor at `/communities/<community_id>/` with
/// `ID: community` (the aggregated layout — Community Spec §Granularity). The
/// descriptor carries no logic; membership/roles/bans are attestations and
/// access control is policy. `policy` points at the community's policy object;
/// `issuer` is the authoritative attestation issuer.
#[allow(clippy::too_many_arguments)]
pub fn community(
    signing_key: &SigningKey,
    community_id: &str,
    name: &str,
    issuer: &str,
    policy: &str,
    description: Option<&str>,
    open: bool,
    created_at: Option<i64>,
) -> Vec<u8> {
    let path = format!("/communities/{community_id}/");
    let payload = serde_json::to_vec(&serde_json::json!({
        "name": name,
        "issuer": issuer,
        "policy": policy,
        "description": description,
        "open": open,
        "created_at": created_at,
    }))
    .expect("community.v1 payload serialization");
    signed_object(
        signing_key,
        &path,
        "community",
        "community.v1",
        "application/json",
        payload,
        None,
        None,
        None,
    )
}

/// Build a closed-membership `policy.v2` for a community, stored at the community
/// **root** `/communities/<community_id>/` with `ID: root`.
///
/// It lives at the community root (not a `policies/` sibling) so the daemon's
/// ancestor-walk `resolve_policy` finds it for every write under the community —
/// `spaces/**`, `members/**`, etc. — without any engine change. The descriptor
/// (`ID: community`) and this policy (`ID: root`) share the prefix but are
/// distinct `(path, id)` objects; policy indexing keys on the prefix alone.
///
/// The `member` role is anyone holding an in-force `membership` attestation from
/// `issuer`; members may post anywhere under the community's `spaces/**`; a `ban`
/// by `issuer` excludes them via `not_attested` (Policy Spec §Attestation-Defined
/// Roles, mirrored by the worked example in `l2_authorization.rs`).
pub fn community_policy(signing_key: &SigningKey, community_id: &str, issuer: &str) -> Vec<u8> {
    let path = format!("/communities/{community_id}/");
    let spaces = format!("/communities/{community_id}/spaces/**");
    let payload = serde_json::to_vec(&serde_json::json!({
        "roles": { "member": [{ "attested": { "type": "membership", "by": issuer } }] },
        "grants": [
            { "to": { "role": "member" }, "can": ["post"], "on": spaces }
        ],
        "restrictions": [
            { "on": spaces, "require": { "not_attested": { "type": "ban", "by": issuer } } }
        ],
    }))
    .expect("policy.v2 payload serialization");
    signed_object(
        signing_key,
        &path,
        "root",
        "policy.v2",
        "application/json",
        payload,
        None,
        None,
        None,
    )
}

/// Like [`community_policy`], but **open** and **community-scoped**: the `member`
/// role accepts a `membership:<community_id>` attestation from ANY issuer —
/// including the subject's own self-attestation (the `by` field is omitted, which
/// the policy engine treats as "any issuer"). This is the "anyone can join by
/// self-issuing a membership" model for `open: true` communities, but a
/// membership in one community does NOT authorize posting in another: the
/// attestation `type` carries the community id, and the matcher filters on `type`
/// (no engine change needed — the same mechanism `role:moderator` uses). Bans are
/// still gated on the community `issuer` so moderation stays with the authority.
pub fn community_policy_open(signing_key: &SigningKey, community_id: &str, issuer: &str) -> Vec<u8> {
    let path = format!("/communities/{community_id}/");
    let spaces = format!("/communities/{community_id}/spaces/**");
    let membership_type = format!("membership:{community_id}");
    let payload = serde_json::to_vec(&serde_json::json!({
        "roles": { "member": [{ "attested": { "type": membership_type } }] },
        "grants": [
            { "to": { "role": "member" }, "can": ["post"], "on": spaces }
        ],
        "restrictions": [
            { "on": spaces, "require": { "not_attested": { "type": "ban", "by": issuer } } }
        ],
    }))
    .expect("policy.v2 payload serialization");
    signed_object(
        signing_key,
        &path,
        "root",
        "policy.v2",
        "application/json",
        payload,
        None,
        None,
        None,
    )
}

/// A starter community in the Mingo aggregated genesis.
pub struct MingoCommunity<'a> {
    /// URL-safe community id (the `/communities/<id>/` segment), e.g. `cooks`.
    pub id: &'a str,
    /// Human-readable name, e.g. `Cooks`.
    pub name: &'a str,
    /// Short description.
    pub description: &'a str,
    /// The authoritative attestation issuer for this community (an email/name).
    pub issuer: &'a str,
}

/// Build the **Mingo aggregated genesis** as one atomic batch (Community Spec
/// §Granularity — several communities in one repository, one genesis, one root
/// policy). Emitted in dependency order so every write before the **hub root
/// policy** is admitted in genesis mode (the daemon allows posts until
/// `/sys/policies/root` exists):
///
/// 1. domain object (`/sys/domains/<domain>`, self-signed by the domain key)
/// 2. domain-certified `sys` identity (`/sys/names/sys`)
/// 3. pinned broker list (`/sys/trust/brokers`) — the on-chain attribution anchor
/// 4. per community: `community.v1`, the community's open-membership `policy.v2`,
///    and a `collection.v1` for `spaces/general/_config`
/// 5. the **hub root policy** (`/sys/policies/root`) — written last
///
/// The hub root policy is the repo-wide fallback (name claims, each user's own
/// namespace). Each community's policy lives at its **root**
/// (`/communities/<id>/`, `ID: root`), so the daemon's ancestor-walk
/// `resolve_policy` resolves it for every write under that community — the
/// per-community scoped `membership`/`ban` rules enforce without any engine
/// change, and each `community.v1`'s `policy` pointer names that same object.
/// All signing for sys-owned objects uses `sys_signing_key`.
#[allow(clippy::too_many_arguments)]
pub fn mingo_genesis(
    domain_signing_key: &SigningKey,
    sys_signing_key: &SigningKey,
    checkpoint_signing_key: &SigningKey,
    domain_name: &str,
    broker: &str,
    communities: &[MingoCommunity<'_>],
    created_at: Option<i64>,
) -> Vec<u8> {
    let domain_public_key = domain_signing_key.public_key();
    let sys_public_key = sys_signing_key.public_key();

    let mut batch = Vec::new();

    // 1. Domain object (self-signed by the domain key).
    let domain_jwt = sbo_core::jwt::create_domain(domain_signing_key, domain_name)
        .expect("domain JWT creation should not fail");
    let domain_bytes = domain_jwt.as_bytes().to_vec();
    let domain_hash = ContentHash::sha256(&domain_bytes);
    let mut domain_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/domains/").unwrap(),
        id: Id::new(domain_name).unwrap(),
        object_type: ObjectType::Object,
        signing_key: domain_public_key,
        signature: Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(domain_hash),
        payload: Some(domain_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("domain.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    domain_msg.sign(domain_signing_key);
    batch.extend(wire::serialize(&domain_msg));

    // 2. Domain-certified sys identity.
    let sys_email = format!("sys@{}", domain_name);
    let sys_jwt = sbo_core::jwt::create_domain_certified_identity(
        domain_signing_key,
        domain_name,
        &sys_email,
        &sys_public_key,
        None,
    )
    .expect("sys JWT creation should not fail");
    let sys_bytes = sys_jwt.as_bytes().to_vec();
    let sys_hash = ContentHash::sha256(&sys_bytes);
    let mut sys_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new("sys").unwrap(),
        object_type: ObjectType::Object,
        signing_key: sys_public_key.clone(),
        signature: Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(sys_hash),
        payload: Some(sys_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    sys_msg.sign(sys_signing_key);
    batch.extend(wire::serialize(&sys_msg));

    // 2b. Key-rooted checkpoint authority identity (`/sys/names/checkpointer`),
    // self-signed by the checkpoint key. The root policy grants it `create` (only,
    // never `update` — checkpoints are write-once) on `/sys/checkpoints/**`, so the
    // daemon can publish `checkpoint.v1` roots signed by this dedicated key without
    // ever holding the `sys` key (State Commitment §Checkpoint authority).
    let checkpoint_public_key = checkpoint_signing_key.public_key();
    let ckpt_jwt = sbo_core::jwt::create_self_signed_identity(checkpoint_signing_key, "checkpointer", None)
        .expect("checkpointer JWT creation should not fail");
    let ckpt_bytes = ckpt_jwt.as_bytes().to_vec();
    let ckpt_hash = ContentHash::sha256(&ckpt_bytes);
    let mut ckpt_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/").unwrap(),
        id: Id::new("checkpointer").unwrap(),
        object_type: ObjectType::Object,
        signing_key: checkpoint_public_key,
        signature: Signature([0u8; 64]),
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(ckpt_hash),
        payload: Some(ckpt_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.v1".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    ckpt_msg.sign(checkpoint_signing_key);
    batch.extend(wire::serialize(&ckpt_msg));

    // 3. Pinned broker list (on-chain attribution trust anchor).
    batch.extend(set_trust_brokers(sys_signing_key, &[broker]));

    // 4. Per-community descriptor + policy + general-space collection config.
    for c in communities {
        // The descriptor's policy pointer names the same object the daemon's
        // ancestor-walk resolves: the community-root policy (ID: root).
        let policy_path = format!("/communities/{}/", c.id);
        batch.extend(community(
            sys_signing_key,
            c.id,
            c.name,
            c.issuer,
            &policy_path,
            Some(c.description),
            true,
            created_at,
        ));
        batch.extend(community_policy_open(sys_signing_key, c.id, c.issuer));
        let general = format!("/communities/{}/spaces/general/", c.id);
        batch.extend(collection_config(
            sys_signing_key,
            &general,
            true,
            Some(5),
            Some(24 * 60 * 60),
            Some("post.v1"),
        ));
    }

    // 5. Hub root policy (written LAST so all prior writes pass in genesis mode).
    // The self-authorizing /sys/dnssec/** grant+restriction are the shared sbo
    // fragment, kept in lockstep with the daemon's `dnssec_proof` predicate.
    let (dnssec_grant, dnssec_restriction) = sbo_core::presets::dnssec_self_auth_policy_entries();
    // Match the checkpoint authority by its PUBLIC KEY, not a name. Policy actors
    // for name-claimed identities canonicalize to `name@domain` (validate.rs
    // resolve_creator), so a bare-name grant `to:"checkpointer"` never matches the
    // `checkpointer@mingo.place` signer. Keying by the fixed pubkey is a clean
    // pubkey compare (evaluate.rs Identity::Key) that sidesteps name resolution
    // entirely — the right match for a machine authority whose key is set here.
    let checkpoint_pubkey = format!(
        "ed25519:{}",
        hex::encode(checkpoint_signing_key.public_key().bytes)
    );
    let policy_payload = serde_json::json!({
        // `admin` is the sys identity. SBO has no superuser; sys-level authority
        // to relocate/remove any object (e.g. moderation, layout migrations) is
        // this explicit, auditable grant — every admin action is a signed,
        // replayable on-chain message. Deny rules still override it.
        "roles": { "admin": ["sys"] },
        "grants": [
            { "to": "*", "can": ["create"], "on": "/sys/names/*" },
            { "to": "owner", "can": ["update", "delete"], "on": "/sys/names/*" },
            { "to": "owner", "can": ["*"], "on": "/u/$owner/**" },
            // Self-authorizing DNSSEC proof refresh (shared sbo fragment): ANY
            // signer may (re)write /sys/dnssec/<domain> because the paired
            // restriction forces the payload to be a valid RFC 9102 proof for
            // that domain. Lets clients keep attribution evidence fresh on their
            // own writes with no privileged refresher. Reused from sbo so the
            // grant/restriction stay in lockstep with the daemon's predicate.
            dnssec_grant,
            // The dedicated checkpoint authority may CREATE (write-once, never
            // update) checkpoint objects. Least privilege: this is the ONLY thing
            // it can do — it is not `admin`.
            { "to": { "key": checkpoint_pubkey }, "can": ["create"], "on": "/sys/checkpoints/**" },
            { "to": { "role": "admin" }, "can": ["post", "transfer", "delete"], "on": "/**" }
        ],
        "restrictions": [
            { "on": "/communities/*/spaces/**", "require": { "not_attested": { "type": "ban" } } },
            dnssec_restriction
        ]
    });
    let policy_bytes = serde_json::to_vec(&policy_payload).unwrap();
    let policy_hash = ContentHash::sha256(&policy_bytes);
    let mut policy_msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/policies/").unwrap(),
        id: Id::new("root").unwrap(),
        object_type: ObjectType::Object,
        signing_key: sys_public_key,
        signature: Signature([0u8; 64]),
        content_type: Some("application/json".to_string()),
        content_hash: Some(policy_hash),
        payload: Some(policy_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("policy.v2".to_string()),
        policy_ref: None,
        related: None,
        hlc: None,
        prev: None,
        auth_cert: None,
        auth_evidence: None,
    };
    policy_msg.sign(sys_signing_key);
    batch.extend(wire::serialize(&policy_msg));

    batch
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a builder's wire bytes, then verify signature + schema acceptance.
    fn parse_verified(wire_bytes: &[u8]) -> Message {
        let msg = wire::parse(wire_bytes).expect("serialized message should parse");
        sbo_core::message::verify_message(&msg).expect("signature should verify");
        sbo_core::schema::validate_schema(&msg).expect("payload should validate against its schema");
        msg
    }

    #[test]
    fn community_builder_roundtrips_and_validates() {
        let key = SigningKey::generate();
        let msg = parse_verified(&community(
            &key,
            "cooks",
            "Cooks",
            "cooks@mingo.place",
            "/communities/cooks/policies/root",
            Some("Home cooks."),
            true,
            Some(1_700_000_000),
        ));
        assert_eq!(msg.path.to_string(), "/communities/cooks/");
        assert_eq!(msg.id.as_str(), "community");
        assert_eq!(msg.content_schema.as_deref(), Some("community.v1"));
        let c = crate::community::parse_community(msg.payload.as_ref().unwrap()).unwrap();
        assert_eq!(c.issuer, "cooks@mingo.place");
        assert_eq!(c.open, Some(true));
    }

    #[test]
    fn community_policy_builder_validates_and_parses_as_policy() {
        let key = SigningKey::generate();
        let msg = parse_verified(&community_policy(&key, "cooks", "cooks@mingo.place"));
        // Stored at the community ROOT so the ancestor-walk resolver finds it.
        assert_eq!(msg.path.to_string(), "/communities/cooks/");
        assert_eq!(msg.id.as_str(), "root");
        let _policy: sbo_core::policy::Policy =
            serde_json::from_slice(msg.payload.as_ref().unwrap()).expect("parses as policy.v2");
    }

    #[test]
    fn root_policy_grants_admin_role_transfer_and_delete() {
        let domain_key = SigningKey::generate();
        let sys_key = SigningKey::generate();
        let ckpt_key = SigningKey::generate();
        let batch = mingo_genesis(
            &domain_key, &sys_key, &ckpt_key, "mingo.place", "id.mingo.place", &[],
            Some(1_700_000_000),
        );
        let msgs = wire::parse_batch(&batch).expect("batch parses");
        let policy_msg = msgs.iter()
            .find(|m| m.path.to_string() == "/sys/policies/" && m.id.as_str() == "root")
            .expect("root policy present");
        // It is a valid policy.v2 document.
        let _typed: sbo_core::policy::Policy =
            serde_json::from_slice(policy_msg.payload.as_ref().unwrap()).expect("parses as policy.v2");
        // The admin role is the sys identity, granted transfer+delete over /**.
        let v: serde_json::Value =
            serde_json::from_slice(policy_msg.payload.as_ref().unwrap()).unwrap();
        assert_eq!(v["roles"]["admin"][0], serde_json::json!("sys"));
        let admin_grant = v["grants"].as_array().unwrap().iter().find(|g| {
            g["to"]["role"] == serde_json::json!("admin") && g["on"] == serde_json::json!("/**")
        }).expect("admin grant on /** present");
        let can: Vec<&str> = admin_grant["can"].as_array().unwrap()
            .iter().filter_map(|c| c.as_str()).collect();
        assert!(can.contains(&"transfer"), "admin must be granted transfer");
        assert!(can.contains(&"delete"), "admin must be granted delete");

        // User namespaces live under the reserved /u/ container, keyed on the
        // owner: `/u/$owner/**` (not root-level `/$owner/**`).
        let owner_grant = v["grants"].as_array().unwrap().iter().find(|g| {
            g["to"] == serde_json::json!("owner") && g["on"] == serde_json::json!("/u/$owner/**")
        });
        assert!(owner_grant.is_some(), "owner namespace grant must be /u/$owner/**");

        // The checkpoint authority is granted CREATE (only) on /sys/checkpoints/**,
        // matched by its public key (not a bare name, which would canonicalize-mismatch).
        let ckpt_grant = v["grants"].as_array().unwrap().iter().find(|g| {
            g["to"].get("key").is_some() && g["on"] == serde_json::json!("/sys/checkpoints/**")
        }).expect("checkpointer key grant present");
        assert!(
            ckpt_grant["to"]["key"].as_str().unwrap().starts_with("ed25519:"),
            "checkpointer grant must match by ed25519 pubkey"
        );
        let ckpt_can: Vec<&str> = ckpt_grant["can"].as_array().unwrap()
            .iter().filter_map(|c| c.as_str()).collect();
        assert_eq!(ckpt_can, vec!["create"], "checkpointer must have create only (write-once), not update");
        // And a key-rooted checkpointer identity exists.
        assert!(
            msgs.iter().any(|m| m.path.to_string() == "/sys/names/" && m.id.as_str() == "checkpointer"),
            "checkpointer identity must be registered at genesis"
        );
        assert!(
            !v["grants"].as_array().unwrap().iter().any(|g| g["on"] == serde_json::json!("/$owner/**")),
            "root-level /$owner/** grant must be gone (moved under /u/)"
        );
    }

    #[test]
    fn mingo_genesis_emits_ordered_batch_with_root_policy_last() {
        let domain_key = SigningKey::generate();
        let sys_key = SigningKey::generate();
        let communities = [
            MingoCommunity { id: "cooks", name: "Cooks", description: "Home cooks.", issuer: "cooks@mingo.place" },
            MingoCommunity { id: "woodworking", name: "Woodworking", description: "Makers.", issuer: "woodworking@mingo.place" },
            MingoCommunity { id: "homelab", name: "Homelab", description: "Self-hosters.", issuer: "homelab@mingo.place" },
        ];
        let ckpt_key = SigningKey::generate();
        let batch = mingo_genesis(
            &domain_key,
            &sys_key,
            &ckpt_key,
            "mingo.place",
            "id.mingo.place",
            &communities,
            Some(1_700_000_000),
        );

        // The batch parses into a stream of well-formed, signature-valid messages.
        let msgs = wire::parse_batch(&batch).expect("batch parses");
        for msg in &msgs {
            sbo_core::message::verify_message(msg).expect("each message verifies");
        }

        // 1 domain + 1 sys + 1 checkpointer + 1 trust + 3 communities * 3 + 1 root policy = 14.
        assert_eq!(msgs.len(), 14);
        // The hub root policy is the final write (genesis-mode ordering).
        let last = msgs.last().unwrap();
        assert_eq!(last.path.to_string(), "/sys/policies/");
        assert_eq!(last.id.as_str(), "root");
        assert_eq!(last.content_schema.as_deref(), Some("policy.v2"));
        // No other root policy precedes it.
        assert!(
            !msgs[..msgs.len() - 1]
                .iter()
                .any(|m| m.path.to_string() == "/sys/policies/" && m.id.as_str() == "root"),
            "root policy must be written exactly once, last"
        );
    }
}
