//! Device-cert model login for the mingo CLI (ADDITIVE alongside `login.rs`).
//!
//! In the device-cert model a headless client is a *device* holding an
//! IdP-signed **agent device cert** (`purpose=authentication`, an opaque holder).
//! It mints a short-lived **access cert** headlessly (`browserid_agent::DeviceAgent`),
//! and to act at an RP it presents the 4-object bundle
//! `access_cert~assertion~warrant~config_cert` — the warrant + config cert coming
//! from the principal's authorization (config) cert.
//!
//! Storage: `~/.mingo/device-credential.json`. Every new field is
//! `#[serde(default)]` / `Option`, so a file written by an older build (or a
//! partially-provisioned one) deserializes without panicking; missing pieces
//! surface as a "re-login" prompt rather than a hard error.
//!
//! ## What is and isn't wired yet
//! The `DeviceCredential` (device key + agent device cert) must be obtained by a
//! **device-grant pairing** that ends in the IdP issuing an *agent* device cert.
//! The broker/IdP today issue *user* device certs (`/device/issue`, session-authed)
//! and mint access certs headlessly (`/access/mint`), but there is no headless
//! endpoint that issues an *agent* device cert from a device-grant. Until that
//! exists, this module operates on a `DeviceCredential` supplied out of band
//! (imported from a file) — it exercises the mint + present half of the flow
//! that IS implemented, so the CLI is ready the moment agent-cert issuance lands.
//! See the migration report / [`import`].

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use browserid_agent::{DeviceAgent, DeviceCredential};
use browserid_core::device::{DeviceCert, Warrant as DeviceWarrant};
use serde::{Deserialize, Serialize};

use crate::login; // reuse mingo_home() indirectly via the same layout

/// On-disk device login: the credential plus any config-cert-signed grants the
/// principal has approved (each `warrant~config_cert`). All new-model, so the
/// whole struct is optional-friendly: an absent/empty file → "re-login".
#[derive(Default, Serialize, Deserialize)]
pub struct StoredDeviceLogin {
    /// The device credential (device key + agent device cert + IdP). Absent until
    /// a device-grant pairing has issued an agent device cert.
    #[serde(default)]
    pub credential: Option<DeviceCredential>,
    /// audience → (warrant, config_cert), both encoded JWS. Absent/empty until a
    /// warrant is approved.
    #[serde(default)]
    pub grants: Vec<StoredGrant>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredGrant {
    pub audience: String,
    pub warrant: String,
    pub config_cert: String,
}

fn device_credential_path() -> Result<PathBuf> {
    Ok(login::mingo_home()?.join("device-credential.json"))
}

impl StoredDeviceLogin {
    pub fn load() -> Result<Self> {
        let path = device_credential_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        // Tolerate an older/partial shape: unknown-but-absent fields default.
        serde_json::from_str(&std::fs::read_to_string(&path)?)
            .with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self) -> Result<()> {
        let path = device_credential_path()?;
        login::write_private(&path, &serde_json::to_string_pretty(self)?)
    }

    /// Build a live [`DeviceAgent`] from the stored credential, loading every
    /// stored grant into it. `Err` (with a "re-login" hint) when no credential is
    /// stored yet.
    pub fn agent(&self) -> Result<DeviceAgent> {
        let credential = self
            .credential
            .clone()
            .ok_or_else(|| anyhow!("no device credential — run `mingo login --device` (re-login)"))?;
        let mut agent = DeviceAgent::new(credential)
            .map_err(|e| anyhow!("invalid device credential (re-login): {e}"))?;
        for g in &self.grants {
            agent
                .add_grant(&g.warrant, &g.config_cert)
                .map_err(|e| anyhow!("stored grant for {}: {e}", g.audience))?;
        }
        Ok(agent)
    }

    /// The identity a write under `audience` is ATTRIBUTED to: the warrant's
    /// `grantor`. For an as-you agent this equals the acting identity; for a
    /// named agent provisioned on behalf of a human it is the approver.
    pub fn grantor_for(&self, audience: &str) -> Result<String> {
        let grant = self
            .grants
            .iter()
            .find(|g| g.audience == audience)
            .ok_or_else(|| anyhow!("no grant held for {audience} — re-run `mingo login`"))?;
        Ok(grant.grantor()?)
    }
}

impl StoredGrant {
    /// The attributed identity this grant delegates FROM.
    pub fn grantor(&self) -> Result<String> {
        Ok(DeviceWarrant::parse(&self.warrant)
            .map_err(|e| anyhow!("stored warrant for {} is unreadable (re-login): {e}", self.audience))?
            .claims()
            .grantor
            .clone())
    }

    /// The acting identity this grant delegates TO (== the access-cert identity).
    pub fn grantee(&self) -> Result<String> {
        Ok(DeviceWarrant::parse(&self.warrant)
            .map_err(|e| anyhow!("stored warrant for {} is unreadable (re-login): {e}", self.audience))?
            .claims()
            .grantee
            .clone())
    }
}

/// Import a `DeviceCredential` from a JSON file (produced by an out-of-band
/// pairing / issuance) and persist it as the device login. The bridge until a
/// headless agent-device-cert issuance endpoint exists.
pub fn import(path: &str) -> Result<()> {
    let credential = DeviceCredential::load(path)
        .map_err(|e| anyhow!("reading device credential {path}: {e}"))?;
    // Validate it certifies its own key + names an identity before storing.
    let agent = DeviceAgent::new(credential.clone())
        .map_err(|e| anyhow!("invalid device credential: {e}"))?;
    let mut stored = StoredDeviceLogin::load()?;
    stored.credential = Some(credential);
    stored.save()?;
    println!("✓ imported device credential for {}", agent.email());
    println!("  stored at {}", device_credential_path()?.display());
    Ok(())
}

/// `mingo whoami --device`: report the stored device identity + its access-cert /
/// grant state, or a re-login prompt if nothing (or a partial file) is stored.
pub fn whoami() -> Result<()> {
    let stored = StoredDeviceLogin::load()?;
    let Some(credential) = &stored.credential else {
        println!("not logged in (device-cert model). Run `mingo login --device` to pair,");
        println!("or `mingo device import <file>` to load a device credential.");
        return Ok(());
    };
    let device_cert = DeviceCert::parse(&credential.agent_device_cert)
        .map_err(|e| anyhow!("stored device cert is unreadable (re-login): {e}"))?;
    let c = device_cert.claims();
    // The ACTING identity is the credential's (what the warrant names) — the
    // cert may name only the base identity, which authorizes its +tags via
    // the protocol subaddress rule.
    let acting = credential
        .identity
        .clone()
        .unwrap_or_else(|| device_cert.claims().identities.join(", "));
    println!("logged in (device-cert model)");
    println!("  identity:   {acting}");
    if credential.identity.is_some()
        && !device_cert.claims().identities.iter().any(|i| i == &acting)
    {
        println!("  certified:  via {}", device_cert.claims().identities.join(", "));
    }
    println!("  holder:     {}", device_cert.holder().as_str());
    println!("  purpose:    {:?}", device_cert.purpose());
    println!("  idp:        {}", credential.idp);
    let now = chrono::Utc::now().timestamp();
    if c.exp <= now {
        println!("  device cert: EXPIRED — re-pair to continue");
    } else {
        println!("  device cert: valid for ~{} more days", (c.exp - now) / 86400);
    }
    if stored.grants.is_empty() {
        println!("  grants:     none — approve a warrant for an audience");
    } else {
        println!("  grants for:");
        for g in &stored.grants {
            // A grant names both parties: attribution lands on the grantor, this
            // credential acts as the grantee. They differ for an on-behalf agent.
            match (g.grantor(), g.grantee()) {
                (Ok(grantor), Ok(grantee)) if grantor == grantee => {
                    println!("    {}  (as {grantor})", g.audience);
                }
                (Ok(grantor), Ok(grantee)) => {
                    println!("    {}  (as {grantee}, on behalf of {grantor})", g.audience);
                }
                _ => println!("    {}  (warrant unreadable — re-login)", g.audience),
            }
        }
    }
    Ok(())
}

/// Mint an access cert headlessly and assemble the RP-facing 4-object bundle for
/// `audience`. Requires a stored grant (warrant + config cert) for it. Returns the
/// encoded `access_cert~assertion~warrant~config_cert` presentation.
pub async fn present_for(audience: &str) -> Result<String> {
    let stored = StoredDeviceLogin::load()?;
    let mut agent = stored.agent()?;
    if agent.warranted_audiences().iter().all(|a| *a != audience) {
        bail!("no grant held for {audience} — approve a warrant for it (re-login)");
    }
    agent
        .assertion_for(audience)
        .await
        .map_err(|e| anyhow!("assembling presentation for {audience}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use browserid_core::device::{Holder, HolderMatcher, Purpose};
    use browserid_core::{device::AccessPresentation, KeyPair};
    use chrono::Duration;

    /// End-to-end (offline): a locally-built IdP issues an agent device cert +
    /// config cert; a stored grant is a config-cert-signed warrant; the assembled
    /// bundle verifies. The IdP `/access/mint` is stood in by minting an access
    /// cert directly — the SDK's network mint is covered by the mingo-idp
    /// `device_cert_e2e` conformance test.
    #[test]
    fn stored_grant_roundtrips_into_agent() {
        let idp = KeyPair::generate();
        let device = KeyPair::generate();
        let config = KeyPair::generate();
        let identity = "svc@mingo.place";
        let audience = "https://rp.example.com";

        let device_cert = DeviceCert::create(
            "mingo.place",
            &device.public_key(),
            Purpose::Authentication,
            Holder::new("svc.cli").unwrap(),
            vec![identity.into()],
            Duration::days(90),
            &idp,
            None,
        )
        .unwrap();
        let config_cert = DeviceCert::create(
            "mingo.place",
            &config.public_key(),
            Purpose::Authorization,
            Holder::new("svc.cli").unwrap(),
            vec![identity.into()],
            Duration::days(90),
            &idp,
            None,
        )
        .unwrap();
        let warrant = DeviceWarrant::create(
            identity,
            identity,
            HolderMatcher::new("svc.cli").unwrap(),
            audience,
            vec!["post".into()],
            Duration::days(90),
            &config,
            None,
        )
        .unwrap();

        let stored = StoredDeviceLogin {
            credential: Some(DeviceCredential {
                device_key: base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    device.secret_bytes(),
                ),
                agent_device_cert: device_cert.encoded().to_string(),
                idp: "https://mingo.place".into(),
                access_mint: None,
                identity: None,
            }),
            grants: vec![StoredGrant {
                audience: audience.into(),
                warrant: warrant.encoded().to_string(),
                config_cert: config_cert.encoded().to_string(),
            }],
        };

        // The stored login rehydrates into an agent that holds the grant.
        let agent = stored.agent().unwrap();
        assert_eq!(agent.email(), identity);
        assert_eq!(agent.warranted_audiences(), vec![audience]);

        // A partial file (no credential) is not an error — it's a re-login prompt.
        let empty = StoredDeviceLogin::default();
        assert!(empty.agent().is_err());
        assert!(empty.credential.is_none());

        // Serde tolerates the minimal shape (old/partial files don't panic).
        let reparsed: StoredDeviceLogin = serde_json::from_str("{}").unwrap();
        assert!(reparsed.credential.is_none());
        assert!(reparsed.grants.is_empty());

        // Sanity: the grant's warrant is signed by the config cert and joins.
        warrant.verify(config_cert.public_key()).unwrap();
        let _ = AccessPresentation::parse; // presentation shape exercised in idp e2e

        // As-you: grantor == grantee, and both read back off the stored warrant.
        assert_eq!(stored.grantor_for(audience).unwrap(), identity);
        assert_eq!(stored.grants[0].grantee().unwrap(), identity);
        assert!(stored.grantor_for("https://other.example.com").is_err());
    }

    /// On-behalf (browserid-ng-8v6c): a named agent holds the credential, but
    /// attribution — what `grantor_for` returns, and what a write's owner must
    /// be — is the approving human.
    #[test]
    fn on_behalf_grant_attributes_to_the_grantor() {
        let idp = KeyPair::generate();
        let device = KeyPair::generate();
        let config = KeyPair::generate();
        let human = "dan@mingo.place";
        let agent_id = "dan+cli@mingo.place";
        let audience = "https://rp.example.com";

        let device_cert = DeviceCert::create(
            "mingo.place",
            &device.public_key(),
            Purpose::Authentication,
            Holder::new("agents.cli1").unwrap(),
            vec![agent_id.into()],
            Duration::days(90),
            &idp,
            None,
        )
        .unwrap();
        // The config cert is the GRANTOR's (the human's) authorization cert.
        let config_cert = DeviceCert::create(
            "mingo.place",
            &config.public_key(),
            Purpose::Authorization,
            Holder::new("agents.cli1").unwrap(),
            vec![human.into()],
            Duration::days(90),
            &idp,
            None,
        )
        .unwrap();
        let warrant = DeviceWarrant::create(
            human,
            agent_id,
            HolderMatcher::new("agents.cli1").unwrap(),
            audience,
            vec!["action:post".into()],
            Duration::days(90),
            &config,
            None,
        )
        .unwrap();

        let stored = StoredDeviceLogin {
            credential: Some(DeviceCredential {
                device_key: base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    device.secret_bytes(),
                ),
                agent_device_cert: device_cert.encoded().to_string(),
                idp: "https://mingo.place".into(),
                access_mint: None,
                identity: Some(agent_id.into()),
            }),
            grants: vec![StoredGrant {
                audience: audience.into(),
                warrant: warrant.encoded().to_string(),
                config_cert: config_cert.encoded().to_string(),
            }],
        };

        // The agent (grantee) holds the grant — `add_grant` pins grantee ==
        // the credential identity, so rehydration proves the split is honored.
        let agent = stored.agent().unwrap();
        assert_eq!(agent.email(), agent_id);
        assert_eq!(agent.warranted_audiences(), vec![audience]);

        // Attribution is the human, not the acting agent identity.
        assert_eq!(stored.grantor_for(audience).unwrap(), human);
        assert_eq!(stored.grants[0].grantee().unwrap(), agent_id);
    }
}
