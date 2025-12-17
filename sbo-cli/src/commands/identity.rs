//! Identity commands
//!
//! Commands for creating and managing identity objects with identity.v1 schema.

use anyhow::Result;
use sbo_core::crypto::{ContentHash, Signature, SigningKey};
use sbo_core::message::{Action, Id, Message, ObjectType, Path};
use sbo_core::schema::Identity;
use sbo_daemon::config::Config;
use sbo_daemon::ipc::{IpcClient, Request, Response};
use std::collections::HashMap;

/// Create an identity object
pub async fn create(
    claim: Option<String>,
    name: Option<String>,
    description: Option<String>,
    avatar: Option<String>,
    website: Option<String>,
    binding: Option<String>,
    dry_run: bool,
) -> Result<()> {
    // Load config
    let config = Config::load(&Config::config_path())?;

    // Look for a key in ~/.sbo/keys/
    let sbo_dir = Config::sbo_dir();
    let keys_dir = sbo_dir.join("keys");

    // Try to find a default key file
    let key_path = keys_dir.join("default.key");

    let signing_key = if key_path.exists() {
        // Load the signing key
        let key_hex = std::fs::read_to_string(&key_path)?;
        let key_hex = key_hex.trim();

        // Parse the hex string to bytes
        let key_bytes = hex::decode(key_hex)?;
        if key_bytes.len() != 32 {
            anyhow::bail!("Key file must contain 32 bytes (64 hex chars), got {}", key_bytes.len());
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&key_bytes);

        SigningKey::from_bytes(&bytes)
    } else {
        // No key found - generate one
        println!("No signing key found at: {}", key_path.display());
        println!("Generating new key...");

        std::fs::create_dir_all(&keys_dir)?;
        let signing_key = SigningKey::generate();

        // Save the key
        let key_hex = hex::encode(signing_key.to_bytes());
        std::fs::write(&key_path, &key_hex)?;
        println!("Saved new key to: {}", key_path.display());

        signing_key
    };

    let public_key = signing_key.public_key();
    let public_key_str = public_key.to_string();

    // Build the identity object
    let mut identity = Identity::new(public_key_str.clone());

    if let Some(display_name) = name {
        identity.display_name = Some(display_name);
    }
    if let Some(desc) = description {
        identity.description = Some(desc);
    }
    if let Some(av) = avatar {
        identity.avatar = Some(av);
    }
    if let Some(ws) = website {
        let mut links = HashMap::new();
        links.insert("website".to_string(), ws);
        identity.links = Some(links);
    }
    if let Some(b) = binding {
        identity.binding = Some(b);
    }

    // Serialize to JSON
    let payload_bytes = identity.to_json()?;
    let payload_pretty = identity.to_json_pretty()?;

    if dry_run {
        println!("Identity object (identity.v1 schema):");
        println!("{}", payload_pretty);
        println!();
        println!("Signing key: {}", public_key_str);
        println!("Payload size: {} bytes", payload_bytes.len());
        println!();
        if claim.is_some() {
            println!("Would post to: /sys/names/{}/identity", claim.as_ref().unwrap());
        } else {
            println!("Add --claim <name> to specify the name to claim");
        }
        println!();
        println!("To submit, run without --dry-run");
        return Ok(());
    }

    // For actual submission, we need a claim name
    let claim_name = match claim {
        Some(n) => n,
        None => {
            // Print the identity and instructions
            println!("Identity object (identity.v1 schema):");
            println!("{}", payload_pretty);
            println!();
            println!("Signing key: {}", public_key_str);
            println!();
            println!("To submit this identity, add --claim <name>");
            println!("  Example: sbo identity create --claim alice --name \"Alice\"");

            // Save the identity JSON to a file for convenience
            let identity_file = sbo_dir.join("identity.json");
            std::fs::write(&identity_file, &payload_bytes)?;
            println!();
            println!("Saved identity JSON to: {}", identity_file.display());
            return Ok(());
        }
    };

    // Build the SBO message
    let sbo_path = format!("/sys/names/{}/", claim_name);
    let path = Path::parse(&sbo_path)?;
    let id = Id::new("identity")?;

    // Create placeholder signature (will be replaced by sign())
    let placeholder_sig = Signature::parse(&"0".repeat(128))?;

    let mut msg = Message {
        action: Action::Post,
        path,
        id,
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: placeholder_sig,
        content_type: Some("application/json".to_string()),
        content_hash: Some(ContentHash::sha256(&payload_bytes)),
        payload: Some(payload_bytes.clone()),
        owner: None,
        creator: None,
        content_encoding: None,
        content_schema: Some("identity.v1".to_string()),
        policy_ref: None,
        related: None,
    };

    // Sign the message
    msg.sign(&signing_key);

    // Serialize to wire format
    let wire_bytes = sbo_core::wire::serialize(&msg);

    println!("Identity object (identity.v1 schema):");
    println!("{}", payload_pretty);
    println!();
    println!("Signing key: {}", public_key_str);
    println!("Path: {}", sbo_path);
    println!("ID: identity");
    println!("Wire format size: {} bytes", wire_bytes.len());
    println!();

    // Submit via daemon
    println!("Submitting to network...");

    let client = IpcClient::new(config.daemon.socket_path);

    // Get the first repo to submit to
    match client.request(Request::RepoList).await {
        Ok(Response::Ok { data }) => {
            if let Some(repos) = data.as_array() {
                if repos.is_empty() {
                    eprintln!("Error: No repos configured. Add one with: sbo repo add <uri> <path>");
                    return Ok(());
                }

                // Use the first repo
                let repo = &repos[0];
                let repo_path = repo["path"].as_str()
                    .ok_or_else(|| anyhow::anyhow!("Invalid repo path"))?;

                // Submit the wire format bytes
                match client.request(Request::Submit {
                    repo_path: std::path::PathBuf::from(repo_path),
                    sbo_path: sbo_path.clone(),
                    id: "identity".to_string(),
                    data: wire_bytes,
                }).await {
                    Ok(Response::Ok { data }) => {
                        println!("✓ Submitted successfully!");
                        if let Some(submission_id) = data["submission_id"].as_str() {
                            println!("  Submission ID: {}", submission_id);
                        }
                        println!();
                        println!("Your identity will be available at:");
                        println!("  {}", sbo_path);
                    }
                    Ok(Response::Error { message }) => {
                        eprintln!("Error submitting: {}", message);
                    }
                    Err(e) => {
                        eprintln!("Failed to submit: {}", e);
                    }
                }
            }
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
        }
        Err(e) => {
            eprintln!("Failed to connect to daemon: {}", e);
            eprintln!("Is the daemon running? Try: sbo daemon start");
        }
    }

    Ok(())
}

/// Show identity information for a name
pub async fn show(name: &str) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    // Query for the identity object at /sys/names/<name>/identity
    println!("Looking up identity for: {}", name);

    // Try to get the object
    match client.request(Request::RepoList).await {
        Ok(Response::Ok { data }) => {
            if let Some(repos) = data.as_array() {
                if repos.is_empty() {
                    println!("No repos configured. Add one with: sbo repo add <uri> <path>");
                    return Ok(());
                }

                // For each repo, try to find the identity
                for repo in repos {
                    if let Some(path) = repo.get("path").and_then(|p| p.as_str()) {
                        // Look for identity file at <repo>/sys/names/<name>/identity.json
                        let identity_path = std::path::Path::new(path)
                            .join("sys")
                            .join("names")
                            .join(name);

                        if identity_path.exists() {
                            // Try to find identity.json in this directory
                            let files: Vec<_> = std::fs::read_dir(&identity_path)?
                                .filter_map(|e| e.ok())
                                .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
                                .collect();

                            if !files.is_empty() {
                                println!("\nFound at: {}", identity_path.display());
                                for file in files {
                                    let content = std::fs::read_to_string(file.path())?;
                                    if let Ok(identity) = serde_json::from_str::<Identity>(&content) {
                                        println!("\nIdentity: {}", name);
                                        println!("  Signing key: {}", identity.signing_key);
                                        if let Some(ref dn) = identity.display_name {
                                            println!("  Display name: {}", dn);
                                        }
                                        if let Some(ref desc) = identity.description {
                                            println!("  Description: {}", desc);
                                        }
                                        if let Some(ref av) = identity.avatar {
                                            println!("  Avatar: {}", av);
                                        }
                                        if let Some(ref links) = identity.links {
                                            println!("  Links:");
                                            for (k, v) in links {
                                                println!("    {}: {}", k, v);
                                            }
                                        }
                                        if let Some(ref b) = identity.binding {
                                            println!("  Binding: {}", b);
                                        }
                                        return Ok(());
                                    }
                                }
                            }
                        }
                    }
                }
                println!("Identity not found for: {}", name);
            }
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
        }
        Err(e) => {
            eprintln!("Failed to connect to daemon: {}", e);
            eprintln!("Is the daemon running? Try: sbo daemon start");
        }
    }

    Ok(())
}
