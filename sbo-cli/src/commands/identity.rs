//! Identity command implementations (identity.v1 schema)
//!
//! Identities are JWT-based per the SBO Identity Specification.
//! The identity JWT contains: iss ("self"), sub (name), public_key, iat
//! Profile data (display_name, bio, etc.) is stored separately as profile.v1.

use anyhow::Result;
use sbo_core::keyring::Keyring;
use sbo_daemon::config::Config;
use sbo_daemon::ipc::{IpcClient, Request, Response};
use std::collections::HashMap;

/// Create an identity on-chain
pub async fn create(
    uri: &str,
    name: &str,
    key_alias: Option<&str>,
    display_name: Option<&str>,
    description: Option<&str>,
    avatar: Option<&str>,
    website: Option<&str>,
    _binding: Option<&str>,
    dry_run: bool,
    no_wait: bool,
) -> Result<()> {
    // Open keyring and resolve signing key
    let mut keyring = Keyring::open()?;
    let alias = keyring.resolve_alias(key_alias)?;
    let signing_key = keyring.get_signing_key(&alias)?;
    let public_key = signing_key.public_key();

    // Check if profile fields were provided
    let has_profile = display_name.is_some()
        || description.is_some()
        || avatar.is_some()
        || website.is_some();

    // Build profile path if profile fields are provided
    let profile_path = if has_profile {
        Some(format!("/{}/profile", name))
    } else {
        None
    };

    // Create identity JWT using presets
    let wire_bytes = if profile_path.is_some() {
        sbo_core::presets::claim_name_with_profile(
            &signing_key,
            name,
            profile_path.as_ref().unwrap(),
        )
    } else {
        sbo_core::presets::claim_name(&signing_key, name)
    };

    if dry_run {
        // Output the SBO message instead of submitting
        println!("{}", String::from_utf8_lossy(&wire_bytes));
        return Ok(());
    }

    // Connect to daemon and submit
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    // Build identity URI
    let identity_uri = format!("{}/sys/names/{}", uri.trim_end_matches('/'), name);

    println!("Creating identity '{}' at {}", name, uri);
    println!("  Key: {} ({})", alias, public_key.to_string());
    if let Some(ref path) = profile_path {
        println!("  Profile: {}", path);
    }

    match client
        .request(Request::SubmitIdentity {
            uri: uri.to_string(),
            name: name.to_string(),
            data: wire_bytes,
            wait: !no_wait,
        })
        .await
    {
        Ok(Response::Ok { data }) => {
            let status = data["status"].as_str().unwrap_or("unknown");

            match status {
                "verified" => {
                    println!("\n✓ Identity created and verified on-chain");
                    println!("  URI: {}", identity_uri);

                    // Add identity to keyring
                    if let Err(e) = keyring.add_identity(&alias, &identity_uri) {
                        eprintln!("Warning: failed to update keyring: {}", e);
                    }

                    // Note about profile
                    if has_profile {
                        println!("\n  Note: Profile data will be stored at {}", profile_path.as_ref().unwrap());
                        println!("  Create profile with: sbo uri post {}{} <profile.json>",
                            uri.trim_end_matches('/'), profile_path.as_ref().unwrap());
                    }
                }
                "unverified" => {
                    println!("\n○ Identity submitted (unverified)");
                    println!("  URI: {}", identity_uri);
                    if let Some(id) = data["submission_id"].as_str() {
                        println!("  Submission ID: {}", id);
                    }
                    println!("\n  Identity record submitted on chain.");
                    println!("  Check status with: sbo id show {}", name);

                    // Add identity to keyring (unverified - will check later)
                    if let Err(e) = keyring.add_identity(&alias, &identity_uri) {
                        eprintln!("Warning: failed to update keyring: {}", e);
                    }

                    // Note about profile
                    if has_profile {
                        println!("\n  Profile: Create after identity is verified");
                    }
                }
                "pending" => {
                    println!("\n○ Identity submitted but verification timed out");
                    println!("  URI: {}", identity_uri);
                    if let Some(msg) = data["message"].as_str() {
                        println!("  {}", msg);
                    }

                    // Add identity to keyring anyway
                    if let Err(e) = keyring.add_identity(&alias, &identity_uri) {
                        eprintln!("Warning: failed to update keyring: {}", e);
                    }
                }
                _ => {
                    println!("\n? Unknown status: {}", status);
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
            }
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to connect to daemon: {}", e);
            eprintln!("Is the daemon running? Try: sbo daemon start");
            std::process::exit(1);
        }
    }

    Ok(())
}

/// List identities from keyring with verification status
pub async fn list(uri_filter: Option<&str>) -> Result<()> {
    let keyring = Keyring::open()?;
    let config = Config::load(&Config::config_path()).ok();

    // Collect all identities from keyring
    let mut identities: Vec<(String, String, String)> = Vec::new(); // (uri, key_alias, public_key)

    for (alias, entry) in keyring.list() {
        for identity_uri in &entry.identities {
            // Apply URI filter if provided
            if let Some(filter) = uri_filter {
                if !identity_uri.starts_with(filter) {
                    continue;
                }
            }
            identities.push((identity_uri.clone(), alias.clone(), entry.public_key.clone()));
        }
    }

    if identities.is_empty() && keyring.list_emails().is_empty() {
        println!("No identities found in keyring.");
        println!("\nCreate one with: sbo id create <chain-uri> <name>");
        return Ok(());
    }

    // Try to connect to daemon to check verification status and get display URIs
    let client = config.map(|c| IpcClient::new(c.daemon.socket_path));

    // Build a map of resolved_uri -> display_uri from repos
    let mut display_uri_map: HashMap<String, String> = HashMap::new();
    if let Some(ref client) = client {
        if let Ok(Response::Ok { data }) = client.request(Request::RepoList).await {
            if let Some(repos) = data["repos"].as_array() {
                for repo in repos {
                    if let (Some(display), Some(resolved)) = (
                        repo["display_uri"].as_str(),
                        repo["resolved_uri"].as_str(),
                    ) {
                        display_uri_map.insert(resolved.to_string(), display.to_string());
                    }
                }
            }
        }
    }

    // Table 1: Identities
    if !identities.is_empty() {
        println!("Identities:");
        println!(
            "  {:<30} {:<12} {:<12} {}",
            "REPO", "NAME", "LOCAL KEY", "STATUS"
        );
        println!("  {}", "-".repeat(70));

        for (identity_uri, key_alias, _public_key) in &identities {
            // Parse URI to extract chain and name
            let (resolved_chain, name) = parse_identity_uri(identity_uri);

            // Look up display URI from repo map
            let display_chain = display_uri_map
                .get(&resolved_chain)
                .cloned()
                .unwrap_or_else(|| resolved_chain.clone());

            // Check verification status via daemon
            let status = if let Some(ref client) = client {
                match client.request(Request::GetIdentity { uri: identity_uri.clone() }).await {
                    Ok(Response::Ok { .. }) => "verified",
                    Ok(Response::Error { .. }) => "unverified",
                    Err(_) => "unknown",
                }
            } else {
                "unknown"
            };

            println!(
                "  {:<30} {:<12} {:<12} {}",
                truncate(&display_chain, 28),
                truncate(&name, 10),
                truncate(key_alias, 10),
                status
            );
        }
    }

    // Table 2: Email associations
    let emails = keyring.list_emails();
    if !emails.is_empty() {
        if !identities.is_empty() {
            println!();
        }
        println!("Email Associations:");
        println!("  {:<35} {:<45} {}", "EMAIL", "SBO URI", "STATUS");
        println!("  {}", "-".repeat(95));

        for (email, sbo_uri) in emails {
            let status = if let Some(ref client) = client {
                match client.request(Request::GetIdentity { uri: sbo_uri.clone() }).await {
                    Ok(Response::Ok { .. }) => "verified",
                    Ok(Response::Error { .. }) => "unverified",
                    Err(_) => "unknown",
                }
            } else {
                "unknown"
            };
            println!("  {:<35} {:<45} {}", email, truncate(sbo_uri, 43), status);
        }
    }

    Ok(())
}

/// Show detailed identity information
pub async fn show(name_or_uri: &str) -> Result<()> {
    let keyring = Keyring::open()?;
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    // Find matching identities in keyring
    let mut found: Vec<(String, String, String)> = Vec::new(); // (uri, key_alias, public_key)

    for (alias, entry) in keyring.list() {
        for identity_uri in &entry.identities {
            // Match by full URI or by name
            let (_, name) = parse_identity_uri(identity_uri);
            if identity_uri == name_or_uri || name == name_or_uri {
                found.push((identity_uri.clone(), alias.clone(), entry.public_key.clone()));
            }
        }
    }

    if found.is_empty() {
        eprintln!("Identity '{}' not found in keyring.", name_or_uri);
        eprintln!("\nList your identities with: sbo id list");
        return Ok(());
    }

    for (i, (identity_uri, key_alias, public_key)) in found.iter().enumerate() {
        if i > 0 {
            println!("\n{}", "-".repeat(60));
        }

        let (chain, name) = parse_identity_uri(identity_uri);

        // Try to get on-chain data
        match client.request(Request::GetIdentity { uri: identity_uri.clone() }).await {
            Ok(Response::Ok { data }) => {
                // Found on chain - show full details
                println!("Identity: {}", name);
                println!("  URI:          {}", identity_uri);
                println!("  Chain:        {}", chain);
                println!("  Public Key:   {}", data["public_key"].as_str().unwrap_or(&public_key));

                if let Some(dn) = data["display_name"].as_str() {
                    println!("  Display Name: {}", dn);
                }
                if let Some(desc) = data["description"].as_str() {
                    println!("  Description:  {}", desc);
                }
                if let Some(av) = data["avatar"].as_str() {
                    println!("  Avatar:       {}", av);
                }
                if let Some(links) = data["links"].as_object() {
                    if !links.is_empty() {
                        println!("  Links:");
                        for (key, val) in links {
                            if let Some(v) = val.as_str() {
                                println!("    {}: {}", key, v);
                            }
                        }
                    }
                }
                if let Some(b) = data["binding"].as_str() {
                    println!("  Binding:      {}", b);
                }

                println!("  Local Key:    {}", key_alias);
                println!("  Status:       verified ✓");
            }
            Ok(Response::Error { .. }) => {
                // Not found on chain - show keyring data only
                println!("Identity: {}", name);
                println!("  URI:          {}", identity_uri);
                println!("  Chain:        {}", chain);
                println!("  Public Key:   {}", public_key);
                println!("  Local Key:    {}", key_alias);
                println!("  Status:       unverified (not yet on chain)");
            }
            Err(e) => {
                // Daemon error
                println!("Identity: {}", name);
                println!("  URI:          {}", identity_uri);
                println!("  Chain:        {}", chain);
                println!("  Public Key:   {}", public_key);
                println!("  Local Key:    {}", key_alias);
                println!("  Status:       unknown (daemon error: {})", e);
            }
        }
    }

    Ok(())
}

/// Update an existing identity's profile
///
/// With JWT identities, the identity object itself is immutable (contains just
/// public_key and profile path). Profile data (display_name, bio, etc.) is stored
/// in a separate profile.v1 object at the linked path.
pub async fn update(
    uri: &str,
    key_alias: Option<&str>,
    display_name: Option<&str>,
    description: Option<&str>,
    avatar: Option<&str>,
    website: Option<&str>,
    _no_wait: bool,
) -> Result<()> {
    // Parse the identity URI to extract name
    let (chain_uri, name) = parse_identity_uri(uri);

    if name.is_empty() {
        eprintln!("Error: Could not parse identity name from URI: {}", uri);
        std::process::exit(1);
    }

    // Check if any profile fields were provided
    let has_updates = display_name.is_some()
        || description.is_some()
        || avatar.is_some()
        || website.is_some();

    if !has_updates {
        eprintln!("Error: No fields to update. Specify at least one of:");
        eprintln!("  --display-name, --description, --avatar, --website");
        std::process::exit(1);
    }

    // Build profile object
    let mut links_map = HashMap::new();
    if let Some(ws) = website {
        links_map.insert("website".to_string(), ws.to_string());
    }

    let profile = sbo_core::jwt::Profile {
        display_name: display_name.map(|s| s.to_string()),
        bio: description.map(|s| s.to_string()),
        avatar: avatar.map(|s| s.to_string()),
        banner: None,
        location: None,
        links: if links_map.is_empty() { None } else { Some(links_map) },
        metadata: None,
    };

    let profile_json = serde_json::to_vec_pretty(&profile)?;
    let profile_path = format!("/{}/profile", name);

    // Open keyring
    let keyring = Keyring::open()?;
    let alias = keyring.resolve_alias(key_alias)?;
    let signing_key = keyring.get_signing_key(&alias)?;
    let public_key = signing_key.public_key();

    // Build profile message
    use sbo_core::crypto::{ContentHash, Signature};
    use sbo_core::message::{Action, Id, Message, ObjectType, Path};

    let placeholder_sig = Signature::parse(&"0".repeat(128))?;
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse(&format!("/{}/", name))?,
        id: Id::new("profile")?,
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: placeholder_sig,
        content_type: Some("application/json".to_string()),
        content_hash: Some(ContentHash::sha256(&profile_json)),
        content_schema: Some("profile.v1".to_string()),
        payload: Some(profile_json),
        owner: None,
        creator: None,
        content_encoding: None,
        policy_ref: None,
        related: None,
    };
    msg.sign(&signing_key);

    let wire_bytes = sbo_core::wire::serialize(&msg);

    // Connect to daemon
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    println!("Updating profile for '{}' at {}", name, chain_uri);
    println!("  Profile path: {}", profile_path);

    // Submit via generic Submit (not SubmitIdentity since this is profile, not identity)
    // For now, we use SubmitIdentity with the profile path as a workaround
    // TODO: Add dedicated profile submission support
    match client
        .request(Request::SubmitIdentity {
            uri: chain_uri.to_string(),
            name: format!("{}/profile", name), // Use profile path
            data: wire_bytes,
            wait: true,
        })
        .await
    {
        Ok(Response::Ok { data }) => {
            let status = data["status"].as_str().unwrap_or("submitted");
            println!("\n✓ Profile {} ({})", status, profile_path);
        }
        Ok(Response::Error { message }) => {
            // Profile submission not yet fully supported, provide guidance
            eprintln!("Note: Profile update not yet fully supported via daemon.");
            eprintln!("To update profile manually, create a profile.v1 JSON file and post it:");
            eprintln!("  sbo uri post {}{} <profile.json>", chain_uri, profile_path);
            eprintln!("\nProfile JSON format:");
            println!("{}", serde_json::to_string_pretty(&profile)?);
            return Err(anyhow::anyhow!("Profile update: {}", message));
        }
        Err(e) => {
            eprintln!("Failed to connect to daemon: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Import an identity from a synced repo into the keyring
pub async fn import(
    repo: &str,
    name: &str,
    proof_file: Option<&std::path::Path>,
) -> Result<()> {
    let mut keyring = Keyring::open()?;

    // Build identity URI
    // Handle both SBO URI (sbo+raw://... or sbo://...) and local path (./my-repo)
    let (identity_uri, chain_uri) = if repo.starts_with("sbo+raw://") || repo.starts_with("sbo://") {
        let chain = repo.trim_end_matches('/');
        (format!("{}/sys/names/{}", chain, name), format!("{}/", chain))
    } else {
        // Local path - need to find the chain URI from daemon
        let config = Config::load(&Config::config_path())?;
        let client = IpcClient::new(config.daemon.socket_path.clone());

        // Query repos to find which chain this path belongs to
        match client.request(Request::RepoList).await {
            Ok(Response::Ok { data }) => {
                let repos = data.as_array().ok_or_else(|| anyhow::anyhow!("Invalid repo list"))?;
                let abs_path = std::fs::canonicalize(repo)
                    .unwrap_or_else(|_| std::path::PathBuf::from(repo));
                let abs_path_str = abs_path.to_string_lossy();

                let mut found_uri = None;
                for r in repos {
                    if let (Some(path), Some(uri)) = (r["path"].as_str(), r["uri"].as_str()) {
                        if abs_path_str == path || abs_path_str.starts_with(&format!("{}/", path)) {
                            found_uri = Some(uri.to_string());
                            break;
                        }
                    }
                }

                match found_uri {
                    Some(uri) => {
                        let chain = uri.trim_end_matches('/');
                        (format!("{}/sys/names/{}", chain, name), format!("{}/", chain))
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "Path '{}' is not a known repo. Add it with: sbo repo add <uri> {}",
                            repo, repo
                        ));
                    }
                }
            }
            Ok(Response::Error { message }) => {
                return Err(anyhow::anyhow!("Failed to list repos: {}", message));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to connect to daemon: {}", e));
            }
        }
    };

    println!("Importing identity '{}' from {}", name, chain_uri);

    // Get identity data - either from proof or from daemon
    let identity_public_key = if let Some(proof_path) = proof_file {
        // Verify proof and extract identity
        println!("  Verifying proof from {}...", proof_path.display());

        let proof_bytes = std::fs::read(proof_path)?;
        let sboq = sbo_core::proof::parse_sboq(&proof_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse proof: {}", e))?;

        // Verify the trie proof
        let trie_valid = sbo_crypto::verify_trie_proof(&sboq.trie_proof)
            .map_err(|e| anyhow::anyhow!("Proof verification failed: {}", e))?;

        if !trie_valid {
            return Err(anyhow::anyhow!("Invalid proof: trie verification failed"));
        }

        // Check this is an existence proof (not non-existence)
        if sboq.object_hash.is_none() {
            return Err(anyhow::anyhow!("Invalid proof: this is a non-existence proof"));
        }

        // Extract object from proof
        let obj_bytes = sboq.object
            .ok_or_else(|| anyhow::anyhow!("Proof does not contain embedded object"))?;

        // Parse wire format
        let msg = sbo_core::wire::parse(&obj_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse object: {}", e))?;

        // Extract identity from payload
        let payload = msg.payload
            .ok_or_else(|| anyhow::anyhow!("Object has no payload"))?;

        let identity = sbo_core::schema::parse_identity(&payload)
            .map_err(|e| anyhow::anyhow!("Failed to parse identity: {}", e))?;

        println!("  Proof valid ✓");
        identity.public_key
    } else {
        // No proof - try daemon (only works in full mode with synced repo)
        let config = Config::load(&Config::config_path())?;
        let client = IpcClient::new(config.daemon.socket_path);

        match client.request(Request::GetIdentity { uri: identity_uri.clone() }).await {
            Ok(Response::Ok { data }) => {
                data["public_key"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Identity missing public_key"))?
                    .to_string()
            }
            Ok(Response::Error { message }) => {
                return Err(anyhow::anyhow!(
                    "Identity not found in synced repos: {}\n\n\
                    In light mode, you must provide a --proof file.\n\
                    In full mode, ensure the repo is synced.",
                    message
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to connect to daemon: {}", e));
            }
        }
    };

    // Find matching key in keyring
    let matching_alias = keyring
        .list()
        .iter()
        .find(|(_, entry)| entry.public_key == identity_public_key)
        .map(|(alias, _)| alias.clone());

    let alias = match matching_alias {
        Some(a) => a,
        None => {
            eprintln!("Error: No local key matches identity public key.");
            eprintln!("  Identity key: {}", identity_public_key);
            eprintln!("\nYou must import the private key first:");
            eprintln!("  sbo key import <key-file-or-hex> --name <alias>");
            std::process::exit(1);
        }
    };

    // Check if already imported
    let entry = keyring.list().get(&alias).unwrap();
    if entry.identities.contains(&identity_uri) {
        println!("\n○ Identity already in keyring");
        println!("  URI:       {}", identity_uri);
        println!("  Local Key: {}", alias);
        return Ok(());
    }

    // Add identity to keyring
    keyring.add_identity(&alias, &identity_uri)?;

    println!("\n✓ Identity imported");
    println!("  URI:       {}", identity_uri);
    println!("  Local Key: {}", alias);

    Ok(())
}

/// Remove an identity from the local keyring (does not affect on-chain state)
pub fn remove(chain: &str, name: &str) -> Result<()> {
    let mut keyring = Keyring::open()?;

    // Build identity URI
    let chain = chain.trim_end_matches('/');
    let identity_uri = format!("{}/sys/names/{}", chain, name);

    // Find which key has this identity
    let mut found_alias = None;
    for (alias, entry) in keyring.list() {
        if entry.identities.contains(&identity_uri) {
            found_alias = Some(alias.clone());
            break;
        }
    }

    let alias = match found_alias {
        Some(a) => a,
        None => {
            println!("Identity not found in keyring: {}", identity_uri);
            println!("\nUse 'sbo id list' to see your identities");
            return Ok(());
        }
    };

    // Remove from keyring
    keyring.remove_identity(&alias, &identity_uri)?;

    println!("✓ Removed identity from keyring");
    println!("  URI:       {}", identity_uri);
    println!("  Was on:    {} (key)", alias);
    println!("\n  Note: On-chain identity unchanged");

    Ok(())
}

/// Parse identity URI to extract chain and name
/// e.g., "sbo+raw://avail:turing:506/sys/names/alice" -> ("sbo+raw://avail:turing:506/", "alice")
fn parse_identity_uri(uri: &str) -> (String, String) {
    if let Some(pos) = uri.find("/sys/names/") {
        let chain = format!("{}/", &uri[..pos]);
        let name = uri[pos + 11..].trim_end_matches('/').to_string();
        (chain, name)
    } else {
        // Fallback: use whole URI as chain, empty name
        (uri.to_string(), String::new())
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}

/// Import an identity discovered via email address
pub async fn import_email(email: &str) -> Result<()> {
    use sbo_daemon::config::Config;
    use sbo_daemon::ipc::{IpcClient, Request, Response};

    // Validate email format
    let (user, domain) = match sbo_core::dns::parse_email(email) {
        Some(parts) => parts,
        None => {
            eprintln!("Error: Invalid email address: {}", email);
            return Ok(());
        }
    };

    println!("Discovering identity for {}...", email);

    // Look up identity host via DNS
    print!("  DNS: _sbo-id.{}...", domain);
    std::io::Write::flush(&mut std::io::stdout())?;

    match sbo_core::dns::resolve_identity_host(domain).await {
        Ok(record) => {
            println!(" host={}", record.host);
        }
        Err(sbo_core::dns::DnsError::NoRecord) => {
            println!();
            eprintln!("Error: Domain {} does not support SBO identity discovery", domain);
            return Ok(());
        }
        Err(e) => {
            println!();
            eprintln!("Error: DNS lookup failed: {}", e);
            return Ok(());
        }
    };

    // Fetch .well-known endpoint
    print!("  HTTP: /.well-known/sbo-identity/{}/{}...", domain, user);
    std::io::Write::flush(&mut std::io::stdout())?;

    let sbo_uri = match sbo_core::dns::resolve_email(email).await {
        Ok(uri) => {
            println!(" ok");
            uri
        }
        Err(sbo_core::dns::DnsError::NoRecord) => {
            println!();
            eprintln!("Error: User {} not found at {}", user, domain);
            return Ok(());
        }
        Err(e) => {
            println!();
            eprintln!("Error: {}", e);
            return Ok(());
        }
    };

    println!("  SBO URI: {}", sbo_uri);

    // Fetch identity from daemon to get public key
    let config = Config::load(&Config::config_path()).ok();
    let client = config.map(|c| IpcClient::new(c.daemon.socket_path));

    let identity_public_key = if let Some(ref client) = client {
        match client.request(Request::GetIdentity { uri: sbo_uri.clone() }).await {
            Ok(Response::Ok { data }) => {
                data["public_key"].as_str().map(|s| s.to_string())
            }
            Ok(Response::Error { message }) => {
                eprintln!("Error: {}", message);
                return Ok(());
            }
            Err(e) => {
                eprintln!("Error: Cannot connect to daemon: {}", e);
                return Ok(());
            }
        }
    } else {
        eprintln!("Error: Cannot connect to daemon");
        return Ok(());
    };

    let identity_public_key = match identity_public_key {
        Some(k) => k,
        None => {
            eprintln!("Error: Identity does not have a public key");
            return Ok(());
        }
    };

    println!("  Public key: {}", identity_public_key);

    // Find matching local key
    let mut keyring = Keyring::open()?;
    let mut matching_alias = None;

    for (alias, entry) in keyring.list() {
        if entry.public_key == identity_public_key {
            matching_alias = Some(alias.clone());
            break;
        }
    }

    let alias = match matching_alias {
        Some(a) => a,
        None => {
            eprintln!("Error: No local key matches this identity's public key");
            eprintln!("       You need to import the private key first: sbo key import <alias> <file>");
            return Ok(());
        }
    };

    // Check if already imported
    let entry = keyring.list().get(&alias).unwrap();
    let already_imported = entry.identities.contains(&sbo_uri);

    if !already_imported {
        // Add identity to keyring
        keyring.add_identity(&alias, &sbo_uri)?;
    }

    // Store email → SBO URI mapping (always, even if identity was already imported)
    keyring.add_email(email, &sbo_uri)?;

    if already_imported {
        println!("\n✓ Identity already imported (email association added)");
    } else {
        println!("\n✓ Identity imported");
    }
    println!("  URI:       {}", sbo_uri);
    println!("  Email:     {}", email);
    println!("  Local key: {}", alias);

    Ok(())
}

/// Create a domain-certified identity
///
/// Uses the domain's identity provisioning endpoint to get a signed JWT.
/// The domain certifies the binding between the email and public key.
pub async fn create_domain_certified(
    email: &str,
    key_alias: Option<&str>,
    no_wait: bool,
) -> Result<()> {
    use std::io::Write;
    use std::time::Duration;

    // Parse email to extract local part and domain
    let (local_part, domain) = match sbo_core::dns::parse_email(email) {
        Some(parts) => parts,
        None => {
            eprintln!("Error: Invalid email address: {}", email);
            std::process::exit(1);
        }
    };

    // Open keyring and resolve signing key
    let mut keyring = Keyring::open()?;
    let alias = keyring.resolve_alias(key_alias)?;
    let signing_key = keyring.get_signing_key(&alias)?;
    let public_key = signing_key.public_key();

    println!("Creating domain-certified identity for {}", email);
    println!("  Local key: {} ({})", alias, public_key.to_string());

    // Connect to daemon
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path.clone());

    // Request identity provisioning from daemon
    println!("  Requesting identity provisioning from {}...", domain);

    let response = client
        .request(Request::RequestIdentityProvisioning {
            email: email.to_string(),
            public_key: public_key.to_string(),
        })
        .await;

    let (status, request_id, verification_uri, identity_jwt) = match response {
        Ok(Response::Ok { data }) => {
            let status = data["status"].as_str().unwrap_or("unknown").to_string();
            let request_id = data["request_id"].as_str().map(|s| s.to_string());
            let verification_uri = data["verification_uri"].as_str().map(|s| s.to_string());
            let identity_jwt = data["identity_jwt"].as_str().map(|s| s.to_string());
            (status, request_id, verification_uri, identity_jwt)
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to connect to daemon: {}", e);
            eprintln!("Is the daemon running? Try: sbo daemon start");
            std::process::exit(1);
        }
    };

    // If already complete (user was logged in), we have the JWT
    let identity_jwt = if status == "complete" {
        println!("  ✓ Domain returned identity immediately (already authenticated)");
        identity_jwt.expect("identity_jwt should be present when status is complete")
    } else if status == "pending" {
        // Need to poll
        let request_id = request_id.expect("request_id should be present when status is pending");
        let verification_uri = verification_uri.expect("verification_uri should be present");

        println!();
        println!("  Please authenticate at:");
        println!("  {}", verification_uri);
        println!();

        // Try to open browser
        if let Err(_e) = open::that(&verification_uri) {
            // Failed to open browser, user can manually visit
        }

        // Poll for completion
        print!("  Waiting for authentication");
        std::io::stdout().flush()?;

        let poll_interval = Duration::from_secs(2);
        let max_attempts = 150; // 5 minutes at 2 second intervals

        let mut jwt = None;
        for _ in 0..max_attempts {
            tokio::time::sleep(poll_interval).await;
            print!(".");
            std::io::stdout().flush()?;

            let poll_response = client
                .request(Request::PollIdentityProvisioning {
                    request_id: request_id.clone(),
                })
                .await;

            match poll_response {
                Ok(Response::Ok { data }) => {
                    let poll_status = data["status"].as_str().unwrap_or("unknown");
                    if poll_status == "complete" {
                        jwt = data["identity_jwt"].as_str().map(|s| s.to_string());
                        break;
                    } else if poll_status == "expired" {
                        println!();
                        eprintln!("Error: Authentication request expired");
                        std::process::exit(1);
                    }
                    // Still pending, continue polling
                }
                Ok(Response::Error { message }) => {
                    println!();
                    eprintln!("Error polling: {}", message);
                    std::process::exit(1);
                }
                Err(e) => {
                    println!();
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        println!();

        match jwt {
            Some(j) => {
                println!("  ✓ Authentication complete");
                j
            }
            None => {
                eprintln!("Error: Timed out waiting for authentication");
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("Error: Unexpected status from identity provisioning: {}", status);
        std::process::exit(1);
    };

    println!("  ✓ Received identity JWT from domain");

    // Now we need to:
    // 1. Resolve the domain's SBO URI (from DNS)
    // 2. Wrap the identity JWT in an SBO message
    // 3. Submit to /sys/names/{local_part}

    // Resolve the domain's SBO URI
    print!("  Resolving {}...", domain);
    std::io::stdout().flush()?;

    let dns_record = sbo_core::dns::resolve(domain).await
        .map_err(|e| anyhow::anyhow!("Failed to resolve domain SBO URI: {}", e))?;

    if dns_record.repository_uri.is_empty() {
        println!();
        eprintln!("Error: Domain {} has no SBO repository configured", domain);
        std::process::exit(1);
    }

    let chain_uri = dns_record.repository_uri.trim_end_matches('/');
    println!(" {}", chain_uri);

    // Build the identity message with the domain-signed JWT as payload
    // The identity JWT IS the payload - we wrap it in an SBO message
    let jwt_bytes = identity_jwt.as_bytes().to_vec();

    // Create identity message wrapping the JWT
    use sbo_core::crypto::{ContentHash, Signature};
    use sbo_core::message::{Action, Id, Message, ObjectType, Path};

    let placeholder_sig = Signature::parse(&"0".repeat(128))?;
    let mut msg = Message {
        action: Action::Post,
        path: Path::parse("/sys/names/")?,
        id: Id::new(local_part)?,
        object_type: ObjectType::Object,
        signing_key: public_key.clone(),
        signature: placeholder_sig,
        content_type: Some("application/jwt".to_string()),
        content_hash: Some(ContentHash::sha256(&jwt_bytes)),
        content_schema: Some("identity.v1".to_string()),
        payload: Some(jwt_bytes),
        owner: None,
        creator: None,
        content_encoding: None,
        policy_ref: None,
        related: None,
    };
    msg.sign(&signing_key);

    let wire_bytes = sbo_core::wire::serialize(&msg);

    // Submit to chain
    let identity_uri = format!("{}/sys/names/{}", chain_uri, local_part);
    println!("  Submitting identity to {}...", identity_uri);

    match client
        .request(Request::SubmitIdentity {
            uri: chain_uri.to_string(),
            name: local_part.to_string(),
            data: wire_bytes,
            wait: !no_wait,
        })
        .await
    {
        Ok(Response::Ok { data }) => {
            let status = data["status"].as_str().unwrap_or("unknown");

            match status {
                "verified" => {
                    println!("\n✓ Domain-certified identity created and verified on-chain");
                    println!("  URI:   {}", identity_uri);
                    println!("  Email: {}", email);

                    // Add identity to keyring
                    if let Err(e) = keyring.add_identity(&alias, &identity_uri) {
                        eprintln!("Warning: failed to update keyring: {}", e);
                    }

                    // Store email → SBO URI mapping
                    if let Err(e) = keyring.add_email(email, &identity_uri) {
                        eprintln!("Warning: failed to store email association: {}", e);
                    }
                }
                "unverified" => {
                    println!("\n○ Identity submitted (unverified)");
                    println!("  URI:   {}", identity_uri);
                    println!("  Email: {}", email);
                    if let Some(id) = data["submission_id"].as_str() {
                        println!("  Submission ID: {}", id);
                    }
                    println!("\n  Identity record submitted on chain.");
                    println!("  Check status with: sbo id show {}", local_part);

                    // Add identity to keyring (unverified - will check later)
                    if let Err(e) = keyring.add_identity(&alias, &identity_uri) {
                        eprintln!("Warning: failed to update keyring: {}", e);
                    }
                    if let Err(e) = keyring.add_email(email, &identity_uri) {
                        eprintln!("Warning: failed to store email association: {}", e);
                    }
                }
                "pending" => {
                    println!("\n○ Identity submitted but verification timed out");
                    println!("  URI:   {}", identity_uri);
                    if let Some(msg) = data["message"].as_str() {
                        println!("  {}", msg);
                    }

                    // Add identity to keyring anyway
                    if let Err(e) = keyring.add_identity(&alias, &identity_uri) {
                        eprintln!("Warning: failed to update keyring: {}", e);
                    }
                    if let Err(e) = keyring.add_email(email, &identity_uri) {
                        eprintln!("Warning: failed to store email association: {}", e);
                    }
                }
                _ => {
                    println!("\n? Unknown status: {}", status);
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
            }
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("Failed to connect to daemon: {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

/// Resolve an email address to its SBO identity URI
pub async fn resolve(email: &str) -> Result<()> {
    // Validate email format
    let (user, domain) = match sbo_core::dns::parse_email(email) {
        Some(parts) => parts,
        None => {
            eprintln!("Error: Invalid email address: {}", email);
            return Ok(());
        }
    };

    print!("Looking up _sbo-id.{}...", domain);
    std::io::Write::flush(&mut std::io::stdout())?;

    // Look up identity host via DNS
    let sbo_id = match sbo_core::dns::resolve_identity_host(domain).await {
        Ok(record) => {
            println!(" host={}", record.host);
            record
        }
        Err(sbo_core::dns::DnsError::NoRecord) => {
            println!();
            eprintln!("Error: Domain {} does not support SBO identity discovery", domain);
            eprintln!("       (no _sbo-id.{} TXT record found)", domain);
            return Ok(());
        }
        Err(e) => {
            println!();
            eprintln!("Error: DNS lookup failed: {}", e);
            return Ok(());
        }
    };

    // Fetch .well-known endpoint
    let url = format!(
        "https://{}/.well-known/sbo-identity/{}/{}",
        sbo_id.host, domain, user
    );

    print!("Fetching {}...", url);
    std::io::Write::flush(&mut std::io::stdout())?;

    match sbo_core::dns::resolve_email(email).await {
        Ok(sbo_uri) => {
            println!(" ok");
            println!();
            println!("{}", sbo_uri);
        }
        Err(sbo_core::dns::DnsError::NoRecord) => {
            println!();
            eprintln!("Error: User {} not found at {}", user, domain);
            return Ok(());
        }
        Err(e) => {
            println!();
            eprintln!("Error: {}", e);
            return Ok(());
        }
    }

    Ok(())
}
