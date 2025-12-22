//! Auth command implementations (sign request approval flow)
//!
//! Implements the nested JWT model with session bindings:
//! 1. User delegation: permanent key delegates to ephemeral key
//! 2. Session binding: domain wraps user delegation with email claim
//! 3. Auth assertion: ephemeral key signs challenge for app

use anyhow::Result;
use sbo_core::keyring::Keyring;
use sbo_core::jwt;
use sbo_daemon::config::Config;
use sbo_daemon::ipc::{IpcClient, Request, Response};
use std::io::Write;

use super::session;
use sbo_core::crypto::{PublicKey, SigningKey};

/// List pending sign requests
pub async fn pending() -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    match client.request(Request::ListSignRequests).await {
        Ok(Response::Ok { data }) => {
            let requests = data["requests"].as_array();

            if requests.is_none() || requests.unwrap().is_empty() {
                println!("No pending sign requests.");
                return Ok(());
            }

            let requests = requests.unwrap();

            println!("{:<20} {:<20} {:<30} {}", "REQUEST ID", "APP", "EMAIL", "PURPOSE");
            println!("{}", "-".repeat(85));

            for req in requests {
                let request_id = req["request_id"].as_str().unwrap_or("-");
                let app_name = req["app_name"].as_str().unwrap_or("-");
                let email = req["email"].as_str().unwrap_or("(undirected)");
                let purpose = req["purpose"].as_str().unwrap_or("-");

                println!(
                    "{:<20} {:<20} {:<30} {}",
                    truncate(request_id, 18),
                    truncate(app_name, 18),
                    truncate(email, 28),
                    truncate(purpose, 30),
                );
            }

            println!();
            println!("To approve: sbo auth approve <request-id> [--as <email>]");
            println!("To reject:  sbo auth reject <request-id>");
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
        }
        Err(e) => {
            eprintln!("Cannot connect to daemon: {}", e);
            eprintln!("Is the daemon running? Try: sbo daemon start");
        }
    }

    Ok(())
}

/// Show details of a specific sign request
pub async fn show(request_id: &str) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    match client.request(Request::GetSignRequest { request_id: request_id.to_string() }).await {
        Ok(Response::Ok { data }) => {
            println!("Sign Request: {}", data["request_id"].as_str().unwrap_or("-"));
            println!();
            println!("  App:        {}", data["app_name"].as_str().unwrap_or("-"));
            if let Some(origin) = data["app_origin"].as_str() {
                println!("  Origin:     {}", origin);
            }
            if let Some(email) = data["email"].as_str() {
                println!("  Email:      {}", email);
            } else {
                println!("  Email:      (undirected - you choose)");
            }
            println!("  Challenge:  {}", data["challenge"].as_str().unwrap_or("-"));
            if let Some(purpose) = data["purpose"].as_str() {
                println!("  Purpose:    {}", purpose);
            }
            println!("  Status:     {}", data["status"].as_str().unwrap_or("-"));

            if let Some(created) = data["created_at"].as_u64() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let age_secs = now.saturating_sub(created);
                println!("  Age:        {}s ago", age_secs);
            }
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
        }
        Err(e) => {
            eprintln!("Cannot connect to daemon: {}", e);
        }
    }

    Ok(())
}

/// Approve a sign request
pub async fn approve(request_id: &str, email: Option<&str>) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    // First, get the request details
    let request_data = match client.request(Request::GetSignRequest {
        request_id: request_id.to_string()
    }).await {
        Ok(Response::Ok { data }) => data,
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
            return Ok(());
        }
        Err(e) => {
            eprintln!("Cannot connect to daemon: {}", e);
            return Ok(());
        }
    };

    let challenge = request_data["challenge"].as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing challenge in request"))?;
    let requested_email = request_data["email"].as_str();
    let app_name = request_data["app_name"].as_str().unwrap_or("Unknown app");
    let app_origin = request_data["app_origin"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    // Open keyring
    let keyring = Keyring::open()?;

    // Determine which identity to use
    let identity_email_opt = email.or(requested_email);

    let (identity_uri, key_alias, claimed_email) = if let Some(em) = identity_email_opt {
        // Look up email in keyring
        let uri = keyring.get_email(em)
            .ok_or_else(|| anyhow::anyhow!(
                "Email '{}' not found in keyring. Import with: sbo id import {}",
                em, em
            ))?
            .to_string();

        // Find the key for this identity
        let alias = keyring.find_key_for_identity(&uri)
            .ok_or_else(|| anyhow::anyhow!("No key found for identity {}", uri))?
            .to_string();

        (uri, alias, em.to_string())
    } else {
        // Undirected request - list available identities and let user choose
        let emails: Vec<_> = keyring.list_emails().iter().collect();

        if emails.is_empty() {
            eprintln!("No email identities in keyring.");
            eprintln!("Import one with: sbo id import <email>");
            return Ok(());
        }

        if emails.len() == 1 {
            let (em, uri) = emails[0];
            let alias = keyring.find_key_for_identity(uri)
                .ok_or_else(|| anyhow::anyhow!("No key found for identity {}", uri))?
                .to_string();
            println!("Using identity: {} ({})", em, uri);
            (uri.clone(), alias, em.clone())
        } else {
            // Multiple identities - user must specify
            eprintln!("Multiple identities available. Specify one with --as:");
            for (em, uri) in &emails {
                eprintln!("  {} -> {}", em, uri);
            }
            return Ok(());
        }
    };

    // Get signing key (permanent user key)
    let signing_key = keyring.get_signing_key(&key_alias)?;

    // Step 1: Check local session storage
    let (session_binding_jwt, ephemeral_signing_key) = match session::get_session(&claimed_email) {
        Some(session) => {
            // Valid session exists - reuse it
            println!("Using existing session for {}", claimed_email);
            let ephemeral_key = session::get_ephemeral_signing_key(&session)?;
            (session.session_binding_jwt.clone(), ephemeral_key)
        }
        None => {
            // Need to obtain new session binding
            println!("No valid session found. Obtaining new session binding...");
            obtain_session_binding(&client, &signing_key, &claimed_email).await?
        }
    };

    // Step 2: Sign auth assertion with ephemeral key
    let assertion_jwt = jwt::create_auth_assertion(
        &ephemeral_signing_key,
        &claimed_email,
        &app_origin,
        challenge,
    )?;

    println!();
    println!("Approving sign request:");
    println!("  Request:  {}", request_id);
    println!("  App:      {}", app_name);
    println!("  Email:    {}", claimed_email);
    println!("  Identity: {}", identity_uri);
    println!("  Key:      {}", key_alias);

    // Send approval to daemon
    match client.request(Request::ApproveSignRequest {
        request_id: request_id.to_string(),
        assertion_jwt,
        session_binding_jwt,
    }).await {
        Ok(Response::Ok { .. }) => {
            println!("\n✓ Request approved. App will receive JWTs.");
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
        }
        Err(e) => {
            eprintln!("Cannot connect to daemon: {}", e);
        }
    }

    Ok(())
}

/// Obtain a new session binding from the domain
async fn obtain_session_binding(
    client: &IpcClient,
    signing_key: &SigningKey,
    email: &str,
) -> Result<(String, SigningKey)> {
    // Step 1: Generate ephemeral keypair
    let (ephemeral_public_key_str, ephemeral_private_key) = session::generate_ephemeral_keypair();

    // Parse public key string into PublicKey type
    let ephemeral_public_key = PublicKey::parse(&ephemeral_public_key_str)
        .map_err(|e| anyhow::anyhow!("Invalid ephemeral public key: {:?}", e))?;

    // Step 2: Create user delegation JWT (permanent key -> ephemeral key)
    // Default to 30 day session
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + (30 * 24 * 60 * 60);

    let user_delegation_jwt = jwt::create_user_delegation(
        signing_key,
        &ephemeral_public_key,
        expiry,
    )?;

    // Step 3: Request session binding from domain via daemon
    println!("Requesting session binding from domain...");

    let response = client.request(Request::RequestSessionBinding {
        email: email.to_string(),
        ephemeral_public_key: ephemeral_public_key_str.clone(),
        user_delegation_jwt: Some(user_delegation_jwt),
    }).await?;

    let (binding_request_id, verification_uri, expires_in) = match response {
        Response::Ok { data } => {
            let request_id = data["request_id"].as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing request_id in response"))?
                .to_string();
            let verification_uri = data["verification_uri"].as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing verification_uri in response"))?
                .to_string();
            let expires_in = data["expires_in"].as_u64()
                .unwrap_or(300);
            (request_id, verification_uri, expires_in)
        }
        Response::Error { message } => {
            return Err(anyhow::anyhow!("Failed to request session binding: {}", message));
        }
    };

    // Step 4: Open browser and print verification URL
    println!();
    println!("Please verify your identity at:");
    println!("  {}", verification_uri);
    println!();

    // Try to open browser automatically
    if let Err(_) = open::that(&verification_uri) {
        // Failed to open browser, user can manually visit
    }

    println!("Waiting for verification (expires in {}s)...", expires_in);

    // Step 5: Poll until complete or timeout
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(expires_in);
    let poll_interval = std::time::Duration::from_secs(2);

    loop {
        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!("Session binding request timed out"));
        }

        tokio::time::sleep(poll_interval).await;

        let poll_response = client.request(Request::PollSessionBinding {
            request_id: binding_request_id.clone(),
        }).await?;

        match poll_response {
            Response::Ok { data } => {
                let status = data["status"].as_str().unwrap_or("unknown");

                match status {
                    "complete" => {
                        let session_binding = data["session_binding"].as_str()
                            .ok_or_else(|| anyhow::anyhow!("Missing session_binding in response"))?
                            .to_string();

                        println!();
                        println!("✓ Session binding obtained!");

                        // Step 6: Store session locally
                        let expires_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() + (30 * 24 * 60 * 60); // 30 days

                        session::save_session(
                            email,
                            &session_binding,
                            &ephemeral_private_key,
                            expires_at,
                        )?;

                        // Return signing key
                        let mut key_bytes = [0u8; 32];
                        key_bytes.copy_from_slice(&ephemeral_private_key);
                        let ephemeral_signing_key = SigningKey::from_bytes(&key_bytes);

                        return Ok((session_binding, ephemeral_signing_key));
                    }
                    "pending" => {
                        // Continue polling
                        print!(".");
                        std::io::stdout().flush()?;
                    }
                    "expired" => {
                        return Err(anyhow::anyhow!("Session binding request expired"));
                    }
                    _ => {
                        return Err(anyhow::anyhow!("Unknown status: {}", status));
                    }
                }
            }
            Response::Error { message } => {
                return Err(anyhow::anyhow!("Poll failed: {}", message));
            }
        }
    }
}

/// Reject a sign request
pub async fn reject(request_id: &str, reason: Option<&str>) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    // First, get the request details for confirmation
    let request_data = match client.request(Request::GetSignRequest {
        request_id: request_id.to_string()
    }).await {
        Ok(Response::Ok { data }) => data,
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
            return Ok(());
        }
        Err(e) => {
            eprintln!("Cannot connect to daemon: {}", e);
            return Ok(());
        }
    };

    let app_name = request_data["app_name"].as_str().unwrap_or("Unknown app");

    println!("Rejecting sign request:");
    println!("  Request: {}", request_id);
    println!("  App:     {}", app_name);
    if let Some(r) = reason {
        println!("  Reason:  {}", r);
    }

    // Send rejection to daemon
    match client.request(Request::RejectSignRequest {
        request_id: request_id.to_string(),
        reason: reason.map(|s| s.to_string()),
    }).await {
        Ok(Response::Ok { .. }) => {
            println!("\n✓ Request rejected.");
        }
        Ok(Response::Error { message }) => {
            eprintln!("Error: {}", message);
        }
        Err(e) => {
            eprintln!("Cannot connect to daemon: {}", e);
        }
    }

    Ok(())
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}
