//! Auth command implementations (sign request approval flow)

use anyhow::Result;
use sbo_core::keyring::Keyring;
use sbo_daemon::config::Config;
use sbo_daemon::ipc::{IpcClient, Request, Response, SignedAssertion};
use std::io::Write;

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

    // Open keyring
    let keyring = Keyring::open()?;

    // Determine which identity to use
    let identity_email = email.or(requested_email);

    let (identity_uri, key_alias) = if let Some(email) = identity_email {
        // Look up email in keyring
        let uri = keyring.get_email(email)
            .ok_or_else(|| anyhow::anyhow!(
                "Email '{}' not found in keyring. Import with: sbo id import {}",
                email, email
            ))?
            .to_string();

        // Find the key for this identity
        let alias = keyring.find_key_for_identity(&uri)
            .ok_or_else(|| anyhow::anyhow!("No key found for identity {}", uri))?
            .to_string();

        (uri, alias)
    } else {
        // Undirected request - list available identities and let user choose
        let emails: Vec<_> = keyring.list_emails().iter().collect();

        if emails.is_empty() {
            eprintln!("No email identities in keyring.");
            eprintln!("Import one with: sbo id import <email>");
            return Ok(());
        }

        if emails.len() == 1 {
            let (email, uri) = emails[0];
            let alias = keyring.find_key_for_identity(uri)
                .ok_or_else(|| anyhow::anyhow!("No key found for identity {}", uri))?
                .to_string();
            println!("Using identity: {} ({})", email, uri);
            (uri.clone(), alias)
        } else {
            // Multiple identities - user must specify
            eprintln!("Multiple identities available. Specify one with --as:");
            for (email, uri) in &emails {
                eprintln!("  {} -> {}", email, uri);
            }
            return Ok(());
        }
    };

    // Get signing key
    let signing_key = keyring.get_signing_key(&key_alias)?;
    let public_key = signing_key.public_key();

    // Create timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Create message to sign: identity_uri || challenge || timestamp
    let message = format!("{}:{}:{}", identity_uri, challenge, timestamp);
    let signature = signing_key.sign(message.as_bytes());

    // Build signed assertion
    let signed_assertion = SignedAssertion {
        identity_uri: identity_uri.clone(),
        public_key: public_key.to_string(),
        challenge: challenge.to_string(),
        timestamp,
        signature: hex::encode(signature.0),
    };

    // Confirm with user
    println!("Approving sign request:");
    println!("  Request:  {}", request_id);
    println!("  App:      {}", app_name);
    println!("  Identity: {}", identity_uri);
    println!("  Key:      {}", key_alias);
    print!("Confirm? [y/N] ");
    std::io::stdout().flush()?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("y") {
        println!("Cancelled.");
        return Ok(());
    }

    // Send approval to daemon
    match client.request(Request::ApproveSignRequest {
        request_id: request_id.to_string(),
        signed_assertion,
    }).await {
        Ok(Response::Ok { .. }) => {
            println!("\n✓ Request approved. App will receive signed assertion.");
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

// ============================================================================
// Test/Demo Commands (simulate an app)
// ============================================================================

/// Simulate an app requesting authentication
pub async fn test_request(
    app_name: &str,
    email: Option<&str>,
    origin: Option<&str>,
) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    // Generate a random request ID and challenge using timestamp + pid
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let rand_val = now.as_nanos() as u64 ^ std::process::id() as u64;
    let request_id = format!("test-{:08x}", (rand_val & 0xFFFFFFFF) as u32);
    let challenge = format!("challenge-{:016x}", rand_val);

    println!("Simulating app authentication request...");
    println!("  App:       {}", app_name);
    if let Some(e) = email {
        println!("  Email:     {} (directed)", e);
    } else {
        println!("  Email:     (undirected - user chooses)");
    }
    if let Some(o) = origin {
        println!("  Origin:    {}", o);
    }
    println!("  Challenge: {}", challenge);
    println!();

    match client.request(Request::SubmitSignRequest {
        request_id: request_id.clone(),
        app_name: app_name.to_string(),
        app_origin: origin.map(|s| s.to_string()),
        email: email.map(|s| s.to_string()),
        challenge: challenge.clone(),
        purpose: Some("Test authentication".to_string()),
    }).await {
        Ok(Response::Ok { .. }) => {
            println!("✓ Request submitted to daemon");
            println!();
            println!("Request ID: {}", request_id);
            println!();
            println!("Now approve it with:");
            println!("  sbo auth pending");
            println!("  sbo auth approve {}", request_id);
            println!();
            println!("Then check the result with:");
            println!("  sbo auth test-poll {}", request_id);
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

/// Poll for a sign request result (simulating an app checking for response)
pub async fn test_poll(request_id: &str) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    println!("Polling for result of request {}...", request_id);
    println!();

    match client.request(Request::GetSignRequestResult {
        request_id: request_id.to_string(),
    }).await {
        Ok(Response::Ok { data }) => {
            let status = data["status"].as_str().unwrap_or("unknown");

            match status {
                "pending" => {
                    println!("Status: PENDING");
                    println!();
                    println!("User has not yet approved or rejected this request.");
                    println!("Check with: sbo auth pending");
                }
                "approved" => {
                    println!("Status: APPROVED ✓");
                    println!();
                    if let Some(assertion) = data.get("assertion") {
                        println!("Signed Assertion:");
                        println!("  Identity:  {}", assertion["identity_uri"].as_str().unwrap_or("-"));
                        println!("  PublicKey: {}", assertion["public_key"].as_str().unwrap_or("-"));
                        println!("  Challenge: {}", assertion["challenge"].as_str().unwrap_or("-"));
                        println!("  Timestamp: {}", assertion["timestamp"].as_u64().unwrap_or(0));
                        println!("  Signature: {}...",
                            assertion["signature"].as_str()
                                .map(|s| &s[..std::cmp::min(32, s.len())])
                                .unwrap_or("-"));
                        println!();
                        println!("App can now verify this signature against the on-chain identity.");
                    }
                }
                "rejected" => {
                    println!("Status: REJECTED ✗");
                    if let Some(reason) = data["reason"].as_str() {
                        println!("  Reason: {}", reason);
                    }
                }
                _ => {
                    println!("Status: {}", status);
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
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
