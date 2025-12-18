//! SBO Auth Demo App
//!
//! Demonstrates the SBO identity authentication flow from an app's perspective.
//! This is a standalone app that communicates with the SBO daemon.

use clap::Parser;
use sbo_daemon::config::Config;
use sbo_daemon::ipc::{IpcClient, Request, Response};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "auth-demo")]
#[command(about = "Demo app showing SBO identity authentication")]
struct Args {
    /// App name to display to user
    #[arg(long, default_value = "Demo App")]
    app_name: String,

    /// Email to request (directed auth) - omit for undirected
    #[arg(long)]
    email: Option<String>,

    /// App origin URL
    #[arg(long, default_value = "https://demo.example.com")]
    origin: String,

    /// Poll interval in milliseconds
    #[arg(long, default_value = "1000")]
    poll_interval: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║              SBO Identity Authentication Demo                  ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    // Load daemon config
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    // Generate request ID and challenge
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?;
    let rand_val = now.as_nanos() as u64 ^ std::process::id() as u64;
    let request_id = format!("demo-{:08x}", (rand_val & 0xFFFFFFFF) as u32);
    let challenge = format!("{:016x}", rand_val);

    // Step 1: Submit sign request
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 1: Submit Authentication Request                          │");
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();
    println!("  App Name:   {}", args.app_name);
    println!("  Origin:     {}", args.origin);
    if let Some(ref email) = args.email {
        println!("  Email:      {} (directed)", email);
    } else {
        println!("  Email:      (undirected - user chooses)");
    }
    println!("  Challenge:  {}", challenge);
    println!("  Request ID: {}", request_id);
    println!();

    match client.request(Request::SubmitSignRequest {
        request_id: request_id.clone(),
        app_name: args.app_name.clone(),
        app_origin: Some(args.origin.clone()),
        email: args.email.clone(),
        challenge: challenge.clone(),
        purpose: Some("Authenticate to demo app".to_string()),
    }).await {
        Ok(Response::Ok { .. }) => {
            println!("  ✓ Request submitted to daemon");
        }
        Ok(Response::Error { message }) => {
            eprintln!("  ✗ Error: {}", message);
            return Ok(());
        }
        Err(e) => {
            eprintln!("  ✗ Cannot connect to daemon: {}", e);
            eprintln!("    Is the daemon running? Try: sbo-daemon start");
            return Ok(());
        }
    }

    println!();
    println!("  Waiting for user approval...");
    println!("  (User should run: sbo auth approve {})", request_id);
    println!();

    // Step 2: Poll for result
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 2: Polling for User Response                              │");
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    let poll_interval = Duration::from_millis(args.poll_interval);
    let assertion;

    loop {
        print!("  Polling... ");

        match client.request(Request::GetSignRequestResult {
            request_id: request_id.clone(),
        }).await {
            Ok(Response::Ok { data }) => {
                let status = data["status"].as_str().unwrap_or("unknown");

                match status {
                    "pending" => {
                        println!("pending");
                        tokio::time::sleep(poll_interval).await;
                        continue;
                    }
                    "approved" => {
                        println!("APPROVED ✓");
                        println!();
                        assertion = data["assertion"].clone();
                        break;
                    }
                    "rejected" => {
                        println!("REJECTED ✗");
                        if let Some(reason) = data["reason"].as_str() {
                            println!("  Reason: {}", reason);
                        }
                        println!();
                        println!("Authentication failed: user rejected the request.");
                        return Ok(());
                    }
                    _ => {
                        println!("unknown status: {}", status);
                        return Ok(());
                    }
                }
            }
            Ok(Response::Error { message }) => {
                println!("error: {}", message);
                return Ok(());
            }
            Err(e) => {
                println!("connection error: {}", e);
                return Ok(());
            }
        }
    }

    // Step 3: Display the assertion
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 3: Received Signed Assertion                              │");
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    let identity_uri = assertion["identity_uri"].as_str().unwrap_or("");
    let claimed_email = assertion["email"].as_str();
    let public_key_str = assertion["public_key"].as_str().unwrap_or("");
    let received_challenge = assertion["challenge"].as_str().unwrap_or("");
    let timestamp = assertion["timestamp"].as_u64().unwrap_or(0);
    let signature_hex = assertion["signature"].as_str().unwrap_or("");

    println!("  Identity URI: {}", identity_uri);
    if let Some(email) = claimed_email {
        println!("  Email:        {}", email);
    }
    println!("  Public Key:   {}", public_key_str);
    println!("  Challenge:    {}", received_challenge);
    println!("  Timestamp:    {}", timestamp);
    println!("  Signature:    {}...", &signature_hex[..std::cmp::min(32, signature_hex.len())]);
    println!();

    // Step 4: Verify the assertion
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 4: Verify Assertion                                       │");
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // 4a. Verify challenge matches
    print!("  [1/5] Challenge matches what we sent... ");
    if received_challenge == challenge {
        println!("✓ PASS");
    } else {
        println!("✗ FAIL");
        println!("       Expected: {}", challenge);
        println!("       Got:      {}", received_challenge);
        return Ok(());
    }

    // 4b. Verify timestamp is recent (within 5 minutes)
    print!("  [2/5] Timestamp is recent (< 5 min)... ");
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let age = now_secs.saturating_sub(timestamp);
    if age < 300 {
        println!("✓ PASS ({}s ago)", age);
    } else {
        println!("✗ FAIL ({}s ago)", age);
        return Ok(());
    }

    // 4c. Verify email matches what we requested (if directed)
    print!("  [3/5] Email matches request... ");
    if let Some(ref requested) = args.email {
        if let Some(claimed) = claimed_email {
            if claimed == requested {
                println!("✓ PASS ({})", claimed);
            } else {
                println!("✗ FAIL");
                println!("       Requested: {}", requested);
                println!("       Got:       {}", claimed);
                return Ok(());
            }
        } else {
            println!("✗ FAIL (no email in assertion)");
            return Ok(());
        }
    } else {
        println!("✓ PASS (undirected request)");
    }

    // 4d. Verify signature
    print!("  [4/5] Signature is valid... ");

    // Parse public key
    let public_key_bytes = if public_key_str.starts_with("ed25519:") {
        hex::decode(&public_key_str[8..])?
    } else {
        hex::decode(public_key_str)?
    };

    let public_key_array: [u8; 32] = public_key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_array)?;

    // Reconstruct the signed message
    let email_str = claimed_email.unwrap_or("");
    let message = format!("{}:{}:{}:{}", identity_uri, email_str, received_challenge, timestamp);

    // Parse signature
    let signature_bytes = hex::decode(signature_hex)?;
    let signature_array: [u8; 64] = signature_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);

    // Verify
    use ed25519_dalek::Verifier;
    match verifying_key.verify(message.as_bytes(), &signature) {
        Ok(_) => println!("✓ PASS"),
        Err(e) => {
            println!("✗ FAIL ({})", e);
            return Ok(());
        }
    }

    // 4e. Verify public key matches on-chain identity
    print!("  [5/5] Public key matches on-chain identity... ");

    match client.request(Request::GetIdentity {
        uri: identity_uri.to_string(),
    }).await {
        Ok(Response::Ok { data }) => {
            let onchain_key = data["public_key"].as_str().unwrap_or("");
            if onchain_key == public_key_str {
                println!("✓ PASS");
            } else {
                println!("✗ FAIL");
                println!("       Assertion key: {}", public_key_str);
                println!("       On-chain key:  {}", onchain_key);
                return Ok(());
            }
        }
        Ok(Response::Error { message }) => {
            println!("✗ FAIL ({})", message);
            return Ok(());
        }
        Err(e) => {
            println!("✗ FAIL (daemon error: {})", e);
            return Ok(());
        }
    }

    println!();
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ AUTHENTICATION SUCCESSFUL                                      │");
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();
    println!("  User has proven control of:");
    if let Some(email) = claimed_email {
        println!("    Email:    {}", email);
    }
    println!("    Identity: {}", identity_uri);
    println!();
    println!("  The app can now trust this user session.");
    println!();

    Ok(())
}
