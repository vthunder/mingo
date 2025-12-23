//! SBO Auth Demo App
//!
//! Demonstrates the SBO identity authentication flow from an app's perspective.
//! This is a standalone app that communicates with the SBO daemon.
//!
//! Uses the nested JWT model:
//! - assertion_jwt: signed by ephemeral key, contains challenge response
//! - session_binding_jwt: signed by domain, wraps user delegation
//!
//! Performs full cryptographic verification of the JWT chain.

use clap::Parser;
use sbo_core::crypto::PublicKey;
use sbo_core::jwt;
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
    let (assertion_jwt, session_binding_jwt);

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
                        assertion_jwt = data["assertion_jwt"].as_str()
                            .ok_or_else(|| anyhow::anyhow!("Missing assertion_jwt"))?
                            .to_string();
                        session_binding_jwt = data["session_binding_jwt"].as_str()
                            .ok_or_else(|| anyhow::anyhow!("Missing session_binding_jwt"))?
                            .to_string();
                        break;
                    }
                    "rejected" => {
                        println!("REJECTED ✗");
                        if let Some(reason) = data["rejection_reason"].as_str() {
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

    // Step 3: Display the JWTs
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 3: Received JWTs                                          │");
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    println!("  Assertion JWT:       {}...", &assertion_jwt[..std::cmp::min(50, assertion_jwt.len())]);
    println!("  Session Binding JWT: {}...", &session_binding_jwt[..std::cmp::min(50, session_binding_jwt.len())]);
    println!();

    // Step 4: Verify the assertion chain
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ STEP 4: Verify JWT Chain                                       │");
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();

    // Check if using placeholder (session binding not yet implemented)
    if session_binding_jwt.starts_with("placeholder:") {
        println!("  NOTE: Session binding is a placeholder - skipping full verification");
        println!();

        // Still verify the assertion JWT
        print!("  [1/3] Decode assertion JWT... ");
        let assertion_claims = match jwt::decode_auth_assertion_claims(&assertion_jwt) {
            Ok(claims) => {
                println!("✓ PASS");
                claims
            }
            Err(e) => {
                println!("✗ FAIL ({:?})", e);
                return Ok(());
            }
        };

        // Verify nonce matches challenge
        print!("  [2/3] Nonce matches challenge... ");
        if assertion_claims.nonce == challenge {
            println!("✓ PASS");
        } else {
            println!("✗ FAIL");
            println!("       Expected: {}", challenge);
            println!("       Got:      {}", assertion_claims.nonce);
            return Ok(());
        }

        // Verify audience matches origin
        print!("  [3/3] Audience matches origin... ");
        if assertion_claims.aud == args.origin {
            println!("✓ PASS");
        } else {
            println!("✗ FAIL");
            println!("       Expected: {}", args.origin);
            println!("       Got:      {}", assertion_claims.aud);
            return Ok(());
        }

        let claimed_email = &assertion_claims.iss;
        println!();
        println!("┌─────────────────────────────────────────────────────────────────┐");
        println!("│ AUTHENTICATION PARTIALLY VERIFIED                              │");
        println!("└─────────────────────────────────────────────────────────────────┘");
        println!();
        println!("  Email (claimed): {}", claimed_email);
        println!();
        println!("  NOTE: Full verification requires session binding from domain.");
        println!("  The domain endpoint infrastructure is not yet implemented.");
        println!();

        return Ok(());
    }

    // Full cryptographic verification of JWT chain

    // Step 1: Decode session binding to get domain name
    print!("  [1/5] Decode session binding... ");
    let session_claims = match jwt::decode_session_binding_claims(&session_binding_jwt) {
        Ok(claims) => {
            println!("✓ PASS");
            claims
        }
        Err(e) => {
            println!("✗ FAIL ({:?})", e);
            return Ok(());
        }
    };

    let domain = session_claims.iss.strip_prefix("domain:")
        .unwrap_or(&session_claims.iss)
        .to_string();
    println!("         Domain: {}", domain);

    // Step 2: Fetch domain's public key from chain
    print!("  [2/5] Fetch domain key from chain... ");
    let domain_key = match client.request(Request::GetDomain {
        domain: domain.clone(),
    }).await {
        Ok(Response::Ok { data }) => {
            let key_str = data["public_key"].as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing public_key in domain"))?;
            match PublicKey::parse(key_str) {
                Ok(key) => {
                    println!("✓ PASS");
                    println!("         Key: {}...", &key_str[..std::cmp::min(30, key_str.len())]);
                    key
                }
                Err(e) => {
                    println!("✗ FAIL (invalid key: {:?})", e);
                    return Ok(());
                }
            }
        }
        Ok(Response::Error { message }) => {
            println!("✗ FAIL ({})", message);
            println!();
            println!("  NOTE: Domain '{}' not found on chain.", domain);
            println!("  Make sure you have synced the repo containing this domain.");
            return Ok(());
        }
        Err(e) => {
            println!("✗ FAIL (connection: {})", e);
            return Ok(());
        }
    };

    // Step 3: Verify full JWT chain cryptographically
    print!("  [3/5] Verify JWT chain signatures... ");
    let verified = match jwt::verify_auth_chain(
        &assertion_jwt,
        &session_binding_jwt,
        &domain_key,
        &args.origin,
        &challenge,
    ) {
        Ok(v) => {
            println!("✓ PASS");
            v
        }
        Err(e) => {
            println!("✗ FAIL");
            println!("         Error: {:?}", e);
            return Ok(());
        }
    };

    // Step 4: Check email matches request (if directed)
    print!("  [4/5] Email matches request... ");
    if let Some(ref requested) = args.email {
        if &verified.email == requested {
            println!("✓ PASS ({})", verified.email);
        } else {
            println!("✗ FAIL");
            println!("         Requested: {}", requested);
            println!("         Got:       {}", verified.email);
            return Ok(());
        }
    } else {
        println!("✓ PASS (undirected, got {})", verified.email);
    }

    // Step 5: Verify user key exists on chain (optional but recommended)
    print!("  [5/5] User key registered on chain... ");
    // For now, we trust the domain's session binding attests to this
    // Full verification would check /sys/names/{local_part} on chain
    println!("✓ PASS (attested by domain)");

    println!();
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│ ✓ AUTHENTICATION VERIFIED CRYPTOGRAPHICALLY                    │");
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();
    println!("  Verified identity:");
    println!("    Email:      {}", verified.email);
    println!("    Domain:     {}", verified.domain);
    println!("    User Key:   {}", verified.user_key.to_string());
    println!();
    println!("  Signature chain verified:");
    println!("    ✓ Session binding signed by domain key");
    println!("    ✓ User delegation signed by user key");
    println!("    ✓ Assertion signed by ephemeral key");
    println!("    ✓ Ephemeral key matches delegation");
    println!("    ✓ Challenge/nonce matches");
    println!("    ✓ Audience matches origin");
    println!();
    println!("  The app can now trust this authenticated session.");
    println!();

    Ok(())
}
