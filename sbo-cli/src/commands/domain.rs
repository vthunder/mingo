//! Domain command implementations (domain.v1 schema)
//!
//! Domains are JWT-based authority objects stored at /sys/domains/<domain_name>.
//! The domain JWT contains: iss ("self"), sub (domain name), public_key, iat.
//! Domains can sign identities for domain-certified identity flows.

use anyhow::Result;
use sbo_core::keyring::Keyring;
use sbo_daemon::config::Config;
use sbo_daemon::ipc::{IpcClient, Request, Response};

/// Create a domain on-chain
pub async fn create(
    uri: &str,
    domain_name: &str,
    key_alias: Option<&str>,
    dry_run: bool,
) -> Result<()> {
    // Open keyring and resolve signing key
    let keyring = Keyring::open()?;
    let alias = keyring.resolve_alias(key_alias)?;
    let signing_key = keyring.get_signing_key(&alias)?;
    let public_key = signing_key.public_key();

    // Create domain JWT and wire-format message
    let wire_bytes = sbo_core::presets::create_domain(&signing_key, domain_name);

    if dry_run {
        // Output the SBO message instead of submitting
        println!("{}", String::from_utf8_lossy(&wire_bytes));
        return Ok(());
    }

    // Connect to daemon and submit
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    // Build domain URI
    let domain_uri = format!("{}/sys/domains/{}", uri.trim_end_matches('/'), domain_name);

    println!("Creating domain '{}' at {}", domain_name, uri);
    println!("  Key: {} ({})", alias, public_key.to_string());

    match client
        .request(Request::SubmitDomain {
            uri: uri.to_string(),
            domain_name: domain_name.to_string(),
            data: wire_bytes,
        })
        .await
    {
        Ok(Response::Ok { data }) => {
            let status = data["status"].as_str().unwrap_or("unknown");

            match status {
                "submitted" => {
                    println!("\n○ Domain submitted");
                    println!("  URI: {}", domain_uri);
                    if let Some(id) = data["submission_id"].as_str() {
                        println!("  Submission ID: {}", id);
                    }
                    println!("\n  Check status with: sbo domain show {}", domain_name);
                }
                _ => {
                    println!("\n? Status: {}", status);
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

/// List domains from synced repos
pub async fn list(uri_filter: Option<&str>) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    match client
        .request(Request::ListDomains {
            uri: uri_filter.map(|s| s.to_string()),
        })
        .await
    {
        Ok(Response::Ok { data }) => {
            let domains = data["domains"].as_array();

            if domains.map(|d| d.is_empty()).unwrap_or(true) {
                println!("No domains found.");
                println!("\nCreate one with: sbo domain create <chain-uri> <domain-name>");
                return Ok(());
            }

            let domains = domains.unwrap();

            println!(
                "{:<30} {:<50} {}",
                "DOMAIN", "PUBLIC KEY", "CHAIN"
            );
            println!("{}", "-".repeat(100));

            for domain in domains {
                let name = domain["domain"].as_str().unwrap_or("?");
                let public_key = domain["public_key"].as_str().unwrap_or("?");
                let chain = domain["chain"].as_str().unwrap_or("?");

                println!(
                    "{:<30} {:<50} {}",
                    truncate(name, 28),
                    truncate(public_key, 48),
                    truncate(chain, 30),
                );
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

/// Show detailed domain information
pub async fn show(domain_or_uri: &str) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    let client = IpcClient::new(config.daemon.socket_path);

    match client
        .request(Request::GetDomain {
            domain: domain_or_uri.to_string(),
        })
        .await
    {
        Ok(Response::Ok { data }) => {
            // Single domain or multiple
            if let Some(domains) = data["domains"].as_array() {
                // Multiple domains with same name across chains
                for (i, domain) in domains.iter().enumerate() {
                    if i > 0 {
                        println!("\n{}", "-".repeat(60));
                    }
                    print_domain_details(domain);
                }
            } else {
                // Single domain
                print_domain_details(&data);
            }
        }
        Ok(Response::Error { message }) => {
            eprintln!("Domain not found: {}", message);
            eprintln!("\nList domains with: sbo domain list");
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

fn print_domain_details(data: &serde_json::Value) {
    let domain = data["domain"].as_str().unwrap_or("?");
    let uri = data["uri"].as_str().unwrap_or("?");
    let chain = data["chain"].as_str().unwrap_or("?");
    let public_key = data["public_key"].as_str().unwrap_or("?");
    let status = data["status"].as_str().unwrap_or("unknown");

    println!("Domain: {}", domain);
    println!("  URI:        {}", uri);
    println!("  Chain:      {}", chain);
    println!("  Public Key: {}", public_key);
    println!("  Status:     {}", status);
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}
