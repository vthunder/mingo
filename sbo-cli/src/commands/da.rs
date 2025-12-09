//! DA layer test commands

use std::path::PathBuf;
use anyhow::Result;
use sbo_avail::{AvailClient, AvailConfig, DataAvailability};

/// Stream blocks from DA layer
pub async fn stream(from: u64, limit: Option<u64>, raw: bool) -> Result<()> {
    println!("Connecting to Avail...");

    let config = AvailConfig::default();
    let client = AvailClient::connect(config).await?;

    println!("Streaming blocks from height {} (limit: {:?}, raw: {})", from, limit, raw);

    use futures::StreamExt;
    let mut stream = std::pin::pin!(client.stream_blocks(from));
    let mut count = 0u64;

    while let Some(block) = stream.next().await {
        println!("\n=== Block {} ===", block.number);
        println!("Hash: {}", hex::encode(block.hash));
        println!("Transactions: {}", block.transactions.len());

        for tx in &block.transactions {
            if raw {
                println!("  [{}] {} bytes: {}", tx.index, tx.data.len(), hex::encode(&tx.data));
            } else {
                // Try to parse as SBO message
                match sbo_core::wire::parse(&tx.data) {
                    Ok(msg) => {
                        println!("  [{}] SBO: {} {} {}", tx.index, msg.action.name(), msg.path, msg.id);
                    }
                    Err(e) => {
                        println!("  [{}] Not SBO: {} ({} bytes)", tx.index, e, tx.data.len());
                    }
                }
            }
        }

        count += 1;
        if let Some(limit) = limit {
            if count >= limit {
                println!("\nReached limit of {} blocks", limit);
                break;
            }
        }
    }

    Ok(())
}

/// Submit test payloads to DA
pub async fn submit(preset: Option<super::super::TestPreset>, file: Option<PathBuf>, count: Option<u32>) -> Result<()> {
    println!("Connecting to Avail...");

    let config = AvailConfig::default();
    let client = AvailClient::connect(config).await?;

    let payloads = if let Some(preset) = preset {
        generate_preset(preset)?
    } else if let Some(file) = file {
        vec![std::fs::read(&file)?]
    } else {
        anyhow::bail!("Must specify --preset or --file");
    };

    let count = count.unwrap_or(1);

    for i in 0..count {
        for (j, payload) in payloads.iter().enumerate() {
            println!("Submitting payload {}/{} ({} bytes)...", i * payloads.len() as u32 + j as u32 + 1, count * payloads.len() as u32, payload.len());

            match client.submit(payload).await {
                Ok(result) => {
                    println!("  Submitted! tx_hash: {}", hex::encode(result.tx_hash));
                    if let Some(block) = result.block_number {
                        println!("  Confirmed in block: {}", block);
                    }
                }
                Err(e) => {
                    println!("  Failed: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Check DA connection
pub async fn ping() -> Result<()> {
    println!("Connecting to Avail...");

    let config = AvailConfig::default();
    let client = AvailClient::connect(config).await?;

    println!("Connected!");
    println!("App ID: {}", client.app_id());

    // Try to fetch latest block
    match client.get_block(0).await {
        Ok(Some(block)) => {
            println!("Latest block: {} ({})", block.number, hex::encode(block.hash));
        }
        Ok(None) => {
            println!("No blocks found");
        }
        Err(e) => {
            println!("Error fetching block: {}", e);
        }
    }

    Ok(())
}

fn generate_preset(preset: super::super::TestPreset) -> Result<Vec<Vec<u8>>> {
    use sbo_core::crypto::SigningKey;

    let signing_key = SigningKey::generate();
    let public_key = signing_key.public_key();

    match preset {
        super::super::TestPreset::Hello => {
            Ok(vec![b"Hello, SBO!".to_vec()])
        }
        super::super::TestPreset::Genesis => {
            // Generate genesis messages
            let sys_identity = generate_sys_identity(&signing_key)?;
            let root_policy = generate_root_policy(&signing_key)?;
            Ok(vec![sys_identity, root_policy])
        }
        super::super::TestPreset::Post => {
            todo!("Generate post preset")
        }
        super::super::TestPreset::Transfer => {
            todo!("Generate transfer preset")
        }
        super::super::TestPreset::Collection => {
            todo!("Generate collection preset")
        }
        super::super::TestPreset::Invalid => {
            Ok(vec![b"SBO-Version: 0.5\nAction: invalid\n\n".to_vec()])
        }
    }
}

fn generate_sys_identity(signing_key: &sbo_core::crypto::SigningKey) -> Result<Vec<u8>> {
    let public_key = signing_key.public_key();
    let payload = serde_json::json!({
        "public_key": public_key.to_string(),
        "display_name": "System"
    });
    let payload_bytes = serde_json::to_vec(&payload)?;
    let content_hash = sbo_core::crypto::ContentHash::sha256(&payload_bytes);

    // Build message manually for now
    let mut headers = String::new();
    headers.push_str("SBO-Version: 0.5\n");
    headers.push_str("Action: post\n");
    headers.push_str("Path: /sys/names/\n");
    headers.push_str("ID: sys\n");
    headers.push_str("Type: object\n");
    headers.push_str("Content-Type: application/json\n");
    headers.push_str(&format!("Content-Length: {}\n", payload_bytes.len()));
    headers.push_str(&format!("Content-Hash: {}\n", content_hash.to_string()));
    headers.push_str(&format!("Signing-Key: {}\n", public_key.to_string()));

    // Sign headers + blank line
    let to_sign = format!("{}\n", headers);
    let signature = signing_key.sign(to_sign.as_bytes());

    headers.push_str(&format!("Signature: {}\n", signature.to_hex()));
    headers.push_str("\n");

    let mut result = headers.into_bytes();
    result.extend_from_slice(&payload_bytes);

    Ok(result)
}

fn generate_root_policy(signing_key: &sbo_core::crypto::SigningKey) -> Result<Vec<u8>> {
    let public_key = signing_key.public_key();
    let payload = serde_json::json!({
        "grants": [
            {"to": "*", "can": ["create"], "on": "/sys/names/*"},
            {"to": "owner", "can": ["update", "delete"], "on": "/sys/names/*"},
            {"to": "owner", "can": ["*"], "on": "/$owner/**"}
        ]
    });
    let payload_bytes = serde_json::to_vec(&payload)?;
    let content_hash = sbo_core::crypto::ContentHash::sha256(&payload_bytes);

    let mut headers = String::new();
    headers.push_str("SBO-Version: 0.5\n");
    headers.push_str("Action: post\n");
    headers.push_str("Path: /sys/policies/\n");
    headers.push_str("ID: root\n");
    headers.push_str("Type: object\n");
    headers.push_str("Content-Type: application/json\n");
    headers.push_str(&format!("Content-Length: {}\n", payload_bytes.len()));
    headers.push_str(&format!("Content-Hash: {}\n", content_hash.to_string()));
    headers.push_str(&format!("Signing-Key: {}\n", public_key.to_string()));

    let to_sign = format!("{}\n", headers);
    let signature = signing_key.sign(to_sign.as_bytes());

    headers.push_str(&format!("Signature: {}\n", signature.to_hex()));
    headers.push_str("\n");

    let mut result = headers.into_bytes();
    result.extend_from_slice(&payload_bytes);

    Ok(result)
}
