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
pub async fn submit(preset: Option<super::super::TestPreset>, file: Option<PathBuf>, count: Option<u32>, verbose: &[String]) -> Result<()> {
    let show_raw = verbose.iter().any(|v| v == "raw-submissions");
    let show_parsed = verbose.iter().any(|v| v == "parsed");

    let payloads = if let Some(preset) = preset {
        generate_preset(preset)?
    } else if let Some(file) = file {
        vec![std::fs::read(&file)?]
    } else {
        anyhow::bail!("Must specify --preset or --file");
    };

    let count = count.unwrap_or(1);

    // If only showing raw, skip connection attempt
    if show_raw && !show_parsed {
        for i in 0..count {
            for (j, payload) in payloads.iter().enumerate() {
                println!("=== Payload {}/{} ({} bytes) ===\n",
                    i * payloads.len() as u32 + j as u32 + 1,
                    count * payloads.len() as u32,
                    payload.len());

                // Show as UTF-8 (SBO wire format is UTF-8 text)
                match std::str::from_utf8(payload) {
                    Ok(s) => println!("{}", s),
                    Err(_) => println!("[binary payload, {} bytes]", payload.len()),
                }
                println!();
            }
        }
        return Ok(());
    }

    println!("Connecting to Avail...");
    let config = AvailConfig::default();
    let client = AvailClient::connect(config).await?;

    for i in 0..count {
        for (j, payload) in payloads.iter().enumerate() {
            println!("Submitting payload {}/{} ({} bytes)...",
                i * payloads.len() as u32 + j as u32 + 1,
                count * payloads.len() as u32,
                payload.len());

            if show_raw {
                if let Ok(s) = std::str::from_utf8(payload) {
                    println!("  Raw:\n{}", s);
                }
            }

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
    use sbo_core::presets;

    let signing_key = SigningKey::generate();

    match preset {
        super::super::TestPreset::Hello => {
            Ok(vec![b"Hello, SBO!".to_vec()])
        }
        super::super::TestPreset::Genesis => {
            // Genesis is a single batch containing both sys identity and root policy
            Ok(vec![presets::genesis(&signing_key)])
        }
        super::super::TestPreset::Post => {
            Ok(vec![presets::post(
                &signing_key,
                "/test/posts/",
                "hello",
                b"{\"message\":\"Hello, SBO!\"}"
            )])
        }
        super::super::TestPreset::Transfer => {
            todo!("Generate transfer preset")
        }
        super::super::TestPreset::Collection => {
            Ok(vec![presets::post(
                &signing_key,
                "/nft/collection/",
                "item001",
                b"{\"name\":\"Test NFT\",\"description\":\"A test NFT\"}"
            )])
        }
        super::super::TestPreset::Invalid => {
            Ok(vec![b"SBO-Version: 0.5\nAction: invalid\n\n".to_vec()])
        }
    }
}
