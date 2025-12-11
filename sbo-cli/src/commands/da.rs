//! DA layer test commands

use std::io::Read as _;
use std::path::PathBuf;
use anyhow::Result;
use flate2::read::GzDecoder;
use sbo_avail::{AvailClient, AvailConfig, DataAvailability};
use sbo_daemon::config::Config;
use sbo_daemon::turbo::TurboDaClient;
use avail_rust::{
    Client as AvailRustClient,
    EncodeSelector,
    ext::avail_rust_core::rpc::system::fetch_extrinsics::Options as RpcOptions,
};

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
pub async fn submit(preset: Option<super::super::TestPreset>, file: Option<PathBuf>, count: Option<u32>, turbo: bool, verbose: &[String]) -> Result<()> {
    let show_raw = verbose.iter().any(|v| v == "raw-submissions");

    let payloads = if let Some(preset) = preset {
        generate_preset(preset)?
    } else if let Some(file) = file {
        vec![std::fs::read(&file)?]
    } else {
        anyhow::bail!("Must specify --preset or --file");
    };

    let count = count.unwrap_or(1);

    if turbo {
        // Use TurboDA for submission
        let config = Config::load(&Config::config_path())?;
        if config.turbo_da.api_key.is_none() {
            anyhow::bail!("TurboDA API key not configured. Set 'api_key' in [turbo_da] section of ~/.sbo/config.toml");
        }

        println!("Connecting to TurboDA: {}", config.turbo_da.endpoint);
        let client = TurboDaClient::new(config.turbo_da);

        for i in 0..count {
            for (j, payload) in payloads.iter().enumerate() {
                println!("Submitting payload {}/{} ({} bytes)...",
                    i * payloads.len() as u32 + j as u32 + 1,
                    count * payloads.len() as u32,
                    payload.len());

                if show_raw {
                    match std::str::from_utf8(payload) {
                        Ok(s) => println!("\n{}\n", s),
                        Err(_) => println!("  [binary payload, {} bytes]", payload.len()),
                    }
                }

                match client.submit_raw(payload).await {
                    Ok(result) => {
                        println!("  Submitted! submission_id: {}", result.submission_id);
                    }
                    Err(e) => {
                        println!("  Failed: {}", e);
                    }
                }
            }
        }
    } else {
        // Use light client for submission (may not work)
        println!("Connecting to Avail light client...");
        println!("Note: Light client submission may not be supported. Use --turbo for TurboDA.");
        let config = AvailConfig::default();
        let client = AvailClient::connect(config).await?;

        for i in 0..count {
            for (j, payload) in payloads.iter().enumerate() {
                println!("Submitting payload {}/{} ({} bytes)...",
                    i * payloads.len() as u32 + j as u32 + 1,
                    count * payloads.len() as u32,
                    payload.len());

                if show_raw {
                    match std::str::from_utf8(payload) {
                        Ok(s) => println!("\n{}\n", s),
                        Err(_) => println!("  [binary payload, {} bytes]", payload.len()),
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

/// Decode SCALE compact-encoded length and return the data bytes
fn decode_compact_and_data(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() {
        anyhow::bail!("Empty bytes");
    }

    let first = bytes[0];
    let mode = first & 0b11;

    let (length, header_size): (usize, usize) = match mode {
        0b00 => {
            // Single-byte mode: upper 6 bits are the value
            ((first >> 2) as usize, 1)
        }
        0b01 => {
            // Two-byte mode: upper 6 bits + next byte
            if bytes.len() < 2 {
                anyhow::bail!("Not enough bytes for 2-byte compact");
            }
            let val = u16::from_le_bytes([first, bytes[1]]) >> 2;
            (val as usize, 2)
        }
        0b10 => {
            // Four-byte mode
            if bytes.len() < 4 {
                anyhow::bail!("Not enough bytes for 4-byte compact");
            }
            let val = u32::from_le_bytes([first, bytes[1], bytes[2], bytes[3]]) >> 2;
            (val as usize, 4)
        }
        0b11 => {
            // Big-integer mode: first byte upper 6 bits = (num_bytes - 4)
            let num_bytes = ((first >> 2) + 4) as usize;
            if bytes.len() < 1 + num_bytes {
                anyhow::bail!("Not enough bytes for big-int compact");
            }
            // Read the bytes as little-endian
            let mut val = 0usize;
            for (i, &b) in bytes[1..1 + num_bytes].iter().enumerate() {
                val |= (b as usize) << (8 * i);
            }
            (val, 1 + num_bytes)
        }
        _ => unreachable!(),
    };

    let data_start = header_size;
    let data_end = data_start + length;

    if bytes.len() < data_end {
        anyhow::bail!(
            "Not enough data: expected {} bytes, have {}",
            length,
            bytes.len() - data_start
        );
    }

    Ok(bytes[data_start..data_end].to_vec())
}

/// Scan a specific block for data submissions
pub async fn scan(block_number: u64, show_raw: bool, _app_id: u32) -> Result<()> {
    let config = Config::load(&Config::config_path()).unwrap_or_default();
    let endpoint = config.rpc.endpoints.first()
        .ok_or_else(|| anyhow::anyhow!("No RPC endpoints configured"))?;

    println!("Connecting to RPC: {}", endpoint);
    let client = AvailRustClient::new(endpoint).await?;

    println!("Fetching block {}...", block_number);

    println!("\n=== Block {} ===", block_number);

    let block = client.block(block_number as u32);

    // Show app_lookup from header
    let header = block.header().await?;
    let (index, size) = match &header.extension {
        avail_rust::ext::avail_rust_core::header::HeaderExtension::V3(ext) => {
            (&ext.app_lookup.index, ext.app_lookup.size)
        }
        avail_rust::ext::avail_rust_core::header::HeaderExtension::V4(ext) => {
            (&ext.app_lookup.index, ext.app_lookup.size)
        }
    };
    println!("\n--- App Lookup (size={}) ---", size);
    for item in index.iter() {
        println!("  app_id {} starts at index {}", item.app_id, item.start);
    }

    // Use extrinsic_infos to get all extrinsics with call data
    let opts = RpcOptions::new().encode_as(EncodeSelector::Call);
    let mut infos = block.extrinsic_infos(opts).await?;

    println!("\n--- All Extrinsics ({}) ---", infos.len());
    for info in &infos {
        println!("[{}] PI:{} VI:{}",
            info.ext_index, info.pallet_id, info.variant_id);
    }

    println!("\n--- Data Submissions ---");

    let mut found_count = 0;

    // Helper to display SubmitData
    let display_data = |idx: usize, ext_idx: u32, raw_data: &[u8], show_raw: bool| {
        // Check for gzip magic and decompress if needed
        let (data, is_gzipped) = if raw_data.len() >= 2 && raw_data[0] == 0x1f && raw_data[1] == 0x8b {
            let mut decoder = GzDecoder::new(raw_data);
            let mut decompressed = Vec::new();
            match decoder.read_to_end(&mut decompressed) {
                Ok(_) => (decompressed, true),
                Err(_) => (raw_data.to_vec(), false),
            }
        } else {
            (raw_data.to_vec(), false)
        };

        let gzip_label = if is_gzipped { " (gzipped)" } else { "" };
        println!("[{}] ext_idx={} {} bytes{}", idx, ext_idx, data.len(), gzip_label);

        // Try to parse as SBO
        match sbo_core::wire::parse(&data) {
            Ok(msg) => {
                println!("     SBO: {} {}{}", msg.action.name(), msg.path, msg.id);
            }
            Err(_) => {
                // Try to show as text, replacing non-printable chars
                let printable: String = data.iter()
                    .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                    .collect();
                if printable.len() <= 100 {
                    println!("     Data: {}", printable);
                } else {
                    println!("     Data: {}...", &printable[..100]);
                }
            }
        }

        if show_raw {
            match std::str::from_utf8(&data) {
                Ok(s) => {
                    println!("     ---");
                    for line in s.lines() {
                        println!("     | {}", line);
                    }
                    println!("     ---");
                }
                Err(_) => {
                    // Show as printable ASCII with dots for non-printable
                    let printable: String = data.iter()
                        .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                        .collect();
                    println!("     ---");
                    for chunk in printable.as_bytes().chunks(80) {
                        println!("     | {}", std::str::from_utf8(chunk).unwrap_or(""));
                    }
                    println!("     ---");
                }
            }
        }
        println!();
    };

    // Process extrinsics with pallet_id 29 (DataAvailability) and variant_id 1 (SubmitData)
    for info in &mut infos {
        if info.pallet_id == 29 && info.variant_id == 1 {
            if let Some(call_data) = info.data.take() {
                // Decode the call data - format: [pallet_id, variant_id, compact_len, ...data]
                if let Ok(bytes) = hex::decode(&call_data) {
                    if bytes.len() > 2 {
                        // Skip pallet + variant bytes, then decode SCALE compact length
                        let payload = &bytes[2..];
                        match decode_compact_and_data(payload) {
                            Ok(data) => {
                                display_data(found_count, info.ext_index, &data, show_raw);
                                found_count += 1;
                            }
                            Err(e) => {
                                println!("[{}] ext_idx={} decode error: {}", found_count, info.ext_index, e);
                                println!("     Raw bytes: {:?}...", &payload[..std::cmp::min(50, payload.len())]);
                            }
                        }
                    }
                }
            }
        }
    }

    if found_count == 0 {
        println!("No SubmitData transactions found in this block");
        println!("(Blocks submitted via TurboDA may use batch wrappers)");
    } else {
        println!("\nTotal: {} SubmitData transaction(s)", found_count);
    }

    Ok(())
}

/// Check TurboDA submission status
pub async fn turbo_status(submission_id: &str) -> Result<()> {
    let config = Config::load(&Config::config_path())?;
    if config.turbo_da.api_key.is_none() {
        anyhow::bail!("TurboDA API key not configured");
    }

    println!("Checking submission: {}", submission_id);
    let client = TurboDaClient::new(config.turbo_da);

    match client.get_submission_status(submission_id).await {
        Ok(status) => {
            println!("\n{}", serde_json::to_string_pretty(&status)?);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    }

    Ok(())
}
