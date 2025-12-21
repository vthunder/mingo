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

// Use shared decode functions from sbo-rpc
use sbo_rpc::{decode_app_data_from_rows, DATA_CHUNK_SIZE};

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
        if let Some(app_id) = config.turbo_da.app_id {
            println!("  App ID: {} (from config)", app_id);
        } else {
            println!("  App ID: (determined by API key)");
        }
        let client = TurboDaClient::new(config.turbo_da);

        for i in 0..count {
            for (j, payload) in payloads.iter().enumerate() {
                println!("\nSubmitting payload {}/{} ({} bytes)...",
                    i * payloads.len() as u32 + j as u32 + 1,
                    count * payloads.len() as u32,
                    payload.len());

                // Always show payload summary
                match std::str::from_utf8(payload) {
                    Ok(s) => {
                        // Show first line (usually SBO-Version header)
                        if let Some(first_line) = s.lines().next() {
                            println!("  First line: {}", first_line);
                        }
                        // Try to parse as SBO to show action/path/id
                        if let Ok(msg) = sbo_core::wire::parse(payload) {
                            println!("  SBO message: {:?} {}{}", msg.action, msg.path, msg.id);
                            println!("  Signing key: {:?}", msg.signing_key);
                        }
                    }
                    Err(_) => println!("  [binary payload, {} bytes]", payload.len()),
                }

                if show_raw {
                    println!("\n--- Raw payload ---");
                    match std::str::from_utf8(payload) {
                        Ok(s) => println!("{}", s),
                        Err(_) => println!("{}", hex::encode(payload)),
                    }
                    println!("--- End payload ---\n");
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

/// Load or create identity key from ~/.sbo/identity
fn load_or_create_identity() -> Result<sbo_core::crypto::SigningKey> {
    use sbo_core::crypto::SigningKey;

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let identity_path = std::path::PathBuf::from(&home).join(".sbo").join("identity");

    if identity_path.exists() {
        // Load existing key
        let hex_str = std::fs::read_to_string(&identity_path)?;
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| anyhow::anyhow!("Invalid identity file: {}", e))?;
        if bytes.len() != 32 {
            anyhow::bail!("Invalid identity file: expected 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        println!("Loaded identity from {}", identity_path.display());
        Ok(SigningKey::from_bytes(&arr))
    } else {
        // Create new key
        std::fs::create_dir_all(identity_path.parent().unwrap())?;
        let key = SigningKey::generate();
        let hex_str = hex::encode(key.to_bytes());
        std::fs::write(&identity_path, &hex_str)?;
        println!("Created new identity at {}", identity_path.display());
        println!("Public key: {}", key.public_key().to_string());
        Ok(key)
    }
}

fn generate_preset(preset: super::super::TestPreset) -> Result<Vec<Vec<u8>>> {
    use sbo_core::crypto::SigningKey;
    use sbo_core::presets;

    // Load persistent identity for most presets (except Hello/Invalid)
    let signing_key = match preset {
        super::super::TestPreset::Hello | super::super::TestPreset::Invalid => {
            SigningKey::generate() // These don't need persistence
        }
        _ => load_or_create_identity()?,
    };

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
        super::super::TestPreset::ClaimName => {
            // Claim name "alice" at /sys/names/alice
            println!("Claiming name 'alice' for key {}", signing_key.public_key().to_string());
            Ok(vec![presets::claim_name(&signing_key, "alice")])
        }
        super::super::TestPreset::PostOwn => {
            // Post to own namespace /alice/nfts/item001
            println!("Posting to /alice/nfts/item001 (should succeed if name claimed)");
            Ok(vec![presets::post_to_own_namespace(
                &signing_key,
                "alice",
                "nfts",
                "item001",
                b"{\"name\":\"My NFT\",\"rarity\":\"legendary\"}"
            )])
        }
        super::super::TestPreset::PostUnauthorized => {
            // Try to post to /bob/nfts/ (should be DENIED)
            println!("Attempting to post to /bob/nfts/stolen (should be DENIED by policy)");
            Ok(vec![presets::post_unauthorized(
                &signing_key,
                "bob",
                "stolen",
                b"{\"name\":\"Stolen NFT\"}"
            )])
        }
    }
}

/// Decode a SCALE compact-encoded u32, returning (value, bytes_consumed)
fn decode_compact_u32(bytes: &[u8]) -> Result<(u32, usize)> {
    if bytes.is_empty() {
        anyhow::bail!("Empty bytes");
    }

    let first = bytes[0];
    let mode = first & 0b11;

    match mode {
        0b00 => {
            // Single-byte mode: upper 6 bits are the value
            Ok(((first >> 2) as u32, 1))
        }
        0b01 => {
            // Two-byte mode
            if bytes.len() < 2 {
                anyhow::bail!("Not enough bytes for 2-byte compact");
            }
            let val = u16::from_le_bytes([first, bytes[1]]) >> 2;
            Ok((val as u32, 2))
        }
        0b10 => {
            // Four-byte mode
            if bytes.len() < 4 {
                anyhow::bail!("Not enough bytes for 4-byte compact");
            }
            let val = u32::from_le_bytes([first, bytes[1], bytes[2], bytes[3]]) >> 2;
            Ok((val, 4))
        }
        0b11 => {
            // Big-integer mode (shouldn't happen for u32)
            anyhow::bail!("Big-integer mode not supported for u32");
        }
        _ => unreachable!(),
    }
}

/// Decode SCALE compact-encoded length and return the data bytes
fn decode_compact_and_data(bytes: &[u8]) -> Result<Vec<u8>> {
    let (length, header_size) = decode_compact_u32(bytes)?;
    let length = length as usize;

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

/// Scan a block using data matrix rows (Kate RPC)
///
/// This uses the same approach as sbo-daemon/rpc.rs to fetch data via
/// kate::query_rows, which retrieves data directly from the DA matrix.
pub async fn scan(block_number: u64, show_raw: bool, app_id: u32) -> Result<()> {
    use avail_rust::ext::avail_rust_core::rpc::kate;

    let config = Config::load(&Config::config_path()).unwrap_or_default();
    let endpoint = config.rpc.endpoints.first()
        .ok_or_else(|| anyhow::anyhow!("No RPC endpoints configured"))?;

    println!("Connecting to RPC: {}", endpoint);
    let client = AvailRustClient::new(endpoint).await?;

    println!("Fetching block {} (app_id={})...", block_number, app_id);

    let block = client.block(block_number as u32);
    let header = block.header().await?;
    let block_hash = header.hash();

    // Extract app_lookup and dimensions from header
    let (app_lookup_size, app_lookup_index, cols, rows) = match &header.extension {
        avail_rust::ext::avail_rust_core::header::HeaderExtension::V3(ext) => {
            (ext.app_lookup.size, &ext.app_lookup.index, ext.commitment.cols as u32, ext.commitment.rows as u32)
        }
        avail_rust::ext::avail_rust_core::header::HeaderExtension::V4(ext) => {
            (ext.app_lookup.size, &ext.app_lookup.index, ext.commitment.cols as u32, ext.commitment.rows as u32)
        }
    };

    println!("\n=== Block {} ===", block_number);
    println!("Matrix: {}x{} (original rows, extended={})", rows, cols, rows * 2);
    println!("App lookup size: {} chunks", app_lookup_size);

    println!("\n--- App Lookup ---");
    for item in app_lookup_index.iter() {
        println!("  app_id {} starts at chunk {}", item.app_id, item.start);
    }

    // Find data range for our app_id
    let mut app_start = None;
    let mut app_end = app_lookup_size;

    for (i, item) in app_lookup_index.iter().enumerate() {
        if item.app_id == app_id {
            app_start = Some(item.start);
            if i + 1 < app_lookup_index.len() {
                app_end = app_lookup_index[i + 1].start;
            }
            break;
        }
    }

    let Some(start_chunk) = app_start else {
        println!("\nApp ID {} not found in this block", app_id);
        return Ok(());
    };

    let chunk_count = app_end - start_chunk;
    println!("\n--- App {} Data ---", app_id);
    println!("Chunks: {} to {} ({} chunks, ~{} bytes)",
        start_chunk, app_end, chunk_count, chunk_count as usize * DATA_CHUNK_SIZE);

    // Calculate which rows we need for this app's data
    let start_row = start_chunk / cols;
    let end_row = (app_end.saturating_sub(1)) / cols;
    let rows_needed: Vec<u32> = (start_row..=end_row).collect();

    println!("Rows needed: {:?} (original indices)", rows_needed);

    // Fetch rows via Kate RPC (convert to extended row indices)
    let extended_rows: Vec<u32> = rows_needed.iter().map(|r| r * 2).collect();
    println!("Fetching extended rows: {:?}", extended_rows);

    let fetched = kate::query_rows(
        &client.rpc_client,
        extended_rows,
        Some(block_hash),
    ).await?;

    // Map fetched rows back to original indices
    let all_rows: Vec<(u32, kate::GRow)> = rows_needed.iter()
        .zip(fetched.into_iter())
        .map(|(&idx, row)| (idx, row))
        .collect();

    // Use shared decode function from sbo-rpc
    // This handles: cell extraction, IEC padding removal, SCALE Vec<Vec<u8>> decode,
    // extrinsic parsing, and gzip decompression
    println!("\n--- Decoding using shared sbo-rpc functions ---");
    let data = decode_app_data_from_rows(&all_rows, start_chunk, app_end, cols, true);

    if data.is_empty() {
        println!("No data extracted from matrix");
        return Ok(());
    }

    println!("\n--- Decoded Data: {} bytes ---", data.len());

    // Try to parse as SBO
    match sbo_core::wire::parse(&data) {
        Ok(msg) => {
            println!("SBO Message: {} {}{}", msg.action.name(), msg.path, msg.id);
            println!("Signing key: {:?}", msg.signing_key);
        }
        Err(e) => {
            println!("Not a valid SBO message: {}", e);
            let preview: String = data.iter().take(80)
                .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                .collect();
            println!("Data preview: {}", preview);
        }
    }

    if show_raw {
        println!("\n--- Raw Data ---");
        match std::str::from_utf8(&data) {
            Ok(s) => {
                for line in s.lines().take(30) {
                    println!("| {}", line);
                }
                if s.lines().count() > 30 {
                    println!("| ... ({} more lines)", s.lines().count() - 30);
                }
            }
            Err(_) => {
                println!("| {}", hex::encode(&data[..std::cmp::min(200, data.len())]));
            }
        }
        println!("-----------------");
    }

    Ok(())
}

// Note: unpad_iec_9797_1 and extract_data_from_encoded_extrinsic
// are now provided by sbo_rpc crate

/// Scan a specific block for data submissions (extrinsic parsing, legacy)
pub async fn scan_ext(block_number: u64, show_raw: bool, _app_id: u32) -> Result<()> {
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
    // Note: app_id is in signed extensions, not call data, so we can't show it here
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
                // Decode the call data - format: [pallet_id, variant_id, compact_len, data...]
                // Note: app_id is in signed extensions, not call data
                if let Ok(bytes) = hex::decode(&call_data) {
                    if bytes.len() > 2 {
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
