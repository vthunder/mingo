# Avail Data Matrix Structure and Decoding

This document describes how data is stored in Avail's data availability layer and how to decode it to retrieve submitted application data.

## Overview

When you submit data to Avail using `submit_data()`, it goes through several transformations before being stored in the block's data matrix. To retrieve the data, you must reverse these transformations.

## Data Flow

```
Submit: raw_data → IEC padding → chunk to 31B → pad to 32B → matrix scalars
Decode: matrix scalars → extract 31B → concat → SCALE decode → remove IEC → raw_data
```

## Block Header Structure

The block header extension contains critical information for locating app-specific data:

```rust
header.extension.v3 {
    app_lookup: DataLookup {
        size: u32,           // Total chunks for all apps
        index: Vec<DataLookupItem> {
            app_id: u32,     // Application ID
            start: u32,      // Starting chunk index (0-based)
        }
    },
    commitment: KateCommitment {
        rows: u16,           // Number of rows in data matrix
        cols: u16,           // Number of columns in data matrix
        ...
    }
}
```

### App Lookup Interpretation

- `start` is the chunk index where this app's data begins
- The app's data extends from `start` to either:
  - The next app's `start` value, or
  - `app_lookup.size` if this is the last app
- Chunk indices map to matrix positions: `row = chunk / cols`, `col = chunk % cols`

## Matrix Structure

### Dimensions

- **Rows**: Typically 1-256, power of 2
- **Columns**: Typically 64-256, power of 2
- **Extension**: Vertical only (rows are doubled for erasure coding parity)
- **Cell size**: 32 bytes (BLS12-381 scalar / U256)

### Erasure Coding Row Interleaving

**IMPORTANT**: The `rows` value in the block header is the ORIGINAL row count. The actual data matrix returned by `kate_queryRows` has 2× the rows due to erasure coding extension, with **original and parity rows interleaved**:

```
Extended Row 0  → Original Row 0 (data)
Extended Row 1  → Parity for Row 0
Extended Row 2  → Original Row 1 (data)
Extended Row 3  → Parity for Row 1
Extended Row 4  → Original Row 2 (data)
...
Extended Row 2N → Original Row N (data)
Extended Row 2N+1 → Parity for Row N
```

This interleaving is a consequence of FFT-based erasure coding. When Avail extends the matrix:
1. Each column is treated as polynomial evaluations
2. IFFT is applied to get coefficients
3. FFT is applied on an extended domain (2× points)
4. The result interleaves original values with parity values

**To fetch original row N, you must request extended row 2*N from the RPC.**

Example for a block with `rows: 32` (header value):
- Extended matrix has 64 rows (0-63)
- Original data is in even rows: 0, 2, 4, ..., 62
- Parity data is in odd rows: 1, 3, 5, ..., 63
- To get all 32 original rows, request extended rows: 0, 2, 4, ..., 62

### Data Packing

Each 32-byte scalar contains only **31 bytes of actual data**:

```
CHUNK_SIZE = 32      // Total scalar size
DATA_CHUNK_SIZE = 31 // Usable data bytes per scalar
```

The last byte of each scalar is padding (always 0x00) because BLS12-381 field elements must be less than the ~255-bit prime modulus.

### Byte Order

Scalars are stored in **big-endian** format. When using `kate::query_rows()`:

```rust
let scalar: U256 = row[col];
let bytes: [u8; 32] = scalar.to_big_endian();
let data: &[u8] = &bytes[0..31];  // First 31 bytes are data
```

## Data Encoding Layers

### Layer 1: IEC 9797-1 Padding

Before chunking, raw data is padded using ISO/IEC 9797-1 method 2:

```
original_data || 0x80 || 0x00...0x00
```

The padding extends to a multiple of the chunk size.

### Layer 2: Chunk Padding

Each 31-byte data chunk is extended to 32 bytes:

```rust
fn pad_to_chunk(chunk: [u8; 31]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    padded[0..31].copy_from_slice(&chunk);
    padded[31] = 0x00;  // Padding byte
    padded
}
```

### Layer 3: SCALE Encoding

The data in the matrix is **not** raw submitted bytes. Per [avail-core kate/recovery](https://github.com/availproject/avail-core/blob/main/kate/recovery/src/com.rs), the matrix stores:

```rust
// From kate/recovery: AppData is Vec<Vec<u8>> = "list of extrinsics encoded in a block"
// decode_app_extrinsics returns Result<AppData, _> where AppData = Vec<Vec<u8>>
Vec<Vec<u8>>  // SCALE-encoded vector of opaque extrinsic bytes
```

Each inner `Vec<u8>` is one raw encoded `UncheckedExtrinsic` (opaque bytes with length prefix).

Structure after removing IEC padding:
```
[outer_vec_len: compact]                    // Number of extrinsics
[ext_0_len: compact][ext_0_bytes...]        // First extrinsic (length-prefixed)
[ext_1_len: compact][ext_1_bytes...]        // Second extrinsic
...
```

**Authoritative source**: In kate/src/com.rs, the encoding step uses `opaques.encode()` where `opaques` is `Vec<Vec<u8>>`. This SCALE-encodes the structured collection, preserving length information and boundaries between individual extrinsics.

### Layer 4: Extrinsic Structure

Each extrinsic (for signed `submit_data` calls) contains:

```
[version: u8]           // 0x84 for signed v4
[address_type: u8]      // MultiAddress variant (0x00=Id)
[address: 32 bytes]     // Public key (for Id variant)
[signature_type: u8]    // 0x00=Ed25519, 0x01=Sr25519, 0x02=Ecdsa
[signature: 64-65 bytes]// Signature (65 for Ecdsa)
[era: 1-2 bytes]        // Mortality (0x00=immortal, else mortal)
[nonce: compact]        // Account nonce
[tip: compact]          // Transaction tip
[app_id: compact]       // **Avail-specific**: Application ID in SignedExtra
[call_data...]          // The actual call
```

**Note**: The `app_id` field in SignedExtra is Avail-specific and not part of standard Substrate extrinsics.

The call data for `DataAvailability::submit_data` (pallet=29, call=1):

```
[pallet_index: u8]      // 29 = DataAvailability pallet
[call_index: u8]        // 1 = submit_data call
[data: Vec<u8>]         // Compact length + raw submitted bytes
```

### Layer 5: Optional Gzip Compression

Submitted data may optionally be gzip-compressed. Check for gzip magic bytes:

```rust
if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
    // Data is gzip-compressed, decompress before parsing
    let mut decoder = GzDecoder::new(data.as_slice());
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    data = decompressed;
}
```

## Decoding Algorithm

### Step 1: Fetch Matrix Rows

```rust
use avail_rust::kate;

// Calculate which ORIGINAL rows we need based on chunk range
let rows_needed: Vec<u32> = compute_rows_for_chunks(start_chunk, end_chunk, cols);

// IMPORTANT: Convert original row indices to extended row indices (multiply by 2)
// This is because the RPC returns the extended matrix with interleaved parity rows
let extended_rows: Vec<u32> = rows_needed.iter().map(|r| r * 2).collect();

let fetched = kate::query_rows(&client, extended_rows, Some(block_hash)).await?;

// Map back: fetched[i] corresponds to original row rows_needed[i]
```

### Step 2: Extract Data from Scalars

```rust
let mut data = Vec::new();

for chunk_idx in start_chunk..end_chunk {
    let row_idx = chunk_idx / cols;
    let col_idx = chunk_idx % cols;

    let scalar = &rows[row_idx][col_idx];
    let bytes: [u8; 32] = scalar.to_big_endian();

    // Take first 31 bytes only (last byte is padding)
    data.extend_from_slice(&bytes[0..31]);
}
```

### Step 3: Remove IEC 9797-1 Padding

```rust
fn unpad_iec_9797_1(data: &mut Vec<u8>) {
    // Scan backwards: skip zeros, find 0x80 marker
    while data.last() == Some(&0x00) {
        data.pop();
    }
    if data.last() == Some(&0x80) {
        data.pop();
    }
}
```

### Step 4: Decode SCALE Vec<Vec<u8>>

Use standard SCALE decoding to parse the outer vector:

```rust
use parity_scale_codec::Decode;

// Decode as Vec<Vec<u8>> per avail-core spec
let extrinsics: Vec<Vec<u8>> = Vec::<Vec<u8>>::decode(&mut &data[..])?;

println!("Decoded {} extrinsic(s)", extrinsics.len());

for ext_bytes in extrinsics {
    let blob = extract_data_from_extrinsic(&ext_bytes)?;
    // Process blob...
}
```

### Step 5: Extract Data from Extrinsic

Parse the extrinsic structure properly - do NOT use magic byte scanning:

```rust
fn extract_data_from_extrinsic(encoded: &[u8]) -> Option<Vec<u8>> {
    let mut input = encoded;

    // Skip optional length prefix (check if first bytes look like a length)
    // ... (see full implementation in sbo-cli/src/commands/da.rs)

    // Version byte
    let version = input[0];
    input = &input[1..];
    let is_signed = (version & 0x80) != 0;

    if is_signed {
        // Skip MultiAddress (1 byte type + 32 bytes for Id variant)
        let addr_type = input[0];
        input = &input[1..];
        let addr_len = match addr_type {
            0x00 => 32,  // Id
            0x01 => decode_compact_len(input),  // Index
            // ... other variants
        };
        input = &input[addr_len..];

        // Skip MultiSignature (1 byte type + 64-65 bytes)
        let sig_type = input[0];
        input = &input[1..];
        let sig_len = match sig_type {
            0x00 | 0x01 => 64,  // Ed25519, Sr25519
            0x02 => 65,         // Ecdsa
        };
        input = &input[sig_len..];

        // Skip Era (1-2 bytes)
        let era = input[0];
        input = &input[1..];
        if era != 0x00 { input = &input[1..]; }

        // Skip Nonce (compact)
        let (_, consumed) = decode_compact(input)?;
        input = &input[consumed..];

        // Skip Tip (compact)
        let (_, consumed) = decode_compact(input)?;
        input = &input[consumed..];

        // Skip AppId in SignedExtra (compact) - Avail-specific!
        let (app_id, consumed) = decode_compact(input)?;
        input = &input[consumed..];
    }

    // Pallet and call index
    let pallet = input[0];
    let call = input[1];
    input = &input[2..];

    // For DataAvailability::submit_data (29, 1), decode Vec<u8>
    if pallet == 29 && call == 1 {
        let data: Vec<u8> = Vec::<u8>::decode(&mut &input[..])?;
        return Some(data);
    }

    None
}
```

**Important**: Never use magic byte scanning (e.g., searching for "SBO-"). Always parse the extrinsic structure properly using the standard encoding.

### Step 6: Decompress if Gzipped

```rust
use flate2::read::GzDecoder;

let final_data = if blob.len() >= 2 && blob[0] == 0x1f && blob[1] == 0x8b {
    let mut decoder = GzDecoder::new(blob.as_slice());
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    decompressed
} else {
    blob
};
```

## Example: Block 2726277

```
Header:
  block_number: 2726277
  app_lookup_size: 70  (70 chunks total)
  cols: 128
  rows: 1
  app_lookup: [{app_id: 246, start: 0}, {app_id: 506, start: 21}]

For app_id 506:
  Chunks: 21 to 70 (49 chunks, ~1519 bytes raw)

Decoded structure (after IEC unpadding):
  Vec<Vec<u8>> with 1 extrinsic:
    [04]              Outer vec length = 1
    [d9 17]           Inner vec length = 1498 bytes (compact: 0x17d9 >> 2 = 1494... wait, let me recalc)

  Extrinsic 0 (1498 bytes):
    [84]              Version 0x84 = signed, version 4
    [00][32 bytes]    MultiAddress::Id (public key)
    [01][64 bytes]    MultiSignature::Sr25519
    [era][nonce][tip] SignedExtra fields
    [f5 03]           app_id = 506 (compact)
    [1d][01]          pallet=29, call=1 (DataAvailability::submit_data)
    [a9 15]           Data length = 1386 bytes (compact)
    [1386 bytes]      Raw SBO data

SBO Message:
  Action: post
  Path: /sys/names/sys
  (Contains system identity registration)
```

## Example: Block 2723989 (Legacy)

```
Header:
  block_number: 2723989
  app_lookup_size: 49  (49 chunks for app 506)
  cols: 64
  rows: 1
  app_lookup: [{app_id: 506, start: 0}]

Matrix (64 cols × 1 row = 64 scalars):
  Total capacity: 64 × 31 = 1984 bytes

Decoded structure:
  [04]              Vec length = 1 extrinsic
  [71 17]           Extrinsic length = 1500 bytes
  [114 bytes]       Signature, address, era, nonce, tip, call metadata
  [a9 15]           Data length = 1386 bytes (compact)
  [1386 bytes]      Raw SBO data (2 messages)

SBO Messages:
  Message 1: /sys/names/sys (758 bytes) - System identity
  Message 2: /sys/policies/root (628 bytes) - Root policy
  Total: 1386 bytes
```

## Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| CHUNK_SIZE | 32 | Bytes per matrix scalar |
| DATA_CHUNK_SIZE | 31 | Usable data bytes per scalar |
| EXTENSION_FACTOR | 2 | Rows are doubled for erasure coding |

## Common Pitfalls

1. **Wrong byte order**: Scalars are big-endian, not little-endian
2. **Using all 32 bytes**: Only first 31 bytes contain data
3. **Expecting raw data**: Matrix contains SCALE-encoded `Vec<Vec<u8>>` of extrinsics
4. **Ignoring IEC padding**: Must be removed before SCALE decoding
5. **Chunk vs byte indexing**: `app_lookup.start` is chunk index, not byte offset
6. **Requesting wrong row indices**: Header `rows` is original count; RPC returns extended matrix with 2× rows. To fetch original row N, request extended row 2*N. Odd rows contain parity data, not original data!
7. **Missing AppId in SignedExtra**: Avail adds `app_id` after `tip` in signed extrinsics - must skip this when parsing
8. **Magic byte scanning**: Never search for patterns like "SBO-" to find data boundaries - parse the structure properly
9. **Ignoring gzip compression**: Submitted data may be gzip-compressed (check for 0x1f 0x8b magic)

## References

- [avail-core kate/recovery com.rs](https://github.com/availproject/avail-core/blob/main/kate/recovery/src/com.rs) - **Authoritative source** for `AppData = Vec<Vec<u8>>` and `decode_app_extrinsics`
- [avail-core kate com.rs](https://github.com/availproject/avail-core/blob/main/kate/src/com.rs) - Encoding with `opaques.encode()` where opaques is `Vec<Vec<u8>>`, FFT extension and interleaving
- [avail-core constants](https://github.com/availproject/avail-core/blob/main/core/src/constants.rs)
- [avail-light app_client.rs](https://github.com/availproject/avail-light/blob/main/core/src/app_client.rs) - Light client usage of kate_recovery
- [avail-light rpc client](https://github.com/availproject/avail-light/blob/main/core/src/network/rpc/client.rs)
- [sbo-cli da.rs](../sbo-cli/src/commands/da.rs) - Working implementation of matrix decoding
