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

The data in the matrix is **not** raw submitted bytes. It's SCALE-encoded extrinsic data:

```
Vec<Extrinsic> where each Extrinsic contains:
  - Compact length prefix
  - Extrinsic bytes (signature, call data, submitted blob)
```

Structure:
```
[vec_len: compact]
[ext_0_len: compact][ext_0_bytes...]
[ext_1_len: compact][ext_1_bytes...]
...
```

### Layer 4: Extrinsic Structure

Each extrinsic (for signed `submit_data` calls) contains:

```
[version: u8]           // 0x84 for signed v4
[address_type: u8]      // MultiAddress variant
[address: 32 bytes]     // Public key
[signature_type: u8]    // 0x00=Ed25519, 0x01=Sr25519
[signature: 64 bytes]   // Signature
[era: 1-2 bytes]        // Mortality
[nonce: compact]        // Account nonce
[tip: compact]          // Transaction tip
[call_data...]          // The actual call
```

The call data for `DataAvailability::submit_data`:

```
[pallet_index: u8]      // DataAvailability pallet
[call_index: u8]        // submit_data call
[data: Vec<u8>]         // Compact length + raw bytes
```

## Decoding Algorithm

### Step 1: Fetch Matrix Rows

```rust
use avail_rust::kate;

let rows_needed: Vec<u32> = compute_rows_for_chunks(start_chunk, end_chunk, cols);
let fetched = kate::query_rows(&client, rows_needed, Some(block_hash)).await?;
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

### Step 4: Decode SCALE Vec

```rust
fn decode_scale_compact(data: &[u8]) -> Option<(usize, usize)> {
    let mode = data[0] & 0b11;
    match mode {
        0b00 => Some((data[0] as usize >> 2, 1)),
        0b01 => Some((u16::from_le_bytes([data[0], data[1]]) as usize >> 2, 2)),
        0b10 => Some((u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize >> 2, 4)),
        _ => None, // Big integer mode
    }
}

let (vec_len, consumed) = decode_scale_compact(&data)?;
let mut offset = consumed;

for _ in 0..vec_len {
    let (ext_len, consumed) = decode_scale_compact(&data[offset..])?;
    offset += consumed;

    let extrinsic = &data[offset..offset + ext_len];
    let blob = extract_data_from_extrinsic(extrinsic);

    offset += ext_len;
}
```

### Step 5: Extract Data from Extrinsic

For SBO data, find the "SBO-" magic and work backwards to find the compact length:

```rust
fn extract_data_from_extrinsic(ext: &[u8]) -> Option<Vec<u8>> {
    const SBO_MAGIC: &[u8] = b"SBO-";

    let sbo_pos = ext.windows(4).position(|w| w == SBO_MAGIC)?;

    // Compact length is 2 bytes before SBO-
    let (data_len, _) = decode_scale_compact(&ext[sbo_pos - 2..])?;

    Some(ext[sbo_pos..sbo_pos + data_len].to_vec())
}
```

## Example: Block 2723989

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
3. **Expecting raw data**: Matrix contains SCALE-encoded extrinsics
4. **Ignoring IEC padding**: Must be removed before SCALE decoding
5. **Chunk vs byte indexing**: `app_lookup.start` is chunk index, not byte offset

## References

- [avail-core constants](https://github.com/availproject/avail-core/blob/main/core/src/constants.rs)
- [avail-light kate rows](https://github.com/availproject/avail-light/blob/main/core/src/network/rpc/client.rs)
- [kate recovery](https://github.com/availproject/avail-core/tree/main/kate/recovery)
