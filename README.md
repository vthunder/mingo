# SBO Reference Implementation

## What is SBO?

SBO (Sovereign Blockchain Objects) is a protocol for storing and retrieving data on blockchain data availability (DA) layers. Data is organized into repositories with filesystem-like paths, signed by identities, and anchored to DA layers like Avail. The result is sovereign, portable data that can be synced, verified, and proven without trusting any centralized server.

This reference implementation provides everything needed to run SBO nodes, create identities, authenticate users, and generate cryptographic proofs.

## What You Can Do

- **Sync repositories** - Follow SBO repos and sync data from DA layers to your local filesystem
- **Create identities** - Claim names on-chain with your signing key (`/sys/names/alice`)
- **Authenticate users** - Let users prove they control an email-linked SBO identity
- **Generate proofs** - Create portable cryptographic proofs that data exists (or doesn't)
- **Run different node types** - Full node, light client, or proof generator

## Components

### Binaries

| Binary | Description |
|--------|-------------|
| `sbo` | CLI for all user operations (keys, identities, repos, proofs) |
| `sbo-daemon` | Background service that syncs from DA layers and manages state |
| `auth-demo` | Standalone demo showing email-based authentication flow |

### Libraries

| Crate | Description |
|-------|-------------|
| `sbo-core` | Core library (wire format, validation, state, keyring, DNS) |
| `sbo-crypto` | Cryptographic primitives (ed25519, sha256, sparse trie) |
| `sbo-types` | Shared type definitions |
| `sbo-avail` | Avail DA layer integration |
| `sbo-daemon` | Daemon library (sync engine, IPC, prover) |
| `sbo-zkvm` | RISC Zero guest program for ZK validity proofs |

## Quick Start

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Build

```bash
cd reference_impl
cargo build --release
```

### Basic Setup

```bash
# 1. Generate a signing key
./target/release/sbo key generate

# 2. Start the daemon
./target/release/sbo-daemon start --foreground

# 3. (In another terminal) Check status
./target/release/sbo daemon status
```

---

## Demos

### Demo 1: Sync and Query Data

Sync an existing SBO repository to your local filesystem:

```bash
# Add a repo using DNS-based URI
./target/release/sbo repo add sbo://sandmill.org/ ./sandmill-data

# Or using raw chain coordinates
./target/release/sbo repo add sbo+raw://avail:turing:506/ ./my-repo

# List repos
./target/release/sbo repo list

# Browse synced data
ls ./sandmill-data/
ls ./sandmill-data/sys/names/
```

Query objects directly:

```bash
# Get an object
./target/release/sbo uri get sbo://sandmill.org/sys/names/alice

# List objects at a path
./target/release/sbo uri list sbo://sandmill.org/sys/names/
```

### Demo 2: Create an Identity

Create an on-chain identity linked to your signing key:

```bash
# Ensure you have a key
./target/release/sbo key list

# Create a new repo (if you're starting fresh)
./target/release/sbo repo create sbo+raw://avail:turing:YOUR_APP_ID/ ./my-repo

# Create an identity
./target/release/sbo id create sbo://your-domain.com/ alice \
  --display-name "Alice Smith" \
  --website "https://alice.example.com"

# List your identities
./target/release/sbo id list

# Show details
./target/release/sbo id show alice
```

### Demo 3: Email-Based Authentication

This demo shows how an app can authenticate users via their email-linked SBO identity.

**Prerequisites:**
1. DNS TXT record: `_sbo-id.yourdomain.com` → `v=sbo-id1 host=yourdomain.com`
2. HTTPS endpoint: `/.well-known/sbo-identity/{domain}/{user}` returning `{"version":1,"sbo_uri":"..."}`
3. An SBO identity created on-chain

**Step 1: Import your email identity**

```bash
# Resolve an email to see its SBO identity
./target/release/sbo id resolve alice@example.com

# Import the identity (links email to your local key)
./target/release/sbo id import alice@example.com

# Verify it's imported
./target/release/sbo id list
```

**Step 2: Run the auth demo (simulates an app)**

```bash
# In terminal 1: Start the demo app
./target/release/auth-demo --email alice@example.com --app-name "My App"
```

**Step 3: Approve the request (as the user)**

```bash
# In terminal 2: See pending requests
./target/release/sbo auth pending

# Approve the request
./target/release/sbo auth approve demo-xxxxxxxx
```

The demo app will show all verification steps:

```
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: Verify Assertion                                       │
└─────────────────────────────────────────────────────────────────┘

  [1/5] Challenge matches what we sent... ✓ PASS
  [2/5] Timestamp is recent (< 5 min)... ✓ PASS
  [3/5] Email matches request... ✓ PASS (alice@example.com)
  [4/5] Signature is valid... ✓ PASS
  [5/5] Public key matches on-chain identity... ✓ PASS

┌─────────────────────────────────────────────────────────────────┐
│ AUTHENTICATION SUCCESSFUL                                      │
└─────────────────────────────────────────────────────────────────┘
```

### Demo 4: Generate and Verify Proofs

Create a portable cryptographic proof that an object exists:

```bash
# Generate a proof for an identity
./target/release/sbo proof generate sbo://sandmill.org/sys/names/alice

# Save to file
./target/release/sbo proof generate ./my-repo/sys/names/alice > proof.sboq

# Verify a proof
./target/release/sbo proof verify proof.sboq
```

Proofs are self-contained and can be verified without access to the full chain state.

---

## URI Formats

SBO supports two URI formats:

### DNS-Based URIs (Recommended)

```
sbo://domain.com/path/to/object
```

Resolved via DNS TXT record at `_sbo.domain.com`:
```
_sbo.domain.com TXT "sbo=v1 chain=avail:turing appId=506"
```

Benefits:
- Human-readable
- Can migrate to different chains
- Supports checkpoints and bootstrap nodes

### Raw URIs

```
sbo+raw://chain:network:appId/path/to/object
```

Direct chain reference without DNS lookup. Use when:
- DNS isn't set up yet
- You need deterministic resolution
- Testing locally

---

## Daemon Modes

The daemon supports three modes of operation:

| Mode | Flag | Description | Use Case |
|------|------|-------------|----------|
| **Full** | (default) | Executes all blocks, computes state | Standard operation |
| **Light** | `--light` | Verifies ZK proofs, trusts proven state | Resource-constrained environments |
| **Prover** | `--prover` | Generates ZK proofs for state transitions | Serving light clients |

### Full Mode (Default)

```bash
./target/release/sbo-daemon start
```

Processes every block, validates all messages, computes state roots. This is the standard mode for most users.

### Light Mode

```bash
./target/release/sbo-daemon start --light
```

Instead of executing blocks, light mode:
1. Waits for ZK validity proofs (SBOP messages)
2. Cryptographically verifies the proofs
3. Trusts the proven state roots

Benefits:
- Much lower CPU usage
- Faster sync (skip execution)
- Same security guarantees (ZK proofs are trustless)

Limitations:
- Depends on prover nodes submitting proofs
- Only stores state roots, not individual objects

### Prover Mode

```bash
./target/release/sbo-daemon start --prover
```

Runs as a full node plus generates ZK proofs:
1. Processes blocks normally
2. Batches state changes
3. Generates RISC Zero zkVM proofs
4. Submits proofs to DA layer

See [ZK Validity Proofs](#zk-validity-proofs) for setup details.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Your App                                │
│                    (or auth-demo, sbo CLI)                      │
└─────────────────────────────────────────────────────────────────┘
                              │ IPC (Unix socket)
                    ┌─────────▼─────────┐
                    │    SBO Daemon     │
                    │   Full / Light    │
                    │     / Prover      │
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  Avail   │   │ Celestia │   │  Other   │
        │   DA     │   │   DA     │   │   DA     │
        └──────────┘   └──────────┘   └──────────┘
```

**Data flow:**
1. **Post**: Sign a message → submit to DA layer via TurboDA
2. **Sync**: Daemon watches chain → downloads new messages
3. **Validate**: Verify signature, ownership, policy rules
4. **Store**: Write to local filesystem + RocksDB state
5. **Prove**: (Prover mode) Generate ZK proof of state transition
6. **Query**: Apps read local files or request proofs

---

## ZK Validity Proofs

ZK proofs enable trustless verification of state transitions without re-executing all transactions.

### Building with zkVM Support

```bash
# Install RISC Zero toolchain
curl -L https://risczero.com/install | bash
rzup install

# Install CMake
brew install cmake  # macOS
apt install cmake   # Linux

# Build with zkVM
cargo build --release
```

### Prover Configuration

Add to `~/.sbo/config.toml`:

```toml
[prover]
enabled = true
batch_size = 10        # Blocks to batch before proving
receipt_kind = "composite"  # composite, succinct, or groth16
dev_mode = false       # true = fake proofs for testing
```

### Proof Types

| Type | Size | Speed | Use Case |
|------|------|-------|----------|
| `composite` | ~400KB | Fast | Development |
| `succinct` | ~100KB | 7-8x slower | Production |
| `groth16` | ~300B | Slowest | On-chain verification |

---

## Configuration

All configuration lives in `~/.sbo/`:

```
~/.sbo/
├── config.toml       # Daemon configuration
├── keys/             # Signing keys (encrypted)
│   └── metadata.json # Key aliases and identities
├── daemon.sock       # IPC socket
└── repos.json        # Repository index
```

### Example config.toml

```toml
[daemon]
socket_path = "~/.sbo/daemon.sock"
repos_dir = "~/.sbo/repos"

[rpc]
url = "wss://turing-rpc.avail.so/ws"

[light_client]
url = "http://127.0.0.1:7007"

[turbo_da]
url = "https://turing-turbo-da.sandmill.dev"
token = "your-api-token"

[prover]
enabled = false
batch_size = 10
receipt_kind = "composite"
dev_mode = false
```

---

## CLI Reference

### Key Management

```bash
sbo key generate [--name <alias>]     # Generate new key
sbo key list                          # List keys
sbo key import <source> [--name ...]  # Import from file/hex
sbo key export [name]                 # Export for backup
sbo key default [name]                # Get/set default key
sbo key delete <name>                 # Delete a key
```

### Identity Management

```bash
sbo id create <uri> <name> [options]  # Create on-chain identity
sbo id list [uri]                     # List identities
sbo id show <name>                    # Show identity details
sbo id update <uri> [options]         # Update identity
sbo id import <email-or-repo> [name]  # Import identity to keyring
sbo id remove <chain> <name>          # Remove from keyring
sbo id resolve <email>                # Resolve email to SBO URI
```

### Repository Management

```bash
sbo repo create <uri> <path>          # Create new repo with genesis
sbo repo add <uri> <path>             # Add existing repo to sync
sbo repo list                         # List repos
sbo repo remove <path-or-uri>         # Remove repo
sbo repo relink <path>                # Re-resolve DNS for repo
```

### Object Operations

```bash
sbo uri get <uri>                     # Get object
sbo uri post <uri> <file> [options]   # Post object
sbo uri list <uri>                    # List objects at path
sbo uri transfer <uri> [options]      # Transfer object
```

### Proofs

```bash
sbo proof generate <path-or-uri>      # Generate inclusion proof
sbo proof verify <file>               # Verify proof file
```

### Authentication

```bash
sbo auth pending                      # List pending sign requests
sbo auth show <request-id>            # Show request details
sbo auth approve <id> [--as <email>]  # Approve and sign
sbo auth reject <id> [--reason ...]   # Reject request
```

### Daemon

```bash
sbo daemon status                     # Check daemon status
sbo daemon stop                       # Stop daemon
sbo-daemon start [--foreground]       # Start daemon
sbo-daemon start --light              # Start in light mode
sbo-daemon start --prover             # Start in prover mode
```

---

## Development

### Running Tests

```bash
# All tests
cargo test

# Fast tests (skip zkvm)
cargo test -p sbo-core -p sbo-crypto -p sbo-daemon

# With zkVM (slower)
cargo test --features zkvm
```

### Project Structure

```
reference_impl/
├── sbo-cli/          # CLI binary
├── sbo-daemon/       # Daemon binary and library
├── sbo-auth-demo/    # Authentication demo app
├── sbo-core/         # Core library
├── sbo-crypto/       # Cryptographic primitives
├── sbo-types/        # Shared types
├── sbo-avail/        # Avail DA client
└── sbo-zkvm/         # RISC Zero zkVM guest
    └── methods/      # Guest program source
```

---

## Troubleshooting

### Daemon won't start

```bash
# Check if already running
ps aux | grep sbo-daemon

# Remove stale socket
rm ~/.sbo/daemon.sock

# Start in foreground to see errors
./target/release/sbo-daemon start --foreground
```

### Build fails with zkVM errors

```bash
# Install/update RISC Zero
rzup install

# Ensure PATH includes risc0
export PATH="$HOME/.risc0/bin:$PATH"

# On macOS, ensure Xcode tools
xcode-select --install
```

### Light mode not verifying proofs

Light mode requires real ZK proofs (not dev mode). Ensure:
1. A prover node is running and submitting proofs
2. Daemon built with zkVM: `cargo build --release`

### DNS resolution failing

```bash
# Test DNS lookup
dig TXT _sbo.yourdomain.com

# Expected format:
# _sbo.yourdomain.com. TXT "sbo=v1 chain=avail:turing appId=506"
```

---

## License

MIT - see [LICENSE](../LICENSE)
