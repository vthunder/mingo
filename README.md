# SBO Reference Implementation

This is the reference implementation of SBO (Sovereign Blockchain Objects). It includes:

- **sbo-cli** (`sbo`) - Command-line tool for posting and querying objects
- **sbo-daemon** - Background service that syncs from DA layers
- **sbo-core** - Core library with validation and state management
- **sbo-crypto** - Cryptographic primitives (signatures, hashing, trie proofs)
- **sbo-avail** - Avail DA layer integration

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Your App                            │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │    SBO Daemon     │  ← Validates & syncs
                    │  (runs locally)   │
                    └─────────┬─────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  Avail   │   │ Ethereum │   │ Celestia │
        │   DA     │   │  (L1)    │   │   DA     │
        └──────────┘   └──────────┘   └──────────┘
```

**How it works:**

1. **Post**: Sign a message and submit it to a DA layer
2. **Sync**: The daemon watches the chain and downloads new messages
3. **Validate**: Each message is verified (signature, ownership, policy)
4. **Store**: Valid messages are written to local filesystem + state DB
5. **Use**: Your app reads data like normal files

---

## Quick Start

### Prerequisites

```bash
# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Building

```bash
cd reference_impl
cargo build --release
```

### Basic Usage

```bash
# Create a signing key
./target/release/sbo key generate

# Start the daemon
./target/release/sbo-daemon start

# Add a repo to sync from Avail
./target/release/sbo repo add sbo+raw://avail:turing:506 ./my-repo

# Check sync status
./target/release/sbo repo status

# View your synced data
ls ./my-repo/
```

### Object Operations

```bash
# Post an object (using full SBO URI)
./target/release/sbo uri post sbo+raw://avail:turing:506/test/hello ./data.json

# Post with specific content type
./target/release/sbo uri post sbo+raw://avail:turing:506/profiles/alice ./profile.json --content-type application/json

# Get an object
./target/release/sbo uri get sbo+raw://avail:turing:506/test/hello

# List objects at a path
./target/release/sbo uri list sbo+raw://avail:turing:506/profiles/
```

---

## Working with Proofs

SBO provides cryptographic proofs that an object exists (or doesn't exist) at a specific state root. These proofs are portable and can be verified without access to the full chain state.

### Generating Proofs

```bash
# Request a proof for an object
./target/release/sbo proof /test/hello

# Save proof to file
./target/release/sbo proof /test/hello > proof.sboq
```

### Proof Format (SBOQ)

Proofs use the SBOQ (SBO Query) format - a self-contained proof with embedded object:

```
SBOQ-Version: 0.2
Path: /test/
Id: hello
Creator: alice
Block: 12345
State-Root: abc123def456...
Object-Hash: 789xyz...
Proof-Format: trie
Proof-Length: 156
Object-Length: 42

[{"segment":"test","siblings":{"other":"sha256:..."}},{"segment":"alice","siblings":{}},{"segment":"hello","siblings":{}}]
{"name":"My First Object"}
```

### Verifying Proofs

```bash
# Verify a proof file
./target/release/sbo verify proof.sboq

# Output shows verification result:
#   Trie proof: valid
#   Object hash: valid
#   State root: abc123... (block 12345)
```

### Proof Verification Details

The verification process:

1. **Object hash check**: `sha256(embedded_object) == Object-Hash`
2. **Trie proof check**: Reconstruct path from leaf to root
   - For each step, combine siblings + current segment hash
   - Final hash must equal `State-Root`
3. **State root trust**: Verify state root against known checkpoints or chain state

### Non-Existence Proofs

Proofs can also demonstrate that an object does NOT exist:

```bash
./target/release/sbo proof /test/nonexistent
# Object-Hash: null (indicates non-existence)
```

The proof shows the trie structure at the divergence point, proving the path isn't present.

---

## Daemon Commands

```bash
# Start daemon in foreground
./target/release/sbo-daemon start

# Check daemon status
./target/release/sbo daemon status

# Stop daemon
./target/release/sbo daemon stop

# View sync progress
./target/release/sbo repo status
```

### Daemon Modes

```bash
# Full node (default) - executes and validates all blocks
./target/release/sbo-daemon start

# Light mode - verifies zkVM proofs instead of executing blocks (see "Light Mode" section)
./target/release/sbo-daemon start --light

# Prover mode - generates ZK proofs for state transitions (see "ZK Validity Proofs" section)
./target/release/sbo-daemon start --prover
```

Note: `--light` and `--prover` are mutually exclusive.

---

## State Commitment

SBO uses a sparse path-segment trie for state commitment. Each object's position in the tree mirrors its path structure.

### Path Segments

An object at path `/sys/names/` with ID `alice` created by `user123` becomes trie segments:
```
["sys", "names", "user123", "alice"]
```

### State Root

The state root is the hash of the trie's root node. It commits to all objects in the database at a given block height.

```bash
# View current state root
./target/release/sbo state root

# View state root at specific block
./target/release/sbo state root --block 12345
```

---

## ZK Validity Proofs

The daemon can generate ZK validity proofs for state transitions using RISC Zero zkVM. This enables trustless verification of batch state updates without re-executing all transactions.

### Building with zkVM Support

#### Prerequisites

```bash
# 1. Install RISC Zero toolchain
curl -L https://risczero.com/install | bash
rzup install

# 2. Install CMake (required for native code compilation)
# macOS:
brew install cmake
# Linux:
apt install cmake
```

#### macOS-Specific Notes

On Apple Silicon (M1/M2/M3), you may encounter build issues:

```bash
# If you see errors about missing SDK or compiler:
xcode-select --install

# If builds fail with Metal/GPU errors, the prover will fall back to CPU
# This is normal - GPU acceleration is optional

# If you see linker errors, ensure Xcode CLT is properly installed:
sudo xcode-select --reset
```

#### Building the Daemon with zkVM

```bash
# Build with zkVM support (release mode recommended)
cargo build --release --features zkvm

# This builds:
# - The RISC-V guest program (runs inside zkVM)
# - The host prover (generates proofs)
# - All verification code
```

Build times: First build compiles the RISC-V toolchain and may take 5-10 minutes. Subsequent builds are faster.

### Running in Prover Mode

#### Quick Start

```bash
# 1. Configure prover settings in ~/.sbo/config.toml
cat >> ~/.sbo/config.toml << 'EOF'
[prover]
enabled = true
batch_size = 10
receipt_kind = "composite"
dev_mode = false
EOF

# 2. Start daemon with prover flag
./target/release/sbo-daemon start --prover
```

#### Prover Configuration

Add to `~/.sbo/config.toml`:

```toml
[prover]
# Enable proof generation
enabled = true

# Number of blocks to wait after state change before proving
# Lower = more frequent proofs, higher = batches more changes
batch_size = 10

# Proof compression level (see "Proof Types" below)
receipt_kind = "composite"

# Dev mode uses fake proofs (no zkVM required)
dev_mode = false
```

### Proof Types

| Type | Size | Time | Use Case |
|------|------|------|----------|
| `composite` | ~400KB | Fast (~30s) | Development, testing |
| `succinct` | ~100KB | 7-8x slower | Production, smaller payloads |
| `groth16` | ~300 bytes | Slowest (needs Docker) | On-chain verification |

**Recommendations:**
- Start with `composite` during development
- Use `succinct` for production if proof size matters
- Use `groth16` only if you need Ethereum on-chain verification

### Dev Mode (Testing Without zkVM)

For development without the full zkVM toolchain:

```toml
[prover]
enabled = true
dev_mode = true  # Generates fake proofs (hash-based, not verifiable)
```

Dev mode proofs:
- Don't require RISC Zero toolchain
- Are NOT cryptographically verifiable
- Useful for testing the proof submission flow

### How Proving Works

1. **Sync**: Daemon processes blocks and tracks state changes
2. **Batch**: After `batch_size` blocks with changes, prover activates
3. **Prove**: zkVM executes state transition and generates proof
4. **Submit**: SBOP message (proof + metadata) sent to TurboDA
5. **Verify**: Other nodes can verify the proof against their state

The prover only generates proofs for blocks with actual state changes and only when the daemon is at the chain head (not while catching up).

### Proof Submission

Proofs are automatically submitted to TurboDA (Avail) when generated:

```
2024-01-15 12:34:56 INFO Generated composite proof for blocks 100-110 (428532 bytes)
2024-01-15 12:34:57 INFO Submitted proof to Avail: 0x1234...
```

---

## Light Mode

Light mode allows running a daemon that verifies zkVM proofs instead of executing every state transition. This enables trustless verification with much lower resource requirements.

### When to Use Light Mode

- **Resource-constrained environments**: Light mode doesn't need to execute all blocks
- **Bootstrapping new nodes**: Quickly sync to chain head by verifying proofs
- **Read-only applications**: Only need to trust proven state, not execute writes
- **Embedded/mobile clients**: Lower CPU and storage requirements

### How Light Mode Works

```
Full Node:                          Light Node:
┌──────────────┐                    ┌──────────────┐
│ Process all  │                    │ Skip block   │
│ blocks       │                    │ execution    │
│ (O(N) work)  │                    │              │
└──────┬───────┘                    └──────┬───────┘
       │                                   │
       ▼                                   ▼
┌──────────────┐                    ┌──────────────┐
│ Compute      │                    │ Verify zkVM  │
│ state root   │                    │ proof        │
└──────┬───────┘                    └──────┬───────┘
       │                                   │
       ▼                                   ▼
┌──────────────┐                    ┌──────────────┐
│ Store state  │                    │ Store proven │
│ in DB        │                    │ state root   │
└──────────────┘                    └──────────────┘
```

1. **Full node**: Executes every block, computes state roots from scratch
2. **Light node**: Waits for SBOP proofs, cryptographically verifies them, trusts proven state roots

### Running in Light Mode

```bash
# Start daemon in light mode
./target/release/sbo-daemon start --light

# Light mode is mutually exclusive with prover mode
# This will error:
./target/release/sbo-daemon start --light --prover  # ❌ Cannot combine
```

### Building with Light Mode Support

Light mode requires the `zkvm` feature for production proof verification:

```bash
# Build with zkVM support (required for real proof verification)
cargo build --release --features zkvm

# Without zkvm feature, light mode can only validate proof formats
# but cannot cryptographically verify them
```

### Light Mode Configuration

Light mode can also be enabled via config file:

```toml
# ~/.sbo/config.toml
[light]
enabled = true
```

When enabled in config, you can start normally:

```bash
./target/release/sbo-daemon start
# Light mode enabled automatically from config
```

### What Light Mode Verifies

When an SBOP proof is received:

1. **Receipt verification**: Cryptographically verify the zkVM receipt
2. **Block range check**: Ensure proof covers expected block range
3. **State root extraction**: Extract `prev_state_root` and `new_state_root` from proof journal
4. **Root storage**: Store the proven state roots for later queries

```
2024-01-15 12:34:56 INFO ✓ Light mode: verified zkVM proof for blocks 100-110 (state: abcd... → ef01...)
2024-01-15 12:34:56 INFO Light mode: stored proven state root ef01... at block 110 for sbo+raw://avail:turing:506/
```

### Limitations

- **No object storage**: Light mode doesn't store individual objects, only state roots
- **No state queries**: Cannot answer queries about specific object contents
- **Proof-dependent**: Relies on prover nodes submitting proofs
- **Dev mode proofs**: Cannot extract state roots from dev mode proofs (hash-based, not cryptographic)

### Troubleshooting

**Build fails with "risc0 toolchain not found":**
```bash
rzup install
# Ensure ~/.risc0/bin is in PATH
export PATH="$HOME/.risc0/bin:$PATH"
```

**Proof generation is very slow:**
- First proof is slower (JIT compilation)
- Ensure release mode: `cargo build --release --features zkvm`
- Check CPU usage - proofs are CPU-intensive

**Proofs too large for submission:**
- Switch from `composite` to `succinct`
- Note: `succinct` takes longer to generate

**"zkVM feature not enabled" error:**
```bash
# Rebuild with zkvm feature
cargo build --release --features zkvm
```

---

## Development

### Running Tests

```bash
# Run all tests
cargo test

# Run tests without zkvm (faster)
cargo test -p sbo-crypto -p sbo-core -p sbo-daemon
```

### Project Structure

```
reference_impl/
├── sbo-cli/          # CLI binary
├── sbo-daemon/       # Daemon binary
├── sbo-core/         # Core library (parsing, validation, state)
├── sbo-crypto/       # Crypto primitives (ed25519, bls, trie)
├── sbo-avail/        # Avail DA client
└── sbo-zkvm/         # RISC Zero guest program for ZK proofs
```

---

## Configuration

Configuration is stored in `~/.sbo/`:

```
~/.sbo/
├── config.toml       # Daemon configuration
├── keys/             # Signing keys
├── state.db/         # RocksDB state database
└── repos/            # Synced repositories
```

### Example config.toml

```toml
[daemon]
listen = "~/.sbo/daemon.sock"

[avail]
rpc_url = "wss://turing-rpc.avail.so/ws"
light_client_url = "http://localhost:7007"

[sync]
poll_interval_secs = 12
```

---

## API Reference

### CLI Commands

| Command | Description |
|---------|-------------|
| `sbo uri get <uri>` | Get an object by SBO URI |
| `sbo uri post <uri> <file>` | Post an object to the DA layer |
| `sbo uri list <uri>` | List objects at a path |
| `sbo uri transfer <uri>` | Transfer an object |
| `sbo key generate` | Generate a new signing key |
| `sbo key list` | List keys in keyring |
| `sbo key import <source>` | Import a key from file/hex |
| `sbo key export [name]` | Export a key for backup |
| `sbo key default [name]` | Get/set default key |
| `sbo id create <uri> <name>` | Create an identity on chain |
| `sbo id list [uri]` | List identities |
| `sbo id show <name>` | Show identity details |
| `sbo id update <uri>` | Update an identity |
| `sbo proof generate <path>` | Generate inclusion proof |
| `sbo proof verify <file>` | Verify a proof file |
| `sbo repo add <uri> <path>` | Add a repository to sync |
| `sbo repo list` | List followed repositories |
| `sbo repo remove <target>` | Remove a repository |
| `sbo daemon start` | Start the daemon |
| `sbo daemon stop` | Stop the daemon |
| `sbo daemon status` | Check daemon status |
| `sbo debug da ...` | DA layer debugging commands |

### Daemon IPC

The daemon exposes a Unix socket at `~/.sbo/daemon.sock` for IPC. Messages use JSON-RPC format.

---

## License

[MIT](../LICENSE)
