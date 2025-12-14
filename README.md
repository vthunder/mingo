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
./target/release/sbo repo add sbo://avail:turing:506 ./my-repo

# Check sync status
./target/release/sbo repo status

# View your synced data
ls ./my-repo/
```

### Posting Objects

```bash
# Post a simple object
echo '{"name":"My First Object"}' | ./target/release/sbo post /test/hello

# Post with specific content type
./target/release/sbo post /profiles/alice --content-type application/json < profile.json
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
# Full node (default) - validates all blocks
./target/release/sbo-daemon start

# Light mode - trusts remote state, only validates owned objects
./target/release/sbo-daemon start --light

# Prover mode - generates ZK proofs for state transitions
./target/release/sbo-daemon start --prover
```

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

## Development

### Running Tests

```bash
# Run all tests (requires risc0 toolchain for zkvm tests)
cargo test

# Run tests without zkvm
RISC0_SKIP_BUILD_KERNELS=1 cargo test -p sbo-crypto -p sbo-core
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
| `sbo key generate` | Generate a new signing key |
| `sbo key list` | List available keys |
| `sbo post <path>` | Post an object to the DA layer |
| `sbo get <path>` | Get an object from local state |
| `sbo proof <path>` | Generate inclusion proof |
| `sbo verify <file>` | Verify a proof file |
| `sbo repo add <uri> <path>` | Add a repository to sync |
| `sbo repo status` | Show sync status |
| `sbo daemon start` | Start the daemon |
| `sbo daemon stop` | Stop the daemon |
| `sbo daemon status` | Check daemon status |

### Daemon IPC

The daemon exposes a Unix socket at `~/.sbo/daemon.sock` for IPC. Messages use JSON-RPC format.

---

## License

[MIT](../LICENSE)
