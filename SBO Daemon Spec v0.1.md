# SBO Daemon Specification v0.1

## Overview

The SBO daemon manages local replicas of SBO repositories, verifying data availability
via an embedded light client and syncing object data from Avail RPC nodes.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SBO Daemon                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │  LC Manager  │    │  RPC Client  │    │   Repo Manager   │  │
│  │ (standalone) │    │ (avail-rust) │    │                  │  │
│  └──────┬───────┘    └──────┬───────┘    └────────┬─────────┘  │
│         │                   │                      │            │
│         ▼                   ▼                      ▼            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Block Processor                        │  │
│  │                                                           │  │
│  │  For each new block:                                      │  │
│  │  1. LC confirms data available (DAS verification)         │  │
│  │  2. RPC fetches transactions for followed app_ids         │  │
│  │  3. Parse SBO messages from transactions                  │  │
│  │  4. Write objects to filesystem repos                     │  │
│  │  5. Raise alarm if DAS fails (data withholding attack)    │  │
│  │                                                           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                              │                                  │
│                              ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                      IPC Server                           │  │
│  │  Unix socket at ~/.sbo/daemon.sock                        │  │
│  │  - repo add/remove/list/sync                              │  │
│  │  - status/health                                          │  │
│  │  - submission status                                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
          ▲
          │ IPC
    ┌─────┴─────┐                    ┌──────────────────┐
    │    CLI    │ ──── submit ─────► │     TurboDA      │
    │           │                    │  (preconfirms)   │
    └───────────┘                    └──────────────────┘
```

## Directory Structure

### Daemon State (~/.sbo/)

```
~/.sbo/
├── daemon.sock              # Unix socket for IPC
├── daemon.pid               # PID file
├── config.toml              # Global config (TurboDA API key, RPC endpoints, etc.)
├── repos.json               # Index of followed repos
└── repos/
    └── <repo-hash>/         # Per-repo metadata
        ├── config.json      # {"uri": "sbo+raw://avail:mainnet:13/", "path": "/home/user/my-repo"}
        ├── head             # Last synced block number
        └── pending/         # Submissions awaiting confirmation
            └── <tx-hash>    # Pending submission metadata
```

### User Repository (user-specified path)

```
my-repo/                     # Clean directory - no hidden files
├── sys/
│   └── names/
│       └── sys              # Raw SBO wire format
└── nft/
    └── collection/
        └── item001          # Raw SBO wire format
```

Objects are stored as raw wire format files. The filename is the object ID.
The directory structure mirrors the SBO path.

## Components

### 1. Light Client Manager

Manages the standalone Avail light client process.

**Responsibilities:**
- Spawn light client on daemon start
- Monitor health, restart if needed
- Query status via HTTP API (localhost:7007)
- Report DAS verification results

**Configuration:**
- Network (mainnet/turing)
- Identity file path
- HTTP port

### 2. RPC Client

Fetches block data from Avail RPC nodes using avail-rust SDK.

**Responsibilities:**
- Connect to Avail RPC endpoints
- Fetch block data for specific app_ids
- Decode data submissions
- Handle RPC failover

**Flow:**
1. LC confirms block N is available
2. RPC client fetches block N data for each followed app_id
3. Returns raw transaction data

### 3. Repo Manager

Manages the set of followed repositories.

**Responsibilities:**
- Add/remove repos
- Track sync state (head block per repo)
- Map SBO URIs to local paths
- Handle pending submissions

**Repo URI format:**
```
sbo+raw://avail:<network>:<app_id>/[path/]
```

Examples:
- `sbo+raw://avail:mainnet:13/` - Full repo at app_id 13
- `sbo+raw://avail:mainnet:13/nft/` - Only the /nft/ subtree

### 4. Block Processor

Core sync logic.

**For each new finalized block:**
1. Wait for LC to confirm availability (DAS)
2. For each followed repo:
   a. Fetch block data for repo's app_id via RPC
   b. Parse SBO messages from transactions
   c. Filter by repo's path prefix (if partial)
   d. Validate signatures
   e. Apply to filesystem
3. Update head block for each repo
4. If DAS fails, raise alarm (log, webhook, etc.)

### 5. Filesystem Writer

Writes SBO objects to the local filesystem.

**Write rules:**
- Path: `<repo-root>/<sbo-path>/<sbo-id>`
- Content: Raw wire format (headers + body)
- Create directories as needed
- Atomic writes (write to temp, rename)

**Example:**
```
Message: POST /nft/collection/ item001
Repo root: /home/user/my-repo
Written to: /home/user/my-repo/nft/collection/item001
```

### 6. TurboDA Client

Submits data via TurboDA for fast preconfirmations.

**Responsibilities:**
- Submit raw data to TurboDA API
- Track submission status
- Store pending submissions until confirmed on-chain

**API:**
- POST /v1/submit_raw_data
- Headers: x-api-key, Content-Type: application/octet-stream
- Response: {"submission_id": "..."}

### 7. IPC Server

Handles CLI commands via Unix socket.

**Commands:**
- `repo_add {uri, path}` - Start following a repo
- `repo_remove {path}` - Stop following
- `repo_list` - List all followed repos
- `repo_sync {path?}` - Force sync
- `status` - Daemon health, block heights, etc.
- `submit {path, id, data}` - Submit via TurboDA

## CLI Commands

```bash
# Daemon management
sbo daemon start                 # Start daemon (foreground or daemonize)
sbo daemon stop                  # Stop daemon
sbo daemon status                # Show health, followed repos, sync status

# Repository management
sbo repo add <uri> <path>        # Follow repo, sync to local path
sbo repo remove <path>           # Stop following repo
sbo repo list                    # List followed repos with sync status
sbo repo sync [path]             # Force sync (all or specific repo)

# Data submission (via TurboDA)
sbo post <repo-path> <sbo-path> <id> --file <file>
                                 # Submit POST to create/update object
sbo transfer <repo-path> <sbo-path> <id> --to <new-owner>
                                 # Submit TRANSFER

# Examples
sbo repo add sbo+raw://avail:mainnet:13/ ./my-repo
sbo post ./my-repo /nft/items/ myitem --file item.json
```

## Configuration

### ~/.sbo/config.toml

```toml
[daemon]
socket_path = "~/.sbo/daemon.sock"
pid_file = "~/.sbo/daemon.pid"

[light_client]
network = "turing"
identity_file = "~/.sbo/identity.toml"
http_port = 7007

[rpc]
endpoints = [
    "wss://turing-rpc.avail.so/ws",
]
timeout_secs = 30

[turbo_da]
endpoint = "https://staging.turbo-api.availproject.org"
api_key = "your-api-key-here"

[alerts]
# Optional webhook for DAS failures
webhook_url = ""
```

## Sync Flow

### Initial Sync (repo add)

1. Parse URI to extract network, app_id, path prefix
2. Create repo metadata in ~/.sbo/repos/<hash>/
3. Query RPC for historical blocks (from genesis or configured start)
4. For each block with app_id data:
   - Parse SBO messages
   - Filter by path prefix
   - Write to filesystem
5. Update head to current block

### Ongoing Sync

1. LC streams new finalized blocks
2. For each block:
   - Verify DAS (LC status)
   - Fetch data for all followed app_ids
   - Route transactions to appropriate repos
   - Parse and write SBO objects
   - Update heads

### Submission Flow

1. CLI calls `sbo post` with local repo path and data
2. Daemon looks up repo config (app_id, etc.)
3. Constructs signed SBO message
4. Submits to TurboDA
5. Stores in pending/ with submission_id
6. TurboDA returns preconfirmation (~250ms)
7. CLI returns success with submission_id
8. Background: daemon monitors for on-chain confirmation
9. On confirmation: remove from pending, write to filesystem

## Error Handling

### DAS Failure

If light client cannot verify data availability:
1. Log error with block number
2. Trigger alert (webhook if configured)
3. Pause sync for affected repos
4. Retry with backoff

### RPC Failure

1. Try next endpoint in list
2. Exponential backoff
3. Continue from last confirmed block

### Invalid SBO Message

1. Log warning with details
2. Skip message, continue processing
3. Do not write to filesystem

## Future Considerations

- Multiple networks (mainnet + testnet repos)
- Partial sync (only specific paths within app_id)
- Compression for large repos
- P2P sync between SBO daemons
- Pruning old object versions
