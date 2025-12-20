# Daemon Debugging

Advanced options for troubleshooting the SBO daemon.

## Verbose Flags

Use `-v` / `--verbose` to enable detailed logging for specific components:

| Flag | Description |
|------|-------------|
| `rpc` | RPC connection details |
| `rpc-decode` | Block header parsing, matrix decode stats |
| `raw-incoming` | Raw data received for repos |
| `blocks` | Log every block processed (including empty) |

```bash
sbo-daemon start -v rpc-decode
sbo-daemon start -v rpc -v blocks
```

## Debug Flags

Use `-d` / `--debug` for development/troubleshooting features:

| Flag | Description |
|------|-------------|
| `save-raw-block` | Save raw block data to `/tmp/sbo-debug/` |

```bash
sbo-daemon start -d save-raw-block
```

### Raw Block Files

When `save-raw-block` is enabled, three files are created per block containing app data:

- `block_{N}_header.json` - Block header with app_lookup index
- `block_{N}_matrix.bin` - Raw data matrix scalars
- `block_{N}_lookup.bin` - App lookup table

Matrix file format:
```
[cols: u32 LE][rows: u32 LE][scalars: 32 bytes each, big-endian]
```

See [Avail Data Matrix](avail-data-matrix.md) for details on interpreting the matrix data.
