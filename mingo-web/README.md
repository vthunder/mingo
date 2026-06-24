# Mingo web client (SBO Phase 7.6)

A static SPA — the SBO reference client. Reads confirmed state from the
`sbo-daemon` `/v1` HTTP API; builds writes in-browser with `sbo-wasm` and signs
them via the browserid typed-signing popup (Phase 7.4).

No build step — plain ES modules.

## Run (local)

```sh
# 1. a synced daemon (serves /v1 on 127.0.0.1:7890) — see ../sbo-daemon
sbo-daemon start --foreground

# 2. serve this dir
cd reference_impl/mingo-web && python3 -m http.server 8090 --bind 127.0.0.1
# open http://127.0.0.1:8090/
```

Config overrides via query (`?daemon=…&broker=…`) or `window.MINGO_CONFIG`:
- `daemon`  default `http://127.0.0.1:7890`
- `broker`  default `https://browserid.me`  (login dialog + signer popup + sbo-wasm)
- `domain`  default `mingo.place`
- `space`   default `general`

## Status

- **Reads (live now):** hub feed, community view, thread, passport — all from
  the daemon over real turing DA.
- **Writes (compose/comment/upvote):** wired (build → popup-sign → `/v1/submit`),
  but only *verify* once:
  1. `browserid.me` DNSSEC + `_browserid` TXT are live (Track A), and the broker
     is cut over to `BROKER_DOMAIN=browserid.me`;
  2. the envelope carries `Auth-Evidence` (a DNSSEC proof for `browserid.me`) —
     the client needs a broker/daemon endpoint to fetch it (TODO);
  3. the author holds an in-force `membership` attestation (posting policy).
  Until then writes will be rejected at L2 attribution.
