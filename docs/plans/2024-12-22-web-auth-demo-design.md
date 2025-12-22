# Web-Based SBO Auth Demo Design

## Goal

Build a web demo that lets developers experience SBO auth in a browser. The demo app uses a "native-looking" API (`navigator.sbo.*`) that communicates with the local daemon.

## Architecture

```
Demo App (sandmill.org/demo)
    │
    │  await navigator.sbo.request({...})
    ▼
JS Shim (wallet.sandmill.org/sbo.js)
    │
    │  postMessage (jschannel-style RPC)
    ▼
Hidden Iframe (wallet.sandmill.org/iframe.html)
    │
    │  fetch("http://localhost:7890/...")
    ▼
Local Daemon (localhost:7890)
```

## Components

### 1. sbo.js (~100 lines)

The shim that apps include. Hosted at `wallet.sandmill.org/sbo.js`.

```js
// App includes the shim
<script src="https://wallet.sandmill.org/sbo.js"></script>

// Then uses native-looking API
const result = await navigator.sbo.request({
  email: "alice@sandmill.org"  // optional, for directed requests
});
// result: { assertion: "jwt...", session: "jwt..." }

// Check if daemon is available
const available = await navigator.sbo.isAvailable();
```

Implementation:
- Creates hidden iframe to `wallet.sandmill.org/iframe.html` on first call
- Uses jschannel-style RPC over postMessage (request IDs, origin validation)
- Returns Promise that resolves on approval, rejects on timeout/error

### 2. iframe.html (~150 lines)

Hidden iframe hosted at `wallet.sandmill.org/iframe.html`.

Responsibilities:
- Listen for postMessage from parent window (origin validated)
- Translate requests to daemon HTTP calls
- Poll `/auth/status/:id` every 2 seconds until resolved
- Relay responses back to parent via postMessage

postMessage protocol:
```js
// parent → iframe
{ type: "sbo:request", id: "msg1", payload: { email: "..." } }

// iframe → parent
{ type: "sbo:response", id: "msg1", payload: { assertion: "...", session: "..." } }
// or
{ type: "sbo:error", id: "msg1", error: { code: "timeout", message: "..." } }
```

### 3. Daemon HTTP Endpoint (~50 lines Rust)

New HTTP listener on `localhost:7890` with CORS allowing `wallet.sandmill.org`.

Endpoints:
```
POST /auth/request
  Body: { app_origin: "https://sandmill.org", challenge: "...", email?: "..." }
  Returns: { request_id: "abc123" }

GET /auth/status/:request_id
  Returns: { status: "pending" }
       or: { status: "approved", assertion_jwt: "...", session_binding_jwt: "..." }
       or: { status: "rejected", reason: "..." }
       or: { status: "expired" }
```

Maps directly to existing IPC commands (`CreateSignRequest`, `GetSignRequest`).

### 4. Demo App (~50 lines)

Simple page at `sandmill.org/demo`:

```html
<button id="login">Sign in with SBO</button>
<div id="status"></div>

<script src="https://wallet.sandmill.org/sbo.js"></script>
<script>
document.getElementById('login').onclick = async () => {
  document.getElementById('status').textContent = 'Waiting for approval...';
  try {
    const { assertion, session } = await navigator.sbo.request();
    // Decode and display JWT claims
    const claims = JSON.parse(atob(assertion.split('.')[1]));
    document.getElementById('status').textContent =
      `Welcome, ${claims.sub}!`;
  } catch (e) {
    document.getElementById('status').textContent = `Error: ${e.message}`;
  }
};
</script>
```

## User Flow

1. User has daemon running (`sbo daemon start`)
2. Visits `sandmill.org/demo`
3. Clicks "Sign in with SBO"
4. Page shows "Waiting for approval... run `sbo auth approve <id>`"
5. User runs `sbo auth approve <id>` in terminal
6. Page shows "Welcome, alice@sandmill.org" with JWT details

## Deployment

- `wallet.sandmill.org` - New Dokku app hosting `sbo.js` and `iframe.html`
- `sandmill.org/demo` - New page in existing sandmill site
- Daemon - Add HTTP listener alongside existing Unix socket IPC

## Inspiration

Architecture follows Mozilla Persona (BrowserID) patterns:
- jschannel-style RPC over postMessage
- Hidden iframe for cross-origin communication
- `navigator.*` style API

Reference: https://github.com/benadida/browserid

## Future Extensions

- Web-based approval UI in the iframe (no CLI needed)
- Full JS wallet for users without daemon
- Browser extension using same `navigator.sbo` API
