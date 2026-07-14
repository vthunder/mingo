// Mingo — SBO reference client (Phase 7.6).
//
// Reads confirmed state from the sbo-daemon /v1 API. Writes are built in-browser
// with sbo-wasm and signed by the browserid agent via the first-party signer
// popup (Phase 7.4). Config is overridable via ?daemon= / ?broker= query params
// or window.MINGO_CONFIG, so the same file works locally and when hosted.

const qs = new URLSearchParams(location.search);
const CONFIG = Object.assign(
  {
    // The public sbo-daemon (DA read/submit API), deployed at da.sandmill.org.
    // Override with ?daemon= or window.MINGO_CONFIG for local dev
    // (e.g. ?daemon=http://127.0.0.1:7890).
    daemon: "https://da.sandmill.org",
    broker: "https://browserid.me",
    // The mingo.place primary IdP. Defaults to the page's own origin, since the
    // mingo-idp service serves this SPA same-origin (so its session cookie is
    // visible to the broker's /provision iframe). Override with ?idp= in dev.
    idp: location.origin,
    domain: "mingo.place",
    space: "general",
  },
  window.MINGO_CONFIG || {},
  qs.get("daemon") ? { daemon: qs.get("daemon") } : {},
  qs.get("broker") ? { broker: qs.get("broker") } : {},
  qs.get("idp") ? { idp: qs.get("idp") } : {}
);

// --- TEMP on-screen diagnostics (enable with ?debug=1) — remove once fixed ----
// Shows a live log at the bottom of the screen and wraps window.open so we can
// see, on mobile, whether include.js actually attempts a popup for the grant.
function dbg(m) {}
if (qs.get("debug") === "1") {
  const box = document.createElement("div");
  box.style.cssText =
    "position:fixed;left:0;right:0;bottom:0;max-height:45vh;overflow:auto;z-index:99999;" +
    "background:rgba(0,0,0,.88);color:#3f6;font:11px/1.35 ui-monospace,monospace;padding:6px;white-space:pre-wrap;";
  const mount = () => (document.body || document.documentElement).appendChild(box);
  document.readyState === "loading" ? addEventListener("DOMContentLoaded", mount) : mount();
  dbg = (m) => {
    const t = new Date().toISOString().slice(11, 19);
    box.textContent += `[${t}] ${m}\n`;
    box.scrollTop = box.scrollHeight;
    try { console.log("[dbg]", m); } catch (e) {}
  };
  const _open = window.open;
  window.open = function () {
    const w = _open.apply(this, arguments);
    dbg("window.open(" + String(arguments[0] || "").slice(0, 60) + ") => " + (w ? "OK" : "NULL(blocked)"));
    return w;
  };
  dbg("diagnostics ready; navigator.id=" + (typeof (window.navigator && navigator.id)) +
      " IdentityCredential=" + ("IdentityCredential" in window));
}
const SBO_WASM_URL = CONFIG.sboWasm || `${CONFIG.broker}/common/js/sbo-wasm/sbo_wasm.js`;

// ---------------------------------------------------------------------------
// daemon read/submit API
// ---------------------------------------------------------------------------
async function api(path) {
  const r = await fetch(`${CONFIG.daemon}${path}`);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}
const getObject = (path, id, proof = false) =>
  api(`/v1/object?path=${encodeURIComponent(path)}&id=${encodeURIComponent(id)}${proof ? "&proof=1" : ""}`);
const listPrefix = (prefix) => api(`/v1/list?prefix=${encodeURIComponent(prefix)}`);
const listSchema = (schema) => api(`/v1/list?schema=${encodeURIComponent(schema)}`);
const stateRoot = () => api(`/v1/state-root`);
// Report whether /sys/dnssec/<domain>'s on-chain proof covers needed_by+margin,
// returning a freshly-captured RFC 9102 proof (base64url) only when it doesn't.
const getDnssec = (domain, neededBy, margin) =>
  api(`/v1/dnssec?domain=${encodeURIComponent(domain)}&needed_by=${neededBy}&margin=${margin}`);

// Decode base64url (no padding) → Uint8Array (the daemon returns the binary
// proof base64url-encoded so the JSON stays UTF-8 safe).
function b64urlToBytes(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function submitWire(bytes) {
  const r = await fetch(`${CONFIG.daemon}/v1/submit`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: bytes,
  });
  if (!r.ok) {
    // The daemon now validates at submit and returns 400 with a stage+reason
    // (e.g. "Attribution: not a member") — surface that, not the raw status.
    let reason = await r.text();
    try { reason = JSON.parse(reason).error || reason; } catch {}
    const err = new Error(reason);
    err.status = r.status;
    throw err;
  }
  // { submission_id, accepted, pending, hash } — the write is validated and
  // staged in the daemon's mempool overlay, visible to all clients within ~1s.
  return r.json();
}

// ---------------------------------------------------------------------------
// domain queries
// ---------------------------------------------------------------------------
async function getCommunities() {
  const objs = await listPrefix("/communities/");
  return objs
    .filter((o) => o.content_schema === "community.v1" && o.id === "community")
    .map((o) => ({ id: o.path.split("/").filter(Boolean)[1], ...o.value }));
}
async function getSpaceItems(commId, space) {
  const objs = await listPrefix(`/communities/${commId}/spaces/${space}/`);
  const posts = [], comments = [];
  for (const o of objs) {
    if (o.content_schema === "post.v1") posts.push(toItem(o));
    else if (o.content_schema === "comment.v1") comments.push(toItem(o));
  }
  return { posts, comments };
}
function toItem(o) {
  return {
    uri: o.path + o.id,
    id: o.id,
    path: o.path,
    author: shortAuthor(o.owner_ref || o.creator),
    authorRef: o.owner_ref || o.creator,
    body: o.value?.body ?? o.payload_text,
    parent: o.value?.parent,
    block: o.block,
    hlc: o.hlc,
    // Authoring time in Unix ms, parsed from the HLC physical component
    // (wire form `<physical>.<counter>`, physical = Unix ms).
    ts: hlcMs(o.hlc),
    // false when served from the daemon's unconfirmed overlay (render pending).
    confirmed: o.confirmed !== false,
  };
}
function shortAuthor(ref) {
  if (!ref) return "unknown";
  if (ref.startsWith("ed25519:")) return ref.slice(8, 16) + "…";
  // Every identity here is <handle>@mingo.place — show just the handle.
  const at = ref.indexOf("@");
  if (at > 0 && ref.endsWith(`@${CONFIG.domain}`)) return ref.slice(0, at);
  return ref; // other email or name
}
// Count present upvotes per target (LWW by author/target/kind handled coarsely:
// keep the latest state per (author,target)).
async function getVoteCounts() {
  let objs = [];
  try { objs = await listSchema("reaction.v1"); } catch { return new Map(); }
  const latest = new Map(); // key author|target -> {state, hlc}
  for (const o of objs) {
    const v = o.value || {};
    if (v.kind !== "upvote") continue;
    const key = (o.owner_ref || o.creator) + "|" + v.target;
    const prev = latest.get(key);
    if (!prev || (o.hlc || "") > (prev.hlc || "")) latest.set(key, { state: v.state !== false, hlc: o.hlc });
  }
  const counts = new Map();
  for (const [key, val] of latest) {
    if (!val.state) continue;
    const target = key.split("|")[1];
    counts.set(target, (counts.get(target) || 0) + 1);
  }
  return counts;
}
async function getPassport(subject) {
  let objs = [];
  try { objs = await listSchema("attestation.v1"); } catch { return []; }
  return objs
    .map((o) => ({ issuer: o.owner_ref || o.creator, ...o.value }))
    .filter((a) => a.subject === subject);
}

// ---------------------------------------------------------------------------
// session (login via the broker dialog popup, requesting sbo_sign)
// ---------------------------------------------------------------------------
const session = {
  get email() { return localStorage.getItem("mingo_email") || null; },
  set email(v) { v ? localStorage.setItem("mingo_email", v) : localStorage.removeItem("mingo_email"); },
};

// Sign-in via the STANDARD browserid client (include.js, loaded in index.html),
// which sets up navigator.id and uses FedCM where the browser supports it. We
// wrap request() in a promise — onlogin resolves it — so the existing two-step
// flow reads the same as before. The dialog reads `sboSign` / `provisionEmail`
// straight from these options (same as the old query-param URL did).
let _pendingAssertion = null;
function requestAssertion(opts) {
  return new Promise((resolve, reject) => {
    _pendingAssertion = { resolve, reject };
    dbg("requestAssertion: sbo=" + !!(opts && opts.sboSign) + " prov=" + ((opts && opts.provisionEmail) || "-"));
    try {
      navigator.id.request(opts || {});
      dbg("requestAssertion: navigator.id.request returned (no throw)");
    } catch (e) {
      _pendingAssertion = null;
      dbg("requestAssertion: THREW " + (e && e.message));
      reject(e);
      return;
    }
    setTimeout(() => {
      if (_pendingAssertion && _pendingAssertion.resolve === resolve) dbg("requestAssertion: STILL PENDING after 15s (no onlogin/onlogout)");
    }, 15000);
  });
}

navigator.id.watch({
  loggedInUser: session.email || null,
  onready: function () { dbg("watch: onready"); },
  onlogin: function (assertion) {
    dbg("watch: onlogin (len=" + (assertion && assertion.length) + ") pending=" + !!_pendingAssertion);
    if (_pendingAssertion) {
      const p = _pendingAssertion;
      _pendingAssertion = null;
      p.resolve(assertion);
    } else {
      silentLogin(assertion); // background (e.g. FedCM) login — re-establish the session
    }
  },
  onlogout: function () {
    dbg("watch: onlogout pending=" + !!_pendingAssertion);
    if (_pendingAssertion) {
      const p = _pendingAssertion;
      _pendingAssertion = null;
      p.resolve(null);
    }
  },
});

// A background login delivers an assertion with no pending request(). Two ways
// we get here: FedCM silent auto-reauthn, OR a returning navigator.id.request
// whose popup the browser turned into a full-page REDIRECT (Chrome on iOS) —
// the reload dropped our in-page promise, so the assertion lands here instead.
async function silentLogin(assertion) {
  if (session.email) return; // already signed in via the RP's own session
  try {
    const sess = await idpPost("/session/from-assertion", { assertion });
    const email = sess.handle
      ? `${sess.handle}@${CONFIG.domain}`
      : sess.identity_mode === "email"
        ? sess.email
        : null;
    if (!email) return; // new user — don't silently auto-register
    session.email = email;
    renderAuth();
    route();
  } catch (e) {
    /* silent */
  }
}

const idpPost = async (path, body) => {
  const r = await fetch(`${CONFIG.idp}${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${path} ${r.status} ${await r.text()}`);
  return r.json();
};

// Login ≠ registration. (1) Authenticate the user's EXTERNAL identity via the
// broker. (2) Establish a mingo.place session from that assertion. (3) New users
// pick a handle (in-page). (4) Silently provision <handle>@mingo.place — the
// broker discovers mingo.place's IdP and, because the session exists, mints the
// cert into custody without a second login.
async function signIn() {
  try {
    const assertion = await requestAssertion({ sboSign: false });
    if (!assertion) return; // cancelled
    const sess = await idpPost("/session/from-assertion", { assertion });

    // Decide the identity to sign as: a returning handle user, a returning
    // external-email user, or a new user who picks in the chooser.
    let email;
    if (sess.handle) {
      email = `${sess.handle}@${CONFIG.domain}`;
    } else if (sess.identity_mode === "email") {
      email = sess.email;
    } else {
      const choice = await promptIdentity(sess.email);
      if (!choice) return; // cancelled registration
      if (choice.mode === "email") {
        await idpPost("/use_external", {});
        email = sess.email;
      } else {
        const claim = await idpPost("/claim_handle", { handle: choice.handle });
        email = claim.email;
      }
    }

    // Deferred signing: DON'T provision/grant now. Login is a single, standard
    // popup — we just show the user as signed in. The SBO-signing grant (a
    // second popup) is requested lazily, the first time they actually sign
    // something (see ensureSigningReady). That keeps login clean and avoids
    // colliding with the FedCM chooser that fires right after this dialog.
    session.email = email;
    renderAuth();
    route(); // flip "Sign in to post" → Join / New post
    toast(`Signed in as ${session.email}`);
  } catch (e) {
    toast("Sign-in failed: " + e.message);
  }
}

// Lazy signing grant. mingo signs objects through a first-party signer popup
// (ensureSigner → /sign), which needs the identity provisioned + the origin
// granted SBO-signing — done here via the broker dialog, once, on first use.
// Returns true only when signing is ready RIGHT NOW. When it has to run the
// grant, it returns false (the signer popup below would be outside the current
// gesture and get blocked), so the caller aborts and the user repeats the
// action — the retry opens the signer inside a fresh gesture. After that the
// signer window is reused, so it's a one-time extra tap.
async function ensureSigningReady() {
  if (localStorage.getItem("mingo_signing_ready") === "1") return true;
  const granted = await new Promise((resolve) => {
    const overlay = el(`<div class="modal-overlay">
      <div class="modal card">
        <div class="h2">Enable signing</div>
        <p class="muted" style="margin-top:8px">To publish as
          <strong>${esc(session.email)}</strong>, authorize Mingo to sign on your
          behalf. Your browser will open a one-time approval window.</p>
        <div class="row-between" style="margin-top:12px">
          <button id="s-cancel">Not now</button>
          <button class="primary" id="s-ok">Enable signing</button>
        </div>
      </div></div>`);
    document.body.appendChild(overlay);
    overlay.querySelector("#s-cancel").onclick = () => { overlay.remove(); resolve(false); };
    overlay.querySelector("#s-ok").onclick = async () => {
      // Open the dialog FIRST, while the tapped button is still in the DOM.
      // requestAssertion's window.open runs synchronously inside this call, so
      // it stays within the user gesture. Removing the overlay (which contains
      // this button) BEFORE the popup opens invalidates the gesture on iOS
      // Safari and the popup gets blocked — so remove it only after.
      const p = requestAssertion({ sboSign: true, provisionEmail: session.email });
      dbg("enable-signing TAP (request kicked off)");
      overlay.remove();
      try {
        const assertion = await p;
        if (!assertion) { toast("Signing not enabled"); return resolve(false); }
        localStorage.setItem("mingo_signing_ready", "1");
        resolve(true);
      } catch (e) { toast("Could not enable signing: " + e.message); resolve(false); }
    };
  });
  if (granted) toast("Signing enabled — tap once more to publish.");
  return false; // never ready on the same gesture that ran the grant
}
async function signOut() {
  // Real sign-out: end the mingo.place server session + clear its cookie, not
  // just client state (a stale session could otherwise still mint certs — mingo-n153).
  try {
    await fetch(`${CONFIG.idp}/logout`, { method: "POST", credentials: "include" });
  } catch (e) {
    console.warn("logout request failed (clearing local state anyway):", e);
  }
  // Standard browserid logout too: clears the FedCM auto-login opt-in + server
  // consent (so we don't silently sign back in) and notifies the broker.
  try { navigator.id.logout(); } catch (e) {}
  localStorage.removeItem("mingo_signing_ready"); // re-grant on next sign-in
  session.email = null;
  renderAuth();
  route();
  toast("Signed out");
}

// In-page identity chooser (a Mingo product decision — never inside the broker
// dialog). A new user either uses their external email as their public identity
// or creates a pseudonymous `<handle>@mingo.place`. Resolves to
// { mode: "email" } | { mode: "handle", handle } | null (cancelled).
function promptIdentity(externalEmail) {
  return new Promise((resolve) => {
    const sanitize = (v) => v.toLowerCase().replace(/[^a-z0-9._-]/g, "");
    const overlay = el(`<div class="modal-overlay">
      <div class="modal card">
        <div class="h2">How do you want to appear here?</div>
        <label style="display:flex;gap:8px;align-items:center;margin-top:8px;cursor:pointer">
          <input type="radio" name="idmode" value="email" checked>
          <span><strong>Use my email</strong> — <span class="muted">${esc(externalEmail)}</span></span>
        </label>
        <label style="display:flex;gap:8px;align-items:center;margin-top:8px;cursor:pointer">
          <input type="radio" name="idmode" value="handle">
          <span><strong>Create a handle</strong> — <span class="muted"><span id="h-prev">handle</span>@${esc(CONFIG.domain)}</span></span>
        </label>
        <input type="text" id="h-input" placeholder="handle" autocapitalize="none" autocomplete="off" spellcheck="false" style="margin-top:8px;display:none">
        <div id="h-help" class="muted tiny" style="margin-top:8px"></div>
        <div id="h-error" class="error tiny"></div>
        <div class="row-between" style="margin-top:12px">
          <button id="h-cancel">Cancel</button>
          <button class="primary" id="h-ok">Continue</button>
        </div>
      </div></div>`);
    document.body.appendChild(overlay);
    const input = overlay.querySelector("#h-input");
    const prev = overlay.querySelector("#h-prev");
    const err = overlay.querySelector("#h-error");
    const help = overlay.querySelector("#h-help");
    const mode = () => overlay.querySelector('input[name="idmode"]:checked').value;
    const syncMode = () => {
      const handle = mode() === "handle";
      input.style.display = handle ? "" : "none";
      help.textContent = handle
        ? "A pseudonym; your email stays private."
        : "This will be shown publicly on everything you post.";
      if (handle) input.focus();
      err.textContent = "";
    };
    syncMode();
    overlay.querySelectorAll('input[name="idmode"]').forEach((r) => r.addEventListener("change", syncMode));
    input.addEventListener("input", () => {
      input.value = sanitize(input.value);
      prev.textContent = input.value || "handle";
    });
    const close = (val) => { overlay.remove(); resolve(val); };
    overlay.querySelector("#h-cancel").onclick = () => close(null);
    overlay.querySelector("#h-ok").onclick = () => {
      if (mode() === "email") return close({ mode: "email" });
      const v = sanitize(input.value.trim());
      if (!v) { err.textContent = "Pick a handle"; return; }
      close({ mode: "handle", handle: v });
    };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") overlay.querySelector("#h-ok").click(); });
  });
}

// ---------------------------------------------------------------------------
// signer popup (reuse the first-party signer; correlate by id)
// ---------------------------------------------------------------------------
let signerWin = null, signerReady = null;
const pendingSign = new Map();
let signSeq = 0;
window.addEventListener("message", (e) => {
  if (e.origin !== CONFIG.broker || e.source !== signerWin) return;
  const d = e.data || {};
  if (d.type === "sbo:signer-ready") { signerReady && signerReady.resolve(); return; }
  const p = d.id != null && pendingSign.get(d.id);
  if (!p) return;
  pendingSign.delete(d.id);
  if (d.type === "sbo:signed") p.resolve(d);
  else if (d.type === "sbo:sign-error") p.reject(new Error(`${d.error}: ${d.message || ""}`));
  // Auto-close the signer popup once it's idle (no pending signs), so it doesn't
  // linger on top. It reopens on the next sign (a user gesture).
  if (pendingSign.size === 0 && signerWin && !signerWin.closed) {
    try { signerWin.close(); } catch {}
    signerWin = null;
  }
});
function ensureSigner() {
  if (signerWin && !signerWin.closed) return signerReady.promise;
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  signerReady = { promise, resolve, reject };
  signerWin = window.open(`${CONFIG.broker}/sign`, "mingo-signer", "width=360,height=200");
  if (!signerWin) { reject(new Error("popup blocked — allow popups")); return promise; }
  window.focus();
  setTimeout(() => reject(new Error("signer popup did not become ready")), 15000);
  return promise;
}
async function signEnvelope(email, envelope) {
  await ensureSigner();
  const id = ++signSeq;
  return new Promise((resolve, reject) => {
    pendingSign.set(id, { resolve, reject });
    signerWin.postMessage({ type: "sbo:sign", id, email, envelope }, CONFIG.broker);
    setTimeout(() => { if (pendingSign.has(id)) { pendingSign.delete(id); reject(new Error("sign timeout")); } }, 20000);
  });
}

// ---------------------------------------------------------------------------
// sbo-wasm (lazy)
// ---------------------------------------------------------------------------
let sboP = null;
function sbo() {
  if (!sboP) sboP = import(SBO_WASM_URL).then((m) => Promise.resolve(m.default && m.default()).then(() => m));
  return sboP;
}

// De-dupes concurrent /sys/dnssec refreshes within a session (all mingo writes
// share the mingo.place domain, so one refresh covers everyone in flight).
let dnssecRefreshInFlight = null;

// Ensure /sys/dnssec/<domain> carries a proof still valid through now+margin.
// If not (expired/absent), capture a fresh proof via the daemon and submit it as
// a KEY-ROOTED write — authorized by the self-authorizing policy (the proof
// payload proves its own authority), so it lands even though the stale on-chain
// proof can't attribute an email-rooted write yet. The caller's subsequent
// email-rooted write then attributes against this fresh proof via the daemon's
// confirmed+pending overlay. Cheap on the common fresh path (no proof returned).
async function ensureDnssecFresh(domain) {
  const now = Math.floor(Date.now() / 1000);
  const MARGIN = 3600; // 1h headroom for inclusion latency + clock skew
  let info;
  try {
    info = await getDnssec(domain, now, MARGIN);
  } catch (e) {
    // The check is best-effort; the daemon is authoritative at submit time.
    console.warn("dnssec freshness check failed, proceeding:", e.message);
    return;
  }
  if (!info || !info.needs_refresh || !info.proof_b64) return;
  if (dnssecRefreshInFlight) return dnssecRefreshInFlight;
  dnssecRefreshInFlight = writeContent({
    path: "/sys/dnssec/", id: domain, schema: "dnssec.v1",
    payload: b64urlToBytes(info.proof_b64),
    contentType: "application/octet-stream",
    keyRooted: true,
  }).finally(() => { dnssecRefreshInFlight = null; });
  return dnssecRefreshInFlight;
}

// The `iss` claim of a browserid cert (JWT). Attribution requires an on-chain
// DNSSEC proof for THIS domain — the cert's issuer, which is the email's own
// domain for a primary IdP (dan@mingo.place → mingo.place) but the BROKER for
// a fallback-certified email (vthunder@gmail.com → browserid.me). Refreshing
// the owner's email domain instead would miss the broker's proof entirely.
function certIssuer(certJwt) {
  try {
    const payload = certJwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload)).iss || null;
  } catch { return null; }
}

// Build → sign → assemble → submit a write. Email-rooted by default (Owner =
// session email); pass `keyRooted: true` for self-authorizing writes like the
// /sys/dnssec refresh, which omit Owner so the daemon's L2 gate passes by
// signing-key match without needing attribution.
async function writeContent({ path, id, schema, payload, hlc, prev, owner, contentType, keyRooted }) {
  if (!session.email) { signIn(); return; }
  const wasm = await sbo();
  const spec = {
    action: "", path, id,
    public_key: "ed25519:" + "00".repeat(32), // set by whichever signer runs
    content_schema: schema,
    payload: Array.from(payload),
    hlc: hlc || `${Date.now()}.0`,
    prev,
  };
  if (contentType) spec.content_type = contentType;

  // Self-authorizing writes (a /sys/dnssec proof: policy grants create/update to
  // anyone and the proof attests its own domain) need NO identity — sign with a
  // throwaway ephemeral key. The effective owner is just that key; the on-chain
  // proof + policy authorize the write. So we never route it through the broker
  // signer (which rightly refuses to sign an unowned write as the user).
  if (keyRooted) {
    return submitWire(await signLocalAndAssemble(wasm, spec));
  }

  // Email-rooted write: sign with the broker's cert-bound key for the identity.
  spec.owner = owner || session.email;
  const res = await signEnvelope(session.email, spec);
  // Ensure the CERT ISSUER's on-chain DNSSEC proof is valid through inclusion so
  // attribution resolves — the issuer (from the just-signed cert) is the email's
  // own domain for a primary, but the BROKER for a fallback-certified email, so
  // we post /sys/dnssec/<issuer>, not /sys/dnssec/<email-domain>.
  const issuer = certIssuer(res.cert) || (owner || session.email).split("@")[1];
  if (issuer) await ensureDnssecFresh(issuer);
  const bound = { ...spec, public_key: res.pubkey, auth_cert: res.cert };
  return submitWire(wasm.assembleWire(bound, res.signature));
}

// Sign a self-authorizing (unowned) envelope with a throwaway Ed25519 key and
// return the assembled wire. Used for /sys/dnssec proof writes: no identity is
// asserted (no Owner, no Auth-Cert) — the on-chain proof authorizes it.
async function signLocalAndAssemble(wasm, spec) {
  const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const bound = { ...spec, public_key: "ed25519:" + hex(rawPub) };
  const bytes = wasm.signingBytes(bound);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, bytes));
  return wasm.assembleWire(bound, hex(sig));
}

// ---------------------------------------------------------------------------
// membership (self-issued, per-community) — an open community accepts an
// in-force `membership:<commId>` attestation, so a user "joins" a community by
// self-issuing one (scoped to that community) in their own namespace. Membership
// is per-community: joining c/cooks does not let you post in c/woodworking.
// ---------------------------------------------------------------------------
async function hasMembership(commId) {
  if (!session.email || !commId) return false;
  try {
    // Path-scoped list (NOT getObject: /v1/object matches by id regardless of
    // path, which would falsely match another user's membership).
    const objs = await listPrefix(`/u/${session.email}/attestations/${session.email}/`);
    // Counts PENDING memberships too (Phase B): the daemon validates posts
    // against confirmed+pending state, so a just-submitted membership authorizes
    // posting immediately — Join flips to New post without waiting for on-chain
    // confirmation. Matched by the community-scoped attestation type.
    return objs.some(
      (o) => o.content_schema === "attestation.v1" && o.value?.type === `membership:${commId}`,
    );
  } catch { return false; }
}
async function joinHub(commId) {
  if (!session.email) { signIn(); return false; }
  const att = {
    subject: session.email,
    type: `membership:${commId}`,
    value: { community: commId, via: "mingo-web" },
    issued_at: Math.floor(Date.now() / 1000),
    expires: null,
    issuer: session.email,
  };
  const payload = new TextEncoder().encode(JSON.stringify(att));
  await writeContent({
    path: `/u/${session.email}/attestations/${session.email}/`,
    id: `membership-${commId}`,
    schema: "attestation.v1",
    contentType: "application/json",
    payload,
  });
  return true;
}

async function composePost(commId, space, body) {
  const wasm = await sbo();
  const payload = wasm.payloadPost(body, undefined, BigInt(Date.now()));
  const id = "p-" + Date.now().toString(36);
  await writeContent({
    path: `/communities/${commId}/spaces/${space}/`, id, schema: "post.v1", payload,
  });
  return id;
}
async function addComment(commId, space, parentUri, body) {
  const wasm = await sbo();
  const payload = wasm.payloadComment(body, parentUri, BigInt(Date.now()));
  const id = "c-" + Date.now().toString(36);
  return writeContent({
    path: `/communities/${commId}/spaces/${space}/`, id, schema: "comment.v1", payload,
  });
}
async function upvote(commId, space, targetUri) {
  const wasm = await sbo();
  const payload = wasm.payloadReaction(targetUri, "upvote", true);
  const id = "r-" + Date.now().toString(36);
  return writeContent({
    path: `/communities/${commId}/spaces/${space}/`, id, schema: "reaction.v1", payload,
  });
}

// ---------------------------------------------------------------------------
// UI helpers + chrome
// ---------------------------------------------------------------------------
const $ = (sel) => document.querySelector(sel);
const el = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstChild; };
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// HLC physical component → Unix ms (wire form `<physical>.<counter>`).
function hlcMs(hlc) {
  if (!hlc) return null;
  const n = parseInt(String(hlc).split(".")[0], 10);
  return Number.isFinite(n) ? n : null;
}
// Compact, human-readable "time ago" for an authoring timestamp (Unix ms).
function relTime(ms) {
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 10) return "just now";
  if (s < 60) return `${s} seconds ago`;
  const units = [["minute", 60], ["hour", 60], ["day", 24], ["week", 7], ["month", 4.345], ["year", 12]];
  let v = s / 60, i = 0;
  for (; i < units.length - 1 && v >= units[i + 1][1]; i++) v /= units[i + 1][1];
  const n = Math.floor(v);
  return `${n} ${units[i][0]}${n === 1 ? "" : "s"} ago`;
}
// A muted "· 5 minutes ago" span tooltipped with the absolute local timestamp.
function timeAgo(ts) {
  if (!ts) return "";
  return ` · <span class="muted" title="${esc(new Date(ts).toLocaleString())}">${esc(relTime(ts))}</span>`;
}
let toastTimer;
// ms = 0 keeps the toast up until the next toast() call (for in-flight tx status).
function toast(msg, ms = 3000) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer);
  if (ms > 0) toastTimer = setTimeout(() => (t.hidden = true), ms);
}

function renderAuth() {
  const slot = $("#auth-slot");
  if (session.email) {
    slot.innerHTML = `<span class="muted">${esc(session.email)}</span> · <button class="link" id="signout">sign out</button>`;
    $("#signout").onclick = signOut;
  } else {
    slot.innerHTML = `<button class="primary" id="signin">Sign in</button>`;
    $("#signin").onclick = signIn;
  }
}

async function renderChrome() {
  renderAuth();
  try {
    const comms = await getCommunities();
    window.__comms = comms;
    const ul = $("#community-list");
    ul.innerHTML = comms.map((c) => `<li><a href="#/c/${esc(c.id)}" data-c="${esc(c.id)}">${esc(c.name)} ${c.open ? "✓" : ""}</a></li>`).join("") || `<li class="muted">none</li>`;
  } catch (e) {
    $("#community-list").innerHTML = `<li class="muted">daemon offline</li>`;
  }
  try {
    const sr = await stateRoot();
    $("#state-root").textContent = `block ${sr.block} · root ${sr.state_root.slice(0, 10)}…`;
  } catch {}
  if (session.email) $("#passport-link").setAttribute("href", `#/passport/${encodeURIComponent(session.email)}`);
}

// ---------------------------------------------------------------------------
// views
// ---------------------------------------------------------------------------
async function viewHub() {
  const main = $("#main");
  main.innerHTML = `<div class="h1">Your feed</div><div id="feed" class="muted">loading…</div>`;
  const comms = window.__comms || (await getCommunities());
  const votes = await getVoteCounts();
  const rows = [];
  for (const c of comms) {
    const { posts } = await getSpaceItems(c.id, CONFIG.space);
    for (const p of posts) rows.push({ ...p, comm: c.id });
  }
  rows.sort((a, b) => (votes.get(b.uri) || 0) - (votes.get(a.uri) || 0) || (b.hlc || "").localeCompare(a.hlc || ""));
  $("#feed").outerHTML = `<div id="feed">${rows.length ? rows.map((p) => feedRow(p, votes)).join("") : `<div class="card muted">No posts yet. Sign in and create the first one.</div>`}</div>`;
  wireVoteButtons();
}

function feedRow(p, votes, showComm = true) {
  const pending = p.confirmed === false;
  return `<div class="card feed-row${pending ? " pending" : ""}">
    <div class="votes"><button class="link up" data-vote="${esc(p.comm)}|${esc(p.uri)}">▲</button><span class="n" data-count="${esc(p.uri)}">${votes.get(p.uri) || 0}</span></div>
    <div style="flex:1">
      <div class="post-meta">${showComm ? `c/${esc(p.comm)} · ` : ""}${esc(p.author)}${timeAgo(p.ts)}${pending ? ` · <span class="muted">pending…</span>` : ""}</div>
      <div class="post-title"><a href="#/c/${esc(p.comm)}/p/${esc(p.id)}">${esc((p.body || "").slice(0, 120))}</a></div>
    </div></div>`;
}

async function viewCommunity(commId) {
  const main = $("#main");
  const comms = window.__comms || (await getCommunities());
  const c = comms.find((x) => x.id === commId);
  if (!c) { main.innerHTML = `<div class="card">Unknown community.</div>`; return; }
  const member = session.email ? await hasMembership(c.id) : false;
  const actionBtn = !session.email
    ? `<button class="primary" id="signin2">Sign in to post</button>`
    : member
      ? `<button class="primary" id="newpost">+ New post</button>`
      : `<button class="primary" id="join">Join to post</button>`;
  main.innerHTML = `
    <div class="row-between"><div class="h1">c/${esc(c.id)} ${c.open ? "✓" : ""}</div>
      ${actionBtn}</div>
    <div class="card muted">${esc(c.description || "")}</div>
    <div id="compose"></div>
    <div id="posts" class="muted">loading…</div>`;
  if (session.email && member) $("#newpost").onclick = () => showCompose(c.id);
  else if (session.email) $("#join").onclick = async (e) => {
    if (!(await ensureSigningReady())) return;
    e.target.disabled = true; e.target.textContent = "Joining…";
    try {
      await joinHub(c.id);
      // The daemon serves the membership from its overlay immediately and now
      // validates posts against confirmed+pending state, so the user can post
      // right away — flip the button without waiting for on-chain confirmation.
      toast("You're in — you can post now.");
      route();
    } catch (err) { toast("join failed: " + err.message); e.target.disabled = false; e.target.textContent = "Join to post"; }
  };
  else $("#signin2").onclick = signIn;
  const [{ posts }, votes] = await Promise.all([getSpaceItems(c.id, CONFIG.space), getVoteCounts()]);
  posts.sort((a, b) => (votes.get(b.uri) || 0) - (votes.get(a.uri) || 0) || (b.hlc || "").localeCompare(a.hlc || ""));
  $("#posts").outerHTML = `<div id="posts">${posts.length ? posts.map((p) => feedRow({ ...p, comm: c.id }, votes, false)).join("") : `<div class="card muted">No posts yet.</div>`}</div>`;
  wireVoteButtons();
}

function showCompose(commId) {
  const box = $("#compose");
  box.innerHTML = `<div class="card"><div class="h2">New post in c/${esc(commId)}/${esc(CONFIG.space)}</div>
    <textarea id="post-body" placeholder="Share something…"></textarea>
    <div class="row-between" style="margin-top:8px"><span class="muted tiny">posts to the DA layer</span>
    <span><button id="post-cancel">Cancel</button> <button class="primary" id="post-submit">Post</button></span></div></div>`;
  $("#post-cancel").onclick = () => (box.innerHTML = "");
  $("#post-submit").onclick = async () => {
    const body = $("#post-body").value.trim();
    if (!body) return;
    if (!(await ensureSigningReady())) return;
    $("#post-submit").disabled = true;
    try {
      const id = await composePost(commId, CONFIG.space, body);
      toast("posted — pending confirmation…");
      box.innerHTML = "";
      // The daemon overlay already serves the post (marked pending) to every
      // client. Re-render shortly to show it, then poll until it confirms so
      // its "pending…" affordance clears.
      await new Promise((r) => setTimeout(r, 1200));
      route();
      for (let i = 0; i < 24; i++) {
        await new Promise((r) => setTimeout(r, 5000));
        const { posts: list } = await getSpaceItems(commId, CONFIG.space);
        const p = list.find((x) => x.id === id);
        if (p && p.confirmed) { toast("post confirmed on-chain."); return void route(); }
      }
    } catch (e) { toast("post failed: " + e.message); $("#post-submit").disabled = false; }
  };
}

async function viewThread(commId, postId) {
  const main = $("#main");
  main.innerHTML = `<div id="thread" class="muted">loading…</div>`;
  const [{ posts, comments }, votes] = await Promise.all([getSpaceItems(commId, CONFIG.space), getVoteCounts()]);
  const post = posts.find((p) => p.id === postId);
  if (!post) { main.innerHTML = `<div class="card">Post not found.</div>`; return; }
  const kids = comments.filter((c) => c.parent === post.uri);
  main.innerHTML = `
    <a class="muted" href="#/c/${esc(commId)}">← c/${esc(commId)}</a>
    <div class="card"><div class="post-meta">${esc(post.author)}${timeAgo(post.ts)}</div>
      <div class="post-body">${esc(post.body)}</div>
      <div style="margin-top:8px"><button class="link up" data-vote="${esc(commId)}|${esc(post.uri)}">▲ upvote</button> · <span data-count="${esc(post.uri)}">${votes.get(post.uri) || 0}</span></div>
    </div>
    <div class="h2">Comments</div>
    <div class="card"><textarea id="c-body" placeholder="Add a comment…"></textarea>
      <div style="text-align:right;margin-top:8px"><button class="primary" id="c-submit">Comment</button></div></div>
    <div id="comments">${kids.length ? kids.map((c) => commentBox(c, votes)).join("") : `<div class="muted">No comments yet.</div>`}</div>`;
  $("#c-submit").onclick = async () => {
    const body = $("#c-body").value.trim(); if (!body) return;
    if (!(await ensureSigningReady())) return;
    $("#c-submit").disabled = true;
    try {
      await addComment(commId, CONFIG.space, post.uri, body);
      toast("commented — pending confirmation…");
      $("#c-body").value = "";
      // Overlay serves the comment immediately; re-render to show it (pending),
      // then poll until the count of confirmed comments grows.
      const before = kids.length;
      await new Promise((r) => setTimeout(r, 1200));
      route();
      for (let i = 0; i < 24; i++) {
        await new Promise((r) => setTimeout(r, 5000));
        const { comments: cs } = await getSpaceItems(commId, CONFIG.space);
        const mine = cs.filter((c) => c.parent === post.uri);
        if (mine.length > before && mine.every((c) => c.confirmed)) { toast("comment confirmed."); return void route(); }
      }
    } catch (e) { toast("comment failed: " + e.message); }
    finally { $("#c-submit").disabled = false; }
  };
  wireVoteButtons();
}
function commentBox(c, votes) {
  return `<div class="comment"><div class="post-meta">${esc(c.author)}${timeAgo(c.ts)} · ${votes.get(c.uri) || 0} ▲</div><div>${esc(c.body)}</div></div>`;
}

function wireVoteButtons() {
  document.querySelectorAll("[data-vote]").forEach((b) => {
    b.onclick = async () => {
      const [comm, uri] = b.getAttribute("data-vote").split("|");
      if (b.dataset.voted) return; // already counted
      if (!(await ensureSigningReady())) return;
      // Bump just this count + mark the button without re-rendering (so content
      // doesn't jump). The daemon overlay also stages the vote server-side, so
      // the bump is now backed by shared state and visible to other users.
      const span = document.querySelector(`[data-count="${CSS.escape(uri)}"]`);
      const prev = span ? span.textContent : null;
      if (span) span.textContent = String((parseInt(span.textContent, 10) || 0) + 1);
      b.dataset.voted = "1"; b.classList.add("voted");
      try { await upvote(comm, CONFIG.space, uri); toast("vote counted — confirming on-chain…"); }
      catch (e) {
        if (span && prev !== null) span.textContent = prev; // revert
        delete b.dataset.voted; b.classList.remove("voted");
        toast("vote failed: " + e.message);
      }
    };
  });
}

async function viewPassport(subject) {
  const main = $("#main");
  subject = subject || session.email;
  if (!subject) { main.innerHTML = `<div class="card">Sign in to see your passport.</div>`; return; }
  main.innerHTML = `<div class="h1">🎖 ${esc(subject)}</div><div id="pp" class="muted">loading…</div>`;
  const atts = await getPassport(subject);
  const roles = atts.filter((a) => a.type !== "vouch" && a.type !== "ban");
  const vouches = atts.filter((a) => a.type === "vouch");
  $("#pp").outerHTML = `<div id="pp">
    <div class="card"><div class="h2">Badges & roles</div>
      ${roles.length ? roles.map((a) => `<div class="passport-row"><span>${esc(a.type)}</span><span class="muted">issued by ${esc(a.issuer)}</span></div>`).join("") : `<div class="muted">No badges yet.</div>`}</div>
    <div class="card"><div class="h2">Vouched by</div>
      ${vouches.length ? vouches.map((a) => esc(a.issuer)).join(" · ") : `<div class="muted">No vouches yet.</div>`}</div>
    <div class="card muted">This is yours. It travels with you across every community here.</div></div>`;
}

// ---------------------------------------------------------------------------
// router
// ---------------------------------------------------------------------------
async function route() {
  const h = location.hash || "#/";
  const parts = h.slice(2).split("/"); // after "#/"
  try {
    if (h === "#/" || h === "") return void (await viewHub());
    if (parts[0] === "c" && parts[2] === "p") return void (await viewThread(parts[1], parts[3]));
    if (parts[0] === "c") return void (await viewCommunity(parts[1]));
    if (parts[0] === "passport") return void (await viewPassport(decodeURIComponent(parts[1] || "")));
    await viewHub();
  } catch (e) {
    $("#main").innerHTML = `<div class="card">Error: ${esc(e.message)}</div>`;
  }
}

document.querySelector(".brand").onclick = () => (location.hash = "#/");
window.addEventListener("hashchange", route);

// Mobile nav drawer: hamburger toggles it; backdrop, navigation, and Escape
// close it. (On desktop the sidebar is a normal column and none of this shows.)
(function wireNav() {
  const toggle = document.getElementById("nav-toggle");
  const backdrop = document.getElementById("nav-backdrop");
  const sidebar = document.getElementById("sidebar");
  const setOpen = (open) => {
    document.body.classList.toggle("nav-open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  };
  toggle.onclick = () => setOpen(!document.body.classList.contains("nav-open"));
  backdrop.onclick = () => setOpen(false);
  // Tapping any link inside the drawer navigates → close it.
  sidebar.addEventListener("click", (e) => { if (e.target.closest("a")) setOpen(false); });
  window.addEventListener("hashchange", () => setOpen(false));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") setOpen(false); });
})();
(async function init() {
  await renderChrome();
  await route();
})();
