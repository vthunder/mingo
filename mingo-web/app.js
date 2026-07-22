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
    // The SBO database reference this mingo instance writes to. Device-model
    // signing binds each write's warrant to this audience (the daemon checks it
    // identifies the target db). Bare form matches across regenesis.
    dbAudience: "sbo+raw://avail:turing:506/",
  },
  window.MINGO_CONFIG || {},
  qs.get("daemon") ? { daemon: qs.get("daemon") } : {},
  qs.get("broker") ? { broker: qs.get("broker") } : {},
  qs.get("idp") ? { idp: qs.get("idp") } : {}
);

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
    const it = o.content_schema === "post.v1" ? toItem(o)
      : o.content_schema === "comment.v1" ? toItem(o) : null;
    if (!it) continue;
    // A delete confirms by the object being ABSENT from head, so there's no
    // confirmed state to reconcile against — the daemon still serves the object
    // as `confirmed:false` (pending) through the delete's confirmation window.
    // Suppress anything the user just deleted so it doesn't render as a permanent
    // "pending…" card and can't reappear from that stale pending overlay entry
    // (mingo-3go6). Once the delete confirms the object is gone from head anyway.
    if (deletedUris.has(it.uri)) continue;
    if (o.content_schema === "post.v1") posts.push(it);
    else comments.push(it);
  }
  return { posts, comments };
}
function toItem(o) {
  return {
    uri: o.path + o.id,
    id: o.id,
    path: o.path,
    schema: o.content_schema,
    author: shortAuthor(o.owner_ref || o.creator),
    authorRef: o.owner_ref || o.creator,
    body: o.value?.body ?? o.payload_text,
    parent: o.value?.parent,
    block: o.block,
    hlc: o.hlc,
    // Current head object hash — an edit rewrites the same (path,id) with this as
    // its `prev`, chaining the new version onto the head (bean mingo-e6kq).
    objectHash: o.object_hash,
    // `prev` is null for a fresh post and set once the object has been edited
    // (the daemon omits the field when null — serde skip). Drives the "· edited"
    // indicator. NOTE: showing PRIOR versions needs daemon history (HEAD-only
    // reads today), so the version-chain viewer in the bean is out of scope here.
    prev: o.prev ?? null,
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
// board-scoped moderation (mingo-n268). A moderator of community <id> is the
// in-force subject of a `role:moderator:<id>` attestation.v1 issued BY that
// community's `issuer` (read from its community.v1 descriptor via getCommunities
// / window.__comms). This mirrors the community policy's moderator role, which
// grants `delete` on the board's spaces to `{attested: {type:
// "role:moderator:<id>", by: <issuer>}}` — so a UI affordance shown here lines up
// exactly with what the daemon will authorize.
// ---------------------------------------------------------------------------
// Resolve, in ONE attestation read, the set of board ids the session user
// moderates. Cached per render (reset in route()), like other attestation reads.
// SECURITY: matches on the AUTHENTICATED issuer (`owner_ref` — who actually
// signed the attestation on-chain), NOT the self-declared `value.issuer`, so a
// self-issued attestation naming a foreign issuer can't fake moderator status.
// That mirrors the daemon's `by:` check; a spoofed one would fail the real
// delete anyway (this only governs whether the button is offered).
let _modBoards = null;
async function moderatedBoards() {
  if (!session.email) return new Set();
  if (_modBoards) return _modBoards;
  const comms = window.__comms || (await getCommunities());
  let objs = [];
  try { objs = await listSchema("attestation.v1"); } catch { objs = []; }
  const now = Math.floor(Date.now() / 1000);
  const set = new Set();
  for (const c of comms) {
    if (!c.issuer) continue;
    const type = `role:moderator:${c.id}`;
    const ok = objs.some((o) => {
      const issuer = o.owner_ref || o.creator; // authenticated, on-chain issuer
      const v = o.value || {};
      return v.subject === session.email && v.type === type && issuer === c.issuer &&
        (!v.expires || v.expires > now);
    });
    if (ok) set.add(c.id);
  }
  _modBoards = set;
  return set;
}
// The boards the CURRENT render knows the session user moderates. Each view
// refreshes this (await moderatedBoards()) before it builds HTML, so the sync
// card/comment renderers below can consult it. Reset per navigation in route().
let currentMods = new Set();
const isMod = (commId) => !!commId && currentMods.has(commId);
// The moderator-delete affordance shows on a NON-owned item in a board the user
// moderates (owners get the plain owner-delete instead). `item.comm` must be set
// by the caller (feed rows carry it; thread/mod-view stamp it at fetch time).
function canModDelete(item) {
  return !!session.email && !ownItem(item) && isMod(item.comm);
}

// ---------------------------------------------------------------------------
// session (login via the broker dialog popup, requesting sbo_sign)
// ---------------------------------------------------------------------------
const session = {
  get email() { return localStorage.getItem("mingo_email") || null; },
  set email(v) { v ? localStorage.setItem("mingo_email", v) : localStorage.removeItem("mingo_email"); },
  // The EXTERNAL root identity (what a browserid dialog can vouch for
  // directly — a @mingo.place display identity would recurse into this IdP's
  // own authorize lane). Remembered for directed re-logins.
  get external() { return localStorage.getItem("mingo_external") || null; },
  set external(v) { v ? localStorage.setItem("mingo_external", v) : localStorage.removeItem("mingo_external"); },
};

// Sign-in via the STANDARD browserid client (include.js, loaded in index.html),
// which sets up navigator.id and uses FedCM where the browser supports it. We
// wrap request() in a promise — onlogin resolves it — so the existing two-step
// flow reads the same as before. The dialog reads `sboSign` / `provisionEmail`
// straight from these options (same as the old query-param URL did).
let _pendingAssertion = null;
let lastLoginDetails = null; // dialog response details for the most recent login
function requestAssertion(opts) {
  return new Promise((resolve, reject) => {
    _pendingAssertion = { resolve, reject };
    // oncancel fires when the user closes the dialog OR the popup is blocked
    // (include.js reports it). Without it, a blocked/cancelled request would
    // never resolve and this promise would hang.
    const req = Object.assign({}, opts, {
      oncancel: function () {
        if (_pendingAssertion && _pendingAssertion.resolve === resolve) {
          _pendingAssertion = null;
          resolve(null);
        }
      },
    });
    try {
      navigator.id.request(req);
    } catch (e) {
      _pendingAssertion = null;
      reject(e);
    }
  });
}

navigator.id.watch({
  loggedInUser: session.email || null,
  onready: function () {},
  onlogin: function (assertion, details) {
    // `details` (newer include.js) is the dialog's full response — notably
    // sbo_sign_granted, the explicit consent decision.
    lastLoginDetails = details || null;
    if (_pendingAssertion) {
      const p = _pendingAssertion;
      _pendingAssertion = null;
      p.resolve(assertion);
    } else {
      silentLogin(assertion, details); // background (FedCM / redirect-return) login
    }
  },
  onlogout: function () {
    if (_pendingAssertion) {
      const p = _pendingAssertion;
      _pendingAssertion = null;
      p.resolve(null);
    }
  },
});

// A background login delivers a presentation with no pending request(). Two ways
// we get here: FedCM silent auto-reauthn, OR a returning navigator.id.request
// whose popup the browser turned into a full-page REDIRECT (Chrome on iOS) —
// the reload dropped our in-page promise, so the assertion lands here instead.
async function silentLogin(assertion, details) {
  // The signing-grant decision must stick even when the dialog came back as a
  // full-page REDIRECT (mobile popup fallback: the in-page promise died with
  // the navigation, so the assertion lands here) — and a DECLINE must not.
  if (details && "sbo_sign_granted" in details) {
    if (details.sbo_sign_granted) {
      if (localStorage.getItem("mingo_signing_ready") !== "1") {
        localStorage.setItem("mingo_signing_ready", "1");
        toast("Signing enabled — you can post now.");
      }
    } else {
      localStorage.removeItem("mingo_signing_ready");
    }
  }
  if (session.email) return; // already signed in via the RP's own session
  try {
    const sess = await idpPost("/session/from-presentation", { presentation: assertion });
    if (sess.email) session.external = sess.email;
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

const idpGet = async (path) => {
  const r = await fetch(`${CONFIG.idp}${path}`, { credentials: "include" });
  if (!r.ok) throw new Error(`${path} ${r.status} ${await r.text()}`);
  return r.json();
};

// ---------------------------------------------------------------------------
// mingo-poster: let mingo sign SBO writes server-side. When enabled, writes go
// to /poster/submit instead of the client-side signing popups — the fix for
// mobile Safari, where window.open is unreliable. Device model (agent/D): the
// poster is an as-you service holding YOUR identity on its own isolated
// holder, so posts attribute on-chain directly to you.
// ---------------------------------------------------------------------------
const poster = { enabled: false };

// Refresh whether mingo currently holds a valid warrant for this user.
async function refreshPosterStatus() {
  if (!session.email) { poster.enabled = false; return; }
  try {
    const s = await idpGet("/poster/status");
    poster.enabled = !!s.enabled;
  } catch { poster.enabled = false; }
}

// Start delegation: mingo raises the consent request at the user's registrar
// and hands back a URL to approve at. We surface it as a tap-through link (no
// window.open — mobile-safe) and poll until the warrant lands.
async function enablePoster() {
  const { verification_uri } = await idpPost("/poster/enable", {});
  return verification_uri;
}

// Poll the pickup until the warrant is stored (or the request dies). Resolves
// true on approval. Runs for ~6 min (60 × 6s) so there's ample time to approve
// on the other tab. The interval must clear the registrar's per-code poll
// throttle (5s) — and we sleep BEFORE each poll (including the first): the
// request was just created, the user needs a moment to approve anyway, and it
// avoids a burst that would trip the throttle. A transient poll error (e.g. a
// rate-limit blip) is swallowed and retried, never aborting the enable.
async function pollPoster({ tries = 60, intervalMs = 6000 } = {}) {
  for (let i = 0; i < tries; i++) {
    await new Promise((res) => setTimeout(res, intervalMs));
    let r;
    try { r = await idpPost("/poster/poll", {}); } catch { continue; }
    if (r.status === "approved") { poster.enabled = true; return true; }
    if (r.status === "denied" || r.status === "expired" || r.status === "failed" || r.status === "none") return false;
  }
  return false;
}

async function disablePoster() {
  try { await idpPost("/poster/disable", {}); } catch {}
  poster.enabled = false;
}

// Submit a write through the server-side signer. Mirrors the fields the
// client-side path builds, minus the signature (mingo signs).
async function submitViaPoster({ path, id, schema, payload, hlc, prev, owner, contentType, action }) {
  return idpPost("/poster/submit", {
    action: action || "post",
    path,
    id,
    schema,
    content_type: contentType || "application/json",
    payload: Array.from(payload),
    hlc: hlc || `${Date.now()}.0`,
    prev: prev || null,
  });
}

// Login ≠ registration. (1) Authenticate the user's EXTERNAL identity via the
// broker. (2) Establish a mingo.place session from that assertion. (3) New users
// pick a handle (in-page). (4) Silently provision <handle>@mingo.place — the
// broker discovers mingo.place's IdP and, because the session exists, mints the
// cert into custody without a second login.
async function signIn(opts) {
  try {
    // Directed mode (session recovery): we know exactly who we expect — skip
    // the chooser and prompt for that identity.
    const directed = opts && opts.directed && session.external;
    const assertion = await requestAssertion(
      directed ? { sboSign: false, provisionEmail: session.external } : { sboSign: false });
    if (!assertion) return; // cancelled
    const sess = await idpPost("/session/from-presentation", { presentation: assertion });
    if (sess.email) session.external = sess.email;

    // Decide the identity to sign as: a returning handle user, a returning
    // external-email user, or a new user who picks in the chooser.
    let email;
    if (sess.handle) {
      email = `${sess.handle}@${CONFIG.domain}`;
    } else if (sess.identity_mode === "email") {
      email = sess.email;
    } else {
      // A new user picks how to appear: their external email, or a pseudonymous
      // <handle>@mingo.place. Handle delegation to mingo-poster works on mobile
      // now (the consent page mints the handle cert via a same-tab handshake —
      // mingo-ytrs), so handles are offered to everyone.
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
// The gate every write goes through. If mingo already posts for you, go. Else
// offer it (the modal — the recommended, mobile-friendly, popup-free path); if
// declined, fall back to client-side signing. Returns true when the write may
// proceed. Skips the offer once you've set up client signing this session, so
// existing client-signers aren't nagged.
async function ensureCanWrite() {
  if (poster.enabled) return true;
  if (localStorage.getItem("mingo_signing_ready") === "1") return ensureSigningReady();
  if (await openPosterEnableModal()) return true;
  return ensureSigningReady();
}

async function ensureSigningReady() {
  // Server-side signing is on: mingo signs, so the client never opens the
  // browserid signing dialog. Skip the whole client-signer setup.
  if (poster.enabled) return true;
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
      // Open the dialog FIRST, while the tapped button is still in the DOM, so
      // requestAssertion's window.open stays within the user gesture (removing
      // the overlay before it opens can invalidate the gesture).
      const p = requestAssertion({ sboSign: true, provisionEmail: session.email });
      overlay.remove();
      try {
        const assertion = await p;
        if (!assertion) { toast("Signing not enabled"); return resolve(false); }
        // Trust the dialog's explicit decision when reported: a login that
        // came back with the consent DECLINED must not mark signing ready.
        if (lastLoginDetails && lastLoginDetails.sbo_sign_granted === false) {
          toast("Signing not enabled");
          return resolve(false);
        }
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
  session.external = null;
  _modBoards = null; currentMods = new Set(); // drop cached moderator status
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
async function signEnvelope(email, envelope, audience) {
  await ensureSigner();
  const id = ++signSeq;
  return new Promise((resolve, reject) => {
    pendingSign.set(id, { resolve, reject });
    signerWin.postMessage({ type: "sbo:sign", id, email, envelope, audience }, CONFIG.broker);
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

// The issuer of a device-model PRESENTATION (access_cert~assertion~warrant~
// config_cert) — the `iss` of its access cert. Attribution needs an on-chain
// DNSSEC proof for THIS domain: the email's own domain for a primary IdP
// (dan@mingo.place → mingo.place) but the BROKER for a fallback-certified
// email (vthunder@gmail.com → browserid.me). Refreshing the owner's email
// domain instead would miss the broker's proof entirely.
function certIssuer(presentation) {
  try {
    const accessCert = presentation.split("~")[0];
    const payload = accessCert.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload)).iss || null;
  } catch { return null; }
}

// Build → sign → assemble → submit a write. Email-rooted by default (Owner =
// session email); pass `keyRooted: true` for self-authorizing writes like the
// /sys/dnssec refresh, which omit Owner so the daemon's L2 gate passes by
// signing-key match without needing attribution.
async function writeContent({ path, id, schema, payload, hlc, prev, owner, contentType, keyRooted, action }) {
  if (!session.email) { signIn(); return; }
  // Server-side signing (mingo-poster): mingo signs + submits on our behalf, so
  // no popup. Only for email-rooted content writes — key-rooted self-authorizing
  // writes (the /sys/dnssec refresh) sign with a throwaway key locally and must
  // not route through the agent signer.
  if (poster.enabled && !keyRooted) {
    return submitViaPoster({ path, id, schema, payload, hlc, prev, owner, contentType, action });
  }
  const wasm = await sbo();
  const spec = {
    action: action || "", path, id,
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
  const res = await signEnvelope(session.email, spec, CONFIG.dbAudience);
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

// Vouch for another identity — a portable, pseudonymous reputation signal that
// travels with the subject across every board. Mirrors joinHub EXACTLY (a
// self-issued attestation.v1 in the issuer's namespace): the object id is
// deterministic (`vouch-<subject-slug>`) so re-vouching overwrites rather than
// piling up, and the payload shape matches the seeder's vouch attestation.
async function vouchFor(subject) {
  if (!session.email) { signIn(); return false; }
  const slug = String(subject).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  const att = {
    subject,
    type: "vouch",
    value: { via: "mingo-web" },
    issued_at: Math.floor(Date.now() / 1000),
    expires: null,
    issuer: session.email,
  };
  const payload = new TextEncoder().encode(JSON.stringify(att));
  await writeContent({
    path: `/u/${session.email}/attestations/${subject}/`,
    id: `vouch-${slug}`,
    schema: "attestation.v1",
    contentType: "application/json",
    payload,
  });
  return true;
}

// Collision-safe object id: time-ordered prefix + random suffix. Under the SBO
// global (path,id) uniqueness rule (sbo-qv95), a shared space path is written by
// many authors, so a wall-clock-only id would let two same-millisecond posts
// collide and one would be dropped (first-valid-write-wins). The random suffix
// makes each author's id unique by construction.
function freshId(prefix) {
  const rnd = crypto.getRandomValues(new Uint8Array(6));
  const suffix = [...rnd].map((b) => b.toString(36).padStart(2, "0")).join("");
  return `${prefix}-${Date.now().toString(36)}-${suffix}`;
}

async function composePost(commId, space, body) {
  const wasm = await sbo();
  const payload = wasm.payloadPost(body, undefined, BigInt(Date.now()));
  const id = freshId("p");
  await writeContent({
    path: `/communities/${commId}/spaces/${space}/`, id, schema: "post.v1", payload,
  });
  return id;
}
async function addComment(commId, space, parentUri, body) {
  const wasm = await sbo();
  const payload = wasm.payloadComment(body, parentUri, BigInt(Date.now()));
  const id = freshId("c");
  return writeContent({
    path: `/communities/${commId}/spaces/${space}/`, id, schema: "comment.v1", payload,
  });
}
// Edit an existing post/comment: a `post` write to the SAME (path,id) is treated
// by the daemon as an UPDATE, which the object's owner may always do. We rebuild
// the payload with the SAME builders composePost/addComment use and set `prev` to
// the item's current head object_hash so the new version chains onto the head
// (LWW-by-HLC resolves it as the new head). Routes through writeContent → poster
// or client signing exactly like a fresh post (bean mingo-e6kq).
async function editContent(item, body) {
  const wasm = await sbo();
  const isComment = item.schema === "comment.v1";
  const payload = isComment
    ? wasm.payloadComment(body, item.parent, BigInt(Date.now()))
    : wasm.payloadPost(body, undefined, BigInt(Date.now()));
  return writeContent({
    path: item.path,
    id: item.id,
    schema: isComment ? "comment.v1" : "post.v1",
    payload,
    contentType: "application/json",
    prev: item.objectHash, // chain onto the current head → daemon sees an update
  });
}

// Owner-delete a post or comment (bean mingo-3go6): a `delete` write to the
// object's (path,id). Delete carries no payload; the daemon removes the object
// from head state (sbo Action::Delete), so it vanishes for every reader on the
// next read — no client cache to invalidate. Authorization is the owner fast
// path (the current owner may always act), so no policy grant is needed; the
// poster path additionally needs `action:delete` in its warrant scopes. We pass
// the object's schema so a poster-signed delete satisfies the warrant's
// `schema:` scope. Routes through writeContent → poster or client signing
// exactly like a post/edit.
async function deleteContent(item) {
  return writeContent({
    path: item.path,
    id: item.id,
    schema: item.schema,
    action: "delete",
    payload: new Uint8Array(0),
    contentType: "application/json",
  });
}

async function upvote(commId, space, targetUri) {
  const wasm = await sbo();
  const payload = wasm.payloadReaction(targetUri, "upvote", true);
  const id = freshId("r");
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

// ---------------------------------------------------------------------------
// identity visuals — deterministic, offline. An identicon + per-board color is
// derived purely from the identity/board string (no requests, no libs), so the
// same author/board always looks the same across every surface.
// ---------------------------------------------------------------------------
// FNV-1a → 32-bit unsigned. Stable across sessions/machines.
function hashStr(s) {
  let h = 2166136261 >>> 0;
  s = String(s || "?");
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h >>> 0;
}
// A blocky 5×5 symmetric identicon (GitHub-style), rendered inline as SVG so it
// tints to the seed's hue and needs no network. `seed` should be the stable
// identity ref (email/handle/key) — display text is handled separately.
function identicon(seed, size = 18) {
  const h = hashStr("id:" + (seed || "?"));
  const hue = h % 360;
  const bg = `hsl(${hue} 62% 96%)`;
  const fg = `hsl(${hue} 58% 46%)`;
  let r = h || 1; // xorshift PRNG seeded by the hash
  const bit = () => { r ^= r << 13; r ^= r >>> 17; r ^= r << 5; r >>>= 0; return r & 1; };
  const g = 20, cells = [];
  for (let x = 0; x < 3; x++) for (let y = 0; y < 5; y++) {
    if (bit()) {
      cells.push(`<rect x="${x * g}" y="${y * g}" width="${g}" height="${g}"/>`);
      if (x < 2) cells.push(`<rect x="${(4 - x) * g}" y="${y * g}" width="${g}" height="${g}"/>`);
    }
  }
  const s = g * 5;
  return `<svg class="idt" width="${size}" height="${size}" viewBox="-4 -4 ${s + 8} ${s + 8}" aria-hidden="true">` +
    `<rect x="-4" y="-4" width="${s + 8}" height="${s + 8}" fill="${bg}"/><g fill="${fg}">${cells.join("")}</g></svg>`;
}
// An author byline: identicon + short display name.
function avatarName(ref, name, size = 18) {
  return `<span class="byline">${identicon(ref, size)}${esc(name)}</span>`;
}
// An author byline that links to that identity's passport. Wraps ONLY the
// identity (identicon + name) so it doesn't swallow neighbouring vote/receipt
// affordances in the post-meta row.
function authorLink(ref, name, size = 18) {
  return `<a class="byline-link" href="#/passport/${encodeURIComponent(ref || "")}">${avatarName(ref, name, size)}</a>`;
}
// Turn an attestation slug (`founding-member`) into a display label
// ("Founding member").
function prettySlug(s) {
  s = String(s || "").replace(/-/g, " ").trim();
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}
// Stable hue for a board id — used by its sidebar dot and its c/<board> tag.
const boardHue = (id) => hashStr("board:" + (id || "?")) % 360;
// The colored c/<board> tag pill.
function boardTag(id) {
  return `<a class="ctag" href="#/c/${esc(id)}" style="--ch:${boardHue(id)}" data-c="${esc(id)}">c/${esc(id)}</a>`;
}

// Inline "verified seal" glyph for the receipt affordance — replaces the bare
// 🧾 emoji, which renders as tofu in some environments.
const RECEIPT_ICON =
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 2.5l7.5 3.2v5.6c0 4.6-3.2 7.7-7.5 9.2-4.3-1.5-7.5-4.6-7.5-9.2V5.7L12 2.5z"/><path d="M8.7 12l2.3 2.3 4.3-4.4"/></svg>`;

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

// ---------------------------------------------------------------------------
// theme (light/dark). A manual choice is persisted in localStorage and wins over
// the OS preference by stamping data-theme on <html>; the CSS re-points the same
// tokens for :root[data-theme="dark"|"light"]. index.html sets the attribute
// before first paint (no flash); here we keep the toggle button glyph in sync
// and flip the choice live. Default (no stored choice) follows the OS.
// ---------------------------------------------------------------------------
function currentTheme() {
  return document.documentElement.getAttribute("data-theme")
    || (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
}
function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  const btn = $("#theme-toggle");
  if (btn) {
    // Show the glyph of the theme you'd switch TO.
    btn.textContent = theme === "dark" ? "☀" : "☾";
    btn.setAttribute("title", theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
  }
}
function toggleTheme() {
  const next = currentTheme() === "dark" ? "light" : "dark";
  localStorage.setItem("mingo_theme", next);
  applyTheme(next);
}

function renderAuth() {
  const slot = $("#auth-slot");
  if (session.email) {
    const name = shortAuthor(session.email);
    slot.innerHTML = `<div class="user-menu">
      <button class="user-btn" id="user-btn" aria-haspopup="true" aria-expanded="false">
        ${identicon(session.email, 22)}<span class="u-name">${esc(name)}</span><span class="u-caret">▾</span>
      </button>
      <div class="menu-pop" id="user-pop" hidden role="menu">
        <button class="menu-item" role="menuitem" id="menu-profile">${ICON_PROFILE}<span>Profile</span></button>
        <button class="menu-item" role="menuitem" id="menu-settings">${ICON_SETTINGS}<span>Settings</span></button>
        <div class="menu-sep"></div>
        <button class="menu-item danger" role="menuitem" id="menu-signout">${ICON_SIGNOUT}<span>Sign out</span></button>
      </div></div>`;
    const btn = $("#user-btn"), pop = $("#user-pop");
    btn.onclick = (e) => { e.stopPropagation(); toggleMenu(btn, pop); };
    $("#menu-profile").onclick = () => { closeAllMenus(); location.hash = `#/passport/${encodeURIComponent(session.email)}`; };
    $("#menu-settings").onclick = () => { closeAllMenus(); location.hash = "#/settings"; };
    $("#menu-signout").onclick = () => { closeAllMenus(); signOut(); };
  } else {
    slot.innerHTML = `<button class="primary" id="signin">Sign in</button>`;
    $("#signin").onclick = signIn;
  }
}

// Small inline icons for the user menu items (currentColor, no network).
const ICON_PROFILE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6.5 8-6.5S20 17 20 21"/></svg>`;
const ICON_SETTINGS = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1"/></svg>`;
const ICON_SIGNOUT = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/></svg>`;
const ICON_EDIT = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg>`;
const ICON_DELETE = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M6 6l1 14a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-14"/><path d="M10 11v6M14 11v6"/></svg>`;

// ---------------------------------------------------------------------------
// popup menus (user dropdown + post-card kebab). A single dismissal model:
// clicking anywhere else or pressing Escape closes any open menu; opening one
// closes the others. Menus are plain absolutely-positioned popovers toggled via
// the [hidden] attribute so their action buttons (data-receipt/data-edit) keep
// working with the existing wireReceiptButtons/wireEditButtons handlers.
// ---------------------------------------------------------------------------
function closeAllMenus() {
  document.querySelectorAll(".menu-pop").forEach((p) => {
    if (p.hidden) return;
    p.hidden = true;
    const trigger = p.previousElementSibling || document.querySelector(`[aria-controls="${p.id}"]`);
    if (trigger) trigger.setAttribute("aria-expanded", "false");
  });
}
function toggleMenu(trigger, pop) {
  const willOpen = pop.hidden;
  closeAllMenus();
  if (willOpen) { pop.hidden = false; trigger.setAttribute("aria-expanded", "true"); }
}

// The open poster modal's controls, so the same-tab consent round-trip can
// drive it from outside its closure: pickupPoster close()s it on approval, and
// the pageshow handler freeze()s it while that check runs (a still-active
// Continue would bounce a stray tap right back to browserid). thaw() re-arms
// Continue when the pickup comes back without an approval.
let posterModal = null;

// A proper modal (not a hard-to-spot link) to enable server-side posting.
// The consent request is raised as soon as the modal opens (the IdP reuses an
// outstanding request, so reopening costs nothing) and Continue is a REAL LINK
// to the consent page: a same-tab navigation no popup blocker can eat. This is
// the fix for mingo-hlka — Arc mobile blocks window.open AND named-target
// anchors, with per-tab block state that survives reloads, so any popup-shaped
// flow silently dead-ends. Where popups ARE allowed, Continue's click opens a
// new tab instead (keeping this page alive) and we poll for approval in place;
// on the same-tab path the pickup happens at next load (pickupPoster).
// Resolves true once enabled.
function openPosterEnableModal() {
  return new Promise((resolve) => {
    const overlay = el(`<div class="modal-overlay">
      <div class="modal card">
        <div class="h2">Let mingo post for you</div>
        <p class="muted" style="margin-top:8px">Approve once and mingo signs your
          posts, comments and votes for you — no signing pop-up every time, and it
          works on mobile. You approve on <strong>browserid.me</strong>, and you
          can turn this off anytime.</p>
        <p class="status" id="pe-status" style="margin-top:8px"></p>
        <div class="row-between" style="margin-top:12px">
          <button id="pe-cancel">Cancel</button>
          <a class="primary" id="pe-go" aria-disabled="true">Continue</a>
        </div>
      </div></div>`);
    document.body.appendChild(overlay);
    const setStatus = (cls, msg) => {
      const s = overlay.querySelector("#pe-status");
      s.className = "status " + (cls || "");
      s.textContent = msg || "";
    };
    const close = (val) => {
      posterModal = null;
      overlay.remove();
      resolve(val);
    };
    overlay.querySelector("#pe-cancel").onclick = () => close(false);
    const go = overlay.querySelector("#pe-go");
    posterModal = {
      close,
      freeze() {
        go.setAttribute("aria-disabled", "true");
        setStatus("muted", "Checking whether your approval landed…");
      },
      thaw() {
        if (go.href) go.removeAttribute("aria-disabled");
        setStatus("warn", "Approval didn't complete — tap Continue to try again.");
      },
    };
    setStatus("muted", "Setting up…");
    let waiting = false;
    enablePoster().then((uri) => {
      go.href = uri;
      go.removeAttribute("aria-disabled");
      setStatus("", "");
      go.onclick = (e) => {
        // Try a new tab first — it keeps this page (and any draft) alive so we
        // can poll for the approval right here. A blocked window.open returns
        // null, and then we DON'T preventDefault: the anchor's default same-tab
        // navigation proceeds, which nothing can block. Stash the draft so it
        // survives that round-trip.
        const win = window.open(uri, "_blank");
        if (!win) return stashDraft();
        e.preventDefault();
        setStatus("muted", "Approve in the browserid.me tab, then return here — waiting…");
        if (waiting) return; // re-tap just reopens the tab; one poller is enough
        waiting = true;
        pollPoster().then((ok) => {
          waiting = false;
          if (ok) {
            close(true);
            renderAuth();
            toast("Done — mingo now posts for you. 🎉");
          } else {
            setStatus("warn", "Approval didn't complete — tap Continue to try again.");
          }
        });
      };
    }).catch((e) => {
      setStatus("err", "Couldn't start: " + e.message);
      toast("Couldn't set up mingo posting: " + e.message);
    });
  });
}

// Pick up an approval after a same-tab consent round-trip (mingo-hlka): the
// in-modal poll dies when the page navigates to browserid.me, so on load (and
// on bfcache restore) check whether a pending request was approved while we
// were away. Poll immediately — the user likely just approved — then briefly;
// "none" means nothing was pending and we stop right away.
let posterPickupRunning = false;
async function pickupPoster() {
  if (posterPickupRunning || poster.enabled || !session.email) return;
  posterPickupRunning = true;
  try {
    for (let i = 0; i < 5; i++) {
      let r;
      try { r = await idpPost("/poster/poll", {}); } catch { posterModal?.thaw(); return; }
      if (r.status === "approved") {
        poster.enabled = true;
        renderAuth();
        toast("Done — mingo now posts for you. 🎉");
        // A bfcache-restored page may still show the modal whose caller is
        // awaiting it (e.g. the Post tap) — resolve it so the write proceeds.
        if (posterModal) posterModal.close(true);
        return;
      }
      if (r.status !== "pending") { posterModal?.thaw(); return; } // none / denied / expired
      await new Promise((res) => setTimeout(res, 6000));
    }
    posterModal?.thaw(); // gave up while still pending — let the user retry
  } finally { posterPickupRunning = false; }
}

// Draft preservation across the same-tab consent hop: bfcache usually restores
// the page (textarea included), but a real reload would eat the draft.
function stashDraft() {
  const post = $("#post-body");
  const comment = $("#c-body");
  const d = post?.value.trim()
    ? { kind: "post", body: post.value, hash: location.hash }
    : comment?.value.trim()
      ? { kind: "comment", body: comment.value, hash: location.hash }
      : null;
  if (d) sessionStorage.setItem("mingo_draft", JSON.stringify(d));
}
function restoreDraft() {
  const raw = sessionStorage.getItem("mingo_draft");
  if (!raw) return;
  sessionStorage.removeItem("mingo_draft");
  let d;
  try { d = JSON.parse(raw); } catch { return; }
  if (d.hash !== location.hash) return; // stale — user landed somewhere else
  if (d.kind === "post") {
    const parts = location.hash.slice(2).split("/");
    if (parts[0] !== "c" || !parts[1] || parts[2]) return;
    showCompose(parts[1]); // reopen the compose box the draft came from
  }
  const ta = $(d.kind === "post" ? "#post-body" : "#c-body");
  if (ta) ta.value = d.body;
}

async function renderChrome() {
  await refreshPosterStatus();
  renderAuth();
  try {
    const comms = await getCommunities();
    window.__comms = comms;
    const ul = $("#community-list");
    ul.innerHTML = comms.map((c) => `<li><a href="#/c/${esc(c.id)}" data-c="${esc(c.id)}"><span class="cdot" style="--ch:${boardHue(c.id)}"></span>${esc(c.name)} ${c.open ? "✓" : ""}</a></li>`).join("") || `<li class="muted">none</li>`;
  } catch (e) {
    $("#community-list").innerHTML = `<li class="muted">daemon offline</li>`;
  }
  try {
    const sr = await stateRoot();
    $("#state-root").textContent = `block ${sr.block} · root ${sr.state_root.slice(0, 10)}…`;
  } catch {}
}

// ---------------------------------------------------------------------------
// views
// ---------------------------------------------------------------------------
async function viewHub() {
  const main = $("#main");
  main.innerHTML = `<div class="card view-header">
      <div class="vh-main"><div class="h1">Your feed</div>
        <div class="muted vh-sub">Top posts across your communities</div></div>
    </div><div id="feed" class="muted">loading…</div>`;
  const comms = window.__comms || (await getCommunities());
  const votes = await getVoteCounts();
  currentMods = await moderatedBoards(); // so mod-delete shows on moderated boards in the feed
  const rows = [];
  for (const c of comms) {
    const { posts } = await getSpaceItems(c.id, CONFIG.space);
    for (const p of posts) rows.push({ ...p, comm: c.id });
  }
  rows.sort((a, b) => (votes.get(b.uri) || 0) - (votes.get(a.uri) || 0) || (b.hlc || "").localeCompare(a.hlc || ""));
  $("#feed").outerHTML = `<div id="feed">${rows.length ? rows.map((p) => feedRow(p, votes)).join("") : `<div class="card muted">No posts yet. Sign in and create the first one.</div>`}</div>`;
  wireVoteButtons();
  wireReceiptButtons();
  wireEditButtons();
  wireCardMenus(); wireDeleteButtons();
  startLivePoll(() => pollFeed("hub"));
}

function feedRow(p, votes, showComm = true) {
  const pending = p.confirmed === false;
  return `<div class="card feed-row${pending ? " pending" : ""}">
    <div class="fr-vote"><div class="votes"><button class="link up" data-vote="${esc(p.comm)}|${esc(p.uri)}">▲</button><span class="n" data-count="${esc(p.uri)}">${votes.get(p.uri) || 0}</span></div></div>
    <div class="post-meta">${showComm ? boardTag(p.comm) : ""}${authorLink(p.authorRef, p.author)}<span class="fr-time">${timeAgo(p.ts)}</span>${editedTag(p)}${pending ? ` · <span class="muted">pending…</span>` : ""}</div>
    ${cardMenu(p)}
    <div class="post-title" data-body="${esc(p.uri)}"><a href="#/c/${esc(p.comm)}/p/${esc(p.id)}">${esc((p.body || "").slice(0, 120))}</a></div>
  </div>`;
}

// The top-right kebab (⋮) menu for a post card. Folds the receipt and (owner-
// only) edit affordances into one popover, keeping their existing data-receipt /
// data-edit hooks so wireReceiptButtons/wireEditButtons still bind them. Future
// items (report/delete) slot in as more .menu-item buttons here. Registers the
// item in receiptItems so both actions can look it up (as receiptLink did).
function cardMenu(item) {
  receiptItems.set(item.uri, item);
  const editItem = ownItem(item)
    ? `<button class="menu-item" role="menuitem" data-edit="${esc(item.uri)}">${ICON_EDIT}<span>Edit</span></button>`
    : "";
  // Delete: the owner's own delete (mingo-3go6), or — for a non-owner who
  // moderates this board — a moderator delete (mingo-n268), authorized by the
  // community's moderator-role policy grant rather than the owner fast path.
  // Both confirm inline before writing; data-moddelete flags the moderator copy.
  const deleteItem = ownItem(item)
    ? `<button class="menu-item danger" role="menuitem" data-delete="${esc(item.uri)}">${ICON_DELETE}<span>Delete</span></button>`
    : canModDelete(item)
      ? `<button class="menu-item danger" role="menuitem" data-delete="${esc(item.uri)}" data-moddelete="1">${ICON_DELETE}<span>Delete (moderator)</span></button>`
      : "";
  const popId = `m-${hashStr(item.uri).toString(36)}`;
  return `<div class="fr-menu">
    <button class="kebab" aria-haspopup="true" aria-expanded="false" aria-controls="${popId}" aria-label="More actions" title="More">⋮</button>
    <div class="menu-pop" id="${popId}" hidden role="menu">
      <button class="menu-item" role="menuitem" data-receipt="${esc(item.uri)}">${RECEIPT_ICON}<span>Receipt</span></button>
      ${editItem}
      ${deleteItem}
    </div></div>`;
}
function wireCardMenus() {
  document.querySelectorAll(".kebab").forEach((b) => {
    const pop = b.nextElementSibling;
    b.onclick = (e) => { e.stopPropagation(); toggleMenu(b, pop); };
    // Selecting any item closes the menu first — captured so it runs before the
    // item's own handler (which may swap out this markup, e.g. beginEdit/beginDelete).
    pop.addEventListener("click", (e) => {
      if (e.target.closest(".menu-item")) closeAllMenus();
    }, true);
  });
}

async function viewCommunity(commId) {
  const main = $("#main");
  const comms = window.__comms || (await getCommunities());
  const c = comms.find((x) => x.id === commId);
  if (!c) { main.innerHTML = `<div class="card">Unknown community.</div>`; return; }
  const member = session.email ? await hasMembership(c.id) : false;
  currentMods = await moderatedBoards();
  const actionBtn = !session.email
    ? `<button class="primary" id="signin2">Sign in to post</button>`
    : member
      ? `<button class="primary" id="newpost">+ New post</button>`
      : `<button class="primary" id="join">Join to post</button>`;
  // A "Moderate" link into the per-board mod view — shown only to this board's
  // moderators (mingo-n268).
  const modLink = isMod(c.id)
    ? `<a class="mod-link" href="#/c/${esc(c.id)}/mod" title="Moderate this board">🛡 Moderate</a>`
    : "";
  main.innerHTML = `
    <div class="card view-header">
      <div class="vh-main">
        <div class="view-title"><span class="cdot" style="--ch:${boardHue(c.id)}"></span><div class="h1">c/${esc(c.id)}${c.open ? " ✓" : ""}</div>${modLink}</div>
        ${c.description ? `<div class="muted vh-sub">${esc(c.description)}</div>` : ""}
      </div>
      <div class="vh-action">${actionBtn}</div>
    </div>
    <div id="compose"></div>
    <div id="posts" class="muted">loading…</div>`;
  if (session.email && member) $("#newpost").onclick = () => showCompose(c.id);
  else if (session.email) $("#join").onclick = async (e) => {
    if (!(await ensureCanWrite())) return;
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
  wireReceiptButtons();
  wireEditButtons();
  wireCardMenus(); wireDeleteButtons();
  startLivePoll(() => pollFeed("community", c.id));
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
    if (!(await ensureCanWrite())) return;
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
  currentMods = await moderatedBoards(); // enables mod-delete on the post + its comments
  const post = posts.find((p) => p.id === postId);
  // A deleted post is gone from head state, so it simply isn't in `posts`. Its
  // comments are independent objects with no chain-side cascade (mingo-3go6), so
  // we don't render the orphaned thread at all — the post is the only entry point
  // to it, and the feed already omits the deleted post.
  if (!post) {
    main.innerHTML = `<a class="muted" href="#/c/${esc(commId)}">← c/${esc(commId)}</a>
      <div class="card muted">This post was deleted or doesn't exist.</div>`;
    return;
  }
  // Stamp the board id so cardMenu/commentBox can offer moderator delete here.
  post.comm = commId;
  const kids = comments.filter((c) => c.parent === post.uri).map((c) => ({ ...c, comm: commId }));
  main.innerHTML = `
    <a class="muted" href="#/c/${esc(commId)}">← c/${esc(commId)}</a>
    <div class="card feed-row thread-post">
      <div class="fr-vote"><div class="votes"><button class="link up" data-vote="${esc(commId)}|${esc(post.uri)}">▲</button><span class="n" data-count="${esc(post.uri)}">${votes.get(post.uri) || 0}</span></div></div>
      <div class="post-meta">${authorLink(post.authorRef, post.author, 22)}<span class="fr-time">${timeAgo(post.ts)}</span>${editedTag(post)}</div>
      ${cardMenu(post)}
      <div class="post-body" data-body="${esc(post.uri)}">${esc(post.body)}</div>
    </div>
    <div class="h2">Comments</div>
    <div class="card"><textarea id="c-body" placeholder="Add a comment…"></textarea>
      <div style="text-align:right;margin-top:8px"><button class="primary" id="c-submit">Comment</button></div></div>
    <div id="comments">${kids.length ? kids.map((c) => commentBox(c, votes)).join("") : `<div class="muted">No comments yet.</div>`}</div>`;
  $("#c-submit").onclick = async () => {
    const body = $("#c-body").value.trim(); if (!body) return;
    if (!(await ensureCanWrite())) return;
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
  wireReceiptButtons();
  wireEditButtons();
  wireCardMenus(); wireDeleteButtons();
  startLivePoll(() => pollThread(commId, post));
}
function commentBox(c, votes) {
  return `<div class="comment"><div class="post-meta">${authorLink(c.authorRef, c.author)}${timeAgo(c.ts)} · ${votes.get(c.uri) || 0} ▲${editedTag(c)}${receiptLink(c)}${editLink(c)}${deleteLink(c)}</div><div data-body="${esc(c.uri)}">${esc(c.body)}</div></div>`;
}

// ---------------------------------------------------------------------------
// per-board moderator view (mingo-n268, route #/c/<board>/mod). A minimal,
// moderator-only surface: recent posts AND comments in the board's space, each
// with a remove control. Reachable only when the session user moderates the
// board (the "Moderate" link in the board header, and this view's own guard).
// Removals go through the same beginDelete/deleteContent path as everywhere
// else — the moderator signs, the daemon authorizes via the moderator-role grant.
// ---------------------------------------------------------------------------
async function viewModerate(commId) {
  const main = $("#main");
  const comms = window.__comms || (await getCommunities());
  const c = comms.find((x) => x.id === commId);
  if (!c) { main.innerHTML = `<div class="card">Unknown community.</div>`; return; }
  currentMods = await moderatedBoards();
  if (!isMod(commId)) {
    main.innerHTML = `<a class="muted" href="#/c/${esc(commId)}">← c/${esc(commId)}</a>
      <div class="card muted">You are not a moderator of c/${esc(commId)}.</div>`;
    return;
  }
  main.innerHTML = `
    <a class="muted" href="#/c/${esc(commId)}">← c/${esc(commId)}</a>
    <div class="card view-header"><div class="vh-main">
      <div class="view-title"><span class="cdot" style="--ch:${boardHue(c.id)}"></span><div class="h1">Moderate c/${esc(c.id)}</div></div>
      <div class="muted vh-sub">Recent posts and comments — remove anything that breaks the rules.</div>
    </div></div>
    <div id="mod-list" class="muted">loading…</div>`;
  const [{ posts, comments }, votes] = await Promise.all([getSpaceItems(commId, CONFIG.space), getVoteCounts()]);
  const items = modItems(posts, comments, commId);
  $("#mod-list").outerHTML = `<div id="mod-list">${
    items.length ? items.map((it) => modRow(it, votes)).join("") : `<div class="card muted">Nothing here yet.</div>`
  }</div>`;
  wireReceiptButtons();
  wireDeleteButtons();
  startLivePoll(() => pollModerate(commId));
}
// Posts + comments in a board, newest first, each stamped with the board id so
// the delete affordance can resolve moderator status.
function modItems(posts, comments, commId) {
  return [...posts, ...comments]
    .map((it) => ({ ...it, comm: commId }))
    .sort((a, b) => (b.hlc || "").localeCompare(a.hlc || ""));
}
// A single moderation row: kind + author + body + a remove control. The item's
// author still gets the plain owner-delete; everyone else's gets the moderator
// remove (data-moddelete). data-body carries the inline confirm swap.
function modRow(it, votes) {
  receiptItems.set(it.uri, it);
  const kind = it.schema === "comment.v1" ? "comment" : "post";
  const del = ownItem(it)
    ? `<button class="link delete-btn danger" data-delete="${esc(it.uri)}" title="delete">delete</button>`
    : `<button class="link delete-btn danger" data-delete="${esc(it.uri)}" data-moddelete="1" title="remove as moderator">remove</button>`;
  return `<div class="card feed-row">
    <div class="post-meta"><span class="mod-kind">${kind}</span>${authorLink(it.authorRef, it.author)}<span class="fr-time">${timeAgo(it.ts)}</span>${editedTag(it)} · <button class="link receipt" data-receipt="${esc(it.uri)}" title="cryptographic receipt" aria-label="cryptographic receipt">${RECEIPT_ICON}<span class="rlbl">receipt</span></button> · ${del}</div>
    <div class="post-body" data-body="${esc(it.uri)}">${esc((it.body || "").slice(0, 400))}</div>
  </div>`;
}
async function pollModerate(commId) {
  const [{ posts, comments }, votes] = await Promise.all([getSpaceItems(commId, CONFIG.space), getVoteCounts()]);
  const container = document.getElementById("mod-list");
  if (!container) return;
  liveAppend(container, modItems(posts, comments, commId), (it) => modRow(it, votes));
}

function wireVoteButtons() {
  document.querySelectorAll("[data-vote]").forEach((b) => {
    b.onclick = async () => {
      const [comm, uri] = b.getAttribute("data-vote").split("|");
      if (b.dataset.voted) return; // already counted
      if (!(await ensureCanWrite())) return;
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

// ---------------------------------------------------------------------------
// provenance receipt — per-post cryptographic receipt drawer (mingo-o7pd).
// The 🧾 in a post-meta line opens a drawer showing who signed the object, the
// cert that binds the signing key to an identity, the delegation warrant when
// it was posted via mingo-poster, and where it sits on-chain. All of it comes
// from ONE request: /v1/object?…&proof=1, whose `sboq` text embeds the full
// original signed wire (headers incl. Auth-Cert/Auth-Warrant) plus the trie
// proof against the CURRENT head state root.
// ---------------------------------------------------------------------------

// Feed rows are rendered as HTML strings, so stash each row's item here and let
// the click handler look it up by uri (same pattern as data-vote, richer data).
const receiptItems = new Map();
// URIs the local user has deleted this session. A delete has no confirmed head
// state to poll for (the object simply leaves head), so we track it client-side:
// getSpaceItems filters these out so the row disappears on the next render and
// never lingers as a "pending…" card or reappears from the stale pending overlay
// entry the daemon serves during the delete's confirmation window (mingo-3go6).
const deletedUris = new Set();
function receiptLink(p) {
  receiptItems.set(p.uri, p);
  return ` · <button class="link receipt" data-receipt="${esc(p.uri)}" title="cryptographic receipt" aria-label="cryptographic receipt">${RECEIPT_ICON}<span class="rlbl">receipt</span></button>`;
}
function wireReceiptButtons() {
  document.querySelectorAll("[data-receipt]").forEach((b) => {
    b.onclick = () => {
      const item = receiptItems.get(b.getAttribute("data-receipt"));
      if (item) openReceipt(item);
    };
  });
}

// ---------------------------------------------------------------------------
// edit affordance (bean mingo-e6kq). Only the owner sees "edit" (session email
// === the item's authorRef); non-owners never get the affordance. Editing opens
// an inline textarea prefilled with the FULL body (display truncation aside) and
// re-writes the same (path,id) via editContent. Items are registered in
// receiptItems by receiptLink already; we register here too so an edit button
// can appear even where receiptLink isn't rendered.
// ---------------------------------------------------------------------------
function ownItem(item) {
  return !!session.email && session.email === item.authorRef;
}
// A subtle "· edited" marker, shown once an object carries a non-null prev.
function editedTag(item) {
  return item && item.prev ? ` · <span class="muted edited" title="this was edited">edited</span>` : "";
}
// The "edit" button (owner-only). Registers the item so beginEdit can look it up.
function editLink(item) {
  if (!ownItem(item)) return "";
  receiptItems.set(item.uri, item);
  return ` · <button class="link edit-btn" data-edit="${esc(item.uri)}" title="edit">edit</button>`;
}
function wireEditButtons() {
  document.querySelectorAll("[data-edit]").forEach((b) => {
    b.onclick = () => beginEdit(b.getAttribute("data-edit"));
  });
}
// The "delete" button for comment meta-lines where the kebab menu isn't
// rendered. Owner-delete (mingo-3go6) or, for a non-owner who moderates the
// board, a moderator delete (mingo-n268). Registers the item so beginDelete can
// look it up.
function deleteLink(item) {
  if (ownItem(item)) {
    receiptItems.set(item.uri, item);
    return ` · <button class="link delete-btn danger" data-delete="${esc(item.uri)}" title="delete">delete</button>`;
  }
  if (canModDelete(item)) {
    receiptItems.set(item.uri, item);
    return ` · <button class="link delete-btn danger" data-delete="${esc(item.uri)}" data-moddelete="1" title="remove as moderator">remove</button>`;
  }
  return "";
}
function wireDeleteButtons() {
  document.querySelectorAll("[data-delete]").forEach((b) => {
    b.onclick = () => beginDelete(b.getAttribute("data-delete"), b.hasAttribute("data-moddelete"));
  });
}
// Confirm-then-delete, mirroring beginEdit's inline swap: the body element
// (data-body="<uri>") is replaced with a confirmation prompt; Cancel restores
// the saved markup, Delete writes and re-renders once the daemon overlay has the
// removal (same ~1.2s settle as edit/post). Works for posts and comments — both
// carry a data-body element keyed by uri.
function beginDelete(uri, asMod = false) {
  const item = receiptItems.get(uri);
  if (!item) return;
  const bodyEl = document.querySelector(`[data-body="${CSS.escape(uri)}"]`);
  if (!bodyEl || bodyEl.querySelector(".edit-box")) return; // already editing/deleting
  const saved = bodyEl.innerHTML;
  const kind = item.schema === "comment.v1" ? "comment" : "post";
  // Moderator-appropriate copy when removing someone else's content (mingo-n268);
  // the owner path keeps its own wording. The write is identical either way — the
  // signer is the session user (the moderator), and the daemon authorizes the
  // removal via the board's moderator-role grant, not the owner fast path.
  const prompt = asMod
    ? `Remove this ${kind} as a moderator? Everyone loses it.`
    : `Delete this ${kind}? This removes it for everyone and can't be undone.`;
  const confirmLabel = asMod ? "Remove" : "Delete";
  bodyEl.innerHTML = `<div class="edit-box"><div class="muted">${prompt}</div>
    <div class="row-between" style="margin-top:8px"><span class="muted tiny">${asMod ? "removing" : "deleting"}</span>
    <span><button class="edit-cancel">Cancel</button> <button class="primary danger delete-confirm">${confirmLabel}</button></span></div></div>`;
  bodyEl.querySelector(".edit-cancel").onclick = () => { bodyEl.innerHTML = saved; };
  bodyEl.querySelector(".delete-confirm").onclick = async () => {
    if (!(await ensureCanWrite())) return;
    const btn = bodyEl.querySelector(".delete-confirm");
    btn.disabled = true; btn.textContent = asMod ? "Removing…" : "Deleting…";
    try {
      await deleteContent(item);
      // Mark it deleted so every render (this one and the live poll) drops it —
      // the daemon still serves it as pending until the delete confirms, so we
      // can't wait for a confirmed head read the way a post/edit does.
      deletedUris.add(item.uri);
      toast(asMod ? `${kind} removed.` : `${kind} deleted.`);
      await new Promise((r) => setTimeout(r, 1200));
      route(); // re-render now omits the object (deletedUris); the row disappears
    } catch (e) {
      toast((asMod ? "remove" : "delete") + " failed: " + e.message);
      btn.disabled = false; btn.textContent = confirmLabel;
    }
  };
}
// Swap the item's body element (marked data-body="<uri>") for an inline editor.
// Cancel restores the saved markup; Save re-writes and re-renders (the daemon
// overlay serves the updated head immediately, like showCompose post-submit).
function beginEdit(uri) {
  const item = receiptItems.get(uri);
  if (!item) return;
  const bodyEl = document.querySelector(`[data-body="${CSS.escape(uri)}"]`);
  if (!bodyEl || bodyEl.querySelector(".edit-box")) return; // already editing
  const saved = bodyEl.innerHTML;
  bodyEl.innerHTML = `<div class="edit-box"><textarea class="edit-ta"></textarea>
    <div class="row-between" style="margin-top:8px"><span class="muted tiny">editing</span>
    <span><button class="edit-cancel">Cancel</button> <button class="primary edit-save">Save</button></span></div></div>`;
  const ta = bodyEl.querySelector(".edit-ta");
  ta.value = item.body || "";
  ta.focus();
  bodyEl.querySelector(".edit-cancel").onclick = () => { bodyEl.innerHTML = saved; };
  bodyEl.querySelector(".edit-save").onclick = async () => {
    const body = ta.value.trim();
    if (!body) return;
    if (!(await ensureCanWrite())) return;
    const btn = bodyEl.querySelector(".edit-save");
    btn.disabled = true; btn.textContent = "Saving…";
    try {
      await editContent(item, body);
      toast("edit saved — pending confirmation…");
      await new Promise((r) => setTimeout(r, 1200));
      route(); // overlay serves the new head; re-render shows it (with "· edited")
    } catch (e) {
      toast("edit failed: " + e.message);
      btn.disabled = false; btn.textContent = "Save";
    }
  };
}

// Parse the SBOQ proof document (sbo-core proof/sboq.rs): RFC-822-ish headers,
// a blank line, ONE line of trie-proof JSON (its serializer escapes newlines,
// so the array never wraps), then the raw embedded SBO wire object — itself
// headers + blank line + payload. We only need header values from both layers,
// so this stays a tolerant line parser; unknown headers are ignored.
function parseSboq(text) {
  const sep = text.indexOf("\n\n");
  if (sep < 0) throw new Error("malformed proof document");
  const proof = parseHeaderLines(text.slice(0, sep));
  const rest = text.slice(sep + 2);
  const nl = rest.indexOf("\n"); // end of the single-line proof JSON
  const wireText = nl >= 0 ? rest.slice(nl + 1) : "";
  const wireEnd = wireText.indexOf("\n\n");
  const wire = parseHeaderLines(wireEnd >= 0 ? wireText.slice(0, wireEnd) : wireText);
  return { proof, wire };
}
function parseHeaderLines(block) {
  const h = {};
  for (const line of block.split("\n")) {
    const i = line.indexOf(":");
    if (i > 0) h[line.slice(0, i)] = line.slice(i + 1).trim();
  }
  return h;
}

// Decode a JWS payload for display (no verification — this is a rendering of
// what the daemon serves; the chain itself already validated the envelope).
function jwsPayload(token) {
  try {
    return JSON.parse(new TextDecoder().decode(b64urlToBytes(token.split(".")[1])));
  } catch { return null; }
}

// Long hex/JWS values stay behind middle-truncation; tap copies the full value.
const truncMid = (s, head = 12, tail = 6) =>
  s && s.length > head + tail + 1 ? s.slice(0, head) + "…" + s.slice(-tail) : s || "";
const copyable = (full, head, tail) =>
  `<span class="mono copy" data-copy="${esc(full)}" title="tap to copy">${esc(truncMid(full, head, tail))}</span>`;
const rDate = (sec) => (sec ? new Date(sec * 1000).toLocaleString() : "unknown");
const rSection = (label, html) =>
  `<div class="receipt-section"><div class="side-h">${esc(label)}</div>${html}</div>`;

function openReceipt(item) {
  const overlay = el(`<div class="modal-overlay">
    <div class="modal card receipt-modal">
      <div class="row-between"><div class="h2" style="margin:0">${RECEIPT_ICON} Receipt</div>
        <button class="link" id="r-close" aria-label="Close">✕</button></div>
      <div id="r-body" class="muted" style="margin-top:8px">loading…</div>
    </div></div>`);
  document.body.appendChild(overlay);
  overlay.querySelector("#r-close").onclick = () => overlay.remove();
  overlay.addEventListener("click", (e) => { if (e.target === overlay) overlay.remove(); });
  const body = overlay.querySelector("#r-body");
  renderReceipt(item, body).catch((e) => {
    body.className = "";
    body.innerHTML = `<div class="error">couldn't load receipt: ${esc(e.message)}</div>`;
  });
}

// "Who vouches for this identity" line: an identity certified by its own email
// domain has a primary IdP; any other issuer is a fallback certifier vouching
// because the domain doesn't run one (that's the only way a foreign issuer is
// accepted — the daemon checks it against /sys/trust/brokers).
function vouchLine(certPayload, email) {
  const iss = certPayload?.iss || "unknown issuer";
  const domain = (email || "").split("@")[1] || "?";
  return iss === domain
    ? `<strong>${esc(iss)}</strong> — the identity's own provider — certified this key speaks for ${esc(email)}`
    : `<strong>${esc(iss)}</strong> — a fallback certifier — vouched for ${esc(email)}, whose domain ${esc(domain)} doesn't run its own identity provider`;
}
// The certifying issuer's key is anchored in DNS; the DNSSEC proof is a public
// record the daemon validates against — link straight to it.
function anchorLine(iss) {
  if (!iss) return "";
  const href = `${CONFIG.daemon}/v1/object?path=${encodeURIComponent("/sys/dnssec/")}&id=${encodeURIComponent(iss)}`;
  return `<div class="tiny muted">${esc(iss)}'s certifying key is anchored in DNS — <a href="${esc(href)}" target="_blank" rel="noopener" class="rlink">DNSSEC proof ↗</a></div>`;
}

async function renderReceipt(item, body) {
  // A pending object lives only in the daemon's mempool overlay — no trie
  // proof exists yet, so show what the list row already knows and say so.
  if (item.confirmed === false) {
    body.className = "";
    body.innerHTML =
      rSection("Status", `<div>⏳ pending confirmation — full receipt available once confirmed</div>`) +
      rSection("Author", `<div>${esc(item.authorRef || item.author)}</div>`) +
      rSection("Written", `<div>${esc(item.ts ? new Date(item.ts).toLocaleString() : "unknown")}</div>`);
    return;
  }

  const view = await getObject(item.path, item.id, true);
  let proof = {}, wire = {};
  if (view.sboq) ({ proof, wire } = parseSboq(view.sboq));
  // The wire spec calls this header Public-Key (wire/serializer.rs); accept
  // Signing-Key too in case an older node still emits the pre-rename name.
  const wireKey = wire["Public-Key"] || wire["Signing-Key"] || "";
  const cert = wire["Auth-Cert"] ? jwsPayload(wire["Auth-Cert"]) : null;
  const warrant = wire["Auth-Warrant"] ? jwsPayload(wire["Auth-Warrant"]) : null;
  // Agent path: the top-level cert certifies the AGENT; the author's own cert
  // rides inside the warrant as `parent-cert` (the author signed the warrant
  // with the key that cert binds). Client path: the top-level cert IS the
  // author's, and the wire signing key is the author's key.
  const authorCert = warrant ? jwsPayload(warrant["parent-cert"] || "") : cert;
  const author = view.owner_ref || view.creator || "unknown";

  const parts = [];
  parts.push(rSection("Status",
    `<div><span class="confirmed">✓ verified</span> · confirmed in block ${esc(String(view.block ?? "?"))}</div>`));

  // -- Author: the identity this post belongs to, and who vouches for it.
  const authorKey = warrant
    ? authorCert?.["public-key"]?.publicKey || ""
    : wireKey;
  parts.push(rSection("Author",
    `<div><strong>${esc(author)}</strong></div>` +
    (authorKey ? `<div class="tiny">identity key ${copyable(authorKey, 16, 6)}</div>` : "") +
    (authorCert
      ? `<div class="tiny muted">${vouchLine(authorCert, authorCert.principal?.email || author)}</div>
         <div class="tiny muted">certified ${esc(rDate(authorCert.iat))} · expires ${esc(rDate(authorCert.exp))}</div>`
      : `<div class="tiny muted">no certificate present</div>`) +
    anchorLine(authorCert?.iss) +
    (warrant ? "" : `<div class="tiny muted" style="margin-top:4px">posted directly by the author from their own browser</div>`)));

  // -- Posted by: only when an agent signed; the warrant is the author→agent link.
  if (warrant) {
    const agentEmail = warrant.agent || cert?.principal?.email || "?";
    const scopes = Array.isArray(warrant.scopes) ? warrant.scopes : [];
    parts.push(rSection("Posted by",
      `<div><strong>${esc(agentEmail)}</strong> <span class="tiny muted">(an agent, not the author)</span></div>` +
      (wireKey ? `<div class="tiny">agent signing key ${copyable(wireKey, 16, 6)}</div>` : "") +
      (cert ? `<div class="tiny muted">${vouchLine(cert, cert.principal?.email || agentEmail)}</div>` : "") +
      `<div style="margin-top:6px"><span class="side-h" style="display:inline">authorized by the author</span></div>
       <div class="tiny">${esc(warrant.iss || author)} signed a warrant with their own identity key allowing ${esc(agentEmail)} to post for them</div>
       <div class="tiny muted">valid until ${esc(rDate(warrant.exp))} · only at ${esc(warrant.aud || "?")}</div>` +
      (scopes.length ? `<div style="margin-top:4px">${scopes.map((s) => `<span class="scope">${esc(String(s))}</span>`).join("")}</div>` : "")));
  }

  // -- Every party's contribution to THIS object, one plain sentence each.
  const who = [];
  if (authorCert) {
    const iss = authorCert.iss || "?";
    const primary = iss === (author.split("@")[1] || "");
    who.push(`<strong>${esc(iss)}</strong> ${primary ? "(identity provider) certified" : "(fallback certifier) vouched for"} the author's identity`);
  }
  if (warrant) {
    if (cert?.iss) who.push(`<strong>${esc(cert.iss)}</strong> (identity provider) certified the posting agent ${esc(warrant.agent || "?")}`);
    who.push(`<strong>${esc(warrant.iss || author)}</strong> (the author) signed the warrant that authorizes the agent`);
    who.push(`<strong>mingo</strong> (the app) operates the agent and submitted this write`);
  } else {
    who.push(`<strong>${esc(author)}</strong> (the author) signed this post themselves`);
  }
  who.push(`the <strong>data layer</strong> recorded it in block ${esc(String(view.block ?? "?"))} and serves the inclusion proof`);
  parts.push(rSection("Who did what",
    who.map((w) => `<div class="tiny">· ${w}</div>`).join("")));

  // -- Record: what and where, plus the proof itself. Honesty note: the daemon
  // proves inclusion against the CURRENT head state root (sboq Block/
  // State-Root), not the block that first confirmed the object (view.block).
  const proofHref = `${CONFIG.daemon}/v1/object?path=${encodeURIComponent(item.path)}&id=${encodeURIComponent(item.id)}&proof=1`;
  const record =
    `<div class="mono tiny" style="word-break:break-all">${esc(item.path + item.id)}</div>` +
    `<div class="tiny muted">${esc(view.content_schema || "?")} · written ${esc(item.ts ? new Date(item.ts).toLocaleString() : rDate(null))}</div>` +
    (view.object_hash ? `<div class="tiny">object hash ${copyable(view.object_hash, 12, 6)}</div>` : "") +
    (proof["State-Root"]
      ? `<div class="tiny muted">inclusion proof computed against the current state root ${copyable(proof["State-Root"], 10, 6)} (block ${esc(proof["Block"] || "?")}) — <a href="${esc(proofHref)}" target="_blank" rel="noopener" class="rlink">Merkle proof ↗</a></div>`
      : `<div class="tiny muted">no inclusion proof available from this daemon</div>`);
  parts.push(rSection("Record", record));

  body.className = "";
  body.innerHTML = parts.join("");
  body.querySelectorAll("[data-copy]").forEach((n) => {
    n.onclick = async () => {
      try {
        await navigator.clipboard.writeText(n.getAttribute("data-copy"));
        toast("copied");
      } catch { toast("copy failed"); }
    };
  });
}

// The user's Profile (route/function still named "passport" internally; the
// user-facing label everywhere is "Profile"). Structure: identicon + name,
// Badges, Member of, Vouched by, and a Vouch button on others' profiles.
//
// PLANNED (bean mingo-chzb) — a Reddit-style profile. NOT built yet; the
// structure below is left ready for these to slot in without a rework:
//   · karma / contribution count (aggregate of upvotes on the subject's items)
//   · account age ("member since", from the earliest owned object)
//   · Posts / Comments tabs listing the subject's authored content
//   · follow / share / report buttons in the header action slot (#pp-vouch)
// Do NOT implement these here — leave the header + section scaffold intact.
async function viewPassport(subject) {
  const main = $("#main");
  subject = subject || session.email;
  if (!subject) { main.innerHTML = `<div class="card">Sign in to see your passport.</div>`; return; }
  const name = shortAuthor(subject);
  const canVouch = !!session.email && subject !== session.email;
  main.innerHTML = `<div class="pp-head avatar-lg">${identicon(subject, 46)}
    <div style="flex:1"><div class="h1">${esc(name)}</div></div>
    <div id="pp-vouch"></div></div>
    <div id="pp" class="muted">loading…</div>`;
  const atts = await getPassport(subject);
  const badges = atts.filter((a) => String(a.type || "").startsWith("badge:"));
  const memberships = atts.filter((a) => String(a.type || "").startsWith("membership:"));
  const vouches = atts.filter((a) => a.type === "vouch");
  const alreadyVouched = canVouch && vouches.some((v) => v.issuer === session.email);

  $("#pp").outerHTML = `<div id="pp">
    <div class="card pp-sec"><div class="h2">Badges</div>
      ${badges.length
        ? `<div class="pp-badges">${badges.map((a) => `<div class="pp-badge"><span class="b-name">${esc(prettySlug(a.type.slice(6)))}</span><span class="b-by">by ${esc(shortAuthor(a.issuer))}</span></div>`).join("")}</div>`
        : `<div class="muted">No badges yet.</div>`}</div>
    <div class="card pp-sec"><div class="h2">Member of</div>
      ${memberships.length
        ? `<div class="pp-pills">${memberships.map((a) => boardTag(a.type.slice(11))).join("")}</div>`
        : `<div class="muted">Not a member of any community yet.</div>`}</div>
    <div class="card pp-sec"><div class="h2">Vouched by</div>
      ${vouches.length
        ? `<div class="vouch-list">${vouches.map((a) => `<a class="byline-link vouch-item" href="#/passport/${encodeURIComponent(a.issuer)}">${identicon(a.issuer, 18)}${esc(shortAuthor(a.issuer))}</a>`).join("")}</div>`
        : `<div class="muted">No vouches yet.</div>`}</div></div>`;

  const vslot = $("#pp-vouch");
  if (vslot && canVouch) {
    vslot.innerHTML = alreadyVouched
      ? `<button class="primary" disabled>✓ Vouched</button>`
      : `<button class="primary" id="do-vouch">Vouch for ${esc(name)}</button>`;
    const btn = $("#do-vouch");
    if (btn) btn.onclick = async () => {
      if (!(await ensureCanWrite())) return;
      btn.disabled = true; btn.textContent = "Vouching…";
      try {
        await vouchFor(subject);
        toast("Vouched — confirming on-chain…");
        route(); // re-render; the daemon overlay serves the new vouch immediately
      } catch (e) {
        toast("vouch failed: " + e.message);
        btn.disabled = false; btn.textContent = "Vouch for " + name;
      }
    };
  }
}

// ---------------------------------------------------------------------------
// settings (route #/settings). Surfaces the mingo-poster status and lets the
// user turn server-side posting OFF (disablePoster) or ON (the existing
// openPosterEnableModal, the same recommended, mobile-safe consent flow the
// write-time prompt uses). Replaces the old standalone "let mingo post for me"
// auth-area link — writes still fall back to that modal via ensureCanWrite.
// ---------------------------------------------------------------------------
async function viewSettings() {
  const main = $("#main");
  if (!session.email) { main.innerHTML = `<div class="card">Sign in to view settings.</div>`; return; }
  main.innerHTML = `<div class="card view-header"><div class="vh-main"><div class="h1">Settings</div>
    <div class="muted vh-sub">Signed in as ${esc(session.email)}</div></div></div>
    <div id="settings-body" class="muted">loading…</div>`;
  await refreshPosterStatus();
  const render = () => {
    const on = poster.enabled;
    $("#settings-body").outerHTML = `<div id="settings-body">
      <div class="card">
        <div class="row-between">
          <div style="min-width:0">
            <div class="h2" style="margin:0">Posting on your behalf</div>
            <div class="muted tiny" style="margin-top:4px">mingo posts for you: <strong class="${on ? "confirmed" : ""}">${on ? "on" : "off"}</strong></div>
          </div>
          <button class="${on ? "" : "primary"}" id="poster-btn">${on ? "Turn off" : "Turn on"}</button>
        </div>
        <p class="muted tiny" style="margin-top:10px">When on, mingo signs your posts,
          comments and votes for you — no signing pop-up each time, and it works on
          mobile. ${on ? "To fully revoke, use Manage at browserid.me." : "You approve once on browserid.me."}</p>
      </div></div>`;
    $("#poster-btn").onclick = async () => {
      if (poster.enabled) {
        const btn = $("#poster-btn");
        btn.disabled = true; btn.textContent = "Turning off…";
        await disablePoster();
        toast("mingo will no longer post for you.");
        renderAuth();
        render();
      } else {
        if (await openPosterEnableModal()) { renderAuth(); render(); }
      }
    };
  };
  render();
}

// ---------------------------------------------------------------------------
// live updates (bean mingo-cu0q). The daemon has no change feed/SSE, so we POLL
// the current view's list on a single module-level interval. route() clears it
// on every navigation (so only the active view polls) and each view restarts it.
// The poll DIFFS-AND-APPENDS rather than replacing innerHTML, so it never clobbers
// a compose box the user is typing in or an open inline edit textarea. Dedup is
// by uri via the data-receipt attribute every rendered item carries, so it can't
// double-insert the optimistic row the local user just posted, and it coexists
// with the per-action confirm-poll loops in showCompose/viewThread.
// ---------------------------------------------------------------------------
let livePoll = null, livePollBusy = false;
function stopLivePoll() {
  if (livePoll) { clearInterval(livePoll); livePoll = null; }
}
function startLivePoll(fn) {
  stopLivePoll();
  livePoll = setInterval(async () => {
    if (livePollBusy) return; // don't overlap a slow poll with the next tick
    livePollBusy = true;
    try { await fn(); } catch {} finally { livePollBusy = false; }
  }, 4000);
}
// Refresh vote counts in place. Skips any target the local user just voted on
// (its button carries .voted) so the optimistic bump isn't flickered back down.
function liveApplyVotes(votes) {
  const voted = new Set();
  document.querySelectorAll("[data-vote].voted").forEach((b) =>
    voted.add(b.getAttribute("data-vote").split("|")[1]));
  document.querySelectorAll("[data-count]").forEach((span) => {
    const uri = span.getAttribute("data-count");
    if (voted.has(uri) || !votes.has(uri)) return;
    span.textContent = String(votes.get(uri) || 0);
  });
}
const shown = (container, uri) => !!container.querySelector(`[data-receipt="${CSS.escape(uri)}"]`);
// Reconcile the DOM against the fresh list: append rows/comments not already
// shown, and REMOVE rows whose object is no longer in head (deleted — here or in
// another session — or filtered by deletedUris). Removal is what makes a delete
// vanish: a deleted object leaves head, drops out of `items`, and its row is
// pulled here instead of lingering forever as a stale "pending…" card (mingo-3go6).
// Clears a placeholder ("No posts yet.") the first time a real item lands, and
// re-wires only after a change.
function liveAppend(container, items, render) {
  if (!container) return;
  const wanted = new Set(items.map((it) => it.uri));
  let changed = false;
  container.querySelectorAll("[data-receipt]").forEach((mark) => {
    const uri = mark.getAttribute("data-receipt");
    if (wanted.has(uri)) return;
    // data-receipt sits on an action button inside the row; remove the row —
    // the direct child of the container — not just the button.
    let row = mark;
    while (row.parentElement && row.parentElement !== container) row = row.parentElement;
    if (row.parentElement === container) { row.remove(); changed = true; }
  });
  for (const it of items) {
    if (shown(container, it.uri)) continue;
    if (!container.querySelector("[data-receipt]")) container.innerHTML = ""; // drop placeholder
    container.appendChild(el(render(it)));
    changed = true;
  }
  if (changed) { wireVoteButtons(); wireReceiptButtons(); wireEditButtons(); wireCardMenus(); wireDeleteButtons(); }
}
async function pollFeed(kind, commId) {
  const votes = await getVoteCounts();
  liveApplyVotes(votes);
  const container = document.getElementById(kind === "hub" ? "feed" : "posts");
  if (!container) return;
  let rows = [];
  if (kind === "hub") {
    const comms = window.__comms || (await getCommunities());
    for (const c of comms) {
      const { posts } = await getSpaceItems(c.id, CONFIG.space);
      for (const p of posts) rows.push({ ...p, comm: c.id });
    }
  } else {
    const { posts } = await getSpaceItems(commId, CONFIG.space);
    rows = posts.map((p) => ({ ...p, comm: commId }));
  }
  liveAppend(container, rows, (p) => feedRow(p, votes, kind === "hub"));
}
async function pollThread(commId, post) {
  const [{ comments }, votes] = await Promise.all([getSpaceItems(commId, CONFIG.space), getVoteCounts()]);
  liveApplyVotes(votes);
  const container = document.getElementById("comments");
  if (!container) return;
  const kids = comments.filter((c) => c.parent === post.uri).map((c) => ({ ...c, comm: post.comm }));
  liveAppend(container, kids, (c) => commentBox(c, votes));
}

// ---------------------------------------------------------------------------
// router
// ---------------------------------------------------------------------------
async function route() {
  stopLivePoll(); // leaving the current view — kill its poller before rendering
  _modBoards = null; // re-resolve moderator status per navigation (cache is per-render)
  const h = location.hash || "#/";
  const parts = h.slice(2).split("/"); // after "#/"
  try {
    if (h === "#/" || h === "") return void (await viewHub());
    if (parts[0] === "c" && parts[2] === "p") return void (await viewThread(parts[1], parts[3]));
    if (parts[0] === "c" && parts[2] === "mod") return void (await viewModerate(parts[1]));
    if (parts[0] === "c") return void (await viewCommunity(parts[1]));
    if (parts[0] === "settings") return void (await viewSettings());
    if (parts[0] === "passport") return void (await viewPassport(decodeURIComponent(parts[1] || "")));
    await viewHub();
  } catch (e) {
    $("#main").innerHTML = `<div class="card">Error: ${esc(e.message)}</div>`;
  }
}

document.querySelector(".brand").onclick = () => (location.hash = "#/");
window.addEventListener("hashchange", route);

// Theme toggle: reflect the active theme on the button and flip on click.
applyTheme(currentTheme());
$("#theme-toggle").onclick = toggleTheme;
// If the user hasn't made a manual choice, follow live OS changes.
if (window.matchMedia) {
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", (e) => {
    if (!localStorage.getItem("mingo_theme")) applyTheme(e.matches ? "dark" : "light");
  });
}

// Global dismissal for popup menus (user dropdown + post-card kebabs): any click
// outside an open menu, or Escape, closes them.
document.addEventListener("click", (e) => {
  if (!e.target.closest(".menu-pop, .kebab, .user-btn")) closeAllMenus();
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeAllMenus(); });

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
// A bfcache restore brings the page back exactly as it was — textarea content
// included, so drop the stash (it would go stale) — but any in-modal poll loop
// is long dead, so check whether the consent hop we left for was approved.
window.addEventListener("pageshow", (e) => {
  if (!e.persisted) return;
  sessionStorage.removeItem("mingo_draft");
  posterModal?.freeze(); // don't let a stray Continue tap bounce back to browserid
  pickupPoster();
});

// Device-authorize resume: the authorize page bounces here with
// ?return=/device-authorize when it finds no live IdP session (its pending
// params survive in sessionStorage). If the cookie is actually live — our
// localStorage "signed in" state can outlive it, and vice versa — go straight
// back; otherwise prompt one real sign-in (a click, so the dialog popup isn't
// blocker-eaten), which establishes the IdP session via the EXTERNAL identity
// (no recursion into mingo's own IdP lane), then return.
async function maybeResumeAuthorize() {
  const ret = new URLSearchParams(location.search).get("return");
  if (!ret || !/^\/[^/]/.test(ret)) return false;
  try {
    const who = await idpGet("/whoami");
    if (who && who.authenticated && who.handle) { location.replace(ret); return true; }
  } catch {}
  return new Promise((resolve) => {
    const who = session.external;
    const overlay = el(`<div class="modal-overlay"><div class="modal card">
      <div class="h2">Sign in to continue</div>
      <p class="muted" style="margin-top:8px">Your mingo session expired, so
        authorizing needs a quick re-login${who ? ` as <strong>${esc(who)}</strong>` : ""}.
        You'll be sent right back to finish.</p>
      <div class="row-between" style="margin-top:12px">
        <button id="ra-cancel">Cancel</button>
        <button class="primary" id="ra-go">${who ? "Sign back in" : "Sign in"}</button>
      </div></div></div>`);
    document.body.appendChild(overlay);
    overlay.querySelector("#ra-cancel").onclick = () => { overlay.remove(); resolve(false); };
    overlay.querySelector("#ra-go").onclick = async () => {
      try {
        await signIn({ directed: true });
        const who2 = await idpGet("/whoami").catch(() => null);
        if (!who2 || !who2.authenticated) return; // cancelled/failed — stay here
        overlay.remove();
        location.replace(ret);
        resolve(true);
      } catch (e) {
        toast("Sign-in failed: " + (e.message || e));
      }
    };
  });
}

(async function init() {
  if (await maybeResumeAuthorize()) return; // navigating back to the authorize page
  await renderChrome();
  await route();
  restoreDraft(); // after route(): the view the draft belongs to must exist
  pickupPoster(); // catch an approval made during a same-tab consent hop
})();
