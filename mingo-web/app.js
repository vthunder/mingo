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

// Open the broker dialog and resolve with its response ({assertion, email?,
// sbo_sign_granted?}). When `provisionEmail` is set, the dialog skips its chooser
// and provisions/sign-in that exact identity (silent if a session exists at its IdP).
function brokerDialog({ sboSign = false, provisionEmail = null } = {}) {
  return new Promise((resolve) => {
    let url = `${CONFIG.broker}/dialog/dialog.html?origin=${encodeURIComponent(location.origin)}`;
    if (sboSign) url += "&sbo_sign=1";
    if (provisionEmail) url += `&provision_email=${encodeURIComponent(provisionEmail)}`;
    const popup = window.open(url, "mingo_login", "width=440,height=600");
    let done = false;
    const onMsg = (e) => {
      if (e.origin !== CONFIG.broker || !e.data || e.data.assertion === undefined) return;
      done = true;
      window.removeEventListener("message", onMsg);
      try { popup && popup.close(); } catch {}
      resolve(e.data);
    };
    window.addEventListener("message", onMsg);
    // If the user closes the popup without finishing, resolve null.
    const poll = setInterval(() => {
      if (done) return clearInterval(poll);
      if (popup && popup.closed) { clearInterval(poll); window.removeEventListener("message", onMsg); resolve(null); }
    }, 500);
  });
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
    const ext = await brokerDialog({ sboSign: false });
    if (!ext || !ext.assertion) return; // cancelled
    const sess = await idpPost("/session/from-assertion", { assertion: ext.assertion });

    let handle = sess.handle;
    if (!handle) {
      handle = await promptHandle();
      if (!handle) return; // cancelled registration
      const claim = await idpPost("/claim_handle", { handle });
      handle = claim.email.split("@")[0];
    }
    const email = `${handle}@${CONFIG.domain}`;

    const prov = await brokerDialog({ sboSign: true, provisionEmail: email });
    if (!prov || !prov.assertion) { toast("Could not provision your @mingo.place identity"); return; }
    if (prov.sbo_sign_granted === false) toast("Signed in, but signing was not granted");

    session.email = prov.email || email;
    renderAuth();
    route(); // re-render the current view (e.g. flip "Sign in to post" → Join/New post)
    toast(`Signed in as ${session.email}`);
  } catch (e) {
    toast("Sign-in failed: " + e.message);
  }
}
function signOut() { session.email = null; renderAuth(); route(); toast("Signed out"); }

// In-page handle picker (a Mingo product decision — never inside the broker dialog).
function promptHandle() {
  return new Promise((resolve) => {
    const sanitize = (v) => v.toLowerCase().replace(/[^a-z0-9._-]/g, "");
    const overlay = el(`<div class="modal-overlay">
      <div class="modal card">
        <div class="h2">Choose your Mingo handle</div>
        <p class="muted tiny">This is your public identity here: <strong><span id="h-prev">handle</span>@${esc(CONFIG.domain)}</strong>. Your email stays private.</p>
        <input type="text" id="h-input" placeholder="handle" autocapitalize="none" autocomplete="off" spellcheck="false">
        <div id="h-error" class="error tiny"></div>
        <div class="row-between" style="margin-top:10px">
          <button id="h-cancel">Cancel</button>
          <button class="primary" id="h-ok">Create my identity</button>
        </div>
      </div></div>`);
    document.body.appendChild(overlay);
    const input = overlay.querySelector("#h-input");
    const prev = overlay.querySelector("#h-prev");
    input.focus();
    input.addEventListener("input", () => {
      input.value = sanitize(input.value);
      prev.textContent = input.value || "handle";
    });
    const close = (val) => { overlay.remove(); resolve(val); };
    overlay.querySelector("#h-cancel").onclick = () => close(null);
    overlay.querySelector("#h-ok").onclick = () => {
      const v = sanitize(input.value.trim());
      if (!v) { overlay.querySelector("#h-error").textContent = "Pick a handle"; return; }
      close(v);
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

// Build → sign → assemble → submit a write. Email-rooted by default (Owner =
// session email); pass `keyRooted: true` for self-authorizing writes like the
// /sys/dnssec refresh, which omit Owner so the daemon's L2 gate passes by
// signing-key match without needing attribution.
async function writeContent({ path, id, schema, payload, hlc, prev, owner, contentType, keyRooted }) {
  if (!session.email) { signIn(); return; }
  const wasm = await sbo();
  // For email-rooted writes, make sure this domain's on-chain DNSSEC proof will
  // still be valid at inclusion time — refresh it first if not, so attribution
  // succeeds. Key-rooted writes need no attribution, so they skip this.
  if (!keyRooted) {
    const domain = (owner || session.email).split("@")[1];
    if (domain) await ensureDnssecFresh(domain);
  }
  const spec = {
    action: "", path, id,
    public_key: "ed25519:" + "00".repeat(32), // overridden by the signer
    content_schema: schema,
    payload: Array.from(payload),
    hlc: hlc || `${Date.now()}.0`,
    prev,
  };
  if (!keyRooted) spec.owner = owner || session.email;
  if (contentType) spec.content_type = contentType;
  const res = await signEnvelope(session.email, spec);
  const bound = { ...spec, public_key: res.pubkey, auth_cert: res.cert };
  const wire = wasm.assembleWire(bound, res.signature);
  return submitWire(wire);
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
(async function init() {
  await renderChrome();
  await route();
})();
