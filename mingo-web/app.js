// Mingo — SBO reference client (Phase 7.6).
//
// Reads confirmed state from the sbo-daemon /v1 API. Writes are built in-browser
// with sbo-wasm and signed by the browserid agent via the first-party signer
// popup (Phase 7.4). Config is overridable via ?daemon= / ?broker= query params
// or window.MINGO_CONFIG, so the same file works locally and when hosted.

const qs = new URLSearchParams(location.search);
const CONFIG = Object.assign(
  {
    daemon: "http://127.0.0.1:7890",
    broker: "https://browserid.me",
    domain: "mingo.place",
    space: "general",
  },
  window.MINGO_CONFIG || {},
  qs.get("daemon") ? { daemon: qs.get("daemon") } : {},
  qs.get("broker") ? { broker: qs.get("broker") } : {}
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
async function submitWire(bytes) {
  const r = await fetch(`${CONFIG.daemon}/v1/submit`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: bytes,
  });
  if (!r.ok) throw new Error(`submit ${r.status} ${await r.text()}`);
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
  };
}
function shortAuthor(ref) {
  if (!ref) return "unknown";
  if (ref.startsWith("ed25519:")) return ref.slice(8, 16) + "…";
  return ref; // email or name
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

function signIn() {
  // T1 federated flow: the dialog authenticates an external email (passwordless),
  // provisions a <handle>@mingo.place identity, and returns it.
  const url = `${CONFIG.broker}/dialog/dialog.html?origin=${encodeURIComponent(location.origin)}&sbo_sign=1&flow=mingo`;
  const popup = window.open(url, "mingo_login", "width=440,height=600");
  const onMsg = (e) => {
    if (e.origin !== CONFIG.broker || !e.data || e.data.assertion === undefined) return;
    window.removeEventListener("message", onMsg);
    const email = e.data.email; // <handle>@mingo.place
    if (!email) { toast("Sign-in did not return an identity"); return; }
    if (e.data.sbo_sign_granted === false) toast("Signed in, but signing was not granted");
    session.email = email;
    try { popup && popup.close(); } catch {}
    renderAuth();
    toast(`Signed in as ${email}`);
  };
  window.addEventListener("message", onMsg);
}
function signOut() { session.email = null; renderAuth(); toast("Signed out"); }

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

// Build → sign → assemble → submit a content write owned by the session email.
async function writeContent({ path, id, schema, payload, hlc, prev }) {
  if (!session.email) { signIn(); return; }
  const wasm = await sbo();
  const spec = {
    action: "", path, id,
    public_key: "ed25519:" + "00".repeat(32), // overridden by the signer
    content_schema: schema,
    owner: session.email,
    payload: Array.from(payload),
    hlc: hlc || `${Date.now()}.0`,
    prev,
  };
  const res = await signEnvelope(session.email, spec);
  const bound = { ...spec, public_key: res.pubkey, auth_cert: res.cert };
  const wire = wasm.assembleWire(bound, res.signature);
  return submitWire(wire);
}

async function composePost(commId, space, body) {
  const wasm = await sbo();
  const payload = wasm.payloadPost(body, undefined, BigInt(Date.now()));
  const id = "p-" + Date.now().toString(36);
  return writeContent({
    path: `/communities/${commId}/spaces/${space}/`, id, schema: "post.v1", payload,
  });
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
let toastTimer;
function toast(msg) {
  const t = $("#toast"); t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 3000);
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

function feedRow(p, votes) {
  return `<div class="card feed-row">
    <div class="votes"><button class="link up" data-vote="${esc(p.comm)}|${esc(p.uri)}">▲</button><span class="n">${votes.get(p.uri) || 0}</span></div>
    <div style="flex:1">
      <div class="post-meta">r/${esc(p.comm)} · ${esc(p.author)} · <span class="confirmed">✅ confirmed</span></div>
      <div class="post-title"><a href="#/c/${esc(p.comm)}/p/${esc(p.id)}">${esc((p.body || "").slice(0, 120))}</a></div>
    </div></div>`;
}

async function viewCommunity(commId) {
  const main = $("#main");
  const comms = window.__comms || (await getCommunities());
  const c = comms.find((x) => x.id === commId);
  if (!c) { main.innerHTML = `<div class="card">Unknown community.</div>`; return; }
  main.innerHTML = `
    <div class="row-between"><div class="h1">r/${esc(c.id)} ${c.open ? "✓" : ""}</div>
      <button class="primary" id="newpost">+ New post</button></div>
    <div class="card muted">${esc(c.description || "")} · issuer ${esc(c.issuer)}</div>
    <div id="compose"></div>
    <div id="posts" class="muted">loading…</div>`;
  $("#newpost").onclick = () => showCompose(c.id);
  const [{ posts }, votes] = await Promise.all([getSpaceItems(c.id, CONFIG.space), getVoteCounts()]);
  posts.sort((a, b) => (votes.get(b.uri) || 0) - (votes.get(a.uri) || 0) || (b.hlc || "").localeCompare(a.hlc || ""));
  $("#posts").outerHTML = `<div id="posts">${posts.length ? posts.map((p) => feedRow({ ...p, comm: c.id }, votes)).join("") : `<div class="card muted">No posts yet.</div>`}</div>`;
  wireVoteButtons();
}

function showCompose(commId) {
  const box = $("#compose");
  box.innerHTML = `<div class="card"><div class="h2">New post in r/${esc(commId)}/${esc(CONFIG.space)}</div>
    <textarea id="post-body" placeholder="Share something…"></textarea>
    <div class="row-between" style="margin-top:8px"><span class="muted tiny">posts to the DA layer</span>
    <span><button id="post-cancel">Cancel</button> <button class="primary" id="post-submit">Post</button></span></div></div>`;
  $("#post-cancel").onclick = () => (box.innerHTML = "");
  $("#post-submit").onclick = async () => {
    const body = $("#post-body").value.trim();
    if (!body) return;
    $("#post-submit").disabled = true;
    try {
      await composePost(commId, CONFIG.space, body);
      toast("posting… it will appear once the block lands");
      box.innerHTML = "";
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
    <a class="muted" href="#/c/${esc(commId)}">← r/${esc(commId)}</a>
    <div class="card"><div class="post-meta">${esc(post.author)} · <span class="confirmed">✅</span></div>
      <div class="post-body">${esc(post.body)}</div>
      <div style="margin-top:8px"><button class="link up" data-vote="${esc(commId)}|${esc(post.uri)}">▲ upvote</button> · ${votes.get(post.uri) || 0}</div>
    </div>
    <div class="h2">Comments</div>
    <div class="card"><textarea id="c-body" placeholder="Add a comment…"></textarea>
      <div style="text-align:right;margin-top:8px"><button class="primary" id="c-submit">Comment</button></div></div>
    <div id="comments">${kids.length ? kids.map((c) => commentBox(c, votes)).join("") : `<div class="muted">No comments yet.</div>`}</div>`;
  $("#c-submit").onclick = async () => {
    const body = $("#c-body").value.trim(); if (!body) return;
    $("#c-submit").disabled = true;
    try { await addComment(commId, CONFIG.space, post.uri, body); toast("commenting… appears once the block lands"); $("#c-body").value = ""; }
    catch (e) { toast("comment failed: " + e.message); } finally { $("#c-submit").disabled = false; }
  };
  wireVoteButtons();
}
function commentBox(c, votes) {
  return `<div class="comment"><div class="post-meta">${esc(c.author)} · ${votes.get(c.uri) || 0} ▲</div><div>${esc(c.body)}</div></div>`;
}

function wireVoteButtons() {
  document.querySelectorAll("[data-vote]").forEach((b) => {
    b.onclick = async () => {
      const [comm, uri] = b.getAttribute("data-vote").split("|");
      try { await upvote(comm, CONFIG.space, uri); toast("vote submitted"); }
      catch (e) { toast("vote failed: " + e.message); }
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
