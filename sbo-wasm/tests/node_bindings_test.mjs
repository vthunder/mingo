// Node smoke test for the sbo-wasm JS bindings (Phase 7.4).
//
// Builds a nodejs-target package into a temp dir and exercises the JS-facing
// API the browserid-ng agent depends on: payload builders, signingBytes (the
// bytes the agent signs), assembleWire (fold a detached signature), objectHash.
// This verifies the wasm <-> JS marshalling, not signature crypto (the native
// `cargo test -p sbo-wasm` proves signing-byte parity + verification).
//
// Run:  node tests/node_bindings_test.mjs
import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = mkdtempSync(join(tmpdir(), "sbo-wasm-node-"));

execFileSync(join(here, "..", "build-web.sh"), ["nodejs", out], { stdio: "inherit" });

const sbo = await import(join(out, "sbo_wasm.js"));

function assert(cond, msg) {
  if (!cond) throw new Error("FAIL: " + msg);
}

// payload builder → JSON bytes
const payload = sbo.payloadPost("hello from node", undefined, undefined);
assert(JSON.parse(new TextDecoder().decode(payload)).body === "hello from node", "payloadPost body");

const spec = {
  action: "",
  path: "/communities/cooks/spaces/general/",
  id: "p1",
  public_key: "ed25519:" + "ab".repeat(32),
  content_schema: "post.v1",
  owner: "alice@mingo.place",
  payload: Array.from(payload),
  hlc: "1703001234567.0",
};

const signing = new TextDecoder().decode(sbo.signingBytes(spec));
assert(signing.startsWith("SBO-Version:"), "signing bytes start with SBO-Version:");
assert(!signing.includes("Signature:"), "signing content excludes Signature");

const wire = sbo.assembleWire(spec, "cd".repeat(64));
assert(new TextDecoder().decode(wire).includes("Signature:"), "assembled wire includes Signature");

assert(sbo.objectHash(wire).length === 32, "objectHash is 32 bytes");

// owner/public-key are caller-controlled fields the agent overrides + checks;
// a malformed key must surface as an error, not a panic.
let threw = false;
try {
  sbo.signingBytes({ ...spec, public_key: "not-a-key" });
} catch {
  threw = true;
}
assert(threw, "bad public key throws");

console.log("sbo-wasm JS bindings: ALL TESTS PASSED");
