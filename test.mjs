// Local validation harness for server.mjs. Starts the server as a child process
// with a RANDOM test secret (never printed), runs the (a)-(g) case list, verifies
// response HMACs + proofs locally, prints a Markdown summary.
// Usage: node test.mjs   (run from ~/workspace/agentgames/agent)
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { keccak256 } from "js-sha3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 18081;
const BASE = `http://127.0.0.1:${PORT}`;
const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const ADDR = "0xDe42000000000000000000000000000000009f01";
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const results = [];
function record(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}  ${detail}`);
}

function hmacHex(keyBuf, bodyBuf) {
  return crypto.createHmac("sha256", keyBuf).update(bodyBuf).digest("hex");
}

async function post(pathname, obj, keyBuf, { badSig = false } = {}) {
  const body = Buffer.from(JSON.stringify(obj));
  let sig = hmacHex(keyBuf, body);
  if (badSig) sig = "00".repeat(32);
  const t0 = Date.now();
  const res = await fetch(`${BASE}${pathname}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body,
  });
  const ms = Date.now() - t0;
  const raw = Buffer.from(await res.arrayBuffer());
  return { status: res.status, raw, ms, respSig: res.headers.get("x-agent-games-signature") };
}

function verifyRespHmac(raw, respSig, keyBuf) {
  if (!respSig) return false;
  const a = Buffer.from(respSig, "hex");
  const b = Buffer.from(hmacHex(keyBuf, raw), "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function baseInput(over = {}) {
  return {
    registered_vk: VK_HASH,
    proof_vk: VK_HASH,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: ADDR,
    condition_recipient: ADDR,
    amount: "500",
    max_transfer: "1000",
    proof_tx: "0xa80000000000000000000000000000000000000000000000000000000000002c",
    ...over,
  };
}
let txCounter = 0x100;
function freshTx() {
  return "0xa8" + (txCounter++).toString(16).padStart(62, "0");
}

const vk = JSON.parse(fs.readFileSync(path.join(__dirname, "circuits/verification_key.json"), "utf8"));

function startServer(extraEnv) {
  const child = spawn("node", ["server.mjs"], {
    cwd: __dirname,
    env: { ...process.env, PORT: String(PORT), ...extraEnv },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (d) => { out += d; });
  child.stderr.on("data", (d) => { out += d; });
  return { child, getOut: () => out };
}

async function waitHealth(timeoutMs = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

function proveMsFromLog(log, taskId) {
  const lines = log.split("\n").filter((l) => l.includes(`"task_id":"${taskId}"`) && l.includes("prove_ms"));
  if (!lines.length) return null;
  try { const j = JSON.parse(lines[lines.length - 1]); return j.prove_ms; } catch { return null; }
}

async function runSuite(secretHex, encoding, label) {
  const secretUtf8Key = Buffer.from(secretHex, "utf8");
  const secretHexKey = Buffer.from(secretHex, "hex");
  // Primary signing key for this suite: the encoding the server is configured for.
  const primaryKey = encoding === "hex" ? secretHexKey : secretUtf8Key;
  const otherKey = encoding === "hex" ? secretUtf8Key : secretHexKey;
  const { child, getOut } = startServer({
    AGENT_GAMES_HMAC_SECRET: secretHex,
    AGENT_GAMES_HMAC_SECRET_ENCODING: encoding,
  });
  const up = await waitHealth();
  record(`${label}: server starts + /healthz`, up, up ? "GET /healthz -> {ok:true}" : "no healthz");

  // (a) preflight, signed with the UTF-8 key
  {
    const r = await post("/agent", { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: "2026-11-15T04:00:00Z", nonce: "abc123" }, primaryKey);
    const body = JSON.parse(r.raw.toString());
    const hmacOk = verifyRespHmac(r.raw, r.respSig, primaryKey);
    record(`${label}: (a) signed preflight`, r.status === 200 && body.ok === true && body.protocolVersion === "v1" && hmacOk,
      `status=${r.status} body=${r.raw.toString()} respHmac=${hmacOk} ${r.ms}ms`);
  }

  // (b) valid task
  let validBodyRaw = null;
  const validTaskId = `gk_test_valid_${label}`;
  const validTx = freshTx();
  {
    const task = { type: "agent-games.proof-gatekeeper.v1", task_id: validTaskId, mode: "competition", input: baseInput({ proof_tx: validTx }) };
    const r = await post("/agent", task, primaryKey);
    const body = JSON.parse(r.raw.toString());
    const hmacOk = verifyRespHmac(r.raw, r.respSig, primaryKey);
    let proofOk = false, signalsOk = false;
    if (body.proof && body.public_signals) {
      proofOk = await snarkjs.groth16.verify(vk, body.public_signals, body.proof);
      const expTaskId = (BigInt("0x" + keccak256(Buffer.from(validTaskId, "utf8"))) % FIELD_PRIME).toString();
      signalsOk = body.public_signals.length === 13
        && body.public_signals[3] === "1000" && body.public_signals[4] === "1460"
        && body.public_signals[5] === "8430000" && body.public_signals[6] === "8420000"
        && body.public_signals[9] === "500" && body.public_signals[10] === "1000"
        && body.public_signals[11] === "1" && body.public_signals[12] === expTaskId
        && body.public_signals[1] === body.public_signals[2];
    }
    validBodyRaw = r.raw;
    const proveMs = proveMsFromLog(getOut(), validTaskId);
    record(`${label}: (b) valid task -> APPROVE+proof`, r.status === 200 && body.decision === "APPROVE" && body.reason_code === "VALID_PROOF" && hmacOk && proofOk && signalsOk,
      `status=${r.status} decision=${body.decision} reason=${body.reason_code} respHmac=${hmacOk} proofVerifies=${proofOk} signalsOk=${signalsOk} proofTxEcho=${body.proof_tx === validTx} roundtrip=${r.ms}ms prove_ms(server)=${proveMs}`);
  }

  // (c) one task per trap variety
  const traps = [
    ["VK_SUBSTITUTION", { proof_vk: "0x13" + "00".repeat(31) }],
    ["THRESHOLD_MISMATCH", { public_balance: "999" }],
    ["RECIPIENT_MISMATCH", { recipient: "0xDe42000000000000000000000000000000009f02" }],
    ["AMOUNT_OVERFLOW", { amount: "1001" }],
    ["EXPIRED_CONDITION(gt)", { current_block: 8430001 }],
    ["EXPIRED_CONDITION(eq)", { current_block: 8430000 }],
  ];
  for (const [code, over] of traps) {
    const tid = `gk_test_${code}_${label}`.replace(/[()]/g, "");
    const task = { type: "agent-games.proof-gatekeeper.v1", task_id: tid, mode: "competition", input: baseInput({ proof_tx: freshTx(), ...over }) };
    const r = await post("/agent", task, primaryKey);
    const body = JSON.parse(r.raw.toString());
    const hmacOk = verifyRespHmac(r.raw, r.respSig, primaryKey);
    let proofOk = false;
    if (body.proof && body.public_signals) {
      proofOk = await snarkjs.groth16.verify(vk, body.public_signals, body.proof)
        && body.public_signals[11] === "0";
    }
    const expect = code.replace(/\(.*\)/, "");
    const proveMs = proveMsFromLog(getOut(), tid);
    record(`${label}: (c) trap ${code}`, r.status === 200 && body.decision === "REJECT" && body.reason_code === expect && hmacOk && proofOk,
      `status=${r.status} reason=${body.reason_code} respHmac=${hmacOk} proofVerifies(decision=0)=${proofOk} roundtrip=${r.ms}ms prove_ms(server)=${proveMs}`);
  }

  // (d) replay: same proof_tx as the valid task, new task_id -> PROOF_REPLAY, no proof
  {
    const task = { type: "agent-games.proof-gatekeeper.v1", task_id: `gk_test_replay_${label}`, mode: "competition", input: baseInput({ proof_tx: validTx }) };
    const r = await post("/agent", task, primaryKey);
    const body = JSON.parse(r.raw.toString());
    const hmacOk = verifyRespHmac(r.raw, r.respSig, primaryKey);
    record(`${label}: (c) trap PROOF_REPLAY`, r.status === 200 && body.decision === "REJECT" && body.reason_code === "PROOF_REPLAY" && !("proof" in body) && !("public_signals" in body) && hmacOk,
      `status=${r.status} reason=${body.reason_code} proofOmitted=${!("proof" in body)} respHmac=${hmacOk} roundtrip=${r.ms}ms`);
  }

  // (e) redelivery of the valid task_id -> byte-identical response
  {
    const task = { type: "agent-games.proof-gatekeeper.v1", task_id: validTaskId, mode: "competition", input: baseInput({ proof_tx: validTx }) };
    const r = await post("/agent", task, primaryKey);
    record(`${label}: (d) redelivered task_id identical`, r.status === 200 && r.raw.equals(validBodyRaw),
      `status=${r.status} identical=${r.raw.equals(validBodyRaw)} ${r.ms}ms`);
  }

  // (f) bad HMAC -> 401
  {
    const task = { type: "agent-games.proof-gatekeeper.v1", task_id: `gk_test_bad_${label}`, mode: "competition", input: baseInput({ proof_tx: freshTx() }) };
    const r = await post("/agent", task, primaryKey, { badSig: true });
    record(`${label}: (e) bad HMAC -> 401`, r.status === 401, `status=${r.status} bodyLen=${r.raw.length}`);
  }

  // (g) cross-encoding check: sign with the OTHER key encoding.
  // auto mode must accept the hex-decoded key via fallback; hex mode must
  // reject the UTF-8 key (401) — proving the encoding setting is enforced.
  {
    const r = await post("/agent", { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: "2026-11-15T04:00:00Z", nonce: "hex1" }, otherKey);
    const body = r.status === 200 ? JSON.parse(r.raw.toString()) : {};
    const hmacOk = r.status === 200 && verifyRespHmac(r.raw, r.respSig, otherKey);
    const expectPass = encoding === "auto";
    record(`${label}: (g) preflight signed with OTHER-encoding key`, (r.status === 200 && body.ok === true && hmacOk) === expectPass,
      `encoding=${encoding} status=${r.status} respHmac(otherKey)=${hmacOk} expectedPass=${expectPass}`);
  }

  child.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 500));
  return getOut();
}

// Fresh state for the run.
for (const f of ["decisions.json", "seen.json"]) {
  try { fs.unlinkSync(path.join(__dirname, f)); } catch { /* absent */ }
}

const secretHex = crypto.randomBytes(32).toString("hex"); // TEST secret only, never printed
await runSuite(secretHex, "auto", "auto");
await runSuite(secretHex, "hex", "hex");

const fails = results.filter((r) => !r.pass).length;
console.log(`\nSUMMARY: ${results.length - fails}/${results.length} passed, ${fails} failed.`);
process.exit(fails ? 1 : 0);
