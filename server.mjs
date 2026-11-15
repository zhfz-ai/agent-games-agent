// zkVerify Agent Games — Proof Gatekeeper agent server.
// Plain node:http, no framework. Listens on PORT (default 18080), POST /agent.
//
// Protocol: see ~/workspace/agentgames/agent-spec.md and README.md in this dir.
//
// SECURITY NOTES
// - The HMAC secret comes ONLY from env AGENT_GAMES_HMAC_SECRET. Never logged.
// - HMAC is verified over the RAW request body BEFORE any JSON parsing.
// - Fail closed: any error / uncertainty -> REJECT, never APPROVE by default.
// - On-chain verification of the SUBMITTED payment proof via zkVerify/Kurier is NOT
//   done here: there is no Kurier API key, and no public lookup call for a proof
//   by proof_tx exists. The task fields carry the checkable claims; the trap
//   checks below operate on those fields. Do NOT call Kurier without a key.
//
// CIRCUIT (gatekeeper, Groth16/BN128, Circom 2.x) — EMPIRICALLY REVERSED, see README:
//   nPublic = 13, nVars = 647. Template: GatekeeperEvaluation.
//   Inputs (13 total): 12 public + 1 private (salt).
//     public inputs: registeredVkHash, proofVkHash, minimum, publicBalance,
//                    expiryBlock, currentBlock, recipient, conditionRecipient,
//                    amount, maxTransfer, decision, taskId
//     private input: salt
//   Public signals (13), in order:
//     [0]  Poseidon(salt, taskId)            <- circuit-computed binding commitment
//     [1]  registeredVkHash (mod p)   [2]  proofVkHash (mod p)
//     [3]  minimum  [4] publicBalance [5] expiryBlock  [6] currentBlock
//     [7]  recipient  [8] conditionRecipient
//     [9]  amount  [10] maxTransfer  [11] decision (1=APPROVE, 0=REJECT)
//     [12] taskId
//   The circuit asserts decision == (vkMatch AND balance>=minimum AND
//   recipientMatch AND amount<=maxTransfer AND currentBlock<expiryBlock).
//   Consequences, all verified by experiment (see experiment.mjs / TESTS.md):
//   - decision=1 is provable ONLY when every check passes.
//   - decision=0 is provable ONLY when at least one check fails.
//     A REJECT of a fully-valid task is UNPROVABLE (the circuit is the referee).
//   - Expiry is STRICT: currentBlock == expiryBlock FAILS (decision must be 0).
//     This contradicts the spec text ("current_block <= expiry_block"); the
//     circuit wins, so equality is treated as EXPIRED_CONDITION here.
//   - PROOF_REPLAY tasks (all field checks pass, proof_tx already seen) have NO
//     provable proof: decision=0 is unprovable because all checks pass. The
//     spec agrees ("PROOF_REUSED tasks have no proof to submit").
//   - taskId and salt are otherwise unconstrained (pure binding via Poseidon).

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { keccak256 } from "js-sha3";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT = Number(process.env.PORT || 18080);
const WASM_PATH = path.join(__dirname, "circuits", "gatekeeper.wasm");
const ZKEY_PATH = path.join(__dirname, "circuits", "gatekeeper_final.zkey");
const VK_PATH = path.join(__dirname, "circuits", "verification_key.json");
const DECISIONS_PATH = path.join(__dirname, "decisions.json");
const SEEN_PATH = path.join(__dirname, "seen.json");
const MAX_BODY_BYTES = 1_000_000;

// BN128 scalar field prime (snarkjs reduces every witness input mod p).
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Gatekeeper vkHash, registered on zkVerify mainnet (GET /api/circuit-info).
const GATEKEEPER_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

// ---------------------------------------------------------------------------
// HMAC secret handling
// ---------------------------------------------------------------------------
// AGENT_GAMES_HMAC_SECRET_ENCODING: utf8 | hex | auto (default auto).
// auto: try the secret as a UTF-8 string first; if verification fails AND the
// secret is 64 hex chars, retry with hex-decoded bytes. The key that verifies
// a request is the key used to sign that request's response.
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET;
if (!SECRET) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET is not set. Refusing to start.");
  process.exit(1);
}
const SECRET_ENCODING = (process.env.AGENT_GAMES_HMAC_SECRET_ENCODING || "auto").toLowerCase();
if (!["utf8", "hex", "auto"].includes(SECRET_ENCODING)) {
  console.error(`FATAL: bad AGENT_GAMES_HMAC_SECRET_ENCODING=${SECRET_ENCODING} (want utf8|hex|auto).`);
  process.exit(1);
}
const IS_64_HEX = /^[0-9a-fA-F]{64}$/.test(SECRET);
if (SECRET_ENCODING === "hex" && !IS_64_HEX) {
  console.error("FATAL: AGENT_GAMES_HMAC_SECRET_ENCODING=hex but secret is not 64 hex chars.");
  process.exit(1);
}

function candidateKeys() {
  if (SECRET_ENCODING === "utf8") return [{ name: "utf8", key: Buffer.from(SECRET, "utf8") }];
  if (SECRET_ENCODING === "hex") return [{ name: "hex", key: Buffer.from(SECRET, "hex") }];
  const out = [{ name: "utf8", key: Buffer.from(SECRET, "utf8") }];
  if (IS_64_HEX) out.push({ name: "hex", key: Buffer.from(SECRET, "hex") });
  return out;
}

function hmacHex(key, body) {
  return crypto.createHmac("sha256", key).update(body).digest("hex");
}

function verifySignature(headerSig, body) {
  if (typeof headerSig !== "string" || !/^[0-9a-fA-F]+$/.test(headerSig)) return null;
  const sigBuf = Buffer.from(headerSig, "hex");
  for (const { name, key } of candidateKeys()) {
    const expect = Buffer.from(hmacHex(key, body), "hex");
    if (sigBuf.length === expect.length && crypto.timingSafeEqual(sigBuf, expect)) {
      return { key, encoding: name };
    }
  }
  return null;
}

function signBody(key, body) {
  return hmacHex(key, body);
}

// ---------------------------------------------------------------------------
// Persistence (decisions + seen-set). Atomic write via tmp + rename.
// ---------------------------------------------------------------------------
function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}
function saveJsonAtomic(file, value) {
  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(value));
  fs.renameSync(tmp, file);
}

const decisions = loadJson(DECISIONS_PATH, {}); // task_id -> { body, decided_at }
const seen = new Set(loadJson(SEEN_PATH, [])); // proof_tx strings (lowercased)

function persistDecisions() { saveJsonAtomic(DECISIONS_PATH, decisions); }
function persistSeen() { saveJsonAtomic(SEEN_PATH, [...seen]); }

// ---------------------------------------------------------------------------
// Witness-input encodings — SWAPPABLE, see README "UNVERIFIED encodings".
// ---------------------------------------------------------------------------
// UNVERIFIED (no public material states these): how the platform encodes the
// task_id STRING and the 256-bit vk hashes as BN128 field elements. What is
// implemented here is the best-supported guess for each:
//  - vkHash (0x… 32 bytes): BigInt(hex), reduced mod p by snarkjs. The circuit
//    only compares registeredVkHash == proofVkHash, so ANY consistent encoding
//    of equal hashes proves; mod-p is the standard snarkjs behaviour.
//  - taskId string ("gk_…"): keccak256(utf8(taskId)) mod p. keccak256 is the
//    platform's house hash (cf. Steal-the-VFY publicInputsHash in the spec).
//    The circuit only binds taskId via Poseidon(salt, taskId); it never
//    constrains taskId's value, so any encoding yields a VALID proof — but if
//    the platform compares public_signals[12] against its own recomputation,
//    the encoding must match theirs. If a practice task shows a mismatch,
//    change ONLY encodeTaskId() here.
//  - addresses: BigInt(address) — 160-bit values fit the field natively.
//  - small numbers / blocks: plain decimal integers as strings.
function encodeTaskId(taskId) {
  const h = keccak256(Buffer.from(String(taskId), "utf8")); // hex, no 0x
  return (BigInt("0x" + h) % FIELD_PRIME).toString();
}
function encodeVkHash(hexStr) {
  if (typeof hexStr !== "string" || !/^0x[0-9a-fA-F]+$/.test(hexStr)) {
    throw new Error("bad vk hash");
  }
  return (BigInt(hexStr) % FIELD_PRIME).toString();
}
function encodeAddress(addr) {
  if (typeof addr !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(addr)) {
    throw new Error("bad address");
  }
  return BigInt(addr).toString();
}
function encodeUint(value) {
  // Accepts decimal strings or JSON numbers; rejects anything non-numeric.
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) throw new Error("bad uint");
    return String(value);
  }
  if (typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value)) return value;
  throw new Error("bad uint");
}
function randomSalt() {
  // Random field element, 1 <= salt < p.
  let s;
  do {
    s = BigInt("0x" + crypto.randomBytes(32).toString("hex")) % FIELD_PRIME;
  } while (s === 0n);
  return s.toString();
}

// ---------------------------------------------------------------------------
// Trap checks (fail-closed, in the spec's order).
// NOTE: expiry is STRICT (current < expiry) because the circuit enforces it;
// current == expiry is EXPIRED_CONDITION, not a pass. See header comment.
// ---------------------------------------------------------------------------
function checkTraps(input) {
  const norm = (a) => String(a).toLowerCase();
  if (norm(input.proof_vk) !== norm(input.registered_vk)) {
    return { code: "VK_SUBSTITUTION", decision: 0 };
  }
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { code: "THRESHOLD_MISMATCH", decision: 0 };
  }
  if (norm(input.recipient) !== norm(input.condition_recipient)) {
    return { code: "RECIPIENT_MISMATCH", decision: 0 };
  }
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { code: "AMOUNT_OVERFLOW", decision: 0 };
  }
  if (BigInt(input.current_block) >= BigInt(input.expiry_block)) {
    return { code: "EXPIRED_CONDITION", decision: 0 };
  }
  const proofTx = String(input.proof_tx).toLowerCase();
  if (seen.has(proofTx)) {
    return { code: "PROOF_REPLAY", decision: 0, replay: true };
  }
  return { code: "VALID_PROOF", decision: 1 };
}

function buildWitnessInput(input, decision, taskId) {
  return {
    registeredVkHash: encodeVkHash(input.registered_vk),
    proofVkHash: encodeVkHash(input.proof_vk),
    minimum: encodeUint(input.minimum),
    publicBalance: encodeUint(input.public_balance),
    expiryBlock: encodeUint(input.expiry_block),
    currentBlock: encodeUint(input.current_block),
    recipient: encodeAddress(input.recipient),
    conditionRecipient: encodeAddress(input.condition_recipient),
    amount: encodeUint(input.amount),
    maxTransfer: encodeUint(input.max_transfer),
    decision: String(decision),
    salt: randomSalt(),
    taskId: encodeTaskId(taskId),
  };
}

let verificationKey = null;
async function getVerificationKey() {
  if (!verificationKey) {
    verificationKey = JSON.parse(fs.readFileSync(VK_PATH, "utf8"));
  }
  return verificationKey;
}

// ---------------------------------------------------------------------------
// Logging (never secrets, never bodies — only task_id / decision / timings).
// ---------------------------------------------------------------------------
function log(entry) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...entry }));
}

// ---------------------------------------------------------------------------
// Task handling
// ---------------------------------------------------------------------------
async function handleTask(reqBody, taskId) {
  const started = Date.now();
  const input = reqBody.input || {};
  const proofTx = typeof input.proof_tx === "string" ? input.proof_tx : undefined;

  // Validate the fields the circuit needs. Malformed -> fail closed, no proof.
  let witnessInput;
  try {
    if (!input || typeof input !== "object") throw new Error("missing input");
    for (const f of ["registered_vk", "proof_vk", "minimum", "public_balance",
      "expiry_block", "current_block", "recipient", "condition_recipient",
      "amount", "max_transfer", "proof_tx"]) {
      if (input[f] === undefined || input[f] === null || input[f] === "") {
        throw new Error(`missing ${f}`);
      }
    }
    // Validate encodability up-front (throws on bad hex / address / uint).
    buildWitnessInput(input, 0, taskId);
  } catch (e) {
    const response = {
      decision: "REJECT",
      reason_code: "PUBLIC_INPUT_MISMATCH",
      ...(proofTx ? { proof_tx: proofTx } : {}),
    };
    finishDecision(taskId, proofTx, response, started, 0, "malformed-input");
    return response;
  }

  const trap = checkTraps(input);

  // PROOF_REPLAY: all field checks pass, so decision=0 is UNPROVABLE in the
  // circuit (decision must equal the AND of the checks). No proof to submit.
  if (trap.replay) {
    const response = {
      decision: "REJECT",
      reason_code: "PROOF_REPLAY",
      ...(proofTx ? { proof_tx: proofTx } : {}),
    };
    finishDecision(taskId, proofTx, response, started, 0, "replay");
    return response;
  }

  // Every other outcome IS provable: decision=1 iff all checks pass,
  // decision=0 iff at least one check fails.
  const proveStarted = Date.now();
  let proof = null;
  let publicSignals = null;
  try {
    witnessInput = buildWitnessInput(input, trap.decision, taskId);
    const result = await snarkjs.groth16.fullProve(
      witnessInput, WASM_PATH, ZKEY_PATH
    );
    proof = result.proof;
    publicSignals = result.publicSignals;
    // Defensive self-check: our proof must verify against our own VK.
    const vk = await getVerificationKey();
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    if (!ok) throw new Error("self-verification failed");
  } catch (e) {
    // Fail closed: keep the trap decision, drop the proof.
    log({ task_id: taskId, event: "prove_failed", reason_code: trap.code, error: String(e && e.message || e).slice(0, 200) });
    const response = {
      decision: "REJECT",
      reason_code: trap.decision === 1 ? "PROOF_INVALID" : trap.code,
      ...(proofTx ? { proof_tx: proofTx } : {}),
    };
    finishDecision(taskId, proofTx, response, started, Date.now() - proveStarted, "prove-failed");
    return response;
  }
  const proveMs = Date.now() - proveStarted;

  const response = {
    decision: trap.decision === 1 ? "APPROVE" : "REJECT",
    reason_code: trap.code,
    proof,
    public_signals: publicSignals,
    ...(proofTx ? { proof_tx: proofTx } : {}),
  };
  finishDecision(taskId, proofTx, response, started, proveMs, "proved");
  return response;
}

function finishDecision(taskId, proofTx, response, started, proveMs, how) {
  const totalMs = Date.now() - started;
  // Record the proof reference as seen AFTER deciding (any decision: the
  // reference has now been submitted once; a second task reusing it is a
  // replay). See README for the reasoning + the alternative considered.
  if (proofTx) {
    seen.add(String(proofTx).toLowerCase());
    persistSeen();
  }
  if (taskId) {
    decisions[taskId] = { body: JSON.stringify(response), decided_at: new Date().toISOString() };
    persistDecisions();
  }
  log({
    task_id: taskId || null,
    decision: response.decision,
    reason_code: response.reason_code,
    prove_ms: proveMs,
    total_ms: totalMs,
    how,
  });
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------
function sendJson(res, status, obj, signKey) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { "content-type": "application/json" };
  if (signKey) headers["x-agent-games-signature"] = signBody(signKey, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    if (req.method === "GET" && url.pathname === "/healthz") {
      sendJson(res, 200, { ok: true }, null); // unsigned, local use only
      return;
    }
    if (req.method !== "POST" || url.pathname !== "/agent") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "not_found" }));
      return;
    }

    const rawBody = await readRawBody(req);

    // HMAC over the RAW body, BEFORE parsing JSON. Reject (401, no details).
    const verified = verifySignature(req.headers["x-agent-games-signature"], rawBody);
    if (!verified) {
      res.writeHead(401);
      res.end();
      return;
    }
    const signKey = verified.key;

    let body;
    try {
      body = JSON.parse(rawBody.toString("utf8"));
    } catch {
      sendJson(res, 400, { ok: false, error: "invalid_json" }, signKey);
      return;
    }

    if (body && body.type === "agent-games.preflight.v1") {
      sendJson(res, 200, { ok: true, protocolVersion: "v1" }, signKey);
      return;
    }

    if (body && body.type === "agent-games.proof-gatekeeper.v1") {
      const taskId = typeof body.task_id === "string" ? body.task_id : null;
      // Idempotency: same task_id -> exact same stored response, never re-decide.
      if (taskId && decisions[taskId]) {
        const stored = Buffer.from(decisions[taskId].body);
        res.writeHead(200, {
          "content-type": "application/json",
          "x-agent-games-signature": signBody(signKey, stored),
        });
        res.end(stored);
        log({ task_id: taskId, event: "idempotent_replay" });
        return;
      }
      if (!taskId) {
        sendJson(res, 400, { ok: false, error: "missing_task_id" }, signKey);
        return;
      }
      const response = await handleTask(body, taskId);
      sendJson(res, 200, response, signKey);
      return;
    }

    sendJson(res, 400, { ok: false, error: "unknown_type" }, signKey);
  } catch (e) {
    // Never leak internals; fail closed for tasks is handled in handleTask.
    log({ event: "handler_error", error: String(e && e.message || e).slice(0, 200) });
    try {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "internal" }));
    } catch { /* socket already gone */ }
  }
});

server.listen(PORT, () => {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    event: "listening",
    port: PORT,
    hmac_encoding: SECRET_ENCODING,
    vk_hash: GATEKEEPER_VK_HASH,
  }));
});
