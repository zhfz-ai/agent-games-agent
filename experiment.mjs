// Empirically map the gatekeeper circuit:
// 1. public-signal ORDER: run witness calc with distinct values, export witness JSON.
// 2. constraint semantics: wtns check with decision=1 + each trap, decision=0 + traps,
//    decision=2, and varying taskId/salt.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const DIR = new URL(".", import.meta.url).pathname;
const SNARK = path.join(DIR, "node_modules/.bin/snarkjs");
const WASM = path.join(DIR, "circuits/gatekeeper.wasm");
const ZKEY = path.join(DIR, "circuits/gatekeeper_final.zkey");
const VK = path.join(DIR, "circuits/verification_key.json");
const TMP = "/tmp/gkexp";
fs.mkdirSync(TMP, { recursive: true });

const VK_HASH = BigInt("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0");
const ADDR = BigInt("0xDe42000000000000000000000000000000009f01");

function baseInput(over = {}) {
  return {
    minimum: "1000",
    publicBalance: "1460",
    expiryBlock: "8430000",
    currentBlock: "8420000",
    recipient: ADDR.toString(),
    conditionRecipient: ADDR.toString(),
    amount: "500",
    maxTransfer: "1000",
    decision: "1",
    salt: "12345",
    registeredVkHash: VK_HASH.toString(),
    proofVkHash: VK_HASH.toString(),
    taskId: "987654321",
    ...over,
  };
}

function run(cmd, args) {
  try {
    const out = execFileSync(cmd, args, { encoding: "utf8", timeout: 120000 });
    return { ok: true, out };
  } catch (e) {
    return { ok: false, out: (e.stdout || "") + (e.stderr || "") + e.message };
  }
}

function witnessCheck(input, label) {
  const inp = path.join(TMP, "in.json");
  const wtns = path.join(TMP, "w.wtns");
  fs.writeFileSync(inp, JSON.stringify(input));
  const r1 = run(SNARK, ["wtns", "calculate", WASM, inp, wtns]);
  if (!r1.ok) { console.log(`${label}: WITNESS CALC FAILED\n  ${r1.out.split("\n").slice(0, 4).join("\n  ")}`); return false; }
  // need r1cs for wtns check; export r1cs from zkey json is not available, so use
  // groth16 fullProve + verify as the constraint check instead (fullProve fails if
  // witness does not satisfy the circuit).
  const proof = path.join(TMP, "proof.json");
  const pub = path.join(TMP, "public.json");
  const t0 = Date.now();
  const r2 = run(SNARK, ["groth16", "fullprove", inp, WASM, ZKEY, proof, pub]);
  const ms = Date.now() - t0;
  if (!r2.ok) { console.log(`${label}: FULLPROVE FAILED (${ms}ms) — constraints NOT satisfied`); return false; }
  const r3 = run(SNARK, ["groth16", "verify", VK, pub, proof]);
  const pubSignals = JSON.parse(fs.readFileSync(pub, "utf8"));
  console.log(`${label}: fullProve OK (${ms}ms) verify=${r3.ok ? "OK" : "FAIL"} public_signals=${JSON.stringify(pubSignals)}`);
  return { ms, pubSignals };
}

// 1. valid case, distinct values -> reveals public-signal order
console.log("=== 1. VALID case (decision=1, all checks pass) ===");
const valid = witnessCheck(baseInput(), "valid");
console.log("\n=== 2. constraint probes ===");
witnessCheck(baseInput({ decision: "0" }), "decision=0, all checks pass (REJECT shape)");
witnessCheck(baseInput({ decision: "2" }), "decision=2 (non-boolean)");
witnessCheck(baseInput({ proofVkHash: (VK_HASH + 1n).toString() }), "decision=1, vk mismatch");
witnessCheck(baseInput({ publicBalance: "999" }), "decision=1, balance < minimum");
witnessCheck(baseInput({ conditionRecipient: (ADDR + 1n).toString() }), "decision=1, recipient mismatch");
witnessCheck(baseInput({ amount: "1001" }), "decision=1, amount > max");
witnessCheck(baseInput({ currentBlock: "8430001" }), "decision=1, expired");
witnessCheck(baseInput({ decision: "0", proofVkHash: (VK_HASH + 1n).toString(), publicBalance: "1", amount: "99999", currentBlock: "99999999" }), "decision=0, ALL traps at once");
witnessCheck(baseInput({ taskId: "555" }), "decision=1, taskId changed (binding only?)");
witnessCheck(baseInput({ salt: "777" }), "decision=1, salt changed (binding only?)");
witnessCheck(baseInput({ decision: "1", publicBalance: "1000" }), "decision=1, balance == minimum (boundary)");
witnessCheck(baseInput({ decision: "1", amount: "1000" }), "decision=1, amount == max (boundary)");
witnessCheck(baseInput({ decision: "1", currentBlock: "8430000" }), "decision=1, current == expiry (boundary)");
