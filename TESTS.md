# Local validation results — Proof Gatekeeper agent server

Run: `node test.mjs` (from this dir). Date: 2026-11-15 ~11:05 WIB.
The harness starts `server.mjs` as a child process with a RANDOM test secret
(generated per run, never printed), runs every case twice — once with
`AGENT_GAMES_HMAC_SECRET_ENCODING=auto`, once with `=hex` — verifies response
HMACs and verifies every returned Groth16 proof locally against
`circuits/verification_key.json`.

## Result: 26/26 passed, 0 failed

### Suite `auto` (secret = random 64-hex string, encoding auto)

| # | Case | Result | Detail |
|---|---|---|---|
| a | Signed preflight | PASS | 200 `{"ok":true,"protocolVersion":"v1"}`, response HMAC valid, 9 ms |
| b | Valid task | PASS | APPROVE / VALID_PROOF, response HMAC valid, proof verifies locally, all 13 public_signals as expected, proof_tx echoed, roundtrip 1145 ms, server prove_ms 1137 |
| c | VK_SUBSTITUTION | PASS | REJECT, proof (decision=0) verifies locally, HMAC valid, roundtrip 327 ms, prove 322 ms |
| c | THRESHOLD_MISMATCH | PASS | REJECT, proof verifies, HMAC valid, roundtrip 334 ms, prove 330 ms |
| c | RECIPIENT_MISMATCH | PASS | REJECT, proof verifies, HMAC valid, roundtrip 338 ms, prove 333 ms |
| c | AMOUNT_OVERFLOW | PASS | REJECT, proof verifies, HMAC valid, roundtrip 391 ms, prove 386 ms |
| c | EXPIRED_CONDITION (current > expiry) | PASS | REJECT, proof verifies, HMAC valid, roundtrip 320 ms, prove 316 ms |
| c | EXPIRED_CONDITION (current == expiry) | PASS | REJECT, proof verifies, HMAC valid, roundtrip 321 ms, prove 315 ms |
| c | PROOF_REPLAY (same proof_tx, new task_id) | PASS | REJECT / PROOF_REPLAY, `proof` and `public_signals` omitted, HMAC valid, 4 ms |
| d | Redelivered task_id | PASS | Byte-identical response body, 3 ms |
| e | Bad HMAC | PASS | 401, empty body |
| g | Preflight signed with hex-decoded key | PASS | 200, response HMAC (hex key) valid — auto fallback works |

### Suite `hex` (same secret, encoding hex)

| # | Case | Result | Detail |
|---|---|---|---|
| a | Signed preflight (hex key) | PASS | 200, HMAC valid, 5 ms |
| b | Valid task | PASS | APPROVE / VALID_PROOF, proof verifies, signals as expected, roundtrip 1278 ms, prove 1268 ms |
| c | VK_SUBSTITUTION | PASS | REJECT, proof verifies, roundtrip 393 ms, prove 387 ms |
| c | THRESHOLD_MISMATCH | PASS | REJECT, proof verifies, roundtrip 392 ms, prove 343 ms |
| c | RECIPIENT_MISMATCH | PASS | REJECT, proof verifies, roundtrip 389 ms, prove 383 ms |
| c | AMOUNT_OVERFLOW | PASS | REJECT, proof verifies, roundtrip 368 ms, prove 363 ms |
| c | EXPIRED_CONDITION (current > expiry) | PASS | REJECT, proof verifies, roundtrip 331 ms, prove 327 ms |
| c | EXPIRED_CONDITION (current == expiry) | PASS | REJECT, proof verifies, roundtrip 421 ms, prove 414 ms |
| c | PROOF_REPLAY | PASS | REJECT / PROOF_REPLAY, proof omitted, 5 ms |
| d | Redelivered task_id | PASS | Byte-identical response body, 6 ms |
| e | Bad HMAC | PASS | 401, empty body |
| g | Preflight signed with UTF-8 key | PASS | 401 — hex mode correctly rejects the wrong encoding |

## Timings (vs the 60 s hard deadline)

- First proof in a fresh server process: **~1.1–1.3 s** (includes loading the
  wasm/zkey into memory; valid-task proves were always the first prove in their process).
- Steady-state proof (witness + Groth16 prove + local self-verify): **~0.3–0.4 s**.
- Slowest full roundtrip observed: **1278 ms**. Worst case is ~50x inside the 60 s limit.
- Preflight / replay / redelivery / 401: **3–9 ms**.

## Circuit experiments (evidence for the layout in README.md)

`experiment.mjs` (run 2026-11-15, fullProve via snarkjs CLI, verify OK where noted):

- Valid input (all checks pass, decision=1) → fullProve OK (~1.1 s), proof verifies
  against the exported VK. public_signals order confirmed (see README).
- decision=0 with all checks passing → witness calc FAILS (assert, template
  `GatekeeperEvaluation_79` line 102). A REJECT of a valid task is unprovable.
- decision=2 → same assert failure (decision must be 0/1 and equal the AND of checks).
- decision=1 with any single trap (vk mismatch / balance<minimum / recipient
  mismatch / amount>max / current>expiry) → assert failure. Each trap makes
  decision=1 unprovable.
- decision=0 with ALL traps at once → fullProve OK, verifies. REJECT proofs are
  generatable exactly when ≥1 check fails.
- Boundary: balance == minimum → decision=1 OK; amount == max → decision=1 OK;
  **currentBlock == expiryBlock → decision=1 FAILS** (expiry is strict `<`).
- taskId changed (same salt) → public_signals[0] changes; salt changed (same
  taskId) → public_signals[0] changes; all other inputs changed → [0] unchanged.
  [0] = Poseidon(salt, taskId), confirmed exactly in 3 independent cases
  (see probe notes in README).
- `public_signals[0] = Poseidon(salt, taskId)` verified with circomlibjs:
  Poseidon([12345, 987654321]) = 8429500003489257934306409591503907017340042922628816703611234279355568056381
  (and likewise for the taskId=555 and salt=777 cases — exact matches).

## State after the test run

`test.mjs` deletes `decisions.json` / `seen.json` before each run, and the run's
test state files were removed afterwards, so the agent dir starts clean for
deployment. No server process is left running; no public tunnel was started;
nothing was registered.
