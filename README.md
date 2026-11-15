# Proof Gatekeeper agent — README

Node.js (`node:http`, no framework) agent server for the zkVerify Agent Games
Proof Gatekeeper track. Protocol spec: `~/workspace/agentgames/agent-spec.md`.

## Files

| File | What it is |
|---|---|
| `server.mjs` | The agent server. |
| `circuits/gatekeeper.wasm` | Gatekeeper circuit (1,755,820 bytes, sha256 `be00aefe…92764f`). |
| `circuits/gatekeeper_final.zkey` | Proving key (309,750 bytes, sha256 `adfe95a4…af80d`). |
| `circuits/verification_key.json` | VK exported with `snarkjs zkey export verificationkey`. Groth16/BN128, **nPublic = 13**, nVars = 647, domainSize 1024. |
| `circuits/gatekeeper_zkey.json` | Full zkey export (inspection artifact). |
| `decisions.json` | Idempotency store: `task_id -> {body, decided_at}`. Created at runtime. |
| `seen.json` | Seen-set: array of lowercased `proof_tx` values. Created at runtime. |
| `test.mjs` | Local validation harness (26 checks, see TESTS.md). |
| `probe.mjs`, `probe2.mjs`, `experiment.mjs` | Circuit-reversal research scripts (FNV-hash dictionary probe + constraint experiments). |
| `package.json`, `package-lock.json` | Deps: `snarkjs@0.7.6`, `circomlibjs` (research only), `js-sha3` (keccak256 for taskId encoding). |

## Start

```sh
cd ~/workspace/agentgames/agent
npm install            # once; snarkjs + js-sha3 (+ circomlibjs, research only)
AGENT_GAMES_HMAC_SECRET='<secret from dashboard Rotate Secret>' \
AGENT_GAMES_HMAC_SECRET_ENCODING=auto \
PORT=18080 node server.mjs
```

Env vars:

| Var | Required | Default | Meaning |
|---|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes | — | 32-byte secret from dashboard Rotate Secret. Server refuses to start without it. |
| `AGENT_GAMES_HMAC_SECRET_ENCODING` | no | `auto` | `utf8` \| `hex` \| `auto` (see below). |
| `PORT` | no | `18080` | Listen port. |

Endpoints: `POST /agent` (preflight + tasks, HMAC-signed both ways),
`GET /healthz` → `{"ok":true}` (unsigned, local use only).

## HMAC encoding auto-detection

The platform docs say HMAC-SHA256 hex over the raw body, but never say whether
the 32-byte secret is used as a UTF-8 string or as hex-decoded bytes. The server
handles both:

- `utf8`: key = `Buffer.from(secret, "utf8")`, only that key is tried.
- `hex`: key = `Buffer.from(secret, "hex")` (secret must be 64 hex chars), only that key is tried.
- `auto` (default): try the UTF-8 key first; if verification fails **and** the
  secret is 64 hex chars, retry with the hex-decoded key. The key that verifies
  a request is the key used to sign that request's response.
  Comparison is `crypto.timingSafeEqual`. A mismatch returns **401 with an empty
  body**, before any JSON parsing.

Local tests confirm: `auto` accepts both encodings (for a 64-hex secret), `hex`
accepts only the hex-decoded key and returns 401 for the UTF-8 key. Once the real
platform secret is in hand, run one preflight against the dashboard: if it passes
in `auto`, the working encoding is whatever verified — check the server log line
(`hmac_encoding` is the configured mode; the per-request match is not logged to
avoid leaking key material). If preflight fails in `auto`, the secret itself is
wrong (rotation needed), not the encoding.

## Decision logic (fail-closed, in order)

1. `proof_vk == registered_vk`, else REJECT `VK_SUBSTITUTION`.
2. `public_balance >= minimum`, else REJECT `THRESHOLD_MISMATCH`.
3. `recipient == condition_recipient` (case-insensitive), else REJECT `RECIPIENT_MISMATCH`.
4. `amount <= max_transfer`, else REJECT `AMOUNT_OVERFLOW`.
5. `current_block < expiry_block` (**strict** — see below), else REJECT `EXPIRED_CONDITION`.
6. `proof_tx` not in the local seen-set, else REJECT `PROOF_REPLAY` (**no proof** — see below).
7. All pass → APPROVE `VALID_PROOF`.

Every provable decision includes a locally generated Groth16 proof
(`snarkjs.groth16.fullProve`, gatekeeper wasm+zkey) + `public_signals`, plus the
`proof_tx` echo. The proof is self-verified against the local VK before responding;
on any prove/verify failure the server fails closed (REJECT, proof omitted).
Slowest observed roundtrip: ~1.3 s (60 s deadline). Log lines carry only
`task_id`, `decision`, `reason_code`, `prove_ms`, `total_ms` — never secrets or bodies.

## Persistence

- `decisions.json` — every decided `task_id` maps to the exact response body.
  A redelivery returns the stored bytes verbatim (re-signed; HMAC is deterministic,
  so the signature matches too). The server never decides twice.
- `seen.json` — every `proof_tx` from a decided task (any decision — see below),
  lowercased. Written after the decision, via atomic tmp+rename.
- Both files are created on first use; delete them to reset state (e.g. after local
  tests — `test.mjs` does this itself before each run).

Why the seen-set records on ANY decision, not just APPROVE: the replay trap is
"the proof reference was already submitted in a previous task". A reference that
appeared in an earlier task — even one rejected for a field trap — has been used
once; a second task reusing it is a replay. If practice/scoring evidence later
shows the platform only counts APPROVEd references, change `finishDecision()` in
`server.mjs` to record only on APPROVE (one-line change, flagged in a comment).

## Circuit layout — RESOLVED (was UNVERIFIED in the spec)

No starter repo or witness spec exists in the public site material (the `/build`
page only offers a "copy starter prompt" text; the JS chunks contain no
`fullProve`/witness code and no github.com repo link). The layout below was
recovered empirically from the artifacts themselves:

- **Probe method:** the wasm exports `getInputSignalSize(fnv1a64(name))`; a
  dictionary attack over task-field names, casings, and semantic variants
  (`probe.mjs`, `probe2.mjs`) found all 13 input signals, each size 1.
- **Inputs (13):** `registeredVkHash, proofVkHash, minimum, publicBalance,
  expiryBlock, currentBlock, recipient, conditionRecipient, amount, maxTransfer,
  decision, taskId` (public) + `salt` (private — it never appears in public_signals).
- **Public signals (13), in order:**
  `[0] Poseidon(salt, taskId)`, `[1] registeredVkHash`, `[2] proofVkHash`,
  `[3] minimum`, `[4] publicBalance`, `[5] expiryBlock`, `[6] currentBlock`,
  `[7] recipient`, `[8] conditionRecipient`, `[9] amount`, `[10] maxTransfer`,
  `[11] decision (1=APPROVE, 0=REJECT)`, `[12] taskId`.
  `[0]` was confirmed as `Poseidon(salt, taskId)` (that input order) in three
  independent cases with circomlibjs — exact decimal matches.
- **Constraint semantics** (verified by `experiment.mjs`, fullProve + local verify):
  the circuit asserts `decision == (vkMatch AND balance>=minimum AND
  recipientMatch AND amount<=maxTransfer AND currentBlock<expiryBlock)`.
  So decision=1 is provable only when every check passes, and decision=0 is
  provable only when at least one check fails. A REJECT of a fully-valid task
  is unprovable — which is exactly why PROOF_REPLAY responses carry no proof.
- **Expiry is STRICT:** `currentBlock == expiryBlock` fails the circuit
  (decision=1 unprovable). The spec text says `<=`; the circuit is the referee,
  so equality is treated as `EXPIRED_CONDITION`. Boundaries verified:
  balance == minimum passes, amount == max passes, current == expiry fails.

## UNVERIFIED items (do not build on guesses)

1. **taskId string → field element encoding.** The circuit takes `taskId` as a
   field element and only binds it via `Poseidon(salt, taskId)`; it never
   constrains its value, so ANY encoding yields a cryptographically valid proof.
   Implemented as `keccak256(utf8(taskId)) mod p` (`encodeTaskId()` in
   `server.mjs`) — keccak256 is the platform's house hash (cf. Steal-the-VFY
   `publicInputsHash` in the spec). If the platform compares `public_signals[12]`
   against its own recomputation, the encoding must match theirs. **If a practice
   task shows a public-signals mismatch, change ONLY `encodeTaskId()`.**
   Alternatives, in order of likelihood: `sha256(taskId) mod p`; Poseidon over
   the string bytes; numeric parse of the id suffix.
2. **vkHash 256-bit → field element encoding.** Implemented as `BigInt(hex) mod p`
   (what snarkjs does to every witness input anyway). The circuit only compares
   the two hashes for equality, so any consistent encoding proves; the only risk
   is a platform-side recomputation expecting a different reduction (e.g. low
   253 bits). Mod-p is the standard behaviour and the best-supported guess.
3. **Submitted-payment-proof on-chain verification.** Not implemented: there is
   no Kurier API key, and no public call to look a proof up by `proof_tx` was
   found. The trap checks operate on the task fields. The server never calls
   Kurier. If a key is obtained later, add the lookup BEFORE the field checks
   (a failed lookup must fail closed to REJECT `PROOF_INVALID`).
4. **`reason_code` for the three traps missing from the canonical table**
   (`EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`): the trap
   names are used, per the event page's own sample (`VK_SUBSTITUTION`). Confirm
   against a practice-task result before a scored round.
5. **Preflight/practice dispatch mechanics, `issued_at`/`deadline_at` formats,
   retry intervals** — as in the spec (dashboard-side, auth-gated).

## What is NOT done here (parent's scope)

No public tunnel, no endpoint registration, no dashboard interaction, no key
creation, no spend. The parent handles hosting + registration with the real
`AGENT_GAMES_HMAC_SECRET`.
