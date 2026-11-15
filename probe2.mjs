// Round-2 probe for the 13th gatekeeper input signal + dump wasm data segments
// to locate the FNV-hash table used by getInputSignalSize.
import fs from "node:fs";
import { WitnessCalculatorBuilder } from "circom_runtime";

function fnvHash(str) {
  const uint64_max = BigInt(2) ** BigInt(64);
  let hash = BigInt("0xCBF29CE484222325");
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash *= BigInt(0x100000001B3);
    hash %= uint64_max;
  }
  let shash = hash.toString(16);
  return "0".repeat(16 - shash.length).concat(shash);
}

const wasm = fs.readFileSync(new URL("./circuits/gatekeeper.wasm", import.meta.url));
const wc = await WitnessCalculatorBuilder(wasm, { sanityCheck: false });
const inst = wc.instance.exports;

const candidates = new Set([
  "seen","isSeen","wasSeen","seenBefore","alreadySeen","proofSeen","used","isUsed",
  "isReplay","isProofReused","proofReused","duplicate","isDuplicate","fresh","unique",
  "firstUse","isFirstUse","taskId","task_id","taskHash","taskIdHash","agentId","agent_id",
  "round","roundId","eventId","matchId","transfer","payment","request","requestHash",
  "paymentHash","blockHeight","height","chainId","network","timestamp","issuedAt",
  "deadline","deadlineAt","conditionRecipientHash","thresholdValue","minBalance",
  "requiredBalance","decisionValue","expectedDecision","verdict","vkSubstitution",
  "substitution","mismatch","proofValid","isProofValid","proofOk","publicInput",
  "publicInputs","inputHash","inputsHash","publicInputHash","randomness","blinding",
  "entropy","seed","caller","sender","from","to","payer","payee","allowance","limit",
  "cap","check1","check2","check3","check4","check5","check6","flag","flags","zero",
  "one","decisionHash","saltHash","minimumHash","amountHash","balanceHash","proof_tx_hash",
  "isExpired","isThresholdMet","isRecipientMatch","isAmountOk","isVkMatch","vkOk",
  "balanceOk","thresholdOk","recipientOk","amountOk","expiryOk","blockOk","proof_tx",
  "tx_hash","txHash","tx","hash","digest","id","idx","index","counter","version",
  "protocolVersion","circuitVersion","roundNumber","taskNumber","serial","serialNumber",
  "commitmentHash","nullifierHash","leaf","leafIndex","root","merkleRoot","proofIndex",
  "isFirst","first","newProof","isNew","reuse","reusedFlag","replayFlag","seenFlag",
  "usedFlag","flag0","flag1","valid","isValidProof","proofValidFlag","allValid",
  "allChecksPass","checksPass","passAll","isApproved","approved","approval","approveFlag",
  "dec","decVal","d","s","v","h","r2","in0","in1","in2","input0","input1","sig0","signal0",
  "x0","x1","a0","a1","b0","b1","v0","v1","w0","p0","q0","n0","m0","t0","u0","k0",
  "amountValue","maxAmount","maxValue","minValue","current","expiry","exp","blk","bal",
  "amt","rcp","crcp","rvk","pvk","pub","pubBal","pubBalance","minBal","maxAmt","curBlk",
  "expBlk","condRcp","condRecipient","expectedRecipient","targetRecipient","payeeAddress",
  "payerAddress","senderAddress","recipientAddress","address","addr","wallet","owner",
  "isFinal","finalized","final","confirmed","onChain","isOnChain","verified","isVerified",
]);
for (const b of ["decision","salt","minimum","publicBalance","expiryBlock","currentBlock","recipient","conditionRecipient","amount","maxTransfer","registeredVkHash","proofVkHash"]) {
  candidates.add(b + "Hash"); candidates.add(b + "_hash");
  candidates.add("is" + b[0].toUpperCase() + b.slice(1));
}
const found = [];
for (const name of candidates) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  let size = -1;
  try { size = inst.getInputSignalSize(hMSB, hLSB); } catch { size = -1; }
  if (size >= 1) found.push({ name, size });
}
console.log("ROUND2 HITS:", JSON.stringify(found));
