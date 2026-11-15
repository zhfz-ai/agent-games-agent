// Probe gatekeeper.wasm for its input signal names via FNV-1a dictionary attack.
// The wasm exports getInputSignalSize(hMSB, hLSB): >=0 if the hashed name exists.
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
  shash = "0".repeat(16 - shash.length).concat(shash);
  return shash;
}

const wasm = fs.readFileSync(new URL("./circuits/gatekeeper.wasm", import.meta.url));
const wc = await WitnessCalculatorBuilder(wasm, { sanityCheck: false });
const inst = wc.instance.exports;
console.log("wasm exports with getInputSignalSize:", typeof inst.getInputSignalSize);
console.log("getInputSize() =", inst.getInputSize(), " getWitnessSize() =", inst.getWitnessSize());

const candidates = new Set();
// task-field names, several casings
const bases = ["registered_vk","registeredVk","registeredvk","proof_vk","proofVk","minimum","public_balance","publicBalance","publicbalance","expiry_block","expiryBlock","current_block","currentBlock","recipient","condition_recipient","conditionRecipient","amount","max_transfer","maxTransfer","proof_tx","proofTx","balance","threshold","decision","approve","approved","isValid","valid","result","outcome","pass","accept","accepted","vkMatch","vk_match","thresholdMet","threshold_met","recipientMatch","recipient_match","amountOk","amount_ok","notExpired","not_expired","expired","notReused","not_reused","reused","replay","allChecks","checksPassed","vkHash","vk_hash","vk","hash","commitment","nullifier","proofHash","txHash","tx_hash","salt","nonce","secret","value","values","data","input","output","is_approved","isApproved","is_valid","check","checks","allow","allowed","deny","denied","ok","gate","gatekeeper","proof","tx","block","expiry","max","min","a","b","c","x","y","z","n","m","i","j","k","in","out","s","t","u","v","w","d","e","f","g","h","l","o","p","q","r"];
for (const b of bases) candidates.add(b);
// hash-suffixed variants of the semantic fields
for (const b of ["registeredVk","proofVk","recipient","conditionRecipient","proofTx","vk","balance","amount","decision"]) {
  candidates.add(b + "Hash"); candidates.add(b + "_hash"); candidates.add(b + "hash");
}
// is-prefixed variants
for (const b of ["Valid","Approved","Expired","Reused","Replayed","ThresholdMet","RecipientMatch","AmountOk","VkMatch","Ok"]) {
  candidates.add("is" + b);
}
// single + double letters
for (let i = 0; i < 26; i++) candidates.add(String.fromCharCode(97 + i));
for (let i = 0; i < 26; i++) for (let j = 0; j < 26; j++)
  candidates.add(String.fromCharCode(97 + i) + String.fromCharCode(97 + j));

const found = [];
for (const name of candidates) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  let size;
  try { size = inst.getInputSignalSize(hMSB, hLSB); } catch { size = -1; }
  if (size >= 0) found.push({ name, size });
}
console.log("FOUND:", JSON.stringify(found, null, 2));
console.log("total input elements found:", found.reduce((s, f) => s + f.size, 0), "vs getInputSize() =", inst.getInputSize());
