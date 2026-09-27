"use strict";

const crypto = require("node:crypto");

const MAX_RECEIPT_BYTES = 8192;
const MAX_RECEIPT_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const DOMAIN = "focustrack:no-award-evaluator-receipt:v1\n";
const ID = /^[a-z0-9][a-z0-9_.:-]{0,95}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const REPOSITORY = /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/;
const BINDING_FIELDS = Object.freeze([
  "taskId", "receiptId", "registrationSha256", "criteriaSha256",
  "sourceRepository", "baselineCommit", "baselineSha256", "candidateCommit",
  "candidateSha256", "registeredAt", "baselineAt", "workStartedAt", "evidenceClass"
]);
const PAYLOAD_FIELDS = Object.freeze([
  "schemaVersion", ...BINDING_FIELDS, "evaluatorRepository", "evaluatorCommit",
  "runId", "runAttempt", "evaluatedAt", "issuedAt", "expiresAt",
  "baselineResult", "result", "checkCount", "passedCount", "noAward"
]);
const NO_AWARD = Object.freeze({
  createsTruth: false, shouldAffectRewards: false, mutatesXp: false,
  mutatesRewards: false, mutatesFlow: false, liveAuthorityApproved: false
});

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function validPayload(value) {
  if (!exactKeys(value, PAYLOAD_FIELDS)) return false;
  if (value.schemaVersion !== 1 || value.noAward !== true) return false;
  if (!["taskId", "receiptId"].every((key) => typeof value[key] === "string" && ID.test(value[key]))) return false;
  if (!["registrationSha256", "criteriaSha256", "baselineSha256", "candidateSha256"]
    .every((key) => typeof value[key] === "string" && SHA256.test(value[key]))) return false;
  if (!["baselineCommit", "candidateCommit", "evaluatorCommit"]
    .every((key) => typeof value[key] === "string" && COMMIT.test(value[key]))) return false;
  if (!["sourceRepository", "evaluatorRepository"]
    .every((key) => typeof value[key] === "string" && REPOSITORY.test(value[key]))) return false;
  if (typeof value.runId !== "string" || !/^[1-9][0-9]{0,19}$/.test(value.runId)) return false;
  if (!["runAttempt", "registeredAt", "baselineAt", "workStartedAt", "evaluatedAt", "issuedAt", "expiresAt", "checkCount"]
    .every((key) => positiveInteger(value[key]))) return false;
  if (value.checkCount > 10000 || !Number.isSafeInteger(value.passedCount) ||
    value.passedCount < 0 || value.passedCount > value.checkCount) return false;
  if (!["passed", "failed", "inconclusive"].includes(value.result) || value.baselineResult !== "failed") return false;
  if ((value.result === "passed") !== (value.passedCount === value.checkCount)) return false;
  if (!["synthetic_setup_only", "prospective_no_award"].includes(value.evidenceClass)) return false;
  return value.registeredAt <= value.baselineAt && value.baselineAt < value.workStartedAt &&
    value.workStartedAt < value.evaluatedAt && value.evaluatedAt <= value.issuedAt &&
    value.issuedAt < value.expiresAt && value.expiresAt - value.evaluatedAt <= MAX_RECEIPT_AGE_MS;
}

function orderedPayload(payload) {
  return Object.fromEntries(PAYLOAD_FIELDS.map((key) => [key, payload[key]]));
}

function signingBytes(keyId, payload) {
  return Buffer.from(DOMAIN + JSON.stringify({ schemaVersion: 1, keyId, payload }), "utf8");
}

// Publisher-side only. This never creates keys or decides whether a task passed.
function signEvaluatorReceipt({ keyId, privateKey, payload } = {}) {
  if (typeof keyId !== "string" || !ID.test(keyId) || !validPayload(payload)) {
    throw new Error("evaluator_receipt_invalid");
  }
  if (!(privateKey instanceof crypto.KeyObject) || privateKey.type !== "private" ||
    privateKey.asymmetricKeyType !== "ed25519") throw new Error("ed25519_private_key_required");
  const body = orderedPayload(payload);
  const signature = crypto.sign(null, signingBytes(keyId, body), privateKey).toString("base64url");
  return JSON.stringify({ schemaVersion: 1, keyId, payload: body, signature });
}

// Remote signing uses exactly the existing wire format and checks the returned signature locally.
async function signEvaluatorReceiptRemotely({ keyId, publicKeyPem, payload, sign } = {}) {
  if (typeof keyId !== "string" || !ID.test(keyId) || !validPayload(payload) || typeof sign !== "function") {
    throw new Error("evaluator_receipt_invalid");
  }
  if (typeof publicKeyPem !== "string" || publicKeyPem.length > 1024 ||
    !/^-----BEGIN PUBLIC KEY-----\r?\n/.test(publicKeyPem)) throw new Error("ed25519_public_key_required");
  const publicKey = crypto.createPublicKey(publicKeyPem);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("ed25519_public_key_required");
  const body = orderedPayload(payload);
  const bytes = signingBytes(keyId, body);
  const signature = await sign(Buffer.from(bytes));
  if (!Buffer.isBuffer(signature) || signature.length !== 64 || !crypto.verify(null, bytes, publicKey, signature)) {
    throw new Error("evaluator_signature_invalid");
  }
  return JSON.stringify({ schemaVersion: 1, keyId, payload: body, signature: signature.toString("base64url") });
}

function parseEvaluatorReceipt(serialized) {
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > MAX_RECEIPT_BYTES) {
    return null;
  }
  try {
    const envelope = JSON.parse(serialized);
    if (!exactKeys(envelope, ["schemaVersion", "keyId", "payload", "signature"]) ||
      envelope.schemaVersion !== 1 || typeof envelope.keyId !== "string" || !ID.test(envelope.keyId) ||
      !validPayload(envelope.payload) || typeof envelope.signature !== "string" ||
      !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature)) return null;
    const signature = Buffer.from(envelope.signature, "base64url");
    if (signature.length !== 64 || signature.toString("base64url") !== envelope.signature) return null;
    const canonical = JSON.stringify({ schemaVersion: 1, keyId: envelope.keyId,
      payload: orderedPayload(envelope.payload), signature: envelope.signature });
    // Exact encoding rejects duplicate JSON keys, extra fields and alternate signed interpretations.
    if (serialized !== canonical) return null;
    return Object.freeze({ ...envelope, payload: Object.freeze(envelope.payload) });
  } catch (_error) {
    return null;
  }
}

function rejection(error) {
  return Object.freeze({ ok: false, error, authenticated: false,
    countsTowardGenuineCorpus: false, ...NO_AWARD });
}

function verifyEvaluatorReceipt(serialized, context = {}) {
  const envelope = parseEvaluatorReceipt(serialized);
  if (!envelope) return rejection("evaluator_receipt_invalid");
  const { trust, expected, now } = context;
  const payload = envelope.payload;
  if (!positiveInteger(now)) return rejection("trusted_clock_required");
  if (!trust || trust.keyId !== envelope.keyId || trust.revoked !== false ||
    !positiveInteger(trust.notBefore) || !positiveInteger(trust.notAfter) ||
    trust.notAfter <= trust.notBefore || typeof trust.publicKeyPem !== "string" ||
    trust.publicKeyPem.length > 1024 ||
    !/^-----BEGIN PUBLIC KEY-----\r?\n/.test(trust.publicKeyPem)) {
    return rejection("evaluator_trust_unavailable");
  }
  if (payload.evaluatorRepository !== trust.evaluatorRepository || payload.evaluatorCommit !== trust.evaluatorCommit) {
    return rejection("evaluator_identity_mismatch");
  }
  if (now < trust.notBefore || now >= trust.notAfter || payload.registeredAt < trust.notBefore ||
    payload.expiresAt > trust.notAfter) return rejection("evaluator_trust_expired");
  if (!expected || !BINDING_FIELDS.every((key) => Object.hasOwn(expected, key) && expected[key] === payload[key])) {
    return rejection("evaluator_task_binding_mismatch");
  }
  if (payload.evidenceClass === "prospective_no_award" && trust.independenceApproved !== true) {
    return rejection("independent_control_not_approved");
  }
  if (payload.issuedAt > now || now >= payload.expiresAt || now - payload.evaluatedAt > MAX_RECEIPT_AGE_MS) {
    return rejection("evaluator_receipt_stale_or_future");
  }
  try {
    const publicKey = crypto.createPublicKey(trust.publicKeyPem);
    if (publicKey.asymmetricKeyType !== "ed25519" || !crypto.verify(null,
      signingBytes(envelope.keyId, payload), publicKey, Buffer.from(envelope.signature, "base64url"))) {
      return rejection("evaluator_signature_invalid");
    }
  } catch (_error) {
    return rejection("evaluator_signature_invalid");
  }
  return Object.freeze({ ok: true, error: null, authenticated: true, payload,
    receiptSha256: crypto.createHash("sha256").update(serialized, "utf8").digest("hex"),
    // Import authenticates the owner's statement; corpus admission is a separate existing gate.
    countsTowardGenuineCorpus: false, ...NO_AWARD });
}

module.exports = Object.freeze({ MAX_RECEIPT_BYTES, MAX_RECEIPT_AGE_MS, BINDING_FIELDS, NO_AWARD,
  signEvaluatorReceipt, signEvaluatorReceiptRemotely, parseEvaluatorReceipt, verifyEvaluatorReceipt });
