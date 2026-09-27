"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { createKmsSigner, validateSigningPolicy, verifyFederationDenial } = require("./evaluator-kms-signer.js");
const { signEvaluatorReceiptRemotely, verifyEvaluatorReceipt, NO_AWARD } = require("../shared/evidence/signed-evaluator-receipt.js");

async function probe({ policy: input, environment = process.env, fetch = globalThis.fetch, now = Date.now() }) {
  const policy = validateSigningPolicy(input);
  if (environment.GITHUB_EVENT_NAME === "workflow_dispatch") {
    const denied = await verifyFederationDenial({ policy, environment, fetch });
    return { schemaVersion: 1, ...denied, evidenceClass: "synthetic_setup_only",
      countsTowardGenuineCorpus: false, ...NO_AWARD };
  }
  // These are visibly synthetic fixtures, not claims about registered work or an XP award.
  const payload = { schemaVersion: 1, taskId: "cloud_signing_setup_probe", receiptId: "cloud_signing_setup_receipt",
    registrationSha256: "1".repeat(64), criteriaSha256: "2".repeat(64), sourceRepository: policy.repository,
    baselineCommit: "3".repeat(40), baselineSha256: "4".repeat(64), candidateCommit: "5".repeat(40), candidateSha256: "6".repeat(64),
    registeredAt: now - 6000, baselineAt: now - 5000, workStartedAt: now - 4000, evidenceClass: "synthetic_setup_only",
    evaluatorRepository: policy.repository, evaluatorCommit: policy.workflowSha,
    runId: environment.GITHUB_RUN_ID, runAttempt: Number(environment.GITHUB_RUN_ATTEMPT),
    evaluatedAt: now - 3000, issuedAt: now, expiresAt: now + 60000,
    baselineResult: "failed", result: "passed", checkCount: 1, passedCount: 1, noAward: true };
  const receipt = await signEvaluatorReceiptRemotely({ keyId: policy.keyId, publicKeyPem: policy.publicKeyPem,
    payload, sign: createKmsSigner({ policy, environment, fetch }) });
  const verified = verifyEvaluatorReceipt(receipt, { now, expected: payload, trust: {
    keyId: policy.keyId, publicKeyPem: policy.publicKeyPem, evaluatorRepository: policy.repository,
    evaluatorCommit: policy.workflowSha, notBefore: now - 10000, notAfter: now + 120000,
    revoked: false, independenceApproved: false
  } });
  if (!verified.ok) throw new Error("cloud_probe_signature_invalid");
  return { schemaVersion: 1, ok: true, status: "cloud_signing_setup_passed", evidenceClass: "synthetic_setup_only",
    receipt, publicKeyPem: policy.publicKeyPem, keyVersion: policy.keyVersion,
    countsTowardGenuineCorpus: false, ...NO_AWARD };
}

if (require.main === module) {
  Promise.resolve().then(async () => {
    const serialized = process.env.FOCUSTRACK_KMS_SIGNING_POLICY;
    if (typeof serialized !== "string" || serialized.length > 8192) throw new Error("policy_missing");
    const result = await probe({ policy: JSON.parse(serialized) });
    const output = path.resolve(__dirname, "../proof/cloud-signing-probe.json");
    fs.mkdirSync(path.dirname(output), { recursive: true });
    fs.writeFileSync(output, JSON.stringify(result, null, 2), { flag: "wx" });
    process.stdout.write(JSON.stringify({ ok: result.ok, status: result.status, evidenceClass: result.evidenceClass }) + "\n");
  }).catch(() => {
    process.stdout.write('{"ok":false,"status":"cloud_probe_failed"}\n');
    process.exitCode = 1;
  });
}

module.exports = Object.freeze({ probe });
