"use strict";
const crypto = require("node:crypto");
const c = require("../../cloud/history-checkpoint/contract.js");
const n = require("../../cloud/history-checkpoint/cloud-run-runtime.js");
const { WORKER_JOB } = require("../../cloud/history-checkpoint/cloud-run-observation.js");

// Ephemeral keys and synthetic provider IDs; never real credentials or work.
function nativePolicyFixture(config, source, receiptTrust = {}) {
  const key = crypto.generateKeyPairSync("ed25519");
  const evaluatorTemplate = { serviceAccount: "evaluator-worker@focustrack-eval-20260927.iam.gserviceaccount.com",
    maxRetries: 0, timeout: "300s", containers: [{ image: `us-central1-docker.pkg.dev/focustrack-eval-20260927/evaluator-vault/vault@sha256:${"8".repeat(64)}`,
      command: ["node"], args: ["cloud/evaluator-vault/worker.js"], env: [{ name: "BINDING_JSON", value: "{}" }] }] };
  const evaluator = { job: WORKER_JOB, jobUid: "33333333-2222-4333-8444-555555555555", creator: n.INVOKER,
    serviceAccount: evaluatorTemplate.serviceAccount, workerImage: evaluatorTemplate.containers[0].image,
    templateSha256: c.cloudRunTemplateSha256(evaluatorTemplate) };
  const policy = { enabled: true, runtime: { kind: n.KIND, job: n.JOB, jobUid: config.jobUid, image: config.image,
    templateSha256: config.templateSha256, enrollmentId: config.enrollmentId },
    observationSelection: { taskId: config.taskId, enrollmentId: config.enrollmentId, registrationSha256: config.registrationSha256,
      profileBindingSha256: config.profileBindingSha256, expiresAt: config.expiresAt, evaluator },
    sourceReader: { repository: source.sourceRepository, repositoryId: source.sourceRepositoryId, repositoryOwnerId: source.sourceOwnerId,
      appIdVersion: "projects/818502899155/secrets/evaluator-github-app-id/versions/1",
      installationIdVersion: "projects/818502899155/secrets/evaluator-github-app-installation-id/versions/1",
      privateKeyVersion: "projects/818502899155/secrets/evaluator-github-app-private-key/versions/1" },
    keyVersion: "projects/focustrack-eval-20260927/locations/us-central1/keyRings/test-only/cryptoKeys/prior-history-checkpoints/cryptoKeyVersions/1",
    publicKeySha256: c.hash(key.publicKey.export({ type: "spki", format: "der" })),
    checkpointTrust: { publicKeyPem: key.publicKey.export({ type: "spki", format: "pem" }), notBefore: 1, notAfter: config.expiresAt + 1, revoked: false },
    receiptTrust };
  return { policy, evaluatorTemplate, evaluator };
}
module.exports = { nativePolicyFixture };
