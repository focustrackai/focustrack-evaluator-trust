"use strict";

const crypto = require("node:crypto");
const { verifyEvaluatorReceipt, BINDING_FIELDS } = require("../../shared/evidence/signed-evaluator-receipt.js");
const trust = require("../../execution-trust-memory.js");
const DOMAIN = "focustrack:protected-prior-checkpoint:production:v1\n";
const KEY_ID = "cloud_prior_history_checkpoint_v1";
const HASH = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const ID = /^[1-9][0-9]{0,19}$/;
const OPAQUE = /^[a-f0-9]{32}$/;
const MAX_BYTES = 256 * 1024;
const CLOUD_RUN = "google_cloud_run_v2";
const EXECUTION = /^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z][a-z0-9-]{0,62}\/jobs\/[a-z][a-z0-9-]{0,62}\/executions\/[a-z][a-z0-9-]{0,62}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const IMAGE = /^[a-z0-9-]+-docker\.pkg\.dev\/[a-z0-9-]+\/[a-z0-9_-]+\/[a-z0-9_./-]+@sha256:[a-f0-9]{64}$/;
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
function reject(code) { throw new Error(code); }
function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.hasOwn(value, "toJSON")) reject("checkpoint_payload_rejected");
  return `{${Object.keys(value).sort().map(key => JSON.stringify(key) + ":" + canonical(value[key])).join(",")}}`;
}
function parse(bytes) {
  if (typeof bytes !== "string" || Buffer.byteLength(bytes) > MAX_BYTES) reject("checkpoint_payload_rejected");
  let value; try { value = JSON.parse(bytes); } catch (_) { reject("checkpoint_payload_rejected"); }
  if (canonical(value) !== bytes) reject("checkpoint_payload_rejected");
  return value;
}
function exact(value, fields) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).length !== fields.length ||
      fields.some(field => !Object.hasOwn(value, field))) reject("checkpoint_fields_rejected");
}
const positive = n => Number.isSafeInteger(n) && n > 0;
function relativePath(value) {
  return typeof value === "string" && /^[A-Za-z0-9_.\/-]{1,240}$/.test(value) &&
    value.split("/").every(part => part && part !== "." && part !== "..");
}
function repository(value) { return typeof value === "string" && /^[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+$/.test(value); }
function validateCloudRunEvaluator(value) {
  exact(value, ["provider", "execution", "uid", "creator", "serviceAccount", "workerImage", "templateSha256"]);
  if (value.provider !== CLOUD_RUN || !EXECUTION.test(value.execution || "") || !UUID.test(value.uid || "") ||
      !HASH.test(value.templateSha256 || "") || !IMAGE.test(value.workerImage || ""))
    reject("cloud_run_identity_rejected");
  const project = value.execution.split("/")[1];
  for (const principal of [value.creator, value.serviceAccount]) {
    if (typeof principal !== "string" || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]@/.test(principal) ||
        !principal.endsWith(`@${project}.iam.gserviceaccount.com`)) reject("cloud_run_identity_rejected");
  }
}
// Pin the entire task template, not only its image. The sole dynamic binding is
// verified separately; command/args, secret references and all other settings stay pinned.
function cloudRunTemplateSha256(template) {
  const bytes = canonical(template);
  if (Buffer.byteLength(bytes) > MAX_BYTES) reject("cloud_run_template_rejected");
  const copy = parse(bytes);
  if (!Array.isArray(copy.containers) || copy.containers.length !== 1 || !Array.isArray(copy.containers[0]?.env))
    reject("cloud_run_template_rejected");
  const env = copy.containers[0].env;
  if (env.some(e => !e || typeof e.name !== "string") || new Set(env.map(e => e.name)).size !== env.length)
    reject("cloud_run_template_rejected");
  const binding = env.filter(e => e.name === "BINDING_JSON");
  if (binding.length !== 1) reject("cloud_run_template_rejected");
  exact(binding[0], ["name", "value"]);
  if (typeof binding[0].value !== "string" || Buffer.byteLength(binding[0].value) > 16384)
    reject("cloud_run_template_rejected");
  binding[0].value = "<verified-task-binding>";
  return hash(canonical(copy));
}
async function observeCloudRun(row, payload, readCloudRunExecution, now) {
  if (typeof readCloudRunExecution !== "function") reject("cloud_run_reader_required");
  const pin = row.evaluator;
  validateCloudRunEvaluator(pin);
  const run = await readCloudRunExecution(pin.execution);
  const job = pin.execution.split("/executions/")[0];
  const completed = Array.isArray(run?.conditions) ? run.conditions.filter(c => c.type === "Completed") : [];
  const created = Date.parse(run?.createTime), started = Date.parse(run?.startTime), ended = Date.parse(run?.completionTime);
  // ProtoJSON omits default false/zero scalars. Explicit success, counts,
  // generation agreement and completed timestamps are still mandatory.
  // The API can return the parent job as a short name. The full execution
  // resource remains exact; do not accept suffix-only or cross-project matches.
  if (run?.name !== pin.execution || run.uid !== pin.uid || (run.job !== job && run.job !== job.split("/").pop()) ||
      run.creator !== pin.creator || !ID.test(run.generation || "") || run.observedGeneration !== run.generation ||
      (run.reconciling !== undefined && run.reconciling !== false) || run.deleteTime || run.expireTime || completed.length !== 1 ||
      completed[0].state !== "CONDITION_SUCCEEDED" || run.taskCount !== 1 || run.succeededCount !== 1 ||
      ["runningCount", "failedCount", "cancelledCount", "retriedCount"].some(k => run[k] !== undefined && run[k] !== 0) ||
      ![created, started, ended].every(positive) || created < payload.workStartedAt || started < created || ended < started || ended > now ||
      payload.evaluatedAt < started || payload.issuedAt > ended || payload.runAttempt !== 1 ||
      !positive(Number(payload.runId)) || Number(payload.runId) < started || Number(payload.runId) > payload.evaluatedAt ||
      run.template?.serviceAccount !== pin.serviceAccount || run.template?.containers?.[0]?.image !== pin.workerImage ||
      cloudRunTemplateSha256(run.template) !== pin.templateSha256) reject("cloud_run_execution_rejected");
  const serialized = run.template.containers[0].env.find(e => e.name === "BINDING_JSON").value;
  let binding;
  try { binding = JSON.parse(serialized); } catch (_) { reject("cloud_run_binding_rejected"); }
  exact(binding, BINDING_FIELDS);
  if (JSON.stringify(binding) !== serialized || BINDING_FIELDS.some(k => binding[k] !== payload[k]))
    reject("cloud_run_binding_rejected");
  return { provider: CLOUD_RUN, execution: pin.execution, uid: pin.uid, workerImage: pin.workerImage,
    templateSha256: pin.templateSha256 };
}
function validateEnrollment(serialized, enrollmentId, now) {
  const input = parse(serialized);
  exact(input, ["schemaVersion", "enrollmentId", "profileBindingSha256", "enrolledAt", "expiresAt", "priorReceipts"]);
  if (!OPAQUE.test(enrollmentId || "") || input.enrollmentId !== enrollmentId || ![1, 2].includes(input.schemaVersion) ||
      !HASH.test(input.profileBindingSha256 || "") || !positive(input.enrolledAt) || input.enrolledAt > now ||
      !positive(input.expiresAt) || input.expiresAt <= now || !Array.isArray(input.priorReceipts) ||
      input.priorReceipts.length < 1 || input.priorReceipts.length > 50) reject("enrollment_rejected");
  const seen = new Set();
  for (const row of input.priorReceipts) {
    exact(row, ["workReceiptId", "processedAt", "serializedReceipt", "receiptSha256", "expected", "source",
      "evaluator", "profileJoin"]);
    exact(row.profileJoin, ["profileBindingSha256", "workReceiptId", "receiptSha256", "joinedAt"]);
    exact(row.source, ["repository", "repositoryId", "repositoryOwnerId", "subjectPath"]);
    if (input.schemaVersion === 2) validateCloudRunEvaluator(row.evaluator);
    else exact(row.evaluator, ["repositoryId", "repositoryOwnerId", "workflowPath", "workflowId", "workflowSha256", "requiredJobNames"]);
    exact(row.expected, BINDING_FIELDS);
    const join = row.profileJoin;
    if (!/^codex_stop_[a-f0-9]{24}$/.test(row.workReceiptId || "") || seen.has(row.workReceiptId) ||
        join.profileBindingSha256 !== input.profileBindingSha256 || join.workReceiptId !== row.workReceiptId ||
        join.receiptSha256 !== row.receiptSha256 || !positive(join.joinedAt) || join.joinedAt > input.enrolledAt ||
        !positive(row.processedAt) || row.processedAt > input.enrolledAt || !HASH.test(row.receiptSha256 || "") ||
        hash(row.serializedReceipt) !== row.receiptSha256 || !repository(row.source.repository) ||
        !ID.test(row.source.repositoryId || "") || !ID.test(row.source.repositoryOwnerId || "") ||
        !relativePath(row.source.subjectPath) || (input.schemaVersion === 1 && (!ID.test(row.evaluator.repositoryId || "") ||
        !ID.test(row.evaluator.repositoryOwnerId || "") || !ID.test(row.evaluator.workflowId || "") ||
        !relativePath(row.evaluator.workflowPath) || !row.evaluator.workflowPath.startsWith(".github/workflows/") ||
        !HASH.test(row.evaluator.workflowSha256 || "") ||
        !Array.isArray(row.evaluator.requiredJobNames) || !row.evaluator.requiredJobNames.length ||
        row.evaluator.requiredJobNames.some(name => typeof name !== "string" || !/^[A-Za-z0-9_. -]{1,120}$/.test(name)) ||
        new Set(row.evaluator.requiredJobNames).size !== row.evaluator.requiredJobNames.length)))
      reject("profile_source_join_unsupported");
    seen.add(row.workReceiptId);
  }
  return input;
}
function githubIdentity(repo, expected) {
  if (typeof repo?.full_name !== "string" || repo.full_name.toLowerCase() !== expected.repository.toLowerCase() || String(repo.id) !== expected.repositoryId ||
      String(repo.owner?.id) !== expected.repositoryOwnerId) reject("github_identity_rejected");
}
// This port is wired to authenticated api.github.com HTTPS reads by the runner.
// Offline tests supply responses; no producer-supplied "verified" status is trusted.
async function observePriorReceipts(input, { githubJson, readCloudRunExecution, receiptTrust, now }) {
  if (![1, 2].includes(input?.schemaVersion) || typeof githubJson !== "function" || !positive(now))
    reject("checkpoint_source_dependencies_rejected");
  const facts = [], seen = new Set();
  for (const row of input.priorReceipts) {
    const verified = verifyEvaluatorReceipt(row.serializedReceipt, { trust: receiptTrust, expected: row.expected, now: row.processedAt });
    const p = verified.payload, suffix = row.workReceiptId.slice(-24);
    if (!verified.ok || !verified.authenticated || p.taskId !== `codex_prospective_${suffix}` ||
        p.receiptId !== `codex_evaluator_${suffix}` || verified.receiptSha256 !== row.receiptSha256 ||
        p.evidenceClass !== "prospective_no_award" || p.result !== "passed" ||
        p.sourceRepository !== row.source.repository || p.evaluatedAt > row.processedAt ||
        p.evaluatedAt > now || row.profileJoin.joinedAt < p.issuedAt) reject("signed_receipt_join_rejected");
    const identity = input.schemaVersion === 2 ? row.evaluator.uid : `${p.evaluatorRepository}:${p.runId}:${p.runAttempt}:${p.candidateCommit}`;
    if (seen.has(identity)) reject("duplicate_provider_observation");
    seen.add(identity);
    let providerProof;
    if (input.schemaVersion === 2) providerProof = await observeCloudRun(row, p, readCloudRunExecution, now);
    else {
      const base = `/repos/${p.evaluatorRepository}/actions/runs/${p.runId}/attempts/${p.runAttempt}`;
      const workflow = await githubJson(`/repos/${p.evaluatorRepository}/contents/${row.evaluator.workflowPath}?ref=${p.evaluatorCommit}`);
      if (workflow.type !== "file" || workflow.path !== row.evaluator.workflowPath || workflow.encoding !== "base64" ||
          typeof workflow.content !== "string" || workflow.content.length > 256 * 1024 ||
          hash(Buffer.from(workflow.content.replace(/\n/g, ""), "base64")) !== row.evaluator.workflowSha256)
        reject("github_frozen_workflow_proof_unsupported");
      const run = await githubJson(base);
      githubIdentity(run.repository, { repository: p.evaluatorRepository, ...row.evaluator });
      if (String(run.id) !== p.runId || run.run_attempt !== p.runAttempt || run.head_sha !== p.evaluatorCommit ||
          !COMMIT.test(run.head_sha || "") || run.path !== row.evaluator.workflowPath ||
          String(run.workflow_id) !== row.evaluator.workflowId || run.event !== "workflow_dispatch" ||
          run.head_branch !== "main" || run.status !== "completed" || run.conclusion !== "success" ||
          !positive(Date.parse(run.created_at)) || Date.parse(run.created_at) < p.workStartedAt ||
          !positive(Date.parse(run.updated_at)) || Date.parse(run.updated_at) > row.processedAt ||
          Date.parse(run.updated_at) < Date.parse(run.created_at))
        reject("github_run_provenance_rejected");
      const jobs = await githubJson(base + "/jobs?per_page=100");
      if (!Array.isArray(jobs.jobs) || jobs.total_count !== jobs.jobs.length || jobs.jobs.length > 100 ||
          row.evaluator.requiredJobNames.some(name => {
            const matched = jobs.jobs.filter(job => job.name === name);
            return matched.length !== 1 || matched[0].run_id !== run.id || matched[0].run_attempt !== p.runAttempt ||
              matched[0].head_sha !== p.evaluatorCommit || matched[0].status !== "completed" || matched[0].conclusion !== "success" ||
              !Array.isArray(matched[0].steps) || !matched[0].steps.length ||
              matched[0].steps.some(step => step.status !== "completed" || step.conclusion !== "success");
          })) reject("github_job_proof_unsupported");
    }
    const sourceRepo = await githubJson(`/repos/${row.source.repository}`);
    githubIdentity(sourceRepo, row.source);
    const file = await githubJson(`/repos/${row.source.repository}/contents/${row.source.subjectPath}?ref=${p.candidateCommit}`);
    if (file.type !== "file" || file.path !== row.source.subjectPath || file.encoding !== "base64" ||
        typeof file.content !== "string" || file.content.length > 2 * 1024 * 1024) reject("github_source_proof_unsupported");
    const encoded = file.content.replace(/\n/g, "");
    const sourceBytes = Buffer.from(encoded, "base64");
    if (sourceBytes.toString("base64") !== encoded || sourceBytes.length !== file.size ||
        hash(sourceBytes) !== p.candidateSha256) reject("github_source_digest_rejected");
    // No candidate module execution, logs, contents, or inferred impact enter output.
    facts.push({ workReceiptId: row.workReceiptId, processedAt: row.processedAt, receiptSha256: row.receiptSha256,
      evaluatorRepository: p.evaluatorRepository, evaluatorCommit: p.evaluatorCommit, runId: p.runId,
      runAttempt: p.runAttempt, candidateCommit: p.candidateCommit, candidateSha256: p.candidateSha256,
      evaluatedAt: p.evaluatedAt, ...(providerProof ? { providerProof } : {}) });
  }
  return facts.sort((a, b) => a.processedAt - b.processedAt || a.workReceiptId.localeCompare(b.workReceiptId));
}
function deriveHistory(facts, checkpointAt) {
  let state = trust.createTrustMemoryState({ createdAt: checkpointAt, updatedAt: checkpointAt });
  for (const fact of facts) {
    // Passing code checks is not aligned impact or a clean full-intelligence verdict.
    state = trust.updateTrustMemoryFromIntegrityResult(state, { verifier: { verifierId: fact.providerProof ? "cloud_run_frozen_receipt" : "github_frozen_receipt" },
      integrityResult: { integrityStatus: "insufficient_evidence", requiresMoreEvidence: true } });
    for (const bucket of Object.values(state.profiles)) for (const profile of Object.values(bucket)) {
      profile.createdAt = checkpointAt; profile.updatedAt = checkpointAt; profile.lastOutcomeAt = checkpointAt;
    }
    state.updatedAt = checkpointAt;
    const event = state.recentEvents[state.recentEvents.length - 1];
    event.timestamp = checkpointAt; event.eventid = `prior_${fact.receiptSha256}`;
  }
  return { trustMemoryState: state, memoryInputs: {} };
}
function validateFacts(facts, checkpointAt, schemaVersion = 1) {
  if (!Array.isArray(facts) || !facts.length || facts.length > 50) reject("checkpoint_fact_rejected");
  const receipts = new Set(), hashes = new Set(), runs = new Set(); let prior;
  for (const f of facts) {
    exact(f, ["workReceiptId", "processedAt", "receiptSha256", "evaluatorRepository", "evaluatorCommit", "runId",
      "runAttempt", "candidateCommit", "candidateSha256", "evaluatedAt", ...(schemaVersion === 2 ? ["providerProof"] : [])]);
    if (schemaVersion === 2) {
      exact(f.providerProof, ["provider", "execution", "uid", "workerImage", "templateSha256"]);
      const p = f.providerProof;
      if (p.provider !== CLOUD_RUN || !EXECUTION.test(p.execution || "") || !UUID.test(p.uid || "") ||
          !HASH.test(p.templateSha256 || "") || !IMAGE.test(p.workerImage || ""))
        reject("checkpoint_fact_rejected");
    }
    const run = schemaVersion === 2 ? f.providerProof.uid : `${f.evaluatorRepository}:${f.runId}:${f.runAttempt}:${f.candidateCommit}`;
    if (!/^codex_stop_[a-f0-9]{24}$/.test(f.workReceiptId || "") || !positive(f.processedAt) || f.processedAt > checkpointAt ||
        !positive(f.evaluatedAt) || f.evaluatedAt > f.processedAt || !HASH.test(f.receiptSha256 || "") ||
        !repository(f.evaluatorRepository) || !COMMIT.test(f.evaluatorCommit || "") || !ID.test(f.runId || "") ||
        !positive(f.runAttempt) || !COMMIT.test(f.candidateCommit || "") || !HASH.test(f.candidateSha256 || "") ||
        receipts.has(f.workReceiptId) || hashes.has(f.receiptSha256) || runs.has(run) ||
        (prior && (prior.processedAt > f.processedAt || (prior.processedAt === f.processedAt && prior.workReceiptId >= f.workReceiptId))))
      reject("checkpoint_fact_rejected");
    receipts.add(f.workReceiptId); hashes.add(f.receiptSha256); runs.add(run); prior = f;
  }
}
function payloadFor(input, facts, inputPin, checkpointAt) {
  // Existing internal callers predate the versioned enrollment input. Their
  // provider-proof-free facts remain v1; external enrollment always requires a version.
  const schemaVersion = input.schemaVersion === undefined ? 1 : input.schemaVersion;
  if (![1, 2].includes(schemaVersion)) reject("checkpoint_input_pin_rejected");
  validateFacts(facts, checkpointAt, schemaVersion);
  if (!facts.length || facts.length !== input.priorReceipts.length || !HASH.test(inputPin.sha256 || "") ||
      !ID.test(inputPin.generation || "") || !positive(inputPin.createdAt) || inputPin.createdAt > checkpointAt)
    reject("checkpoint_input_pin_rejected");
  return { schemaVersion, enrollmentId: input.enrollmentId, profileBindingSha256: input.profileBindingSha256,
    checkpointAt, expiresAt: input.expiresAt, inputPin, receiptProofs: facts, ...deriveHistory(facts, checkpointAt),
    noAward: true, mutatesXp: false, countsTowardGenuineCorpus: false };
}
function signingBytes(serialized) { return Buffer.from(DOMAIN + KEY_ID + "\n" + hash(serialized)); }
function verifyCheckpoint(envelope, { publicKeyPem, notBefore, notAfter, revoked }, expected, now) {
  exact(envelope, ["keyId", "serialized", "sha256", "signature"]);
  const p = parse(envelope.serialized);
  exact(p, ["schemaVersion", "enrollmentId", "profileBindingSha256", "checkpointAt", "expiresAt", "inputPin",
    "receiptProofs", "trustMemoryState", "memoryInputs", "noAward", "mutatesXp", "countsTowardGenuineCorpus"]);
  if (envelope.keyId !== KEY_ID || hash(envelope.serialized) !== envelope.sha256 || revoked !== false ||
      !positive(now) || !positive(notBefore) || !positive(notAfter) || now < notBefore || now >= notAfter ||
      !positive(p.checkpointAt) || p.checkpointAt < notBefore || p.checkpointAt > now ||
      !positive(p.expiresAt) || p.expiresAt <= now || p.expiresAt > notAfter || ![1, 2].includes(p.schemaVersion) ||
      p.enrollmentId !== expected.enrollmentId || !OPAQUE.test(p.enrollmentId || "") ||
      p.profileBindingSha256 !== expected.profileBindingSha256 || !HASH.test(p.profileBindingSha256 || "") ||
      p.noAward !== true || p.mutatesXp !== false || p.countsTowardGenuineCorpus !== false ||
      canonical(p.inputPin) !== canonical(expected.inputPin) || !Array.isArray(p.receiptProofs) || !p.receiptProofs.length ||
      p.receiptProofs.length > 50 || new Set(p.receiptProofs.map(f => f.workReceiptId)).size !== p.receiptProofs.length ||
      p.receiptProofs.some(f => !/^codex_stop_[a-f0-9]{24}$/.test(f.workReceiptId || "") ||
        !HASH.test(f.receiptSha256 || "") || !positive(f.processedAt) || f.processedAt > p.checkpointAt) ||
      typeof envelope.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature) ||
      Buffer.from(envelope.signature, "base64url").toString("base64url") !== envelope.signature)
    reject("checkpoint_binding_rejected");
  exact(p.inputPin, ["generation", "sha256", "createdAt"]);
  if (!ID.test(p.inputPin.generation || "") || !HASH.test(p.inputPin.sha256 || "") ||
      !positive(p.inputPin.createdAt) || p.inputPin.createdAt > p.checkpointAt) reject("checkpoint_input_pin_rejected");
  validateFacts(p.receiptProofs, p.checkpointAt, p.schemaVersion);
  const key = crypto.createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519" || !crypto.verify(null, signingBytes(envelope.serialized), key,
    Buffer.from(envelope.signature, "base64url"))) reject("checkpoint_signature_rejected");
  const derived = deriveHistory(p.receiptProofs, p.checkpointAt);
  if (canonical(derived.trustMemoryState) !== canonical(p.trustMemoryState) ||
      canonical(derived.memoryInputs) !== canonical(p.memoryInputs)) reject("checkpoint_derived_state_rejected");
  return p;
}
// Protected reader adapter, not an award switch. Storage returns authoritative generation/creation metadata.
function createHistorySourceAdapter({ readCheckpoint, checkpointTrust, now = Date.now }) {
  const pinnedTrust = parse(canonical(checkpointTrust));
  return async (snapshot, enrollment) => {
    snapshot = parse(canonical(snapshot)); enrollment = parse(canonical(enrollment));
    exact(enrollment, ["enrollmentId", "outputGeneration", "outputSha256", "inputPin"]);
    if (!OPAQUE.test(enrollment.enrollmentId || "") || !ID.test(enrollment.outputGeneration || "") ||
        !HASH.test(enrollment.outputSha256 || "") || !positive(snapshot.start?.workStartedAt) ||
        !/^codex_prospective_[a-f0-9]{24}$/.test(snapshot.policy?.taskId || "") ||
        !/^codex_stop_[a-f0-9]{24}$/.test(snapshot.policy.workReceiptId || "")) reject("checkpoint_source_binding_rejected");
    const stored = await readCheckpoint(enrollment.enrollmentId, enrollment.outputGeneration);
    if (stored?.generation !== enrollment.outputGeneration || !ID.test(stored.generation || "") ||
        !positive(stored.createdAt) || stored.createdAt >= snapshot.start.workStartedAt ||
        hash(stored.serialized) !== enrollment.outputSha256) reject("checkpoint_custody_rejected");
    const p = verifyCheckpoint(parse(stored.serialized), pinnedTrust, { enrollmentId: enrollment.enrollmentId,
      profileBindingSha256: snapshot.policy.profileBindingSha256, inputPin: enrollment.inputPin }, now());
    if (p.checkpointAt > stored.createdAt || p.checkpointAt >= snapshot.start.workStartedAt ||
        p.receiptProofs.some(f => f.workReceiptId === snapshot.policy.workReceiptId)) reject("checkpoint_history_chronology_rejected");
    return { taskId: snapshot.policy.taskId, profileBindingSha256: p.profileBindingSha256, capturedAt: p.checkpointAt,
      priorReceipts: p.receiptProofs.map(f => ({ workReceiptId: f.workReceiptId, processedAt: f.processedAt })),
      trustMemoryState: p.trustMemoryState, memoryInputs: p.memoryInputs };
  };
}
module.exports = Object.freeze({ DOMAIN, KEY_ID, canonical, parse, hash, OPAQUE, validateEnrollment, observePriorReceipts, cloudRunTemplateSha256,
  payloadFor, signingBytes, verifyCheckpoint, createHistorySourceAdapter });
