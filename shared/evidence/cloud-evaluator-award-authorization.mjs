export const CLOUD_AWARD_DOMAIN = "focustrack:cloud-evaluator-award-authorization:v1\n";

export const CLOUD_AWARD_POLICY_FIELDS = Object.freeze([
  "schemaVersion", "authority", "evidenceClass", "policyId", "taskId", "workReceiptId",
  "profileBindingSha256", "registrationSha256", "criteriaSha256",
  "evaluatorKeyId", "evaluatorRepository", "evaluatorCommit",
  "xpAmount", "notBefore", "notAfter"
]);

export const CLOUD_AWARD_FIELDS = Object.freeze([
  "schemaVersion", "authority", "evidenceClass", "policyId", "taskId", "workReceiptId",
  "profileBindingSha256", "registrationSha256", "criteriaSha256",
  "evaluatorKeyId", "evaluatorRepository", "evaluatorCommit",
  "evaluatorReceiptSha256", "decisionPackageSha256", "xpAmount",
  "issuedAt", "expiresAt"
]);

const ID = /^[a-z0-9][a-z0-9_.:-]{0,95}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const REPOSITORY = /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/;
const TASK = /^codex_prospective_([a-f0-9]{24})$/;
const DAY_MS = 24 * 60 * 60 * 1000;

function exactKeys(value, fields) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field));
}

export function validCloudAwardPolicy(policy) {
  if (!exactKeys(policy, CLOUD_AWARD_POLICY_FIELDS)) return false;
  const taskSuffix = typeof policy.taskId === "string" ? TASK.exec(policy.taskId)?.[1] : null;
  return policy.schemaVersion === 1 && policy.authority === "single_task_10_xp" &&
    policy.evidenceClass === "prospective_award" &&
    typeof policy.policyId === "string" && ID.test(policy.policyId) &&
    taskSuffix !== null && policy.workReceiptId === `codex_stop_${taskSuffix}` &&
    ["profileBindingSha256", "registrationSha256", "criteriaSha256"]
      .every((field) => typeof policy[field] === "string" && SHA256.test(policy[field])) &&
    typeof policy.evaluatorKeyId === "string" && ID.test(policy.evaluatorKeyId) &&
    typeof policy.evaluatorRepository === "string" && REPOSITORY.test(policy.evaluatorRepository) &&
    typeof policy.evaluatorCommit === "string" && COMMIT.test(policy.evaluatorCommit) &&
    policy.xpAmount === 10 && Number.isSafeInteger(policy.notBefore) && policy.notBefore > 0 &&
    Number.isSafeInteger(policy.notAfter) && policy.notAfter > policy.notBefore &&
    policy.notAfter - policy.notBefore <= 7 * DAY_MS;
}

function validAuthorizationShape(payload) {
  if (!exactKeys(payload, CLOUD_AWARD_FIELDS)) return false;
  const taskSuffix = typeof payload.taskId === "string" ? TASK.exec(payload.taskId)?.[1] : null;
  return payload.schemaVersion === 1 && payload.authority === "single_task_10_xp" &&
    payload.evidenceClass === "prospective_award" &&
    typeof payload.policyId === "string" && ID.test(payload.policyId) &&
    taskSuffix !== null && payload.workReceiptId === `codex_stop_${taskSuffix}` &&
    ["profileBindingSha256", "registrationSha256", "criteriaSha256",
      "evaluatorReceiptSha256", "decisionPackageSha256"]
      .every((field) => typeof payload[field] === "string" && SHA256.test(payload[field])) &&
    typeof payload.evaluatorKeyId === "string" && ID.test(payload.evaluatorKeyId) &&
    typeof payload.evaluatorRepository === "string" && REPOSITORY.test(payload.evaluatorRepository) &&
    typeof payload.evaluatorCommit === "string" && COMMIT.test(payload.evaluatorCommit) &&
    payload.xpAmount === 10 && Number.isSafeInteger(payload.issuedAt) && payload.issuedAt > 0 &&
    Number.isSafeInteger(payload.expiresAt) && payload.expiresAt > payload.issuedAt &&
    payload.expiresAt - payload.issuedAt <= DAY_MS;
}

// This only validates a proposed wire payload. A caller must separately verify
// both signatures, the frozen evaluation, and the complete intelligence decision.
export function validCloudAwardAuthorization(payload, policy, expected, now) {
  if (!validCloudAwardPolicy(policy) || !validAuthorizationShape(payload) ||
    !expected || typeof expected !== "object" || Array.isArray(expected) ||
    !Number.isSafeInteger(now) || now <= 0) return false;
  const policyFields = CLOUD_AWARD_POLICY_FIELDS.filter((field) => !["notBefore", "notAfter"].includes(field));
  return policyFields.every((field) => payload[field] === policy[field]) &&
    typeof expected.evaluatorReceiptSha256 === "string" && SHA256.test(expected.evaluatorReceiptSha256) &&
    typeof expected.decisionPackageSha256 === "string" && SHA256.test(expected.decisionPackageSha256) &&
    payload.evaluatorReceiptSha256 === expected.evaluatorReceiptSha256 &&
    payload.decisionPackageSha256 === expected.decisionPackageSha256 &&
    Number.isSafeInteger(payload.issuedAt) && payload.issuedAt >= policy.notBefore &&
    payload.issuedAt <= now && Number.isSafeInteger(payload.expiresAt) &&
    payload.expiresAt > now && payload.expiresAt > payload.issuedAt &&
    payload.expiresAt <= policy.notAfter && payload.expiresAt - payload.issuedAt <= DAY_MS;
}

export function cloudAwardSigningText(payload) {
  if (!validAuthorizationShape(payload)) throw new Error("cloud_award_payload_invalid");
  return CLOUD_AWARD_DOMAIN + JSON.stringify(Object.fromEntries(
    CLOUD_AWARD_FIELDS.map((field) => [field, payload[field]])
  ));
}
