"use strict";

const crypto = require("node:crypto");

const POLICY_FIELDS = Object.freeze(["schemaVersion", "keyId", "keyVersion", "publicKeyPem", "publicKeySha256",
  "workloadIdentityProvider", "repository", "repositoryId", "repositoryOwnerId", "ref", "workflow",
  "workflowSha", "environment", "protectionLevel"]);
const WORKFLOW = ".github/workflows/publish-no-award-evaluator-receipt.yml";
const ENVIRONMENT = "focustrack-evaluator";
const MAX_RESPONSE_BYTES = 32768;

function validateSigningPolicy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
    Object.keys(value).length !== POLICY_FIELDS.length || !POLICY_FIELDS.every(k => Object.hasOwn(value, k)) ||
    !POLICY_FIELDS.filter(k => k !== "schemaVersion").every(k => typeof value[k] === "string") ||
    value.schemaVersion !== 1 || !/^[a-z0-9][a-z0-9_.:-]{0,95}$/.test(value.keyId) ||
    !/^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/locations\/[a-z0-9-]+\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/[A-Za-z0-9_-]+\/cryptoKeyVersions\/[1-9][0-9]*$/.test(value.keyVersion) ||
    !/^projects\/[1-9][0-9]*\/locations\/global\/workloadIdentityPools\/[a-z][a-z0-9-]{3,31}\/providers\/[a-z][a-z0-9-]{3,31}$/.test(value.workloadIdentityProvider) ||
    !/^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/.test(value.repository) ||
    ![value.repositoryId, value.repositoryOwnerId].every(v => typeof v === "string" && /^[1-9][0-9]{0,19}$/.test(v)) ||
    value.ref !== "refs/heads/main" || value.workflow !== WORKFLOW || !/^[a-f0-9]{40}$/.test(value.workflowSha) ||
    value.environment !== ENVIRONMENT || value.protectionLevel !== "SOFTWARE" ||
    typeof value.publicKeyPem !== "string" || value.publicKeyPem.length > 1024 ||
    !/^-----BEGIN PUBLIC KEY-----\r?\n/.test(value.publicKeyPem)) throw new Error("kms_policy_invalid");
  const key = crypto.createPublicKey(value.publicKeyPem);
  const fingerprint = crypto.createHash("sha256").update(key.export({ type: "spki", format: "der" })).digest("hex");
  if (key.asymmetricKeyType !== "ed25519" || fingerprint !== value.publicKeySha256) throw new Error("kms_policy_invalid");
  return Object.freeze({ ...value });
}

// A narrow local precheck; Google verifies the JWT and enforces the provider condition independently.
function validateRunner(policy, environment) {
  const expected = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: policy.repository,
    GITHUB_REPOSITORY_ID: policy.repositoryId, GITHUB_REPOSITORY_OWNER_ID: policy.repositoryOwnerId,
    GITHUB_REF: policy.ref, GITHUB_SHA: policy.workflowSha, GITHUB_WORKFLOW_SHA: policy.workflowSha,
    GITHUB_WORKFLOW_REF: `${policy.repository}/${policy.workflow}@${policy.ref}`,
    GITHUB_EVENT_NAME: "repository_dispatch", RUNNER_ENVIRONMENT: "github-hosted" };
  if (!Object.entries(expected).every(([key, value]) => environment[key] === value)) throw new Error("kms_runner_rejected");
}

function crc32c(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0x82f63b78 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

async function boundedJson(fetcher, url, init = {}, expectedStatus = 200) {
  const response = await fetcher(url, { ...init, redirect: "error", signal: AbortSignal.timeout(15000) });
  if (response.status !== expectedStatus || response.redirected ||
    !/^application\/json(?:;|$)/i.test(response.headers.get("content-type") || "") ||
    Number(response.headers.get("content-length")) > MAX_RESPONSE_BYTES) throw new Error("kms_request_failed");
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw new Error("kms_response_invalid");
      chunks.push(Buffer.from(value));
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function secretString(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 16384 && !/[\s\r\n]/.test(value);
}

function identityUrl(policy, environment) {
  const requestUrl = new URL(environment.ACTIONS_ID_TOKEN_REQUEST_URL);
  if (requestUrl.protocol !== "https:" || requestUrl.port || requestUrl.username || requestUrl.password ||
    requestUrl.hash || !requestUrl.hostname.endsWith(".actions.githubusercontent.com") ||
    !secretString(environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN)) throw new Error("kms_oidc_unavailable");
  requestUrl.searchParams.set("audience", `//iam.googleapis.com/${policy.workloadIdentityProvider}`);
  return requestUrl;
}

async function exchangeIdentity(policy, environment, fetcher, expectedStatus = 200) {
  const identity = await boundedJson(fetcher, identityUrl(policy, environment), {
    headers: { authorization: `Bearer ${environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` }
  });
  if (!secretString(identity.value)) throw new Error("kms_oidc_unavailable");
  return boundedJson(fetcher, "https://sts.googleapis.com/v1/token", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
      grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
      audience: `//iam.googleapis.com/${policy.workloadIdentityProvider}`,
      scope: "https://www.googleapis.com/auth/cloudkms",
      requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
      subjectTokenType: "urn:ietf:params:oauth:token-type:jwt", subjectToken: identity.value
    })
  }, expectedStatus);
}

// Setup-only negative probe: Google must reject the real JWT, not just a local environment check.
async function verifyFederationDenial({ policy: input, environment = process.env, fetch: fetcher = globalThis.fetch } = {}) {
  try {
    const policy = validateSigningPolicy(input);
    if (environment.GITHUB_EVENT_NAME !== "workflow_dispatch") throw new Error("wrong_probe_event");
    const result = await exchangeIdentity(policy, environment, fetcher, 400);
    if (result.error !== "unauthorized_client" || result.error_description !== "The given credential is rejected by the attribute condition.") {
      throw new Error("unexpected_denial");
    }
    return Object.freeze({ ok: true, status: "cloud_attribute_condition_rejected" });
  } catch (_error) {
    throw new Error("kms_denial_not_proven");
  }
}

function createKmsSigner({ policy: input, environment = process.env, fetch: fetcher = globalThis.fetch } = {}) {
  const policy = validateSigningPolicy(input);
  validateRunner(policy, environment);
  identityUrl(policy, environment);
  return async function sign(bytes) {
    try {
      if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 8192) throw new Error("kms_input_invalid");
      const token = await exchangeIdentity(policy, environment, fetcher);
      if (!secretString(token.access_token) || token.token_type !== "Bearer" ||
        !Number.isSafeInteger(token.expires_in) || token.expires_in <= 0 || token.expires_in > 3600) {
        throw new Error("kms_token_invalid");
      }
      const signed = await boundedJson(fetcher, `https://cloudkms.googleapis.com/v1/${policy.keyVersion}:asymmetricSign`, {
        method: "POST", headers: { authorization: `Bearer ${token.access_token}`, "content-type": "application/json" },
        body: JSON.stringify({ data: bytes.toString("base64"), dataCrc32c: String(crc32c(bytes)) })
      });
      const signature = typeof signed.signature === "string" ? Buffer.from(signed.signature, "base64") : Buffer.alloc(0);
      if (signed.name !== policy.keyVersion || signed.protectionLevel !== policy.protectionLevel ||
        signed.verifiedDataCrc32c !== true || signature.length !== 64 || signature.toString("base64") !== signed.signature ||
        String(crc32c(signature)) !== signed.signatureCrc32c ||
        !crypto.verify(null, bytes, policy.publicKeyPem, signature)) throw new Error("kms_signature_invalid");
      return signature;
    } catch (_error) {
      // Cloud error bodies and fetch errors can contain credentials. Never include them in diagnostics.
      throw new Error("kms_signing_failed");
    }
  };
}

function federationPolicy(input) {
  const policy = validateSigningPolicy(input);
  const claims = { repository_id: policy.repositoryId, repository_owner_id: policy.repositoryOwnerId,
    repository: policy.repository, ref: policy.ref,
    workflow_ref: `${policy.repository}/${policy.workflow}@${policy.ref}`, workflow_sha: policy.workflowSha,
    environment: policy.environment, event_name: "repository_dispatch", runner_environment: "github-hosted" };
  return Object.freeze({
    issuerUri: "https://token.actions.githubusercontent.com",
    allowedAudiences: [`//iam.googleapis.com/${policy.workloadIdentityProvider}`],
    attributeMapping: { "google.subject": "assertion.repository_id",
      ...Object.fromEntries(Object.keys(claims).map(key => [`attribute.${key}`, `assertion.${key}`])) },
    attributeCondition: Object.entries(claims).map(([key, value]) => `assertion.${key} == '${value}'`).join(" && "),
    member: `principal://iam.googleapis.com/${policy.workloadIdentityProvider.split("/providers/")[0]}/subject/${policy.repositoryId}`,
    permissions: ["cloudkms.cryptoKeyVersions.useToSign"],
    resource: policy.keyVersion.split("/cryptoKeyVersions/")[0]
  });
}

module.exports = Object.freeze({ validateSigningPolicy, validateRunner, federationPolicy, createKmsSigner, verifyFederationDenial, crc32c });
