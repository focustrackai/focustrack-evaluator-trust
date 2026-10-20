"use strict";

const crypto = require("node:crypto");
const {
  NO_AWARD,
  loadPolicy,
  validBinding,
  cloneAndEvaluate
} = require("./common.js");

const POLICY_BUCKET = /^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$/;
const POSITIVE_ID = /^[1-9][0-9]{0,14}$/;
const SAFE_EVALUATION_FAILURES = new Set([
  "binding_rejected", "subject_rejected", "subject_pin_mismatch",
  "candidate_unchanged", "baseline_not_proven_failing", "worker_rejected",
  "source_clone_failed", "source_fetch_failed", "source_worktree_failed",
  "source_authentication_failed", "source_repository_unavailable",
  "source_authorization_failed", "source_network_unavailable"
]);

function evaluationFailureStatus(error) {
  const reason = typeof error?.message === "string" ? error.message : "";
  return SAFE_EVALUATION_FAILURES.has(reason) ? `evaluation_rejected_${reason}` : "evaluation_rejected";
}

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function serviceConfig(environment) {
  const value = {
    signerUrl: typeof environment.FOCUSTRACK_SIGNER_URL === "string" ? environment.FOCUSTRACK_SIGNER_URL.trim() : "",
    workerSigningToken: typeof environment.FOCUSTRACK_WORKER_SIGNING_TOKEN === "string" ? environment.FOCUSTRACK_WORKER_SIGNING_TOKEN.trim() : "",
    policyBucket: typeof environment.FOCUSTRACK_POLICY_BUCKET === "string" ? environment.FOCUSTRACK_POLICY_BUCKET.trim() : "",
    githubAppId: typeof environment.FOCUSTRACK_GITHUB_APP_ID === "string" ? environment.FOCUSTRACK_GITHUB_APP_ID.trim() : "",
    githubInstallationId: typeof environment.FOCUSTRACK_GITHUB_APP_INSTALLATION_ID === "string" ? environment.FOCUSTRACK_GITHUB_APP_INSTALLATION_ID.trim() : "",
    githubAppPrivateKey: environment.FOCUSTRACK_GITHUB_APP_PRIVATE_KEY
  };
  let signerUrl;
  try { signerUrl = new URL(value.signerUrl); } catch (_error) { return null; }
  if (signerUrl.username || signerUrl.password || value.signerUrl.includes("#")) return null;
  if (!value.signerUrl.startsWith("https://") || value.workerSigningToken.length < 32 || !POLICY_BUCKET.test(value.policyBucket) ||
      !POSITIVE_ID.test(value.githubAppId) || !POSITIVE_ID.test(value.githubInstallationId) ||
      typeof value.githubAppPrivateKey !== "string" || value.githubAppPrivateKey.length > 16 * 1024 ||
      !/^-----BEGIN (?:RSA )?PRIVATE KEY-----\r?\n/.test(value.githubAppPrivateKey)) return null;
  return Object.freeze(value);
}

async function metadataToken(fetch) {
  const response = await fetch("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {
    headers: { "Metadata-Flavor": "Google" }, redirect: "error", signal: AbortSignal.timeout(5000)
  });
  const value = response?.ok ? await response.json().catch(() => null) : null;
  return typeof value?.access_token === "string" && value.access_token.length > 20 ? value.access_token : null;
}

async function loadPolicyTemplate(binding, bucket, fetch) {
  if (!validBinding(binding) || !POLICY_BUCKET.test(bucket)) throw new Error("policy_unavailable");
  const token = await metadataToken(fetch);
  if (!token) throw new Error("policy_unavailable");
  const objectName = `policies/${binding.criteriaSha256}.json`;
  const response = await fetch(`https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o/${encodeURIComponent(objectName)}?alt=media`, {
    headers: { authorization: `Bearer ${token}` }, redirect: "error", signal: AbortSignal.timeout(15_000)
  });
  const serialized = response?.ok ? await response.text() : null;
  const policy = loadPolicy(serialized);
  if (!policy || policy.schemaVersion !== 2 || policy.criteriaSha256 !== binding.criteriaSha256 ||
      policy.sourceRepository !== binding.sourceRepository) throw new Error("policy_unavailable");
  return policy;
}

function createGitHubAppJwt({ appId, privateKey, now = Date.now() }) {
  if (!POSITIVE_ID.test(String(appId)) || typeof privateKey !== "string" || privateKey.length > 16 * 1024 ||
      !/^-----BEGIN (?:RSA )?PRIVATE KEY-----\r?\n/.test(privateKey)) throw new Error("source_access_unavailable");
  const header = base64Url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const issuedAt = Math.floor(now / 1000) - 30;
  const claims = base64Url(JSON.stringify({ iat: issuedAt, exp: issuedAt + 540, iss: String(appId) }));
  const signingInput = `${header}.${claims}`;
  let key;
  try { key = crypto.createPrivateKey(privateKey); } catch (_error) { throw new Error("source_access_unavailable"); }
  return `${signingInput}.${crypto.sign("RSA-SHA256", Buffer.from(signingInput), key).toString("base64url")}`;
}

async function githubInstallationToken({ appId, installationId, privateKey, sourceRepository, fetch, now = Date.now() }) {
  if (!POSITIVE_ID.test(String(installationId)) || typeof sourceRepository !== "string" || !/^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/.test(sourceRepository)) {
    throw new Error("source_access_unavailable");
  }
  const repository = sourceRepository.split("/")[1];
  const response = await fetch(`https://api.github.com/app/installations/${encodeURIComponent(installationId)}/access_tokens`, {
    method: "POST", redirect: "error", signal: AbortSignal.timeout(15_000),
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${createGitHubAppJwt({ appId, privateKey, now })}`,
      "x-github-api-version": "2022-11-28",
      "user-agent": "focustrack-evaluator-vault"
    },
    body: JSON.stringify({ repositories: [repository], permissions: { contents: "read" } })
  });
  const value = response?.ok ? await response.json().catch(() => null) : null;
  const expiresAt = Date.parse(String(value?.expires_at || ""));
  if (!value || typeof value.token !== "string" || value.token.length < 20 || /[\r\n\0]/.test(value.token) ||
      !Number.isFinite(expiresAt) || expiresAt <= now || expiresAt > now + (61 * 60 * 1000)) throw new Error("source_access_unavailable");
  return value.token;
}

async function run(environment = process.env, dependencies = {}) {
  let binding;
  try { binding = JSON.parse(environment.BINDING_JSON || ""); } catch (_error) { binding = null; }
  const config = serviceConfig(environment);
  if (!validBinding(binding) || !config) {
    return Object.freeze({ ok: false, status: "worker_configuration_unavailable", ...NO_AWARD });
  }
  const fetch = dependencies.fetch || globalThis.fetch;
  const now = dependencies.now || Date.now;
  let policy;
  let sourceToken;
  try {
    policy = await loadPolicyTemplate(binding, config.policyBucket, fetch);
    sourceToken = await githubInstallationToken({ appId: config.githubAppId, installationId: config.githubInstallationId,
      privateKey: config.githubAppPrivateKey, sourceRepository: binding.sourceRepository, fetch, now: now() });
  } catch (_error) {
    return Object.freeze({ ok: false, status: "evaluation_dependencies_unavailable", ...NO_AWARD });
  }
  let evaluation;
  try { evaluation = (dependencies.cloneAndEvaluate || cloneAndEvaluate)({ binding, policy, sourceToken, ...(dependencies.evaluator || {}) }); }
  catch (error) { return Object.freeze({ ok: false, status: evaluationFailureStatus(error), ...NO_AWARD }); }
  try {
    const response = await fetch(new URL("/v1/sign", config.signerUrl), {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(30_000),
      headers: { "content-type": "application/json", "x-focustrack-worker-token": config.workerSigningToken },
      body: JSON.stringify({ binding, evaluation, runId: String(now()), runAttempt: 1 })
    });
    const value = response?.ok ? await response.json().catch(() => null) : null;
    if (!value || value.ok !== true || !["signed", "already_signed"].includes(value.status)) {
      throw new Error("signing_rejected");
    }
    return Object.freeze({ ok: true, status: value.status, ...NO_AWARD });
  } catch (_error) {
    return Object.freeze({ ok: false, status: "signing_unavailable", ...NO_AWARD });
  }
}

if (require.main === module) {
  run().then((result) => {
    process.stdout.write(JSON.stringify(result) + "\n");
    process.exitCode = result.ok ? 0 : 1;
  });
}

module.exports = Object.freeze({ run, serviceConfig, loadPolicyTemplate, createGitHubAppJwt, githubInstallationToken, evaluationFailureStatus });
