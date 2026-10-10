"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawnSync } = require("node:child_process");
const {
  BINDING_FIELDS,
  NO_AWARD,
  signEvaluatorReceiptRemotely
} = require("../../shared/evidence/signed-evaluator-receipt.js");

const ID = /^[a-z0-9][a-z0-9_.:-]{0,95}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const REPOSITORY = /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/;
const MAX_CASES = 32;
const MAX_SUBJECT_BYTES = 1024 * 1024;
const MAX_CRITERIA_BYTES = 64 * 1024;

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function validBinding(value) {
  if (!exactKeys(value, BINDING_FIELDS)) return false;
  return ["taskId", "receiptId"].every((key) => typeof value[key] === "string" && ID.test(value[key])) &&
    ["registrationSha256", "criteriaSha256", "baselineSha256", "candidateSha256"].every((key) =>
      typeof value[key] === "string" && SHA256.test(value[key])) &&
    ["baselineCommit", "candidateCommit"].every((key) => typeof value[key] === "string" && COMMIT.test(value[key])) &&
    typeof value.sourceRepository === "string" && REPOSITORY.test(value.sourceRepository) &&
    ["registeredAt", "baselineAt", "workStartedAt"].every((key) => positiveInteger(value[key])) &&
    value.registeredAt <= value.baselineAt && value.baselineAt < value.workStartedAt &&
    value.evidenceClass === "prospective_no_award";
}

function validCase(value) {
  return exactKeys(value, ["id", "input", "expected", "expectFrozen"]) &&
    typeof value.id === "string" && ID.test(value.id) && typeof value.expectFrozen === "boolean" &&
    Buffer.byteLength(JSON.stringify(value), "utf8") <= 12 * 1024;
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : null;
  if (Array.isArray(value)) {
    const items = value.map(canonicalJson);
    return items.every((item) => typeof item === "string") ? `[${items.join(",")}]` : null;
  }
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) return null;
  const keys = Object.keys(value).sort();
  const entries = keys.map((key) => {
    const serialized = canonicalJson(value[key]);
    return typeof serialized === "string" ? `${JSON.stringify(key)}:${serialized}` : null;
  });
  return entries.every((entry) => typeof entry === "string") ? `{${entries.join(",")}}` : null;
}

function criteriaFingerprint(value) {
  if (!value || typeof value !== "object") return null;
  const canonical = canonicalJson({
    schemaVersion: 2,
    sourceRepository: value.sourceRepository,
    subjectPath: value.subjectPath,
    exportName: value.exportName,
    cases: value.cases
  });
  return typeof canonical === "string" ? sha256(canonical) : null;
}

function normalizePolicy(value) {
  const legacy = exactKeys(value, ["schemaVersion", "taskId", "criteriaSha256", "sourceRepository", "subjectPath", "exportName", "cases"]) &&
    value.schemaVersion === 1;
  const template = exactKeys(value, ["schemaVersion", "criteriaSha256", "sourceRepository", "subjectPath", "exportName", "cases"]) &&
    value.schemaVersion === 2;
  if ((!legacy && !template) || (legacy && (typeof value.taskId !== "string" || !ID.test(value.taskId))) ||
      typeof value.criteriaSha256 !== "string" || !SHA256.test(value.criteriaSha256) ||
      typeof value.sourceRepository !== "string" || !REPOSITORY.test(value.sourceRepository) ||
      typeof value.subjectPath !== "string" || value.subjectPath.length > 220 || !/\.(?:js|cjs)$/.test(value.subjectPath) ||
      !value.subjectPath.split("/").every((part) => /^[A-Za-z0-9_-][A-Za-z0-9_.-]*$/.test(part)) ||
      typeof value.exportName !== "string" || !/^[A-Za-z_$][A-Za-z0-9_$]{0,95}$/.test(value.exportName) ||
      !Array.isArray(value.cases) || value.cases.length < 1 || value.cases.length > MAX_CASES ||
      !value.cases.every(validCase)) return null;
  const caseIds = new Set(value.cases.map((item) => item.id));
  if (caseIds.size !== value.cases.length || Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_CRITERIA_BYTES) return null;
  if (template && criteriaFingerprint(value) !== value.criteriaSha256) return null;
  return Object.freeze({ ...value, cases: Object.freeze(value.cases.map((item) => Object.freeze({ ...item }))) });
}

function loadPolicy(serialized) {
  if (typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > MAX_CRITERIA_BYTES) return null;
  try { return normalizePolicy(JSON.parse(serialized)); } catch (_error) { return null; }
}

function tokenMatches(actual, expected) {
  if (typeof actual !== "string" || typeof expected !== "string" || actual.length < 32 || expected.length < 32) return false;
  const left = Buffer.from(actual, "utf8");
  const right = Buffer.from(expected, "utf8");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function safeGitEnvironment(token = "", source = process.env) {
  if (typeof token !== "string" || token.length > 4096 || /[\r\n\0]/.test(token)) throw new Error("source_credential_invalid");
  const nullFile = process.platform === "win32" ? "NUL" : "/dev/null";
  const environment = Object.fromEntries(["PATH", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP"]
    .filter((key) => typeof source[key] === "string").map((key) => [key, source[key]]));
  Object.assign(environment, { GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: nullFile, GIT_TERMINAL_PROMPT: "0", GCM_INTERACTIVE: "never" });
  const config = [["credential.helper", ""], ["core.hooksPath", nullFile], ["core.autocrlf", "false"], ["protocol.file.allow", "never"],
    ["protocol.ext.allow", "never"], ["http.followRedirects", "false"]];
  if (token) config.push(["http.https://github.com/.extraheader", "Authorization: Basic " + Buffer.from(`x-access-token:${token}`).toString("base64")]);
  environment.GIT_CONFIG_COUNT = String(config.length);
  config.forEach(([key, value], index) => {
    environment[`GIT_CONFIG_KEY_${index}`] = key;
    environment[`GIT_CONFIG_VALUE_${index}`] = value;
  });
  return environment;
}

function sourceGitFailure(stage, error) {
  const output = Buffer.isBuffer(error?.stderr) ? error.stderr.toString("utf8") : String(error?.stderr || "");
  if (/authentication failed|could not read username|http.*401|invalid credentials/i.test(output)) return "source_authentication_failed";
  if (/repository.*not found|http.*404/i.test(output)) return "source_repository_unavailable";
  if (/\b403\b|access denied|resource not accessible|permission denied/i.test(output)) return "source_authorization_failed";
  if (/could not resolve host|failed to connect|network is unreachable/i.test(output)) return "source_network_unavailable";
  return `source_${stage}_failed`;
}

function readPinnedSource(directory, subjectPath, expectedHash) {
  const root = fs.realpathSync(directory);
  const target = path.resolve(root, subjectPath);
  const actual = fs.realpathSync(target);
  const relative = path.relative(root, actual);
  const stat = fs.lstatSync(actual);
  if (actual !== target || relative.startsWith("..") || path.isAbsolute(relative) || !stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_SUBJECT_BYTES) {
    throw new Error("subject_rejected");
  }
  const bytes = fs.readFileSync(actual);
  if (bytes.length > MAX_SUBJECT_BYTES || sha256(bytes) !== expectedHash) throw new Error("subject_pin_mismatch");
  return bytes;
}

function workerResult(subjectPath, exportName, testCase, runner = spawnSync) {
  const requestId = crypto.randomBytes(16).toString("hex");
  const request = JSON.stringify({ schemaVersion: 1, requestId, exportName, input: testCase.input });
  if (Buffer.byteLength(request, "utf8") > 16 * 1024) throw new Error("request_too_large");
  const worker = path.join(__dirname, "subject-worker.js");
  const environment = { PATH: process.env.PATH || "", FOCUSTRACK_VAULT_SUBJECT_PATH: subjectPath };
  const result = runner(process.execPath, ["--permission", `--allow-fs-read=${worker}`, `--allow-fs-read=${subjectPath}`, "--no-addons", "--frozen-intrinsics", worker], {
    input: request, encoding: "utf8", timeout: 15_000, maxBuffer: 24 * 1024, windowsHide: true, env: environment
  });
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") return { passed: false, reason: "worker_rejected" };
  try {
    const response = JSON.parse(result.stdout);
    if (!exactKeys(response, ["schemaVersion", "requestId", "status", "value", "frozen"]) || response.schemaVersion !== 1 ||
        response.requestId !== requestId || response.status !== "ok" || typeof response.frozen !== "boolean" || JSON.stringify(response) !== result.stdout) {
      return { passed: false, reason: "worker_rejected" };
    }
    const passed = JSON.stringify(response.value) === JSON.stringify(testCase.expected) && response.frozen === testCase.expectFrozen;
    return { passed, reason: passed ? null : "assertion_failed" };
  } catch (_error) {
    return { passed: false, reason: "worker_rejected" };
  }
}

function evaluatePair({ baselineDirectory, candidateDirectory, binding, policy }, runCase = workerResult) {
  if (!validBinding(binding) || !policy || (policy.schemaVersion === 1 && binding.taskId !== policy.taskId) ||
      binding.criteriaSha256 !== policy.criteriaSha256 ||
      binding.sourceRepository !== policy.sourceRepository) throw new Error("binding_rejected");
  const baseline = readPinnedSource(baselineDirectory, policy.subjectPath, binding.baselineSha256);
  const candidate = readPinnedSource(candidateDirectory, policy.subjectPath, binding.candidateSha256);
  if (baseline.equals(candidate)) throw new Error("candidate_unchanged");
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "focustrack-vault-"));
  try {
    const beforePath = path.join(workspace, "baseline.cjs");
    const afterPath = path.join(workspace, "candidate.cjs");
    fs.writeFileSync(beforePath, baseline, { flag: "wx", mode: 0o600 });
    fs.writeFileSync(afterPath, candidate, { flag: "wx", mode: 0o600 });
    const baselineResults = policy.cases.map((item) => runCase(beforePath, policy.exportName, item));
    if (baselineResults.some((item) => item.reason === "worker_rejected") || !baselineResults.some((item) => item.reason === "assertion_failed")) {
      throw new Error("baseline_not_proven_failing");
    }
    const candidateResults = policy.cases.map((item) => runCase(afterPath, policy.exportName, item));
    const passedCount = candidateResults.filter((item) => item.passed).length;
    return Object.freeze({ baselineResult: "failed", result: passedCount === candidateResults.length ? "passed" :
      candidateResults.some((item) => item.reason === "worker_rejected") ? "inconclusive" : "failed",
    checkCount: candidateResults.length, passedCount });
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true, maxRetries: 2 });
  }
}

function cloneAndEvaluate({ binding, policy, sourceToken, runGit = execFileSync, runCase = workerResult }) {
  if (!sourceToken || sourceToken.length < 20) throw new Error("source_access_unavailable");
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "focustrack-vault-source-"));
  try {
    const source = path.join(workspace, "source");
    const git = (stage, args, cwd) => {
      try { return runGit("git", args, { cwd, env: safeGitEnvironment(sourceToken), stdio: ["ignore", "ignore", "pipe"], timeout: 120_000, windowsHide: true }); }
      catch (error) { throw new Error(sourceGitFailure(stage, error)); }
    };
    git("clone", ["clone", "--no-checkout", "--filter=blob:none", `https://github.com/${binding.sourceRepository}.git`, source], workspace);
    git("fetch", ["fetch", "--depth=1", "origin", binding.baselineCommit, binding.candidateCommit], source);
    const baseline = path.join(workspace, "baseline");
    const candidate = path.join(workspace, "candidate");
    git("worktree", ["worktree", "add", "--detach", baseline, binding.baselineCommit], source);
    git("worktree", ["worktree", "add", "--detach", candidate, binding.candidateCommit], source);
    return evaluatePair({ baselineDirectory: baseline, candidateDirectory: candidate, binding, policy }, runCase);
  } catch (error) {
    if (error?.message === "binding_rejected" || error?.message === "subject_rejected" ||
        error?.message === "subject_pin_mismatch" || error?.message === "candidate_unchanged" ||
        error?.message === "baseline_not_proven_failing") throw error;
    throw error;
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true, maxRetries: 2 });
  }
}

function buildReceiptPayload({ binding, evaluation, evaluatorRepository, evaluatorCommit, now = Date.now(), runId = String(Date.now()), runAttempt = 1 }) {
  if (!validBinding(binding) || !exactKeys(evaluation, ["baselineResult", "result", "checkCount", "passedCount"]) ||
      evaluation.baselineResult !== "failed" || !["passed", "failed", "inconclusive"].includes(evaluation.result) ||
      !positiveInteger(evaluation.checkCount) || evaluation.checkCount > 10_000 || !Number.isSafeInteger(evaluation.passedCount) ||
      evaluation.passedCount < 0 || evaluation.passedCount > evaluation.checkCount ||
      (evaluation.result === "passed") !== (evaluation.passedCount === evaluation.checkCount) ||
      !REPOSITORY.test(evaluatorRepository) || !COMMIT.test(evaluatorCommit) || !/^[1-9][0-9]{0,19}$/.test(runId) ||
      !positiveInteger(runAttempt) || !positiveInteger(now) || now <= binding.workStartedAt) throw new Error("receipt_input_invalid");
  return Object.freeze({ schemaVersion: 1, ...binding, evaluatorRepository, evaluatorCommit, runId, runAttempt,
    evaluatedAt: now - 1, issuedAt: now, expiresAt: now + (24 * 60 * 60 * 1000), ...evaluation, noAward: true });
}

async function signWithKms({ keyId, keyVersion, publicKeyPem, payload, fetch = globalThis.fetch }) {
  if (!ID.test(keyId) || typeof keyVersion !== "string" || !/^projects\/[a-z0-9-]+\/locations\/[a-z0-9-]+\/keyRings\/[a-z0-9-]+\/cryptoKeys\/[a-z0-9-]+\/cryptoKeyVersions\/[1-9][0-9]*$/.test(keyVersion) ||
      typeof publicKeyPem !== "string" || !/^-----BEGIN PUBLIC KEY-----\r?\n/.test(publicKeyPem)) throw new Error("signer_configuration_invalid");
  const sign = async (bytes) => {
    const tokenResponse = await fetch("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {
      headers: { "Metadata-Flavor": "Google" }, redirect: "error", signal: AbortSignal.timeout(5000)
    });
    const token = tokenResponse?.ok ? await tokenResponse.json().catch(() => null) : null;
    if (!token || typeof token.access_token !== "string") throw new Error("kms_signing_failed");
    const response = await fetch(`https://cloudkms.googleapis.com/v1/${keyVersion}:asymmetricSign`, {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(15_000),
      headers: { authorization: `Bearer ${token.access_token}`, "content-type": "application/json" },
      body: JSON.stringify({ data: bytes.toString("base64") })
    });
    const value = response?.ok ? await response.json().catch(() => null) : null;
    if (!value || typeof value.signature !== "string") throw new Error("kms_signing_failed");
    return Buffer.from(value.signature, "base64");
  };
  return signEvaluatorReceiptRemotely({ keyId, publicKeyPem, payload, sign });
}

module.exports = Object.freeze({
  NO_AWARD, BINDING_FIELDS, exactKeys, sha256, canonicalJson, criteriaFingerprint, validBinding, normalizePolicy, loadPolicy, tokenMatches,
  safeGitEnvironment, sourceGitFailure, workerResult, evaluatePair, cloneAndEvaluate, buildReceiptPayload, signWithKms
});
