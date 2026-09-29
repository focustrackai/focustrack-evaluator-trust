"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const TASK_ID = "codex_prospective_evaluator_receipt_inbox_v2";
const REGISTRATION_PATH = path.resolve(__dirname, "../../evaluator-task-registration.json");
const SOURCE_FILES = Object.freeze([
  "desktop/state/desktop-evaluator-receipt-inbox.js",
  "execution-work-verification-assertion.js",
  "shared/evidence/signed-evaluator-receipt.js"
]);
const MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024;
const DIGEST = /^[a-f0-9]{64}$/;

function readSourceFile(root, relativePath, required = true) {
  const resolved = path.resolve(root, relativePath);
  const relative = path.relative(root, resolved);
  let stat;
  try {
    stat = fs.lstatSync(resolved);
  } catch (error) {
    if (!required && error?.code === "ENOENT") return null;
    throw error;
  }
  if (relative.startsWith("..") || path.isAbsolute(relative) || !stat.isFile() || stat.isSymbolicLink() ||
    stat.size > MAX_SOURCE_FILE_BYTES) throw new Error("source_file_invalid");
  return fs.readFileSync(resolved);
}

function sourceDigest(root) {
  const canonical = SOURCE_FILES.map((relativePath) => {
    const bytes = readSourceFile(root, relativePath, false);
    return bytes === null
      ? `${relativePath}\0missing\n`
      : `${relativePath}\0present\0${crypto.createHash("sha256").update(bytes).digest("hex")}\n`;
  }).join("");
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

function loadRegistration() {
  const serialized = fs.readFileSync(REGISTRATION_PATH, "utf8");
  const registration = JSON.parse(serialized);
  if (!registration || typeof registration !== "object" || Array.isArray(registration) ||
      registration.schemaVersion !== 1 || registration.taskId !== TASK_ID ||
      registration.sourceRepository !== "focustrackai/focustrack-" ||
      !/^[a-f0-9]{40}$/.test(registration.baselineCommit || "") ||
      !DIGEST.test(registration.baselineSha256 || "") || !DIGEST.test(registration.criteriaSha256 || "")) {
    throw new Error("task_registration_invalid");
  }
  return Object.freeze({
    registration,
    sha256: crypto.createHash("sha256").update(serialized, "utf8").digest("hex")
  });
}

function strictResult(value) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === "assertions,countsTowardGenuineCorpus,createsTruth,liveAuthorityApproved,mutatesFlow,mutatesRewards,mutatesXp,ok,shouldAffectRewards,status" &&
    value.ok === true && value.status === "assertions_read" && value.shouldAffectRewards === false &&
    value.countsTowardGenuineCorpus === false && value.createsTruth === false &&
    value.liveAuthorityApproved === false && value.mutatesXp === false && value.mutatesRewards === false && value.mutatesFlow === false &&
    Array.isArray(value.assertions);
}

function createProbeReceipt(sourceRoot) {
  const digest = "a".repeat(24);
  const now = Date.now();
  const taskId = `codex_prospective_${digest}`;
  const evaluatorReceiptId = `codex_evaluator_${digest}`;
  const workReceiptId = `codex_stop_${digest}`;
  const keyPair = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" });
  const binding = {
    taskId, receiptId: evaluatorReceiptId, registrationSha256: "1".repeat(64), criteriaSha256: "2".repeat(64),
    sourceRepository: "focustrackai/focustrack-", baselineCommit: "3".repeat(40), baselineSha256: "4".repeat(64),
    candidateCommit: "5".repeat(40), candidateSha256: "6".repeat(64), registeredAt: now - 6000,
    baselineAt: now - 5000, workStartedAt: now - 4000, evidenceClass: "prospective_no_award"
  };
  const signed = require(path.join(sourceRoot, "shared/evidence/signed-evaluator-receipt.js"));
  const serialized = signed.signEvaluatorReceipt({ keyId: "receipt_fusion_probe", privateKey: keyPair.privateKey, payload: {
    schemaVersion: 1, ...binding, evaluatorRepository: "focustrackai/focustrack-evaluator-trust",
    evaluatorCommit: "7".repeat(40), runId: "1", runAttempt: 1, evaluatedAt: now - 3000,
    issuedAt: now - 2000, expiresAt: now + 60000, baselineResult: "failed", result: "passed",
    checkCount: 4, passedCount: 4, noAward: true
  } });
  return {
    taskId,
    workReceiptId,
    unrelatedReceiptId: `codex_stop_${"b".repeat(24)}`,
    serialized,
    context: {
      trust: {
        keyId: "receipt_fusion_probe", publicKeyPem, evaluatorRepository: "focustrackai/focustrack-evaluator-trust",
        evaluatorCommit: "7".repeat(40), notBefore: now - 10000, notAfter: now + 120000,
        revoked: false, independenceApproved: true
      },
      expected: binding,
      now
    }
  };
}

function evaluateSource(sourceRoot) {
  const inboxPath = path.join(sourceRoot, "desktop/state/desktop-evaluator-receipt-inbox.js");
  const inboxBytes = readSourceFile(sourceRoot, "desktop/state/desktop-evaluator-receipt-inbox.js", false);
  if (!inboxBytes) {
    return { passed: false, checks: 0 };
  }
  const inboxSource = inboxBytes.toString("utf8");
  if (!/getAssertionsForWorkReceipt/.test(inboxSource)) return { passed: false, checks: 0 };

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "focustrack-receipt-fusion-"));
  try {
    const { createDesktopEvaluatorReceiptInbox } = require(inboxPath);
    const probe = createProbeReceipt(sourceRoot);
    const inbox = createDesktopEvaluatorReceiptInbox({
      filePath: path.join(directory, "inbox.json"),
      protectSerialized: (value) => Buffer.from(value, "utf8").toString("base64"),
      unprotectSerialized: (value) => Buffer.from(value, "base64").toString("utf8"),
      getContext: (taskId) => taskId === probe.taskId ? probe.context : null,
      now: () => probe.context.now
    });
    if (inbox.initialize().ok !== true || inbox.importReceipt(probe.serialized).ok !== true) {
      return { passed: false, checks: 0 };
    }
    const matched = inbox.getAssertionsForWorkReceipt(probe.workReceiptId);
    const unrelated = inbox.getAssertionsForWorkReceipt(probe.unrelatedReceiptId);
    if (!strictResult(matched) || !strictResult(unrelated) || matched.assertions.length !== 1 || unrelated.assertions.length !== 0) {
      return { passed: false, checks: 0 };
    }
    const assertion = matched.assertions[0];
    const exactJoin = assertion?.receiptId === probe.workReceiptId && assertion?.result === "verified" &&
      assertion?.independenceLevel === "external_independent" && assertion?.transportAuthenticated === true;
    const noAward = assertion?.createsTruth === false && assertion?.shouldAffectRewards === false &&
      assertion?.mutatesXp === false && assertion?.mutatesRewards === false && assertion?.mutatesFlow === false;
    return { passed: exactJoin && noAward, checks: exactJoin && noAward ? 4 : 0 };
  } catch (_error) {
    return { passed: false, checks: 0 };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 2 });
  }
}

function evaluate({ baselineDirectory, candidateDirectory, binding } = {}) {
  const { registration, sha256: registrationSha256 } = loadRegistration();
  if (!binding || !/^codex_prospective_[a-f0-9]{24}$/.test(binding.taskId) ||
      binding.receiptId !== `codex_evaluator_${binding.taskId.slice("codex_prospective_".length)}` ||
      binding.registrationSha256 !== registrationSha256 ||
      binding.criteriaSha256 !== registration.criteriaSha256 || binding.sourceRepository !== registration.sourceRepository ||
      binding.baselineCommit !== registration.baselineCommit || binding.baselineSha256 !== registration.baselineSha256 ||
      !DIGEST.test(binding.baselineSha256 || "") ||
      !DIGEST.test(binding.candidateSha256 || "") || sourceDigest(baselineDirectory) !== binding.baselineSha256 ||
      sourceDigest(candidateDirectory) !== binding.candidateSha256) throw new Error("task_binding_invalid");
  const baseline = evaluateSource(baselineDirectory);
  if (baseline.passed) throw new Error("baseline_already_satisfies_task");
  const candidate = evaluateSource(candidateDirectory);
  return Object.freeze({
    baselineResult: "failed",
    result: candidate.passed ? "passed" : "failed",
    checkCount: 4,
    passedCount: candidate.passed ? candidate.checks : 0
  });
}

module.exports = Object.freeze({ TASK_ID, SOURCE_FILES, sourceDigest, evaluateSource, evaluate });
