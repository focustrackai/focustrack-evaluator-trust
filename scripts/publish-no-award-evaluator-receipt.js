#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { BINDING_FIELDS, parseEvaluatorReceipt, signEvaluatorReceiptRemotely } = require("../shared/evidence/signed-evaluator-receipt.js");
const { validateSigningPolicy, createKmsSigner } = require("./evaluator-kms-signer.js");

const ROOT = path.resolve(__dirname, "..");
const ID = /^[a-z0-9][a-z0-9_.:-]{0,95}$/;

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function readJson(relativePath) {
  if (typeof relativePath !== "string" || !relativePath || relativePath.length > 240) throw new Error("input_invalid");
  const resolved = path.resolve(ROOT, relativePath);
  const relative = path.relative(ROOT, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("input_invalid");
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 8192) throw new Error("input_invalid");
  return JSON.parse(fs.readFileSync(resolved, "utf8"));
}

function outputPath(relativePath) {
  if (typeof relativePath !== "string" || !relativePath || relativePath.length > 240) throw new Error("output_invalid");
  const resolved = path.resolve(ROOT, relativePath);
  const relative = path.relative(ROOT, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("output_invalid");
  return resolved;
}

function parseArgs(argv) {
  const values = {};
  if (!Array.isArray(argv) || argv.length !== 6) throw new Error("arguments_invalid");
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    if (!new Set(["--binding", "--evaluation", "--out"]).has(key) || values[key] || !argv[index + 1]) {
      throw new Error("arguments_invalid");
    }
    values[key] = argv[index + 1];
  }
  return values;
}

function buildPayload(binding, evaluation, environment, now) {
  if (!exactKeys(binding, BINDING_FIELDS) || !exactKeys(evaluation, ["baselineResult", "result", "checkCount", "passedCount"])) {
    throw new Error("input_invalid");
  }
  if (binding.evidenceClass !== "prospective_no_award" || evaluation.baselineResult !== "failed" ||
      !["passed", "failed", "inconclusive"].includes(evaluation.result) ||
      !Number.isSafeInteger(evaluation.checkCount) || evaluation.checkCount < 1 || evaluation.checkCount > 10000 ||
      !Number.isSafeInteger(evaluation.passedCount) || evaluation.passedCount < 0 || evaluation.passedCount > evaluation.checkCount ||
      (evaluation.result === "passed") !== (evaluation.passedCount === evaluation.checkCount)) throw new Error("input_invalid");
  const keyId = String(environment.FOCUSTRACK_EVALUATOR_KEY_ID || "").trim();
  const evaluatorRepository = String(environment.GITHUB_REPOSITORY || "").trim().toLowerCase();
  const evaluatorCommit = String(environment.GITHUB_SHA || "").trim().toLowerCase();
  const runId = String(environment.GITHUB_RUN_ID || "").trim();
  const runAttempt = Number(environment.GITHUB_RUN_ATTEMPT);
  if (!ID.test(keyId) || !/^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/.test(evaluatorRepository) ||
      !/^[a-f0-9]{40}$/.test(evaluatorCommit) || !/^[1-9][0-9]{0,19}$/.test(runId) ||
      !Number.isSafeInteger(runAttempt) || runAttempt < 1 || runAttempt > 10000 || binding.workStartedAt >= now - 1) {
    throw new Error("publisher_environment_invalid");
  }
  return {
    keyId,
    payload: {
      schemaVersion: 1,
      ...binding,
      evaluatorRepository,
      evaluatorCommit,
      runId,
      runAttempt,
      evaluatedAt: now - 1,
      issuedAt: now,
      expiresAt: now + (24 * 60 * 60 * 1000),
      baselineResult: evaluation.baselineResult,
      result: evaluation.result,
      checkCount: evaluation.checkCount,
      passedCount: evaluation.passedCount,
      noAward: true
    }
  };
}

async function publish(argv, environment = process.env, now = Date.now(), options = {}) {
  try {
    const args = parseArgs(argv);
    const binding = readJson(args["--binding"]);
    const evaluation = readJson(args["--evaluation"]);
    const result = buildPayload(binding, evaluation, environment, now);
    const serializedPolicy = environment.FOCUSTRACK_KMS_SIGNING_POLICY;
    if (typeof serializedPolicy !== "string" || serializedPolicy.length > 8192) throw new Error("kms_policy_invalid");
    const policy = validateSigningPolicy(JSON.parse(serializedPolicy));
    if (policy.keyId !== result.keyId || policy.repository !== result.payload.evaluatorRepository ||
        policy.workflowSha !== result.payload.evaluatorCommit) throw new Error("kms_identity_mismatch");
    const receipt = await signEvaluatorReceiptRemotely({ keyId: result.keyId, publicKeyPem: policy.publicKeyPem,
      payload: result.payload, sign: createKmsSigner({ policy, environment, fetch: options.fetch }) });
    if (!parseEvaluatorReceipt(receipt)) throw new Error("receipt_invalid");
    const feedId = String(environment.FOCUSTRACK_EVALUATOR_FEED_ID || "focustrack_evaluator_feed_v1").trim();
    if (!ID.test(feedId)) throw new Error("publisher_environment_invalid");
    const output = outputPath(args["--out"]);
    fs.mkdirSync(path.dirname(output), { recursive: true });
    const temporary = output + ".tmp";
    fs.writeFileSync(temporary, JSON.stringify({ schemaVersion: 1, feedId, issuedAt: now, receipts: [receipt] }), "utf8");
    fs.renameSync(temporary, output);
    return { ok: true, status: "no_award_feed_published", receiptSha256: crypto.createHash("sha256").update(receipt, "utf8").digest("hex"),
      createsTruth: false, mutatesXp: false, mutatesRewards: false, mutatesFlow: false };
  } catch (_error) {
    return { ok: false, status: "publisher_rejected", createsTruth: false, mutatesXp: false, mutatesRewards: false, mutatesFlow: false };
  }
}

if (require.main === module) {
  publish(process.argv.slice(2)).then(result => {
    process.stdout.write(JSON.stringify(result) + "\n");
    process.exitCode = result.ok ? 0 : 1;
  });
}

module.exports = Object.freeze({ publish });
