"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { executeCase } = require("./isolated-evaluation-controller.js");

function exact(value, keys) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function digest(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }

function readPinnedFile(file, expected, limit) {
  if (typeof expected !== "string" || !/^[a-f0-9]{64}$/.test(expected)) throw new Error("file_pin_required");
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > limit) throw new Error("file_rejected");
  const bytes = fs.readFileSync(file);
  if (bytes.length > limit || digest(bytes) !== expected) throw new Error("file_pin_mismatch");
  return bytes;
}

function validateCriteria(value, taskId) {
  if (!exact(value, ["schemaVersion", "taskId", "subjectPath", "exportName", "cases"]) || value.schemaVersion !== 1 ||
      value.taskId !== taskId || typeof value.taskId !== "string" || !/^[a-z0-9][a-z0-9_.:-]{0,95}$/.test(value.taskId) ||
      typeof value.subjectPath !== "string" || value.subjectPath.length > 220 || !/\.(?:js|cjs)$/.test(value.subjectPath) ||
      !value.subjectPath.split("/").every(part => /^[A-Za-z0-9_-][A-Za-z0-9_.-]*$/.test(part)) ||
      typeof value.exportName !== "string" || !/^[A-Za-z_$][A-Za-z0-9_$]{0,95}$/.test(value.exportName) ||
      !Array.isArray(value.cases) || value.cases.length < 1 || value.cases.length > 32) throw new Error("criteria_invalid");
  const ids = new Set();
  for (const item of value.cases) {
    if (!exact(item, ["id", "input", "expected", "expectFrozen"]) || typeof item.id !== "string" ||
        !/^[a-z0-9][a-z0-9_.:-]{0,95}$/.test(item.id) || ids.has(item.id) || typeof item.expectFrozen !== "boolean" ||
        Buffer.byteLength(JSON.stringify(item), "utf8") > 12000) throw new Error("criteria_invalid");
    ids.add(item.id);
  }
  return value;
}

function sourceBytes(directory, subjectPath, expected) {
  const root = fs.realpathSync(directory);
  const file = path.resolve(root, subjectPath);
  const actual = fs.realpathSync(file);
  const relative = path.relative(root, actual);
  if (actual !== file || relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("subject_path_rejected");
  return readPinnedFile(file, expected, 1024 * 1024);
}

function evaluateFrozenTask({ baselineDirectory, candidateDirectory, binding, criteriaPath }, runCase = executeCase) {
  const criteria = validateCriteria(JSON.parse(readPinnedFile(criteriaPath, binding.criteriaSha256, 65536)), binding.taskId);
  const beforeBytes = sourceBytes(baselineDirectory, criteria.subjectPath, binding.baselineSha256);
  const afterBytes = sourceBytes(candidateDirectory, criteria.subjectPath, binding.candidateSha256);
  if (beforeBytes.equals(afterBytes)) throw new Error("unchanged_candidate");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "focustrack-evaluation-snapshot-"));
  try {
    // Mount sealed copies of the two files, never source directories or evaluator criteria.
    const before = path.join(directory, "baseline.cjs");
    const after = path.join(directory, "candidate.cjs");
    fs.writeFileSync(before, beforeBytes, { flag: "wx", mode: 0o644 });
    fs.writeFileSync(after, afterBytes, { flag: "wx", mode: 0o644 });
    const baseline = criteria.cases.map(item => runCase(before, criteria.exportName, item));
    if (baseline.some(item => item.reason === "worker_rejected") || !baseline.some(item => item.reason === "assertion_failed")) {
      throw new Error("failing_baseline_unverified");
    }
    const candidate = criteria.cases.map(item => runCase(after, criteria.exportName, item));
    const passedCount = candidate.filter(item => item.passed).length;
    return { baselineResult: "failed", result: passedCount === candidate.length ? "passed"
      : candidate.some(item => item.reason === "worker_rejected") ? "inconclusive" : "failed",
    checkCount: candidate.length, passedCount };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function evaluate(input) {
  return evaluateFrozenTask({ ...input, criteriaPath: path.resolve(__dirname, "../../evaluator-criteria.json") });
}

module.exports = Object.freeze({ evaluate, evaluateFrozenTask, validateCriteria });
