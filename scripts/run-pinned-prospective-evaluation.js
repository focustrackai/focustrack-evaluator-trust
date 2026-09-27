#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const childProcess = require("node:child_process");
const { BINDING_FIELDS } = require("../shared/evidence/signed-evaluator-receipt.js");

const ROOT = path.resolve(__dirname, "..");
const SHA256 = /^[a-f0-9]{64}$/;
const REPOSITORY = /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/;
const COMMIT = /^[a-f0-9]{40}$/;

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function readJson(relativePath, limit = 16384) {
  if (typeof relativePath !== "string" || !relativePath || relativePath.length > 240) throw new Error("evaluation_invalid");
  const resolved = path.resolve(ROOT, relativePath);
  const relative = path.relative(ROOT, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("evaluation_invalid");
  const stat = fs.lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > limit) throw new Error("evaluation_invalid");
  return JSON.parse(fs.readFileSync(resolved, "utf8"));
}

function outputPath(relativePath) {
  if (typeof relativePath !== "string" || !relativePath || relativePath.length > 240) throw new Error("evaluation_invalid");
  const resolved = path.resolve(ROOT, relativePath);
  const relative = path.relative(ROOT, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("evaluation_invalid");
  return resolved;
}

function parseArgs(argv) {
  const values = {};
  if (!Array.isArray(argv) || argv.length !== 4) throw new Error("arguments_invalid");
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    if (!new Set(["--binding", "--out"]).has(key) || values[key] || !argv[index + 1]) throw new Error("arguments_invalid");
    values[key] = argv[index + 1];
  }
  return values;
}

function loadPolicy() {
  const policy = readJson("evaluator-policy.json");
  if (!exactKeys(policy, ["schemaVersion", "criteriaSha256", "sourceRepository", "verifierModule", "verifierSha256"]) ||
      policy.schemaVersion !== 1 || !SHA256.test(policy.criteriaSha256) || !REPOSITORY.test(policy.sourceRepository) ||
      typeof policy.verifierModule !== "string" || !SHA256.test(policy.verifierSha256)) throw new Error("policy_invalid");
  const modulePath = path.resolve(ROOT, policy.verifierModule);
  const relative = path.relative(ROOT, modulePath);
  const stat = fs.lstatSync(modulePath);
  if (relative.startsWith("..") || path.isAbsolute(relative) || !stat.isFile() || stat.isSymbolicLink() || stat.size > 1048576 ||
      crypto.createHash("sha256").update(fs.readFileSync(modulePath)).digest("hex") !== policy.verifierSha256) throw new Error("policy_invalid");
  return Object.freeze({ ...policy, modulePath });
}

function gitEnvironment(token = "", source = process.env) {
  if (typeof token !== "string" || token.length > 4096 || /[\r\n\0]/.test(token)) throw new Error("source_credential_invalid");
  const env = Object.fromEntries(["PATH", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP"]
    .filter(key => typeof source[key] === "string").map(key => [key, source[key]]));
  Object.assign(env, { GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: os.devNull,
    GIT_TERMINAL_PROMPT: "0", GCM_INTERACTIVE: "never" });
  const config = [["credential.helper", ""], ["core.hooksPath", os.devNull],
    ["protocol.file.allow", "never"], ["protocol.ext.allow", "never"], ["http.followRedirects", "false"]];
  if (token) config.push(["http.https://github.com/.extraheader", "Authorization: Basic " + Buffer.from("x-access-token:" + token).toString("base64")]);
  env.GIT_CONFIG_COUNT = String(config.length);
  config.forEach(([key, value], index) => { env["GIT_CONFIG_KEY_" + index] = key; env["GIT_CONFIG_VALUE_" + index] = value; });
  return env;
}

function runGit(args, cwd, token) {
  childProcess.execFileSync("git", args, { cwd, env: gitEnvironment(token), stdio: "ignore", timeout: 120000, windowsHide: true });
}

function validEvaluation(value) {
  return exactKeys(value, ["baselineResult", "result", "checkCount", "passedCount"]) &&
    value.baselineResult === "failed" && ["passed", "failed", "inconclusive"].includes(value.result) &&
    Number.isSafeInteger(value.checkCount) && value.checkCount >= 1 && value.checkCount <= 10000 &&
    Number.isSafeInteger(value.passedCount) && value.passedCount >= 0 && value.passedCount <= value.checkCount &&
    (value.result === "passed") === (value.passedCount === value.checkCount);
}

async function evaluate(argv) {
  let temporary = null;
  try {
    const args = parseArgs(argv);
    const sourceToken = process.env.FOCUSTRACK_SOURCE_READ_TOKEN || "";
    delete process.env.FOCUSTRACK_SOURCE_READ_TOKEN;
    const binding = readJson(args["--binding"]);
    const policy = loadPolicy();
    if (!exactKeys(binding, BINDING_FIELDS) || binding.evidenceClass !== "prospective_no_award" ||
        binding.criteriaSha256 !== policy.criteriaSha256 || binding.sourceRepository !== policy.sourceRepository ||
        !COMMIT.test(binding.baselineCommit) || !COMMIT.test(binding.candidateCommit)) throw new Error("binding_invalid");
    temporary = fs.mkdtempSync(path.join(os.tmpdir(), "focustrack-evaluator-"));
    const source = path.join(temporary, "source");
    runGit(["clone", "--no-checkout", "--filter=blob:none", "https://github.com/" + policy.sourceRepository + ".git", source], temporary, sourceToken);
    runGit(["fetch", "--depth=1", "origin", binding.baselineCommit, binding.candidateCommit], source, sourceToken);
    const baselineDirectory = path.join(temporary, "baseline");
    const candidateDirectory = path.join(temporary, "candidate");
    runGit(["worktree", "add", "--detach", baselineDirectory, binding.baselineCommit], source, sourceToken);
    runGit(["worktree", "add", "--detach", candidateDirectory, binding.candidateCommit], source, sourceToken);
    delete require.cache[require.resolve(policy.modulePath)];
    const verifier = require(policy.modulePath);
    if (!verifier || typeof verifier.evaluate !== "function") throw new Error("verifier_invalid");
    const result = await verifier.evaluate(Object.freeze({ baselineDirectory, candidateDirectory, binding: Object.freeze({ ...binding }) }));
    if (!validEvaluation(result)) throw new Error("evaluation_invalid");
    const target = outputPath(args["--out"]);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, JSON.stringify(result), { encoding: "utf8", flag: "wx" });
    return Object.freeze({ ok: true, status: "pinned_evaluation_completed" });
  } catch (_error) {
    return Object.freeze({ ok: false, status: "pinned_evaluation_rejected" });
  } finally {
    if (temporary) fs.rmSync(temporary, { recursive: true, force: true, maxRetries: 2 });
  }
}

if (require.main === module) {
  evaluate(process.argv.slice(2)).then((result) => {
    process.stdout.write(JSON.stringify(result) + "\\n");
    process.exitCode = result.ok ? 0 : 1;
  });
}

module.exports = Object.freeze({ evaluate, loadPolicy, validEvaluation, gitEnvironment });
