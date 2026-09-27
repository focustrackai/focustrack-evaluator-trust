#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { BINDING_FIELDS } = require("../shared/evidence/signed-evaluator-receipt.js");

const ROOT = path.resolve(__dirname, "..");
const ID = /^[a-z0-9][a-z0-9_.:-]{0,95}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const REPOSITORY = /^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/;

function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function safeOutput(relativePath) {
  if (typeof relativePath !== "string" || !relativePath || relativePath.length > 240) throw new Error("dispatch_invalid");
  const resolved = path.resolve(ROOT, relativePath);
  const relative = path.relative(ROOT, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("dispatch_invalid");
  return resolved;
}

function validBinding(value) {
  return exactKeys(value, BINDING_FIELDS) &&
    ["taskId", "receiptId"].every((key) => typeof value[key] === "string" && ID.test(value[key])) &&
    ["registrationSha256", "criteriaSha256", "baselineSha256", "candidateSha256"]
      .every((key) => typeof value[key] === "string" && SHA256.test(value[key])) &&
    ["baselineCommit", "candidateCommit"].every((key) => typeof value[key] === "string" && COMMIT.test(value[key])) &&
    typeof value.sourceRepository === "string" && REPOSITORY.test(value.sourceRepository) &&
    ["registeredAt", "baselineAt", "workStartedAt"].every((key) => Number.isSafeInteger(value[key]) && value[key] > 0) &&
    value.registeredAt <= value.baselineAt && value.baselineAt < value.workStartedAt &&
    value.evidenceClass === "prospective_no_award";
}

function prepare(environment = process.env, output = "private/binding.json") {
  try {
    if (environment.GITHUB_EVENT_NAME !== "repository_dispatch") throw new Error("dispatch_invalid");
    const eventPath = String(environment.GITHUB_EVENT_PATH || "");
    const stat = fs.lstatSync(eventPath);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16384) throw new Error("dispatch_invalid");
    const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));
    if (event?.action !== "focustrack_prospective_evaluation" ||
        !exactKeys(event?.client_payload, ["schemaVersion", "binding"]) ||
        event.client_payload.schemaVersion !== 1 || !validBinding(event.client_payload.binding)) {
      throw new Error("dispatch_invalid");
    }
    const target = safeOutput(output);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, JSON.stringify(event.client_payload.binding), { encoding: "utf8", flag: "wx" });
    return Object.freeze({ ok: true, status: "prospective_binding_accepted" });
  } catch (_error) {
    return Object.freeze({ ok: false, status: "prospective_dispatch_rejected" });
  }
}

if (require.main === module) {
  const result = prepare();
  process.stdout.write(JSON.stringify(result) + "\\n");
  process.exitCode = result.ok ? 0 : 1;
}

module.exports = Object.freeze({ prepare });
