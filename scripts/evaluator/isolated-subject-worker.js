"use strict";

// Preserve the existing evaluator's bounded worker protocol. Verdicts stay in the controller.
const fs = require("node:fs");
const stringify = JSON.stringify;
const parse = JSON.parse;
const isFrozen = Object.isFrozen.bind(Object);
const writeSync = fs.writeSync.bind(fs);
const byteLength = Buffer.byteLength;

function respond(value) {
  const text = stringify(value);
  if (byteLength(text, "utf8") > 16384) throw new Error("response_too_large");
  writeSync(1, text, null, "utf8");
}

try {
  const input = fs.readFileSync(0, "utf8");
  if (byteLength(input, "utf8") > 16384) throw new Error("request_too_large");
  const request = parse(input);
  if (!request || Object.keys(request).sort().join(",") !== "exportName,input,requestId,schemaVersion" ||
      request.schemaVersion !== 1 || !/^[a-f0-9]{32}$/.test(request.requestId) ||
      typeof request.exportName !== "string" || !/^[A-Za-z_$][A-Za-z0-9_$]{0,95}$/.test(request.exportName)) {
    throw new Error("request_invalid");
  }
  const subject = require("/subject.cjs");
  const operation = subject?.[request.exportName];
  if (typeof operation !== "function") throw new Error("subject_export_invalid");
  const value = operation(request.input);
  if (value === undefined || typeof value === "function" || typeof value === "symbol" ||
      typeof value === "bigint" || (value && typeof value.then === "function")) throw new Error("result_invalid");
  respond({ schemaVersion: 1, requestId: request.requestId, status: "ok", value,
    frozen: value !== null && typeof value === "object" ? isFrozen(value) : false });
} catch (_error) {
  try { respond({ schemaVersion: 1, status: "rejected" }); } catch (_ignored) {}
  process.exitCode = 1;
}
