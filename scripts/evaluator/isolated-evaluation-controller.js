"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const IMAGE = "node:24.21.0-bookworm-slim@sha256:5cbc7caba8c2c0f0bca675d1b61b9f2857e1cf1853c6164ee9dd409501a936e7";
const WORKER = path.join(__dirname, "isolated-subject-worker.js");

function clientEnvironment() {
  return Object.fromEntries(["PATH", "SystemRoot", "SYSTEMROOT", "USERPROFILE", "HOME", "TEMP", "TMP"]
    .filter(key => typeof process.env[key] === "string").map(key => [key, process.env[key]]));
}

function containerArguments(subjectPath, name) {
  if (!path.isAbsolute(subjectPath) || /[,\r\n]/.test(subjectPath) || /[,\r\n]/.test(WORKER) ||
      !/^focustrack-eval-[a-f0-9]{32}$/.test(name)) throw new Error("container_configuration_invalid");
  return ["create", "--interactive", "--name", name, "--pull", "never", "--platform", "linux/amd64",
    "--network", "none", "--read-only", "--user", "10001:10001", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges=true", "--pids-limit", "32", "--memory", "128m",
    "--memory-swap", "128m", "--cpus", "1", "--ulimit", "nofile=64:64", "--ipc", "none",
    "--log-driver", "none", "--workdir", "/", "--entrypoint", "/usr/local/bin/node",
    "--mount", `type=bind,source=${subjectPath},target=/subject.cjs,readonly`,
    "--mount", `type=bind,source=${WORKER},target=/worker.cjs,readonly`, IMAGE,
    "--permission", "--allow-fs-read=/subject.cjs", "--allow-fs-read=/worker.cjs", "--no-addons",
    "--frozen-intrinsics", "/worker.cjs"];
}

function executeCase(subjectPath, exportName, testCase, run = spawnSync) {
  const requestId = crypto.randomBytes(16).toString("hex");
  const name = `focustrack-eval-${requestId}`;
  const request = JSON.stringify({ schemaVersion: 1, requestId, exportName, input: testCase.input });
  if (Buffer.byteLength(request, "utf8") > 16384) throw new Error("request_too_large");
  const options = { windowsHide: true, env: clientEnvironment(), encoding: "utf8", timeout: 15000, maxBuffer: 24576 };
  let response;
  try {
    const created = run("docker", containerArguments(subjectPath, name), options);
    if (created.error || created.status !== 0 || !/^[a-f0-9]{64}\s*$/.test(created.stdout || "")) {
      throw new Error("container_unavailable");
    }
    const child = run("docker", ["start", "--attach", "--interactive", name], { ...options, input: request });
    if (!child.error && child.status === 0 && typeof child.stdout === "string") {
      try {
        const parsed = JSON.parse(child.stdout);
        if (parsed && Object.keys(parsed).sort().join(",") === "frozen,requestId,schemaVersion,status,value" &&
            parsed.schemaVersion === 1 && parsed.requestId === requestId && parsed.status === "ok" &&
            typeof parsed.frozen === "boolean" && JSON.stringify(parsed) === child.stdout) response = parsed;
      } catch (_error) {}
    }
  } finally {
    // A killed Docker client does not necessarily stop its container. Always remove our exact random name.
    const removed = run("docker", ["rm", "--force", name], options);
    if (removed.error || (removed.status !== 0 && !String(removed.stderr).includes(`No such container: ${name}`))) {
      throw new Error("container_cleanup_unverified");
    }
  }
  if (!response) return { passed: false, reason: "worker_rejected" };
  const passed = JSON.stringify(response.value) === JSON.stringify(testCase.expected) && response.frozen === testCase.expectFrozen;
  return { passed, reason: passed ? null : "assertion_failed" };
}

module.exports = Object.freeze({ IMAGE, containerArguments, executeCase });
