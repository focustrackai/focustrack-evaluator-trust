"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { IMAGE, containerArguments, executeCase } = require("../scripts/evaluator/isolated-evaluation-controller.js");
const { evaluateFrozenTask, validateCriteria } = require("../scripts/evaluator/evaluate-container-task.js");
const sha = value => crypto.createHash("sha256").update(value).digest("hex");
const item = { id: "increment", input: 1, expected: 2, expectFrozen: false };

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "focustrack-container-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const before = "exports.run = value => value;";
  const after = "exports.run = value => value + 1;";
  for (const name of ["baseline", "candidate"]) fs.mkdirSync(path.join(root, name));
  fs.writeFileSync(path.join(root, "baseline", "subject.cjs"), before);
  fs.writeFileSync(path.join(root, "candidate", "subject.cjs"), after);
  const criteria = { schemaVersion: 1, taskId: "synthetic_container_probe", subjectPath: "subject.cjs", exportName: "run", cases: [item] };
  const criteriaPath = path.join(root, "criteria.json");
  fs.writeFileSync(criteriaPath, JSON.stringify(criteria));
  return { root, criteria, baselineDirectory: path.join(root, "baseline"), candidateDirectory: path.join(root, "candidate"), criteriaPath,
    binding: { taskId: criteria.taskId, criteriaSha256: sha(JSON.stringify(criteria)), baselineSha256: sha(before), candidateSha256: sha(after) } };
}

test("frozen task checks exact criteria and source bytes before running either subject", t => {
  const f = fixture(t);
  const paths = [];
  const result = evaluateFrozenTask(f, file => {
    paths.push(file);
    assert.notEqual(path.dirname(file), f.baselineDirectory);
    return path.basename(file) === "baseline.cjs" ? { passed: false, reason: "assertion_failed" } : { passed: true, reason: null };
  });
  assert.deepEqual(result, { baselineResult: "failed", result: "passed", checkCount: 1, passedCount: 1 });
  assert.ok(paths.every(file => !fs.existsSync(file)));
  for (const field of ["criteriaSha256", "baselineSha256", "candidateSha256"]) {
    assert.throws(() => evaluateFrozenTask({ ...f, binding: { ...f.binding, [field]: "0".repeat(64) } }, () => assert.fail("must not execute")), /file_pin_mismatch/);
  }
});

test("passing or unexecutable baselines cannot be presented as a repaired failure", t => {
  const f = fixture(t);
  for (const baseline of [{ passed: true, reason: null }, { passed: false, reason: "worker_rejected" }]) {
    let calls = 0;
    assert.throws(() => evaluateFrozenTask(f, () => { calls++; return baseline; }), /failing_baseline_unverified/);
    assert.equal(calls, 1);
  }
  assert.throws(() => evaluateFrozenTask({ ...f, candidateDirectory: f.baselineDirectory,
    binding: { ...f.binding, candidateSha256: f.binding.baselineSha256 } }), /unchanged_candidate/);
});

test("worker failures are inconclusive, while completed wrong answers are failures", t => {
  const f = fixture(t);
  for (const [reason, result] of [["worker_rejected", "inconclusive"], ["assertion_failed", "failed"]]) {
    assert.deepEqual(evaluateFrozenTask(f, file => ({ passed: false,
      reason: path.basename(file) === "baseline.cjs" ? "assertion_failed" : reason })),
    { baselineResult: "failed", result, checkCount: 1, passedCount: 0 });
  }
});

test("criteria refuse traversals, duplicate cases, extra fields, oversized sets, and wrong tasks", t => {
  const { criteria } = fixture(t);
  for (const change of [{ subjectPath: "../owner.cjs" }, { subjectPath: "/owner.cjs" }, { subjectPath: "dir\\owner.cjs" },
    { cases: [] }, { cases: [item, item] }, { cases: Array.from({ length: 33 }, (_, i) => ({ ...item, id: `case_${i}` })) },
    { taskId: "other" }, { cases: [{ ...item, command: "untrusted" }] }, { unknown: true }]) {
    assert.throws(() => validateCriteria({ ...criteria, ...change }, criteria.taskId), /criteria_invalid/);
  }
});

test("source symlinks cannot redirect pinned reads outside the source tree", { skip: process.platform === "win32" }, t => {
  const f = fixture(t);
  const outside = path.join(f.root, "outside.cjs");
  fs.copyFileSync(path.join(f.baselineDirectory, "subject.cjs"), outside);
  fs.unlinkSync(path.join(f.baselineDirectory, "subject.cjs"));
  fs.symlinkSync(outside, path.join(f.baselineDirectory, "subject.cjs"));
  assert.throws(() => evaluateFrozenTask(f), /subject_path_rejected/);
});

test("container configuration exposes only read-only subject and worker files", () => {
  const args = containerArguments(path.resolve("subject.cjs"), "focustrack-eval-" + "1".repeat(32));
  for (const [flag, value] of [["--network", "none"], ["--user", "10001:10001"], ["--cap-drop", "ALL"],
    ["--memory", "128m"], ["--memory-swap", "128m"], ["--cpus", "1"], ["--pids-limit", "32"],
    ["--security-opt", "no-new-privileges=true"], ["--log-driver", "none"], ["--pull", "never"]]) {
    assert.equal(args[args.indexOf(flag) + 1], value);
  }
  assert.ok(args.includes("--read-only"));
  assert.match(IMAGE, /@sha256:[a-f0-9]{64}$/);
  assert.equal(args.filter(arg => arg.startsWith("type=bind,")).length, 2);
  assert.ok(args.filter(arg => arg.startsWith("type=bind,")).every(arg => arg.endsWith(",readonly")));
  assert.ok(!args.includes("--privileged") && !args.includes("--env") && !args.includes("--pid"));
});

function fakeDocker(output, cleanup = true) {
  const calls = [];
  const run = (command, args, options) => {
    assert.equal(command, "docker");
    calls.push({ args, options });
    assert.equal(options.env.FOCUSTRACK_SOURCE_READ_TOKEN, undefined);
    assert.equal(options.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN, undefined);
    if (args[0] === "create") return { status: 0, stdout: "a".repeat(64) + "\n" };
    if (args[0] === "rm") return { status: cleanup ? 0 : 1, stderr: "unavailable" };
    const request = JSON.parse(options.input);
    return output(request);
  };
  return { calls, run };
}

test("controller owns comparisons and rejects forged or noisy worker output", () => {
  for (const output of [() => ({ status: 0, stdout: '{"passed":true}' }), () => ({ status: 0, stdout: "noise" }),
    request => ({ status: 0, stdout: JSON.stringify({ schemaVersion: 1, requestId: request.requestId,
      status: "ok", value: 2, frozen: false }) + "\n" })]) {
    const f = fakeDocker(output);
    assert.deepEqual(executeCase(path.resolve("subject.cjs"), "run", item, f.run), { passed: false, reason: "worker_rejected" });
    assert.equal(f.calls.at(-1).args[0], "rm");
  }
});

test("timed-out workers are cleaned up and cleanup failures stop evaluation", () => {
  const timeout = () => ({ status: null, error: Object.assign(new Error("timeout"), { code: "ETIMEDOUT" }) });
  const f = fakeDocker(timeout);
  assert.equal(executeCase(path.resolve("subject.cjs"), "run", item, f.run).reason, "worker_rejected");
  assert.equal(f.calls.at(-1).args[0], "rm");
  assert.throws(() => executeCase(path.resolve("subject.cjs"), "run", item, fakeDocker(timeout, false).run), /container_cleanup_unverified/);
});

const live = process.env.FOCUSTRACK_CONTAINER_TESTS === "1";
test("real container: frozen synthetic baseline fails and candidate passes", { skip: !live }, t => {
  assert.deepEqual(evaluateFrozenTask(fixture(t)), { baselineResult: "failed", result: "passed", checkCount: 1, passedCount: 1 });
});

test("real container: OS boundary holds even without Node permission switches", { skip: !live }, t => {
  const f = fixture(t);
  const subject = path.join(f.root, "os-probe.cjs");
  fs.writeFileSync(subject, `exports.run = () => {
    const fs = require('node:fs');
    const status = fs.readFileSync('/proc/self/status', 'utf8');
    let writeError = null;
    try { fs.writeFileSync('/tmp/should-not-write', 'probe'); } catch (error) { writeError = error.code; }
    return { uid: process.getuid(), writeError, hasHostFile: fs.existsSync(${JSON.stringify(f.criteriaPath)}),
      hasCredential: Object.keys(process.env).some(key => /TOKEN|SECRET|GITHUB|GOOGLE/.test(key)),
      noNewPrivileges: /NoNewPrivs:\\s+1/.test(status), noCapabilities: /CapEff:\\s+0000000000000000/.test(status),
      interfaces: Object.keys(require('node:os').networkInterfaces()),
      routes: fs.readFileSync('/proc/net/route', 'utf8').trim().split('\\n').length - 1,
      memoryLimit: fs.readFileSync('/sys/fs/cgroup/memory.max', 'utf8').trim(),
      processLimit: fs.readFileSync('/sys/fs/cgroup/pids.max', 'utf8').trim(),
      cpuLimit: fs.readFileSync('/sys/fs/cgroup/cpu.max', 'utf8').trim() };
  };`);
  const runWithoutSeatbelt = (command, args, options) => spawnSync(command,
    args.filter(arg => arg !== "--permission" && !arg.startsWith("--allow-fs-read=")), options);
  const expected = { uid: 10001, writeError: "EROFS", hasHostFile: false, hasCredential: false,
    noNewPrivileges: true, noCapabilities: true, interfaces: ["lo"], routes: 0,
    memoryLimit: "134217728", processLimit: "32", cpuLimit: "100000 100000" };
  assert.deepEqual(executeCase(subject, "run", { ...item, expected }, runWithoutSeatbelt), { passed: true, reason: null });
});

test("real container: ten repeated checks and rejected noisy/throwing submissions leave no containers", { skip: !live }, t => {
  const f = fixture(t);
  const subject = path.join(f.candidateDirectory, "subject.cjs");
  for (let i = 0; i < 10; i++) assert.equal(executeCase(subject, "run", item).passed, true);
  for (const code of ["console.log('forged verdict');exports.run = () => 2;", "exports.run = () => { throw new Error('candidate detail'); };"] ) {
    fs.writeFileSync(subject, code);
    assert.equal(executeCase(subject, "run", item).reason, "worker_rejected");
  }
  const remaining = spawnSync("docker", ["ps", "-aq", "--filter", "name=focustrack-eval-"], { encoding: "utf8", timeout: 15000, windowsHide: true });
  assert.equal(remaining.status, 0);
  assert.equal(remaining.stdout.trim(), "");
});

test("real container: an infinite submission times out and its container is removed", { skip: !live }, t => {
  const f = fixture(t);
  const subject = path.join(f.candidateDirectory, "subject.cjs");
  fs.writeFileSync(subject, "exports.run = () => { while (true) {} };");
  assert.equal(executeCase(subject, "run", item).reason, "worker_rejected");
  const remaining = spawnSync("docker", ["ps", "-aq", "--filter", "name=focustrack-eval-"], { encoding: "utf8", timeout: 15000, windowsHide: true });
  assert.equal(remaining.status, 0);
  assert.equal(remaining.stdout.trim(), "");
});
