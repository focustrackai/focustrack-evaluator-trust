"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const os = require("node:os"), { spawnSync } = require("node:child_process");
const d = require("../scripts/protected-registration-deploy.js");
const b = require("../scripts/prepare-protected-deployment.js");
const c = require("../cloud/history-checkpoint/contract.js");
const native = require("../cloud/history-checkpoint/cloud-run-runtime.js");
const { registeredFixture } = require("./fixtures/registered-observation.js");
const clone = x => structuredClone(x);
function fixture() {
  const registered = registeredFixture();
  let time = registered.now(), gen = 10;
  const policy = clone(registered.policy); policy.enabled = false;
  const job = clone(registered.job); job.template.template.containers[0].env.find(e => e.name === "FOCUSTRACK_HISTORY_PRODUCER_ENABLED").value = "0";
  job.template.template.containers[0].env.find(e => e.name === native.POLICY_ENV).value = c.canonical(policy);
  const traffic = [{ type: "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION", revision: "focustrack-evaluator-dispatcher-existing", percent: 100 }];
  const service = { name: d.SERVICE, uid: "service-fixture", etag: "service-1", generation: "1", observedGeneration: "1",
    reconciling: false, ingress: "INGRESS_TRAFFIC_ALL", invokerIamDisabled: false,
    traffic, trafficStatuses: clone(traffic), terminalCondition: { state: "CONDITION_SUCCEEDED" },
    template: { revision: traffic[0].revision, serviceAccount: native.INVOKER, timeout: "300s", containers: [{
      image: `us-central1-docker.pkg.dev/${d.PROJECT}/evaluator-vault/vault@sha256:${"5".repeat(64)}`,
      resources: { limits: { cpu: "1", memory: "256Mi" } }, env: [{ name: "UNCHANGED", value: "fixture" },
        { name: "EXISTING_SECRET_REFERENCE", valueSource: { secretKeyRef: { secret: "fixture", version: "1" } } }] }] } };
  const worker = { name: d.WORKER, uid: "worker-fixture", etag: "worker-1", generation: "1", observedGeneration: "1", template: { unchanged: true } };
  const resources = new Map([[d.SERVICE, service], [d.JOB, job], [d.WORKER, worker]]);
  const p = { schemaVersion: 1, installationId: "1".repeat(32), installerCommit: "a".repeat(40), repositoryId: "123", repositoryOwnerId: "456",
    deploymentServiceAccount: `protected-deploy@${d.PROJECT}.iam.gserviceaccount.com`, sourceContextSha256: d.SOURCE,
    buildEvidenceSha256: "8".repeat(64), boundaryEvidenceSha256: "9".repeat(64), edgeDisabledEvidenceSha256: "a".repeat(64),
    notBefore: time - 1, notAfter: time + 3600000, policy,
    dispatcherImage: `us-central1-docker.pkg.dev/${d.PROJECT}/evaluator-vault/vault@sha256:${"6".repeat(64)}`,
    candidate: "focustrack-evaluator-dispatcher-install-" + "1".repeat(12),
    before: Object.fromEntries(["service", "job", "worker"].map((k, i) => {
      const r = [service, job, worker][i]; return [k, { sha256: d.digest(r), etag: r.etag, uid: r.uid }];
    })), iam: {} };
  const registration = require("../scripts/plan-observation-registration.js").planObservationRegistration(policy), policies = new Map();
  for (const binding of [...registration.proposedBindings, registration.existingBindingToVerifyNotBroaden]) {
    if (!policies.has(binding.bucket)) policies.set(binding.bucket, { version: 3, etag: "IAM-FIXTURE", bindings: [] });
    policies.get(binding.bucket).bindings.push({ role: binding.role, members: binding.members, condition: binding.condition });
  }
  for (const [name, value] of policies) p.iam[name] = d.iamFingerprint(value);
  let sha, claims;
  const originalControls = clone(policies.get(d.BUCKET));
  function pin() {
    sha = d.digest(p);
    policies.set(d.BUCKET, { ...clone(originalControls), bindings: [...clone(originalControls.bindings), ...d.journalBindings(p, sha)] });
    claims = { iss: "https://token.actions.githubusercontent.com", aud: d.audience(sha), repository: d.REPO,
      repository_id: p.repositoryId, repository_owner_id: p.repositoryOwnerId,
      job_workflow_ref: `${d.REPO}/${d.WORKFLOW}@${p.installerCommit}`, job_workflow_sha: p.installerCommit,
      event_name: "workflow_dispatch", ref: "refs/heads/main", environment: d.ENVIRONMENT,
      runner_environment: "github-hosted", run_attempt: "1", run_id: "1234" };
  }
  pin();
  const objects = new Map(), calls = [], operations = new Map();
  const ports = {
    resource: async name => { calls.push(["read", name]); return clone(resources.get(name)); },
    bucketIam: async name => clone(policies.get(name)),
    bucket: async name => ({ name, location: "US-CENTRAL1", storageClass: "STANDARD", iamConfiguration: {
      uniformBucketLevelAccess: { enabled: true }, publicAccessPrevention: "enforced" } }),
    role: async name => ({ includedPermissions: name.endsWith("Appender") ? ["storage.objects.get", "storage.objects.create"] : ["storage.objects.get"] }),
    revision: async () => null,
    object: async (name, generation) => {
      calls.push(["object", name]); const row = objects.get(name);
      return row && (!generation || generation === row.generation) ? clone(row) : null;
    },
    create: async (name, serialized) => {
      calls.push(["create", name]); if (objects.has(name)) throw Error("fixture_collision");
      const generation = String(++gen); objects.set(name, { generation, serialized }); return generation;
    },
    patch: async (name, expected, template) => {
      calls.push(["patch", name]); const before = resources.get(name);
      assert.equal(before.etag, expected.etag);
      const after = { ...clone(before), template: clone(template), etag: expected.etag + "-new", generation: String(Number(before.generation) + 1),
        observedGeneration: String(Number(before.generation) + 1) };
      if (name === d.SERVICE) after.latestCreatedRevision = `${d.SERVICE}/revisions/${p.candidate}`;
      resources.set(name, after);
      const operation = { name: `${d.BASE}/operations/fixture-${operations.size}`, done: true, response: { name, uid: before.uid } };
      operations.set(operation.name, operation); return clone(operation);
    },
    operation: async name => clone(operations.get(name)),
    wait: async ms => { time += ms; }
  };
  const emptyIam = () => ({ version: 3, etag: "EXPLICIT_TEST_ONLY", bindings: [] });
  const bootstrap = { providerAbsent: true, pool: { name: d.PROVIDER.split("/providers/")[0], state: "ACTIVE", disabled: false },
    existingProviders: [{ name: d.PROVIDER.replace("pinned-deployment", "pinned-producer"),
      oidc: { issuerUri: "https://token.actions.githubusercontent.com" }, attributeMapping: { "google.subject": "assertion.sub" } }],
    deploymentAccount: { email: p.deploymentServiceAccount, disabled: false, iam: emptyIam() }, controlsIam: originalControls,
    projectIam: emptyIam(), runtimeIam: { [native.INVOKER]: emptyIam(), [native.SA]: emptyIam() }, roleAbsent: true };
  return { p, ports, resources, policies, objects, calls, bootstrap, pin, claims: () => claims, hash: () => sha,
    tick: ms => { time += ms; }, run: extra => d.executeDeployment({ plan: p, planSha256: sha, claims, ports, now: () => time, ...extra }) };
}
const patches = f => f.calls.filter(([kind]) => kind === "patch");
test("default disabled exits without any token or network request", async () => {
  assert.equal((await d.runHosted({}, () => { throw Error("network"); })).status, "DISABLED");
});
test("complete disabled stage preserves traffic, accounts, secrets/resources and writes eight durable records", async () => {
  const f = fixture(), before = clone(f.resources.get(d.SERVICE));
  const result = await f.run(); assert.equal(result.status, "DISABLED_STAGING_PASS");
  assert.equal(patches(f).length, 2); assert.equal(f.objects.size, 8);
  const s = f.resources.get(d.SERVICE); assert.deepEqual(s.traffic, before.traffic);
  assert.equal(s.template.serviceAccount, native.INVOKER);
  assert.deepEqual(s.template.containers[0].resources, before.template.containers[0].resources);
  for (const gate of d.ZERO_GATES) assert.equal(s.template.containers[0].env.find(e => e.name === gate).value, "0");
  assert.deepEqual(s.template.containers[0].env.find(e => e.name === "EXISTING_SECRET_REFERENCE"), before.template.containers[0].env[1]);
  const template = f.resources.get(d.JOB).template.template;
  const policy = JSON.parse(template.containers[0].env.find(e => e.name === native.POLICY_ENV).value);
  assert.equal(native.nativeTemplateSha256(template), policy.runtime.templateSha256);
  assert.equal(policy.enabled, false); assert.equal(result.xpAwarded, 0);
});
for (const [key, value] of [["repository_id", "999"], ["repository_owner_id", "999"], ["job_workflow_sha", "b".repeat(40)],
  ["job_workflow_ref", `${d.REPO}/${d.WORKFLOW}@refs/heads/main`], ["aud", "wrong"], ["run_attempt", "2"],
  ["event_name", "pull_request_target"], ["runner_environment", "self-hosted"], ["environment", "other"], ["ref", "refs/heads/other"]]) {
  test(`wrong ${key} fails before reads or writes`, async () => {
    const f = fixture(); f.claims()[key] = value; await assert.rejects(f.run(), /claims_rejected/); assert.equal(f.calls.length, 0);
  });
}
test("correct caller hash cannot authorize tampered document", async () => {
  const f = fixture(); f.p.dispatcherImage = f.p.dispatcherImage.replace(/6/g, "7");
  await assert.rejects(f.run()); assert.equal(f.calls.length, 0);
});
for (const value of ["evaluator-dispatcher", "history-checkpoint-producer", "evaluator-builder", "evaluator-worker", "kms-signer"]) {
  test(`reject existing ${value} as deploy authority`, async () => {
    const f = fixture(); f.p.deploymentServiceAccount = `${value}@${d.PROJECT}.iam.gserviceaccount.com`; f.pin();
    await assert.rejects(f.run(), /identity_rejected/); assert.equal(f.calls.length, 0);
  });
}
for (const key of ["installerCommit", "sourceContextSha256", "buildEvidenceSha256", "boundaryEvidenceSha256", "edgeDisabledEvidenceSha256"]) {
  test(`missing ${key} is never replaced with guessed live evidence`, async () => {
    const f = fixture(); delete f.p[key]; await assert.rejects(f.run()); assert.equal(f.calls.length, 0);
  });
}
test("extra caller-selected command rejected", async () => {
  const f = fixture(); f.p.command = "echo arbitrary"; await assert.rejects(f.run(), /fields_rejected/);
});
test("prestate drift fails before intent and any patch", async () => {
  const f = fixture(); f.resources.get(d.SERVICE).etag = "changed"; await assert.rejects(f.run(), /prestate_changed/);
  assert.equal(f.objects.size, 0); assert.equal(patches(f).length, 0);
});
test("unpinned latest traffic cannot promote candidate", async () => {
  const f = fixture(); const r = f.resources.get(d.SERVICE); r.traffic[0].type = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST";
  f.p.before.service.sha256 = d.digest(r); f.pin(); await assert.rejects(f.run(), /pinned_traffic/); assert.equal(patches(f).length, 0);
});
test("protected signing/source identity changes rejected even in an approved-shaped input", async () => {
  const f = fixture(); const old = f.resources.get(d.JOB).template.template.containers[0].env.find(e => e.name === native.POLICY_ENV);
  const v = JSON.parse(old.value); v.keyVersion = v.keyVersion.replace(/1$/, "2"); old.value = c.canonical(v);
  f.p.before.job.sha256 = d.digest(f.resources.get(d.JOB)); f.pin();
  await assert.rejects(f.run(), /protected_authority_changed/); assert.equal(patches(f).length, 0);
});
test("IAM extra grant or changed role fails closed", async () => {
  const f = fixture(); f.policies.values().next().value.bindings.push({ role: "roles/editor", members: ["allUsers"] });
  await assert.rejects(f.run(), /iam_changed/); assert.equal(patches(f).length, 0);
  const g = fixture(); g.ports.role = async () => ({ includedPermissions: ["storage.objects.get", "storage.objects.delete"] });
  await assert.rejects(g.run(), /role_changed/); assert.equal(patches(g).length, 0);
});
test("uncertain intent creation consumes attempt; reconstructed runner never applies", async () => {
  const f = fixture(), create = f.ports.create;
  f.ports.create = async (...args) => { await create(...args); throw Error("late commit, disconnected"); };
  await assert.rejects(f.run()); assert.equal(patches(f).length, 0);
  f.ports.create = create;
  assert.equal((await f.run()).status, "RECONCILED_READ_ONLY_NO_APPLY"); assert.equal(patches(f).length, 0);
});
test("duplicate/restart after complete deployment makes no second mutation", async () => {
  const f = fixture(); await f.run(); const count = f.objects.size;
  const result = await f.run(); assert.equal(result.status, "RECONCILED_READ_ONLY_NO_APPLY");
  assert.ok(result.states.every(s => s.status === "TERMINAL_DISABLED_STATE_MATCHES"));
  assert.equal(patches(f).length, 2); assert.equal(f.objects.size, count);
});
test("provider commits then times out: no second patch, no false PASS", async () => {
  const f = fixture(), patch = f.ports.patch;
  f.ports.patch = async (...args) => { await patch(...args); throw Error("uncertain patch"); };
  await assert.rejects(f.run()); assert.equal(patches(f).length, 1);
  const result = await f.run(); assert.equal(result.status, "RECONCILED_READ_ONLY_NO_APPLY");
  assert.equal(result.states[0].status, "UNKNOWN_SUBMISSION_NO_OPERATION_RECORD"); assert.equal(patches(f).length, 1);
});
test("job complete and service uncertain is incomplete, not full staging", async () => {
  const f = fixture(), patch = f.ports.patch;
  f.ports.patch = async (...args) => { const r = await patch(...args); if (args[0] === d.SERVICE) throw Error("service uncertain"); return r; };
  await assert.rejects(f.run()); assert.equal(patches(f).length, 2);
  assert.ok(!f.objects.has(`installations/${f.p.installationId}/result.json`));
});
test("terminal operation mismatch does not pass", async () => {
  const f = fixture(), patch = f.ports.patch;
  f.ports.patch = async (...args) => ({ ...await patch(...args), response: { name: d.WORKER, uid: "wrong" } });
  await assert.rejects(f.run(), /operation_failed_or_mismatched/); assert.equal(patches(f).length, 1);
});
test("pending operation polls reads only and stops at fake deadline", async () => {
  const f = fixture(); f.ports.patch = async name => { f.calls.push(["patch", name]); return { name: `${d.BASE}/operations/hang`, done: false }; };
  f.ports.operation = async name => ({ name, done: false });
  f.ports.wait = async () => f.tick(600000);
  await assert.rejects(f.run(), /deadline/); assert.equal(patches(f).length, 1);
});
test("signal after provider mutation leaves durable reconciliation evidence", async () => {
  const f = fixture(), controller = new AbortController(), patch = f.ports.patch;
  f.ports.patch = async (...args) => { const result = await patch(...args); controller.abort(); return result; };
  await assert.rejects(f.run({ signal: controller.signal })); assert.equal(patches(f).length, 1); assert.ok(f.objects.size >= 2);
});
test("expired approval only checks retained intent and makes zero writes", async () => {
  const f = fixture(); f.tick(3600001); await assert.rejects(f.run(), /deadline/);
  assert.deepEqual(f.calls.map(c => c[0]), ["object"]); assert.equal(patches(f).length, 0);
});
test("readback traffic movement or worker execution cannot pass", async () => {
  for (const drift of ["traffic", "worker"]) {
    const f = fixture(), patch = f.ports.patch;
    f.ports.patch = async (...args) => { const result = await patch(...args);
      if (args[0] === d.SERVICE) {
        if (drift === "traffic") f.resources.get(d.SERVICE).traffic[0].revision = f.p.candidate;
        else f.resources.get(d.WORKER).generation = "2";
      } return result;
    };
    await assert.rejects(f.run()); assert.ok(!f.objects.has(`installations/${f.p.installationId}/result.json`));
  }
});
test("bootstrap emits exact immutable trust, CAS requests, no new account or runtime administration", () => {
  const f = fixture(), result = b.bootstrap(f.p, f.bootstrap), packet = result.packet;
  assert.equal(c.hash(result.planBytes), f.hash()); assert.equal(packet.provider.disabled, true);
  assert.deepEqual(packet.provider.oidc.allowedAudiences, [d.audience(f.hash())]);
  assert.match(packet.provider.attributeCondition, /job_workflow_sha/); assert.match(packet.provider.attributeCondition, /run_attempt == '1'/);
  assert.ok(result.caller.includes(`@${f.p.installerCommit}`)); assert.ok(!result.caller.includes("secrets:"));
  assert.equal(packet.newServiceAccounts, 0); assert.equal(packet.liveProviderCalls, 0);
  assert.ok(packet.requests.every(r => r.retries === 0 && !r.url.includes("generateAccessToken")));
  const permissions = packet.requests.filter(r => r.id.startsWith("role-")).flatMap(r => r.body.role.includedPermissions);
  assert.ok(!permissions.some(p => /sign|setIamPolicy|jobs.run|create|delete|secret|keys/.test(p)));
  const project = packet.requests.find(r => r.id === "project-bindings").body.policy;
  assert.equal(project.etag, f.bootstrap.projectIam.etag);
  const stager = project.bindings.find(r => r.role.endsWith("focustrackDisabledRunStager"));
  assert.ok(!stager.condition.expression.includes(d.WORKER));
});
test("bootstrap missing independent pins fails, does not invent a deploy account or role prestate", () => {
  const f = fixture(); delete f.bootstrap.roleAbsent; assert.throws(() => b.bootstrap(f.p, f.bootstrap));
});
test("bootstrap rejects pool collision, unknown mapping and foreign issuer", () => {
  for (const change of [p => { p.attributeMapping["google.subject"] = "'ft-install-' + assertion.repository_id"; },
    p => { p.oidc.issuerUri = "https://foreign.invalid"; }, p => { p.name = d.PROVIDER; }]) {
    const f = fixture(); change(f.bootstrap.existingProviders[0]);
    assert.throws(() => b.bootstrap(f.p, f.bootstrap), /pool_subject_separation_unproven/);
  }
});
test("expired retained attempt still reconciles without mutation", async () => {
  const f = fixture(); await f.run(); const count = f.objects.size; f.tick(3600001);
  const result = await f.run(); assert.equal(result.status, "RECONCILED_READ_ONLY_NO_APPLY");
  assert.equal(patches(f).length, 2); assert.equal(f.objects.size, count);
});
test("foreign retained intent is never accepted as this attempt", async () => {
  const f = fixture(); await f.run();
  const key = `installations/${f.p.installationId}/intent.json`, row = f.objects.get(key), intent = JSON.parse(row.serialized);
  intent.planSha256 = "b".repeat(64); row.serialized = c.canonical(intent);
  await assert.rejects(f.run(), /retained_intent_mismatch/); assert.equal(patches(f).length, 2);
});
test("concurrent etag change between intent and patch is denied", async () => {
  const f = fixture(), create = f.ports.create;
  f.ports.create = async (name, bytes) => { const generation = await create(name, bytes);
    if (name.endsWith("/intent.json")) f.resources.get(d.JOB).etag = "foreign-writer";
    return generation;
  };
  await assert.rejects(f.run(), /prestate_changed/); assert.equal(patches(f).length, 0);
});
test("completed job changed by another writer stops before staging service", async () => {
  const f = fixture(), create = f.ports.create;
  f.ports.create = async (name, bytes) => { const generation = await create(name, bytes);
    if (name.endsWith("/job-result.json")) f.resources.get(d.JOB).etag = "other-writer";
    return generation;
  };
  await assert.rejects(f.run(), /completed_resource_changed/); assert.equal(patches(f).length, 1);
});
test("full hosted adapter uses independent approval aud, provider STS audience and separate deployment identity", async () => {
  const f = fixture(), seen = [];
  f.p.notBefore = Date.now() - 1000; f.p.notAfter = Date.now() + 3600000; f.pin();
  const planName = `installations/by-sha/${f.hash()}.json`;
  f.objects.set(planName, { serialized: c.canonical(f.p), generation: "99" });
  const jwt = `fixture.${Buffer.from(JSON.stringify(f.claims())).toString("base64url")}.signature`;
  const json = (value, status = 200) => new Response(JSON.stringify(value), { status });
  const fetcher = async (input, init = {}) => {
    const u = new URL(input), method = init.method || "GET";
    seen.push({ origin: u.origin, path: u.pathname, method });
    if (u.hostname === "fixture.actions.githubusercontent.com") {
      assert.equal(u.searchParams.get("audience"), d.audience(f.hash())); return json({ value: jwt });
    }
    if (u.hostname === "sts.googleapis.com") {
      const body = JSON.parse(init.body); assert.equal(body.audience, `//iam.googleapis.com/${d.PROVIDER}`);
      assert.equal(JSON.parse(Buffer.from(body.subjectToken.split(".")[1], "base64url")).aud, d.audience(f.hash()));
      return json({ access_token: "TEST_FEDERATED_ONLY" });
    }
    if (u.hostname === "iamcredentials.googleapis.com") {
      assert.ok(u.pathname.includes(f.p.deploymentServiceAccount)); assert.equal(init.headers.authorization, "Bearer TEST_FEDERATED_ONLY");
      return json({ accessToken: "TEST_DEPLOY_ONLY" });
    }
    if (u.hostname === "iam.googleapis.com") return json(await f.ports.role(u.pathname.slice(4)));
    if (u.hostname === "storage.googleapis.com") {
      const bucket = u.pathname.split("/b/")[1].split("/")[0];
      if (u.pathname.endsWith("/iam")) return json(await f.ports.bucketIam(bucket));
      if (!u.pathname.includes("/o")) return json(await f.ports.bucket(bucket));
      const name = method === "POST" ? u.searchParams.get("name") : decodeURIComponent(u.pathname.split("/o/")[1]);
      if (name === planName) assert.equal(init.headers.authorization, "Bearer TEST_FEDERATED_ONLY");
      else assert.equal(init.headers.authorization, "Bearer TEST_DEPLOY_ONLY");
      if (method === "POST") {
        assert.equal(u.searchParams.get("ifGenerationMatch"), "0"); return json({ generation: await f.ports.create(name, init.body) });
      }
      const row = await f.ports.object(name, u.searchParams.get("generation"));
      if (!row) return json({}, 404);
      return u.searchParams.get("alt") === "media" ? new Response(row.serialized) : json({ bucket, name, generation: row.generation });
    }
    if (u.hostname === "run.googleapis.com") {
      assert.equal(init.headers.authorization, "Bearer TEST_DEPLOY_ONLY");
      const name = u.pathname.slice(4);
      if (name.includes("/operations/")) return json(await f.ports.operation(name));
      if (name.includes("/revisions/")) return json({}, 404);
      if (method === "PATCH") { const body = JSON.parse(init.body); return json(await f.ports.patch(name, { etag: body.etag }, body.template)); }
      return json(await f.ports.resource(name));
    }
    throw Error("Unexpected route " + u.origin);
  };
  const result = await d.runHosted({ FOCUSTRACK_PROTECTED_DEPLOYMENT_ENABLED: "1", FOCUSTRACK_INSTALL_PLAN_SHA256: f.hash(),
    FOCUSTRACK_INSTALLER_COMMIT: f.p.installerCommit, GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", GITHUB_REPOSITORY: d.REPO,
    GITHUB_RUN_ATTEMPT: "1", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "TEST_OIDC_REQUEST_ONLY", ACTIONS_ID_TOKEN_REQUEST_URL: "https://fixture.actions.githubusercontent.com/oidc" }, fetcher);
  assert.equal(result.status, "DISABLED_STAGING_PASS"); assert.equal(patches(f).length, 2);
  assert.equal(seen.filter(r => r.origin === "https://sts.googleapis.com").length, 1);
});
test("preparer writes only new local private packet and refuses overwrite", () => {
  const f = fixture(), root = fs.mkdtempSync(path.join(os.tmpdir(), "ft-install-test-"));
  try {
    const input = path.join(root, "fixture.json"), out = path.join(root, "new-packet");
    fs.writeFileSync(input, JSON.stringify({ plan: f.p, bootstrap: f.bootstrap }));
    const args = [path.resolve(__dirname, "../scripts/prepare-protected-deployment.js"), "--input", input, "--out", out];
    const first = spawnSync(process.execPath, args, { encoding: "utf8" }); assert.equal(first.status, 0, first.stderr);
    assert.equal(c.hash(fs.readFileSync(path.join(out, "approved-plan.json"))), f.hash());
    assert.equal(spawnSync(process.execPath, args, { encoding: "utf8" }).status, 1);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
test("HTTP ports bind exact no-traffic template patch, generation preconditions, no invocation", async () => {
  const seen = [], request = async (url, init) => { seen.push({ url, init }); return '{"generation":"10","name":"op"}'; };
  const ports = d.createPorts(request, "TEST_ONLY");
  const before = { etag: "etag", labels: { existing: "preserved" }, annotations: { note: "kept" }, launchStage: "GA",
    binaryAuthorization: { useDefault: true }, client: "prior", clientVersion: "1" };
  await ports.patch(d.SERVICE, before, { disabled: true }); await ports.patch(d.JOB, before, { disabled: true });
  await ports.create("installations/fixture/intent.json", "{}");
  assert.ok(seen[0].url.endsWith("?updateMask=template")); assert.equal(seen[1].url, `https://run.googleapis.com/v2/${d.JOB}`);
  assert.ok(seen[2].url.includes("ifGenerationMatch=0"));
  assert.deepEqual(JSON.parse(seen[1].init.body), { name: d.JOB, ...before, template: { disabled: true } });
  for (const call of seen) {
    const u = new URL(call.url); assert.ok(!/:run|:sign|setIamPolicy|secretmanager/.test(call.url));
    assert.ok(u.hostname === "run.googleapis.com" ? u.pathname.startsWith("/v2/") : u.hostname === "storage.googleapis.com");
  }
});
test("HTTP body stalls or redirects fail bounded without retry", async () => {
  let calls = 0;
  const fetcher = async (_url, init) => { calls++; return new Response(new ReadableStream({ start(controller) {
    init.signal.addEventListener("abort", () => controller.error(Error("aborted")), { once: true });
  } })); };
  await assert.rejects(d.transport(fetcher, AbortSignal.timeout(20))("https://run.googleapis.com/test")); assert.equal(calls, 1);
  await assert.rejects(d.transport(async () => new Response("", { status: 302 }))("https://run.googleapis.com/test"));
});
test("workflow has no caller checkout, secrets inheritance, unpinned action or automatic trigger", () => {
  const text = fs.readFileSync(path.join(__dirname, "../.github/workflows/deploy-protected-registration.yml"), "utf8");
  assert.match(text, /workflow_call:/); assert.doesNotMatch(text, /pull_request_target:|\n  push:|secrets: inherit|self-hosted|upload-artifact|continue-on-error/);
  assert.match(text, /ref: \$\{\{ steps\.receiver\.outputs\.commit \}\}/);
  assert.match(text, /job_workflow_sha/); assert.match(text, /cancel-in-progress: false/);
  assert.ok([...text.matchAll(/uses: (.+)/g)].every(m => /@[a-f0-9]{40}$/.test(m[1])));
});
module.exports = { fixture };
