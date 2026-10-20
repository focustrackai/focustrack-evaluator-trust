"use strict";

const c = require("../cloud/history-checkpoint/contract.js");
const native = require("../cloud/history-checkpoint/cloud-run-runtime.js");
const { planObservationRegistration } = require("./plan-observation-registration.js");
const PROJECT = "focustrack-eval-20260927", REGION = "us-central1";
const BASE = `projects/${PROJECT}/locations/${REGION}`;
const SERVICE = `${BASE}/services/focustrack-evaluator-dispatcher`, JOB = native.JOB;
const WORKER = `${BASE}/jobs/focustrack-evaluator-worker`;
const BUCKET = "focustrack-award-controls-818502899155";
const REPO = "focustrackai/focustrack-evaluator-trust";
const WORKFLOW = ".github/workflows/deploy-protected-registration.yml";
const ENVIRONMENT = "protected-registration-install";
const PROVIDER = "projects/818502899155/locations/global/workloadIdentityPools/github-history-checkpoint/providers/pinned-deployment";
const SOURCE = "56a0664450f3a7c0786f9de2283214db4a259018b41b0473ff8b67aed7a4206e";
const HASH = /^[a-f0-9]{64}$/, SHA = /^[a-f0-9]{40}$/, ID = /^[1-9][0-9]{0,19}$/;
const ZERO_GATES = ["FOCUSTRACK_OBSERVATION_REGISTRATION_ENABLED", "FOCUSTRACK_NO_AWARD_OBSERVATION_ENABLED",
  "FOCUSTRACK_HISTORY_FINALIZATION_ENABLED", "FOCUSTRACK_ENROLLMENT_START_ENABLED",
  "FOCUSTRACK_OBSERVATION_INSPECTION_ENABLED"];
const JOURNAL_FILES = ["intent", "job-intent", "job-operation", "job-result", "service-intent", "service-operation", "service-result", "result"];
const fail = code => { throw Error(code); };
const digest = value => c.hash(c.canonical(value));
const same = (a, b) => c.canonical(a) === c.canonical(b);
function exact(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype ||
      !same(Object.keys(value).sort(), keys.slice().sort())) fail("deployment_fields_rejected");
}
function validatePlan(p) {
  exact(p, ["schemaVersion", "installationId", "installerCommit", "repositoryId", "repositoryOwnerId",
    "deploymentServiceAccount", "sourceContextSha256", "buildEvidenceSha256", "boundaryEvidenceSha256",
    "edgeDisabledEvidenceSha256", "notBefore", "notAfter", "policy", "dispatcherImage", "candidate",
    "before", "iam"]);
  if (p.schemaVersion !== 1 || !/^[a-f0-9]{32}$/.test(p.installationId || "") ||
      !SHA.test(p.installerCommit || "") || /^0+$/.test(p.installerCommit) ||
      !ID.test(p.repositoryId || "") || !ID.test(p.repositoryOwnerId || "") ||
      p.sourceContextSha256 !== SOURCE ||
      ![p.buildEvidenceSha256, p.boundaryEvidenceSha256, p.edgeDisabledEvidenceSha256].every(x => HASH.test(x || "") && !/^0+$/.test(x)) ||
      !Number.isSafeInteger(p.notBefore) || !Number.isSafeInteger(p.notAfter) || p.notBefore <= 0 ||
      p.notAfter <= p.notBefore || p.notAfter - p.notBefore > 86400000 ||
      !/^focustrack-evaluator-dispatcher-install-[a-f0-9]{12}$/.test(p.candidate || "") ||
      p.candidate !== `focustrack-evaluator-dispatcher-install-${p.installationId.slice(0, 12)}` ||
      !new RegExp(`^us-central1-docker\\.pkg\\.dev/${PROJECT}/evaluator-vault/vault@sha256:[a-f0-9]{64}$`).test(p.dispatcherImage || ""))
    fail("deployment_plan_rejected");
  // A separately verified EXISTING deployment identity is required. Never
  // repurpose any runtime, build, signing or source-reader identity for setup.
  const email = p.deploymentServiceAccount;
  if (!new RegExp(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@${PROJECT}\\.iam\\.gserviceaccount\\.com$`).test(email || "") ||
      /evaluator|history|sign|reader|worker|builder|dispatch/.test(email.split("@")[0])) fail("deployment_identity_rejected");
  exact(p.before, ["service", "job", "worker"]);
  for (const value of Object.values(p.before)) {
    exact(value, ["sha256", "etag", "uid"]);
    if (!HASH.test(value.sha256 || "") || typeof value.etag !== "string" || !value.etag ||
        typeof value.uid !== "string" || !value.uid) fail("deployment_prestate_required");
  }
  const installation = planObservationRegistration(p.policy);
  if (p.policy.enabled !== false || p.policy.runtime.jobUid !== p.before.job.uid)
    fail("deployment_policy_must_be_disabled");
  const buckets = [installation.proposedBucket.name, installation.proposedBindings[2].bucket, BUCKET];
  exact(p.iam, buckets);
  for (const value of Object.values(p.iam)) if (!HASH.test(value || "")) fail("deployment_iam_pin_required");
  return installation;
}
function audience(sha) { if (!HASH.test(sha || "")) fail("deployment_plan_hash_required"); return `https://focustrack.invalid/install/${sha}`; }
function claimsMatch(claims, p, sha) {
  const expected = { iss: "https://token.actions.githubusercontent.com", aud: audience(sha),
    repository: REPO, repository_id: p.repositoryId, repository_owner_id: p.repositoryOwnerId,
    job_workflow_ref: `${REPO}/${WORKFLOW}@${p.installerCommit}`, job_workflow_sha: p.installerCommit,
    event_name: "workflow_dispatch", ref: "refs/heads/main", environment: ENVIRONMENT,
    runner_environment: "github-hosted", run_attempt: "1" };
  if (!Object.entries(expected).every(([k, v]) => claims[k] === v) || !ID.test(claims.run_id || ""))
    fail("deployment_claims_rejected");
}
function environment(container) {
  if (!Array.isArray(container?.env) || container.env.some(e => !e || typeof e.name !== "string") ||
      new Set(container.env.map(e => e.name)).size !== container.env.length) fail("deployment_environment_rejected");
  return new Map(container.env.map(e => [e.name, structuredClone(e)]));
}
function setEnvironment(container, values, remove = []) {
  const env = environment(container);
  for (const key of remove) env.delete(key);
  for (const [name, value] of Object.entries(values)) env.set(name, { name, value });
  container.env = [...env.values()];
}
function settled(resource) {
  if (!resource || resource.reconciling === true || resource.deleteTime || resource.expireTime ||
      !ID.test(resource.generation || "") || resource.generation !== resource.observedGeneration ||
      !resource.etag) fail("deployment_resource_not_settled");
}
function traffic(service, candidate) {
  if (!Array.isArray(service.traffic) || !service.traffic.length ||
      service.traffic.some(t => t.type !== "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION" ||
        typeof t.revision !== "string" || !t.revision || t.revision === candidate || t.tag ||
        !Number.isInteger(t.percent) || t.percent <= 0) ||
      service.traffic.reduce((n, t) => n + t.percent, 0) !== 100) fail("deployment_pinned_traffic_required");
  const normalize = list => list.map(t => ({ type: t.type, revision: t.revision, percent: t.percent, tag: t.tag || "" }));
  if (!Array.isArray(service.trafficStatuses) || !same(normalize(service.traffic), normalize(service.trafficStatuses)))
    fail("deployment_traffic_status_mismatch");
}
function assertBefore(resource, name, pin) {
  settled(resource);
  if (resource.name !== name || resource.uid !== pin.uid || resource.etag !== pin.etag || digest(resource) !== pin.sha256)
    fail("deployment_prestate_changed");
}
function desiredTemplates(p, service, job) {
  validatePlan(p); assertBefore(service, SERVICE, p.before.service); assertBefore(job, JOB, p.before.job);
  traffic(service, p.candidate);
  const s = structuredClone(service.template), j = structuredClone(job.template);
  if (s?.serviceAccount !== native.INVOKER || s.containers?.length !== 1 ||
      j?.template?.serviceAccount !== native.SA || j.template.containers?.length !== 1 ||
      j.taskCount !== 1 || j.parallelism !== 1) fail("deployment_existing_runtime_mismatch");
  s.revision = p.candidate; s.containers[0].image = p.dispatcherImage;
  setEnvironment(s.containers[0], Object.fromEntries(ZERO_GATES.map(k => [k, "0"])),
    ["FOCUSTRACK_NO_AWARD_OBSERVATION_CONFIG_JSON", "FOCUSTRACK_HISTORY_FINALIZATION_CONFIG_JSON"]);
  const policy = structuredClone(p.policy), container = j.template.containers[0];
  const previousPolicy = c.parse(environment(container).get(native.POLICY_ENV)?.value);
  for (const key of ["keyVersion", "publicKeySha256", "checkpointTrust", "receiptTrust", "sourceReader"])
    if (!same(previousPolicy[key], policy[key])) fail("deployment_protected_authority_changed");
  for (const key of ["kind", "job", "jobUid", "enrollmentId"])
    if (previousPolicy.runtime[key] !== policy.runtime[key]) fail("deployment_native_authority_changed");
  if (environment(container).get("FOCUSTRACK_HISTORY_PRODUCER_ENABLED")?.value !== "0")
    fail("deployment_existing_job_must_be_disabled");
  container.image = policy.runtime.image;
  setEnvironment(container, { FOCUSTRACK_HISTORY_PRODUCER_ENABLED: "0", FOCUSTRACK_HISTORY_OBSERVATION_INPUT_ENABLED: "0",
    FOCUSTRACK_HISTORY_SOURCE_READER_ENABLED: "0", FOCUSTRACK_HISTORY_ENROLLMENT_ID: policy.runtime.enrollmentId,
    [native.POLICY_ENV]: c.canonical(policy) });
  // Reuse the existing self-template algorithm; only the disabled template's
  // self-hash changes. Any subsequent activation needs its own reviewed pin.
  policy.runtime.templateSha256 = native.nativeTemplateSha256(j.template);
  setEnvironment(container, { [native.POLICY_ENV]: c.canonical(policy) });
  setEnvironment(s.containers[0], { FOCUSTRACK_OBSERVATION_REGISTRATION_POLICY_JSON: c.canonical(policy) });
  planObservationRegistration(policy);
  return { service: s, job: j };
}
// Ignore provider-generated output fields, not any editable configuration.
function unchangedConfiguration(resource) {
  const output = new Set(["template", "etag", "generation", "observedGeneration", "updateTime", "lastModifier", "reconciling",
    "conditions", "terminalCondition", "latestReadyRevision", "latestCreatedRevision", "trafficStatuses"]);
  return Object.fromEntries(Object.entries(resource).filter(([k]) => !output.has(k)));
}
function updateBody(name, before, template) {
  const body = { name, etag: before.etag, template };
  if (name === JOB) for (const key of ["labels", "annotations", "launchStage", "binaryAuthorization", "client", "clientVersion"])
    if (Object.hasOwn(before, key)) body[key] = structuredClone(before[key]);
  return body;
}
function assertAfter(after, before, template, p, kind) {
  settled(after);
  if (!same(unchangedConfiguration(after), unchangedConfiguration(before)) ||
      !same(after.template, template) || after.etag === before.etag ||
      BigInt(after.generation) <= BigInt(before.generation)) fail("deployment_readback_mismatch");
  if (kind === "service") {
    traffic(after, p.candidate);
    if (after.latestCreatedRevision !== `${SERVICE}/revisions/${p.candidate}` ||
        after.terminalCondition?.state !== "CONDITION_SUCCEEDED") fail("deployment_candidate_not_ready");
  }
}
function journalBindings(p, sha) {
  const objectCondition = names => ({ title: `install-${p.installationId}`,
    expression: names.map(n => `resource.name == 'projects/_/buckets/${BUCKET}/objects/${n}'`).join(" || ") });
  return [
    { role: `projects/${PROJECT}/roles/protectedEvidenceReader`,
      members: [`principal://iam.googleapis.com/${PROVIDER.split("/providers/")[0]}/subject/ft-install-${p.installationId}`],
      condition: objectCondition([`installations/by-sha/${sha}.json`]) },
    { role: `projects/${PROJECT}/roles/protectedEvidenceAppender`, members: [`serviceAccount:${p.deploymentServiceAccount}`],
      condition: objectCondition(JOURNAL_FILES.map(f => `installations/${p.installationId}/${f}.json`)) }
  ];
}
function iamFingerprint(policy) {
  const copy = structuredClone(policy); delete copy.etag;
  return digest(copy);
}
async function verifyIam(p, ports) {
  const plan = planObservationRegistration(p.policy);
  const policies = {};
  for (const [bucket, sha] of Object.entries(p.iam)) {
    policies[bucket] = await ports.bucketIam(bucket);
    const runtimePolicy = structuredClone(policies[bucket]);
    if (bucket === BUCKET) {
      // Remove only the TWO exact installation bindings after proving them.
      // This avoids a circular plan-hash -> IAM -> plan-hash dependency.
      for (const binding of journalBindings(p, digest(p))) {
        const matches = runtimePolicy.bindings?.filter(b => same(b, binding));
        if (matches?.length !== 1) fail("deployment_journal_scope_mismatch");
        runtimePolicy.bindings = runtimePolicy.bindings.filter(b => !same(b, binding));
      }
    }
    if (iamFingerprint(runtimePolicy) !== sha) fail("deployment_iam_changed");
  }
  const bucket = await ports.bucket(plan.proposedBucket.name);
  if (bucket.name !== plan.proposedBucket.name || bucket.location !== "US-CENTRAL1" || bucket.storageClass !== "STANDARD" ||
      bucket.iamConfiguration?.uniformBucketLevelAccess?.enabled !== true ||
      bucket.iamConfiguration?.publicAccessPrevention !== "enforced") fail("deployment_bucket_mismatch");
  for (const binding of [...plan.proposedBindings, plan.existingBindingToVerifyNotBroaden]) {
    const role = await ports.role(binding.role);
    if (role.deleted || !same((role.includedPermissions || []).slice().sort(), binding.requiredRolePermissions.slice().sort()))
      fail("deployment_role_changed");
    if (!policies[binding.bucket].bindings?.some(b => b.role === binding.role &&
        same((b.members || []).slice().sort(), binding.members.slice().sort()) &&
        b.condition?.expression === binding.condition.expression)) fail("deployment_binding_missing");
  }
  // This readback does not replace independent effective/inherited-permission proof.
}
async function reconcileDeployment(p, sha, ports, retained) {
  const root = `installations/${p.installationId}/`, intent = c.parse(retained.serialized);
  exact(intent, ["schemaVersion", "planSha256", "runId", "startedAt", "beforeConfiguration"]);
  if (intent.schemaVersion !== 1 || intent.planSha256 !== sha || !ID.test(intent.runId || "") ||
      !Number.isSafeInteger(intent.startedAt)) fail("deployment_retained_intent_mismatch");
  exact(intent.beforeConfiguration, ["job", "service"]);
  const states = [];
  for (const kind of ["job", "service"]) {
    const step = await ports.object(root + `${kind}-intent.json`), record = await ports.object(root + `${kind}-operation.json`);
    if (!step) { states.push({ kind, status: record ? "UNKNOWN_JOURNAL_ORDER" : "NOT_SUBMITTED_BY_THIS_RECEIVER" }); continue; }
    const planned = c.parse(step.serialized);
    exact(planned, ["planSha256", "beforeSha256", "desiredSha256"]);
    if (planned.planSha256 !== sha || planned.beforeSha256 !== p.before[kind].sha256 || !HASH.test(planned.desiredSha256 || ""))
      fail("deployment_retained_step_mismatch");
    if (!record) { states.push({ kind, status: "UNKNOWN_SUBMISSION_NO_OPERATION_RECORD" }); continue; }
    const submitted = c.parse(record.serialized);
    exact(submitted, ["name", "receivedAt", "planSha256"]);
    if (submitted.planSha256 !== sha || !new RegExp(`^${BASE}/operations/[A-Za-z0-9-]+$`).test(submitted.name || ""))
      fail("deployment_retained_operation_mismatch");
    const operation = await ports.operation(submitted.name), name = kind === "job" ? JOB : SERVICE;
    const current = await ports.resource(name);
    let status = "UNKNOWN_PENDING_OPERATION";
    if (operation.name !== submitted.name) fail("deployment_operation_binding_mismatch");
    if (operation.done === true) {
      status = "TERMINAL_FAILED_OR_MISMATCHED";
      if (!operation.error && operation.response?.name === name && operation.response?.uid === p.before[kind].uid) {
        settled(current);
        if (current.uid !== p.before[kind].uid || digest(current.template) !== planned.desiredSha256 ||
            digest(unchangedConfiguration(current)) !== intent.beforeConfiguration[kind]) fail("deployment_reconciliation_drift");
        if (kind === "service") traffic(current, p.candidate);
        status = "TERMINAL_DISABLED_STATE_MATCHES";
      }
    }
    states.push({ kind, status, operation: submitted.name, generation: current.generation });
  }
  assertBefore(await ports.resource(WORKER), WORKER, p.before.worker);
  await verifyIam(p, ports);
  return { status: "RECONCILED_READ_ONLY_NO_APPLY", states,
    finalReceiptPresent: Boolean(await ports.object(root + "result.json")),
    fullInstallationProven: false, xpAwarded: 0 };
}
async function executeDeployment({ plan: p, planSha256, claims, ports, now = Date.now, signal }) {
  validatePlan(p);
  if (digest(p) !== planSha256) fail("deployment_plan_hash_mismatch");
  claimsMatch(claims, p, planSha256);
  const start = now(), deadline = Math.min(p.notAfter, start + 600000);
  function time() { signal?.throwIfAborted(); if (now() < start || now() < p.notBefore || now() + 15000 >= deadline) fail("deployment_deadline"); }
  const journal = `installations/${p.installationId}/`, events = [], completed = new Map();
  signal?.throwIfAborted();
  const retained = await ports.object(journal + "intent.json");
  // Expired approval can still reconcile an earlier attempt, but never mutate.
  if (retained) return reconcileDeployment(p, planSha256, ports, retained);
  time();
  await verifyIam(p, ports);
  const before = { service: await ports.resource(SERVICE), job: await ports.resource(JOB), worker: await ports.resource(WORKER) };
  assertBefore(before.worker, WORKER, p.before.worker);
  const desired = desiredTemplates(p, before.service, before.job);
  if (await ports.revision(p.candidate)) fail("deployment_candidate_already_exists");
  time();
  const reserve = async (name, value) => {
    time(); const bytes = c.canonical(value), generation = await ports.create(name, bytes);
    const stored = await ports.object(name, generation);
    if (!ID.test(generation || "") || stored?.generation !== generation || stored.serialized !== bytes)
      fail("deployment_journal_uncertain_no_retry");
  };
  await reserve(journal + "intent.json", { schemaVersion: 1, planSha256, runId: claims.run_id, startedAt: now(),
    beforeConfiguration: { job: digest(unchangedConfiguration(before.job)), service: digest(unchangedConfiguration(before.service)) } });
  for (const kind of ["job", "service"]) {
    time();
    const name = kind === "job" ? JOB : SERVICE;
    // Recheck just before every mutation; initial readback is not a lease.
    for (const [resourceName, snapshot] of completed)
      if (!same(await ports.resource(resourceName), snapshot)) fail("deployment_completed_resource_changed");
    assertBefore(await ports.resource(name), name, p.before[kind]);
    assertBefore(await ports.resource(WORKER), WORKER, p.before.worker);
    await verifyIam(p, ports);
    await reserve(journal + `${kind}-intent.json`, { planSha256, beforeSha256: digest(before[kind]), desiredSha256: digest(desired[kind]) });
    time();
    let operation = await ports.patch(name, before[kind], desired[kind]);
    const operationName = operation?.name;
    if (!new RegExp(`^${BASE}/operations/[A-Za-z0-9-]+$`).test(operationName || "")) fail("deployment_operation_unknown");
    await reserve(journal + `${kind}-operation.json`, { name: operationName, receivedAt: now(), planSha256 });
    while (operation.done !== true) {
      time(); await ports.wait(1000); time(); operation = await ports.operation(operationName);
      if (operation?.name !== operationName) fail("deployment_operation_binding_mismatch");
    }
    if (operation.error || operation.response?.name !== name || operation.response?.uid !== before[kind].uid)
      fail("deployment_operation_failed_or_mismatched");
    const after = await ports.resource(name);
    assertAfter(after, before[kind], desired[kind], p, kind);
    await reserve(journal + `${kind}-result.json`, { planSha256, operation: operationName,
      generation: after.generation, etag: after.etag, sha256: digest(after), finishedAt: now() });
    completed.set(name, after);
    events.push({ kind, operation: operationName, generation: after.generation });
  }
  time();
  const service = await ports.resource(SERVICE), job = await ports.resource(JOB);
  assertAfter(service, before.service, desired.service, p, "service");
  assertAfter(job, before.job, desired.job, p, "job");
  assertBefore(await ports.resource(WORKER), WORKER, p.before.worker);
  await verifyIam(p, ports);
  const result = { status: "DISABLED_STAGING_PASS", planSha256, candidate: p.candidate,
    dispatcherImage: p.dispatcherImage, producerImage: p.policy.runtime.image,
    operations: events, completedAt: now(), trafficChanged: false, enrollmentEnabled: false,
    observationStarted: false, xpAwarded: 0 };
  await reserve(journal + "result.json", result);
  return result;
}

// Only these provider endpoints exist. No SDK credential discovery, CLI, IAM
// mutation, application invocation, secret read, job execution or retries.
function transport(fetcher = globalThis.fetch, signal) {
  return async (url, init = {}, missing = false) => {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 15000);
    const combined = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
    try {
      const response = await fetcher(url, { ...init, redirect: "error", signal: combined });
      if (missing && response.status === 404) return null;
      if (!response.ok || response.redirected) fail("deployment_provider_request_failed_no_retry");
      const reader = response.body.getReader(); let bytes = 0; const chunks = [];
      try { while (true) { const row = await reader.read(); if (row.done) break;
        bytes += row.value.length; if (bytes > 2 * 1024 * 1024) fail("deployment_response_too_large"); chunks.push(Buffer.from(row.value));
      } } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
      return Buffer.concat(chunks).toString("utf8");
    } catch (_) { fail("deployment_provider_request_failed_no_retry"); } finally { clearTimeout(timer); }
  };
}
function createPorts(request, token) {
  const headers = { authorization: `Bearer ${token}` }, json = async (url, init = {}, missing = false) => {
    const raw = await request(url, { ...init, headers: { ...headers, ...init.headers } }, missing);
    return raw === null ? null : JSON.parse(raw);
  };
  async function object(name, generation) {
    const root = `https://storage.googleapis.com/storage/v1/b/${BUCKET}/o/${encodeURIComponent(name)}`;
    const suffix = generation ? `?generation=${encodeURIComponent(generation)}` : "";
    const meta = await json(root + suffix, {}, true);
    if (!meta) return null;
    if (meta.name !== name || meta.bucket !== BUCKET || !ID.test(meta.generation || "")) fail("deployment_object_binding_rejected");
    const serialized = await request(`${root}?alt=media&generation=${meta.generation}`, { headers });
    const current = await json(root);
    if (current.generation !== meta.generation) fail("deployment_object_changed");
    return { generation: meta.generation, serialized };
  }
  return Object.freeze({ object,
    create: async (name, bytes) => (await json(`https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&ifGenerationMatch=0&name=${encodeURIComponent(name)}`,
      { method: "POST", headers: { "content-type": "application/json" }, body: bytes })).generation,
    resource: name => json(`https://run.googleapis.com/v2/${name}`),
    revision: candidate => json(`https://run.googleapis.com/v2/${SERVICE}/revisions/${candidate}`, {}, true),
    operation: name => json(`https://run.googleapis.com/v2/${name}`),
    patch: (name, before, template) => json(`https://run.googleapis.com/v2/${name}${name === SERVICE ? "?updateMask=template" : ""}`,
      { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(updateBody(name, before, template)) }),
    bucket: name => json(`https://storage.googleapis.com/storage/v1/b/${name}`),
    bucketIam: name => json(`https://storage.googleapis.com/storage/v1/b/${name}/iam?optionsRequestedPolicyVersion=3`),
    role: name => json(`https://iam.googleapis.com/v1/${name}`),
    wait: ms => new Promise(resolve => setTimeout(resolve, ms))
  });
}
async function runHosted(env = process.env, fetcher = globalThis.fetch, signal) {
  if (env.FOCUSTRACK_PROTECTED_DEPLOYMENT_ENABLED !== "1") return { status: "DISABLED", xpAwarded: 0 };
  signal = signal ? AbortSignal.any([signal, AbortSignal.timeout(600000)]) : AbortSignal.timeout(600000);
  const sha = env.FOCUSTRACK_INSTALL_PLAN_SHA256;
  audience(sha);
  if (env.GITHUB_ACTIONS !== "true" || env.RUNNER_ENVIRONMENT !== "github-hosted" || env.GITHUB_REPOSITORY !== REPO ||
      env.GITHUB_RUN_ATTEMPT !== "1" || env.GOOGLE_APPLICATION_CREDENTIALS || env.CLOUDSDK_AUTH_ACCESS_TOKEN ||
      !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) fail("deployment_hosted_context_required");
  const request = transport(fetcher, signal), oidcUrl = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  if (oidcUrl.protocol !== "https:" || !oidcUrl.hostname.endsWith(".actions.githubusercontent.com") ||
      oidcUrl.port || oidcUrl.username || oidcUrl.password || oidcUrl.hash) fail("deployment_oidc_url_rejected");
  oidcUrl.searchParams.set("audience", audience(sha));
  const oidc = JSON.parse(await request(oidcUrl, { headers: { authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } }));
  const claims = JSON.parse(Buffer.from(oidc.value.split(".")[1], "base64url").toString("utf8"));
  const post = async (url, body, token) => JSON.parse(await request(url, { method: "POST",
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) }));
  // STS, not the decode above, validates issuer/signature and independently
  // installed exact caller/callee/plan-audience conditions.
  const sts = await post("https://sts.googleapis.com/v1/token", {
    grantType: "urn:ietf:params:oauth:grant-type:token-exchange", audience: `//iam.googleapis.com/${PROVIDER}`,
    scope: "https://www.googleapis.com/auth/cloud-platform", requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
    subjectTokenType: "urn:ietf:params:oauth:token-type:jwt", subjectToken: oidc.value });
  if (typeof sts.access_token !== "string" || !sts.access_token) fail("deployment_federation_rejected");
  const stored = await createPorts(request, sts.access_token).object(`installations/by-sha/${sha}.json`);
  if (!stored || c.hash(stored.serialized) !== sha) fail("deployment_approved_plan_missing");
  const plan = c.parse(stored.serialized); validatePlan(plan); claimsMatch(claims, plan, sha);
  if (env.FOCUSTRACK_INSTALLER_COMMIT !== plan.installerCommit) fail("deployment_checkout_mismatch");
  const sa = await post(`https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${plan.deploymentServiceAccount}:generateAccessToken`,
    { scope: ["https://www.googleapis.com/auth/cloud-platform"], lifetime: "900s" }, sts.access_token);
  if (typeof sa.accessToken !== "string" || !sa.accessToken) fail("deployment_identity_rejected");
  return executeDeployment({ plan, planSha256: sha, claims, ports: createPorts(request, sa.accessToken), signal });
}
if (require.main === module) {
  const abort = new AbortController();
  process.on("SIGINT", () => abort.abort()); process.on("SIGTERM", () => abort.abort());
  runHosted(process.env, globalThis.fetch, abort.signal).then(r => {
    console.log(JSON.stringify(r)); if (!["DISABLED", "DISABLED_STAGING_PASS"].includes(r.status)) process.exitCode = 1;
  }).catch(e => { console.error(JSON.stringify({ status: "UNKNOWN_STOPPED_NO_RETRY",
    reason: /^deployment_[a-z_]+$/.test(e.message || "") ? e.message : "deployment_interrupted_or_unclassified",
    recovery: "READ_ONLY_RECONCILIATION_REQUIRED", xpAwarded: 0 })); process.exitCode = 1; });
}
module.exports = { validatePlan, desiredTemplates, executeDeployment, reconcileDeployment, createPorts, transport, runHosted, claimsMatch, audience,
  digest, iamFingerprint, journalBindings, JOURNAL_FILES, PROJECT, REGION, BASE, SERVICE, JOB, WORKER, BUCKET, REPO, WORKFLOW, ENVIRONMENT, PROVIDER, SOURCE, ZERO_GATES };
