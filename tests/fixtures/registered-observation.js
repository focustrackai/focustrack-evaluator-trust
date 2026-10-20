"use strict";
const crypto = require("node:crypto"), assert = require("node:assert/strict");
const c = require("../../cloud/history-checkpoint/contract.js"), n = require("../../cloud/history-checkpoint/cloud-run-runtime.js");
const { nativePolicyFixture } = require("./history-checkpoint-native-policy.js");
const { authoritySha256 } = require("../../cloud/history-checkpoint/registered-observation.js");

// Entirely synthetic: actual HTTP adapters, in-memory provider responses, no network.
function registeredFixture() {
  let time = 1800000000000, generation = 0;
  const bytes = "test baseline", taskId = `codex_prospective_${"e".repeat(24)}`, slotId = "a".repeat(32);
  const config = { schemaVersion: 1, taskId, enrollmentId: "b".repeat(32), profileBindingSha256: "c".repeat(64),
    registrationSha256: "d".repeat(64), expiresAt: time + 3600000,
    jobUid: "11111111-2222-4333-8444-555555555555", templateSha256: "2".repeat(64),
    image: `us-central1-docker.pkg.dev/focustrack-eval-20260927/evaluator-vault/history-checkpoint-producer@sha256:${"1".repeat(64)}` };
  const source = { profileBindingSha256: config.profileBindingSha256, criteriaSha256: "c".repeat(64), baselineSha256: c.hash(bytes),
    ownerSubject: "11111111-1111-4111-8111-111111111111", runnerSubject: "22222222-2222-4222-8222-222222222222",
    sourceRepository: "fixture/private", sourceRepositoryId: "123", sourceOwnerId: "456", baselineCommit: "d".repeat(40),
    identityIssuer: "https://fixture.supabase.co/auth/v1", identityAudience: "authenticated",
    baselineFiles: [{ path: "subject.js", bytes: Buffer.byteLength(bytes), sha256: c.hash(bytes) }], subjectPath: "subject.js" };
  const key = crypto.generateKeyPairSync("ed25519");
  const trust = { keyId: "fixture_receipt", evaluatorRepository: "fixture/evaluator", evaluatorCommit: "e".repeat(40),
    publicKeyPem: key.publicKey.export({ type: "spki", format: "pem" }), notBefore: time - 1000, notAfter: config.expiresAt + 1,
    revoked: false, independenceApproved: true };
  const { policy } = nativePolicyFixture(config, source, trust), evaluator = policy.observationSelection.evaluator;
  delete policy.observationSelection;
  policy.observationRegistration = { schemaVersion: 1, slotId, taskId, notBefore: time, notAfter: config.expiresAt,
    observation: { schemaVersion: 1, bucket: `focustrack-observation-slot-${slotId}`,
      receiptBucket: "focustrack-evaluator-receipts-818502899155", config: source, receiptTrust: trust },
    history: { enrollmentId: config.enrollmentId, jobUid: config.jobUid, image: config.image,
      evaluator, producerAuthoritySha256: authoritySha256(policy) } };
  const env = { FOCUSTRACK_HISTORY_PRODUCER_ENABLED: "1", FOCUSTRACK_HISTORY_OBSERVATION_INPUT_ENABLED: "1",
    FOCUSTRACK_HISTORY_SOURCE_READER_ENABLED: "1", FOCUSTRACK_HISTORY_ENROLLMENT_ID: config.enrollmentId,
    CLOUD_RUN_JOB: n.JOB.split("/").pop(), CLOUD_RUN_EXECUTION: "focustrack-history-checkpoint-producer-fixture",
    CLOUD_RUN_TASK_COUNT: "1", CLOUD_RUN_TASK_INDEX: "0", CLOUD_RUN_TASK_ATTEMPT: "0" };
  const template = { serviceAccount: n.SA, maxRetries: 0, timeout: "600s", containers: [{ image: config.image,
    command: ["node", "cloud/history-checkpoint/producer.js"],
    env: n.ENVS.map(name => ({ name, value: name === n.POLICY_ENV ? c.canonical(policy) : env[name] })) }] };
  policy.runtime.templateSha256 = n.nativeTemplateSha256(template);
  template.containers[0].env[0].value = c.canonical(policy);
  const execution = { name: `${n.JOB}/executions/${env.CLOUD_RUN_EXECUTION}`, uid: "22222222-2222-4333-8444-555555555555",
    job: n.JOB, creator: n.INVOKER, taskCount: 1, parallelism: 1, template: structuredClone(template) };
  const job = { name: n.JOB, uid: config.jobUid, generation: "2", observedGeneration: "2", etag: "TEST_ETAG",
    template: { taskCount: 1, parallelism: 1, template } };
  const claims = { iss: source.identityIssuer, aud: "authenticated", sub: source.runnerSubject, role: "authenticated", exp: Math.floor((time + 3600000) / 1000) };
  const request = { headers: { authorization: `Bearer test.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.test` } };
  const objects = new Map(), calls = [];
  const f = { policy, config, source, env, job, execution, request, objects, calls, taskId, body: { taskId },
    now: () => time, tick: ms => { time += ms; }, getAccessToken: async () => "TEST_ONLY_ACCESS_NOT_A_CREDENTIAL",
    getGitHubSourceToken: async () => "TEST_ONLY_SOURCE_NOT_A_CREDENTIAL" };
  f.environment = { FOCUSTRACK_OBSERVATION_REGISTRATION_ENABLED: "1", FOCUSTRACK_SUPABASE_PUBLISHABLE_KEY: "TEST_ONLY_PUBLIC_KEY",
    FOCUSTRACK_OBSERVATION_REGISTRATION_POLICY_JSON: c.canonical(policy) };
  f.fetch = async (input, init = {}) => {
    const url = new URL(input), method = init.method || "GET";
    init.signal?.throwIfAborted(); calls.push({ url: String(url), method });
    if (f.intercept) { const value = await f.intercept(url, init); if (value) return value; }
    const json = value => new Response(JSON.stringify(value));
    if (url.origin === "https://fixture.supabase.co") {
      assert.equal(init.headers.authorization, request.headers.authorization);
      return json({ id: source.runnerSubject, is_anonymous: false });
    }
    if (url.origin === "https://api.github.com") {
      const prefix = `/repos/${source.sourceRepository}`;
      if (url.pathname === prefix) return json({ private: true, id: 123, owner: { id: 456 }, full_name: source.sourceRepository });
      if (url.pathname === prefix + "/git/commits/" + source.baselineCommit) return json({ sha: source.baselineCommit });
      if (url.pathname === prefix + "/contents/subject.js") return json({ type: "file", path: "subject.js", encoding: "base64",
        content: Buffer.from(bytes).toString("base64"), size: Buffer.byteLength(bytes),
        sha: crypto.createHash("sha1").update(`blob ${Buffer.byteLength(bytes)}\0${bytes}`).digest("hex") });
    }
    if (url.hostname === "metadata.google.internal") {
      const value = url.pathname.endsWith("project-id") ? "focustrack-eval-20260927" : url.pathname.endsWith("/email") ? n.SA :
        JSON.stringify({ access_token: await f.getAccessToken(), token_type: "Bearer", expires_in: 600 });
      return new Response(value, { headers: { "Metadata-Flavor": "Google" } });
    }
    if (url.origin === "https://run.googleapis.com") {
      if (url.pathname === `/v2/${n.JOB}`) return json(job);
      if (url.pathname === `/v2/${execution.name}`) return json(execution);
    }
    if (url.origin === "https://storage.googleapis.com") {
      const bucket = url.pathname.split("/b/")[1].split("/")[0];
      const name = url.searchParams.get("name") || decodeURIComponent(url.pathname.split("/o/")[1]);
      const mapKey = bucket + "/" + name;
      if (method === "POST") {
        assert.equal(url.searchParams.get("ifGenerationMatch"), "0");
        if (objects.has(mapKey)) return new Response("", { status: 412 });
        objects.set(mapKey, { serialized: init.body, generation: String(++generation), createdAt: ++time });
      }
      const raw = objects.get(mapKey);
      if (!raw || (url.searchParams.has("generation") && raw.generation !== url.searchParams.get("generation"))) return new Response("", { status: 404 });
      return url.searchParams.get("alt") === "media" ? new Response(raw.serialized) : json({ bucket, name,
        generation: raw.generation, timeCreated: new Date(raw.createdAt).toISOString(), size: String(Buffer.byteLength(raw.serialized)) });
    }
    throw Error("TEST_UNEXPECTED_ROUTE " + url.origin + url.pathname);
  };
  return f;
}
module.exports = { registeredFixture };
