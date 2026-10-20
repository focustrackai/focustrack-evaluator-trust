"use strict";

const c = require("./contract.js");
const PROJECT = "focustrack-eval-20260927";
const JOB = `projects/${PROJECT}/locations/us-central1/jobs/focustrack-history-checkpoint-producer`;
const SA = `history-checkpoint-producer@${PROJECT}.iam.gserviceaccount.com`;
const INVOKER = `evaluator-dispatcher@${PROJECT}.iam.gserviceaccount.com`;
const KIND = "google_cloud_run_job_v1";
const POLICY_ENV = "FOCUSTRACK_HISTORY_PRODUCER_POLICY";
const HASH = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const IMAGE = /^us-central1-docker\.pkg\.dev\/focustrack-eval-20260927\/evaluator-vault\/history-checkpoint-producer@sha256:[a-f0-9]{64}$/;
const ENVS = [POLICY_ENV, "FOCUSTRACK_HISTORY_PRODUCER_ENABLED", "FOCUSTRACK_HISTORY_OBSERVATION_INPUT_ENABLED",
  "FOCUSTRACK_HISTORY_SOURCE_READER_ENABLED", "FOCUSTRACK_HISTORY_ENROLLMENT_ID"];
const fail = () => { throw Error("producer_native_runtime_rejected"); };

// Job ExecutionReference uses a short name; Execution itself uses a full name.
function executionName(job, name) {
  if (![JOB, `projects/${PROJECT}/locations/us-central1/jobs/focustrack-evaluator-worker`].includes(job) || typeof name !== "string") return undefined;
  const prefix = job + "/executions/", short = name.startsWith(prefix) ? name.slice(prefix.length) : name;
  return new RegExp(`^${job.split("/").pop()}-[a-z0-9]+$`).test(short) ? prefix + short : undefined;
}

function validateNativeConfiguration(policy) {
  const r = policy.runtime, fields = ["kind", "job", "jobUid", "image", "templateSha256", "enrollmentId"];
  if (!r || Object.keys(r).length !== fields.length || fields.some(k => !Object.hasOwn(r, k)) ||
      r.kind !== KIND || r.job !== JOB || !UUID.test(r.jobUid || "") || !IMAGE.test(r.image || "") ||
      !HASH.test(r.templateSha256 || "") || /^0+$/.test(r.templateSha256) || !c.OPAQUE.test(r.enrollmentId || "") ||
      policy.workflowSha !== undefined || policy.repositoryId !== undefined || policy.repositoryOwnerId !== undefined ||
      [policy.observationInput, policy.observationSelection, policy.observationRegistration].filter(Boolean).length !== 1 ||
      (!policy.observationRegistration && (policy.observationInput || policy.observationSelection)?.enrollmentId !== r.enrollmentId) || !policy.sourceReader) fail();
  if (policy.observationSelection) require("./cloud-run-observation.js").validateSelection(policy.observationSelection, r.enrollmentId);
  if (policy.observationRegistration) require("./registered-observation.js").validateRegisteredPolicy(policy);
  return r;
}

function validateNativePolicy(policy, env) {
  const r = validateNativeConfiguration(policy);
  if (env.FOCUSTRACK_HISTORY_ENROLLMENT_ID !== r.enrollmentId || env.CLOUD_RUN_JOB !== JOB.split("/").pop() ||
      !/^focustrack-history-checkpoint-producer-[a-z0-9]+$/.test(env.CLOUD_RUN_EXECUTION || "") ||
      env.CLOUD_RUN_TASK_COUNT !== "1" || env.CLOUD_RUN_TASK_INDEX !== "0" || env.CLOUD_RUN_TASK_ATTEMPT !== "0" ||
      ["GITHUB_ACTIONS", "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS"].some(k => env[k] !== undefined)) fail();
  return r;
}

function nativeTemplateSha256(template) {
  const copy = c.parse(c.canonical(template));
  if (copy.serviceAccount !== SA || copy.timeout !== "600s" || copy.maxRetries !== 0 ||
      (copy.volumes !== undefined && (!Array.isArray(copy.volumes) || copy.volumes.length !== 0)) ||
      !Array.isArray(copy.containers) || copy.containers.length !== 1) fail();
  const container = copy.containers[0];
  if (!IMAGE.test(container.image || "") || c.canonical(container.command) !== '["node","cloud/history-checkpoint/producer.js"]' ||
      (container.args !== undefined && c.canonical(container.args) !== "[]") ||
      (container.volumeMounts !== undefined && c.canonical(container.volumeMounts) !== "[]") ||
      !Array.isArray(container.env) || container.env.length !== ENVS.length ||
      new Set(container.env.map(e => e?.name)).size !== ENVS.length ||
      container.env.some(e => !e || Object.keys(e).length !== 2 || !ENVS.includes(e.name) || typeof e.value !== "string")) fail();
  const entry = container.env.find(e => e.name === POLICY_ENV), policy = c.parse(entry.value);
  if (policy.runtime?.kind !== KIND || !HASH.test(policy.runtime.templateSha256 || "")) fail();
  // Only the self-referential hash slot is masked; all policy/input/command/env bytes remain pinned.
  policy.runtime.templateSha256 = "<self-template-sha256>";
  entry.value = c.canonical(policy);
  return c.hash(c.canonical(copy));
}

function verifyNativeExecution(policy, env, job, execution) {
  const r = validateNativePolicy(policy, env), name = `${JOB}/executions/${env.CLOUD_RUN_EXECUTION}`;
  const generation = v => typeof v === "string" && /^[1-9][0-9]*$/.test(v);
  if (job?.name !== JOB || job.uid !== r.jobUid || !generation(job.generation) || job.observedGeneration !== job.generation ||
      (job.reconciling !== undefined && job.reconciling !== false) || job.deleteTime || job.expireTime ||
      executionName(JOB, job.latestCreatedExecution?.name) !== name || job.template?.taskCount !== 1 || job.template?.parallelism !== 1 ||
      execution?.name !== name || !UUID.test(execution.uid || "") ||
      ![JOB, JOB.split("/").pop()].includes(execution.job) || execution.creator !== INVOKER ||
      execution.taskCount !== 1 || execution.parallelism !== 1 || execution.deleteTime || execution.expireTime ||
      ["retriedCount", "failedCount", "cancelledCount"].some(k => execution[k] !== undefined && execution[k] !== 0)) fail();
  for (const template of [job.template.template, execution.template]) {
    if (template?.containers?.[0]?.image !== r.image || nativeTemplateSha256(template) !== r.templateSha256) fail();
    const values = Object.fromEntries(template.containers[0].env.map(e => [e.name, e.value]));
    if (values[POLICY_ENV] !== c.canonical(policy) || ENVS.filter(k => k !== POLICY_ENV).some(k => values[k] !== env[k])) fail();
  }
}

async function nativeAccessToken(policy, env, request) {
  validateNativePolicy(policy, env);
  const base = "http://metadata.google.internal/computeMetadata/v1/";
  const metadata = path => request(base + path, { headers: { "Metadata-Flavor": "Google" } }, 32768, 5000);
  try {
    if ((await metadata("project/project-id")).trim() !== PROJECT ||
        (await metadata("instance/service-accounts/default/email")).trim() !== SA) fail();
    const value = JSON.parse(await metadata("instance/service-accounts/default/token"));
    if (value.token_type !== "Bearer" || !Number.isInteger(value.expires_in) || value.expires_in < 60 ||
        typeof value.access_token !== "string" || !/^[^\s]{20,16384}$/.test(value.access_token)) fail();
    await revalidateNativeExecution(policy, env, request, value.access_token);
    return value.access_token;
  } catch (_) { fail(); }
}

async function revalidateNativeExecution(policy, env, request, token) {
  try {
    validateNativePolicy(policy, env);
    const read = async name => JSON.parse(await request(`https://run.googleapis.com/v2/${name}`,
      { headers: { authorization: `Bearer ${token}` } }));
    const job = await read(JOB), execution = await read(`${JOB}/executions/${env.CLOUD_RUN_EXECUTION}`);
    verifyNativeExecution(policy, env, job, execution);
  } catch (_) { fail(); }
}

module.exports = { validateNativePolicy, validateNativeConfiguration, nativeTemplateSha256, verifyNativeExecution, nativeAccessToken, revalidateNativeExecution,
  executionName, JOB, SA, INVOKER, KIND, POLICY_ENV, ENVS };
