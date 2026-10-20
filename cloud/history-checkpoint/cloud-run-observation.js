"use strict";

const c = require("./contract.js");
const { executionName } = require("./cloud-run-runtime.js");
const PROJECT = "focustrack-eval-20260927";
const WORKER_JOB = `projects/${PROJECT}/locations/us-central1/jobs/focustrack-evaluator-worker`;
const HASH = /^[a-f0-9]{64}$/, GEN = /^[1-9][0-9]{0,19}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const positive = n => Number.isSafeInteger(n) && n > 0;
const fail = () => { throw Error("producer_observation_selection_rejected"); };
function exact(value, fields) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).length !== fields.length ||
      fields.some(k => !Object.hasOwn(value, k))) fail();
}
function validateSelection(selection, enrollmentId) {
  exact(selection, ["taskId", "enrollmentId", "profileBindingSha256", "registrationSha256", "expiresAt", "evaluator"]);
  const e = selection.evaluator;
  exact(e, ["job", "jobUid", "creator", "serviceAccount", "workerImage", "templateSha256"]);
  if (!/^codex_prospective_[a-f0-9]{24}$/.test(selection.taskId || "") || !c.OPAQUE.test(enrollmentId || "") ||
      selection.enrollmentId !== enrollmentId || !HASH.test(selection.profileBindingSha256 || "") ||
      !HASH.test(selection.registrationSha256 || "") || !positive(selection.expiresAt) || e.job !== WORKER_JOB ||
      !UUID.test(e.jobUid || "") || e.creator !== `evaluator-dispatcher@${PROJECT}.iam.gserviceaccount.com` ||
      e.serviceAccount !== `evaluator-worker@${PROJECT}.iam.gserviceaccount.com` || !HASH.test(e.templateSha256 || "") ||
      !/^us-central1-docker\.pkg\.dev\/focustrack-eval-20260927\/evaluator-vault\/vault@sha256:[a-f0-9]{64}$/.test(e.workerImage || "")) fail();
  return selection;
}

// Rules are sealed before work; only authenticated protected/provider reads may
// supply later generations and execution IDs. No caller policy or latest-search fallback.
async function resolveObservationInput(selection, ports, now) {
  const s = c.parse(c.canonical(validateSelection(selection, selection.enrollmentId)));
  if ([ports.readObservation, ports.readCloudRunJob, ports.readCloudRunExecution, now].some(fn => typeof fn !== "function")) fail();
  let last = 0;
  const clock = () => { const t = now(); if (!positive(t) || t < last || t >= s.expiresAt) fail(); last = t; return t; };
  clock();
  function pin(name, raw) {
    if (raw?.status !== "found" || !GEN.test(raw.generation || "") || !positive(raw.createdAt) || raw.createdAt > clock()) fail();
    c.parse(raw.serialized);
    return { name, generation: raw.generation, sha256: c.hash(raw.serialized), createdAt: raw.createdAt };
  }
  const prefix = `observations/${s.taskId}/`, declarationName = prefix + "declaration.json", joinName = prefix + "profile-join.json";
  const declarationRaw = await ports.readObservation(declarationName), declarationPin = pin(declarationName, declarationRaw);
  const joinRaw = await ports.readObservation(joinName), joinPin = pin(joinName, joinRaw);
  const declaration = c.parse(declarationRaw.serialized), join = c.parse(joinRaw.serialized);
  if (declaration.evidenceClass !== "prospective_no_award" || declaration.registrationSha256 !== s.registrationSha256 ||
      c.hash(c.canonical({ schemaVersion: 1, evidenceClass: "prospective_no_award", config: declaration.config })) !== s.registrationSha256 ||
      declaration.config?.taskId !== s.taskId || declaration.config.profileBindingSha256 !== s.profileBindingSha256 ||
      c.canonical(join.declaration) !== c.canonical(declarationPin)) fail();
  const e = s.evaluator;
  function selectedExecution(job) {
    if (job?.name !== e.job || job.uid !== e.jobUid || !GEN.test(job.generation || "") || job.generation !== job.observedGeneration ||
        (job.reconciling !== undefined && job.reconciling !== false) || job.deleteTime || job.expireTime ||
        job.template?.taskCount !== 1 || job.template?.parallelism !== 1 || job.template.template?.serviceAccount !== e.serviceAccount ||
        job.template.template?.containers?.[0]?.image !== e.workerImage ||
        c.cloudRunTemplateSha256(job.template.template) !== e.templateSha256) fail();
    const name = executionName(e.job, job.latestCreatedExecution?.name);
    if (typeof name !== "string" || !name.startsWith(e.job + "/executions/") ||
        !/^focustrack-evaluator-worker-[a-z0-9]+$/.test(name.slice((e.job + "/executions/").length))) fail();
    return name;
  }
  const job = await ports.readCloudRunJob(e.job), execution = selectedExecution(job);
  const run = await ports.readCloudRunExecution(execution);
  if (run?.name !== execution || !UUID.test(run.uid || "") || ![e.job, e.job.split("/").pop()].includes(run.job) ||
      run.creator !== e.creator || run.template?.serviceAccount !== e.serviceAccount ||
      run.template?.containers?.[0]?.image !== e.workerImage || c.cloudRunTemplateSha256(run.template) !== e.templateSha256) fail();
  // The existing input writer rechecks success, chronology, exact BINDING_JSON,
  // signatures and private source bytes before any input is created or signed.
  for (const expected of [declarationPin, joinPin]) {
    if (c.canonical(pin(expected.name, await ports.readObservation(expected.name, { generation: expected.generation }))) !== c.canonical(expected)) fail();
  }
  const after = await ports.readCloudRunJob(e.job);
  if (selectedExecution(after) !== execution || after.generation !== job.generation) fail();
  clock();
  return { taskId: s.taskId, enrollmentId: s.enrollmentId, profileBindingSha256: s.profileBindingSha256,
    declarationPin, joinPin, evaluator: { provider: "google_cloud_run_v2", execution, uid: run.uid,
      creator: e.creator, serviceAccount: e.serviceAccount, workerImage: e.workerImage, templateSha256: e.templateSha256 }, expiresAt: s.expiresAt };
}

module.exports = { validateSelection, resolveObservationInput, WORKER_JOB };
