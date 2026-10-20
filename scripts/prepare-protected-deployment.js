"use strict";

const fs = require("node:fs"), path = require("node:path");
const d = require("./protected-registration-deploy.js");
const c = require("../cloud/history-checkpoint/contract.js");
const { planObservationRegistration } = require("./plan-observation-registration.js");
const clone = x => JSON.parse(JSON.stringify(x));
const fail = code => { throw Error(code); };
function mergePolicy(before, added) {
  if (!before || before.version !== 3 || typeof before.etag !== "string" || !before.etag || !Array.isArray(before.bindings))
    fail("bootstrap_fresh_iam_v3_etag_required");
  const after = clone(before);
  for (const b of added) {
    if (after.bindings.some(row => c.canonical(row) === c.canonical(b))) fail("bootstrap_binding_already_present_reconcile");
    after.bindings.push(b);
  }
  return after;
}
function bootstrap(plan, state) {
  const registration = d.validatePlan(plan), planBytes = c.canonical(plan), sha = c.hash(planBytes);
  if (!state || Object.keys(state).sort().join() !== ["providerAbsent", "pool", "existingProviders", "deploymentAccount", "controlsIam", "projectIam", "runtimeIam", "roleAbsent"].sort().join() ||
      state.providerAbsent !== true || state.pool?.name !== d.PROVIDER.split("/providers/")[0] ||
      state.pool.state !== "ACTIVE" || state.pool.disabled === true ||
      state.deploymentAccount?.email !== plan.deploymentServiceAccount || state.deploymentAccount.disabled === true ||
      state.roleAbsent !== true) fail("bootstrap_current_independent_prestate_required");
  // The independently reviewed existing pool must not map other providers to
  // this constant subject. Its custody/effective-permission proof is separate.
  // Existing provider subjects must retain GitHub's repo: namespace. Unknown
  // mappings fail; a new provider shares the pool's principal namespace.
  if (!Array.isArray(state.existingProviders) || !state.existingProviders.length ||
      state.existingProviders.some(p => !p.name?.startsWith(state.pool.name + "/providers/") ||
        p.name === d.PROVIDER || p.oidc?.issuerUri !== "https://token.actions.githubusercontent.com" ||
        p.attributeMapping?.["google.subject"] !== "assertion.sub" || p.saml || p.aws))
    fail("bootstrap_pool_subject_separation_unproven");
  const subject = `ft-install-${plan.installationId}`;
  const principal = `principal://iam.googleapis.com/${state.pool.name}/subject/${subject}`;
  const member = `serviceAccount:${plan.deploymentServiceAccount}`;
  const name = `installations/by-sha/${sha}.json`;
  const conditions = { iss: "https://token.actions.githubusercontent.com", aud: d.audience(sha),
    repository: d.REPO, repository_id: plan.repositoryId, repository_owner_id: plan.repositoryOwnerId,
    job_workflow_ref: `${d.REPO}/${d.WORKFLOW}@${plan.installerCommit}`, job_workflow_sha: plan.installerCommit,
    event_name: "workflow_dispatch", ref: "refs/heads/main", environment: d.ENVIRONMENT,
    runner_environment: "github-hosted", run_attempt: "1" };
  const provider = { displayName: "FocusTrack exact disabled deployment", disabled: true,
    oidc: { issuerUri: conditions.iss, allowedAudiences: [conditions.aud] },
    attributeMapping: { "google.subject": `'${subject}'` },
    attributeCondition: Object.entries(conditions).map(([k, v]) => `assertion.${k} == '${v}'`).join(" && ") };
  const roles = {
    focustrackDisabledRunStager: ["run.services.get", "run.services.update", "run.revisions.get", "run.jobs.get", "run.jobs.update"],
    focustrackInstallMetadataReader: ["run.operations.get", "iam.roles.get", "storage.buckets.get", "storage.buckets.getIamPolicy"]
  };
  const roleResources = Object.entries(roles).map(([id, includedPermissions]) => ({ id,
    body: { title: id, description: "EX538 disabled staging only; immutable receiver also restricts request bodies", stage: "GA", includedPermissions } }));
  const scopedRun = { role: `projects/${d.PROJECT}/roles/focustrackDisabledRunStager`, members: [member],
    condition: { title: `install-${plan.installationId}`, expression:
      `resource.name == '${d.SERVICE}' || resource.name == '${d.JOB}' || resource.name == '${d.SERVICE}/revisions/${plan.candidate}'` } };
  // Worker gets read only through a separate binding, never jobs.update.
  const workerReadRole = { id: "focustrackInstallWorkerReader", body: { title: "focustrackInstallWorkerReader", stage: "GA", includedPermissions: ["run.jobs.get"] } };
  roleResources.push(workerReadRole);
  const projectAfter = mergePolicy(state.projectIam, [scopedRun,
    { role: `projects/${d.PROJECT}/roles/${workerReadRole.id}`, members: [member], condition: { title: `install-worker-${plan.installationId}`, expression: `resource.name == '${d.WORKER}'` } },
    { role: `projects/${d.PROJECT}/roles/focustrackInstallMetadataReader`, members: [member] }]);
  if (d.iamFingerprint(state.controlsIam) !== plan.iam[d.BUCKET]) fail("bootstrap_controls_prestate_mismatch");
  const controlsAfter = mergePolicy(state.controlsIam, d.journalBindings(plan, sha));
  const serviceAccountPolicies = [{ email: plan.deploymentServiceAccount,
    before: state.deploymentAccount.iam,
    after: mergePolicy(state.deploymentAccount.iam, [{ role: "roles/iam.workloadIdentityUser", members: [principal] }]) }];
  const runtimeEmails = [`evaluator-dispatcher@${d.PROJECT}.iam.gserviceaccount.com`, `history-checkpoint-producer@${d.PROJECT}.iam.gserviceaccount.com`];
  if (!state.runtimeIam || Object.keys(state.runtimeIam).sort().join() !== runtimeEmails.sort().join()) fail("bootstrap_runtime_prestate_required");
  for (const email of runtimeEmails) serviceAccountPolicies.push({ email, before: state.runtimeIam[email],
    after: mergePolicy(state.runtimeIam[email], [{ role: "roles/iam.serviceAccountUser", members: [member] }]) });
  const caller = `name: Stage approved disabled registration\non:\n  workflow_dispatch:\npermissions:\n  contents: read\n  id-token: write\njobs:\n  stage:\n    uses: ${d.REPO}/${d.WORKFLOW}@${plan.installerCommit}\n    with:\n      approved_plan_sha256: '${sha}'\n`;
  const requests = [];
  const add = (id, method, url, body, prestate, effect) => requests.push({ id, method, url, body,
    prestateSha256: prestate === null ? null : d.digest(prestate), effect, retries: 0,
    onUncertain: "STOP_AND_RECONCILE_READ_ONLY; never repeat from an absent snapshot" });
  for (const role of roleResources) add(`role-${role.id}`, "POST",
    `https://iam.googleapis.com/v1/projects/${d.PROJECT}/roles`, { roleId: role.id, role: role.body }, null, "Create this exact role only if absent; no replacement");
  add("disabled-provider", "POST", `https://iam.googleapis.com/v1/${state.pool.name}/providers?workloadIdentityPoolProviderId=pinned-deployment`, provider, null,
    "Create disabled; wait for terminal operation and compare complete provider configuration");
  add("project-bindings", "POST", `https://cloudresourcemanager.googleapis.com/v1/projects/${d.PROJECT}:setIamPolicy`,
    { policy: projectAfter }, state.projectIam, "Preserve existing bindings and supplied etag; never force overwrite");
  add("controls-bindings", "PUT", `https://storage.googleapis.com/storage/v1/b/${d.BUCKET}/iam`, controlsAfter, state.controlsIam,
    "Private approval read and exact install-journal get/create only; no task evidence write");
  for (const row of serviceAccountPolicies) add(`sa-${row.email.split("@")[0]}`, "POST",
    `https://iam.googleapis.com/v1/projects/${d.PROJECT}/serviceAccounts/${row.email}:setIamPolicy`,
    { policy: row.after }, row.before, "Preserve etag and bindings; WIF only on selected deploy account, actAs only on existing runtimes");
  add("approval-object", "POST", `https://storage.googleapis.com/upload/storage/v1/b/${d.BUCKET}/o?uploadType=media&ifGenerationMatch=0&name=${encodeURIComponent(name)}`,
    { privateLocalBodyFile: "approved-plan.json", sha256: sha }, null, "Upload exact canonical private bytes once, then generation/hash readback");
  return { planBytes, caller, packet: { schemaVersion: 1, status: "PREPARED_NOT_INSTALLED", planSha256: sha,
    sourceContextSha256: plan.sourceContextSha256, providerResource: d.PROVIDER, provider, requests,
    registrationPrerequisites: registration,
    requiredBeforeExecution: ["Independent control of existing pool, selected deploy account and provider IAM, outside both working sessions",
      "Other providers cannot map to this installation subject; selected deploy identity has no broader inherited or direct authority",
      "Exact context built once and both approved digest/provenance records verified; no build by this receiver",
      "Registration bucket and exact 7/5/1 grants provisioned independently; existing history three-object grant verify-only",
      "Separate Supabase disabled staging completed with its own protected authority; no token passed to GitHub",
      "Same genuine reviewer approves this exact new source before protected use",
      "Fresh plan prestate/etags and installed IAM hashes (after setup) still match; no expiring observation started"],
    activation: { separateDecisionRequired: true, providerRemainsDisabled: true, githubVariableRemainsAbsentOrZero: true,
      instructions: "After terminal setup readbacks and review, separately authorize exact provider enable + environment flag. Do not execute merely because this file exists." },
    recovery: { disableProvider: d.PROVIDER, preserveJournal: true, automaticRollback: false,
      instructions: "No unconditional rollback. Reconcile all submitted operations, compare current state to owned poststate, then separately review exact etag-bound restore. Baseline traffic never intentionally changes." },
    liveProviderCalls: 0, newServiceAccounts: 0, observationStarted: false, xpAwarded: 0 } };
}
function main(argv) {
  if (argv.length !== 4 || argv[0] !== "--input" || argv[2] !== "--out") fail("usage: node scripts/prepare-protected-deployment.js --input independently-approved-install.json --out NEW_PRIVATE_DIRECTORY");
  const input = JSON.parse(fs.readFileSync(argv[1], "utf8"));
  if (Object.keys(input).sort().join() !== "bootstrap,plan") fail("bootstrap_input_fields_rejected");
  const result = bootstrap(input.plan, input.bootstrap), out = path.resolve(argv[3]);
  // New output directory only, so previous approvals/receipts cannot be replaced.
  fs.mkdirSync(out, { mode: 0o700 });
  const files = { "approved-plan.json": result.planBytes, "bootstrap-requests.json": JSON.stringify(result.packet, null, 2) + "\n",
    "stage-approved-registration.yml": result.caller };
  for (const [name, bytes] of Object.entries(files)) fs.writeFileSync(path.join(out, name), bytes, { flag: "wx", mode: 0o600 });
  console.log(JSON.stringify({ status: result.packet.status, files: Object.entries(files).map(([name, bytes]) => ({ name, sha256: c.hash(bytes) })), providerCalls: 0 }));
}
if (require.main === module) { try { main(process.argv.slice(2)); } catch (e) {
  console.error(e.message.startsWith("usage:") ? e.message : "Preparation rejected; no provider call. Required pins/prestate must be complete."); process.exitCode = 1;
} }
module.exports = { bootstrap, mergePolicy };
