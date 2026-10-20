"use strict";

const { validatePolicyConfiguration } = require("../cloud/history-checkpoint/producer.js");
const { validateRegisteredPolicy } = require("../cloud/history-checkpoint/registered-observation.js");
const { canonical, hash } = require("../cloud/history-checkpoint/contract.js");
const PROJECT = "focustrack-eval-20260927";
const DISPATCHER = `serviceAccount:evaluator-dispatcher@${PROJECT}.iam.gserviceaccount.com`;
const PRODUCER = `serviceAccount:history-checkpoint-producer@${PROJECT}.iam.gserviceaccount.com`;

// Pure preparation. No provider, credential, filesystem, apply or activation path.
// This does not authenticate a native task or prove the installer's authority.
function planObservationRegistration(installed) {
  validatePolicyConfiguration(installed);
  const p = validateRegisteredPolicy(installed), bucket = p.observation.bucket;
  const slot = [`registration-slots/${p.slotId}.intent.json`, `registration-slots/${p.slotId}.json`];
  const observations = ["declaration", "start", "profile-join", "history-invocation", "history-submission"]
    .map(name => `observations/${p.taskId}/${name}.json`);
  const binding = (bucket, names, members, append, title) => ({ bucket,
    role: `projects/${PROJECT}/roles/protectedEvidence${append ? "Appender" : "Reader"}`, members,
    requiredRolePermissions: append ? ["storage.objects.create", "storage.objects.get"] : ["storage.objects.get"],
    condition: { title, expression: names.map(name => `resource.name == 'projects/_/buckets/${bucket}/objects/${name}'`).join(" || ") },
    exactObjectNames: names });
  return {
    schemaVersion: 1, status: "PREPARATION_ONLY_NOT_INSTALLABLE", project: PROJECT, region: "us-central1",
    installedPolicySha256: hash(canonical(installed)), registrationPolicySha256: hash(canonical(p)),
    taskId: p.taskId, slotId: p.slotId, enrollmentId: p.history.enrollmentId,
    proposedBucket: { name: bucket, location: "US-CENTRAL1", storageClass: "STANDARD",
      uniformBucketLevelAccess: true, publicAccessPrevention: "enforced" },
    proposedBindings: [
      binding(bucket, [...slot, ...observations], [DISPATCHER], true, "cp2-registration-dispatcher-" + p.slotId),
      binding(bucket, [...slot, ...observations.slice(0, 3)], [PRODUCER], false, "cp2-registration-producer-" + p.slotId),
      binding(p.observation.receiptBucket, [`receipts/${p.taskId}.json`], [DISPATCHER, PRODUCER], false, "cp2-registration-receipt-" + p.slotId)
    ],
    existingBindingToVerifyNotBroaden: binding("focustrack-award-controls-818502899155",
      ["inputs", "reservations", "checkpoints"].map(name => `${name}/${p.history.enrollmentId}.json`), [PRODUCER], true,
      "cp2-existing-producer-history"),
    requiredBeforeAnyApply: ["independent_installer_and_scoped_install_authority",
      "current_genuine_native_task_evidence_matches_installed_task",
      "reviewed_source_and_exact_new_image_digests",
      "fresh_provider_prestate_etags_roles_service_job_flags_traffic",
      "existing_signer_worker_and_owner_cutoff_preserved",
      "provider_readback_and_actual_worker_boundary_verification"],
    newHumanAccounts: 0, newServiceIdentities: 0, protectedObjectWritesDuringInstallation: 0,
    runtimeIamAdministration: false, runtimeJobUpdates: false, credentialExport: false,
    enrollmentEnabled: false, observationEnabled: false, awardEnabled: false,
    applicationRequests: 0, jobExecutions: 0, xpAwarded: 0
  };
}
module.exports = Object.freeze({ planObservationRegistration });
