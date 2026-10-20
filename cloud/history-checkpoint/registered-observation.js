"use strict";

const c = require("./contract.js");
const { exactKeys } = require("../evaluator-vault/common.js");
const { createObservationRegistration } = require("../evaluator-vault/observation-registration.js");
const { createEnrollmentGcsActionPort } = require("../evaluator-vault/enrollment-action-adapters.js");
const n = require("./cloud-run-runtime.js");
const fail = () => { throw Error("registered_observation_binding_required"); };

// Only the existing self-template slot is excluded. Native verification still
// hashes the actual complete installed job template, not this effective policy.
function authoritySha256(policy) {
  const { templateSha256, ...runtime } = policy.runtime;
  return c.hash(c.canonical({ runtime, sourceReader: policy.sourceReader,
    keyVersion: policy.keyVersion, publicKeySha256: policy.publicKeySha256,
    checkpointTrust: policy.checkpointTrust, receiptTrust: policy.receiptTrust }));
}

function validateRegisteredPolicy(installed) {
  const p = installed.observationRegistration, h = p?.history;
  if (!p || !exactKeys(h, ["enrollmentId", "jobUid", "image", "evaluator", "producerAuthoritySha256"]) ||
      h.producerAuthoritySha256 !== authoritySha256(installed) ||
      h.enrollmentId !== installed.runtime.enrollmentId || h.jobUid !== installed.runtime.jobUid ||
      h.image !== installed.runtime.image || installed.runtime.job !== n.JOB ||
      !/^focustrack-observation-slot-[a-f0-9]{32}$/.test(p.observation?.bucket || "") ||
      p.observation.bucket !== `focustrack-observation-slot-${p.slotId}` ||
      p.observation.receiptBucket !== "focustrack-evaluator-receipts-818502899155" ||
      c.canonical(p.observation.receiptTrust) !== c.canonical(installed.receiptTrust) ||
      p.notBefore < installed.checkpointTrust.notBefore || p.notAfter > installed.checkpointTrust.notAfter ||
      installed.checkpointTrust.revoked !== false || installed.receiptTrust.revoked !== false ||
      installed.receiptTrust.independenceApproved !== true ||
      p.notBefore < installed.receiptTrust.notBefore || p.notAfter > installed.receiptTrust.notAfter ||
      p.observation.config.sourceRepository !== installed.sourceReader.repository ||
      p.observation.config.sourceRepositoryId !== installed.sourceReader.repositoryId ||
      p.observation.config.sourceOwnerId !== installed.sourceReader.repositoryOwnerId) fail();
  const noPort = () => { throw Error("configuration_validation_only"); };
  createObservationRegistration({ actionEnabled: true, policy: p, readObject: noPort, createObject: noPort,
    verifyIdentity: noPort, readPrivateBaseline: noPort });
  require("./cloud-run-observation.js").validateSelection({
    taskId: `codex_prospective_${"0".repeat(24)}`, enrollmentId: h.enrollmentId,
    profileBindingSha256: p.observation.config.profileBindingSha256, registrationSha256: "0".repeat(64),
    expiresAt: p.notAfter, evaluator: h.evaluator
  }, h.enrollmentId);
  return p;
}

function materializeRegisteredPolicy(installed, resolved) {
  const p = validateRegisteredPolicy(installed);
  if (resolved?.status !== "protected_registration_resolved" || resolved.policySha256 !== c.hash(c.canonical(p)) ||
      resolved.taskId !== p.taskId ||
      resolved.pin?.name !== `registration-slots/${p.slotId}.json` ||
      !/^[1-9][0-9]{0,19}$/.test(resolved.pin.generation || "") ||
      !Number.isSafeInteger(resolved.pin.createdAt) || resolved.pin.createdAt < p.notBefore ||
      resolved.pin.createdAt >= p.notAfter) fail();
  const expectedSlot = { schemaVersion: 1, policySha256: resolved.policySha256, taskId: resolved.taskId };
  if (resolved.pin.sha256 !== c.hash(c.canonical(expectedSlot))) fail();
  const observation = { ...p.observation, config: { ...p.observation.config, taskId: resolved.taskId,
    startsAt: resolved.pin.createdAt, endsAt: Math.min(p.notAfter, resolved.pin.createdAt + 1800000) } };
  if (c.canonical(resolved.deployment) !== c.canonical(observation)) fail();
  const registrationSha256 = c.hash(c.canonical({ schemaVersion: 1, evidenceClass: "prospective_no_award", config: observation.config }));
  const policy = c.parse(c.canonical(installed));
  delete policy.observationRegistration;
  policy.observationSelection = { taskId: resolved.taskId, enrollmentId: p.history.enrollmentId,
    profileBindingSha256: observation.config.profileBindingSha256, registrationSha256,
    expiresAt: observation.config.endsAt, evaluator: p.history.evaluator };
  return { policy, observation, finalization: { schemaVersion: 1, taskId: resolved.taskId,
    enrollmentId: p.history.enrollmentId, registrationSha256, profileBindingSha256: observation.config.profileBindingSha256,
    expiresAt: observation.config.endsAt, jobUid: p.history.jobUid, image: p.history.image,
    templateSha256: installed.runtime.templateSha256 }, pin: resolved.pin };
}

function createRegistrationReader({ installed, fetch, getAccessToken, now = Date.now }) {
  const p = validateRegisteredPolicy(installed), name = `registration-slots/${p.slotId}.json`;
  const objects = createEnrollmentGcsActionPort({ actionEnabled: true, bucket: p.observation.bucket,
    allowedReadNames: [name, `registration-slots/${p.slotId}.intent.json`], allowedCreateNames: [], getAccessToken, fetch });
  const noWrite = () => { throw Error("registration_reader_only"); };
  const resolver = createObservationRegistration({ actionEnabled: true, policy: p, readObject: objects.readObject,
    createObject: noWrite, verifyIdentity: noWrite, readPrivateBaseline: noWrite, now });
  return Object.freeze({ async read(expectedPin) {
    const slot = await resolver.resolveForBackend(expectedPin);
    return { slot, ...materializeRegisteredPolicy(installed, slot) };
  } });
}

module.exports = Object.freeze({ authoritySha256, validateRegisteredPolicy, materializeRegisteredPolicy, createRegistrationReader });
