"use strict";

const c = require("./contract.js");
const { BINDING_FIELDS } = require("../../shared/evidence/signed-evaluator-receipt.js");
const FLAGS = Object.freeze({ mutatesXp: false, awardAuthorized: false, countsTowardGenuineCorpus: false });
const HASH = /^[a-f0-9]{64}$/, GEN = /^[1-9][0-9]{0,19}$/;
const positive = n => Number.isSafeInteger(n) && n > 0;
function exact(value, names) {
  if (!value || Object.keys(value).length !== names.length || names.some(k => !Object.hasOwn(value, k))) throw Error("input_scope_rejected");
}
function validPin(pin, name) {
  exact(pin, ["name", "generation", "sha256", "createdAt"]);
  if (pin.name !== name || !GEN.test(pin.generation || "") || !HASH.test(pin.sha256 || "") || !positive(pin.createdAt))
    throw Error("input_pin_rejected");
}

// Custodian-only handoff into the EXISTING producer input contract. No public
// route, caller-supplied history, signing port, provider launch or XP capability.
function createProtectedObservationInputWriter({ actionEnabled = false, config, readObservation, readReceipt,
  readInput, createInput, githubJson, readCloudRunExecution, receiptTrust, now = Date.now } = {}) {
  if (actionEnabled !== true) return Object.freeze({ write: async () => ({ status: "disabled", ...FLAGS }) });
  const cfg = c.parse(c.canonical(config)), trust = c.parse(c.canonical(receiptTrust));
  exact(cfg, ["taskId", "enrollmentId", "profileBindingSha256", "declarationPin", "joinPin", "evaluator", "expiresAt"]);
  if (!/^codex_prospective_[a-f0-9]{24}$/.test(cfg.taskId || "") || !c.OPAQUE.test(cfg.enrollmentId || "") ||
      !HASH.test(cfg.profileBindingSha256 || "") || !positive(cfg.expiresAt) ||
      [readObservation, readReceipt, readInput, createInput, githubJson, readCloudRunExecution, now].some(fn => typeof fn !== "function"))
    throw Error("input_writer_configuration_required");
  const prefix = `observations/${cfg.taskId}/`, name = `inputs/${cfg.enrollmentId}.json`;
  validPin(cfg.declarationPin, prefix + "declaration.json"); validPin(cfg.joinPin, prefix + "profile-join.json");
  let lastTime = 0, attempted = false;
  const clock = () => { const t = now(); if (!positive(t) || t < lastTime || t >= cfg.expiresAt) throw Error("input_writer_expired"); lastTime = t; return t; };
  async function readPinned(read, pin) {
    const raw = await read(pin.name, { generation: pin.generation });
    if (raw?.status !== "found" || raw.generation !== pin.generation || raw.createdAt !== pin.createdAt ||
        !positive(raw.createdAt) || raw.createdAt > clock() || typeof raw.serialized !== "string" ||
        c.hash(raw.serialized) !== pin.sha256) throw Error("input_source_changed");
    return raw;
  }
  return Object.freeze({ async write(request) {
    try {
      exact(request, ["enrollmentId"]);
      if (request.enrollmentId !== cfg.enrollmentId || attempted) throw Error("input_request_rejected");
      attempted = true; clock();
      const declaration = c.parse((await readPinned(readObservation, cfg.declarationPin)).serialized);
      const join = c.parse((await readPinned(readObservation, cfg.joinPin)).serialized);
      exact(declaration, ["schemaVersion", "evidenceClass", "config", "registrationSha256", "registeredAt"]);
      exact(join, ["schemaVersion", "evidenceClass", "declaration", "start", "receipt", "profileJoin", "expected"]);
      validPin(join.start, prefix + "start.json"); validPin(join.receipt, `receipts/${cfg.taskId}.json`);
      const start = c.parse((await readPinned(readObservation, join.start)).serialized);
      exact(start, ["schemaVersion", "taskId", "declaration", "runnerSubject", "startedAt", "endsAt"]);
      const d = declaration.config;
      if (declaration.schemaVersion !== 1 || declaration.evidenceClass !== "prospective_no_award" || join.schemaVersion !== 1 ||
          join.evidenceClass !== "prospective_no_award" || d?.taskId !== cfg.taskId || d.profileBindingSha256 !== cfg.profileBindingSha256 ||
          declaration.registrationSha256 !== c.hash(c.canonical({ schemaVersion: 1, evidenceClass: "prospective_no_award", config: d })) ||
          !positive(declaration.registeredAt) || declaration.registeredAt < d.startsAt || declaration.registeredAt > cfg.declarationPin.createdAt ||
          c.canonical(join.declaration) !== c.canonical(cfg.declarationPin) || start.schemaVersion !== 1 || start.taskId !== cfg.taskId ||
          c.canonical(start.declaration) !== c.canonical(cfg.declarationPin) || start.runnerSubject !== d.runnerSubject ||
          !positive(start.startedAt) || start.startedAt <= cfg.declarationPin.createdAt || join.start.createdAt < start.startedAt ||
          start.endsAt !== Math.min(d.endsAt, start.startedAt + 1800000) || join.start.createdAt >= start.endsAt ||
          join.profileJoin?.joinedAt > cfg.joinPin.createdAt) throw Error("input_declaration_join_rejected");
      const receipt = await readPinned(readReceipt, join.receipt);
      const expected = { taskId: cfg.taskId, receiptId: `codex_evaluator_${cfg.taskId.slice(-24)}`,
        registrationSha256: declaration.registrationSha256, criteriaSha256: d.criteriaSha256, sourceRepository: d.sourceRepository,
        baselineCommit: d.baselineCommit, baselineSha256: d.baselineSha256, registeredAt: declaration.registeredAt,
        baselineAt: cfg.declarationPin.createdAt, workStartedAt: join.start.createdAt, evidenceClass: "prospective_no_award",
        candidateCommit: join.expected?.candidateCommit, candidateSha256: join.expected?.candidateSha256 };
      exact(join.expected, BINDING_FIELDS);
      if (c.canonical(expected) !== c.canonical(join.expected) || join.profileJoin?.receiptSha256 !== join.receipt.sha256 ||
          join.profileJoin?.joinedAt < join.receipt.createdAt) throw Error("input_receipt_join_rejected");
      const enrolledAt = clock();
      const source = { repository: d.sourceRepository, repositoryId: d.sourceRepositoryId,
        repositoryOwnerId: d.sourceOwnerId, subjectPath: d.subjectPath };
      const actorAssociation = { subject: start.runnerSubject, issuer: d.identityIssuer, audience: d.identityAudience,
        taskId: cfg.taskId, profileBindingSha256: cfg.profileBindingSha256, source,
        declarationPin: cfg.declarationPin, startPin: join.start, joinPin: cfg.joinPin,
        registeredAt: declaration.registeredAt, startedAt: start.startedAt, endsAt: start.endsAt,
        associationOnly: true, evidenceStatus: "insufficient_evidence" };
      const input = { schemaVersion: 3, enrollmentId: cfg.enrollmentId, profileBindingSha256: cfg.profileBindingSha256,
        enrolledAt, expiresAt: cfg.expiresAt, priorReceipts: [{ workReceiptId: `codex_stop_${cfg.taskId.slice(-24)}`,
          processedAt: cfg.joinPin.createdAt, serializedReceipt: receipt.serialized, receiptSha256: join.receipt.sha256,
          expected, source, evaluator: cfg.evaluator, profileJoin: join.profileJoin, actorAssociation }] };
      const serialized = c.canonical(input);
      c.validateEnrollment(serialized, cfg.enrollmentId, enrolledAt);
      const facts = await c.observePriorReceipts(input, { githubJson, readCloudRunExecution, readObservation, receiptTrust: trust, now: enrolledAt });
      if (facts.length !== 1 || facts[0].evaluatedAt >= start.endsAt) throw Error("input_observation_window_rejected");
      // Reread all immutable source generations before creating the input once.
      await readPinned(readObservation, cfg.declarationPin); await readPinned(readObservation, cfg.joinPin);
      await readPinned(readObservation, join.start); await readPinned(readReceipt, join.receipt);
      const before = clock(), result = await createInput(name, serialized, { ifGenerationMatch: 0 });
      clock();
      if (result?.status !== "created") throw Error("input_write_unconfirmed");
      const saved = await readInput(name);
      if (saved?.status !== "found" || !GEN.test(saved.generation || "") || saved.serialized !== serialized ||
          !positive(saved.createdAt) || saved.createdAt < before || saved.createdAt > clock()) throw Error("input_readback_unconfirmed");
      const inputPin = { name, generation: saved.generation, sha256: c.hash(saved.serialized), createdAt: saved.createdAt };
      await readPinned(readInput, inputPin);
      return { status: "protected_observation_history_input_stored", inputPin, ...FLAGS };
    } catch (_) { return { status: "protected_observation_history_input_unconfirmed", ...FLAGS }; }
  } });
}

module.exports = Object.freeze({ createProtectedObservationInputWriter });
