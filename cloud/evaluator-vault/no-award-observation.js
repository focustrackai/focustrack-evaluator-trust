"use strict";

const { canonicalJson, sha256, exactKeys, validBinding } = require("./common.js");
const { parseEvaluatorReceipt, verifyEvaluatorReceipt, BINDING_FIELDS, NO_AWARD } = require("../../shared/evidence/signed-evaluator-receipt.js");
const SHA = /^[a-f0-9]{64}$/, GEN = /^[1-9][0-9]{0,19}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const FLAGS = Object.freeze({ ...NO_AWARD, awardAuthorized: false, liveAwardEnabled: false,
  workReleased: false, dispatchPerformed: false, countsTowardGenuineCorpus: false });

// Read-only declaration prerequisites shared by inspection and the real writer.
// Storage permission and create-only commitment are checked only by the writer.
function createDeclarationGuard({ config, verifyIdentity, readPrivateBaseline, receiptTrust, now }) {
  const c = JSON.parse(JSON.stringify(config));
  if (!exactKeys(c, ["taskId", "profileBindingSha256", "criteriaSha256", "baselineSha256", "ownerSubject", "runnerSubject",
      "sourceRepository", "sourceRepositoryId", "sourceOwnerId", "baselineCommit", "identityIssuer", "identityAudience",
      "startsAt", "endsAt", "baselineFiles", "subjectPath"]) ||
      [verifyIdentity, readPrivateBaseline, now].some(fn => typeof fn !== "function") ||
      !/^codex_prospective_[a-f0-9]{24}$/.test(c?.taskId || "") ||
      ![c.profileBindingSha256, c.criteriaSha256, c.baselineSha256].every(v => SHA.test(v || "")) ||
      ![c.ownerSubject, c.runnerSubject].every(v => UUID.test(v || "")) ||
      !/^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/.test(c.sourceRepository || "") ||
      !GEN.test(c.sourceRepositoryId || "") || !GEN.test(c.sourceOwnerId || "") ||
      !/^[a-f0-9]{40}$/.test(c.baselineCommit || "") || c.identityAudience !== "authenticated" ||
      !Number.isSafeInteger(c.startsAt) || c.startsAt <= 0 || !Number.isSafeInteger(c.endsAt) ||
      c.endsAt <= c.startsAt || c.endsAt - c.startsAt > 86400000 ||
      !Array.isArray(c.baselineFiles) || c.baselineFiles.length < 1 || c.baselineFiles.length > 128 ||
      !receiptTrust) throw Error("protected_observation_configuration_required");
  const issuer = new URL(c.identityIssuer);
  if (issuer.protocol !== "https:" || issuer.port || issuer.username || issuer.password || issuer.search || issuer.hash ||
      issuer.pathname !== "/auth/v1") throw Error("protected_observation_configuration_required");
  const files = new Map(); let total = 0;
  for (const f of c.baselineFiles) {
    if (!exactKeys(f, ["path", "bytes", "sha256"]) || typeof f.path !== "string" || !/^[A-Za-z0-9_./-]+$/.test(f.path) ||
        f.path.split("/").some(p => !p || p === "." || p === "..") || files.has(f.path) ||
        !Number.isSafeInteger(f.bytes) || f.bytes < 0 || f.bytes > 512 * 1024 || !SHA.test(f.sha256))
      throw Error("protected_observation_baseline_required");
    files.set(f.path, f); total += f.bytes;
  }
  if (total > 16 * 1024 * 1024 || files.get(c.subjectPath)?.sha256 !== c.baselineSha256)
    throw Error("protected_observation_baseline_required");
  const trust = JSON.parse(JSON.stringify(receiptTrust));
  const prefix = `observations/${c.taskId}/`, declarationName = `${prefix}declaration.json`, startName = `${prefix}start.json`;
  const registrationHash = sha256(canonicalJson({ schemaVersion: 1, evidenceClass: "prospective_no_award", config: c }));
  let previousTime = 0;
  function clock() {
    const t = now();
    if (!Number.isSafeInteger(t) || t < previousTime || t < c.startsAt || t >= c.endsAt) throw Error("observation_closed");
    previousTime = t; return t;
  }
  async function identity(request, body) {
    if (!exactKeys(body, ["taskId"]) || body.taskId !== c.taskId) throw Error("task_only_request_required");
    const v = await verifyIdentity(request);
    if (v?.status !== "verified_identity" || v.subject !== c.runnerSubject || v.issuer !== c.identityIssuer ||
        v.audience !== c.identityAudience || !Number.isSafeInteger(v.expiresAt) || v.expiresAt <= clock())
      throw Error("worker_identity_required");
    return v;
  }
  function stillAuthorized(v) { const time = clock(); if (v.expiresAt <= time) throw Error("worker_identity_expired"); return time; }
  async function baseline() {
    const source = await readPrivateBaseline(c.taskId);
    if (source?.status !== "authenticated_private_commit" || source.visibility !== "private" || source.repository !== c.sourceRepository ||
        source.repositoryId !== c.sourceRepositoryId || source.repositoryOwnerId !== c.sourceOwnerId ||
        source.commit !== c.baselineCommit || !Array.isArray(source.files) || source.files.length !== files.size)
      throw Error("private_baseline_required");
    const seen = new Set();
    for (const f of source.files) {
      const expected = files.get(f?.path);
      if (!expected || seen.has(f.path) || typeof f.serialized !== "string" ||
          Buffer.byteLength(f.serialized) !== expected.bytes || sha256(f.serialized) !== expected.sha256)
        throw Error("private_baseline_changed");
      seen.add(f.path);
    }
    clock();
  }
  async function prepare(request, body, setStage) {
    const v = await identity(request, body);
    setStage("private_baseline"); await baseline();
    setStage("pre_write_authorization"); const checkedAt = stillAuthorized(v);
    return { v, checkedAt };
  }
  return { c, trust, prefix, declarationName, startName, registrationHash, clock, identity, baseline, stillAuthorized, prepare };
}

function createNoAwardObservationInspector({ actionEnabled = false, config, verifyIdentity,
  readPrivateBaseline, receiptTrust, now = Date.now } = {}) {
  const unknown = stage => Object.freeze({ status: "protected_observation_inspected", outcome: "UNKNOWN",
    scope: "application_declaration_preconditions_only", stage, ...FLAGS });
  if (actionEnabled !== true) return Object.freeze({ inspect: async () => unknown("disabled"), ...FLAGS });
  const guard = createDeclarationGuard({ config, verifyIdentity, readPrivateBaseline, receiptTrust, now });
  return Object.freeze({
    async inspect(request, body) {
      let stage = "identity";
      try {
        const { v, checkedAt } = await guard.prepare(request, body, value => { stage = value; });
        return { status: "protected_observation_inspected", outcome: "PRECHECK_PASSED",
          scope: "application_declaration_preconditions_only", stage: "complete", taskId: guard.c.taskId,
          registrationSha256: guard.registrationHash, target: guard.declarationName, checkedAt,
          identity: { subject: v.subject, issuer: v.issuer, audience: v.audience, expiresAt: v.expiresAt }, ...FLAGS };
      } catch (_) { return unknown(stage); }
    }, ...FLAGS
  });
}

// A first real no-award observation needs a protected declaration, not invented
// prior history. This writer has no award-enrollment, evaluation or signing port.
function createNoAwardObservationCustody({ actionEnabled = false, config, verifyIdentity,
  readPrivateBaseline, readObject, createObject, readReceipt, receiptTrust, now = Date.now,
  onDeclarationFailure } = {}) {
  const denied = () => Object.freeze({ status: "protected_observation_denied", ...FLAGS });
  if (actionEnabled !== true) return Object.freeze({ declare: async () => denied(), sealStart: async () => denied(), joinReceipt: async () => denied(), ...FLAGS });
  if ([readObject, createObject, readReceipt].some(fn => typeof fn !== "function")) throw Error("protected_observation_configuration_required");
  const { c, trust, prefix, declarationName, startName, registrationHash, clock, identity, baseline, stillAuthorized, prepare } =
    createDeclarationGuard({ config, verifyIdentity, readPrivateBaseline, receiptTrust, now });
  function checkedObject(raw) {
    if (raw?.status !== "found" || !GEN.test(raw.generation || "") || typeof raw.serialized !== "string" ||
        Buffer.byteLength(raw.serialized) > 256 * 1024 || !Number.isSafeInteger(raw.createdAt) ||
        raw.createdAt < c.startsAt || raw.createdAt > clock()) throw Error("protected_object_required");
    return raw;
  }
  function pin(name, raw) { return { name, generation: raw.generation, sha256: sha256(raw.serialized), createdAt: raw.createdAt }; }
  async function createConfirmed(name, value, v) {
    stillAuthorized(v); const before = clock(), bytes = canonicalJson(value);
    const created = await createObject(name, bytes, { ifGenerationMatch: 0 });
    stillAuthorized(v);
    if (created?.status !== "created") throw Error("create_once_unconfirmed");
    const saved = checkedObject(await readObject(name));
    stillAuthorized(v);
    if (saved.serialized !== bytes || saved.createdAt < before)
      throw Error("create_readback_unconfirmed");
    const pinned = checkedObject(await readObject(name, { generation: saved.generation }));
    stillAuthorized(v);
    if (canonicalJson(pin(name, pinned)) !== canonicalJson(pin(name, saved))) throw Error("create_readback_unconfirmed");
    return saved;
  }
  async function declaration() {
    const raw = checkedObject(await readObject(declarationName)), value = JSON.parse(raw.serialized);
    if (raw.serialized !== canonicalJson(value) || !exactKeys(value, ["schemaVersion", "evidenceClass", "config", "registrationSha256", "registeredAt"]) ||
        value.schemaVersion !== 1 || value.evidenceClass !== "prospective_no_award" || value.registrationSha256 !== registrationHash ||
        canonicalJson(value.config) !== canonicalJson(c) || !Number.isSafeInteger(value.registeredAt) ||
        value.registeredAt < c.startsAt || value.registeredAt > raw.createdAt) throw Error("declaration_changed");
    const registration = { taskId: c.taskId, receiptId: `codex_evaluator_${c.taskId.slice(-24)}`, registrationSha256: registrationHash,
      criteriaSha256: c.criteriaSha256, sourceRepository: c.sourceRepository, baselineCommit: c.baselineCommit,
      baselineSha256: c.baselineSha256, registeredAt: value.registeredAt, baselineAt: raw.createdAt, evidenceClass: "prospective_no_award" };
    return { raw, registration, pin: pin(declarationName, raw) };
  }
  return Object.freeze({
    async declare(request, body) {
      let stage = "identity", writeMayHaveOccurred = false;
      try {
        const { v } = await prepare(request, body, value => { stage = value; });
        stage = "create_and_readback"; writeMayHaveOccurred = true;
        const created = await createConfirmed(declarationName, { schemaVersion: 1, evidenceClass: "prospective_no_award", config: c,
          registrationSha256: registrationHash, registeredAt: clock() }, v);
        stage = "final_readback";
        const d = await declaration(); stillAuthorized(v);
        if (canonicalJson(d.pin) !== canonicalJson(pin(declarationName, created))) throw Error("declaration_changed");
        return { status: "protected_no_award_declared", registration: d.registration, declaration: d.pin, ...FLAGS };
      } catch (_) {
        // Fixed labels only: no exception inspection or request/config contents.
        // Unconfirmed storage remains uncertain; diagnostics never authorize retry.
        try {
          if (typeof onDeclarationFailure === "function") Promise.resolve(onDeclarationFailure(Object.freeze({
            event: "no_award_observation_declaration_denied", schemaVersion: 1,
            stage, reason: "stage_not_completed", writeMayHaveOccurred
          }))).catch(() => {});
        } catch (_) { /* Logging cannot change the protected denial. */ }
        return denied();
      }
    },
    async sealStart(request, body) {
      try {
        const v = await identity(request, body), d = await declaration(); await baseline(); stillAuthorized(v);
        const started = clock();
        if (started <= d.raw.createdAt) throw Error("start_must_follow_declaration");
        const endsAt = Math.min(c.endsAt, started + 30 * 60 * 1000);
        const saved = await createConfirmed(startName, { schemaVersion: 1, taskId: c.taskId, declaration: d.pin,
          runnerSubject: v.subject, startedAt: started, endsAt }, v);
        if (saved.createdAt >= endsAt || canonicalJson((await declaration()).pin) !== canonicalJson(d.pin)) throw Error("start_unconfirmed");
        stillAuthorized(v);
        return { status: "protected_no_award_start_sealed", taskId: c.taskId, workStartedAt: saved.createdAt, endsAt,
          start: pin(startName, saved), ...FLAGS };
      } catch (_) { return denied(); }
    },
    async joinReceipt(request, body) {
      try {
        const v = await identity(request, body), d = await declaration(), start = checkedObject(await readObject(startName));
        const s = JSON.parse(start.serialized);
        if (start.serialized !== canonicalJson(s) || !exactKeys(s, ["schemaVersion", "taskId", "declaration", "runnerSubject", "startedAt", "endsAt"]) ||
            s.schemaVersion !== 1 || s.taskId !== c.taskId || s.runnerSubject !== c.runnerSubject ||
            canonicalJson(s.declaration) !== canonicalJson(d.pin) || !Number.isSafeInteger(s.startedAt) || s.startedAt <= d.raw.createdAt ||
            start.createdAt < s.startedAt || !Number.isSafeInteger(s.endsAt) || s.endsAt !== Math.min(c.endsAt, s.startedAt + 1800000) ||
            start.createdAt >= s.endsAt) throw Error("protected_start_required");
        // Receipt bytes come from the existing signer store, never from this caller.
        const raw = checkedObject(await readReceipt(`receipts/${c.taskId}.json`));
        const envelope = parseEvaluatorReceipt(raw.serialized);
        const expected = { ...d.registration, workStartedAt: start.createdAt,
          candidateCommit: envelope?.payload?.candidateCommit, candidateSha256: envelope?.payload?.candidateSha256 };
        const binding = Object.fromEntries(BINDING_FIELDS.map(k => [k, expected[k]]));
        if (!validBinding(binding)) throw Error("signed_binding_required");
        const receivedAt = clock(), verified = verifyEvaluatorReceipt(raw.serialized, { expected: binding, trust, now: receivedAt });
        if (!verified.ok || !verified.authenticated || verified.payload.result !== "passed" ||
            verified.payload.evaluatedAt >= s.endsAt || raw.createdAt < verified.payload.issuedAt || raw.createdAt < start.createdAt)
          throw Error("signed_receipt_required");
        const profileJoin = { profileBindingSha256: c.profileBindingSha256, workReceiptId: `codex_stop_${c.taskId.slice(-24)}`,
          receiptSha256: verified.receiptSha256, joinedAt: clock() };
        const saved = await createConfirmed(`${prefix}profile-join.json`, { schemaVersion: 1, evidenceClass: "prospective_no_award",
          declaration: d.pin, start: pin(startName, start), receipt: pin(`receipts/${c.taskId}.json`, raw), profileJoin, expected: binding }, v);
        if (canonicalJson((await declaration()).pin) !== canonicalJson(d.pin) ||
            canonicalJson(pin(startName, checkedObject(await readObject(startName)))) !== canonicalJson(pin(startName, start)) ||
            canonicalJson(pin(`receipts/${c.taskId}.json`, checkedObject(await readReceipt(`receipts/${c.taskId}.json`)))) !==
              canonicalJson(pin(`receipts/${c.taskId}.json`, raw))) throw Error("protected_source_changed");
        stillAuthorized(v);
        return { status: "protected_no_award_profile_join", join: pin(`${prefix}profile-join.json`, saved), ...FLAGS };
      } catch (_) { return denied(); }
    },
    async readJoin(request, body) {
      try {
        const v = await identity(request, body), d = await declaration();
        const name = `${prefix}profile-join.json`, raw = checkedObject(await readObject(name));
        const joined = JSON.parse(raw.serialized);
        if (raw.serialized !== canonicalJson(joined) || !exactKeys(joined,
          ["schemaVersion", "evidenceClass", "declaration", "start", "receipt", "profileJoin", "expected"]) ||
            joined.schemaVersion !== 1 || joined.evidenceClass !== "prospective_no_award" ||
            canonicalJson(joined.declaration) !== canonicalJson(d.pin) ||
            joined.profileJoin?.profileBindingSha256 !== c.profileBindingSha256) throw Error("protected_join_required");
        stillAuthorized(v);
        return { status: "protected_no_award_profile_join", join: pin(name, raw), identityExpiresAt: v.expiresAt, ...FLAGS };
      } catch (_) { return denied(); }
    }, ...FLAGS
  });
}

module.exports = Object.freeze({ createNoAwardObservationCustody, createNoAwardObservationInspector });
