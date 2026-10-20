"use strict";

const { canonicalJson, exactKeys, sha256 } = require("./common.js");
const { createNoAwardObservationInspector } = require("./no-award-observation.js");
const TASK = /^codex_prospective_[a-f0-9]{24}$/;
const GENERATION = /^[1-9][0-9]{0,19}$/;
const FLAGS = Object.freeze({ mutatesXp: false, awardAuthorized: false, liveAwardEnabled: false,
  workReleased: false, dispatchPerformed: false, countsTowardGenuineCorpus: false });
const reject = () => { throw Error("protected_registration_unconfirmed"); };

// The installed policy pins one independently admitted task. Authentication of
// a caller-supplied task-shaped string alone is not native task admission.
// A slot is single-use; these ports intentionally have no update/delete/reset.
function createObservationRegistration({ actionEnabled = false, policy, readObject, createObject,
  verifyIdentity, readPrivateBaseline, now = Date.now } = {}) {
  const denied = () => ({ status: "protected_registration_unconfirmed", ...FLAGS });
  if (actionEnabled !== true) return Object.freeze({ register: async () => denied(), resolve: async () => denied(), ...FLAGS });
  const p = JSON.parse(canonicalJson(policy));
  if (!exactKeys(p, ["schemaVersion", "slotId", "taskId", "notBefore", "notAfter", "observation", ...(Object.hasOwn(p, "history") ? ["history"] : [])]) || p.schemaVersion !== 1 || !TASK.test(p.taskId || "") ||
      !/^[a-f0-9]{32}$/.test(p.slotId || "") || !Number.isSafeInteger(p.notBefore) || p.notBefore <= 0 ||
      !Number.isSafeInteger(p.notAfter) || p.notAfter <= p.notBefore ||
      !exactKeys(p.observation, ["schemaVersion", "bucket", "receiptBucket", "config", "receiptTrust"]) ||
      p.observation.schemaVersion !== 1 ||
      [readObject, createObject, verifyIdentity, readPrivateBaseline, now].some(fn => typeof fn !== "function")) reject();
  const name = `registration-slots/${p.slotId}.json`, intentName = `registration-slots/${p.slotId}.intent.json`;
  const policySha256 = sha256(canonicalJson(p));
  let lastTime = 0, writing = false, uncertain = false, rememberedPin, rememberedIntent;
  function clock() {
    const t = now();
    if (!Number.isSafeInteger(t) || t < lastTime || t < p.notBefore || t >= p.notAfter) reject();
    lastTime = t; return t;
  }
  function deployment(taskId, createdAt) {
    return { ...p.observation, config: { ...p.observation.config, taskId,
      startsAt: createdAt, endsAt: Math.min(p.notAfter, createdAt + 1800000) } };
  }
  // Reuse the complete baseline/configuration validator, with no provider calls.
  function inspector(taskId, createdAt) {
    const d = deployment(taskId, createdAt);
    return createNoAwardObservationInspector({ actionEnabled: true, config: d.config,
      receiptTrust: d.receiptTrust, verifyIdentity,
      readPrivateBaseline: () => readPrivateBaseline(d.config), now: clock });
  }
  inspector(`codex_prospective_${"0".repeat(24)}`, p.notBefore);
  function bodyTask(body) {
    if (!exactKeys(body, ["taskId"]) || body.taskId !== p.taskId) reject();
    return body.taskId;
  }
  function valueFor(taskId) { return { schemaVersion: 1, policySha256, taskId }; }
  function pin(raw, taskId, objectName = name) {
    if (raw?.status !== "found" || !GENERATION.test(raw.generation || "") ||
        !Number.isSafeInteger(raw.createdAt) || raw.createdAt < p.notBefore || raw.createdAt > clock() ||
        raw.serialized !== canonicalJson(valueFor(taskId))) reject();
    return { name: objectName, generation: raw.generation, sha256: sha256(raw.serialized), createdAt: raw.createdAt };
  }
  async function readIntent(taskId) {
    const raw = await readObject(intentName);
    clock();
    if (raw?.status === "absent") return undefined;
    const current = pin(raw, taskId, intentName);
    if (rememberedIntent && canonicalJson(current) !== canonicalJson(rememberedIntent)) reject();
    for (const options of [{ generation: current.generation }, undefined]) {
      if (canonicalJson(pin(await readObject(intentName, options), taskId, intentName)) !== canonicalJson(current)) reject();
    }
    rememberedIntent = current;
    return current;
  }
  async function read(taskId, expectedPin) {
    const raw = await readObject(name);
    clock();
    if (raw?.status === "absent") return undefined;
    const current = pin(raw, taskId);
    const intent = await readIntent(taskId);
    if (!intent || intent.createdAt > current.createdAt) reject();
    for (const expected of [expectedPin, rememberedPin]) {
      if (expected && canonicalJson(current) !== canonicalJson(expected)) reject();
    }
    const pinned = await readObject(name, { generation: current.generation });
    if (canonicalJson(pin(pinned, taskId)) !== canonicalJson(current)) reject();
    const head = await readObject(name);
    if (canonicalJson(pin(head, taskId)) !== canonicalJson(current)) reject();
    const d = deployment(taskId, current.createdAt);
    if (clock() >= d.config.endsAt) reject();
    rememberedPin = current;
    return { status: "protected_registration_resolved", taskId, policySha256,
      pin: current, intentPin: intent, deployment: d, nativeAdmissionProven: false, ...FLAGS };
  }
  async function authenticate(request, taskId, createdAt) {
    const result = await inspector(taskId, createdAt).inspect(request, { taskId });
    if (result?.outcome !== "PRECHECK_PASSED" || result.taskId !== taskId ||
        result.identity?.expiresAt <= clock()) reject();
    return result.identity;
  }
  return Object.freeze({
    async register(request, body) {
      if (writing || uncertain) return denied();
      writing = true;
      try {
        const taskId = bodyTask(body), before = clock();
        const identity = await authenticate(request, taskId, before);
        const existing = await read(taskId);
        if (existing) {
          if (clock() >= identity.expiresAt) reject();
          return { ...existing, duplicate: true };
        }
        // An existing intent means another instance owns (or may have applied)
        // the attempt. Absence of the slot is never permission to apply again.
        if (await readIntent(taskId)) reject();
        if (clock() >= identity.expiresAt) reject();
        // Set before transport: a thrown/ambiguous create must not be retried.
        uncertain = true;
        const intent = await createObject(intentName, canonicalJson(valueFor(taskId)), { ifGenerationMatch: 0 });
        if (intent?.status !== "created") reject();
        const intentPin = await readIntent(taskId);
        if (!intentPin || intentPin.createdAt < before || clock() >= identity.expiresAt) reject();
        const created = await createObject(name, canonicalJson(valueFor(taskId)), { ifGenerationMatch: 0 });
        if (created?.status !== "created") reject();
        const saved = await read(taskId);
        if (!saved || canonicalJson(saved.intentPin) !== canonicalJson(intentPin) || saved.pin.createdAt < before ||
            clock() >= identity.expiresAt) reject();
        uncertain = false;
        return { ...saved, duplicate: false };
      } catch (_) { return denied(); }
      finally { writing = false; }
    },
    // Read-only reconciliation is separate from register and never clears an
    // ambiguous write for another attempt. Consumers retain the returned pin.
    async resolve(request, body, expectedPin) {
      try {
        const taskId = bodyTask(body);
        await authenticate(request, taskId, clock());
        const saved = await read(taskId, expectedPin);
        if (!saved) reject();
        const identity = await authenticate(request, taskId, saved.pin.createdAt);
        const checked = await read(taskId, saved.pin);
        if (!checked || clock() >= identity.expiresAt) reject();
        return checked;
      } catch (_) { return denied(); }
    },
    // Trusted backend read, not an HTTP identity/admission endpoint. The
    // producer authenticates its workload and exact installed template first.
    async resolveForBackend(expectedPin) {
      try {
        const raw = await readObject(name);
        if (raw?.status !== "found") reject();
        const value = JSON.parse(raw.serialized);
        if (value?.taskId !== p.taskId) reject();
        const saved = await read(value.taskId, expectedPin);
        return saved || denied();
      } catch (_) { return denied(); }
    }, ...FLAGS
  });
}

module.exports = Object.freeze({ createObservationRegistration });
