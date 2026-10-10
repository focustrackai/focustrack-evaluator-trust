const TRUST_MEMORY_SCHEMA_VERSION = 1;

const TRUST_ENTITY_TYPES = Object.freeze(["agent", "human", "verifier", "workflow", "evidence_source"]);
const TRUST_BUCKETS = Object.freeze(["agents", "humans", "verifiers", "workflows", "evidenceSources"]);
const TRUST_LEVELS = Object.freeze(["unknown", "low", "medium", "high", "very_high"]);
const TRUST_TRENDS = Object.freeze(["unknown", "improving", "stable", "declining"]);

function isPlainTrustObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function clampTrustNumber(value, min = 0, max = Number.MAX_SAFE_INTEGER) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.max(min, Math.min(max, number));
}

function clampTrustScore(value) {
  return Math.round(clampTrustNumber(value, 0, 100));
}

function sanitizeTrustMemoryText(value, options = {}) {
  const maxLength = typeof options === "number"
    ? options
    : Number(options?.maxLength || 160);
  return String(value ?? "")
    .replace(/https?:\/\/[^\s]+/gi, "")
    .replace(/www\.[^\s]+/gi, "")
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, Math.max(1, Math.min(500, Number(maxLength) || 160)))
    .trim();
}

function sanitizeTrustMemoryKey(value) {
  return sanitizeTrustMemoryText(value, 80)
    .toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function sanitizeTrustEntityId(value, fallback = "unknown") {
  return sanitizeTrustMemoryText(value || fallback, 120)
    .toLowerCase()
    .replace(/[^a-z0-9_.:-]+/g, "_")
    .replace(/^_+|_+$/g, "") || fallback;
}

function normalizeNullableTrustText(value, maxLength = 80) {
  const safe = sanitizeTrustMemoryText(value, maxLength);
  return safe || null;
}

function isUnsafeTrustMemoryMetadataKey(key) {
  return /token|api[_-]?key|password|secret|oauth|credential|prompt|diff|patch|content|body|stdout|stderr|terminal|url|path|query|hash|html|page|file/i.test(String(key || ""));
}

function sanitizeTrustMemoryMetadataValue(key, value, depth = 0) {
  if (depth > 2 || isUnsafeTrustMemoryMetadataKey(key)) return undefined;
  if (value == null) return null;
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string") return sanitizeTrustMemoryText(value, 120) || null;
  if (Array.isArray(value)) {
    return value
      .slice(0, 20)
      .map((item) => sanitizeTrustMemoryMetadataValue(key, item, depth + 1))
      .filter((item) => item !== undefined);
  }
  if (isPlainTrustObject(value)) return sanitizeTrustMemoryMetadata(value, depth + 1);
  return undefined;
}

function sanitizeTrustMemoryMetadata(metadata, depth = 0) {
  if (!isPlainTrustObject(metadata)) return {};
  const out = {};
  Object.entries(metadata).forEach(([key, value]) => {
    if (isUnsafeTrustMemoryMetadataKey(key)) return;
    const safeKey = sanitizeTrustMemoryKey(key);
    if (!safeKey) return;
    const safeValue = sanitizeTrustMemoryMetadataValue(safeKey, value, depth);
    if (safeValue !== undefined) out[safeKey] = safeValue;
  });
  return out;
}

function createTrustProfileId(entityType = "agent", entityId = "unknown") {
  return `${sanitizeTrustEntityId(entityType, "agent")}_${sanitizeTrustEntityId(entityId, "unknown")}`;
}

function createTrustMemoryEventId(prefix = "trust_event") {
  try {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return `${prefix}_${crypto.randomUUID()}`;
    }
  } catch (_) {}
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

function createEmptyTrustTotals() {
  return {
    observations: 0,
    aligned: 0,
    contradicted: 0,
    blocked: 0,
    insufficientEvidence: 0,
    needsReview: 0,
    clean: 0
  };
}

function normalizeTrustTotals(raw = {}) {
  const source = isPlainTrustObject(raw) ? raw : {};
  return {
    observations: Math.round(clampTrustNumber(source.observations, 0)),
    aligned: Math.round(clampTrustNumber(source.aligned, 0)),
    contradicted: Math.round(clampTrustNumber(source.contradicted, 0)),
    blocked: Math.round(clampTrustNumber(source.blocked, 0)),
    insufficientEvidence: Math.round(clampTrustNumber(source.insufficientEvidence, 0)),
    needsReview: Math.round(clampTrustNumber(source.needsReview, 0)),
    clean: Math.round(clampTrustNumber(source.clean, 0))
  };
}

function calculateReliabilityScore(profile = {}) {
  const totals = normalizeTrustTotals(profile.totals);
  if (totals.observations <= 0) return 0;
  const observations = Math.max(1, totals.observations);
  const alignedRate = totals.aligned / observations;
  const cleanRate = totals.clean / observations;
  const contradictionRate = totals.contradicted / observations;
  const blockedRate = totals.blocked / observations;
  const insufficientRate = totals.insufficientEvidence / observations;
  const needsReviewRate = totals.needsReview / observations;
  return clampTrustScore(
    (alignedRate * 42) +
    (cleanRate * 30) +
    ((1 - contradictionRate) * 18) +
    ((1 - blockedRate) * 10) -
    (insufficientRate * 18) -
    (needsReviewRate * 8)
  );
}

function calculateTrustScore(profile = {}) {
  const totals = normalizeTrustTotals(profile.totals);
  if (totals.observations <= 0) return 0;
  const observations = Math.max(1, totals.observations);
  const alignedRate = totals.aligned / observations;
  const cleanRate = totals.clean / observations;
  const contradictionRate = totals.contradicted / observations;
  const blockedRate = totals.blocked / observations;
  const insufficientRate = totals.insufficientEvidence / observations;
  const needsReviewRate = totals.needsReview / observations;
  return clampTrustScore(
    42 +
    (alignedRate * 28) +
    (cleanRate * 22) -
    (contradictionRate * 34) -
    (blockedRate * 30) -
    (insufficientRate * 20) -
    (needsReviewRate * 10)
  );
}

function classifyTrustLevel(score, observations = 0) {
  const safeScore = clampTrustScore(score);
  const count = Math.round(clampTrustNumber(observations, 0));
  if (count <= 0) return "unknown";
  if (safeScore >= 85 && count >= 10) return "very_high";
  if (safeScore >= 70 && count >= 5) return "high";
  if (safeScore >= 45) return "medium";
  return "low";
}

function scoreTrustOutcomeLabel(label) {
  if (label === "aligned" || label === "clean") return 1;
  if (label === "needs_review") return 0.45;
  if (label === "insufficient_evidence") return 0.2;
  if (label === "contradicted" || label === "blocked") return 0;
  return 0.4;
}

function classifyReliabilityTrend(profile = {}) {
  const totals = normalizeTrustTotals(profile.totals);
  const recentSource = Array.isArray(profile.metadata?.recentOutcomes)
    ? profile.metadata.recentOutcomes
    : (Array.isArray(profile.metadata?.recentoutcomes) ? profile.metadata.recentoutcomes : []);
  const recent = Array.isArray(recentSource)
    ? recentSource.map((item) => sanitizeTrustMemoryKey(item)).filter(Boolean).slice(-6)
    : [];
  if (totals.observations < 4 || recent.length < 3) return "unknown";
  const historicalAverage = totals.observations > 0
    ? ((totals.aligned + totals.clean) / Math.max(1, totals.observations * 2))
    : 0;
  const recentAverage = recent.reduce((sum, label) => sum + scoreTrustOutcomeLabel(label), 0) / recent.length;
  const recentBad = recent.filter((label) => ["contradicted", "blocked", "insufficient_evidence"].includes(label)).length / recent.length;
  if (recentAverage >= historicalAverage + 0.18 && recentBad <= 0.34) return "improving";
  if (recentAverage <= historicalAverage - 0.18 || recentBad >= 0.5) return "declining";
  return "stable";
}

function normalizeTrustSafeNotes(values) {
  const list = Array.isArray(values) ? values : [];
  const seen = new Set();
  return list
    .map((item) => sanitizeTrustMemoryText(item, 160))
    .filter(Boolean)
    .filter((item) => {
      const key = item.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 10);
}

function classifyProfileFlags(profile = {}) {
  const totals = normalizeTrustTotals(profile.totals);
  const observations = Math.max(1, totals.observations);
  const contradictionRate = totals.contradicted / observations;
  const blockedRate = totals.blocked / observations;
  const insufficientRate = totals.insufficientEvidence / observations;
  const trustScore = calculateTrustScore(profile);
  return {
    possibleRubberStamping: profile.entityType === "human" && totals.observations >= 3 && (contradictionRate + insufficientRate) >= 0.45,
    frequentContradictions: totals.observations >= 3 && contradictionRate >= 0.34,
    insufficientEvidencePattern: totals.observations >= 3 && insufficientRate >= 0.34,
    highReliabilityPattern: totals.observations >= 5 && trustScore >= 70 && (contradictionRate + blockedRate) <= 0.15
  };
}

function normalizeTrustProfile(raw = {}) {
  const source = isPlainTrustObject(raw) ? raw : {};
  const entityType = TRUST_ENTITY_TYPES.includes(source.entityType) ? source.entityType : "agent";
  const entityId = sanitizeTrustEntityId(source.entityId || source.profileId, "unknown");
  const totals = normalizeTrustTotals(source.totals);
  const metadata = sanitizeTrustMemoryMetadata(source.metadata);
  const baseProfile = {
    schemaVersion: TRUST_MEMORY_SCHEMA_VERSION,
    profileId: sanitizeTrustMemoryText(source.profileId, 140) || createTrustProfileId(entityType, entityId),
    entityType,
    entityId,
    displayName: normalizeNullableTrustText(source.displayName, 80),
    createdAt: Math.round(clampTrustNumber(source.createdAt || Date.now(), 0)),
    updatedAt: Math.round(clampTrustNumber(source.updatedAt || Date.now(), 0)),
    totals,
    scores: {
      trustScore: 0,
      reliabilityScore: 0,
      evidenceAlignmentScore: 0,
      attestationAccuracyScore: 0,
      completionAccuracyScore: 0
    },
    trend: "unknown",
    trustLevel: "unknown",
    lastOutcomeAt: source.lastOutcomeAt == null ? null : Math.round(clampTrustNumber(source.lastOutcomeAt, 0)),
    flags: {
      possibleRubberStamping: false,
      frequentContradictions: false,
      insufficientEvidencePattern: false,
      highReliabilityPattern: false
    },
    safeNotes: normalizeTrustSafeNotes(source.safeNotes),
    metadata
  };
  const observations = Math.max(1, totals.observations);
  const trustScore = calculateTrustScore(baseProfile);
  const reliabilityScore = calculateReliabilityScore(baseProfile);
  baseProfile.scores = {
    trustScore,
    reliabilityScore,
    evidenceAlignmentScore: totals.observations <= 0 ? 0 : clampTrustScore(((totals.aligned + totals.clean) / (observations * 2)) * 100),
    attestationAccuracyScore: totals.observations <= 0 ? 0 : clampTrustScore((1 - ((totals.contradicted + totals.insufficientEvidence) / observations)) * 100),
    completionAccuracyScore: totals.observations <= 0 ? 0 : clampTrustScore((1 - ((totals.blocked + totals.insufficientEvidence) / observations)) * 100)
  };
  baseProfile.trend = TRUST_TRENDS.includes(source.trend) && source.trend !== "unknown"
    ? source.trend
    : classifyReliabilityTrend(baseProfile);
  baseProfile.trustLevel = classifyTrustLevel(trustScore, totals.observations);
  baseProfile.flags = {
    ...baseProfile.flags,
    ...classifyProfileFlags(baseProfile),
    ...(isPlainTrustObject(source.flags) ? {
      possibleRubberStamping: source.flags.possibleRubberStamping === true || classifyProfileFlags(baseProfile).possibleRubberStamping,
      frequentContradictions: source.flags.frequentContradictions === true || classifyProfileFlags(baseProfile).frequentContradictions,
      insufficientEvidencePattern: source.flags.insufficientEvidencePattern === true || classifyProfileFlags(baseProfile).insufficientEvidencePattern,
      highReliabilityPattern: source.flags.highReliabilityPattern === true || classifyProfileFlags(baseProfile).highReliabilityPattern
    } : {})
  };
  return baseProfile;
}

function createTrustProfile(input = {}) {
  return normalizeTrustProfile(input);
}

function createTrustMemoryState(input = {}) {
  return normalizeTrustMemoryState(input);
}

function normalizeTrustMemoryState(raw = {}) {
  const source = isPlainTrustObject(raw) ? raw : {};
  const profiles = isPlainTrustObject(source.profiles) ? source.profiles : {};
  const outProfiles = {
    agents: {},
    humans: {},
    verifiers: {},
    workflows: {},
    evidenceSources: {}
  };
  TRUST_BUCKETS.forEach((bucket) => {
    const collection = isPlainTrustObject(profiles[bucket]) ? profiles[bucket] : {};
    Object.entries(collection).forEach(([key, value]) => {
      const profile = normalizeTrustProfile(value);
      outProfiles[bucket][sanitizeTrustEntityId(key || profile.entityId, profile.entityId)] = profile;
    });
  });
  const recentEvents = (Array.isArray(source.recentEvents) ? source.recentEvents : [])
    .map((event) => sanitizeTrustMemoryMetadata(event))
    .filter((event) => Object.keys(event).length)
    .slice(-50);
  return {
    schemaVersion: TRUST_MEMORY_SCHEMA_VERSION,
    createdAt: Math.round(clampTrustNumber(source.createdAt || Date.now(), 0)),
    updatedAt: Math.round(clampTrustNumber(source.updatedAt || Date.now(), 0)),
    profiles: outProfiles,
    recentEvents
  };
}

function deriveTrustOutcome(input = {}) {
  const source = isPlainTrustObject(input) ? input : {};
  const integrity = isPlainTrustObject(source.integrityResult) ? source.integrityResult : {};
  const provided = isPlainTrustObject(source.outcome) ? source.outcome : {};
  const status = sanitizeTrustMemoryKey(integrity.integrityStatus || "");
  const verifiedProgressEligible = integrity.verifiedProgressEligible === true;
  return {
    aligned: provided.aligned === true || (status === "clean" && verifiedProgressEligible),
    contradicted: provided.contradicted === true || status === "conflict",
    blocked: provided.blocked === true || status === "blocked" || integrity.blocked === true,
    insufficientEvidence: provided.insufficientEvidence === true || status === "insufficient_evidence" || integrity.requiresMoreEvidence === true,
    needsReview: provided.needsReview === true || status === "needs_review" || status === "pending" || integrity.requiresHumanReview === true,
    clean: provided.clean === true || status === "clean"
  };
}

function getTrustOutcomeLabel(outcome = {}) {
  if (outcome.blocked) return "blocked";
  if (outcome.contradicted) return "contradicted";
  if (outcome.insufficientEvidence) return "insufficient_evidence";
  if (outcome.needsReview) return "needs_review";
  if (outcome.clean || outcome.aligned) return "clean";
  return "needs_review";
}

function buildTrustOutcomeNote(entityType, outcome, input = {}) {
  const human = isPlainTrustObject(input.human) ? input.human : {};
  if (entityType === "human" && human.attestationStatus === "human_attested_complete" && (outcome.contradicted || outcome.insufficientEvidence)) {
    return "Human attestation needs stronger evidence";
  }
  if (outcome.blocked) return "Blocked integrity outcome observed";
  if (outcome.contradicted) return "Contradiction observed";
  if (outcome.insufficientEvidence) return "Repeated insufficient evidence detected";
  if (outcome.clean || outcome.aligned) return "Outcome aligned with available proof";
  return "Outcome needs review";
}

function updateTrustProfileFromOutcome(profile = {}, input = {}) {
  const current = normalizeTrustProfile(profile);
  const outcome = deriveTrustOutcome(input);
  const label = getTrustOutcomeLabel(outcome);
  const totals = { ...current.totals };
  totals.observations += 1;
  if (outcome.aligned) totals.aligned += 1;
  if (outcome.contradicted) totals.contradicted += 1;
  if (outcome.blocked) totals.blocked += 1;
  if (outcome.insufficientEvidence) totals.insufficientEvidence += 1;
  if (outcome.needsReview) totals.needsReview += 1;
  if (outcome.clean) totals.clean += 1;
  const currentRecentOutcomes = Array.isArray(current.metadata.recentOutcomes)
    ? current.metadata.recentOutcomes
    : (Array.isArray(current.metadata.recentoutcomes) ? current.metadata.recentoutcomes : []);
  const recentOutcomes = Array.isArray(currentRecentOutcomes)
    ? currentRecentOutcomes.map((item) => sanitizeTrustMemoryKey(item)).filter(Boolean)
    : [];
  recentOutcomes.push(label);
  const next = normalizeTrustProfile({
    ...current,
    updatedAt: Date.now(),
    lastOutcomeAt: Date.now(),
    totals,
    safeNotes: [
      buildTrustOutcomeNote(current.entityType, outcome, input),
      ...current.safeNotes
    ],
    metadata: {
      ...current.metadata,
      recentOutcomes: recentOutcomes.slice(-10)
    }
  });
  return next;
}

function getTrustBucketForEntityType(entityType) {
  return ({
    agent: "agents",
    human: "humans",
    verifier: "verifiers",
    workflow: "workflows",
    evidence_source: "evidenceSources"
  })[entityType] || "agents";
}

function getOrCreateTrustProfile(state, entityType, entityId, displayName) {
  const safeEntityType = TRUST_ENTITY_TYPES.includes(entityType) ? entityType : "agent";
  const safeEntityId = sanitizeTrustEntityId(entityId, "unknown");
  const bucket = getTrustBucketForEntityType(safeEntityType);
  const existing = state.profiles[bucket][safeEntityId];
  return normalizeTrustProfile(existing || {
    entityType: safeEntityType,
    entityId: safeEntityId,
    displayName
  });
}

function updateTrustMemoryFromIntegrityResult(state = {}, input = {}) {
  const next = normalizeTrustMemoryState(state);
  const source = isPlainTrustObject(input) ? input : {};
  const outcome = deriveTrustOutcome(source);
  const entities = [];
  const agent = isPlainTrustObject(source.agent) ? source.agent : {};
  if (agent.agentId || agent.agentSource) {
    entities.push({
      entityType: "agent",
      entityId: agent.agentId || agent.agentSource,
      displayName: agent.displayName || agent.agentSource
    });
  }
  const human = isPlainTrustObject(source.human) ? source.human : {};
  if (human.reviewerId || human.displayName) {
    entities.push({
      entityType: "human",
      entityId: human.reviewerId || human.displayName,
      displayName: human.displayName
    });
  }
  const verifier = isPlainTrustObject(source.verifier) ? source.verifier : {};
  if (verifier.verifierId || verifier.provider) {
    entities.push({
      entityType: "verifier",
      entityId: verifier.verifierId || verifier.provider,
      displayName: verifier.displayName || verifier.provider
    });
  }
  const workflow = isPlainTrustObject(source.workflow) ? source.workflow : {};
  if (workflow.workflowId || workflow.displayName) {
    entities.push({
      entityType: "workflow",
      entityId: workflow.workflowId || workflow.displayName,
      displayName: workflow.displayName
    });
  }
  const evidenceSource = isPlainTrustObject(source.evidenceSource) ? source.evidenceSource : {};
  if (evidenceSource.sourceId || evidenceSource.sourceType) {
    entities.push({
      entityType: "evidence_source",
      entityId: evidenceSource.sourceId || evidenceSource.sourceType,
      displayName: evidenceSource.displayName || evidenceSource.sourceType
    });
  }
  entities.forEach((entity) => {
    const bucket = getTrustBucketForEntityType(entity.entityType);
    const profile = getOrCreateTrustProfile(next, entity.entityType, entity.entityId, entity.displayName);
    next.profiles[bucket][profile.entityId] = updateTrustProfileFromOutcome(profile, {
      ...source,
      outcome
    });
  });
  next.updatedAt = Date.now();
  next.recentEvents = [
    ...next.recentEvents,
    {
      eventid: createTrustMemoryEventId(),
      timestamp: Date.now(),
      integritystatus: sanitizeTrustMemoryKey(source.integrityResult?.integrityStatus || ""),
      outcome: getTrustOutcomeLabel(outcome),
      entitycount: entities.length
    }
  ].slice(-50);
  return next;
}

function buildTrustReceiptLines(profile = {}) {
  const safe = normalizeTrustProfile(profile);
  const lines = [];
  if (safe.trustLevel !== "unknown") lines.push(`Trust level: ${safe.trustLevel}`);
  if (safe.trend === "improving") lines.push(`${safe.entityType === "agent" ? "Agent" : "Reliability"} reliability is improving`);
  if (safe.trend === "declining") lines.push("Reliability is declining");
  if (safe.flags.possibleRubberStamping) lines.push("Human attestations need stronger evidence");
  if (safe.flags.insufficientEvidencePattern) lines.push("Repeated insufficient evidence detected");
  if (safe.flags.highReliabilityPattern) lines.push("Verifier evidence has aligned with past outcomes");
  if (!lines.length) lines.push("Trust profile initialized");
  return lines
    .map((line) => sanitizeTrustMemoryText(line, 120))
    .filter(Boolean)
    .slice(0, 8);
}

function buildTrustProfileSummary(profile = {}) {
  const safe = normalizeTrustProfile(profile);
  return {
    schemaVersion: TRUST_MEMORY_SCHEMA_VERSION,
    profileId: safe.profileId,
    entityType: safe.entityType,
    entityId: safe.entityId,
    displayName: safe.displayName,
    observations: safe.totals.observations,
    trustScore: safe.scores.trustScore,
    reliabilityScore: safe.scores.reliabilityScore,
    trustLevel: safe.trustLevel,
    trend: safe.trend,
    flags: safe.flags,
    receiptLines: buildTrustReceiptLines(safe)
  };
}

function buildTrustMemorySummary(state = {}) {
  const safe = normalizeTrustMemoryState(state);
  const counts = {};
  TRUST_BUCKETS.forEach((bucket) => {
    counts[bucket] = Object.keys(safe.profiles[bucket]).length;
  });
  const allProfiles = TRUST_BUCKETS.flatMap((bucket) => Object.values(safe.profiles[bucket]));
  const highTrustProfiles = allProfiles.filter((profile) => ["high", "very_high"].includes(profile.trustLevel)).length;
  const lowTrustProfiles = allProfiles.filter((profile) => profile.trustLevel === "low").length;
  return {
    schemaVersion: TRUST_MEMORY_SCHEMA_VERSION,
    profileCounts: counts,
    totalProfiles: allProfiles.length,
    highTrustProfiles,
    lowTrustProfiles,
    recentEventsCount: safe.recentEvents.length
  };
}

const trustMemoryApi = {
  createTrustMemoryState,
  normalizeTrustMemoryState,
  createTrustProfile,
  normalizeTrustProfile,
  updateTrustMemoryFromIntegrityResult,
  updateTrustProfileFromOutcome,
  calculateTrustScore,
  calculateReliabilityScore,
  classifyTrustLevel,
  classifyReliabilityTrend,
  buildTrustMemorySummary,
  buildTrustProfileSummary,
  buildTrustReceiptLines,
  sanitizeTrustMemoryText,
  sanitizeTrustMemoryMetadata,
  createTrustProfileId,
  createTrustMemoryEventId
};

globalThis.FocusTrackTrustMemory = trustMemoryApi;

Object.entries(trustMemoryApi).forEach(([key, value]) => {
  if (globalThis[key] === undefined) globalThis[key] = value;
});

if (typeof module !== "undefined" && module.exports) {
  module.exports = trustMemoryApi;
}
