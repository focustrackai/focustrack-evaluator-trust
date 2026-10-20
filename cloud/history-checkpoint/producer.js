"use strict";

const crypto = require("node:crypto");
const c = require("./contract.js");
const BUCKET = "focustrack-award-controls-818502899155"; // Proposed, not provisioned.
const SA = "history-checkpoint-producer@focustrack-eval-20260927.iam.gserviceaccount.com";
const WIF = "projects/818502899155/locations/global/workloadIdentityPools/github-history-checkpoint/providers/pinned-producer";
const WORKFLOW = ".github/workflows/produce-history-checkpoint.yml";
// Source: docs/GATE_H_EXISTING_SOURCE_REUSE_20261004.md:47 and
// docs/GATE_H_SINGLE_PILOT_CUSTODY_APPROVAL_PACKET_20261004.md:54.
// Historical producer/no-award SHA is NOT this new workflow's activation SHA.
const TRUST_REPOSITORY = "focustrackai/focustrack-evaluator-trust";
const TRUST_REPOSITORY_ID = "1391046244", TRUST_OWNER_ID = "289272418";
const fail = code => { throw new Error(code); };
function validatePolicy(policy, env) {
  const isNative = Object.hasOwn(policy, "runtime");
  const expected = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: TRUST_REPOSITORY,
    GITHUB_REF: "refs/heads/main", GITHUB_EVENT_NAME: "workflow_dispatch", RUNNER_ENVIRONMENT: "github-hosted",
    GITHUB_SHA: policy.workflowSha, GITHUB_WORKFLOW_SHA: policy.workflowSha,
    GITHUB_WORKFLOW_REF: `${TRUST_REPOSITORY}/${WORKFLOW}@refs/heads/main`,
    GITHUB_REPOSITORY_ID: policy.repositoryId, GITHUB_REPOSITORY_OWNER_ID: policy.repositoryOwnerId };
  if (isNative) require("./cloud-run-runtime.js").validateNativePolicy(policy, env);
  else if (!/^[a-f0-9]{40}$/.test(policy.workflowSha || "") || /^0+$/.test(policy.workflowSha) ||
      policy.repositoryId !== TRUST_REPOSITORY_ID || policy.repositoryOwnerId !== TRUST_OWNER_ID ||
      !Object.entries(expected).every(([k, v]) => typeof v === "string" && env[k] === v)) fail("producer_policy_rejected");
  return validatePolicyConfiguration(policy);
}
function validatePolicyConfiguration(policy) {
  if (Object.hasOwn(policy, "runtime")) require("./cloud-run-runtime.js").validateNativeConfiguration(policy);
  if (!/^projects\/focustrack-eval-20260927\/locations\/us-central1\/keyRings\/[A-Za-z0-9_-]+\/cryptoKeys\/prior-history-checkpoints\/cryptoKeyVersions\/[1-9][0-9]*$/.test(policy.keyVersion || "") ||
      policy.checkpointTrust?.revoked !== false || !Number.isSafeInteger(policy.checkpointTrust?.notBefore) ||
      !Number.isSafeInteger(policy.checkpointTrust?.notAfter)) fail("producer_policy_rejected");
  const key = crypto.createPublicKey(policy.checkpointTrust.publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519" ||
      c.hash(key.export({ type: "spki", format: "der" })) !== policy.publicKeySha256) fail("producer_key_rejected");
  if (policy.sourceReader) {
    const r = policy.sourceReader, versions = { appIdVersion: "evaluator-github-app-id",
      installationIdVersion: "evaluator-github-app-installation-id", privateKeyVersion: "evaluator-github-app-private-key" };
    if (Object.keys(r).length !== 6 || !/^[a-z0-9][a-z0-9-]{0,38}\/[a-z0-9][a-z0-9_.-]{0,99}$/.test(r.repository || "") ||
        !/^[1-9][0-9]{0,19}$/.test(r.repositoryId || "") || !/^[1-9][0-9]{0,19}$/.test(r.repositoryOwnerId || "") ||
        !Object.entries(versions).every(([field, name]) => new RegExp(`^projects/818502899155/secrets/${name}/versions/[1-9][0-9]*$`).test(r[field] || "")))
      fail("producer_source_reader_policy_rejected");
  }
  return policy;
}
async function produce({ policy, enrollmentId, environment = {}, ports, now = Date.now }) {
  // No input reads, token requests, locks, signing or output writes when disabled.
  if (policy?.enabled !== true || environment.FOCUSTRACK_HISTORY_PRODUCER_ENABLED !== "1")
    return { status: "disabled", mutatesXp: false };
  policy = c.parse(c.canonical(policy));
  validatePolicy(policy, environment);
  if (policy.observationRegistration) {
    if (typeof ports?.resolveRegistration !== "function") fail("producer_registration_required");
    policy = require("./registered-observation.js").materializeRegisteredPolicy(policy, await ports.resolveRegistration()).policy;
    validatePolicy(policy, environment);
  }
  const isNative = Object.hasOwn(policy, "runtime");
  if (isNative && enrollmentId !== policy.runtime.enrollmentId) fail("producer_native_enrollment_rejected");
  if (!c.OPAQUE.test(enrollmentId || "") || !ports ||
      ["readInput", "createReservedObject", "readReservation", "readOutput", "githubJson", "sign"].some(k => typeof ports[k] !== "function"))
    fail("producer_dependencies_rejected");
  let time = now();
  if (!Number.isSafeInteger(time) || time < policy.checkpointTrust.notBefore || time >= policy.checkpointTrust.notAfter)
    fail("producer_trust_expired");
  let nativeInputPin, observationInput = policy.observationInput;
  if (policy.observationSelection) {
    if (!isNative || environment.FOCUSTRACK_HISTORY_OBSERVATION_INPUT_ENABLED !== "1" ||
        policy.observationSelection.expiresAt > policy.checkpointTrust.notAfter)
      fail("producer_observation_input_disabled_or_mismatched");
    observationInput = await require("./cloud-run-observation.js").resolveObservationInput(policy.observationSelection, ports, now);
  }
  if (observationInput) {
    if (environment.FOCUSTRACK_HISTORY_OBSERVATION_INPUT_ENABLED !== "1" || observationInput.enrollmentId !== enrollmentId ||
        observationInput.expiresAt > policy.checkpointTrust.notAfter)
      fail("producer_observation_input_disabled_or_mismatched");
    const { createProtectedObservationInputWriter } = require("./observation-input.js");
    const writer = createProtectedObservationInputWriter({ actionEnabled: true, config: observationInput,
      readObservation: ports.readObservation, readReceipt: ports.readReceipt, readInput: ports.readInput,
      createInput: ports.createObservationInput, githubJson: ports.githubJson, readCloudRunExecution: ports.readCloudRunExecution,
      receiptTrust: policy.receiptTrust, now });
    const written = await writer.write({ enrollmentId });
    if (written.status !== "protected_observation_history_input_stored") fail("producer_observation_input_unconfirmed_no_retry");
    if (isNative) nativeInputPin = written.inputPin;
    const afterInput = now();
    if (!Number.isSafeInteger(afterInput) || afterInput < time || afterInput >= policy.checkpointTrust.notAfter)
      fail("producer_input_time_rejected_no_retry");
    time = afterInput;
  }
  const source = await ports.readInput(`inputs/${enrollmentId}.json`, nativeInputPin);
  const input = c.validateEnrollment(source.serialized, enrollmentId, time);
  if (isNative && (![2, 3].includes(input.schemaVersion) || !nativeInputPin || source.generation !== nativeInputPin.generation ||
      source.createdAt !== nativeInputPin.createdAt || c.hash(source.serialized) !== nativeInputPin.sha256))
    fail("producer_native_input_pin_rejected");
  if (input.schemaVersion >= 2 && typeof ports.readCloudRunExecution !== "function") fail("producer_cloud_run_reader_required");
  if (input.schemaVersion === 3 && typeof ports.readObservation !== "function") fail("producer_actor_custody_reader_required");
  const inputPin = { generation: source.generation, sha256: c.hash(source.serialized), createdAt: source.createdAt };
  if (!/^[1-9][0-9]{0,19}$/.test(source.generation || "") || !Number.isSafeInteger(source.createdAt) ||
      source.createdAt <= 0 || source.createdAt > time || input.expiresAt > policy.checkpointTrust.notAfter)
    fail("producer_input_custody_rejected");
  // Consume the enrollment before signing. Any collision/uncertain result stops;
  // never overwrite, release, re-sign or automatically retry a reserved attempt.
  const reservationName = `reservations/${enrollmentId}.json`;
  const reservationBytes = c.canonical({ enrollmentId, inputPin, reservedAt: time });
  const reservation = await ports.createReservedObject(reservationName, reservationBytes, { ifGenerationMatch: 0 });
  if (reservation?.status !== "created" || !/^[1-9][0-9]{0,19}$/.test(reservation.generation || ""))
    fail("producer_attempt_reserved_or_uncertain");
  const reserved = await ports.readReservation(reservationName, reservation.generation);
  if (reserved?.generation !== reservation.generation || reserved.serialized !== reservationBytes ||
      !Number.isSafeInteger(reserved.createdAt) || reserved.createdAt < time)
    fail("producer_reservation_readback_rejected");
  const facts = await c.observePriorReceipts(input, { githubJson: ports.githubJson, readCloudRunExecution: ports.readCloudRunExecution,
    readObservation: ports.readObservation, receiptTrust: policy.receiptTrust, now: time });
  const capturedAt = now();
  if (!Number.isSafeInteger(capturedAt) || capturedAt < time || capturedAt >= input.expiresAt ||
      capturedAt >= policy.checkpointTrust.notAfter) fail("producer_capture_expired");
  const payload = c.payloadFor(input, facts, inputPin, capturedAt);
  const serialized = c.canonical(payload);
  if (policy.observationSelection) {
    const current = await require("./cloud-run-observation.js").resolveObservationInput(policy.observationSelection, ports, now);
    if (c.canonical(current) !== c.canonical(observationInput)) fail("producer_selection_changed_no_retry");
    const checkedAt = now();
    if (!Number.isSafeInteger(checkedAt) || checkedAt < capturedAt || checkedAt >= input.expiresAt ||
        checkedAt >= policy.checkpointTrust.notAfter) fail("producer_capture_expired");
  }
  const signature = await ports.sign(c.signingBytes(serialized));
  const signedAt = now();
  if (!Number.isSafeInteger(signedAt) || signedAt < capturedAt || signedAt >= input.expiresAt ||
      signedAt >= policy.checkpointTrust.notAfter) fail("producer_signing_expired");
  if (!Buffer.isBuffer(signature) || signature.length !== 64) fail("producer_signature_rejected");
  const envelope = { keyId: c.KEY_ID, serialized, sha256: c.hash(serialized), signature: signature.toString("base64url") };
  c.verifyCheckpoint(envelope, policy.checkpointTrust, { enrollmentId, profileBindingSha256: input.profileBindingSha256, inputPin }, signedAt);
  const bytes = c.canonical(envelope), name = `checkpoints/${enrollmentId}.json`;
  const result = await ports.createReservedObject(name, bytes, { ifGenerationMatch: 0 });
  const writtenAt = now();
  if (!Number.isSafeInteger(writtenAt) || writtenAt < signedAt || writtenAt >= input.expiresAt ||
      writtenAt >= policy.checkpointTrust.notAfter) fail("producer_output_expired_no_retry");
  if (result?.status !== "created" || !/^[1-9][0-9]{0,19}$/.test(result.generation || "")) fail("producer_output_uncertain");
  const stored = await ports.readOutput(name, result.generation);
  const readAt = now();
  if (!Number.isSafeInteger(readAt) || readAt < writtenAt || readAt >= input.expiresAt ||
      readAt >= policy.checkpointTrust.notAfter) fail("producer_readback_expired_no_retry");
  if (stored?.generation !== result.generation || stored.serialized !== bytes ||
      !Number.isSafeInteger(stored.createdAt) || stored.createdAt < capturedAt) fail("producer_output_readback_rejected");
  // No identifiers, evidence, signature, content, token, or output object in logs.
  return { status: "checkpoint_stored", mutatesXp: false, countsTowardGenuineCorpus: false };
}
// Live HTTPS transport is dormant until BOTH activation switches and runner pins pass.
// Google validates OIDC cryptographically via this isolated WIF provider; local
// environment matching is not claimed to authenticate a JWT.
function createProductionPorts(policy, env, fetcher = globalThis.fetch, { now = Date.now } = {}) {
  if (policy?.enabled !== true || env.FOCUSTRACK_HISTORY_PRODUCER_ENABLED !== "1") fail("producer_disabled");
  policy = c.parse(c.canonical(policy));
  validatePolicy(policy, env);
  const installedPolicy = policy;
  let registrationReader, registration;
  let tokenPromise, sourceTokenPromise;
  let inputExpiresAt, previousTime = 0;
  const transportStarted = performance.now();
  function mutationBudget() {
    const time = now(), expiry = Math.min(policy.checkpointTrust.notAfter,
      (policy.observationSelection || policy.observationInput)?.expiresAt ?? inputExpiresAt ?? 0);
    const remaining = Math.floor(Math.min(expiry - time, 600000 - (performance.now() - transportStarted)));
    if (!Number.isSafeInteger(time) || time < previousTime || time < policy.checkpointTrust.notBefore || remaining <= 0)
      fail("producer_mutation_expired");
    previousTime = time; return remaining;
  }
  async function request(url, init = {}, max = 2 * 1024 * 1024, timeoutMs = 15000) {
    try {
      if (init.method === "POST" && (String(url).startsWith("https://storage.googleapis.com/upload/") ||
          String(url).startsWith("https://cloudkms.googleapis.com/"))) timeoutMs = Math.min(timeoutMs, mutationBudget());
      const response = await fetcher(url, { ...init, redirect: "error", signal: AbortSignal.timeout(timeoutMs) });
      if (response.redirected || !response.ok) fail("remote_request_rejected");
      if (String(url).startsWith("http://metadata.google.internal/") && response.headers?.get("Metadata-Flavor") !== "Google")
        fail("metadata_identity_rejected");
      const reader = response.body.getReader(); let size = 0; const chunks = [];
      try { while (true) { const row = await reader.read(); if (row.done) break;
        size += row.value.byteLength; if (size > max) fail("remote_response_rejected"); chunks.push(Buffer.from(row.value)); }
      } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
      return Buffer.concat(chunks).toString("utf8");
    } catch (_) { fail("producer_remote_request_failed_no_retry"); }
  }
  const json = async (url, init) => {
    const bytes = await request(url, init);
    try { return JSON.parse(bytes); } catch (_) { fail("producer_remote_response_invalid"); }
  };
  async function accessToken() {
    if (!tokenPromise) tokenPromise = (async () => {
      if (Object.hasOwn(policy, "runtime"))
        return require("./cloud-run-runtime.js").nativeAccessToken(installedPolicy, env, request);
      const url = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
      if (url.protocol !== "https:" || url.port || url.username || url.password || url.hash ||
          !url.hostname.endsWith(".actions.githubusercontent.com") ||
          !/^[^\s]{1,16384}$/.test(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || "")) fail("producer_oidc_unavailable");
      url.searchParams.set("audience", `//iam.googleapis.com/${WIF}`);
      const oidc = await json(url, { headers: { authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` } });
      if (!/^[^\s]{1,16384}$/.test(oidc.value || "")) fail("producer_oidc_unavailable");
      const sts = await json("https://sts.googleapis.com/v1/token", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ grantType: "urn:ietf:params:oauth:grant-type:token-exchange",
          audience: `//iam.googleapis.com/${WIF}`, scope: "https://www.googleapis.com/auth/cloud-platform",
          requestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
          subjectTokenType: "urn:ietf:params:oauth:token-type:jwt", subjectToken: oidc.value }) });
      if (!/^[^\s]{1,16384}$/.test(sts.access_token || "")) fail("producer_federation_rejected");
      const sa = await json(`https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SA}:generateAccessToken`,
        { method: "POST", headers: { authorization: `Bearer ${sts.access_token}`, "content-type": "application/json" },
          body: JSON.stringify({ scope: ["https://www.googleapis.com/auth/cloud-platform"], lifetime: "600s" }) });
      if (!/^[^\s]{1,16384}$/.test(sa.accessToken || "")) fail("producer_identity_rejected");
      return sa.accessToken;
    })();
    return tokenPromise;
  }
  async function headers(durableUse = false) {
    const token = await accessToken();
    if (durableUse && Object.hasOwn(policy, "runtime"))
      await require("./cloud-run-runtime.js").revalidateNativeExecution(installedPolicy, env, request, token);
    if (durableUse && installedPolicy.observationRegistration) await resolveRegistration(true);
    return { authorization: `Bearer ${token}` };
  }
  async function resolveRegistration(requireExisting = false) {
    if (!installedPolicy.observationRegistration || (requireExisting && !registration)) fail("producer_registration_required");
    await accessToken(); // Authenticate the actual installed workload before slot reads.
    if (!registrationReader) registrationReader = require("./registered-observation.js").createRegistrationReader({
      installed: installedPolicy, fetch: fetcher, getAccessToken: accessToken, now });
    const resolved = await registrationReader.read(registration?.pin);
    if (registration && c.canonical(resolved.policy) !== c.canonical(policy)) fail("producer_registration_changed");
    registration = resolved; policy = resolved.policy;
    return resolved.slot;
  }
  async function sourceHeaders() {
    const r = policy.sourceReader;
    if (env.FOCUSTRACK_HISTORY_SOURCE_READER_ENABLED !== "1" || !r) fail("github_source_reader_disabled");
    if (!sourceTokenPromise) sourceTokenPromise = (async () => {
      try {
        async function secret(name) {
          const value = JSON.parse(await request(`https://secretmanager.googleapis.com/v1/${name}:access`, { headers: await headers() }, 32 * 1024));
          const data = value?.payload?.data;
          if (value.name !== name || typeof data !== "string" || data.length > 24 * 1024) fail("source_secret_rejected");
          const bytes = Buffer.from(data, "base64");
          if (bytes.length === 0 || bytes.length > 16 * 1024 || bytes.toString("base64") !== data ||
              !Buffer.from(bytes.toString("utf8")).equals(bytes)) fail("source_secret_rejected");
          return bytes.toString("utf8");
        }
        // Reuse the repository-limited App exchange. No disk/env export, fallback
        // credential, retry or new key; activation still needs exact secret access.
        const { githubInstallationToken } = require("../evaluator-vault/worker.js");
        const token = await githubInstallationToken({ appId: await secret(r.appIdVersion),
          installationId: await secret(r.installationIdVersion), privateKey: await secret(r.privateKeyVersion),
          sourceRepository: r.repository, fetch: async (url, init) => {
            const value = JSON.parse(await request(url, init, 32 * 1024));
            return { ok: true, json: async () => value };
          } });
        const h = { authorization: `Bearer ${token}`, accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28", "user-agent": "focustrack-history-source-reader" };
        const repo = await json(`https://api.github.com/repos/${r.repository}`, { headers: h });
        if (repo.private !== true || repo.full_name?.toLowerCase() !== r.repository ||
            String(repo.id) !== r.repositoryId || String(repo.owner?.id) !== r.repositoryOwnerId)
          fail("source_repository_rejected");
        return { headers: h, repository: repo };
      } catch (_) { fail("github_source_read_identity_unavailable_no_retry"); }
    })();
    return sourceTokenPromise;
  }
  async function read(name, generation, bucket = BUCKET) {
    const base = `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
    const query = generation ? `?generation=${generation}` : "";
    const metadata = await json(base + query, { headers: await headers() });
    if (metadata.name !== name || metadata.bucket !== bucket || !/^[1-9][0-9]{0,19}$/.test(metadata.generation || "") ||
        (generation && metadata.generation !== generation)) fail("producer_storage_identity_rejected");
    const serialized = await request(base + `?alt=media&generation=${metadata.generation}`, { headers: await headers() }, 256 * 1024);
    return { status: "found", serialized, generation: metadata.generation, createdAt: Date.parse(metadata.timeCreated) };
  }
  function observationScope() {
    const scope = policy.observationInput || policy.observationSelection;
    if (env.FOCUSTRACK_HISTORY_OBSERVATION_INPUT_ENABLED !== "1" ||
        !/^codex_prospective_[a-f0-9]{24}$/.test(scope?.taskId || "") || !c.OPAQUE.test(scope?.enrollmentId || ""))
      fail("producer_observation_input_disabled_or_mismatched");
    return scope;
  }
  return {
    resolveRegistration,
    readInput: async (name, pin) => {
      if (!/^inputs\/[a-f0-9]{32}\.json$/.test(name)) fail("producer_storage_scope_rejected");
      const value = await read(name, pin?.generation);
      try { const input = c.parse(value.serialized); if (Number.isSafeInteger(input.expiresAt)) inputExpiresAt = input.expiresAt; } catch (_) { /* Production validation rejects malformed input before use. */ }
      return value;
    },
    readObservation: (name, pin) => {
      const scope = observationScope();
      const selectionRead = policy.observationSelection && !pin &&
        ["declaration", "profile-join"].some(suffix => name === `observations/${scope.taskId}/${suffix}.json`);
      if (!["declaration", "start", "profile-join"].some(suffix => name === `observations/${scope.taskId}/${suffix}.json`) ||
          (!selectionRead && !/^[1-9][0-9]{0,19}$/.test(pin?.generation || ""))) fail("producer_storage_scope_rejected");
      return read(name, pin?.generation, registration?.observation.bucket || "focustrack-evaluator-policies-818502899155");
    },
    readReceipt: (name, pin) => {
      const scope = observationScope();
      if (name !== `receipts/${scope.taskId}.json` || !/^[1-9][0-9]{0,19}$/.test(pin?.generation || "")) fail("producer_storage_scope_rejected");
      return read(name, pin.generation, "focustrack-evaluator-receipts-818502899155");
    },
    createObservationInput: async (name, serialized, precondition) => {
      const scope = observationScope();
      if (name !== `inputs/${scope.enrollmentId}.json` || precondition?.ifGenerationMatch !== 0 ||
          typeof serialized !== "string" || Buffer.byteLength(serialized) > 256 * 1024) fail("producer_storage_scope_rejected");
      const result = await json(`https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${encodeURIComponent(name)}&ifGenerationMatch=0`,
        { method: "POST", headers: { ...await headers(true), "content-type": "application/json" }, body: serialized });
      if (result.name !== name || result.bucket !== BUCKET) fail("producer_output_uncertain");
      return { status: "created", generation: result.generation };
    },
    readReservation: (name, generation) => { if (!/^reservations\/[a-f0-9]{32}\.json$/.test(name)) fail("producer_storage_scope_rejected"); return read(name, generation); },
    readOutput: (name, generation) => { if (!/^checkpoints\/[a-f0-9]{32}\.json$/.test(name)) fail("producer_storage_scope_rejected"); return read(name, generation); },
    createReservedObject: async (name, serialized, precondition) => {
      if (!/^(reservations|checkpoints)\/[a-f0-9]{32}\.json$/.test(name) || precondition.ifGenerationMatch !== 0)
        fail("producer_storage_scope_rejected");
      const result = await json(`https://storage.googleapis.com/upload/storage/v1/b/${BUCKET}/o?uploadType=media&name=${encodeURIComponent(name)}&ifGenerationMatch=0`,
        { method: "POST", headers: { ...await headers(true), "content-type": "application/json" }, body: serialized });
      if (result.name !== name || result.bucket !== BUCKET) fail("producer_output_uncertain");
      return { status: "created", generation: result.generation };
    },
    githubJson: async route => {
      const prefix = policy.sourceReader && `/repos/${policy.sourceReader.repository}`;
      if (prefix && (route === prefix || route.startsWith(prefix + "/"))) {
        const suffix = route.slice(prefix.length);
        if (suffix && (!/^\/contents\/[A-Za-z0-9_./-]+\?ref=[a-f0-9]{40}$/.test(suffix) ||
            suffix.split("?")[0].split("/").slice(2).some(part => !part || part === "." || part === "..")))
          fail("github_source_read_scope_rejected");
        const source = await sourceHeaders();
        return suffix ? json("https://api.github.com" + route, { headers: source.headers }) : structuredClone(source.repository);
      }
      if (Object.hasOwn(policy, "runtime")) fail("producer_native_github_scope_rejected");
      if (!/^\/repos\/[A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+\//.test(route + "/") || route.includes("..") ||
          !/^[^\s]{1,16384}$/.test(env.GITHUB_TOKEN || "")) fail("github_read_identity_unavailable");
      return json("https://api.github.com" + route, { headers: { authorization: `Bearer ${env.GITHUB_TOKEN}`,
        accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" } });
    },
    readCloudRunJob: async name => {
      if (!policy.observationSelection || name !== require("./cloud-run-observation.js").WORKER_JOB)
        fail("cloud_run_job_scope_rejected");
      return json(`https://run.googleapis.com/v2/${name}`, { headers: await headers() });
    },
    readCloudRunExecution: async name => {
      if (!/^projects\/focustrack-eval-20260927\/locations\/us-central1\/jobs\/focustrack-evaluator-worker\/executions\/focustrack-evaluator-worker-[a-z0-9]+$/.test(name || ""))
        fail("cloud_run_execution_scope_rejected");
      return json(`https://run.googleapis.com/v2/${name}`, { headers: await headers() });
    },
    sign: async bytes => {
      const result = await json(`https://cloudkms.googleapis.com/v1/${policy.keyVersion}:asymmetricSign`,
        { method: "POST", headers: { ...await headers(true), "content-type": "application/json" },
          body: JSON.stringify({ data: bytes.toString("base64") }) });
      if (result.name !== policy.keyVersion || result.protectionLevel !== "SOFTWARE" ||
          typeof result.signature !== "string") fail("producer_kms_response_rejected");
      const signature = Buffer.from(result.signature, "base64");
      if (signature.toString("base64") !== result.signature) fail("producer_kms_response_rejected");
      return signature; // Independently checked against the pinned public key before storage.
    }
  };
}
if (require.main === module) {
  (async () => {
    // Owner-protected repository variable; never echo it or accept dispatch policy bytes.
    const policy = JSON.parse(process.env.FOCUSTRACK_HISTORY_PRODUCER_POLICY || '{"enabled":false}');
    if (policy.enabled !== true || process.env.FOCUSTRACK_HISTORY_PRODUCER_ENABLED !== "1") {
      process.stdout.write('{"status":"disabled","mutatesXp":false}\n'); return;
    }
    validatePolicy(policy, process.env);
    const result = await produce({ policy, enrollmentId: process.env.FOCUSTRACK_HISTORY_ENROLLMENT_ID,
      environment: process.env, ports: createProductionPorts(policy, process.env) });
    process.stdout.write(JSON.stringify(result) + "\n");
  })().catch(() => { process.stderr.write("history_checkpoint_stopped_no_retry\n"); process.exitCode = 1; });
}
module.exports = { produce, createProductionPorts, validatePolicy, validatePolicyConfiguration, BUCKET, SA, WIF, WORKFLOW,
  TRUST_REPOSITORY, TRUST_REPOSITORY_ID, TRUST_OWNER_ID };
