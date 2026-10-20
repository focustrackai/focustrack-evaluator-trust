"use strict";

// Append-only issuance backend. No credential acquisition or default cloud target.
// The injected object port must implement durable create-if-generation-zero and
// generation-pinned reads using a separately authorized service identity.
const { cloudAwardSigningText } = require("./cloud-evaluator-award-authorization.mjs");
const TASK = /^codex_prospective_[a-f0-9]{24}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const GENERATION = /^[1-9][0-9]{0,29}$/;
const MAX_BYTES = 16384;
const clone = value => JSON.parse(JSON.stringify(value));

function validRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === 4 && ["taskId", "bindingSha256", "payload", "serializedAuthorization"].every(key => Object.hasOwn(value, key)) &&
    typeof value.taskId === "string" && TASK.test(value.taskId) && typeof value.bindingSha256 === "string" && SHA256.test(value.bindingSha256) &&
    value.payload?.taskId === value.taskId && (value.serializedAuthorization === null || typeof value.serializedAuthorization === "string");
}

function serializedRecord(record) {
  if (!validRecord(record)) throw new Error("issuance_record_invalid");
  cloudAwardSigningText(record.payload);
  const serialized = JSON.stringify({ taskId: record.taskId, bindingSha256: record.bindingSha256,
    payload: record.payload, serializedAuthorization: record.serializedAuthorization });
  if (Buffer.byteLength(serialized, "utf8") > MAX_BYTES) throw new Error("issuance_record_too_large");
  return serialized;
}

function sameReservation(left, right) {
  return left.taskId === right.taskId && left.bindingSha256 === right.bindingSha256 &&
    cloudAwardSigningText(left.payload) === cloudAwardSigningText(right.payload);
}

function createCloudAwardIssuanceStore({ readObject, createObject } = {}) {
  if (typeof readObject !== "function" || typeof createObject !== "function") throw new Error("atomic_object_port_required");
  function name(taskId, namespace) {
    if (typeof taskId !== "string" || !TASK.test(taskId)) throw new Error("task_rejected");
    return `${namespace}/${taskId}.json`;
  }
  async function readRecord(objectName) {
    const object = await readObject(objectName);
    if (object?.status === "absent") return null;
    if (object?.status !== "found" || typeof object.generation !== "string" || !GENERATION.test(object.generation) ||
        typeof object.serialized !== "string" || Buffer.byteLength(object.serialized, "utf8") > MAX_BYTES)
      throw new Error("issuance_object_read_failed");
    const record = JSON.parse(object.serialized);
    if (serializedRecord(record) !== object.serialized) throw new Error("issuance_object_noncanonical");
    return record;
  }
  async function createOrRead(objectName, record, matchPayload = true) {
    const serialized = serializedRecord(record);
    const written = await createObject(objectName, serialized, { ifGenerationMatch: 0 });
    if (!["created", "already_exists"].includes(written?.status)) throw new Error("issuance_object_write_failed");
    // Always read back authoritative bytes. A lost response may have committed;
    // caller retries rather than deleting/resetting or creating another task key.
    const stored = await readRecord(objectName);
    if (!stored || stored.taskId !== record.taskId || stored.bindingSha256 !== record.bindingSha256 ||
        (matchPayload && !sameReservation(stored, record))) throw new Error("issuance_reservation_conflict");
    return stored;
  }
  async function read(taskId) {
    const reservation = await readRecord(name(taskId, "reservations"));
    if (!reservation) return null;
    if (reservation.taskId !== taskId || reservation.serializedAuthorization !== null) throw new Error("issuance_reservation_invalid");
    const publication = await readRecord(name(taskId, "authorizations"));
    if (!publication) return clone(reservation);
    if (!sameReservation(publication, reservation) || typeof publication.serializedAuthorization !== "string")
      throw new Error("issuance_publication_conflict");
    return clone(publication);
  }
  return Object.freeze({ read,
    async reserveOnce(record) {
      if (record?.serializedAuthorization !== null) throw new Error("unsigned_reservation_required");
      const reservation = await createOrRead(name(record.taskId, "reservations"), record, false);
      if (reservation.serializedAuthorization !== null) throw new Error("unsigned_reservation_required");
      return read(record.taskId);
    },
    async publishOnce(record) {
      if (typeof record?.serializedAuthorization !== "string" || !record.serializedAuthorization) throw new Error("publication_required");
      const reservation = await readRecord(name(record.taskId, "reservations"));
      if (!reservation || reservation.serializedAuthorization !== null || !sameReservation(reservation, record))
        throw new Error("issuance_reservation_conflict");
      const published = await createOrRead(name(record.taskId, "authorizations"), record);
      if (published.serializedAuthorization !== record.serializedAuthorization) throw new Error("issuance_publication_conflict");
      return clone(published);
    }
  });
}

// Concrete Cloud Storage JSON transport; supplied authorizedFetch owns auth.
// No default fetch/token/metadata call exists, so construction cannot contact GCP.
function createCloudAwardGcsObjectPort({ bucket, authorizedFetch, maxBytes = MAX_BYTES } = {}) {
  if (typeof bucket !== "string" || !/^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$/.test(bucket) ||
      typeof authorizedFetch !== "function" || !Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > 256 * 1024)
    throw new Error("authorized_gcs_transport_required");
  const base = `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o`;
  function objectName(value) {
    if (typeof value !== "string" || value.length > 512 || !/^[a-z0-9_./:-]+$/.test(value) ||
        value.split("/").some(part => !part || part === "." || part === "..")) throw new Error("object_name_rejected");
    return encodeURIComponent(value);
  }
  const request = (url, options = {}) => authorizedFetch(url, { ...options, redirect: "error", signal: AbortSignal.timeout(15000) });
  return Object.freeze({
    async readObject(name, { generation } = {}) {
      const encoded = objectName(name);
      if (generation !== undefined && (typeof generation !== "string" || !GENERATION.test(generation))) throw new Error("gcs_generation_rejected");
      const response = await request(`${base}/${encoded}${generation === undefined ? "" : `?generation=${generation}`}`);
      if (response.status === 404) return { status: "absent" };
      if (!response.ok) throw new Error("gcs_object_read_failed");
      const metadata = await response.json();
      if (metadata.name !== name || typeof metadata.generation !== "string" || !GENERATION.test(metadata.generation) ||
          (generation !== undefined && generation !== metadata.generation) ||
          !/^[0-9]{1,10}$/.test(String(metadata.size)) || Number(metadata.size) > maxBytes) throw new Error("gcs_object_metadata_rejected");
      const content = await request(`${base}/${encoded}?alt=media&generation=${metadata.generation}`);
      if (!content.ok) throw new Error("gcs_object_generation_read_failed");
      const serialized = await content.text();
      if (Buffer.byteLength(serialized, "utf8") !== Number(metadata.size)) throw new Error("gcs_object_size_rejected");
      return { status: "found", generation: metadata.generation, serialized, createdAt: Date.parse(metadata.timeCreated) };
    },
    async createObject(name, serialized, precondition) {
      const encoded = objectName(name);
      if (precondition?.ifGenerationMatch !== 0 || typeof serialized !== "string" || Buffer.byteLength(serialized, "utf8") > maxBytes)
        throw new Error("gcs_create_precondition_required");
      const response = await request(`https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(bucket)}/o?uploadType=media&name=${encoded}&ifGenerationMatch=0`,
        { method: "POST", headers: { "content-type": "application/json" }, body: serialized });
      if (response.status === 412) return { status: "already_exists" };
      if (!response.ok) throw new Error("gcs_object_create_failed");
      return { status: "created" };
    }
  });
}

module.exports = Object.freeze({ createCloudAwardIssuanceStore, createCloudAwardGcsObjectPort });
