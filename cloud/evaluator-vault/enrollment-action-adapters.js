"use strict";

// Prepared adapters only. Construction/default calls perform no credential or
// network access. Runtime callers must explicitly approve and supply transports.
const { createCloudAwardGcsObjectPort } = require("../../shared/evidence/cloud-award-issuance-store.js");
const disabled = () => { throw Error("enrollment_action_adapter_disabled"); };
function createSupabaseAuthHttpClient({ actionEnabled = false, issuer, getApiKey, fetch: transport } = {}) {
  if (actionEnabled !== true) return Object.freeze({ getUser: disabled });
  const url = new URL(issuer);
  if (url.protocol !== "https:" || url.pathname !== "/auth/v1" || url.username || url.password || url.search || url.hash || url.port ||
      typeof getApiKey !== "function" || typeof transport !== "function") throw Error("supabase_auth_transport_required");
  return Object.freeze({ async getUser(token) {
    try {
      if (typeof token !== "string" || token.length > 8192 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw Error("invalid_bearer");
      const key = await getApiKey();
      if (typeof key !== "string" || !key || key.length > 8192 || /[\s\x00-\x1f\x7f]/.test(key)) throw Error("auth_api_key_unavailable");
      const response = await transport(`${issuer}/user`, { method: "GET", redirect: "error", signal: AbortSignal.timeout(15000),
        headers: { apikey: key, authorization: `Bearer ${token}` } });
      if (!response?.ok || Number(response.headers?.get?.("content-length") || 0) > 65536) throw Error("auth_request_failed");
      const text = await response.text();
      if (Buffer.byteLength(text) > 65536) throw Error("auth_response_too_large");
      const user = JSON.parse(text);
      if (typeof user?.id !== "string" || !user.id) throw Error("auth_user_missing");
      // Never expose email, user metadata, sessions, API key or bearer.
      return { data: { user: { id: user.id, is_anonymous: user.is_anonymous } }, error: null };
    } catch (_) { return { data: { user: null }, error: { message: "auth_verification_unavailable" } }; }
  } });
}
function createSupabaseEnrollmentIdentityVerifier({ actionEnabled = false, auth, issuer, audience,
  allowedSubjects, now = Date.now } = {}) {
  if (actionEnabled !== true) return async () => ({ status: "identity_verification_disabled" });
  if (typeof auth?.getUser !== "function" || typeof issuer !== "string" || typeof audience !== "string" || !audience ||
      !Array.isArray(allowedSubjects) || ![1, 2].includes(allowedSubjects.length) || allowedSubjects.some(s => typeof s !== "string" || !s) ||
      new Set(allowedSubjects).size !== allowedSubjects.length || typeof now !== "function") throw Error("supabase_identity_configuration_required");
  const expectedIssuer = new URL(issuer);
  if (expectedIssuer.protocol !== "https:" || expectedIssuer.username || expectedIssuer.password || expectedIssuer.search ||
      expectedIssuer.hash || expectedIssuer.port || expectedIssuer.pathname !== "/auth/v1") throw Error("supabase_identity_configuration_required");
  const subjects = new Set(allowedSubjects);
  return async request => {
    const denied = { status: "identity_verification_denied" };
    try {
      const header = typeof request?.headers?.get === "function" ? request.headers.get("authorization") : request?.headers?.authorization;
      if (typeof header !== "string" || header.length > 8192 || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(header)) return denied;
      const token = header.slice(7), parts = token.split(".");
      const serialized = Buffer.from(parts[1], "base64url").toString("utf8");
      if (Buffer.from(serialized).toString("base64url") !== parts[1]) return denied;
      const claims = JSON.parse(serialized), before = now();
      // Decode is only a rejection precheck. Never return identity until the
      // existing server-side getUser(token) has authenticated the SAME token.
      if (!Number.isSafeInteger(before) || before <= 0 || claims.iss !== issuer || claims.aud !== audience || !subjects.has(claims.sub) ||
          claims.role !== "authenticated" || claims.is_anonymous === true || !Number.isSafeInteger(claims.exp) ||
          !Number.isSafeInteger(claims.exp * 1000) || claims.exp * 1000 <= before) return denied;
      const result = await auth.getUser(token), user = result?.data?.user, after = now();
      if (result?.error || !user || user.id !== claims.sub || user.is_anonymous === true || !Number.isSafeInteger(after) ||
          after < before || after >= claims.exp * 1000) return denied;
      return { status: "verified_identity", issuer, audience, subject: user.id, expiresAt: claims.exp * 1000 };
    } catch (_) { return denied; }
  };
}

function createEnrollmentGcsActionPort({ actionEnabled = false, bucket, allowedReadNames, allowedCreateNames,
  getAccessToken, fetch: transport } = {}) {
  if (actionEnabled !== true) return Object.freeze({ readObject: disabled, createObject: disabled });
  if (typeof getAccessToken !== "function" || typeof transport !== "function" ||
      !Array.isArray(allowedReadNames) || !Array.isArray(allowedCreateNames)) throw Error("gcs_action_transport_required");
  const reads = new Set(allowedReadNames), creates = new Set(allowedCreateNames);
  for (const name of [...reads, ...creates]) if (typeof name !== "string" || !/^[a-z0-9_./:-]+$/.test(name) ||
      name.split("/").some(p => !p || p === "." || p === "..")) throw Error("gcs_action_object_scope_required");
  const port = createCloudAwardGcsObjectPort({ bucket, authorizedFetch: async (url, options) => {
    const token = await getAccessToken();
    if (typeof token !== "string" || token.length < 20 || /[\s\x00-\x1f\x7f]/.test(token)) throw Error("runtime_access_token_unavailable");
    return transport(url, { ...options, headers: { ...options.headers, authorization: `Bearer ${token}` } });
  } });
  return Object.freeze({
    readObject(name, options) { if (!reads.has(name)) throw Error("gcs_action_read_scope_denied"); return port.readObject(name, options); },
    createObject(name, serialized, precondition) { if (!creates.has(name)) throw Error("gcs_action_create_scope_denied"); return port.createObject(name, serialized, precondition); }
  });
}

module.exports = Object.freeze({ createSupabaseEnrollmentIdentityVerifier, createEnrollmentGcsActionPort, createSupabaseAuthHttpClient });
