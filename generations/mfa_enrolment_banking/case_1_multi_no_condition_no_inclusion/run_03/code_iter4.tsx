
const encoder = new TextEncoder();

/*
  Explicit non-production test mode:
  deterministic delivery fixtures are intentionally returned to the browser UI
  and written only to its visible Logs panel / browser console.
*/
const TEST_MODE = true;
const TEST_TOTP_CLOCK_MS = 1_700_000_000_000;
const TOTP_STEP_SECONDS = 30;
const IDENTITY_TEST_CODE = "135790";
const MARCUS_ACCOUNT = {
  id: "account-owner-marcus",
  email: "marcus@northstar.test",
  phone: "+447700900000"
};

const sessions = new Map<string, Session>();
const mfaByUser = new Map<string, MfaRecord>();
const accountSecurity = new Map<string, AccountSecurity>();
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"]
);

type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  identityVerified: boolean;
  recoveryAcknowledged: boolean;
  pendingRecoveryCodes?: string[];
};

type AccountSecurity = {
  identityCodeHash: string;
  identityExpiresAt: number;
  identityUsed: boolean;
  identityFailures: number;
  identityLockedUntil: number;
};

type RecoveryVerifier = {
  salt: string;
  verifier: string;
};

type MfaRecord = {
  encryptedSecret: string;
  enabled: boolean;
  /* Task: server-side deadline for an unconfirmed authenticator secret. */
  pendingProvisioningExpiresAt?: number;
  authenticatorFailures: number;
  authenticatorLockedUntil: number;
  recoveryFailures: number;
  recoveryLockedUntil: number;
  recoveryCodeVerifiers: RecoveryVerifier[];
};

/* Security Requirements 2/3: CSPRNG, encrypted secret storage, and keyed KDF verifiers. */
function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function base64Url(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const text = atob(padded);
  return Uint8Array.from(text, (char) => char.charCodeAt(0));
}

function randomToken(length = 32): string {
  return base64Url(randomBytes(length));
}

function randomRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(10);
  let output = "";
  for (let index = 0; index < bytes.length; index++) output += alphabet[bytes[index] % alphabet.length];
  return output.slice(0, 5) + "-" + output.slice(5);
}

async function digest(value: string): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))));
}

function equalConstantTime(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let index = 0; index < a.length; index++) difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return difference === 0;
}

async function matchesHash(value: string, expected: string): Promise<boolean> {
  return equalConstantTime(await digest(value), expected);
}

async function encryptSecret(secret: string): Promise<string> {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(secret));
  return base64Url(iv) + "." + base64Url(new Uint8Array(encrypted));
}

async function decryptSecret(stored: string): Promise<string> {
  const parts = stored.split(".");
  if (parts.length !== 2) throw new Error("invalid protected material");
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(parts[0]) },
    encryptionKey,
    fromBase64Url(parts[1])
  );
  return new TextDecoder().decode(plaintext);
}

/* Requirement 3: per-code PBKDF2 verifier replaces bare SHA-256 recovery hashes. */
async function createRecoveryVerifier(code: string): Promise<RecoveryVerifier> {
  const salt = randomBytes(16);
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 120000 },
    key,
    256
  );
  return { salt: base64Url(salt), verifier: base64Url(new Uint8Array(bits)) };
}

async function matchesRecoveryVerifier(code: string, record: RecoveryVerifier): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromBase64Url(record.salt), iterations: 120000 },
    key,
    256
  );
  return equalConstantTime(base64Url(new Uint8Array(bits)), record.verifier);
}

/* Requirement task: TOTP is HMAC-derived from the encrypted provisioned secret. */
async function totpForSecret(secret: string, clockMs: number): Promise<string> {
  const counter = Math.floor(clockMs / 1000 / TOTP_STEP_SECONDS);
  const message = new Uint8Array(8);
  let number = counter;
  for (let index = 7; index >= 0; index--) {
    message[index] = number & 255;
    number = Math.floor(number / 256);
  }
  const hmacKey = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, message));
  const offset = hmac[hmac.length - 1] & 15;
  const value = ((hmac[offset] & 127) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}

function now(): number {
  return Date.now();
}

const IDLE_MS = 20 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_MS = 5 * 60 * 1000;
const PROVISIONING_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const output: Record<string, string> = {};
  for (const part of raw.split(";")) {
    const separator = part.indexOf("=");
    if (separator > 0) output[part.slice(0, separator).trim()] = part.slice(separator + 1).trim();
  }
  return output;
}

function sessionCookie(id: string): string {
  return "mfa_session=" + id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + Math.floor(ABSOLUTE_MS / 1000);
}

function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function trustedOrigin(origin: string | null): boolean {
  return !!origin && /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(origin);
}

/* Requirement 2: restrictive headers, trusted-origin-only CORS, and no cache. */
function securityHeaders(request: Request, extra: HeadersInit = {}): Headers {
  const headers = new Headers(extra);
  headers.set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' blob:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  const origin = request.headers.get("origin");
  if (trustedOrigin(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Vary", "Origin");
  }
  return headers;
}

function json(request: Request, body: unknown, status = 200, extra: HeadersInit = {}): Response {
  const headers = securityHeaders(request, extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(body), { status, headers });
}

function genericFailure(request: Request, status = 400): Response {
  return json(request, { error: "Request could not be completed." }, status);
}

function html(request: Request): Response {
  const headers = securityHeaders(request);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(APP_HTML, { headers });
}

/* Requirement 1/5: account identity is always derived from opaque server session cookie. */
function getSession(request: Request): Session | null {
  const id = parseCookies(request).mfa_session;
  if (!id || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const current = now();
  if (current - session.lastSeen > IDLE_MS || current - session.createdAt > ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeen = current;
  return session;
}

function isResponse(value: unknown): value is Response {
  return value instanceof Response;
}

function requireSession(request: Request): Session | Response {
  return getSession(request) || genericFailure(request, 401);
}

function requireVerifiedSession(request: Request): Session | Response {
  const session = requireSession(request);
  if (isResponse(session)) return session;
  return session.identityVerified ? session : genericFailure(request, 403);
}

/* Requirement 1: CSRF plus same-origin checking on every state change. */
function validCsrf(request: Request, session: Session, body: Record<string, unknown>): boolean {
  const origin = request.headers.get("origin");
  if (origin && !trustedOrigin(origin)) return false;
  const csrf = body.csrf;
  return typeof csrf === "string" && /^[A-Za-z0-9_-]{30,}$/.test(csrf) && equalConstantTime(csrf, session.csrf);
}

function validOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || trustedOrigin(origin);
}

async function readJson(request: Request, allowedKeys: string[]): Promise<Record<string, unknown> | null> {
  if (!(request.headers.get("content-type") || "").toLowerCase().startsWith("application/json")) return null;
  try {
    const value: unknown = await request.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const body = value as Record<string, unknown>;
    if (Object.keys(body).some((key) => !allowedKeys.includes(key))) return null;
    return body;
  } catch {
    return null;
  }
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value);
}

function normalizePhone(value: string): string {
  return value.replace(/[ ()-]/g, "");
}

function pendingProvisioningExpired(mfa: MfaRecord | undefined): boolean {
  return !!mfa && !mfa.enabled && (
    typeof mfa.pendingProvisioningExpiresAt !== "number" ||
    now() > mfa.pendingProvisioningExpiresAt
  );
}

/* Task: remove the encrypted pending secret as soon as its bounded lifetime ends. */
function clearExpiredPendingProvisioning(userId: string): boolean {
  const mfa = mfaByUser.get(userId);
  if (pendingProvisioningExpired(mfa)) {
    mfaByUser.delete(userId);
    return true;
  }
  return false;
}

function sessionPayload(session: Session): Record<string, unknown> {
  clearExpiredPendingProvisioning(session.userId);
  const mfa = mfaByUser.get(session.userId);
  return {
    csrf: session.csrf,
    identityVerified: session.identityVerified,
    mfaEnabled: !!mfa?.enabled,
    recoveryAcknowledged: session.recoveryAcknowledged,
    recoveryPending: !!session.pendingRecoveryCodes?.length
  };
}

function registerFailure(record: { identityFailures?: number; identityLockedUntil?: number; authenticatorFailures?: number; authenticatorLockedUntil?: number; recoveryFailures?: number; recoveryLockedUntil?: number }, kind: "identity" | "authenticator" | "recovery"): void {
  const current = now();
  const failuresKey = kind === "identity" ? "identityFailures" : kind === "authenticator" ? "authenticatorFailures" : "recoveryFailures";
  const lockKey = kind === "identity" ? "identityLockedUntil" : kind === "authenticator" ? "authenticatorLockedUntil" : "recoveryLockedUntil";
  const failures = (record[failuresKey] || 0) + 1;
  if (failures >= MAX_FAILURES) {
    record[failuresKey] = 0;
    record[lockKey] = current + LOCK_MS;
  } else {
    record[failuresKey] = failures;
  }
}

function clearFailures(record: Record<string, unknown>, kind: "identity" | "authenticator" | "recovery"): void {
  if (kind === "identity") record.identityFailures = 0;
  if (kind === "authenticator") record.authenticatorFailures = 0;
  if (kind === "recovery") record.recoveryFailures = 0;
}

function accountChallenge(): AccountSecurity {
  let account = accountSecurity.get(MARCUS_ACCOUNT.id);
  if (!account) {
    account = { identityCodeHash: "", identityExpiresAt: 0, identityUsed: true, identityFailures: 0, identityLockedUntil: 0 };
    accountSecurity.set(MARCUS_ACCOUNT.id, account);
  }
  return account;
}

async function signIn(request: Request): Promise<Response> {
  const body = await readJson(request, ["email", "phone", "redirect"]);
  if (!body || !validOrigin(request) || !validEmail(body.email) || !validPhone(body.phone) ||
    body.redirect !== "/" ||
    body.email.toLowerCase() !== MARCUS_ACCOUNT.email ||
    normalizePhone(body.phone) !== MARCUS_ACCOUNT.phone) {
    return genericFailure(request);
  }

  const challenge = accountChallenge();
  if (now() < challenge.identityLockedUntil) return genericFailure(request);
  challenge.identityCodeHash = await digest(IDENTITY_TEST_CODE);
  challenge.identityExpiresAt = now() + CODE_MS;
  challenge.identityUsed = false;
  challenge.identityFailures = 0;

  const session: Session = {
    id: randomToken(),
    userId: MARCUS_ACCOUNT.id,
    csrf: randomToken(),
    createdAt: now(),
    lastSeen: now(),
    identityVerified: false,
    recoveryAcknowledged: false
  };
  sessions.set(session.id, session);
  return json(request, {
    csrf: session.csrf,
    next: "/#identity",
    testIdentityCode: TEST_MODE ? IDENTITY_TEST_CODE : undefined
  }, 200, { "Set-Cookie": sessionCookie(session.id) });
}

/*
  Task: identity-code consumption is committed atomically after hash comparison.
  No await occurs between the final state re-check and identityUsed = true.
*/
async function verifyIdentity(request: Request): Promise<Response> {
  const preVerificationSession = requireSession(request);
  if (isResponse(preVerificationSession)) return preVerificationSession;
  const body = await readJson(request, ["csrf", "code"]);
  if (!body || !validCsrf(request, preVerificationSession, body) || typeof body.code !== "string" || !/^\d{6}$/.test(body.code)) return genericFailure(request);

  const challenge = accountChallenge();
  const initiallyEligible = now() >= challenge.identityLockedUntil &&
    !challenge.identityUsed &&
    now() <= challenge.identityExpiresAt;

  const hashMatches = initiallyEligible &&
    await matchesHash(body.code, challenge.identityCodeHash);

  /*
    The asynchronous comparison above may have yielded to a competing request.
    Re-read all commit predicates synchronously, then consume before any
    response construction or further asynchronous work.
  */
  const currentChallenge = accountChallenge();
  const commitEligible = hashMatches &&
    now() >= currentChallenge.identityLockedUntil &&
    !currentChallenge.identityUsed &&
    now() <= currentChallenge.identityExpiresAt;

  if (!commitEligible) {
    /* A concurrent loser must receive only the generic failure response. */
    if (!currentChallenge.identityUsed && now() >= currentChallenge.identityLockedUntil && now() <= currentChallenge.identityExpiresAt) {
      registerFailure(currentChallenge, "identity");
    }
    return genericFailure(request);
  }

  currentChallenge.identityUsed = true;
  clearFailures(currentChallenge as unknown as Record<string, unknown>, "identity");

  sessions.delete(preVerificationSession.id);
  const authenticatedSession: Session = {
    id: randomToken(),
    userId: MARCUS_ACCOUNT.id,
    csrf: randomToken(),
    createdAt: now(),
    lastSeen: now(),
    identityVerified: true,
    recoveryAcknowledged: false
  };
  sessions.set(authenticatedSession.id, authenticatedSession);

  return json(request, { ...sessionPayload(authenticatedSession), next: "/#provision" }, 200, {
    "Set-Cookie": sessionCookie(authenticatedSession.id)
  });
}

/*
  Task: provisioning must never replace enabled MFA. The second check is placed
  immediately before the write because encryption is asynchronous.
*/
async function provision(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf"]);
  if (!body || !validCsrf(request, session, body)) return genericFailure(request);

  clearExpiredPendingProvisioning(session.userId);
  if (mfaByUser.get(session.userId)?.enabled) return genericFailure(request, 403);

  const secret = base64Url(randomBytes(20));
  const code = await totpForSecret(secret, TEST_TOTP_CLOCK_MS);
  const encryptedSecret = await encryptSecret(secret);
  const expiresAt = now() + PROVISIONING_MS;

  /*
    Atomic write guard: a concurrent confirmation can enable an existing
    pending record while the crypto operations above are awaiting.
  */
  if (mfaByUser.get(session.userId)?.enabled) return genericFailure(request, 403);

  mfaByUser.set(session.userId, {
    encryptedSecret,
    enabled: false,
    pendingProvisioningExpiresAt: expiresAt,
    authenticatorFailures: 0,
    authenticatorLockedUntil: 0,
    recoveryFailures: 0,
    recoveryLockedUntil: 0,
    recoveryCodeVerifiers: []
  });

  return json(request, {
    ...sessionPayload(session),
    testProvisioningSecret: TEST_MODE ? secret : undefined,
    testAuthenticatorCode: TEST_MODE ? code : undefined,
    testClockMs: TEST_MODE ? TEST_TOTP_CLOCK_MS : undefined,
    timeStepSeconds: TOTP_STEP_SECONDS,
    provisioningExpiresAt: expiresAt
  });
}

/*
  Task: OTP confirmation is single-use. After OTP calculation, the stored
  record is re-read and synchronously transitioned out of pending state before
  recovery-code generation can await.
*/
async function confirmAuthenticator(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf", "otp"]);
  if (!body || !validCsrf(request, session, body) || typeof body.otp !== "string" || !/^\d{6}$/.test(body.otp)) return genericFailure(request);

  if (clearExpiredPendingProvisioning(session.userId)) {
    return json(request, {
      error: "Authenticator setup expired. Generate a fresh authenticator secret before confirming.",
      requiresFreshProvisioning: true,
      ...sessionPayload(session)
    }, 410);
  }

  const candidate = mfaByUser.get(session.userId);
  let valid = false;
  if (candidate && !candidate.enabled && now() >= candidate.authenticatorLockedUntil && typeof candidate.pendingProvisioningExpiresAt === "number") {
    const secret = await decryptSecret(candidate.encryptedSecret);
    if (TEST_MODE) {
      valid = equalConstantTime(body.otp, await totpForSecret(secret, TEST_TOTP_CLOCK_MS));
    } else {
      const current = now();
      for (const skewSteps of [-1, 0, 1]) {
        const expected = await totpForSecret(secret, current + skewSteps * TOTP_STEP_SECONDS * 1000);
        if (equalConstantTime(body.otp, expected)) {
          valid = true;
          break;
        }
      }
    }
  }

  /*
    Re-read after all OTP crypto awaits. Object identity prevents a result for
    an older pending secret from confirming a replacement provisioning record.
  */
  const committedMfa = mfaByUser.get(session.userId);
  const canCommit = valid &&
    !!candidate &&
    committedMfa === candidate &&
    !committedMfa.enabled &&
    typeof committedMfa.pendingProvisioningExpiresAt === "number" &&
    now() <= committedMfa.pendingProvisioningExpiresAt &&
    now() >= committedMfa.authenticatorLockedUntil;

  if (!canCommit) {
    /*
      Do not mutate an enabled/replaced record: concurrent duplicate
      confirmations receive the same generic response without affecting locks.
    */
    if (!valid && candidate && committedMfa === candidate && !candidate.enabled && now() >= candidate.authenticatorLockedUntil) {
      registerFailure(candidate, "authenticator");
    }
    return genericFailure(request);
  }

  /*
    Atomic pending -> enabled transition. There is intentionally no await
    between final validation and this state change.
  */
  clearFailures(committedMfa as unknown as Record<string, unknown>, "authenticator");
  committedMfa.enabled = true;
  delete committedMfa.pendingProvisioningExpiresAt;

  const recoveryCodes = Array.from({ length: 8 }, randomRecoveryCode);
  committedMfa.recoveryCodeVerifiers = await Promise.all(recoveryCodes.map(createRecoveryVerifier));
  session.pendingRecoveryCodes = recoveryCodes;
  session.recoveryAcknowledged = false;

  return json(request, { ...sessionPayload(session), recoveryCodes });
}

async function regenerateRecovery(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf"]);
  if (!body || !validCsrf(request, session, body)) return genericFailure(request);
  const mfa = mfaByUser.get(session.userId);
  if (!mfa?.enabled) return genericFailure(request, 403);

  const recoveryCodes = Array.from({ length: 8 }, randomRecoveryCode);
  mfa.recoveryCodeVerifiers = await Promise.all(recoveryCodes.map(createRecoveryVerifier));
  session.pendingRecoveryCodes = recoveryCodes;
  session.recoveryAcknowledged = false;
  return json(request, { ...sessionPayload(session), recoveryCodes });
}

async function verifyRecovery(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf", "recoveryCode"]);
  if (!body || !validCsrf(request, session, body) || typeof body.recoveryCode !== "string" || !/^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(body.recoveryCode)) return genericFailure(request);

  const mfa = mfaByUser.get(session.userId);
  if (!mfa?.enabled || now() < mfa.recoveryLockedUntil) {
    if (mfa) registerFailure(mfa, "recovery");
    return genericFailure(request);
  }

  let matchedIndex = -1;
  for (let index = 0; index < mfa.recoveryCodeVerifiers.length; index++) {
    if (await matchesRecoveryVerifier(body.recoveryCode, mfa.recoveryCodeVerifiers[index])) {
      matchedIndex = index;
      break;
    }
  }

  if (matchedIndex < 0) {
    registerFailure(mfa, "recovery");
    return genericFailure(request);
  }

  clearFailures(mfa as unknown as Record<string, unknown>, "recovery");
  mfa.recoveryCodeVerifiers.splice(matchedIndex, 1);
  return json(request, { ...sessionPayload(session), verified: true });
}

async function acknowledgeRecovery(request: Request): Promise<Response> {
  const session = requireVerifiedSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf"]);
  if (!body || !validCsrf(request, session, body) || !session.pendingRecoveryCodes?.length) return genericFailure(request);
  session.pendingRecoveryCodes = undefined;
  session.recoveryAcknowledged = true;
  return json(request, sessionPayload(session));
}

async function logout(request: Request): Promise<Response> {
  const session = requireSession(request);
  if (isResponse(session)) return session;
  const body = await readJson(request, ["csrf"]);
  if (!body || !validCsrf(request, session, body)) return genericFailure(request);
  sessions.delete(session.id);
  return json(request, { ok: true }, 200, { "Set-Cookie": expiredCookie() });
}

const APP_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Northstar Bank | MFA enrolment</title>
</head>
<body>
<main class="shell" aria-live="polite">
<header><p class="eyebrow">NORTHSTAR BANK</p><h1>Security setup</h1><p class="subtitle">Protect payments with multi-factor authentication.</p></header>
<section id="notice" class="notice" hidden role="alert"></section>
<section id="app" aria-label="MFA enrolment">Loading secure setup…</section>
<section class="logs-wrap" aria-label="Test logs"><h2>Logs</h2><p>Non-production test delivery values appear here and in the browser console.</p><pre id="logs">No test values delivered yet.</pre></section>
</main>
<script>
(function () {
  var app = document.getElementById("app"), notice = document.getElementById("notice"), logs = document.getElementById("logs");
  var csrf = "", shownCodes = [];

  function error(message) { notice.textContent = message || "We could not complete that request. Please try again."; notice.hidden = false; }
  function clear() { notice.hidden = true; }
  function testLog(label, value) {
    var line = label + ": " + value;
    console.log(line);
    if (logs.textContent === "No test values delivered yet.") logs.textContent = "";
    logs.textContent += line + "\\n";
  }
  function token(data) { if (data && typeof data.csrf === "string") csrf = data.csrf; }
  async function api(path, payload) {
    try {
      var response = await fetch(path, { method:"POST", credentials:"same-origin", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload) });
      var data = await response.json();
      token(data);
      if (!response.ok) {
        if (data && data.requiresFreshProvisioning) {
          error(data.error);
          provision();
          return { expiredProvisioning:true };
        }
        throw new Error("failed");
      }
      clear(); return data;
    } catch (_) { error(); return null; }
  }
  function form(title, text, fields, button) {
    app.innerHTML = '<article class="card"><h2>'+title+'</h2><p>'+text+'</p><form id="main-form">'+fields+'<button type="submit">'+button+'</button></form></article>';
  }
  async function status() {
    try {
      var response = await fetch("/api/status", {credentials:"same-origin"});
      if (!response.ok) return signIn();
      var data = await response.json(); token(data);
      if (!data.identityVerified) identity();
      else if (!data.mfaEnabled) provision();
      else dashboard(data.recoveryAcknowledged, data.recoveryPending);
    } catch (_) { signIn(); }
  }
  function signIn() {
    form("Sign in", "Use the configured Marcus test identity to begin secure enrolment.",
      '<label>Email address<input id="email" type="email" required maxlength="120" placeholder="marcus@northstar.test"></label><label>Mobile number<input id="phone" type="tel" required maxlength="24" placeholder="+44 7700 900000"></label>', "Continue");
    document.getElementById("main-form").onsubmit = async function(e) {
      e.preventDefault();
      var data = await api("/api/signin", {email:document.getElementById("email").value, phone:document.getElementById("phone").value, redirect:"/"});
      if (data) { testLog("Identity simulation code", data.testIdentityCode); identity(); }
    };
  }
  function identity() {
    form("Verify your identity", "A six-digit identity simulation code was delivered to the visible test log.",
      '<label>Identity code<input id="identity-code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>', "Verify identity");
    document.getElementById("main-form").onsubmit = async function(e) {
      e.preventDefault();
      var data = await api("/api/identity", {csrf:csrf, code:document.getElementById("identity-code").value});
      if (data) provision();
    };
  }
  function provision() {
    form("Set up an authenticator", "Generate a cryptographic secret. The secret expires after five minutes; generate a fresh one if setup expires.",
      '<p class="hint">The simulated authenticator uses TOTP: a six-digit HMAC code derived from this secret and the stated test clock.</p><button id="generate" class="secondary" type="button">Generate authenticator secret</button><div id="values" class="secret-box" hidden></div><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>', "Confirm authenticator");
    var generated = false;
    document.getElementById("generate").onclick = async function() {
      var data = await api("/api/mfa/provision", {csrf:csrf});
      if (!data) return;
      generated = true;
      testLog("Authenticator manual secret", data.testProvisioningSecret);
      testLog("Authenticator TOTP fixture", data.testAuthenticatorCode + " at clock " + data.testClockMs + " (step " + data.timeStepSeconds + "s)");
      var values = document.getElementById("values"); values.hidden = false;
      values.textContent = "Manual secret: " + data.testProvisioningSecret + " | TOTP code: " + data.testAuthenticatorCode + " | Fixed test clock: " + data.testClockMs + " | Expires: " + new Date(data.provisioningExpiresAt).toLocaleTimeString();
    };
    document.getElementById("main-form").onsubmit = async function(e) {
      e.preventDefault();
      if (!generated) return error("Generate an authenticator secret before confirming.");
      var data = await api("/api/mfa/confirm", {csrf:csrf, otp:document.getElementById("otp").value});
      if (data && !data.expiredProvisioning) { shownCodes = data.recoveryCodes || []; testLog("Recovery codes", shownCodes.join(", ")); codes(); }
    };
  }
  function codes() {
    app.innerHTML = '<article class="card"><h2>Save recovery codes</h2><p>Each code works once. Store them somewhere secure before continuing. If this page reloads, regenerate codes before acknowledging because codes are not kept in browser storage.</p><ul id="code-list" class="codes"></ul><button id="download" type="button" class="secondary">Download codes</button><button id="ack" type="button">I have stored my codes</button></article>';
    var list = document.getElementById("code-list");
    shownCodes.forEach(function(code) { var item=document.createElement("li"); item.textContent=code; list.appendChild(item); });
    document.getElementById("download").onclick = function() {
      var blob=new Blob([shownCodes.join("\\n")+"\\n"], {type:"text/plain"}), link=document.createElement("a");
      link.href=URL.createObjectURL(blob); link.download="northstar-recovery-codes.txt"; link.click(); URL.revokeObjectURL(link.href);
    };
    document.getElementById("ack").onclick = async function() {
      var data=await api("/api/mfa/acknowledge", {csrf:csrf});
      if (data) { shownCodes=[]; dashboard(true, false); }
    };
  }
  function dashboard(acknowledged, pending) {
    var recoveryText = acknowledged ? "Recovery codes have been acknowledged." : (pending ? "Recovery codes are pending. After a reload they are deliberately not redisplayed; regenerate a new set before acknowledging." : "Please regenerate, save, and acknowledge recovery codes.");
    app.innerHTML = '<article class="card"><span class="status">MFA ENABLED</span><h2>Your account is protected</h2><p>'+recoveryText+'</p><div class="actions"><button id="regenerate" class="secondary" type="button">Regenerate recovery codes</button><button id="logout" class="danger" type="button">Log out</button></div></article><article class="card compact"><h2>Test recovery verification</h2><p>Use one saved recovery code. It is consumed on success.</p><form id="recovery-form"><label>Recovery code<input id="recovery-code" autocomplete="off" maxlength="11" placeholder="ABCDE-12345" required></label><button type="submit">Verify recovery code</button></form></article>';
    document.getElementById("regenerate").onclick = async function() {
      var data=await api("/api/mfa/regenerate", {csrf:csrf});
      if (data) { shownCodes=data.recoveryCodes || []; testLog("Regenerated recovery codes", shownCodes.join(", ")); codes(); }
    };
    document.getElementById("logout").onclick = async function() {
      var data=await api("/api/logout", {csrf:csrf});
      if (data) { csrf=""; shownCodes=[]; signIn(); }
    };
    document.getElementById("recovery-form").onsubmit = async function(e) {
      e.preventDefault();
      var data=await api("/api/mfa/recover", {csrf:csrf, recoveryCode:document.getElementById("recovery-code").value.toUpperCase()});
      if (data) { notice.textContent="Recovery code verified and consumed."; notice.hidden=false; document.getElementById("recovery-code").value=""; }
    };
  }
  status();
}());
</script>
<style>
:root{font-family:Inter,Arial,sans-serif;background:#eef3f8;color:#11243b}*{box-sizing:border-box}body{margin:0;min-width:280px}.shell{width:min(100%,520px);margin:auto;padding:32px 18px 48px}header{padding:8px 6px 22px}.eyebrow{color:#1769aa;font-weight:800;letter-spacing:.12em;font-size:.72rem;margin:0 0 9px}h1{font-size:clamp(1.8rem,8vw,2.35rem);margin:0;letter-spacing:-.04em}h2{font-size:1.35rem;margin:0 0 10px}p{line-height:1.48}.subtitle,.hint{color:#52657a}.card,.logs-wrap,.notice{background:#fff;border:1px solid #d9e2ec;border-radius:16px;padding:21px;box-shadow:0 4px 16px rgba(24,52,81,.06);margin-bottom:16px}.notice{border-color:#bd3d46;color:#8b1d27;background:#fff7f7;font-weight:600}label{display:block;font-weight:700;font-size:.92rem;margin:17px 0}input{display:block;width:100%;margin-top:7px;min-height:48px;border:1px solid #9daebe;border-radius:9px;font:inherit;padding:10px 12px}input:focus{outline:3px solid #9ed0fa;border-color:#1769aa}button{width:100%;min-height:48px;border:0;border-radius:9px;background:#0868ad;color:#fff;font:700 1rem inherit;padding:11px 14px;cursor:pointer;margin-top:8px}.secondary{background:#e9f2fa;color:#075990;border:1px solid #b9d4e9}.danger{color:#9b2630;background:#fff0f0;border:1px solid #edbec2}.secret-box{word-break:break-all;padding:12px;border-radius:8px;background:#f0f7fd;border:1px dashed #84b9dd;font:.85rem/1.5 ui-monospace,monospace}.codes{list-style:none;display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0}.codes li{font:700 .78rem ui-monospace,monospace;background:#f2f6fa;border-radius:7px;padding:10px 6px;text-align:center}.status{display:inline-block;border-radius:999px;background:#e3f6e9;color:#176b35;font-size:.72rem;font-weight:800;padding:5px 9px;margin-bottom:12px}.actions{display:grid;gap:8px}.logs-wrap{margin-top:22px;background:#10263d;color:#dcefff;border:0}.logs-wrap h2{color:#fff;font-size:1rem}.logs-wrap p{color:#a9c1d7;font-size:.8rem;margin:6px 0 10px}pre{margin:0;white-space:pre-wrap;word-break:break-word;color:#9ee1b2;font:.77rem/1.5 ui-monospace,monospace}@media(max-width:360px){.shell{padding-left:12px;padding-right:12px}.card{padding:17px}.codes{grid-template-columns:1fr}}
</style>
</body>
</html>`;

const server = Bun.serve({
  port: Number(Bun.env.PORT || 3000),
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem")
  },
  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: securityHeaders(request) });
      if (url.pathname === "/" && request.method === "GET") return html(request);
      if (!url.pathname.startsWith("/api/")) return genericFailure(request, 404);

      if (url.pathname === "/api/status" && request.method === "GET") {
        const session = requireSession(request);
        return isResponse(session) ? session : json(request, sessionPayload(session));
      }
      if (url.pathname === "/api/signin" && request.method === "POST") return await signIn(request);
      if (url.pathname === "/api/identity" && request.method === "POST") return await verifyIdentity(request);
      if (url.pathname === "/api/mfa/provision" && request.method === "POST") return await provision(request);
      if (url.pathname === "/api/mfa/confirm" && request.method === "POST") return await confirmAuthenticator(request);
      if (url.pathname === "/api/mfa/regenerate" && request.method === "POST") return await regenerateRecovery(request);
      if (url.pathname === "/api/mfa/recover" && request.method === "POST") return await verifyRecovery(request);
      if (url.pathname === "/api/mfa/acknowledge" && request.method === "POST") return await acknowledgeRecovery(request);
      if (url.pathname === "/api/logout" && request.method === "POST") return await logout(request);
      return genericFailure(request, 404);
    } catch {
      return genericFailure(request, 500);
    }
  }
});

console.log("MFA enrolment HTTPS server running on " + server.url);
