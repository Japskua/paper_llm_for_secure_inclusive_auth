
const encoder = new TextEncoder();
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();
const masterKey = await crypto.subtle.importKey(
  "raw",
  crypto.getRandomValues(new Uint8Array(32)),
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"]
);

const PORT = 3000;
const IDLE_MS = 15 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const TEST_IDENTITY_CODE = "246810";
const TEST_AUTHENTICATOR_CODE = "135790";
const trustedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

accounts.set("marcus", {
  id: "marcus",
  email: "marcus@example.com",
  phone: "15551234567",
  mfa: null,
});

function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function base32(bytes: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let result = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += alphabet[(value << (5 - bits)) & 31];
  return result;
}

function safeEqual(a: string, b: string) {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  if (aa.length !== bb.length) return false;
  let difference = 0;
  for (let i = 0; i < aa.length; i++) difference |= aa[i] ^ bb[i];
  return difference === 0;
}

async function hashValue(value: string, salt = randomToken(16)) {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(`${salt}:${value}`));
  return `${salt}:${Buffer.from(bytes).toString("base64url")}`;
}

async function hashMatches(value: string, stored: string) {
  const split = stored.indexOf(":");
  if (split < 1) return false;
  const candidate = await hashValue(value, stored.slice(0, split));
  return safeEqual(candidate, stored);
}

/* Requirement 3: AES-GCM protects the temporary/shared MFA secret at rest. */
async function encryptSecret(secret: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    masterKey,
    encoder.encode(secret)
  );
  return {
    iv: Buffer.from(iv).toString("base64url"),
    ciphertext: Buffer.from(encrypted).toString("base64url"),
  };
}

async function decryptSecret(value: any) {
  const iv = Buffer.from(value.iv, "base64url");
  const ciphertext = Buffer.from(value.ciphertext, "base64url");
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv) },
    masterKey,
    ciphertext
  );
  return new TextDecoder().decode(decrypted);
}

function parseCookies(request: Request) {
  const parsed: Record<string, string> = {};
  const source = request.headers.get("cookie") || "";
  for (const entry of source.split(";")) {
    const i = entry.indexOf("=");
    if (i > 0) parsed[entry.slice(0, i).trim()] = entry.slice(i + 1).trim();
  }
  return parsed;
}

function cookie(value: string, maxAge = Math.floor(ABSOLUTE_MS / 1000)) {
  return `mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function securityHeaders(nonce: string, origin?: string | null) {
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  /* Requirement 2: CORS is emitted only for explicitly trusted local HTTPS origins. */
  if (origin && trustedOrigins.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}

function json(request: Request, data: any, status = 200, extra?: Record<string, string>) {
  const headers = securityHeaders(randomToken(16), request.headers.get("origin"));
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) for (const [key, value] of Object.entries(extra)) headers.set(key, value);
  return new Response(JSON.stringify(data), { status, headers });
}

function genericError(request: Request, status = 400) {
  return json(request, { ok: false, message: "The request could not be completed." }, status);
}

function page(request: Request) {
  const nonce = randomToken(16);
  const headers = securityHeaders(nonce, request.headers.get("origin"));
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(html(nonce), { headers });
}

function requestOriginAllowed(request: Request) {
  const origin = request.headers.get("origin");
  return !!origin && trustedOrigins.has(origin);
}

function sessionFrom(request: Request) {
  const id = parseCookies(request).mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  /* Requirement 5: idle and absolute server-side session expiry. */
  if (now - session.last > IDLE_MS || now - session.created > ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.last = now;
  return { id, session };
}

function authenticated(request: Request) {
  const found = sessionFrom(request);
  if (!found || found.session.phase !== "authenticated" || !found.session.userId) return null;
  const account = accounts.get(found.session.userId);
  if (!account) return null;
  return { ...found, account };
}

function createSession(phase: "pending" | "authenticated", userId?: string, candidate = false) {
  const id = randomToken();
  const now = Date.now();
  const session = {
    phase,
    userId,
    candidate,
    csrf: randomToken(),
    created: now,
    last: now,
    identity: phase === "pending" ? { expires: now + CHALLENGE_MS, used: false, failures: 0, lockUntil: 0 } : null,
    enrollment: null as any,
    mfaChallenge: null as any,
  };
  sessions.set(id, session);
  return { id, session };
}

/* Requirement 5: session ID is regenerated after successful identity authentication. */
function rotateAuthenticated(oldId: string, userId: string) {
  sessions.delete(oldId);
  return createSession("authenticated", userId, true);
}

/* Requirements 1 and 5: anti-CSRF plus trusted-Origin validation for every mutation. */
function csrfValid(request: Request, session: any) {
  return requestOriginAllowed(request) &&
    !!session &&
    typeof request.headers.get("x-csrf-token") === "string" &&
    safeEqual(request.headers.get("x-csrf-token")!, session.csrf);
}

async function body(request: Request) {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096) throw new Error("large");
  const value = await request.json();
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid");
  return value as Record<string, unknown>;
}

function isEmail(value: unknown) {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function isPhone(value: unknown) {
  return typeof value === "string" && /^\+?[0-9]{7,15}$/.test(value);
}
function isOtp(value: unknown) {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function isRecovery(value: unknown) {
  return typeof value === "string" && /^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$/.test(value);
}
function isSecret(value: unknown) {
  return typeof value === "string" && /^[A-Z2-7]{16,80}$/.test(value);
}
function allowedRedirect(value: unknown) {
  return value === undefined || value === "/" || value === "/mfa";
}
function hasForeignIdentity(value: Record<string, unknown>) {
  return "userId" in value || "accountId" in value || "ownerId" in value;
}

function locked(record: any) {
  return record.lockUntil && record.lockUntil > Date.now();
}
function failed(record: any) {
  record.failures = (record.failures || 0) + 1;
  if (record.failures >= 5) {
    record.lockUntil = Date.now() + LOCK_MS;
    record.failures = 0;
  }
}
function passed(record: any) {
  record.failures = 0;
  record.lockUntil = 0;
}

function newRecoveryCodes() {
  return Array.from({ length: 8 }, () => {
    const raw = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex").toUpperCase();
    return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
  });
}

async function storeRecoveryCodes(codes: string[]) {
  const stored = new Map<string, boolean>();
  for (const code of codes) stored.set(await hashValue(code), false);
  return stored;
}

async function useRecoveryCode(mfa: any, code: string) {
  if (locked(mfa.recoveryGuard)) return { ok: false, locked: true };
  for (const [hash, used] of mfa.recoveryCodes.entries()) {
    if (!used && await hashMatches(code, hash)) {
      mfa.recoveryCodes.set(hash, true);
      passed(mfa.recoveryGuard);
      return { ok: true };
    }
  }
  failed(mfa.recoveryGuard);
  return { ok: false, locked: locked(mfa.recoveryGuard) };
}

async function handleApi(request: Request, url: URL) {
  if (request.method === "OPTIONS") {
    if (!requestOriginAllowed(request)) return genericError(request, 403);
    const headers = securityHeaders(randomToken(16), request.headers.get("origin"));
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers });
  }

  if (url.pathname === "/api/session" && request.method === "GET") {
    const auth = authenticated(request);
    if (!auth) return json(request, { ok: true, signedIn: false });
    return json(request, {
      ok: true,
      signedIn: true,
      csrf: auth.session.csrf,
      mfaEnabled: !!auth.account.mfa?.enabled,
      setupInProgress: !!auth.session.enrollment,
    });
  }

  if (url.pathname === "/api/sign-in" && request.method === "POST") {
    if (!requestOriginAllowed(request)) return genericError(request, 403);
    const input = await body(request);
    if (!isEmail(input.email) || !isPhone(input.phone) || !allowedRedirect(input.redirect)) return genericError(request);
    const account = accounts.get("marcus");
    const candidate = safeEqual(String(input.email).toLowerCase(), account.email) && safeEqual(String(input.phone).replace("+", ""), account.phone);
    const pending = createSession("pending", undefined, candidate);
    /* Requirement 5: deliberately generic response prevents account enumeration. */
    return json(request, {
      ok: true,
      message: "If the details can be verified, continue with identity verification.",
      csrf: pending.session.csrf,
      testIdentityCode: TEST_IDENTITY_CODE,
    }, 200, { "Set-Cookie": cookie(pending.id, Math.floor(CHALLENGE_MS / 1000)) });
  }

  if (url.pathname === "/api/identity-verify" && request.method === "POST") {
    const found = sessionFrom(request);
    if (!found || found.session.phase !== "pending" || !csrfValid(request, found.session)) return genericError(request, 403);
    const input = await body(request);
    if (!isOtp(input.code) || hasForeignIdentity(input)) return genericError(request);
    const check = found.session.identity;
    if (locked(check)) return genericError(request, 429);
    const valid = !check.used && check.expires > Date.now() && found.session.candidate && safeEqual(String(input.code), TEST_IDENTITY_CODE);
    if (!valid) {
      failed(check);
      return genericError(request, locked(check) ? 429 : 400);
    }
    check.used = true;
    const auth = rotateAuthenticated(found.id, "marcus");
    return json(request, {
      ok: true,
      csrf: auth.session.csrf,
      mfaEnabled: !!accounts.get("marcus").mfa?.enabled,
    }, 200, { "Set-Cookie": cookie(auth.id) });
  }

  const auth = authenticated(request);
  /* Requirement 1: every MFA route derives owner identity only from authenticated session. */
  if (!auth) return genericError(request, 401);

  if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
    if (!csrfValid(request, auth.session)) return genericError(request, 403);
    const input = await body(request);
    if (hasForeignIdentity(input)) return genericError(request);
    const secret = base32(crypto.getRandomValues(new Uint8Array(20)));
    auth.session.enrollment = {
      encryptedSecret: await encryptSecret(secret),
      expires: Date.now() + CHALLENGE_MS,
      used: false,
      failures: 0,
      lockUntil: 0,
    };
    return json(request, {
      ok: true,
      secret,
      provisioningLabel: "Online Bank (Marcus)",
      testAuthenticatorCode: TEST_AUTHENTICATOR_CODE,
    });
  }

  if (url.pathname === "/api/mfa/confirm" && request.method === "POST") {
    if (!csrfValid(request, auth.session)) return genericError(request, 403);
    const input = await body(request);
    if (hasForeignIdentity(input) || !isOtp(input.otp) || !isSecret(input.manualSecret)) return genericError(request);
    const enrollment = auth.session.enrollment;
    if (!enrollment || locked(enrollment)) return genericError(request, locked(enrollment) ? 429 : 400);
    const secret = await decryptSecret(enrollment.encryptedSecret);
    const valid = !enrollment.used && enrollment.expires > Date.now() &&
      safeEqual(String(input.otp), TEST_AUTHENTICATOR_CODE) &&
      safeEqual(String(input.manualSecret), secret);
    if (!valid) {
      failed(enrollment);
      return genericError(request, locked(enrollment) ? 429 : 400);
    }
    enrollment.used = true;
    const codes = newRecoveryCodes();
    auth.account.mfa = {
      enabled: true,
      encryptedSecret: enrollment.encryptedSecret,
      recoveryCodes: await storeRecoveryCodes(codes),
      recoveryGuard: { failures: 0, lockUntil: 0 },
    };
    auth.session.enrollment = null;
    return json(request, { ok: true, recoveryCodes: codes });
  }

  if (url.pathname === "/api/mfa/challenge" && request.method === "POST") {
    if (!csrfValid(request, auth.session)) return genericError(request, 403);
    const input = await body(request);
    if (hasForeignIdentity(input) || (input.action !== "verify" && input.action !== "regenerate")) return genericError(request);
    if (!auth.account.mfa?.enabled) return genericError(request, 400);
    auth.session.mfaChallenge = {
      action: input.action,
      expires: Date.now() + CHALLENGE_MS,
      used: false,
      failures: 0,
      lockUntil: 0,
    };
    return json(request, { ok: true, testAuthenticatorCode: TEST_AUTHENTICATOR_CODE });
  }

  if (url.pathname === "/api/mfa/verify" && request.method === "POST") {
    if (!csrfValid(request, auth.session)) return genericError(request, 403);
    const input = await body(request);
    if (hasForeignIdentity(input) || !isOtp(input.otp)) return genericError(request);
    const challenge = auth.session.mfaChallenge;
    if (!challenge || challenge.action !== "verify" || locked(challenge)) return genericError(request, 400);
    const valid = !challenge.used && challenge.expires > Date.now() && safeEqual(String(input.otp), TEST_AUTHENTICATOR_CODE);
    if (!valid) {
      failed(challenge);
      return genericError(request, locked(challenge) ? 429 : 400);
    }
    challenge.used = true;
    passed(challenge);
    return json(request, { ok: true, message: "Authenticator verification succeeded." });
  }

  if (url.pathname === "/api/mfa/recovery-verify" && request.method === "POST") {
    if (!csrfValid(request, auth.session)) return genericError(request, 403);
    const input = await body(request);
    if (hasForeignIdentity(input) || !isRecovery(input.recoveryCode) || !auth.account.mfa?.enabled) return genericError(request);
    const result = await useRecoveryCode(auth.account.mfa, String(input.recoveryCode));
    if (!result.ok) return genericError(request, result.locked ? 429 : 400);
    return json(request, { ok: true, message: "Recovery code accepted and permanently consumed." });
  }

  if (url.pathname === "/api/mfa/regenerate" && request.method === "POST") {
    if (!csrfValid(request, auth.session)) return genericError(request, 403);
    const input = await body(request);
    if (hasForeignIdentity(input) || !auth.account.mfa?.enabled) return genericError(request, 400);
    let verified = false;
    if (typeof input.otp === "string" && isOtp(input.otp)) {
      const challenge = auth.session.mfaChallenge;
      if (challenge && challenge.action === "regenerate" && !locked(challenge)) {
        verified = !challenge.used && challenge.expires > Date.now() && safeEqual(input.otp, TEST_AUTHENTICATOR_CODE);
        if (verified) {
          challenge.used = true;
          passed(challenge);
        } else {
          failed(challenge);
          if (locked(challenge)) return genericError(request, 429);
        }
      }
    } else if (typeof input.recoveryCode === "string" && isRecovery(input.recoveryCode)) {
      const result = await useRecoveryCode(auth.account.mfa, input.recoveryCode);
      verified = result.ok;
      if (result.locked) return genericError(request, 429);
    } else {
      return genericError(request);
    }
    if (!verified) return genericError(request);
    const codes = newRecoveryCodes();
    /* Requirement 3: only hashes remain server-side; old code hashes are discarded. */
    auth.account.mfa.recoveryCodes = await storeRecoveryCodes(codes);
    return json(request, { ok: true, recoveryCodes: codes });
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    if (!csrfValid(request, auth.session)) return genericError(request, 403);
    sessions.delete(auth.id);
    return json(request, { ok: true }, 200, { "Set-Cookie": cookie("", 0) });
  }

  return genericError(request, 404);
}

function html(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Online Bank · MFA enrolment</title>
<style nonce="${nonce}">
:root{color-scheme:light;--ink:#10233b;--blue:#0759b7;--pale:#eef6ff;--line:#cfdae7;--danger:#a42323;--ok:#126a47}
*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font:16px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:#102f52;color:#fff;padding:18px 20px}header div,main,footer{max-width:560px;margin:auto}header strong{font-size:1.12rem}header small{display:block;opacity:.82}
main{padding:20px 16px 34px}.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px;margin-bottom:16px;box-shadow:0 2px 8px #10233b0d}
h1{font-size:1.5rem;line-height:1.2;margin:0 0 10px}h2{font-size:1.15rem;margin:0 0 8px}p{margin:8px 0 14px}.hint{background:var(--pale);border-left:4px solid var(--blue);padding:10px 12px;border-radius:4px;font-size:.92rem}
label{display:block;font-weight:650;margin:14px 0 5px}input{width:100%;padding:12px;border:1px solid #8496aa;border-radius:8px;font:inherit;background:#fff}input:focus{outline:3px solid #9cc8ff;border-color:var(--blue)}
button,.button{display:inline-block;width:100%;border:0;border-radius:8px;background:var(--blue);color:#fff;padding:12px 14px;font:inherit;font-weight:700;cursor:pointer;margin-top:17px;text-align:center}.secondary{background:#e7eef6;color:#173450}.danger{background:var(--danger)}button:disabled{opacity:.6;cursor:not-allowed}
a{color:#0759b7;font-weight:650}.message{min-height:24px;margin:12px 0 0;font-weight:600}.error{color:var(--danger)}.success{color:var(--ok)}
code,.secret{display:block;word-break:break-all;background:#f3f6f8;border:1px dashed #9aabba;padding:10px;border-radius:7px;font-size:.9rem}
ul.codes{list-style:none;padding:0;margin:12px 0;display:grid;grid-template-columns:1fr 1fr;gap:8px}ul.codes li{font-family:ui-monospace,SFMono-Regular,monospace;background:#f3f6f8;padding:8px;border-radius:6px;font-size:.78rem}
.logs{background:#091827;color:#d8ecff;border-radius:10px;padding:12px;max-height:180px;overflow:auto;font:12px/1.45 ui-monospace,SFMono-Regular,monospace;white-space:pre-wrap}.logs-title{display:flex;justify-content:space-between;align-items:center}.logs-title button{width:auto;margin:0;padding:5px 9px;background:#31516e;font-size:.8rem}
nav{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px;font-size:.9rem}footer{padding:0 16px 24px;color:#526273;font-size:.8rem}
@media(min-width:600px){main{padding-top:32px}} 
</style>
</head>
<body>
<header><div><strong>Online Bank</strong><small>Secure MFA enrolment</small></div></header>
<main id="app" aria-live="polite">Loading secure service…</main>
<footer>Use a private device when storing recovery codes.</footer>
<script nonce="${nonce}">
/* Requirement UI: mobile semantic SPA; sensitive values remain only in in-memory JS variables. */
(() => {
  const app = document.getElementById("app");
  let csrf = "";
  let sessionState = null;
  let provisioning = null;
  let visibleCodes = [];
  const logs = [];

  function log(message) {
    console.log(message);
    logs.push(message);
    const panel = document.getElementById("logs");
    if (panel) panel.textContent = logs.join("\\n");
  }
  function escText(node, text) { node.textContent = text; }
  function logsPanel() {
    return '<section class="card" aria-label="Simulation logs"><div class="logs-title"><h2>Logs</h2><button type="button" id="clearLogs">Clear</button></div><div id="logs" class="logs">No simulated values logged yet.</div></section>';
  }
  function bindLogs() {
    const clear = document.getElementById("clearLogs");
    if (clear) clear.onclick = () => { logs.length = 0; document.getElementById("logs").textContent = "No simulated values logged yet."; };
    const panel = document.getElementById("logs");
    if (panel && logs.length) panel.textContent = logs.join("\\n");
  }
  async function api(path, options = {}) {
    const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
    if (csrf) headers["X-CSRF-Token"] = csrf;
    const response = await fetch(path, Object.assign({ credentials: "same-origin", headers }, options));
    let data;
    try { data = await response.json(); } catch (_) { data = { ok:false, message:"The request could not be completed." }; }
    if (!response.ok || !data.ok) throw new Error(data.message || "The request could not be completed.");
    return data;
  }
  function message(text, good = false) {
    const element = document.getElementById("message");
    if (element) { element.className = "message " + (good ? "success" : "error"); escText(element, text); }
  }
  function common() { bindLogs(); }

  function signIn() {
    app.innerHTML = '<section class="card"><h1>Sign in to enrol MFA</h1><p>Verify your contact details before setting up your authenticator.</p><form id="signin"><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" required placeholder="marcus@example.com"><label for="phone">Mobile phone</label><input id="phone" name="phone" inputmode="tel" autocomplete="tel" required placeholder="15551234567"><button>Continue securely</button></form><div id="message" class="message"></div></section>' + logsPanel();
    common();
    document.getElementById("signin").onsubmit = async e => {
      e.preventDefault();
      const form = new FormData(e.target);
      try {
        const data = await api("/api/sign-in", { method:"POST", body:JSON.stringify({email:form.get("email"),phone:form.get("phone"),redirect:"/"}) });
        csrf = data.csrf;
        log("Simulated identity verification code: " + data.testIdentityCode);
        location.hash = "#identity";
      } catch (err) { message(err.message); }
    };
  }

  function identity() {
    app.innerHTML = '<section class="card"><h1>Verify your identity</h1><p>Enter the six-digit identity code. In this simulation, the test value is shown in Logs.</p><form id="identityForm"><label for="identityCode">Identity verification code</label><input id="identityCode" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required><button>Verify identity</button></form><div id="message" class="message"></div><nav><a href="#signin">Start over</a></nav></section>' + logsPanel();
    common();
    document.getElementById("identityForm").onsubmit = async e => {
      e.preventDefault();
      try {
        const data = await api("/api/identity-verify", { method:"POST", body:JSON.stringify({code:document.getElementById("identityCode").value}) });
        csrf = data.csrf; sessionState = { signedIn:true, mfaEnabled:data.mfaEnabled };
        location.hash = data.mfaEnabled ? "#settings" : "#setup";
      } catch (err) { message(err.message); }
    };
  }

  function setup() {
    app.innerHTML = '<section class="card"><h1>Set up an authenticator</h1><p>Use an authenticator app to add the secret below. You may enter it manually instead of scanning a code.</p><button id="provision">Create authenticator setup</button><div id="provisioning"></div><div id="message" class="message"></div></section>' + logsPanel();
    common();
    document.getElementById("provision").onclick = async () => {
      try {
        provisioning = await api("/api/mfa/provision", { method:"POST", body:"{}" });
        log("Simulated authenticator secret: " + provisioning.secret);
        log("Simulated authenticator test code: " + provisioning.testAuthenticatorCode);
        document.getElementById("provisioning").innerHTML = '<div class="hint"><strong>Provisioning information</strong><span class="secret" id="secretValue"></span><p>Account label: <strong id="labelValue"></strong></p></div><form id="confirmForm"><label for="manualSecret">Manual secret entry</label><input id="manualSecret" autocomplete="off" required placeholder="Enter the secret shown above"><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" maxlength="6" pattern="[0-9]{6}" required placeholder="6 digits"><button>Confirm authenticator</button></form>';
        escText(document.getElementById("secretValue"), provisioning.secret);
        escText(document.getElementById("labelValue"), provisioning.provisioningLabel);
        document.getElementById("confirmForm").onsubmit = confirmSetup;
      } catch (err) { message(err.message); }
    };
  }

  async function confirmSetup(e) {
    e.preventDefault();
    try {
      const data = await api("/api/mfa/confirm", { method:"POST", body:JSON.stringify({
        manualSecret:document.getElementById("manualSecret").value,
        otp:document.getElementById("otp").value
      }) });
      visibleCodes = data.recoveryCodes;
      log("New simulated recovery codes (displayed once): " + visibleCodes.join(", "));
      location.hash = "#backup";
    } catch (err) { message(err.message); }
  }

  function codesList(codes) {
    return '<ul class="codes">' + codes.map(() => '<li></li>').join("") + '</ul>';
  }
  function fillCodes() {
    document.querySelectorAll(".codes li").forEach((li, i) => escText(li, visibleCodes[i] || ""));
  }
  function backup() {
    app.innerHTML = '<section class="card"><h1>Store recovery codes</h1><p>Each recovery code works once. Store these in a secure offline location; they will not be shown again.</p>' + codesList(visibleCodes) + '<button id="done">I have stored these codes</button></section>' + logsPanel();
    fillCodes(); common();
    document.getElementById("done").onclick = () => { visibleCodes = []; location.hash = "#settings"; };
  }

  function settings() {
    app.innerHTML = '<section class="card"><h1>MFA settings</h1><p class="success">Authenticator MFA is enabled.</p><button id="startVerify">Test authenticator verification</button><button id="useRecovery" class="secondary">Use a recovery code</button><button id="regenerate" class="secondary">Regenerate recovery codes</button><button id="logout" class="danger">Log out</button><div id="action"></div><div id="message" class="message"></div></section>' + logsPanel();
    common();
    document.getElementById("startVerify").onclick = async () => {
      try {
        const data = await api("/api/mfa/challenge", {method:"POST",body:JSON.stringify({action:"verify"})});
        log("Simulated verification test code: " + data.testAuthenticatorCode);
        document.getElementById("action").innerHTML = '<form id="verifyForm"><label for="verifyOtp">Authenticator code</label><input id="verifyOtp" inputmode="numeric" maxlength="6" required><button>Verify</button></form>';
        document.getElementById("verifyForm").onsubmit = async e => { e.preventDefault(); try { const result=await api("/api/mfa/verify",{method:"POST",body:JSON.stringify({otp:document.getElementById("verifyOtp").value})}); message(result.message,true); } catch(err){message(err.message);} };
      } catch(err) { message(err.message); }
    };
    document.getElementById("useRecovery").onclick = () => {
      document.getElementById("action").innerHTML = '<form id="recoveryForm"><label for="recoveryCode">Recovery code</label><input id="recoveryCode" autocomplete="off" placeholder="ABCD-1234-EF56-7890" required><button>Use recovery code</button></form>';
      document.getElementById("recoveryForm").onsubmit = async e => { e.preventDefault(); try { const result=await api("/api/mfa/recovery-verify",{method:"POST",body:JSON.stringify({recoveryCode:document.getElementById("recoveryCode").value.toUpperCase()})}); message(result.message,true); } catch(err){message(err.message);} };
    };
    document.getElementById("regenerate").onclick = () => location.hash = "#regenerate";
    document.getElementById("logout").onclick = async () => {
      try { await api("/api/logout",{method:"POST",body:"{}"}); csrf=""; sessionState=null; provisioning=null; visibleCodes=[]; location.hash="#signin"; }
      catch(err) { message(err.message); }
    };
  }

  function regenerate() {
    app.innerHTML = '<section class="card"><h1>Regenerate recovery codes</h1><p>Regenerating permanently invalidates every previous recovery code. Confirm using an authenticator code or one current recovery code.</p><button id="getChallenge">Get simulated authenticator challenge</button><form id="regenForm"><label for="regenOtp">Authenticator code (optional)</label><input id="regenOtp" inputmode="numeric" maxlength="6"><label for="regenRecovery">Or a recovery code (optional)</label><input id="regenRecovery" autocomplete="off" placeholder="ABCD-1234-EF56-7890"><button>Regenerate securely</button></form><nav><a href="#settings">Back to settings</a></nav><div id="message" class="message"></div></section>' + logsPanel();
    common();
    document.getElementById("getChallenge").onclick = async () => {
      try { const data=await api("/api/mfa/challenge",{method:"POST",body:JSON.stringify({action:"regenerate"})}); log("Simulated regeneration test code: " + data.testAuthenticatorCode); message("Challenge ready. Enter the test code from Logs.",true); }
      catch(err){message(err.message);}
    };
    document.getElementById("regenForm").onsubmit = async e => {
      e.preventDefault();
      const otp = document.getElementById("regenOtp").value;
      const recoveryCode = document.getElementById("regenRecovery").value.toUpperCase();
      try {
        const data = await api("/api/mfa/regenerate",{method:"POST",body:JSON.stringify(otp ? {otp} : {recoveryCode})});
        visibleCodes=data.recoveryCodes;
        log("Regenerated simulated recovery codes (displayed once): " + visibleCodes.join(", "));
        location.hash="#backup";
      } catch(err){message(err.message);}
    };
  }

  async function route() {
    const wanted = location.hash.replace("#","") || "signin";
    if (wanted === "signin") return signIn();
    if (wanted === "identity") return identity();
    try {
      const state = await api("/api/session", {method:"GET"});
      sessionState = state;
      if (!state.signedIn) { location.hash="#signin"; return; }
      csrf = state.csrf;
      if (wanted === "setup") return state.mfaEnabled ? settings() : setup();
      if (wanted === "backup") return visibleCodes.length ? backup() : settings();
      if (wanted === "regenerate") return state.mfaEnabled ? regenerate() : setup();
      return state.mfaEnabled ? settings() : setup();
    } catch (_) { location.hash="#signin"; }
  }
  window.addEventListener("hashchange", route);
  route();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  hostname: "0.0.0.0",
  port: PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url);
      if (request.method !== "GET" && request.method !== "HEAD") return genericError(request, 405);
      return page(request);
    } catch (_) {
      /* Requirement 2: production-safe generic response without stack traces. */
      return genericError(request, 500);
    }
  },
});

console.log(`MFA enrolment service listening securely on https://localhost:${server.port}`);
