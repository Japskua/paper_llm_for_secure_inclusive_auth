
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const users = new Map<string, User>();
const sessions = new Map<string, Session>();
const PORT = Number(Bun.env.PORT ?? 3000);

const masterKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const masterKey = await crypto.subtle.importKey("raw", masterKeyBytes, "AES-GCM", false, [
  "encrypt",
  "decrypt",
]);
const recoveryPepper = randomToken(32);

// Deterministic mock identity credentials. Authentication succeeds only for this configured account.
const MARCUS_EMAIL = "marcus@example.test";
const MARCUS_PHONE = "+1 555 123 4567";
// Defined mock trusted recovery/reset proof. It is only used by the explicit reset process.
const TRUSTED_RESET_PROOF = "MARCUS-TRUSTED-RESET";

type Session = {
  accountId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
};

type EncryptedSecret = {
  iv: string;
  ciphertext: string;
};

type User = {
  id: string;
  email: string;
  mfaActive: boolean;
  encryptedSecret?: EncryptedSecret;
  recoveryHashes: string[];
  verification?: {
    used: boolean;
    verified: boolean;
  };
  // Requirement 5: account-level failures survive new challenges and provisioning requests.
  mfaVerificationFailures: number;
  mfaVerificationLockedUntil: number;
  recoveryFailures: number;
  recoveryLocked: boolean;
};

users.set("acct_marcus", {
  id: "acct_marcus",
  email: MARCUS_EMAIL,
  mfaActive: false,
  recoveryHashes: [],
  mfaVerificationFailures: 0,
  mfaVerificationLockedUntil: 0,
  recoveryFailures: 0,
  recoveryLocked: false,
});

const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const TOTP_STEP_MS = 30 * 1000;
const MFA_FAILURE_LIMIT = 5;
const MFA_LOCKOUT_MS = 15 * 60 * 1000;

// Requirement 2: trusted cross-origin TLS origins contain the configured HTTPS port.
const TRUSTED_ORIGINS = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function randomBase32(length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (byte) => alphabet[byte % alphabet.length]).join("");
}

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function fromB64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function base32Bytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of value) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("invalid base32");
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return new Uint8Array(bytes);
}

// Requirement 3: AES-GCM protects the provisioned shared secret while held in memory.
async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    masterKey,
    encoder.encode(secret),
  );
  return { iv: b64(iv), ciphertext: b64(new Uint8Array(ciphertext)) };
}

async function decryptSecret(stored: EncryptedSecret): Promise<string> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(stored.iv) },
    masterKey,
    fromB64(stored.ciphertext),
  );
  return decoder.decode(plaintext);
}

// Requirement 5: deterministic mock TOTP generated from the encrypted provisioned secret.
async function totpForSecret(secret: string, now = Date.now()): Promise<string> {
  const counter = Math.floor(now / TOTP_STEP_MS);
  const counterBytes = new Uint8Array(8);
  const view = new DataView(counterBytes.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);
  const key = await crypto.subtle.importKey(
    "raw",
    base32Bytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signed[signed.length - 1] & 0x0f;
  const numeric =
    ((signed[offset] & 0x7f) << 24) |
    (signed[offset + 1] << 16) |
    (signed[offset + 2] << 8) |
    signed[offset + 3];
  return String((numeric >>> 0) % 1_000_000).padStart(6, "0");
}

// Requirement 3: recovery codes are never retained in plaintext after their one-time response.
async function hashRecoveryCode(code: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(`${recoveryPepper}:${code}`),
  );
  return b64(new Uint8Array(digest));
}

function secureEqual(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  let difference = aa.length ^ bb.length;
  const max = Math.max(aa.length, bb.length);
  for (let i = 0; i < max; i++) difference |= (aa[i] ?? 0) ^ (bb[i] ?? 0);
  return difference === 0;
}

function baseHeaders(nonce = randomToken(16)): Headers {
  const headers = new Headers();
  headers.set(
    "Content-Security-Policy",
    `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'`,
  );
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cache-Control", "no-store");
  return headers;
}

// Requirement 2: same-origin requests are always accepted; CORS permits only configured TLS origins.
function applyCors(request: Request, headers: Headers): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;

  let requestOrigin = "";
  try {
    requestOrigin = new URL(request.url).origin;
  } catch {
    return false;
  }

  if (origin !== requestOrigin && !TRUSTED_ORIGINS.has(origin)) return false;

  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Vary", "Origin");
  headers.set("Access-Control-Allow-Credentials", "true");
  headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  return true;
}

function json(body: unknown, status = 200, headers = baseHeaders()): Response {
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(status = 400, headers = baseHeaders()): Response {
  return json({ ok: false, error: "Unable to process this request." }, status, headers);
}

function cookieValue(request: Request, name: string): string | undefined {
  const cookies = request.headers.get("cookie") ?? "";
  for (const piece of cookies.split(";")) {
    const [key, ...rest] = piece.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

function sessionCookie(token: string): string {
  return `mfa_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(
    SESSION_ABSOLUTE_MS / 1000,
  )}`;
}

function clearSessionCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

// Requirements 1 and 5: ownership is solely derived from an opaque server-side session.
function authorize(request: Request): { session: Session; user: User; token: string } | null {
  const url = new URL(request.url);
  for (const key of ["id", "uid", "userId", "accountId"]) {
    if (url.searchParams.has(key)) return null;
  }

  const token = cookieValue(request, "mfa_session");
  if (!token) return null;
  const session = sessions.get(token);
  const now = Date.now();
  if (!session || now > session.expiresAt || now - session.lastSeenAt > SESSION_IDLE_MS) {
    sessions.delete(token);
    return null;
  }
  const user = users.get(session.accountId);
  if (!user) return null;
  session.lastSeenAt = now;
  return { session, user, token };
}

function csrfValid(request: Request, session: Session): boolean {
  const value = request.headers.get("x-csrf-token") ?? "";
  return /^[A-Za-z0-9_-]{32,128}$/.test(value) && secureEqual(value, session.csrf);
}

async function bodyObject(request: Request): Promise<Record<string, unknown> | null> {
  if (!request.headers.get("content-type")?.includes("application/json")) return null;
  try {
    const value = await request.json();
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const object = value as Record<string, unknown>;
    if (["id", "uid", "userId", "accountId"].some((key) => key in object)) return null;
    return object;
  } catch {
    return null;
  }
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,22}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{12}$/.test(value);
}

function createRecoveryCodes(): string[] {
  return Array.from({ length: 10 }, () => randomBase32(12));
}

function allowedView(value: unknown): boolean {
  return typeof value === "string" && ["signin", "enrol", "provision", "confirm", "recovery"].includes(value);
}

function locked(user: User): boolean {
  return user.mfaVerificationLockedUntil > Date.now();
}

async function api(request: Request): Promise<Response> {
  const initialHeaders = baseHeaders();
  if (!applyCors(request, initialHeaders)) return genericError(403, initialHeaders);
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: initialHeaders });

  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/api/auth/signin" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !validEmail(body.email) || !validPhone(body.phone)) {
      return genericError(401, initialHeaders);
    }

    // Requirement 5: only the configured Marcus mock credentials authenticate; failures stay generic.
    const credentialsMatch =
      secureEqual(body.email, MARCUS_EMAIL) && secureEqual(body.phone, MARCUS_PHONE);
    if (!credentialsMatch) return genericError(401, initialHeaders);

    const user = users.get("acct_marcus")!;
    const oldToken = cookieValue(request, "mfa_session");
    if (oldToken) sessions.delete(oldToken);

    const token = randomToken(32);
    const now = Date.now();
    const session: Session = {
      accountId: user.id,
      csrf: randomToken(32),
      createdAt: now,
      lastSeenAt: now,
      expiresAt: now + SESSION_ABSOLUTE_MS,
    };
    sessions.set(token, session);
    initialHeaders.set("Set-Cookie", sessionCookie(token));
    return json(
      { ok: true, csrf: session.csrf, active: user.mfaActive, view: user.mfaActive ? "recovery" : "enrol" },
      200,
      initialHeaders,
    );
  }

  if (path === "/api/session" && request.method === "GET") {
    const auth = authorize(request);
    if (!auth) return genericError(401, initialHeaders);
    return json(
      { ok: true, csrf: auth.session.csrf, active: auth.user.mfaActive, view: auth.user.mfaActive ? "recovery" : "enrol" },
      200,
      initialHeaders,
    );
  }

  const auth = authorize(request);
  if (!auth) return genericError(401, initialHeaders);

  if (path === "/api/logout" && request.method === "POST") {
    if (!csrfValid(request, auth.session)) return genericError(403, initialHeaders);
    sessions.delete(auth.token);
    initialHeaders.set("Set-Cookie", clearSessionCookie());
    return json({ ok: true }, 200, initialHeaders);
  }

  // Requirement 5: only this explicit trusted reset process can clear an MFA verification lockout.
  if (path === "/api/mfa/trusted-reset" && request.method === "POST") {
    const body = await bodyObject(request);
    if (
      !body ||
      !csrfValid(request, auth.session) ||
      typeof body.proof !== "string" ||
      !secureEqual(body.proof, TRUSTED_RESET_PROOF)
    ) {
      return genericError(403, initialHeaders);
    }
    auth.user.mfaVerificationFailures = 0;
    auth.user.mfaVerificationLockedUntil = 0;
    auth.user.verification = undefined;
    auth.user.encryptedSecret = undefined;
    auth.user.mfaActive = false;
    auth.user.recoveryHashes = [];
    auth.user.recoveryFailures = 0;
    auth.user.recoveryLocked = false;
    return json({ ok: true, view: "enrol" }, 200, initialHeaders);
  }

  if (path === "/api/mfa/provision" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || (body.view !== undefined && !allowedView(body.view))) {
      return genericError(403, initialHeaders);
    }
    // A new secret never clears account-level failure count or lockout.
    if (locked(auth.user)) return genericError(423, initialHeaders);

    const secret = randomBase32(32);
    auth.user.encryptedSecret = await encryptSecret(secret);
    auth.user.verification = { used: false, verified: false };
    const testOtp = await totpForSecret(secret);
    const remaining = Math.max(1, Math.ceil((TOTP_STEP_MS - (Date.now() % TOTP_STEP_MS)) / 1000));

    return json({ ok: true, secret, testOtp, expiresInSeconds: remaining }, 200, initialHeaders);
  }

  if (path === "/api/mfa/verify" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || !validOtp(body.otp)) {
      return genericError(400, initialHeaders);
    }
    const verification = auth.user.verification;
    if (!verification || verification.used || locked(auth.user)) return genericError(403, initialHeaders);

    try {
      if (!auth.user.encryptedSecret) throw new Error("missing");
      const secret = await decryptSecret(auth.user.encryptedSecret);
      const expectedOtp = await totpForSecret(secret);
      // No universal bypass exists: only the current bounded TOTP-style value is accepted.
      if (!secureEqual(body.otp, expectedOtp)) {
        auth.user.mfaVerificationFailures += 1;
        if (auth.user.mfaVerificationFailures >= MFA_FAILURE_LIMIT) {
          auth.user.mfaVerificationLockedUntil = Date.now() + MFA_LOCKOUT_MS;
        }
        return genericError(403, initialHeaders);
      }
    } catch {
      return genericError(400, initialHeaders);
    }

    verification.used = true;
    verification.verified = true;
    auth.user.mfaVerificationFailures = 0;
    return json({ ok: true, verified: true }, 200, initialHeaders);
  }

  if (path === "/api/mfa/enable" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session)) return genericError(403, initialHeaders);
    if (!auth.user.verification?.verified || !auth.user.encryptedSecret || locked(auth.user)) {
      return genericError(403, initialHeaders);
    }

    const codes = createRecoveryCodes();
    auth.user.recoveryHashes = await Promise.all(codes.map(hashRecoveryCode));
    auth.user.recoveryFailures = 0;
    auth.user.recoveryLocked = false;
    auth.user.mfaActive = true;
    delete auth.user.verification;
    return json({ ok: true, codes }, 200, initialHeaders);
  }

  if (path === "/api/mfa/recovery/regenerate" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || !auth.user.mfaActive) return genericError(403, initialHeaders);

    const codes = createRecoveryCodes();
    auth.user.recoveryHashes = await Promise.all(codes.map(hashRecoveryCode));
    auth.user.recoveryFailures = 0;
    auth.user.recoveryLocked = false;
    return json({ ok: true, codes }, 200, initialHeaders);
  }

  if (path === "/api/mfa/recovery/verify" && request.method === "POST") {
    const body = await bodyObject(request);
    if (!body || !csrfValid(request, auth.session) || !validRecoveryCode(body.code) || !auth.user.mfaActive) {
      return genericError(400, initialHeaders);
    }
    if (auth.user.recoveryLocked) return genericError(403, initialHeaders);

    const hash = await hashRecoveryCode(body.code);
    const index = auth.user.recoveryHashes.findIndex((stored) => secureEqual(stored, hash));
    if (index < 0) {
      auth.user.recoveryFailures += 1;
      if (auth.user.recoveryFailures >= 5) auth.user.recoveryLocked = true;
      return genericError(403, initialHeaders);
    }

    auth.user.recoveryHashes.splice(index, 1);
    auth.user.recoveryFailures = 0;
    return json({ ok: true, remaining: auth.user.recoveryHashes.length }, 200, initialHeaders);
  }

  return genericError(404, initialHeaders);
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Northstar Bank — MFA enrolment</title>
  <style nonce="${nonce}">
    :root{color-scheme:light;--navy:#102a43;--blue:#1261a6;--pale:#edf6ff;--line:#cbd5df;--danger:#a61b1b;--ok:#116b43}
    *{box-sizing:border-box}body{margin:0;min-width:280px;background:#f2f5f8;color:#17212b;font:16px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    header{background:var(--navy);color:#fff;padding:1rem max(1rem,calc((100% - 620px)/2))}header p{margin:.1rem 0 0;color:#d7e8f8;font-size:.9rem}
    h1{font-size:1.2rem;margin:0}h2{font-size:1.35rem;line-height:1.2;margin:.2rem 0 .8rem}h3{margin-bottom:.3rem}
    main{width:min(100%,620px);margin:0 auto;padding:1rem}section,aside{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.1rem;margin-bottom:1rem;box-shadow:0 1px 2px #102a4310}
    label{display:block;font-weight:650;margin:.85rem 0 .25rem}input{width:100%;padding:.8rem;border:1px solid #8b9bab;border-radius:7px;font:inherit}
    button{appearance:none;border:0;border-radius:7px;background:var(--blue);color:#fff;font:inherit;font-weight:700;padding:.78rem 1rem;margin-top:1rem;width:100%;cursor:pointer}
    button.secondary{background:#e5edf4;color:#18324a}button:focus-visible,input:focus-visible{outline:3px solid #f7b955;outline-offset:2px}
    .notice{min-height:1.4rem;color:var(--danger);font-weight:600}.success{color:var(--ok)}.muted{color:#526374;font-size:.92rem}
    .code{font:700 1.05rem ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em;word-break:break-all;background:var(--pale);padding:.75rem;border-radius:7px}
    ul.codes{columns:2;padding-left:1.3rem}ul.codes li{font-family:ui-monospace,monospace;margin:.3rem 0}.logs{max-height:190px;overflow:auto;background:#0d1c29;color:#d9efff;border-radius:7px;padding:.7rem;font:12px/1.45 ui-monospace,monospace;white-space:pre-wrap}.warning{border-left:4px solid #df9720;padding-left:.8rem}
    @media(max-width:380px){ul.codes{columns:1}main{padding:.7rem}section,aside{padding:.9rem}}
  </style>
</head>
<body>
<header><h1>Northstar Bank</h1><p>Secure MFA enrolment</p></header>
<main>
  <div id="app" aria-live="polite">Loading secure session…</div>
  <aside aria-labelledby="log-title"><h2 id="log-title">Logs</h2><p class="muted">Simulated delivery and provisioning values appear here for academic testing.</p><div id="logs" class="logs">Ready.</div></aside>
</main>
<script nonce="${nonce}">
(() => {
  "use strict";
  let csrf="", screen="signin", shownCodes=[], currentSecret="";
  const app=document.getElementById("app"), logs=document.getElementById("logs");
  const allowedViews=new Set(["signin","enrol","provision","confirm","recovery"]);

  // Requirement 4: dynamic output is assigned through textContent, never HTML interpolation.
  function audit(text){console.log(text);const line=document.createElement("div");line.textContent=text;logs.appendChild(line);logs.scrollTop=logs.scrollHeight}
  function message(text,ok){const el=document.getElementById("notice");if(el){el.textContent=text||"";el.className=ok?"notice success":"notice"}}
  async function api(path,data){
    const options={method:data===undefined?"GET":"POST",headers:{}};
    if(data!==undefined){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;options.body=JSON.stringify(data)}
    try{const response=await fetch(path,options);const result=await response.json().catch(()=>({}));if(!response.ok||!result.ok)throw new Error("request");return result}
    catch{message("We could not complete that request. Please try again.");throw new Error("request")}
  }
  function setScreen(next){screen=allowedViews.has(next)?next:"signin";render()}
  function codesList(codes){const list=document.getElementById("codes");if(!list)return;list.textContent="";codes.forEach(code=>{const item=document.createElement("li");item.textContent=code;list.appendChild(item)})}

  function render(){
    if(screen==="signin"){
      app.innerHTML='<section aria-labelledby="signin-title"><h2 id="signin-title">Sign in and verify identity</h2><p>Enter your registered details to begin MFA enrolment.</p><form id="signin-form"><label for="email">Email address</label><input id="email" type="email" autocomplete="email" value="marcus@example.test" required><label for="phone">Mobile number</label><input id="phone" type="tel" autocomplete="tel" value="+1 555 123 4567" required><p id="notice" class="notice"></p><button type="submit">Verify and continue</button></form></section>';
      document.getElementById("signin-form").addEventListener("submit",signIn);
    } else if(screen==="enrol"){
      app.innerHTML='<section aria-labelledby="enrol-title"><h2 id="enrol-title">Set up your authenticator</h2><p>Use an authenticator app for payment approvals above your security threshold.</p><p class="warning muted">Keep your phone nearby. You will confirm a six-digit code in the next step.</p><p id="notice" class="notice"></p><button id="start">Set up authenticator app</button><button id="logout" class="secondary">Log out</button></section>';
      document.getElementById("start").onclick=provision;document.getElementById("logout").onclick=logout;
    } else if(screen==="provision"){
      app.innerHTML='<section aria-labelledby="provision-title"><h2 id="provision-title">Add this account to your app</h2><p>Choose manual entry in your authenticator app and enter this setup secret:</p><div id="secret" class="code" aria-label="Authenticator setup secret"></div><p class="muted">The current simulated, time-bound authenticator code and setup secret were sent to the visible Logs panel. Codes refresh every 30 seconds; there is no universal test code.</p><form id="otp-form"><label for="otp">Six-digit authenticator code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required><p id="notice" class="notice"></p><button type="submit">Confirm code</button></form><button id="logout" class="secondary">Log out</button></section>';
      document.getElementById("secret").textContent=currentSecret;document.getElementById("otp-form").addEventListener("submit",verifyOtp);document.getElementById("logout").onclick=logout;
    } else if(screen==="confirm"){
      app.innerHTML='<section aria-labelledby="confirm-title"><h2 id="confirm-title">Code confirmed</h2><p class="success">Your authenticator is verified.</p><p>Next, save recovery codes in a secure location. Each code can be used once.</p><p id="notice" class="notice"></p><button id="enable">Activate MFA and show recovery codes</button><button id="logout" class="secondary">Log out</button></section>';
      document.getElementById("enable").onclick=enable;document.getElementById("logout").onclick=logout;
    } else {
      app.innerHTML='<section aria-labelledby="recovery-title"><h2 id="recovery-title">MFA is active</h2><p class="success">Your authenticator is ready for secure payment approvals.</p><div><h3>Recovery codes</h3><p class="muted">Store these securely. They are shown only when generated in this demo.</p><ul id="codes" class="codes"></ul></div><p id="notice" class="notice"></p><button id="regenerate">Regenerate recovery codes</button><button id="logout" class="secondary">Log out</button></section><section aria-labelledby="test-title"><h2 id="test-title">Test a recovery code</h2><p class="muted">This consumes a valid code, demonstrating single-use server verification.</p><form id="recovery-form"><label for="recovery-code">Recovery code</label><input id="recovery-code" maxlength="12" autocomplete="off" placeholder="Example: ABCD2345EFGH"><button type="submit">Verify recovery code</button></form></section>';
      codesList(shownCodes);document.getElementById("regenerate").onclick=regenerate;document.getElementById("logout").onclick=logout;document.getElementById("recovery-form").addEventListener("submit",verifyRecovery);
    }
  }
  async function signIn(event){
    event.preventDefault();const email=document.getElementById("email").value.trim(),phone=document.getElementById("phone").value.trim();
    try{const result=await fetch("/api/auth/signin",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,phone})});const data=await result.json();if(!result.ok||!data.ok)throw new Error("bad");csrf=data.csrf;setScreen(data.view);audit("Simulated configured-identity verification completed in browser.")}catch{message("Unable to sign in. Check your details and try again.")}
  }
  async function provision(){
    try{const data=await api("/api/mfa/provision",{view:"provision"});currentSecret=data.secret;audit("Simulated authenticator provisioning — manual secret: "+data.secret);audit("Simulated current TOTP-style verification OTP: "+data.testOtp+" (expires in "+data.expiresInSeconds+" seconds)");setScreen("provision")}catch{}
  }
  async function verifyOtp(event){event.preventDefault();const otp=document.getElementById("otp").value.trim();try{await api("/api/mfa/verify",{otp});setScreen("confirm")}catch{}}
  async function enable(){try{const data=await api("/api/mfa/enable",{});shownCodes=data.codes;audit("Simulated recovery codes generated: "+data.codes.join(", "));setScreen("recovery")}catch{}}
  async function regenerate(){try{const data=await api("/api/mfa/recovery/regenerate",{});shownCodes=data.codes;audit("Simulated replacement recovery codes generated: "+data.codes.join(", "));render();message("Recovery codes have been replaced.",true)}catch{}}
  async function verifyRecovery(event){event.preventDefault();const code=document.getElementById("recovery-code").value.trim().toUpperCase();try{const data=await api("/api/mfa/recovery/verify",{code});message("Recovery code accepted and consumed. "+data.remaining+" remain.",true)}catch{}}
  async function logout(){try{await api("/api/logout",{})}catch{}csrf="";shownCodes=[];currentSecret="";audit("Session logged out and invalidated.");setScreen("signin")}
  window.addEventListener("hashchange",()=>{const requested=location.hash.slice(1);if(requested==="signin")setScreen("signin")});
  (async()=>{try{const data=await api("/api/session");csrf=data.csrf;setScreen(data.view)}catch{setScreen("signin")}})();
})();
</script>
</body>
</html>`;
}

const server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await api(request);
      if (request.method !== "GET" || url.pathname !== "/") {
        return new Response("Not found", { status: 404, headers: baseHeaders() });
      }
      const nonce = randomToken(16);
      const headers = baseHeaders(nonce);
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers });
    } catch {
      // Requirement 2: generic production failures never reveal stack traces.
      return new Response("Unable to process this request.", {
        status: 500,
        headers: baseHeaders(),
      });
    }
  },
});

console.log(`MFA enrolment demo listening securely on https://localhost:${server.port}`);
