
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/*
 Requirements 2 & 3: process-local cryptographic material. This demo deliberately
 uses no database, browser storage, external services, or server-side secret logs.
 */
const masterKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const recoveryPepper = bytesToBase64(crypto.getRandomValues(new Uint8Array(32)));

type ProtectedSecret = { iv: string; ciphertext: string };
type Provision = {
  secret: ProtectedSecret;
  createdAt: number;
  verified: boolean;
  usedSteps: Set<number>;
};
type FailureState = { count: number; lockUntil: number };
type User = {
  id: string;
  email: string;
  phone: string;
  identityVerified: boolean;
  mfaActive: boolean;
  provision?: Provision;
  backups: string[];
  authFailures: FailureState;
  recoveryFailures: FailureState;
  regenerationLastAt: number;
};
type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
};

const users = new Map<string, User>();
const sessions = new Map<string, Session>();
const ACCOUNT_OWNER_ID = "account-owner-marcus";
const DEMO_EMAIL = "marcus@example.test";
const DEMO_PASSWORD = "DemoPass123!";

users.set(ACCOUNT_OWNER_ID, {
  id: ACCOUNT_OWNER_ID,
  email: DEMO_EMAIL,
  phone: "",
  identityVerified: false,
  mfaActive: false,
  backups: [],
  authFailures: { count: 0, lockUntil: 0 },
  recoveryFailures: { count: 0, lockUntil: 0 },
  regenerationLastAt: 0,
});

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_STEP_MS = 30_000;
const LOCKOUT_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

/*
 Requirement update: these are the exact TLS origins served by this Bun instance.
 Any other Origin header is rejected rather than reflected.
 */
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

/* Separate alphabets: RFC 4648 Base32 is only for authenticator secrets. */
const PROVISIONING_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function bytesToBase64(bytes: Uint8Array): string {
  let value = "";
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}
function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
function randomToken(bytes = 32): string {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(bytes)))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function cookieValue(request: Request, name: string): string | undefined {
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
}
function sessionCookie(id: string, maxAge = Math.floor(SESSION_IDLE_MS / 1000)): string {
  /* Requirement 2/5: HttpOnly means browser JavaScript cannot read session IDs. */
  return `mfa_session=${id}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}
function standardHeaders(request: Request, contentType = "application/json"): Headers {
  /*
   Requirement 2: HTTPS-only response hardening, restricted CORS, CSP, and
   anti-clickjacking headers. Inline script/style are necessary in this single file.
   */
  const headers = new Headers({
    "Content-Type": contentType,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const origin = request.headers.get("origin");
  if (origin && TRUSTED_ORIGINS.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(request: Request, value: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = standardHeaders(request);
  if (extra) for (const [key, value] of new Headers(extra)) headers.set(key, value);
  return new Response(JSON.stringify(value), { status, headers });
}
function genericError(request: Request, status = 400): Response {
  /* Requirement 2: production errors are intentionally generic. */
  return json(request, { ok: false, message: "We could not complete that request. Please try again." }, status);
}
function parseJson(request: Request): Promise<Record<string, unknown> | null> {
  return request.json()
    .then((body) => body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null)
    .catch(() => null);
}
function invalidIdentifierAttempt(body: Record<string, unknown>): boolean {
  /* Requirement 1: account identity is never accepted from a client request. */
  return "userId" in body || "accountId" in body || "ownerId" in body;
}
function getSession(request: Request): Session | null {
  const id = cookieValue(request, "mfa_session");
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now > session.expiresAt || now - session.lastSeenAt > SESSION_IDLE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return session;
}
function authorized(request: Request): { session: Session; user: User } | null {
  /*
   Requirement 1: Every MFA API caller is mapped only from its authenticated
   server-side session. There is no client-supplied account identifier to authorize.
   */
  const session = getSession(request);
  if (!session) return null;
  const user = users.get(session.userId);
  if (!user) {
    sessions.delete(session.id);
    return null;
  }
  return { session, user };
}
function csrfValid(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  return supplied.length === session.csrf.length && timingSafe(supplied, session.csrf);
}
function timingSafe(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  let difference = aa.length ^ bb.length;
  const maximum = Math.max(aa.length, bb.length);
  for (let index = 0; index < maximum; index++) difference |= (aa[index] || 0) ^ (bb[index] || 0);
  return difference === 0;
}
async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return bytesToBase64(new Uint8Array(digest));
}
async function encryptSecret(secret: string): Promise<ProtectedSecret> {
  /* Requirement 3: the provisioning seed is encrypted while held in memory. */
  const key = await crypto.subtle.importKey("raw", masterKeyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}
async function decryptSecret(protectedValue: ProtectedSecret): Promise<string> {
  const key = await crypto.subtle.importKey("raw", masterKeyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(protectedValue.iv) },
    key,
    base64ToBytes(protectedValue.ciphertext),
  );
  return decoder.decode(plain);
}
function randomFromAlphabet(alphabet: string, count: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(count));
  let value = "";
  for (let index = 0; index < bytes.length; index++) value += alphabet[bytes[index] % alphabet.length];
  return value;
}
function randomProvisioningSecret(): string {
  /* Exactly 32 RFC 4648 Base32 characters, matching validSecret below. */
  return randomFromAlphabet(PROVISIONING_ALPHABET, 32);
}
function randomRecoveryCode(): string {
  const code = randomFromAlphabet(RECOVERY_ALPHABET, 10);
  return `${code.slice(0, 5)}-${code.slice(5)}`;
}
async function newBackupCodes(user: User): Promise<string[]> {
  const plain = Array.from({ length: 8 }, randomRecoveryCode);
  user.backups = await Promise.all(plain.map((code) => sha256(`${code}.${recoveryPepper}`)));
  return plain;
}
function base32ToBytes(value: string): Uint8Array {
  /*
   RFC 4648 Base32 decoding. Provisioning values are unpadded uppercase Base32,
   but optional trailing padding is handled defensively before validation.
   */
  const normalized = value.replaceAll("=", "");
  if (!/^[A-Z2-7]+$/.test(normalized)) throw new Error("Invalid Base32");
  let bits = 0;
  let bitCount = 0;
  const output: number[] = [];
  for (const character of normalized) {
    const index = PROVISIONING_ALPHABET.indexOf(character);
    if (index < 0) throw new Error("Invalid Base32");
    bits = (bits << 5) | index;
    bitCount += 5;
    while (bitCount >= 8) {
      bitCount -= 8;
      output.push((bits >>> bitCount) & 0xff);
    }
  }
  return new Uint8Array(output);
}
async function otpFor(secret: string, step: number): Promise<string> {
  /*
   Requirement 3/5: RFC 6238 TOTP using Base32-decoded secret bytes, the
   documented 30-second counter, an 8-byte big-endian time counter, HMAC-SHA-1,
   and RFC dynamic truncation.
   */
  const secretBytes = base32ToBytes(secret);
  const counter = new Uint8Array(8);
  let remaining = BigInt(step);
  for (let index = 7; index >= 0; index--) {
    counter[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) * 0x1000000) +
    (mac[offset + 1] * 0x10000) +
    (mac[offset + 2] * 0x100) +
    mac[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}
function failureBlocked(failure: FailureState): boolean {
  return Date.now() < failure.lockUntil;
}
function recordFailure(failure: FailureState): void {
  failure.count++;
  if (failure.count >= MAX_FAILURES) {
    failure.count = 0;
    failure.lockUntil = Date.now() + LOCKOUT_MS;
  }
}
function clearFailure(failure: FailureState): void {
  failure.count = 0;
  failure.lockUntil = 0;
}
function publicUser(user: User, session: Session) {
  return {
    authenticated: true,
    csrf: session.csrf,
    email: user.email,
    phone: user.phone,
    identityVerified: user.identityVerified,
    mfaActive: user.mfaActive,
    provisioningPending: !!user.provision && !user.provision.verified,
  };
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value);
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validSecret(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-7]{32}$/.test(value);
}
function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}$/.test(value);
}
function safeInternalPath(value: unknown): string {
  /* Requirement 4: explicit allow-list prevents open redirects. */
  const allowed = new Set(["#/sign-in", "#/identity", "#/provision", "#/verify", "#/confirm", "#/dashboard", "#/recovery"]);
  return typeof value === "string" && allowed.has(value) ? value : "#/dashboard";
}

async function handler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const origin = request.headers.get("origin");
    if (origin && !TRUSTED_ORIGINS.has(origin)) return genericError(request, 403);

    if (request.method === "OPTIONS") {
      const headers = standardHeaders(request);
      headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
      return new Response(null, { status: 204, headers });
    }

    if (request.method === "GET" && url.pathname === "/") {
      return new Response(pageHtml, { headers: standardHeaders(request, "text/html; charset=utf-8") });
    }
    if (request.method === "GET" && url.pathname === "/api/me") {
      const auth = authorized(request);
      if (!auth) return json(request, { authenticated: false }, 401);
      return json(request, publicUser(auth.user, auth.session));
    }

    if (request.method === "POST" && url.pathname === "/api/login") {
      const body = await parseJson(request);
      /*
       Requirement 5: deterministic demo credentials only. Every bad email/password
       combination receives the same generic authentication failure response.
       */
      const suppliedEmail = typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";
      const suppliedPassword = typeof body?.password === "string" ? body.password : "";
      const credentialsValid =
        !!body &&
        !invalidIdentifierAttempt(body) &&
        validEmail(suppliedEmail) &&
        suppliedPassword.length >= 8 &&
        suppliedPassword.length <= 128 &&
        timingSafe(suppliedEmail, DEMO_EMAIL) &&
        timingSafe(suppliedPassword, DEMO_PASSWORD);

      if (!credentialsValid) return genericError(request, 401);

      /* Successful authentication rotates any prior session to prevent fixation. */
      const old = cookieValue(request, "mfa_session");
      if (old) sessions.delete(old);
      const id = randomToken(32);
      const now = Date.now();
      const session: Session = {
        id,
        userId: ACCOUNT_OWNER_ID,
        csrf: randomToken(32),
        createdAt: now,
        lastSeenAt: now,
        expiresAt: now + SESSION_ABSOLUTE_MS,
      };
      sessions.set(id, session);
      return json(request, publicUser(users.get(ACCOUNT_OWNER_ID)!, session), 200, { "Set-Cookie": sessionCookie(id) });
    }

    if (request.method === "POST" && url.pathname === "/api/logout") {
      const auth = authorized(request);
      if (!auth || !csrfValid(request, auth.session)) return genericError(request, 403);
      sessions.delete(auth.session.id);
      return json(request, { ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
    }

    const auth = authorized(request);
    if (!auth) return genericError(request, 401);
    if (request.method !== "GET" && !csrfValid(request, auth.session)) return genericError(request, 403);

    if (request.method === "POST" && url.pathname === "/api/identity") {
      const body = await parseJson(request);
      if (!body || invalidIdentifierAttempt(body) || !validEmail(body.email) || !validPhone(body.phone)) return genericError(request);
      /* Requirement 4: validated scalar input only; no HTML is server-rendered from it. */
      auth.user.email = body.email.trim().toLowerCase();
      auth.user.phone = body.phone.trim();
      auth.user.identityVerified = true;
      return json(request, { ok: true, next: safeInternalPath(body.next) });
    }

    if (request.method === "POST" && url.pathname === "/api/provision") {
      const body = await parseJson(request);
      if (!body || invalidIdentifierAttempt(body) || !auth.user.identityVerified || auth.user.mfaActive) return genericError(request, 400);
      const secret = randomProvisioningSecret();
      auth.user.provision = { secret: await encryptSecret(secret), createdAt: Date.now(), verified: false, usedSteps: new Set() };
      const testOtp = await otpFor(secret, Math.floor(Date.now() / OTP_STEP_MS));
      /* No server console logging: browser receives this deliberately test-only mock delivery. */
      return json(request, { ok: true, manualSecret: secret, testOtp, expiresInSeconds: 30 });
    }

    if (request.method === "POST" && url.pathname === "/api/verify-authenticator") {
      const body = await parseJson(request);
      if (!body || invalidIdentifierAttempt(body) || !validOtp(body.otp) || !validSecret(body.manualSecret)) return genericError(request);
      const provision = auth.user.provision;
      if (!provision || provision.verified || failureBlocked(auth.user.authFailures)) return genericError(request, 429);
      if (Date.now() - provision.createdAt > 15 * 60 * 1000) return genericError(request, 400);

      const secret = await decryptSecret(provision.secret);
      const step = Math.floor(Date.now() / OTP_STEP_MS);
      const expected = await otpFor(secret, step);
      const secretMatches = timingSafe(body.manualSecret, secret);

      if (!secretMatches || !timingSafe(body.otp, expected) || provision.usedSteps.has(step)) {
        recordFailure(auth.user.authFailures);
        return genericError(request, 400);
      }

      provision.usedSteps.add(step);
      provision.verified = true;
      auth.user.mfaActive = true;
      clearFailure(auth.user.authFailures);
      const codes = await newBackupCodes(auth.user);
      return json(request, { ok: true, recoveryCodes: codes });
    }

    if (request.method === "POST" && url.pathname === "/api/verify-recovery") {
      const body = await parseJson(request);
      if (!body || invalidIdentifierAttempt(body) || !validRecovery(body.code) || !auth.user.mfaActive ||
          failureBlocked(auth.user.recoveryFailures)) return genericError(request, 400);
      const hash = await sha256(`${body.code}.${recoveryPepper}`);
      const found = auth.user.backups.findIndex((stored) => timingSafe(stored, hash));
      if (found < 0) {
        recordFailure(auth.user.recoveryFailures);
        return genericError(request, 400);
      }
      auth.user.backups.splice(found, 1);
      clearFailure(auth.user.recoveryFailures);
      return json(request, { ok: true, message: "Recovery code accepted. It cannot be used again." });
    }

    if (request.method === "POST" && url.pathname === "/api/regenerate-backups") {
      const body = await parseJson(request);
      if (!body || invalidIdentifierAttempt(body) || !auth.user.mfaActive) return genericError(request, 400);
      if (Date.now() - auth.user.regenerationLastAt < 60_000) return genericError(request, 429);
      auth.user.regenerationLastAt = Date.now();
      const codes = await newBackupCodes(auth.user);
      return json(request, { ok: true, recoveryCodes: codes });
    }

    return genericError(request, 404);
  } catch {
    return genericError(request, 500);
  }
}

const pageHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Northstar Bank · MFA enrolment</title>
<style>
:root{color-scheme:light;--ink:#172238;--blue:#124ea5;--soft:#eef5ff;--line:#c5d0df;--good:#0b6b45;--warn:#8a5200;--danger:#a02626}
*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font:17px/1.55 Arial,Helvetica,sans-serif;letter-spacing:.015em}
header{background:#102a50;color:#fff;padding:18px max(18px,calc((100% - 680px)/2));display:flex;justify-content:space-between;gap:12px;align-items:center}
.brand{font-weight:800;font-size:1.13rem}.tag{font-size:.88rem;opacity:.9}main{max-width:680px;margin:auto;padding:22px 16px 42px}
.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:22px;box-shadow:0 2px 9px #1c365015;margin-bottom:16px}
h1{font-size:1.65rem;line-height:1.2;margin:0 0 12px}h2{font-size:1.18rem;margin:0 0 10px}p{margin:8px 0 14px}
label{display:block;font-weight:700;margin:17px 0 6px}input{width:100%;font:inherit;padding:13px;border:2px solid #aab9cc;border-radius:8px;background:#fff;color:var(--ink)}
input:focus{outline:3px solid #9cc5ff;border-color:var(--blue)}button,.button{display:inline-block;border:0;border-radius:8px;padding:12px 16px;font:700 1rem Arial,sans-serif;cursor:pointer;text-decoration:none;margin:8px 8px 0 0}
button,.primary{background:var(--blue);color:#fff}.secondary{background:#e4ebf4;color:#172238}.danger{background:#8e2424;color:#fff}
.notice{padding:13px;border-left:5px solid var(--blue);background:var(--soft);border-radius:4px;margin:14px 0}.success{border-color:var(--good);background:#eaf8f0}.warning{border-color:var(--warn);background:#fff5df}
.error{border-color:var(--danger);background:#fff0f0}.small{font-size:.9rem}.code-list{padding-left:24px;font-family:ui-monospace,monospace;font-size:1.05rem;font-weight:bold;line-height:1.9}
.steps{font-size:.92rem;color:#3d4b5d}.logs{background:#101c2d;color:#e5f0ff;border-radius:10px;padding:14px;max-height:220px;overflow:auto;font:13px/1.45 ui-monospace,monospace;white-space:pre-wrap}
.hidden{display:none}@media(max-width:430px){body{font-size:16px}.card{padding:18px;border-radius:10px}header{padding:15px 16px}.tag{display:none}button,.button{width:100%;text-align:center;margin-right:0}}
</style>
</head>
<body>
<header><div class="brand">Northstar Bank</div><div class="tag">Secure MFA enrolment</div></header>
<main>
<div class="steps" id="steps">Sign in → Identity → Authenticator → Recovery codes</div>
<section id="app" aria-live="polite"><div class="card">Loading secure enrolment…</div></section>
<section class="card" aria-label="Mock delivery logs"><h2>Logs</h2><p class="small">Test-only browser mock delivery log. Do not use these values in a real banking service.</p><div class="logs" id="logs">Ready.</div></section>
</main>
<script>
/* Single-file/mobile/mock-delivery client. No localStorage, sessionStorage, or cookies are read here. */
const app=document.getElementById("app"),logs=document.getElementById("logs");
let state={me:null,csrf:"",codes:[],provision:null};

function mockLog(message){console.log("[MFA mock]",message);logs.textContent+="\\n"+message;logs.scrollTop=logs.scrollHeight}
function errorBox(message){const box=document.createElement("div");box.className="notice error";box.textContent=message;return box}
async function api(path,body){
 const headers={"Content-Type":"application/json"};
 if(state.csrf)headers["X-CSRF-Token"]=state.csrf;
 let response;
 try{response=await fetch(path,{method:"POST",credentials:"same-origin",headers,body:JSON.stringify(body||{})})}
 catch(e){throw new Error("Connection problem. Please try again.")}
 const data=await response.json().catch(()=>({}));
 if(!response.ok)throw new Error(data.message||"We could not complete that request. Please try again.");
 return data;
}
async function refresh(){
 const response=await fetch("/api/me",{credentials:"same-origin"});
 if(response.ok){state.me=await response.json();state.csrf=state.me.csrf}
 else{state.me=null;state.csrf=""}
}
function shell(title,content){app.innerHTML='<article class="card"><h1>'+title+'</h1>'+content+'</article>'}
function go(path){
 if(location.hash!==path)location.hash=path;
 else route();
}

/*
 Client route guards mirror enrolment state for a clear mobile flow. Server-side
 authorization still remains the security boundary for every API operation.
 */
function route(){
 const hash=location.hash||"#/sign-in";

 if(!state.me){
  if(hash!=="#/sign-in"){go("#/sign-in");return}
  renderSignIn();
  return;
 }

 if(!state.me.identityVerified){
  if(hash!=="#/identity"){go("#/identity");return}
  renderIdentity();
  return;
 }

 if(!state.me.mfaActive){
  if(hash==="#/verify"&&state.provision){renderVerify();return}
  if(hash!=="#/provision"){go("#/provision");return}
  renderProvision();
  return;
 }

 if(hash==="#/confirm"&&state.codes.length){renderConfirm();return}
 if(hash==="#/recovery"){renderRecovery();return}
 if(hash!=="#/dashboard"){go("#/dashboard");return}
 renderDashboard();
}

function renderSignIn(){
 shell("Sign in to begin",'<p>Use your bank sign-in details to start secure MFA enrolment.</p><form id="login"><label>Email address<input name="email" type="email" autocomplete="email" required value="marcus@example.test"></label><label>Password<input name="password" type="password" autocomplete="current-password" required minlength="8" value="DemoPass123!"></label><div id="message"></div><button>Sign in</button></form><p class="small">Academic demo credentials: marcus@example.test and DemoPass123!</p>');
 document.getElementById("login").onsubmit=async e=>{
  e.preventDefault();
  const f=new FormData(e.target),message=document.getElementById("message");
  try{
   const data=await api("/api/login",{email:f.get("email"),password:f.get("password")});
   state.me=data;state.csrf=data.csrf;
   go(data.identityVerified?(data.mfaActive?"#/dashboard":"#/provision"):"#/identity");
  }catch(err){message.replaceChildren(errorBox(err.message))}
 };
}
function renderIdentity(){
 shell("Confirm your identity",'<p>Check the contact details we will use for account security.</p><form id="identity"><label>Email address<input name="email" type="email" required></label><label>Mobile number<input name="phone" type="tel" inputmode="tel" placeholder="+44 7700 900000" required></label><div id="message"></div><button>Continue to authenticator setup</button></form>');
 const form=document.getElementById("identity");
 form.email.value=state.me.email;
 form.phone.value=state.me.phone||"";
 form.onsubmit=async e=>{
  e.preventDefault();
  const f=new FormData(form),m=document.getElementById("message");
  try{
   await api("/api/identity",{email:f.get("email"),phone:f.get("phone"),next:"#/provision"});
   await refresh();
   go("#/provision");
  }catch(err){m.replaceChildren(errorBox(err.message))}
 };
}
function renderProvision(){
 shell("Set up your authenticator",'<p>An authenticator app creates a six-digit code every 30 seconds. Start below, then copy the RFC 4648 Base32 secret into your app manually.</p><div id="provision-area"><button id="start">Create secure setup secret</button></div>');
 document.getElementById("start").onclick=async()=>{
  const area=document.getElementById("provision-area");
  try{
   const data=await api("/api/provision",{});
   state.provision=data;
   mockLog("Test-only authenticator secret delivered: "+data.manualSecret);
   mockLog("Test-only current authenticator code: "+data.testOtp);
   area.innerHTML='<div class="notice warning"><strong>Test-only setup secret</strong><br><code id="secret"></code><br><span class="small">Copy this into an authenticator app. It expires if not completed soon.</span></div><a class="button primary" href="#/verify">I have added the secret</a>';
   document.getElementById("secret").textContent=data.manualSecret;
  }catch(err){area.replaceChildren(errorBox(err.message))}
 };
}
function renderVerify(){
 shell("Verify your authenticator",'<p>Enter the setup secret manually and the current six-digit code from your authenticator app.</p><form id="verify"><label>Setup secret<input name="manualSecret" autocapitalize="characters" autocomplete="off" placeholder="32 character secret" required></label><label>Six-digit code<input name="otp" inputmode="numeric" pattern="[0-9]{6}" autocomplete="one-time-code" required></label><div id="message"></div><button>Verify and enable MFA</button><a class="button secondary" href="#/provision">Back</a></form>');
 document.getElementById("verify").onsubmit=async e=>{
  e.preventDefault();
  const f=new FormData(e.target),m=document.getElementById("message");
  try{
   const data=await api("/api/verify-authenticator",{manualSecret:String(f.get("manualSecret")).trim().toUpperCase(),otp:String(f.get("otp")).trim()});
   state.codes=data.recoveryCodes;
   state.provision=null;
   await refresh();
   mockLog("Test-only backup recovery codes: "+state.codes.join(", "));
   go("#/confirm");
  }catch(err){m.replaceChildren(errorBox(err.message))}
 };
}
function renderConfirm(){
 shell("Save your recovery codes",'<div class="notice success"><strong>MFA is enabled.</strong> Save these codes somewhere safe. Each code works once. They will not be shown again after you leave this screen.</div><ul class="code-list" id="codes"></ul><button id="saved">I saved these codes</button>');
 const list=document.getElementById("codes");
 state.codes.forEach(code=>{const li=document.createElement("li");li.textContent=code;list.appendChild(li)});
 document.getElementById("saved").onclick=()=>{state.codes=[];go("#/dashboard")};
}
function renderDashboard(){
 /* This view is only reachable through the mfaActive route guard. */
 shell("MFA security settings",'<div class="notice success"><strong>Authenticator MFA is active.</strong><br>Your account requires an authenticator code for protected actions.</div><p>Keep recovery codes private and use each only once.</p><button id="regen">Generate new recovery codes</button><a class="button secondary" href="#/recovery">Test a recovery code</a><button class="danger" id="logout">Sign out</button><div id="message"></div>');
 document.getElementById("regen").onclick=async()=>{
  const m=document.getElementById("message");
  try{
   const data=await api("/api/regenerate-backups",{});
   state.codes=data.recoveryCodes;
   mockLog("Test-only regenerated recovery codes: "+state.codes.join(", "));
   go("#/confirm");
  }catch(err){m.replaceChildren(errorBox(err.message))}
 };
 document.getElementById("logout").onclick=async()=>{
  try{
   await api("/api/logout",{});
   state.me=null;state.csrf="";state.codes=[];state.provision=null;
   go("#/sign-in");
  }catch(err){document.getElementById("message").replaceChildren(errorBox(err.message))}
 };
}
function renderRecovery(){
 shell("Use a recovery code",'<p>Enter one unused recovery code. It is permanently consumed after successful verification.</p><form id="recovery"><label>Recovery code<input name="code" autocapitalize="characters" autocomplete="off" placeholder="ABCDE-23456" required></label><div id="message"></div><button>Verify recovery code</button><a class="button secondary" href="#/dashboard">Back</a></form>');
 document.getElementById("recovery").onsubmit=async e=>{
  e.preventDefault();
  const f=new FormData(e.target),m=document.getElementById("message");
  try{
   const data=await api("/api/verify-recovery",{code:String(f.get("code")).trim().toUpperCase()});
   const good=document.createElement("div");
   good.className="notice success";
   good.textContent=data.message;
   m.replaceChildren(good);
  }catch(err){m.replaceChildren(errorBox(err.message))}
 };
}
window.addEventListener("hashchange",route);
(async()=>{try{await refresh()}catch(e){mockLog("Secure session check unavailable.")}route()})();
</script>
</body>
</html>`;

/*
 Requirements 2 and single-file constraint: Bun serves this one document over TLS.
 mkcert files are intentionally referenced directly and no external asset is loaded.
 */
Bun.serve({
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: handler,
});
