
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
type LoginCredentialDigests = {
  realEmail: string;
  dummyEmail: string;
  realPassword: string;
  dummyPassword: string;
};

const users = new Map<string, User>();
const sessions = new Map<string, Session>();

/*
 Task update: login failures are not stored against raw email addresses. The map
 key is a SHA-256 privacy-preserving identifier derived from normalized input.
 */
const loginFailures = new Map<string, FailureState>();

const ACCOUNT_OWNER_ID = "account-owner-marcus";
const DEMO_EMAIL = "marcus@example.test";
const DEMO_PASSWORD = "DemoPass123!";
const DUMMY_EMAIL = "unrecognised-login-account@example.invalid";
const DUMMY_PASSWORD = "FixedDummyCredentialForComparisonOnly!";

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_STEP_MS = 30_000;
const LOCKOUT_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const LOGIN_EMAIL_WIDTH = 254;
const LOGIN_PASSWORD_WIDTH = 128;

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

/* Requirement 2: only the TLS origins served by this Bun instance are trusted. */
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

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
  return `mfa_session=${id}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Strict`;
}
function standardHeaders(request: Request, contentType = "application/json"): Headers {
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
  return json(request, { ok: false, message: "We could not complete that request. Please try again." }, status);
}
/* Task update: every login failure class deliberately uses this same response. */
function genericLoginFailure(request: Request): Response {
  return json(request, { ok: false, message: "We could not complete that request. Please try again." }, 401);
}
function parseJson(request: Request): Promise<Record<string, unknown> | null> {
  return request.json()
    .then((body) => body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null)
    .catch(() => null);
}
function invalidIdentifierAttempt(body: Record<string, unknown>): boolean {
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
  const session = getSession(request);
  if (!session) return null;
  const user = users.get(session.userId);
  if (!user) {
    sessions.delete(session.id);
    return null;
  }
  return { session, user };
}
function timingSafe(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  let difference = aa.length ^ bb.length;
  const maximum = Math.max(aa.length, bb.length);
  for (let index = 0; index < maximum; index++) difference |= (aa[index] || 0) ^ (bb[index] || 0);
  return difference === 0;
}
/* Fixed-width values are always equal length before this comparison. */
function timingSafeFixed(a: string, b: string): boolean {
  const aa = encoder.encode(a);
  const bb = encoder.encode(b);
  let difference = 0;
  for (let index = 0; index < aa.length; index++) difference |= aa[index] ^ bb[index];
  return difference === 0;
}
function csrfValid(request: Request, session: Session): boolean {
  const supplied = request.headers.get("x-csrf-token") || "";
  return supplied.length === session.csrf.length && timingSafe(supplied, session.csrf);
}
async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return bytesToBase64(new Uint8Array(digest));
}

/*
 Task update: hash exactly fixed-length byte buffers for every credential input.
 This means malformed, unknown, overlong, short, and valid submissions traverse
 the same fixed-cost hashing and fixed-size comparison path.
 */
function fixedCredentialBytes(value: string, width: number): Uint8Array {
  const result = new Uint8Array(width);
  const source = encoder.encode(value);
  result.set(source.subarray(0, width));
  return result;
}
async function fixedCredentialDigest(value: string, width: number): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", fixedCredentialBytes(value, width));
  return bytesToBase64(new Uint8Array(digest));
}
const loginCredentialDigests: Promise<LoginCredentialDigests> = Promise.all([
  fixedCredentialDigest(DEMO_EMAIL, LOGIN_EMAIL_WIDTH),
  fixedCredentialDigest(DUMMY_EMAIL, LOGIN_EMAIL_WIDTH),
  fixedCredentialDigest(DEMO_PASSWORD, LOGIN_PASSWORD_WIDTH),
  fixedCredentialDigest(DUMMY_PASSWORD, LOGIN_PASSWORD_WIDTH),
]).then(([realEmail, dummyEmail, realPassword, dummyPassword]) => ({
  realEmail, dummyEmail, realPassword, dummyPassword,
}));

function normalizedLoginEmail(value: unknown): string {
  /* Bound raw input before it enters the privacy-state identifier. */
  return typeof value === "string" ? value.trim().toLowerCase().slice(0, LOGIN_EMAIL_WIDTH) : "";
}
async function loginFailureKey(normalizedEmail: string): Promise<string> {
  return sha256(`mfa-login-failure-v1:${normalizedEmail}`);
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
async function encryptSecret(secret: string): Promise<ProtectedSecret> {
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
  const normalized = value.replaceAll("=", "");
  if (!/^[A-Z2-7]+$/.test(normalized)) throw new Error("Invalid Base32");
  let bits = 0, bitCount = 0;
  const output: number[] = [];
  for (const character of normalized) {
    const index = PROVISIONING_ALPHABET.indexOf(character);
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
  const counter = new Uint8Array(8);
  let remaining = BigInt(step);
  for (let index = 7; index >= 0; index--) {
    counter[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", base32ToBytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[mac.length - 1] & 15;
  const binary = ((mac[offset] & 127) * 0x1000000) + (mac[offset + 1] * 0x10000) + (mac[offset + 2] * 0x100) + mac[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}
function publicUser(user: User, session: Session) {
  return {
    authenticated: true, csrf: session.csrf, email: user.email, phone: user.phone,
    identityVerified: user.identityVerified, mfaActive: user.mfaActive,
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
      return auth ? json(request, publicUser(auth.user, auth.session)) : json(request, { authenticated: false }, 401);
    }

    if (request.method === "POST" && url.pathname === "/api/login") {
      const body = await parseJson(request);
      const suppliedEmail = normalizedLoginEmail(body?.email);
      const suppliedPassword = typeof body?.password === "string" ? body.password : "";
      const failureKey = await loginFailureKey(suppliedEmail);
      const failure = loginFailures.get(failureKey) || { count: 0, lockUntil: 0 };

      /*
       Task update: all submissions first calculate both fixed-width input hashes.
       Both real and dummy credentials are then compared. The dummy password is
       selected for unrecognised accounts, avoiding a cheap unknown-user path.
       */
      const [inputEmail, inputPassword, expected] = await Promise.all([
        fixedCredentialDigest(suppliedEmail, LOGIN_EMAIL_WIDTH),
        fixedCredentialDigest(suppliedPassword, LOGIN_PASSWORD_WIDTH),
        loginCredentialDigests,
      ]);
      const emailMatchesReal = timingSafeFixed(inputEmail, expected.realEmail);
      const emailMatchesDummy = timingSafeFixed(inputEmail, expected.dummyEmail);
      const expectedPassword = emailMatchesReal ? expected.realPassword : expected.dummyPassword;
      const passwordMatchesExpected = timingSafeFixed(inputPassword, expectedPassword);

      const structurallyValid =
        !!body &&
        !invalidIdentifierAttempt(body) &&
        validEmail(suppliedEmail) &&
        suppliedPassword.length >= 8 &&
        suppliedPassword.length <= LOGIN_PASSWORD_WIDTH;
      const credentialsValid = structurallyValid && emailMatchesReal && passwordMatchesExpected && !emailMatchesDummy;

      /*
       Locked attempts preserve their existing state. Other failed attempts record
       one failure. Both return exactly the same 401 body as malformed/unknown
       and incorrect submissions, preventing account and lockout enumeration.
       */
      if (failureBlocked(failure) || !credentialsValid) {
        if (!failureBlocked(failure)) recordFailure(failure);
        loginFailures.set(failureKey, failure);
        return genericLoginFailure(request);
      }

      /* Successful authentication clears only the matching privacy-keyed state. */
      loginFailures.delete(failureKey);
      const old = cookieValue(request, "mfa_session");
      if (old) sessions.delete(old);
      const id = randomToken(32);
      const now = Date.now();
      const session: Session = {
        id, userId: ACCOUNT_OWNER_ID, csrf: randomToken(32),
        createdAt: now, lastSeenAt: now, expiresAt: now + SESSION_ABSOLUTE_MS,
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
      auth.user.email = body.email.trim().toLowerCase();
      auth.user.phone = body.phone.trim();
      auth.user.identityVerified = true;
      return json(request, { ok: true, next: safeInternalPath(body.next) });
    }
    if (request.method === "POST" && url.pathname === "/api/provision") {
      const body = await parseJson(request);
      if (!body || invalidIdentifierAttempt(body) || !auth.user.identityVerified || auth.user.mfaActive) return genericError(request);
      const secret = randomProvisioningSecret();
      auth.user.provision = { secret: await encryptSecret(secret), createdAt: Date.now(), verified: false, usedSteps: new Set() };
      return json(request, {
        ok: true, manualSecret: secret,
        testOtp: await otpFor(secret, Math.floor(Date.now() / OTP_STEP_MS)), expiresInSeconds: 30,
      });
    }
    if (request.method === "POST" && url.pathname === "/api/verify-authenticator") {
      const body = await parseJson(request);
      if (!body || invalidIdentifierAttempt(body) || !validOtp(body.otp) || !validSecret(body.manualSecret)) return genericError(request);
      const provision = auth.user.provision;
      if (!provision || provision.verified || failureBlocked(auth.user.authFailures)) return genericError(request, 429);
      if (Date.now() - provision.createdAt > 15 * 60 * 1000) return genericError(request);
      const secret = await decryptSecret(provision.secret);
      const step = Math.floor(Date.now() / OTP_STEP_MS);
      if (!timingSafe(body.manualSecret, secret) || !timingSafe(body.otp, await otpFor(secret, step)) || provision.usedSteps.has(step)) {
        recordFailure(auth.user.authFailures);
        return genericError(request);
      }
      provision.usedSteps.add(step);
      provision.verified = true;
      auth.user.mfaActive = true;
      clearFailure(auth.user.authFailures);
      return json(request, { ok: true, recoveryCodes: await newBackupCodes(auth.user) });
    }
    if (request.method === "POST" && url.pathname === "/api/verify-recovery") {
      const body = await parseJson(request);
      if (!body || invalidIdentifierAttempt(body) || !validRecovery(body.code) || !auth.user.mfaActive || failureBlocked(auth.user.recoveryFailures)) return genericError(request);
      const hash = await sha256(`${body.code}.${recoveryPepper}`);
      const found = auth.user.backups.findIndex((stored) => timingSafe(stored, hash));
      if (found < 0) {
        recordFailure(auth.user.recoveryFailures);
        return genericError(request);
      }
      auth.user.backups.splice(found, 1);
      clearFailure(auth.user.recoveryFailures);
      return json(request, { ok: true, message: "Recovery code accepted. It cannot be used again." });
    }
    if (request.method === "POST" && url.pathname === "/api/regenerate-backups") {
      const body = await parseJson(request);
      if (!body || invalidIdentifierAttempt(body) || !auth.user.mfaActive) return genericError(request);
      if (Date.now() - auth.user.regenerationLastAt < 60_000) return genericError(request, 429);
      auth.user.regenerationLastAt = Date.now();
      return json(request, { ok: true, recoveryCodes: await newBackupCodes(auth.user) });
    }
    return genericError(request, 404);
  } catch {
    return genericError(request, 500);
  }
}

const pageHtml = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · MFA enrolment</title><style>
:root{--ink:#172238;--blue:#124ea5;--line:#c5d0df;--good:#087043;--bad:#9a2020}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font:17px/1.5 Arial,sans-serif}header{background:#102a50;color:white;padding:18px max(16px,calc((100% - 680px)/2));font-weight:bold;font-size:1.15rem}main{max-width:680px;margin:auto;padding:20px 16px}.card{background:white;border:1px solid var(--line);border-radius:13px;padding:21px;margin-bottom:16px}h1{font-size:1.6rem;line-height:1.2;margin:0 0 12px}h2{font-size:1.15rem;margin:0 0 8px}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;padding:12px;border:2px solid #aab9cc;border-radius:8px;font:inherit}input:focus{outline:3px solid #a5cbff;border-color:var(--blue)}button,.button{display:inline-block;margin:12px 7px 0 0;padding:12px 15px;border:0;border-radius:8px;background:var(--blue);color:#fff;text-decoration:none;font:bold 1rem Arial;cursor:pointer}.secondary{background:#e4ebf4;color:var(--ink)}.danger{background:#8d2424}.notice{padding:12px;border-left:5px solid var(--blue);background:#eef5ff;margin:14px 0}.success{border-color:var(--good);background:#eaf8f0}.error{border-color:var(--bad);background:#fff0f0}.small,.steps{font-size:.9rem}.code-list{font:bold 1.04rem ui-monospace,monospace;line-height:1.85}.logs{background:#101c2d;color:#e5f0ff;padding:12px;border-radius:8px;max-height:180px;overflow:auto;white-space:pre-wrap;font:13px ui-monospace,monospace}@media(max-width:430px){body{font-size:16px}.card{padding:17px}button,.button{width:100%;text-align:center;margin-right:0}}
</style></head><body><header>Northstar Bank · Secure MFA enrolment</header><main>
<p class="steps">Sign in → Identity → Authenticator → Recovery codes</p><section id="app" aria-live="polite"></section>
<section class="card"><h2>Logs</h2><p class="small">Test-only browser mock delivery log.</p><div id="logs" class="logs">Ready.</div></section>
</main><script>
const app=document.getElementById("app"),logs=document.getElementById("logs");let state={me:null,csrf:"",codes:[],provision:null};
function mockLog(x){console.log("[MFA mock]",x);logs.textContent+="\\n"+x;logs.scrollTop=logs.scrollHeight}
function err(x){const d=document.createElement("div");d.className="notice error";d.textContent=x;return d}
function shell(t,c){app.innerHTML='<article class="card"><h1>'+t+'</h1>'+c+'</article>'}
async function api(path,body){const h={"Content-Type":"application/json"};if(state.csrf)h["X-CSRF-Token"]=state.csrf;let r;try{r=await fetch(path,{method:"POST",credentials:"same-origin",headers:h,body:JSON.stringify(body||{})})}catch{throw Error("Connection problem. Please try again.")}const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.message||"We could not complete that request. Please try again.");return d}
async function refresh(){const r=await fetch("/api/me",{credentials:"same-origin"});if(r.ok){state.me=await r.json();state.csrf=state.me.csrf}else{state.me=null;state.csrf=""}}
function go(p){if(location.hash!==p)location.hash=p;else route()}
function route(){const h=location.hash||"#/sign-in";if(!state.me){if(h!="#/sign-in")return go("#/sign-in");return signIn()}if(!state.me.identityVerified){if(h!="#/identity")return go("#/identity");return identity()}if(!state.me.mfaActive){if(h=="#/verify"&&state.provision)return verify();if(h!="#/provision")return go("#/provision");return provision()}if(h=="#/confirm"&&state.codes.length)return confirm();if(h=="#/recovery")return recovery();if(h!="#/dashboard")return go("#/dashboard");dashboard()}
function signIn(){shell("Sign in to begin",'<p>Use your bank sign-in details to start MFA enrolment.</p><form id="f"><label>Email address<input name="email" type="email" required value="marcus@example.test"></label><label>Password<input name="password" type="password" required value="DemoPass123!"></label><div id="m"></div><button>Sign in</button></form><p class="small">Academic demo: marcus@example.test / DemoPass123!</p>');f.onsubmit=async e=>{e.preventDefault();const x=new FormData(f);try{const d=await api("/api/login",{email:x.get("email"),password:x.get("password")});state.me=d;state.csrf=d.csrf;go(d.identityVerified?(d.mfaActive?"#/dashboard":"#/provision"):"#/identity")}catch(e){m.replaceChildren(err(e.message))}}}
function identity(){shell("Confirm your identity",'<form id="f"><label>Email address<input name="email" type="email" required></label><label>Mobile number<input name="phone" type="tel" required placeholder="+44 7700 900000"></label><div id="m"></div><button>Continue</button></form>');f.email.value=state.me.email;f.phone.value=state.me.phone||"";f.onsubmit=async e=>{e.preventDefault();const x=new FormData(f);try{await api("/api/identity",{email:x.get("email"),phone:x.get("phone"),next:"#/provision"});await refresh();go("#/provision")}catch(e){m.replaceChildren(err(e.message))}}}
function provision(){shell("Set up your authenticator",'<p>Create a test-only secret, then add it manually to your authenticator app.</p><div id="area"><button id="start">Create secure setup secret</button></div>');start.onclick=async()=>{try{const d=await api("/api/provision",{});state.provision=d;mockLog("Test-only authenticator secret delivered: "+d.manualSecret);mockLog("Test-only current authenticator code: "+d.testOtp);area.innerHTML='<div class="notice"><strong>Test-only setup secret</strong><br><code id="secret"></code></div><a class="button" href="#/verify">I have added the secret</a>';secret.textContent=d.manualSecret}catch(e){area.replaceChildren(err(e.message))}}}
function verify(){shell("Verify your authenticator",'<form id="f"><label>Setup secret<input name="secret" required></label><label>Six-digit code<input name="otp" inputmode="numeric" required></label><div id="m"></div><button>Verify and enable MFA</button><a class="button secondary" href="#/provision">Back</a></form>');f.onsubmit=async e=>{e.preventDefault();const x=new FormData(f);try{const d=await api("/api/verify-authenticator",{manualSecret:String(x.get("secret")).trim().toUpperCase(),otp:String(x.get("otp")).trim()});state.codes=d.recoveryCodes;state.provision=null;await refresh();mockLog("Test-only backup recovery codes: "+state.codes.join(", "));go("#/confirm")}catch(e){m.replaceChildren(err(e.message))}}}
function confirm(){shell("Save your recovery codes",'<div class="notice success"><strong>MFA is enabled.</strong> Save these one-time codes now.</div><ul id="list" class="code-list"></ul><button id="saved">I saved these codes</button>');state.codes.forEach(x=>{const l=document.createElement("li");l.textContent=x;list.appendChild(l)});saved.onclick=()=>{state.codes=[];go("#/dashboard")}}
function dashboard(){shell("MFA security settings",'<div class="notice success"><strong>Authenticator MFA is active.</strong></div><button id="regen">Generate new recovery codes</button><a class="button secondary" href="#/recovery">Test a recovery code</a><button class="danger" id="out">Sign out</button><div id="m"></div>');regen.onclick=async()=>{try{const d=await api("/api/regenerate-backups",{});state.codes=d.recoveryCodes;mockLog("Test-only regenerated recovery codes: "+state.codes.join(", "));go("#/confirm")}catch(e){m.replaceChildren(err(e.message))}};out.onclick=async()=>{try{await api("/api/logout",{});state.me=null;state.csrf="";state.codes=[];state.provision=null;go("#/sign-in")}catch(e){m.replaceChildren(err(e.message))}}}
function recovery(){shell("Use a recovery code",'<form id="f"><label>Recovery code<input name="code" required placeholder="ABCDE-23456"></label><div id="m"></div><button>Verify recovery code</button><a class="button secondary" href="#/dashboard">Back</a></form>');f.onsubmit=async e=>{e.preventDefault();try{const d=await api("/api/verify-recovery",{code:String(new FormData(f).get("code")).trim().toUpperCase()});const q=document.createElement("div");q.className="notice success";q.textContent=d.message;m.replaceChildren(q)}catch(e){m.replaceChildren(err(e.message))}}}
addEventListener("hashchange",route);(async()=>{try{await refresh()}catch{mockLog("Secure session check unavailable.")}route()})();
</script></body></html>`;

Bun.serve({
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: handler,
});
