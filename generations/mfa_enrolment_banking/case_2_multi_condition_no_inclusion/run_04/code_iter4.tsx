
import { } from "bun";

// MFA Enrolment System: single-file Bun HTTPS server and mobile SPA.
// Security controls map to requirements 1–5.

const PORT = Number(Bun.env.PORT || 3000);
const SESSION_COOKIE = "__Host-mfa_session";
const IDLE_MS = 15 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const IDENTITY_CODE_MS = 3 * 60 * 1000;
const VERIFY_WINDOW_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const TOTP_STEP_MS = 30_000;

type State = "anonymous" | "identity" | "authenticated";
type RecoveryEntry = { salt: string; digest: string; used: boolean };
type Draft = {
  encryptedSecret: string;
  expiresAt: number;
  used: boolean;
  reserved: boolean;
  failedAttempts: number;
  lockedUntil: number;
};
type Session = {
  id: string;
  csrf: string;
  state: State;
  userId?: string;
  createdAt: number;
  lastSeenAt: number;
  identityCode?: string;
  identityCodeExpiresAt?: number;
  identityAttempts: number;
  identityLockedUntil: number;
  draft?: Draft;
  // Task: synchronous reservation prevents concurrent provisioning drafts.
  provisionReserved: boolean;
  encryptedMfaSecret?: string;
  recoveryCodes: RecoveryEntry[];
  recoveryAttempts: number;
  recoveryLockedUntil: number;
  // Task: per-session recovery-operation mutex across verify and regenerate.
  recoveryReserved: boolean;
};

const sessions = new Map<string, Session>();
const keyBytes = randomBytes(32);
const encryptionKeyPromise = crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
const trustedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

function randomBytes(length: number): Uint8Array {
  const result = new Uint8Array(length);
  crypto.getRandomValues(result);
  return result;
}
function token(length = 32): string { return Buffer.from(randomBytes(length)).toString("base64url"); }
function randomDigits(): string {
  return String(new DataView(randomBytes(4).buffer).getUint32(0) % 1_000_000).padStart(6, "0");
}
function base32Secret(length = 32): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(randomBytes(length), byte => alphabet[byte % alphabet.length]).join("");
}
function recoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = Array.from(randomBytes(10), byte => alphabet[byte % alphabet.length]).join("");
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}
async function sha256(value: string): Promise<string> {
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))).toString("base64url");
}
async function encryptAtRest(value: string): Promise<string> {
  const iv = randomBytes(12);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await encryptionKeyPromise, new TextEncoder().encode(value));
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(cipher).toString("base64url")}`;
}
async function decryptDraftSecret(value: string): Promise<string | null> {
  try {
    const [ivText, cipherText] = value.split(".");
    if (!ivText || !cipherText) return null;
    const iv = Buffer.from(ivText, "base64url");
    const cipher = Buffer.from(cipherText, "base64url");
    if (iv.length !== 12 || cipher.length < 17) return null;
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, await encryptionKeyPromise, cipher);
    return new TextDecoder().decode(plain);
  } catch { return null; }
}
function base32Decode(value: string): Uint8Array | null {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0, bits = 0;
  const out: number[] = [];
  for (const char of value) {
    const n = alphabet.indexOf(char);
    if (n < 0) return null;
    buffer = (buffer << 5) | n;
    bits += 5;
    while (bits >= 8) { bits -= 8; out.push((buffer >> bits) & 255); }
  }
  return out.length ? new Uint8Array(out) : null;
}
async function totpForStep(seed: string, step: number): Promise<string | null> {
  const secret = base32Decode(seed);
  if (!secret || step < 0 || !Number.isSafeInteger(step)) return null;
  const counter = new Uint8Array(8);
  const data = new DataView(counter.buffer);
  data.setUint32(0, Math.floor(step / 0x1_0000_0000), false);
  data.setUint32(4, step >>> 0, false);
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hash = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = hash[hash.length - 1] & 15;
  const number = (((hash[offset] & 127) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3]) % 1_000_000;
  return String(number).padStart(6, "0");
}
async function validTotp(seed: string, code: string, now: number): Promise<boolean> {
  const step = Math.floor(now / TOTP_STEP_MS);
  for (let i = -1; i <= 1; i++) {
    const expected = await totpForStep(seed, step + i);
    if (expected && sameValue(code, expected)) return true;
  }
  return false;
}
function sameValue(a: string, b: string): boolean {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  if (aa.length !== bb.length) return false;
  let different = 0;
  for (let i = 0; i < aa.length; i++) different |= aa[i] ^ bb[i];
  return different === 0;
}
function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const point = item.indexOf("=");
    if (point > 0) result[item.slice(0, point).trim()] = item.slice(point + 1).trim();
  }
  return result;
}
function sessionCookie(id: string): string {
  return `${SESSION_COOKIE}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE_MS / 1000}`;
}
function clearCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}
function createSession(state: State = "anonymous", userId?: string): Session {
  const now = Date.now();
  const session: Session = {
    id: token(), csrf: token(), state, userId, createdAt: now, lastSeenAt: now,
    identityAttempts: 0, identityLockedUntil: 0,
    provisionReserved: false,
    recoveryCodes: [], recoveryAttempts: 0, recoveryLockedUntil: 0, recoveryReserved: false,
  };
  sessions.set(session.id, session);
  return session;
}
function getSession(request: Request): Session | null {
  const id = parseCookies(request)[SESSION_COOKIE];
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeenAt > IDLE_MS || now - session.createdAt > ABSOLUTE_MS) {
    sessions.delete(session.id);
    return null;
  }
  session.lastSeenAt = now;
  return session;
}
function sessionStillCurrent(session: Session): boolean {
  return sessions.get(session.id) === session;
}
function rotateSession(old: Session, state: State, userId?: string): Session {
  sessions.delete(old.id);
  return createSession(state, userId);
}
function trustedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || trustedOrigins.has(origin);
}
function headers(request: Request, nonce: string): Headers {
  const result = new Headers();
  result.set("Content-Security-Policy", `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  result.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  result.set("X-Content-Type-Options", "nosniff");
  result.set("X-Frame-Options", "DENY");
  result.set("Referrer-Policy", "no-referrer");
  result.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  const origin = request.headers.get("origin");
  if (origin && trustedOrigins.has(origin)) {
    result.set("Access-Control-Allow-Origin", origin);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Vary", "Origin");
  }
  return result;
}
function reply(request: Request, nonce: string, data: unknown, status = 200, cookie?: string): Response {
  const result = headers(request, nonce);
  result.set("Content-Type", "application/json; charset=utf-8");
  result.set("Cache-Control", "no-store");
  if (cookie) result.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: result });
}
function error(request: Request, nonce: string, status = 400, cookie?: string): Response {
  return reply(request, nonce, { ok: false, message: "We could not complete that request. Please try again." }, status, cookie);
}
async function bodyObject(request: Request): Promise<Record<string, unknown> | null> {
  try {
    if (!(request.headers.get("content-type") || "").includes("application/json")) return null;
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
}
function text(value: unknown, maximum: number): string | null {
  return typeof value === "string" && value.length <= maximum ? value.trim() : null;
}
function email(value: unknown): string | null {
  const result = text(value, 254)?.toLowerCase() || "";
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(result) ? result : null;
}
function phone(value: unknown): string | null {
  const result = text(value, 40)?.replace(/[\s().-]/g, "") || "";
  return /^\+?[0-9]{8,15}$/.test(result) ? result : null;
}
function otp(value: unknown): string | null {
  const result = text(value, 12)?.replace(/\s/g, "") || "";
  return /^[0-9]{6}$/.test(result) ? result : null;
}
function secret(value: unknown): string | null {
  const result = text(value, 80)?.toUpperCase().replace(/\s/g, "") || "";
  return /^[A-Z2-7]{16,64}$/.test(result) ? result : null;
}
function recovery(value: unknown): string | null {
  const result = text(value, 20)?.toUpperCase().replace(/\s/g, "") || "";
  return /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(result) ? result : null;
}
function csrfOK(session: Session, body: Record<string, unknown>): boolean {
  return typeof body.csrf === "string" && sameValue(body.csrf, session.csrf);
}
function manipulated(body: Record<string, unknown>): boolean {
  return ["userId", "user_id", "accountId", "account_id", "ownerId"].some(key => key in body);
}
function authenticated(session: Session | null): session is Session {
  return !!session && session.state === "authenticated" && session.userId === "marcus-account-001";
}

// Requirement 3: recovery codes are generated with CSPRNG and only salted hashes persist.
async function generateRecoveryCodeSet(): Promise<{ codes: string[]; entries: RecoveryEntry[] }> {
  const codes: string[] = [];
  const entries: RecoveryEntry[] = [];
  for (let i = 0; i < 8; i++) {
    const code = recoveryCode();
    const salt = token(16);
    entries.push({ salt, digest: await sha256(`${salt}:${code}`), used: false });
    codes.push(code);
  }
  return { codes, entries };
}

const html = (nonce: string) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Northstar Bank · MFA enrolment</title>
<style nonce="${nonce}">
:root{--ink:#17233d;--blue:#135cc8;--soft:#f1f6ff;--line:#c7d4e8;--bad:#a31919;--ok:#09683b}*{box-sizing:border-box}body{margin:0;background:#eef3f9;color:var(--ink);font:18px/1.6 Arial,Verdana,sans-serif}main{max-width:620px;min-height:100vh;margin:auto;padding:18px 16px 38px;background:#fff}header{border-bottom:4px solid var(--blue);padding:4px 0 18px;margin-bottom:24px}.brand{font-weight:bold;color:var(--blue)}h1{font-size:1.55rem;line-height:1.3}h2{font-size:1.3rem;line-height:1.3}.card{background:var(--soft);border:1px solid var(--line);border-radius:12px;padding:16px;margin:16px 0}label{display:block;font-weight:bold;margin:16px 0 6px}input{width:100%;min-height:50px;border:2px solid #7184a1;border-radius:8px;font:inherit;padding:8px}button{min-height:50px;margin:12px 8px 0 0;border:0;border-radius:8px;padding:10px 16px;background:var(--blue);color:#fff;font:bold 1rem Arial;cursor:pointer}.secondary{background:#e2eaf5;color:var(--ink);border:1px solid #7184a1}.danger{background:#9f1d1d}.error{color:var(--bad);font-weight:bold;min-height:1.6em}.hint{font-size:.9rem}.success{border-left:6px solid var(--ok)}button:focus,input:focus{outline:4px solid #f0b429;outline-offset:2px}
</style></head><body><main>
<header><div class="brand">Northstar Bank</div><h1>Multi-factor authentication</h1></header>
<div id="view" aria-live="polite">Loading securely…</div>
</main><script nonce="${nonce}">
(()=>{"use strict";let csrf="",page="signin",provisioned=false;const view=document.getElementById("view");
function log(message){console.log("[MFA demo]",message)}
async function api(path,data,method="POST"){const o={method,credentials:"same-origin",headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.body=JSON.stringify(Object.assign({},data||{},{csrf}))}let r;try{r=await fetch(path,o)}catch{throw Error("Connection problem. Please try again.")}const j=await r.json().catch(()=>null);if(j&&j.csrf)csrf=j.csrf;if(!r.ok||!j||!j.ok)throw Error(j&&j.message||"We could not complete that request. Please try again.");return j}
function show(s){view.innerHTML=s}function err(s){const e=document.getElementById("error");if(e)e.textContent=s||""}
function render(){if(page==="signin"){show('<section><h2>Sign in to begin</h2><p>Set up an authenticator before approving higher-value payments.</p><form id="f"><label>Email address<input id="email" type="email" required></label><label>Mobile phone number<input id="phone" type="tel" required></label><div id="error" class="error" role="alert"></div><button>Continue</button></form></section>');document.getElementById("f").onsubmit=async e=>{e.preventDefault();try{const r=await api("/api/sign-in",{email:email.value,phone:phone.value});csrf=r.csrf;log("Identity check code delivered in this browser for testing: "+r.testIdentityCode);page="identity";render()}catch(x){err(x.message)}}}
else if(page==="identity"){show('<section><h2>Verify your identity</h2><p>Enter the six-digit code sent to you.</p><form id="f"><label>Verification code<input id="code" inputmode="numeric" maxlength="6" required></label><div id="error" class="error" role="alert"></div><button>Verify identity</button></form></section>');document.getElementById("f").onsubmit=async e=>{e.preventDefault();try{const r=await api("/api/identity-verify",{code:code.value});csrf=r.csrf;page="setup";render()}catch(x){err(x.message)}}}
else if(page==="setup"){show('<section><h2>Set up your authenticator</h2><div class="card" id="p"><button id="get" type="button">Create setup key</button></div><form id="f"><label>Setup key from authenticator app<input id="secret" autocapitalize="characters" required></label><label>Six-digit code from app<input id="otp" inputmode="numeric" maxlength="6" required></label><div id="error" class="error" role="alert"></div><button>Confirm authenticator</button></form><button id="out" class="secondary" type="button">Sign out</button></section>');if(provisioned){const p=document.getElementById("p");p.textContent="A setup key was created. Enter it manually from your authenticator app."}document.getElementById("get")?.addEventListener("click",async()=>{try{const r=await api("/api/mfa/provision",{});provisioned=true;log("Authenticator setup key for testing: "+r.manualSecret);log("Current RFC 6238 authenticator test code: "+r.testOtp);render()}catch(x){err(x.message)}});out.onclick=logout;document.getElementById("f").onsubmit=async e=>{e.preventDefault();try{const r=await api("/api/mfa/confirm",{manualSecret:secret.value,otp:otp.value});log("Recovery codes issued for testing: "+r.recoveryCodes.join(", "));provisioned=false;page="confirmed";render()}catch(x){err(x.message)}}}
else if(page==="confirmed"){show('<section><h2>Authenticator confirmed</h2><div class="card success"><strong>MFA is active.</strong><br>Your recovery codes have been issued. Store them somewhere safe.</div><button id="rec">Recovery codes</button><button id="out" class="secondary">Sign out</button></section>');rec.onclick=()=>{page="recovery";render()};out.onclick=logout}
else{show('<section><h2>Recovery codes</h2><p class="hint">Enter a stored recovery code to verify it. Each code can be used once.</p><form id="f"><label>Recovery code<input id="rc" placeholder="ABCDE-FGHIJ" required></label><div id="error" class="error" role="alert"></div><button>Verify recovery code</button></form><div class="card"><h2>Replace codes</h2><p class="hint">Replacement codes invalidate all previous recovery codes.</p><button id="regen" class="danger" type="button">Generate replacement codes</button></div><button id="done" class="secondary">Done</button><button id="out" class="secondary">Sign out</button></section>');f.onsubmit=async e=>{e.preventDefault();try{await api("/api/recovery/verify",{code:rc.value});log("A recovery code was verified and consumed.");err("Recovery code accepted and consumed.")}catch(x){err(x.message)}};regen.onclick=async()=>{try{const r=await api("/api/recovery/regenerate",{});log("Replacement recovery codes issued for testing: "+r.recoveryCodes.join(", "));render()}catch(x){err(x.message)}};done.onclick=()=>{page="confirmed";render()};out.onclick=logout}}
async function logout(){try{await api("/api/logout",{})}catch{}csrf="";provisioned=false;page="signin";log("Signed out. This browser session was invalidated.");render()}
(async()=>{try{const r=await api("/api/bootstrap",null,"GET");csrf=r.csrf;page=r.state==="authenticated"?"setup":r.state==="identity"?"identity":"signin";render()}catch{view.textContent="Secure service unavailable. Please refresh and try again."}})()})();
</script></body></html>`;

Bun.serve({
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request: Request): Promise<Response> {
    const nonce = token(18);
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") {
        if (!trustedOrigin(request)) return error(request, nonce, 403);
        const result = headers(request, nonce);
        result.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        result.set("Access-Control-Allow-Headers", "Content-Type");
        return new Response(null, { status: 204, headers: result });
      }
      if (url.pathname === "/" && request.method === "GET") {
        const result = headers(request, nonce);
        result.set("Content-Type", "text/html; charset=utf-8");
        result.set("Cache-Control", "no-store");
        return new Response(html(nonce), { headers: result });
      }
      if (!url.pathname.startsWith("/api/") || !trustedOrigin(request)) return error(request, nonce, 403);

      if (url.pathname === "/api/bootstrap" && request.method === "GET") {
        let session = getSession(request), cookie: string | undefined;
        if (!session) { session = createSession(); cookie = sessionCookie(session.id); }
        return reply(request, nonce, { ok: true, csrf: session.csrf, state: session.state }, 200, cookie);
      }

      const session = getSession(request);
      const body = await bodyObject(request);
      if (!body || manipulated(body) || !session || !csrfOK(session, body)) return error(request, nonce, 403);

      if (url.pathname === "/api/sign-in" && request.method === "POST") {
        const suppliedEmail = email(body.email), suppliedPhone = phone(body.phone);
        if (!suppliedEmail || !suppliedPhone || suppliedEmail !== "marcus@example.test" || suppliedPhone !== "+15550101954") return error(request, nonce, 401);
        const next = rotateSession(session, "identity", "marcus-account-001");
        next.identityCode = randomDigits();
        next.identityCodeExpiresAt = Date.now() + IDENTITY_CODE_MS;
        return reply(request, nonce, { ok: true, csrf: next.csrf, testIdentityCode: next.identityCode }, 200, sessionCookie(next.id));
      }
      if (url.pathname === "/api/identity-verify" && request.method === "POST") {
        if (session.state !== "identity" || session.userId !== "marcus-account-001") return error(request, nonce, 403);
        const code = otp(body.code), now = Date.now();
        if (!session.identityCode || !session.identityCodeExpiresAt || now > session.identityCodeExpiresAt) {
          session.identityCode = undefined; session.identityCodeExpiresAt = undefined; return error(request, nonce, 401);
        }
        if (!code || now < session.identityLockedUntil || !sameValue(code, session.identityCode)) {
          if (++session.identityAttempts >= MAX_ATTEMPTS) session.identityLockedUntil = now + LOCK_MS;
          return error(request, nonce, 401);
        }
        const next = rotateSession(session, "authenticated", "marcus-account-001");
        return reply(request, nonce, { ok: true, csrf: next.csrf }, 200, sessionCookie(next.id));
      }
      if (url.pathname === "/api/logout" && request.method === "POST") {
        sessions.delete(session.id);
        return reply(request, nonce, { ok: true }, 200, clearCookie());
      }
      if (!authenticated(session)) return error(request, nonce, 403);

      if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
        // Task: reserve synchronously before any async crypto work. A concurrent call is rejected.
        if (session.provisionReserved || session.draft?.reserved) return error(request, nonce, 409);
        session.provisionReserved = true;
        const seed = base32Secret();

        try {
          const testOtp = await totpForStep(seed, Math.floor(Date.now() / TOTP_STEP_MS));
          const encryptedSecret = await encryptAtRest(seed);
          if (!testOtp || !sessionStillCurrent(session) || !authenticated(session)) return error(request, nonce, 401);

          // Synchronous active-draft commit occurs before the setup key is returned.
          session.draft = {
            encryptedSecret, expiresAt: Date.now() + VERIFY_WINDOW_MS,
            used: false, reserved: false, failedAttempts: 0, lockedUntil: 0,
          };
          return reply(request, nonce, { ok: true, csrf: session.csrf, manualSecret: seed, testOtp });
        } catch {
          return error(request, nonce, 500);
        } finally {
          session.provisionReserved = false;
        }
      }

      if (url.pathname === "/api/mfa/confirm" && request.method === "POST") {
        const suppliedSecret = secret(body.manualSecret);
        const suppliedOtp = otp(body.otp);
        const draft = session.draft;
        const now = Date.now();

        if (session.provisionReserved || !draft || draft.used || draft.reserved || now > draft.expiresAt) {
          if (draft && now > draft.expiresAt) session.draft = undefined;
          return error(request, nonce, 401);
        }
        if (!suppliedSecret || !suppliedOtp || now < draft.lockedUntil) {
          if (++draft.failedAttempts >= MAX_ATTEMPTS) draft.lockedUntil = now + LOCK_MS;
          return error(request, nonce, 401);
        }

        // Atomic reservation before decrypt/TOTP/hash awaits prevents competing confirmations.
        draft.reserved = true;

        try {
          const draftSecret = await decryptDraftSecret(draft.encryptedSecret);
          const valid = !!draftSecret && sameValue(suppliedSecret, draftSecret) && await validTotp(draftSecret, suppliedOtp, now);

          if (!sessionStillCurrent(session) || Date.now() > draft.expiresAt) {
            if (session.draft === draft) session.draft = undefined;
            return error(request, nonce, 401);
          }
          if (!valid) {
            if (++draft.failedAttempts >= MAX_ATTEMPTS) draft.lockedUntil = Date.now() + LOCK_MS;
            draft.reserved = false;
            return error(request, nonce, 401);
          }

          const set = await generateRecoveryCodeSet();
          if (!sessionStillCurrent(session) || Date.now() > draft.expiresAt) {
            if (session.draft === draft) session.draft = undefined;
            return error(request, nonce, 401);
          }

          draft.used = true;
          session.encryptedMfaSecret = draft.encryptedSecret;
          session.recoveryCodes = set.entries;
          session.recoveryAttempts = 0;
          session.recoveryLockedUntil = 0;
          session.draft = undefined;
          return reply(request, nonce, { ok: true, csrf: session.csrf, recoveryCodes: set.codes });
        } catch {
          if (session.draft === draft && !draft.used) draft.reserved = false;
          return error(request, nonce, 500);
        }
      }

      if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
        const supplied = recovery(body.code), now = Date.now();
        if (!supplied || now < session.recoveryLockedUntil) return error(request, nonce, 401);

        // Task: acquire the per-session recovery mutex synchronously before hashing.
        // Competing verify/regenerate calls are rejected rather than observing partial state.
        if (session.recoveryReserved) return error(request, nonce, 409);
        session.recoveryReserved = true;

        try {
          let matched: RecoveryEntry | undefined;
          for (const entry of session.recoveryCodes) {
            const digest = await sha256(`${entry.salt}:${supplied}`);
            if (!entry.used && sameValue(digest, entry.digest)) matched = entry;
          }
          if (!sessionStillCurrent(session) || !authenticated(session)) return error(request, nonce, 401);

          // Atomic while held: only one request can consume a matched code.
          if (!matched) {
            if (++session.recoveryAttempts >= MAX_ATTEMPTS) session.recoveryLockedUntil = Date.now() + LOCK_MS;
            return error(request, nonce, 401);
          }
          matched.used = true;
          session.recoveryAttempts = 0;
          return reply(request, nonce, { ok: true, csrf: session.csrf });
        } catch {
          return error(request, nonce, 500);
        } finally {
          session.recoveryReserved = false;
        }
      }

      if (url.pathname === "/api/recovery/regenerate" && request.method === "POST") {
        if (!session.encryptedMfaSecret) return error(request, nonce, 400);

        // Task: this shares the verify mutex. A concurrent regeneration is rejected,
        // so a caller can never receive a recovery-code set superseded by another concurrent call.
        if (session.recoveryReserved) return error(request, nonce, 409);
        session.recoveryReserved = true;

        try {
          const set = await generateRecoveryCodeSet();
          if (!sessionStillCurrent(session) || !authenticated(session) || !session.encryptedMfaSecret) return error(request, nonce, 401);

          // Atomic replacement and response construction while the mutex remains held.
          session.recoveryCodes = set.entries;
          session.recoveryAttempts = 0;
          session.recoveryLockedUntil = 0;
          return reply(request, nonce, { ok: true, csrf: session.csrf, recoveryCodes: set.codes });
        } catch {
          return error(request, nonce, 500);
        } finally {
          session.recoveryReserved = false;
        }
      }
      return error(request, nonce, 404);
    } catch {
      // Requirement 2: generic production failure only; no secret or stack trace exposure.
      return error(request, nonce, 500);
    }
  },
});
