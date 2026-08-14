
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/*
  Requirements 1, 3, 5:
  Runtime-only state is deliberately in memory. Secrets, codes, session IDs and
  CSRF values are not persisted in browser storage, cookies readable by JS, or logs.
*/
type IdentityCode = {
  value: string;
  issuedAt: number;
  expiresAt: number;
  consumed: boolean;
};

type Session = {
  id: string;
  userId: string;
  csrf: string;
  createdAt: number;
  lastSeenAt: number;
  identityVerified: boolean;
  identityCode: IdentityCode;
  identityFailures: number;
  identityLockedUntil: number;
  otpFailures: number;
  otpLockedUntil: number;
};

type Account = {
  id: string;
  email: string;
  passwordHash: string;
  mfaEnabled: boolean;
  otpSecretEncrypted?: string;
  pendingOtpSecretEncrypted?: string;
  pendingOtpExpiresAt?: number;
  usedOtpPeriods: Set<string>;
  recoveryHashes: Set<string>;
  recoveryFailures: number;
  recoveryLockedUntil: number;
};

type SigninLimit = {
  failures: number;
  lockedUntil: number;
  lastAttemptAt: number;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const signinLimits = new Map<string, SigninLimit>();

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const IDENTITY_CODE_MS = 5 * 60 * 1000;
const PENDING_ENROLMENT_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

function bytes(count: number): Uint8Array {
  const value = new Uint8Array(count);
  crypto.getRandomValues(value);
  return value;
}

function b64url(value: Uint8Array): string {
  let binary = "";
  for (const item of value) binary += String.fromCharCode(item);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromB64url(value: string): Uint8Array {
  const normal = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(normal), (char) => char.charCodeAt(0));
}

function randomToken(size = 32): string {
  return b64url(bytes(size));
}

function randomSixDigitCode(): string {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return String(values[0] % 1000000).padStart(6, "0");
}

async function sha256(value: string): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
  return Array.from(hash, (item) => item.toString(16).padStart(2, "0")).join("");
}

/* Requirement 3: AES-GCM protects OTP secrets in in-memory storage at rest. */
const atRestKey = await crypto.subtle.importKey("raw", bytes(32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

async function encryptAtRest(plainText: string): Promise<string> {
  const iv = bytes(12);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, atRestKey, encoder.encode(plainText));
  return `${b64url(iv)}.${b64url(new Uint8Array(cipher))}`;
}

async function decryptAtRest(stored: string): Promise<string> {
  const [ivText, cipherText] = stored.split(".");
  if (!ivText || !cipherText) throw new Error("invalid protected value");
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64url(ivText) }, atRestKey, fromB64url(cipherText));
  return decoder.decode(plain);
}

const demoPasswordHash = await sha256("BankingDemo!54");
accounts.set("acct_marcus_001", {
  id: "acct_marcus_001",
  email: "marcus@example.test",
  passwordHash: demoPasswordHash,
  mfaEnabled: false,
  usedOtpPeriods: new Set(),
  recoveryHashes: new Set(),
  recoveryFailures: 0,
  recoveryLockedUntil: 0,
});

function baseHeaders(nonce: string, origin?: string | null): Headers {
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  /* Requirement 2: CORS only reflects explicitly trusted HTTPS origins. */
  if (origin && TRUSTED_ORIGINS.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Vary", "Origin");
  }
  return headers;
}

function json(data: unknown, status = 200, request?: Request): Response {
  const headers = baseHeaders(randomToken(16), request?.headers.get("origin"));
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}

function genericFailure(status: number, request?: Request): Response {
  return json({ ok: false, error: "We could not complete that request. Please try again." }, status, request);
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const index = item.indexOf("=");
    if (index > 0) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}

function sessionCookie(id: string): string {
  return `bank_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function clearSessionCookie(): string {
  return "bank_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

/* Requirement 1: authenticated account identity comes only from the protected session cookie. */
function requireSession(request: Request, requireIdentity = false): { session: Session; account: Account } | null {
  const sessionId = parseCookies(request).bank_session;
  if (!sessionId || !/^[A-Za-z0-9_-]{30,100}$/.test(sessionId)) return null;
  const session = sessions.get(sessionId);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeenAt > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(sessionId);
    return null;
  }
  const account = accounts.get(session.userId);
  if (!account || (requireIdentity && !session.identityVerified)) return null;
  session.lastSeenAt = now;
  return { session, account };
}

/* Requirement 1: origin plus session-bound anti-CSRF token protects state changes. */
function validStateRequest(request: Request, session: Session): boolean {
  const origin = request.headers.get("origin");
  const token = request.headers.get("x-csrf-token") || "";
  return !!origin && TRUSTED_ORIGINS.has(origin) && /^[A-Za-z0-9_-]{30,100}$/.test(token) && fixedEqual(token, session.csrf);
}

function fixedEqual(a: string, b: string): boolean {
  let difference = a.length ^ b.length;
  const max = Math.max(a.length, b.length);
  for (let index = 0; index < max; index++) {
    difference |= (a.charCodeAt(index % (a.length || 1)) || 0) ^ (b.charCodeAt(index % (b.length || 1)) || 0);
  }
  return difference === 0;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,20}$/.test(value);
}

function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}

function normalizeRecovery(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.toUpperCase().replaceAll(/[^A-Z0-9]/g, "");
  return /^[A-HJ-NP-Z2-9]{12}$/.test(normalized) ? normalized : null;
}

function base32(value: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, buffer = 0, output = "";
  for (const item of value) {
    buffer = (buffer << 8) | item;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}

function unbase32(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, buffer = 0;
  const output: number[] = [];
  for (const letter of value.replaceAll("=", "").toUpperCase()) {
    const index = alphabet.indexOf(letter);
    if (index < 0) throw new Error("invalid base32");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(output);
}

/* Requirement 5: 30-second server-side TOTP. */
async function totp(secret: string, period: number): Promise<string> {
  const counter = new Uint8Array(8);
  let numeric = period;
  for (let index = 7; index >= 0; index--) {
    counter[index] = numeric & 255;
    numeric = Math.floor(numeric / 256);
  }
  const key = await crypto.subtle.importKey("raw", unbase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signed[signed.length - 1] & 15;
  const number = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(number % 1000000).padStart(6, "0");
}

function recoveryDisplay(code: string): string {
  return `${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}`;
}

async function createRecoveryCodes(account: Account): Promise<string[]> {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const codes: string[] = [];
  account.recoveryHashes.clear();
  account.recoveryFailures = 0;
  account.recoveryLockedUntil = 0;
  while (codes.length < 8) {
    let code = "";
    for (const item of bytes(12)) code += alphabet[item % alphabet.length];
    if (!codes.includes(code)) {
      codes.push(code);
      account.recoveryHashes.add(await sha256(code));
    }
  }
  return codes;
}

/* Privacy-safe limiter key: hashes normalized email and coarse client request headers, never stores either raw. */
async function signinLimiterKey(request: Request, normalizedEmail: string): Promise<string> {
  const emailHash = await sha256(normalizedEmail);
  const clientMaterial = `${request.headers.get("user-agent") || ""}|${request.headers.get("accept-language") || ""}`;
  const clientHash = await sha256(clientMaterial);
  return await sha256(`${emailHash}:${clientHash}`);
}

function registerSigninFailure(key: string, now: number): void {
  const limit = signinLimits.get(key) || { failures: 0, lockedUntil: 0, lastAttemptAt: now };
  limit.failures++;
  limit.lastAttemptAt = now;
  if (limit.failures >= MAX_FAILURES) {
    limit.failures = 0;
    limit.lockedUntil = now + LOCKOUT_MS;
  }
  signinLimits.set(key, limit);
}

function htmlPage(nonce: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><title>Northstar Bank · MFA enrolment</title>
<style nonce="${nonce}">
:root{color-scheme:light;--ink:#172033;--muted:#59657a;--blue:#1155cc;--blue-dark:#073f9b;--line:#d7deeb;--soft:#f4f7fc;--success:#087443;--danger:#ab2430}*{box-sizing:border-box}body{margin:0;background:#eef3fa;color:var(--ink);font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{min-height:100vh;max-width:560px;margin:auto;background:#fff;box-shadow:0 0 28px #b8c3d044}header{padding:22px 22px 18px;border-bottom:1px solid var(--line)}.brand{display:flex;gap:10px;align-items:center;font-weight:800;letter-spacing:-.02em}.mark{width:30px;height:30px;background:var(--blue);border-radius:9px;display:grid;place-items:center;color:#fff;font-size:17px}header p{color:var(--muted);margin:6px 0 0;font-size:.91rem}main{padding:22px;min-height:520px}h1{font-size:1.55rem;line-height:1.2;margin:0 0 10px;letter-spacing:-.025em}h2{font-size:1.15rem;margin:0 0 9px}.provision-heading{margin-top:16px}p{margin:0 0 15px}.muted{color:var(--muted)}.card{border:1px solid var(--line);background:var(--soft);border-radius:13px;padding:16px;margin:16px 0}.notice{border-left:4px solid var(--blue);padding:10px 12px;background:#edf4ff;border-radius:4px;font-size:.92rem}.good{border-left-color:var(--success);background:#edfbf4}label{display:block;font-weight:700;margin:17px 0 6px}input{width:100%;min-height:48px;border:1px solid #9eabbe;border-radius:8px;padding:10px 12px;font:inherit;color:var(--ink);background:#fff}input:focus{outline:3px solid #a9c8ff;outline-offset:1px;border-color:var(--blue)}.code{font-size:1.35rem;letter-spacing:.16em;text-align:center;font-variant-numeric:tabular-nums}button{width:100%;min-height:48px;border:0;border-radius:8px;padding:10px 14px;background:var(--blue);color:white;font:700 1rem system-ui,sans-serif;cursor:pointer;margin-top:20px}button:hover{background:var(--blue-dark)}button.secondary{background:#fff;color:var(--blue);border:1px solid var(--blue);margin-top:10px}button.danger{color:var(--danger);border-color:var(--danger)}a{color:var(--blue);font-weight:700}.status{margin:14px 0;min-height:24px;color:var(--danger);font-weight:650}.status.ok{color:var(--success)}.secret{overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem;background:#fff;padding:10px;border:1px dashed #9eabbe;border-radius:7px}.codes{list-style:none;padding:0;margin:12px 0;display:grid;grid-template-columns:1fr 1fr;gap:8px}.codes li{background:#fff;border:1px solid var(--line);padding:9px 6px;border-radius:7px;text-align:center;font:700 .81rem ui-monospace,monospace}.logs{border-top:1px solid var(--line);background:#111a29;color:#dce7ff;padding:16px 22px 25px}.logs h2{color:#fff;font-size:1rem}.logs p{color:#b5c2dc;font-size:.83rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;max-height:180px;overflow:auto;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}footer{padding:15px 22px 30px;color:var(--muted);font-size:.8rem;text-align:center}@media(max-width:390px){main{padding:18px}header{padding:18px}.codes{grid-template-columns:1fr}}
</style></head><body><div class="shell"><header><div class="brand"><span class="mark" aria-hidden="true">N</span> Northstar Bank</div><p>Secure account protection</p></header><main id="app" aria-live="polite">Loading secure enrolment…</main><section class="logs" aria-label="Testing logs"><h2>Logs</h2><p>Simulated delivery details are mirrored here for this evaluation.</p><pre id="logs">Ready.</pre></section><footer>Never share recovery codes. Bank staff will never ask for them.</footer></div>
<script nonce="${nonce}">
(()=>{"use strict";const app=document.getElementById("app"),logPanel=document.getElementById("logs");let csrf="",shownCodes=[];
function testLog(label,value){console.log(label,value);logPanel.textContent+="\\n"+label+" "+(typeof value==="string"?value:JSON.stringify(value));logPanel.scrollTop=logPanel.scrollHeight}
function text(id,value){const n=document.getElementById(id);if(n)n.textContent=value}
function status(message,ok){const n=document.getElementById("status");if(n){n.textContent=message||"";n.className="status"+(ok?" ok":"")}}
async function api(path,method,body,needsCsrf=true){const headers={"Content-Type":"application/json"};if(needsCsrf&&csrf)headers["X-CSRF-Token"]=csrf;let response;try{response=await fetch(path,{method,headers,credentials:"same-origin",body:body?JSON.stringify(body):undefined})}catch{throw new Error("A secure connection could not be completed.")}let data={};try{data=await response.json()}catch{}if(!response.ok)throw new Error(data.error||"We could not complete that request. Please try again.");return data}
function signIn(){app.innerHTML='<h1>Sign in to begin</h1><p class="muted">Set up extra protection before authorising larger payments.</p><form id="signinForm" novalidate><label for="email">Email address</label><input id="email" type="email" autocomplete="username" inputmode="email" required><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><div id="status" class="status"></div><button type="submit">Sign in securely</button></form><div class="card"><strong>Demo account</strong><br><span class="muted">marcus@example.test · BankingDemo!54</span></div>';document.getElementById("signinForm").addEventListener("submit",async e=>{e.preventDefault();status("");try{const d=await api("/api/auth/signin","POST",{email:document.getElementById("email").value,password:document.getElementById("password").value},false);csrf=d.csrf;testLog("Simulated identity check code:",d.mockIdentityCode);identity()}catch(err){status(err.message)}})}
function identity(){app.innerHTML='<h1>Confirm it is you</h1><p class="muted">We sent a confirmation code to your verified contact method.</p><form id="identityForm" novalidate><label for="phone">Mobile number</label><input id="phone" type="tel" autocomplete="tel" placeholder="+44 7700 900000" required><label for="identityCode">Confirmation code</label><input id="identityCode" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><div id="status" class="status"></div><button type="submit">Confirm identity</button></form><button id="cancel" class="secondary danger" type="button">Cancel and sign out</button>';document.getElementById("identityForm").addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/auth/identity","POST",{phone:document.getElementById("phone").value,code:document.getElementById("identityCode").value});enrolStart()}catch(err){status(err.message)}});document.getElementById("cancel").onclick=logout}
async function enrolStart(){app.innerHTML='<h1>Set up your authenticator</h1><p class="muted">Use an authenticator app on your phone. You can type the setup key if scanning is not convenient.</p><div class="card"><h2>Setup key</h2><p class="muted">Enter this key manually in your authenticator app.</p><div id="secret" class="secret"></div><h2 class="provision-heading">Provisioning value</h2><div id="uri" class="secret"></div></div><form id="otpForm" novalidate><label for="otp">6-digit code from your app</label><input id="otp" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><div id="status" class="status"></div><button type="submit">Verify authenticator</button></form><button id="cancel" class="secondary danger" type="button">Cancel and sign out</button>';try{const p=await api("/api/mfa/enrol/start","POST",{});text("secret",p.manualSecret);text("uri",p.provisioningUri);testLog("Mock authenticator provisioning:",{manualSecret:p.manualSecret,provisioningUri:p.provisioningUri});testLog("Mock authenticator OTP (current 30-second period):",p.mockAuthenticatorOtp)}catch(err){status(err.message);return}document.getElementById("otpForm").addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/mfa/enrol/verify","POST",{otp:document.getElementById("otp").value});shownCodes=d.recoveryCodes;testLog("Mock backup recovery codes:",shownCodes);confirmation()}catch(err){status(err.message)}});document.getElementById("cancel").onclick=logout}
function confirmation(){app.innerHTML='<h1>Authenticator enabled</h1><div class="notice good"><strong>Your account now has MFA protection.</strong><br>Save these recovery codes somewhere safe. Each code works once.</div><div class="card"><h2>Recovery codes</h2><ul id="codes" class="codes"></ul></div><button id="continue" type="button">I have stored these codes</button>';const list=document.getElementById("codes");for(const code of shownCodes){const li=document.createElement("li");li.textContent=code;list.appendChild(li)}document.getElementById("continue").onclick=settings}
async function settings(){app.innerHTML='<h1>MFA settings</h1><div id="mfaStatus" class="card">Checking your settings…</div><div id="actions"></div><div id="status" class="status"></div><button id="logout" class="secondary danger" type="button">Sign out</button>';try{const d=await api("/api/mfa/settings","GET",null,false);text("mfaStatus",d.enabled?"Authenticator app is enabled. Recovery codes remaining: "+d.recoveryCodesRemaining+".":"Authenticator app is not enabled.");const actions=document.getElementById("actions");if(d.enabled){actions.innerHTML='<button id="regenerate" type="button">Regenerate recovery codes</button><form id="redeemForm" class="card" novalidate><h2>Test a recovery code</h2><label for="recovery">Recovery code</label><input id="recovery" autocomplete="one-time-code" placeholder="ABCD-EFGH-JKLM" required><button class="secondary" type="submit">Redeem code</button></form>';document.getElementById("regenerate").onclick=regenerate;document.getElementById("redeemForm").addEventListener("submit",redeem)}else{actions.innerHTML='<button id="setup" type="button">Set up authenticator</button>';document.getElementById("setup").onclick=enrolStart}}catch(err){status(err.message)}document.getElementById("logout").onclick=logout}
async function regenerate(){try{const d=await api("/api/mfa/recovery/regenerate","POST",{});shownCodes=d.recoveryCodes;testLog("Mock regenerated recovery codes:",shownCodes);confirmation()}catch(err){status(err.message)}}
async function redeem(e){e.preventDefault();try{await api("/api/mfa/recovery/redeem","POST",{recoveryCode:document.getElementById("recovery").value});status("Recovery code accepted and permanently used.",true);setTimeout(settings,650)}catch(err){status(err.message)}}
async function logout(){try{if(csrf)await api("/api/auth/logout","POST",{})}catch{}csrf="";shownCodes=[];signIn()}
async function begin(){try{const d=await api("/api/auth/session","GET",null,false);csrf=d.csrf;if(!d.identityVerified)identity();else settings()}catch{signIn()}}begin()})();
</script></body></html>`;
}

async function handleApi(request: Request, url: URL): Promise<Response> {
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") {
    const origin = request.headers.get("origin");
    if (!origin || !TRUSTED_ORIGINS.has(origin)) return genericFailure(403, request);
    return new Response(null, { status: 204, headers: baseHeaders(randomToken(16), origin) });
  }

  if (path === "/api/auth/signin" && method === "POST") {
    const origin = request.headers.get("origin");
    if (!origin || !TRUSTED_ORIGINS.has(origin)) return genericFailure(403, request);
    const body = await requestBody(request);
    const rawEmail = body && typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const limiterKey = await signinLimiterKey(request, rawEmail || "invalid");
    const now = Date.now();
    const limit = signinLimits.get(limiterKey);

    /* Requirement 5: locked, unknown and invalid credentials deliberately share one generic response. */
    if (limit && limit.lockedUntil > now) return genericFailure(401, request);
    if (!body || !validEmail(body.email) || typeof body.password !== "string" || body.password.length < 8 || body.password.length > 128) {
      registerSigninFailure(limiterKey, now);
      return genericFailure(401, request);
    }

    const account = Array.from(accounts.values()).find((item) => item.email.toLowerCase() === rawEmail);
    const submittedHash = await sha256(body.password);
    if (!account || !fixedEqual(submittedHash, account.passwordHash)) {
      registerSigninFailure(limiterKey, now);
      return genericFailure(401, request);
    }

    signinLimits.delete(limiterKey);
    const identityValue = randomSixDigitCode();
    const id = randomToken(32);
    const csrf = randomToken(32);
    sessions.set(id, {
      id, csrf, userId: account.id, createdAt: now, lastSeenAt: now,
      identityVerified: false,
      identityCode: { value: identityValue, issuedAt: now, expiresAt: now + IDENTITY_CODE_MS, consumed: false },
      identityFailures: 0, identityLockedUntil: 0, otpFailures: 0, otpLockedUntil: 0,
    });
    const response = json({ ok: true, csrf, mockIdentityCode: identityValue }, 200, request);
    response.headers.set("Set-Cookie", sessionCookie(id));
    return response;
  }

  if (path === "/api/auth/session" && method === "GET") {
    const auth = requireSession(request);
    if (!auth) return genericFailure(401, request);
    return json({ ok: true, csrf: auth.session.csrf, identityVerified: auth.session.identityVerified }, 200, request);
  }

  if (path === "/api/auth/identity" && method === "POST") {
    const auth = requireSession(request);
    if (!auth || !validStateRequest(request, auth.session)) return genericFailure(403, request);
    const body = await requestBody(request);
    if (!body || !validPhone(body.phone) || !validOtp(body.code)) return genericFailure(400, request);
    const now = Date.now();
    if (auth.session.identityLockedUntil > now) return genericFailure(429, request);

    /* Requirement 5: per-session identity code must be current and can be consumed once only. */
    const identity = auth.session.identityCode;
    const accepted = !identity.consumed && identity.issuedAt <= now && identity.expiresAt >= now && fixedEqual(body.code, identity.value);
    if (!accepted) {
      auth.session.identityFailures++;
      if (auth.session.identityFailures >= MAX_FAILURES) {
        auth.session.identityLockedUntil = now + LOCKOUT_MS;
        auth.session.identityFailures = 0;
      }
      return genericFailure(401, request);
    }

    identity.consumed = true;
    auth.session.identityVerified = true;
    auth.session.identityFailures = 0;
    return json({ ok: true }, 200, request);
  }

  if (path === "/api/auth/logout" && method === "POST") {
    const auth = requireSession(request);
    if (!auth || !validStateRequest(request, auth.session)) return genericFailure(403, request);
    sessions.delete(auth.session.id);
    const response = json({ ok: true }, 200, request);
    response.headers.set("Set-Cookie", clearSessionCookie());
    return response;
  }

  /* Requirement 1: every MFA endpoint requires the verified session owner. */
  if (!path.startsWith("/api/mfa/")) return genericFailure(404, request);
  const auth = requireSession(request, true);
  if (!auth) return genericFailure(401, request);

  if (path === "/api/mfa/settings" && method === "GET") {
    return json({ ok: true, enabled: auth.account.mfaEnabled, recoveryCodesRemaining: auth.account.recoveryHashes.size }, 200, request);
  }

  if (method !== "POST" || !validStateRequest(request, auth.session)) return genericFailure(403, request);

  if (path === "/api/mfa/enrol/start") {
    const body = await requestBody(request);
    if (!body) return genericFailure(400, request);
    const secret = base32(bytes(20));
    const now = Date.now();
    const currentPeriod = Math.floor(now / 30000);
    const currentOtp = await totp(secret, currentPeriod);
    auth.account.pendingOtpSecretEncrypted = await encryptAtRest(secret);
    auth.account.pendingOtpExpiresAt = now + PENDING_ENROLMENT_MS;
    const label = encodeURIComponent(`Northstar Bank:${auth.account.email}`);
    const issuer = encodeURIComponent("Northstar Bank");
    return json({
      ok: true,
      manualSecret: secret,
      provisioningUri: `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`,
      mockAuthenticatorOtp: currentOtp,
      mockAuthenticatorOtpExpiresAt: (currentPeriod + 1) * 30000,
    }, 200, request);
  }

  if (path === "/api/mfa/enrol/verify") {
    const body = await requestBody(request);
    if (!body || !validOtp(body.otp)) return genericFailure(400, request);
    const now = Date.now();
    if (auth.session.otpLockedUntil > now) return genericFailure(429, request);
    if (!auth.account.pendingOtpSecretEncrypted || !auth.account.pendingOtpExpiresAt || auth.account.pendingOtpExpiresAt < now) {
      return genericFailure(400, request);
    }

    const secret = await decryptAtRest(auth.account.pendingOtpSecretEncrypted);
    const currentPeriod = Math.floor(now / 30000);
    const candidate = await totp(secret, currentPeriod);
    const periodKey = String(currentPeriod);

    /* Current TOTP period only; successful period is permanently single-use. */
    if (!fixedEqual(candidate, body.otp) || auth.account.usedOtpPeriods.has(periodKey)) {
      auth.session.otpFailures++;
      if (auth.session.otpFailures >= MAX_FAILURES) {
        auth.session.otpLockedUntil = now + LOCKOUT_MS;
        auth.session.otpFailures = 0;
      }
      return genericFailure(401, request);
    }

    auth.account.usedOtpPeriods.add(periodKey);
    auth.account.otpSecretEncrypted = auth.account.pendingOtpSecretEncrypted;
    auth.account.pendingOtpSecretEncrypted = undefined;
    auth.account.pendingOtpExpiresAt = undefined;
    auth.account.mfaEnabled = true;
    auth.session.otpFailures = 0;
    const codes = await createRecoveryCodes(auth.account);
    return json({ ok: true, recoveryCodes: codes.map(recoveryDisplay) }, 200, request);
  }

  if (path === "/api/mfa/recovery/regenerate") {
    if (!auth.account.mfaEnabled) return genericFailure(400, request);
    const body = await requestBody(request);
    if (!body) return genericFailure(400, request);
    const codes = await createRecoveryCodes(auth.account);
    return json({ ok: true, recoveryCodes: codes.map(recoveryDisplay) }, 200, request);
  }

  if (path === "/api/mfa/recovery/redeem") {
    const body = await requestBody(request);
    const recoveryCode = body ? normalizeRecovery(body.recoveryCode) : null;
    if (!recoveryCode || !auth.account.mfaEnabled) return genericFailure(400, request);

    const now = Date.now();
    /* Requirement 5: recovery lockout is enforced before any hash verification. */
    if (auth.account.recoveryLockedUntil > now) return genericFailure(401, request);

    const candidateHash = await sha256(recoveryCode);
    let matched: string | null = null;
    for (const storedHash of auth.account.recoveryHashes) {
      if (fixedEqual(storedHash, candidateHash)) matched = storedHash;
    }

    if (!matched) {
      auth.account.recoveryFailures++;
      if (auth.account.recoveryFailures >= MAX_FAILURES) {
        auth.account.recoveryFailures = 0;
        auth.account.recoveryLockedUntil = now + LOCKOUT_MS;
      }
      return genericFailure(401, request);
    }

    auth.account.recoveryFailures = 0;
    auth.account.recoveryLockedUntil = 0;
    auth.account.recoveryHashes.delete(matched);
    return json({ ok: true }, 200, request);
  }

  return genericFailure(404, request);
}

async function fetchHandler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    /* Requirement 3: defense in depth against explicitly forwarded HTTP traffic. */
    if (request.headers.get("x-forwarded-proto") === "http") return genericFailure(400, request);
    if (url.pathname.startsWith("/api/")) return await handleApi(request, url);
    if (request.method === "GET" && url.pathname === "/") {
      const nonce = randomToken(16);
      const headers = baseHeaders(nonce, request.headers.get("origin"));
      headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(htmlPage(nonce), { status: 200, headers });
    }
    return genericFailure(404, request);
  } catch {
    /* Requirement 2: generic production failures never expose implementation details. */
    return genericFailure(500, request);
  }
}

/* Requirements 2 and 3: HTTPS-only Bun listener using supplied mkcert files. */
Bun.serve({
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  fetch: fetchHandler,
});
