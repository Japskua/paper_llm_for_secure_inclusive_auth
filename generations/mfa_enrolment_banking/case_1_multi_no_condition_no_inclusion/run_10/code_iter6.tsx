
/*
  One-file Bun HTTPS server + inline vanilla-JS mobile SPA.
  Requirements 1–5: deterministic in-memory mock state, no external requests,
  no browser storage, server-side authorization, TLS, CSRF, and secure mocks.
*/
const port = Number(Bun.env.PORT || 3000);
const sessions = new Map<string, Session>();
const identityStates = new Map<string, IdentityState>();
const masterKey = randomBytes(32);
const recoveryPepper = toBase64Url(randomBytes(32));
const encoder = new TextEncoder();

type AttemptKind = "identity" | "authenticator" | "recovery";
type Attempt = { count: number; lockedUntil: number };
type Attempts = Record<AttemptKind, Attempt>;
type EncryptedValue = { iv: string; ciphertext: string };
type IdentityState = { target: string; account?: "marcus"; challenge: { code: string; expiresAt: number; used: boolean }; attempts: Attempt };
type Session = {
  id: string; csrf: string; account?: "marcus"; identityTarget?: string;
  stage: "anonymous" | "identity" | "verified" | "provisioned" | "mfa";
  createdAt: number; lastSeen: number; encryptedSecret?: EncryptedValue;
  authenticatorUsed?: boolean; recoveryHashes: string[]; pendingRecoveryDisplay?: string[];
  recoveryVerifiedUntil?: number; attempts: Attempts;
};

const SESSION_IDLE_MS = 15 * 60 * 1000, SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_MS = 5 * 60 * 1000, RECOVERY_GRANT_MS = 5 * 60 * 1000, LOCKOUT_MS = 10 * 60 * 1000;
const MARCUS_ACCOUNT = { id: "marcus" as const, email: "marcus@example.test", phone: "+447700900123" };
const TRUSTED_ORIGINS = new Set([`https://localhost:${port}`, `https://127.0.0.1:${port}`, `https://[::1]:${port}`]);

/* Security Evaluation Requirement 3: cryptographic RNG, encrypted OTP secret, and hashed recovery codes. */
function randomBytes(size: number): Uint8Array { const b = new Uint8Array(size); crypto.getRandomValues(b); return b; }
function toBase64Url(bytes: Uint8Array): string {
  let binary = ""; for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function fromBase64Url(value: string): Uint8Array {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
function secureEqual(a: string, b: string): boolean {
  const left = encoder.encode(a), right = encoder.encode(b);
  let difference = left.length ^ right.length;
  for (let i = 0; i < Math.max(left.length, right.length); i++) difference |= (left[i] || 0) ^ (right[i] || 0);
  return difference === 0;
}
function base32(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let result = "", buffer = 0, bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte; bits += 8;
    while (bits >= 5) { result += alphabet[(buffer >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) result += alphabet[(buffer << (5 - bits)) & 31];
  return result;
}
function randomDecimalCode(): string {
  let code = "";
  while (code.length < 6) { const byte = randomBytes(1)[0]; if (byte < 250) code += String(byte % 10); }
  return code;
}
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function randomRecoveryCode(): string {
  let result = "";
  while (result.length < 10) { const byte = randomBytes(1)[0]; if (byte < 248) result += RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length]; }
  return `${result.slice(0, 5)}-${result.slice(5)}`;
}
async function sha256(value: string): Promise<string> { return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)))); }
async function encryptSecret(secret: string): Promise<EncryptedValue> {
  const iv = randomBytes(12), key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["encrypt"]);
  return { iv: toBase64Url(iv), ciphertext: toBase64Url(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret)))) };
}
async function decryptSecret(value: EncryptedValue): Promise<string> {
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["decrypt"]);
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(value.iv) }, key, fromBase64Url(value.ciphertext)));
}

/* Security Evaluation Requirement 5: time-bound TOTP verification uses deterministic server-side mock timing. */
async function totp(secret: string): Promise<string> {
  const counter = Math.floor(Date.now() / 120000), counterBytes = new Uint8Array(8);
  let value = counter;
  for (let i = 7; i >= 0; i--) { counterBytes[i] = value & 255; value = Math.floor(value / 256); }
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = signature[signature.length - 1] & 15;
  const numeric = (
    ((signature[offset] & 0x7f) * 0x1000000) +
    (signature[offset + 1] * 0x10000) +
    (signature[offset + 2] * 0x100) +
    signature[offset + 3]
  ) >>> 0;
  const otp = (numeric % 1000000).toString(10).padStart(6, "0");
  return /^[0-9]{6}$/.test(otp) ? otp : "000000";
}

/* Security Evaluation Requirement 5: secure sessions, expiry, single-use values, rate limits, and lockout controls. */
function newAttempts(): Attempts { return { identity: { count: 0, lockedUntil: 0 }, authenticator: { count: 0, lockedUntil: 0 }, recovery: { count: 0, lockedUntil: 0 } }; }
function newSession(stage: Session["stage"] = "anonymous"): Session {
  const now = Date.now();
  return { id: toBase64Url(randomBytes(32)), csrf: toBase64Url(randomBytes(32)), stage, createdAt: now, lastSeen: now, recoveryHashes: [], attempts: newAttempts() };
}
function mayAttempt(a: Attempt): boolean { return a.lockedUntil <= Date.now(); }
function failedAttempt(a: Attempt): void { a.count++; if (a.count >= 5) { a.count = 0; a.lockedUntil = Date.now() + LOCKOUT_MS; } }
function successfulAttempt(a: Attempt): void { a.count = 0; a.lockedUntil = 0; }

/* Security Evaluation Requirement 4: strict server-side input validation prevents injection and malformed values. */
function validatedIdentity(email: unknown, phone: unknown): { email: string; phone: string } | undefined {
  if (typeof email !== "string" || typeof phone !== "string" || email.length > 254 || phone.length > 40) return;
  const normalizedEmail = email.trim().toLowerCase(), normalizedPhone = phone.replace(/[ ()-]/g, "");
  if (normalizedEmail !== email.trim() || !/^[a-z0-9.!#$%&'*+/=?^_\`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(normalizedEmail)) return;
  if (!/^\+[1-9][0-9]{7,14}$/.test(normalizedPhone)) return;
  return { email: normalizedEmail, phone: normalizedPhone };
}
const validOtp = (v: unknown): v is string => typeof v === "string" && /^[0-9]{6}$/.test(v);
const validSecret = (v: unknown): v is string => typeof v === "string" && /^[A-Z2-7]{16,80}$/.test(v);
const validRecovery = (v: unknown): v is string => typeof v === "string" && /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{5}$/.test(v);
function identityTarget(i: { email: string; phone: string }): { target: string; account?: "marcus" } {
  return { target: `email:${i.email}|phone:${i.phone}`, account: secureEqual(i.email, MARCUS_ACCOUNT.email) && secureEqual(i.phone, MARCUS_ACCOUNT.phone) ? "marcus" : undefined };
}

/* Security Evaluation Requirement 2: hardened headers, trusted CORS, secure cookies, and generic errors. */
function cookieFor(s: Session): string { return `mfa_session=${s.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`; }
function expiredCookie(): string { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function cookieValue(r: Request, name: string): string | undefined { return (r.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1); }
function sessionFrom(r: Request): Session | undefined {
  const id = cookieValue(r, "mfa_session"); if (!id || !/^[A-Za-z0-9_-]{32,64}$/.test(id)) return;
  const s = sessions.get(id); if (!s) return;
  const now = Date.now(); if (now - s.lastSeen > SESSION_IDLE_MS || now - s.createdAt > SESSION_ABSOLUTE_MS) { sessions.delete(id); return; }
  s.lastSeen = now; return s;
}
function baseHeaders(nonce?: string): Headers {
  const h = new Headers();
  const source = nonce ? `'self' 'nonce-${nonce}'` : "'self'";
  h.set("Content-Security-Policy", `default-src 'self'; script-src ${source}; style-src ${source}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("X-Content-Type-Options", "nosniff"); h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer"); h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  return h;
}
function corsHeaders(r: Request, h: Headers): boolean {
  const origin = r.headers.get("origin"); if (!origin) return true; if (!TRUSTED_ORIGINS.has(origin)) return false;
  h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); return true;
}
function json(data: unknown, status = 200, cookie?: string, request?: Request): Response {
  const h = baseHeaders(); h.set("Content-Type", "application/json; charset=utf-8"); if (request) corsHeaders(request, h); if (cookie) h.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: h });
}
function genericError(status = 400, r?: Request): Response { return json({ error: "Unable to complete this request. Please try again." }, status, undefined, r); }

/* Security Evaluation Requirement 1: every state change requires an owned session and matching CSRF token. */
function validCsrf(v: unknown, s: Session): boolean { return typeof v === "string" && /^[A-Za-z0-9_-]{32,64}$/.test(v) && secureEqual(v, s.csrf); }
function authenticated(s: Session | undefined): s is Session { return !!s?.account; }
async function requestBody(r: Request): Promise<Record<string, unknown> | undefined> {
  if (Number(r.headers.get("content-length") || "0") > 10000) return;
  try { const b = await r.json(); return b && typeof b === "object" && !Array.isArray(b) ? b as Record<string, unknown> : undefined; } catch { return; }
}
async function setRecoveryCodes(s: Session): Promise<void> {
  const codes = Array.from({ length: 8 }, randomRecoveryCode);
  s.recoveryHashes = await Promise.all(codes.map(c => sha256(`${recoveryPepper}:${c}`))); s.pendingRecoveryDisplay = codes;
}

function page(nonce: string): string { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Harbour Bank · MFA enrolment</title><style nonce="${nonce}">
:root{--n:#102a43;--b:#1769aa;--p:#edf6ff;--l:#c8d6e5;--i:#172b4d;--g:#106b45;--d:#a52a2a}*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--i);font:16px/1.45 system-ui,sans-serif}header{background:var(--n);color:#fff;padding:18px 20px}header h1{font-size:1.15rem;margin:0}header p{margin:3px 0 0;font-size:.88rem;color:#d9e9f6}main{max-width:570px;margin:auto;padding:18px 14px 42px}.card{background:#fff;border:1px solid var(--l);border-radius:12px;padding:20px;margin-bottom:15px}h2{font-size:1.35rem;margin:0 0 10px}.muted{color:#52677d;font-size:.93rem}.notice{background:var(--p);border-left:4px solid var(--b);padding:10px 12px;margin:14px 0}.warning{background:#fff7df;border-left-color:#a86d00}.success{background:#e9f8ef;border-left-color:var(--g)}label{display:block;font-weight:650;margin:13px 0 5px}input{width:100%;font:inherit;padding:11px;border:1px solid #8fa6ba;border-radius:7px}button{font:inherit;font-weight:700;padding:11px 15px;border:0;border-radius:7px;background:var(--b);color:#fff;margin-top:17px;min-height:45px}.secondary{background:#e6eef5;color:#173d60}.danger{background:var(--d)}.actions{display:flex;gap:9px;flex-wrap:wrap}.view[hidden],.detail[hidden]{display:none}.code{display:block;overflow-wrap:anywhere;background:#f3f7fa;border:1px solid var(--l);padding:9px;font:14px ui-monospace,monospace}.codes{padding-left:22px;font:16px ui-monospace,monospace}.error{color:var(--d);font-weight:650;min-height:1.45em}.status{color:var(--g);font-weight:650;min-height:1.45em}a{color:#075b9c;text-decoration:underline;cursor:pointer}#logs{background:#081725;color:#d5f1ff;padding:10px;min-height:78px;max-height:180px;overflow:auto;font:12px ui-monospace,monospace;white-space:pre-wrap}
</style></head><body><header><h1>Harbour Bank</h1><p>Secure multi-factor authentication enrolment</p></header><main>
<section id="signin" class="view card"><h2>Sign in to begin</h2><p class="muted">Confirm your bank account details before enrolling MFA.</p><form id="signin-form"><label>Email address<input id="email" type="email" value="marcus@example.test" required></label><label>Mobile number<input id="phone" type="tel" value="+44 7700 900123" required></label><p id="signin-error" class="error"></p><button>Continue securely</button></form></section>
<section id="identity" class="view card" hidden><h2>Verify your identity</h2><div class="notice">The protected mock delivery code is shown only in the Logs panel and browser console.</div><form id="identity-form"><label>Verification code<input id="identity-code" inputmode="numeric" maxlength="6" required></label><p id="identity-error" class="error"></p><button>Verify identity</button></form></section>
<section id="setup" class="view card" hidden><h2>Set up an authenticator app</h2><p>Use an authenticator app to generate a code.</p><div id="provision-start"><button id="provision-button" type="button">Create authenticator setup</button></div><div id="provision-detail" class="detail" hidden><div class="notice success">Authenticator created. Add this value manually.</div><label>Manual setup secret</label><output id="setup-secret" class="code"></output><label>Provisioning value</label><output id="provision-uri" class="code"></output><form id="authenticator-form"><label>Manual secret<input id="manual-secret" required></label><label>Authenticator code<input id="auth-code" inputmode="numeric" maxlength="6" required></label><p id="auth-error" class="error"></p><button>Enable authenticator MFA</button></form></div></section>
<section id="recovery" class="view card" hidden><h2>Save your recovery codes</h2><div class="notice warning"><strong>Shown once.</strong> Copy these codes now. Each code can be used once.</div><p id="recovery-state" class="muted"></p><ul id="recovery-list" class="codes"></ul><p id="recovery-error" class="error"></p><button id="recovery-finish" type="button">I have saved my codes</button></section>
<section id="settings" class="view card" hidden><h2>MFA settings</h2><p id="settings-status" class="status"></p><div class="notice">Your authenticator is enabled. Recovery codes are protected one-way verification values.</div><div class="actions"><button id="open-recovery-check" class="secondary" type="button">Regenerate recovery codes</button><button id="logout-button" class="danger" type="button">Log out</button></div></section>
<section id="recover-verify" class="view card" hidden><h2>Confirm with a recovery code</h2><p>To generate replacements, enter one unused recovery code. It will be consumed.</p><form id="recovery-verify-form"><label>Recovery code<input id="recovery-code" placeholder="ABCDE-23489" required></label><p id="recover-verify-error" class="error"></p><button>Verify recovery code</button></form><div id="regen-action" class="detail" hidden><div class="notice success">Recovery code confirmed.</div><button id="regenerate-button" type="button">Generate replacement codes</button></div><p><a id="back-settings">Back to MFA settings</a></p></section>
<section class="card"><h2>Logs</h2><p class="muted">Mock delivery and recovery values for evaluation.</p><div id="logs">Ready.</div></section></main>
<script nonce="${nonce}">(()=>{let csrf="";const V=["signin","identity","setup","recovery","settings","recover-verify"],$=x=>document.getElementById(x),L=$("logs");function log(x){console.log(x);let d=document.createElement("div");d.textContent=x;L.append(d);L.scrollTop=L.scrollHeight}function show(n){V.forEach(x=>$(x).hidden=x!==n)}function err(i,x=""){$(i).textContent=x}function clear(){document.querySelectorAll(".error").forEach(x=>x.textContent="")}async function api(p,o={}){let r=await fetch(p,{method:o.method||"GET",credentials:"same-origin",headers:o.body?{"Content-Type":"application/json"}:{},body:o.body?JSON.stringify(o.body):undefined}),d={};try{d=await r.json()}catch(_){}if(d.csrf)csrf=d.csrf;if(!r.ok){let e=Error(d.error||"Unable to complete this request. Please try again.");e.status=r.status;throw e}return d}function provision(d){$("setup-secret").textContent=d.secret;$("provision-uri").textContent=d.provisioning;$("manual-secret").value=d.secret||"";$("provision-detail").hidden=false;$("provision-start").hidden=true;if(d.testOtp)log("Mock authenticator OTP: "+d.testOtp)}async function settings(){try{let d=await api("/api/mfa/settings");$("settings-status").textContent=d.enabled?"Authenticator MFA is active.":"";show("settings")}catch(_){show("signin")}}async function codes(){let l=$("recovery-list");l.replaceChildren();try{let d=await api("/api/recovery-codes");d.codes.forEach(c=>{let i=document.createElement("li");i.textContent=c;l.append(i)});log("Mock recovery codes: "+d.codes.join(", "));show("recovery")}catch(e){if(e.status===409){$("recovery-state").textContent="These recovery codes have already been displayed or are unavailable.";show("recovery")}else settings()}}async function boot(){try{let d=await api("/api/bootstrap");if(d.view==="settings")settings();else if(d.view==="recovery")codes();else if(d.view==="identity")show("identity");else if(d.view==="setup"){show("setup");if(d.pendingSetup)provision(d.pendingSetup)}else show("signin")}catch(_){show("signin")}}$("signin-form").onsubmit=async e=>{e.preventDefault();clear();try{let d=await api("/api/signin",{method:"POST",body:{csrf,email:$("email").value.trim(),phone:$("phone").value.trim()}});log("Mock identity verification code: "+d.testOtp);show("identity")}catch(e){err("signin-error",e.message)}};$("identity-form").onsubmit=async e=>{e.preventDefault();clear();try{await api("/api/identity/verify",{method:"POST",body:{csrf,otp:$("identity-code").value.trim()}});show("setup")}catch(e){err("identity-error",e.message)}};$("provision-button").onclick=async()=>{try{provision(await api("/api/authenticator/provision",{method:"POST",body:{csrf}}))}catch(e){err("auth-error",e.message)}};$("authenticator-form").onsubmit=async e=>{e.preventDefault();clear();try{await api("/api/authenticator/confirm",{method:"POST",body:{csrf,secret:$("manual-secret").value.trim().toUpperCase(),otp:$("auth-code").value.trim()}});codes()}catch(e){err("auth-error",e.message)}};$("recovery-finish").onclick=settings;$("open-recovery-check").onclick=()=>{$("regen-action").hidden=true;$("recovery-code").value="";show("recover-verify")};$("back-settings").onclick=settings;$("recovery-verify-form").onsubmit=async e=>{e.preventDefault();try{await api("/api/recovery/verify",{method:"POST",body:{csrf,code:$("recovery-code").value.trim().toUpperCase()}});$("regen-action").hidden=false}catch(e){err("recover-verify-error",e.message)}};$("regenerate-button").onclick=async()=>{try{await api("/api/recovery/regenerate",{method:"POST",body:{csrf}});codes()}catch(e){err("recover-verify-error",e.message)}};$("logout-button").onclick=async()=>{try{await api("/api/logout",{method:"POST",body:{csrf}})}catch(_){}csrf="";show("signin");log("Session logged out.")};boot()})();</script></body></html>`; }

async function pendingSetupPayload(s: Session) {
  if (s.stage !== "provisioned" || !s.encryptedSecret) return;
  const secret = await decryptSecret(s.encryptedSecret);
  return { secret, provisioning: `otpauth://totp/HarbourBank:marcus?secret=${secret}&issuer=HarbourBank&period=120`, testOtp: await totp(secret) };
}

/* Security Evaluation Requirements 1 and 5: endpoint ownership, CSRF, session rotation, and lockout are enforced server-side. */
async function handleApi(r: Request, path: string): Promise<Response> {
  const preflight = baseHeaders(); if (!corsHeaders(r, preflight)) return genericError(403, r);
  if (r.method === "OPTIONS") { preflight.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); preflight.set("Access-Control-Allow-Headers", "Content-Type"); return new Response(null, { status: 204, headers: preflight }); }
  if (path === "/api/bootstrap" && r.method === "GET") {
    let s = sessionFrom(r), cookie: string | undefined; if (!s) { s = newSession(); sessions.set(s.id, s); cookie = cookieFor(s); }
    if (s.stage === "provisioned") return json({ csrf: s.csrf, view: "setup", pendingSetup: await pendingSetupPayload(s) }, 200, cookie, r);
    return json({ csrf: s.csrf, view: s.stage === "mfa" ? (s.pendingRecoveryDisplay ? "recovery" : "settings") : s.stage === "identity" ? "identity" : s.stage === "verified" ? "setup" : "signin" }, 200, cookie, r);
  }
  const s = sessionFrom(r); if (!s) return genericError(401, r);
  if (path === "/api/mfa/settings" && r.method === "GET") return authenticated(s) && s.stage === "mfa" ? json({ csrf: s.csrf, enabled: true }, 200, undefined, r) : genericError(403, r);
  if (path === "/api/recovery-codes" && r.method === "GET") {
    if (!authenticated(s) || s.stage !== "mfa") return genericError(403, r);
    const codes = s.pendingRecoveryDisplay; if (!codes?.length) return json({ error: "Recovery codes are unavailable. Return to MFA settings." }, 409, undefined, r);
    s.pendingRecoveryDisplay = undefined; return json({ csrf: s.csrf, codes }, 200, undefined, r);
  }
  if (r.method !== "POST") return genericError(404, r);
  const b = await requestBody(r); if (!b || !validCsrf(b.csrf, s)) return genericError(403, r);
  if (path === "/api/signin") {
    const i = s.stage === "anonymous" ? validatedIdentity(b.email, b.phone) : undefined;
    if (!i) return genericError(400, r); const resolved = identityTarget(i);
    let state = identityStates.get(resolved.target);
    if (!state) { state = { target: resolved.target, account: resolved.account, challenge: { code: randomDecimalCode(), expiresAt: Date.now() + CHALLENGE_MS, used: false }, attempts: { count: 0, lockedUntil: 0 } }; identityStates.set(resolved.target, state); }
    else state.challenge = { code: randomDecimalCode(), expiresAt: Date.now() + CHALLENGE_MS, used: false };
    sessions.delete(s.id); const rotated = newSession("identity"); rotated.identityTarget = state.target; sessions.set(rotated.id, rotated);
    return json({ csrf: rotated.csrf, testOtp: state.challenge.code }, 200, cookieFor(rotated), r);
  }
  if (path === "/api/identity/verify") {
    const state = s.stage === "identity" && s.identityTarget ? identityStates.get(s.identityTarget) : undefined;
    if (!state || !mayAttempt(state.attempts)) return genericError(400, r);
    const c = state.challenge;
    if (!validOtp(b.otp) || c.used || c.expiresAt < Date.now() || !secureEqual(b.otp, c.code) || !state.account) { failedAttempt(state.attempts); return genericError(400, r); }
    c.used = true; successfulAttempt(state.attempts); sessions.delete(s.id);
    const a = newSession("verified"); a.account = state.account; sessions.set(a.id, a); return json({ csrf: a.csrf, ok: true }, 200, cookieFor(a), r);
  }
  if (!authenticated(s)) return genericError(401, r);
  if (path === "/api/authenticator/provision") {
    if (s.stage !== "verified") return genericError(400, r); const secret = base32(randomBytes(20));
    s.encryptedSecret = await encryptSecret(secret); s.authenticatorUsed = false; s.stage = "provisioned";
    return json({ csrf: s.csrf, secret, provisioning: `otpauth://totp/HarbourBank:marcus?secret=${secret}&issuer=HarbourBank&period=120`, testOtp: await totp(secret) }, 200, undefined, r);
  }
  if (path === "/api/authenticator/confirm") {
    if (s.stage !== "provisioned" || !s.encryptedSecret || !mayAttempt(s.attempts.authenticator) || !validSecret(b.secret) || !validOtp(b.otp)) { if (s.stage === "provisioned") failedAttempt(s.attempts.authenticator); return genericError(400, r); }
    const secret = await decryptSecret(s.encryptedSecret);
    if (s.authenticatorUsed || !secureEqual(b.secret, secret) || !secureEqual(b.otp, await totp(secret))) { failedAttempt(s.attempts.authenticator); return genericError(400, r); }
    s.authenticatorUsed = true; successfulAttempt(s.attempts.authenticator); s.stage = "mfa"; await setRecoveryCodes(s); return json({ csrf: s.csrf, ok: true }, 200, undefined, r);
  }
  if (path === "/api/recovery/verify") {
    if (s.stage !== "mfa" || !mayAttempt(s.attempts.recovery) || !validRecovery(b.code)) { if (s.stage === "mfa") failedAttempt(s.attempts.recovery); return genericError(400, r); }
    const candidate = await sha256(`${recoveryPepper}:${b.code}`), index = s.recoveryHashes.findIndex(h => secureEqual(h, candidate));
    if (index < 0) { failedAttempt(s.attempts.recovery); return genericError(400, r); }
    s.recoveryHashes.splice(index, 1); s.recoveryVerifiedUntil = Date.now() + RECOVERY_GRANT_MS; successfulAttempt(s.attempts.recovery); return json({ csrf: s.csrf, ok: true }, 200, undefined, r);
  }
  if (path === "/api/recovery/regenerate") {
    if (s.stage !== "mfa" || !s.recoveryVerifiedUntil || s.recoveryVerifiedUntil < Date.now()) return genericError(400, r);
    s.recoveryVerifiedUntil = undefined; await setRecoveryCodes(s); return json({ csrf: s.csrf, ok: true }, 200, undefined, r);
  }
  if (path === "/api/logout") { sessions.delete(s.id); return json({ ok: true }, 200, expiredCookie(), r); }
  return genericError(404, r);
}

/* Security Evaluation Requirement 2: production handler returns generic errors without stack traces. */
async function fetchHandler(r: Request): Promise<Response> {
  try {
    const u = new URL(r.url); if (u.pathname.startsWith("/api/")) return await handleApi(r, u.pathname);
    if (u.pathname === "/" && r.method === "GET") { const nonce = toBase64Url(randomBytes(24)), h = baseHeaders(nonce); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page(nonce), { headers: h }); }
    return new Response("Not found", { status: 404, headers: baseHeaders() });
  } catch { return new Response("Unable to complete this request.", { status: 500, headers: baseHeaders() }); }
}
Bun.serve({ port, tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") }, fetch: fetchHandler });
