
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/*
 Requirements 1–5: single-process, deterministic demo state. Production systems
 would use a durable credential store, encrypted key management, and audit trail.
*/
type AttemptState = { failures: number; lockUntil: number };
type EncryptedValue = { iv: string; ciphertext: string };
type Session = {
  userId?: string; csrf: string; createdAt: number; lastSeen: number;
  identityVerified: boolean; identityHash?: string; identityExpires?: number;
  identityUsed?: boolean; identityAttempts: AttemptState;
};
type Account = {
  id: string; totpSecret?: EncryptedValue; totpUsedSteps: Set<number>;
  totpAttempts: AttemptState; recoveryAttempts: AttemptState;
  mfaEnabled: boolean; recoveryCodes: Map<string, boolean>;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const activeIdentityHashes = new Set<string>();

/*
 Task requirement: sign-in limiter is independent of anonymous sessions. Keys are
 canonical login identifiers plus server-observed client address buckets.
*/
const signInAttempts = new Map<string, AttemptState>();

const encryptionKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const hashPepper = crypto.getRandomValues(new Uint8Array(32));
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_LIFETIME_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const TRUSTED_ACCOUNT_ID = "acct_trusted_marcus_demo";
const DEMO_LOGIN = "marcus";
const DEMO_PASSWORD = "Northstar!2025";

function randomBytes(n: number): Uint8Array { return crypto.getRandomValues(new Uint8Array(n)); }
function hex(v: Uint8Array): string { return Array.from(v, x => x.toString(16).padStart(2, "0")).join(""); }
function token(n = 32): string { return hex(randomBytes(n)); }
function b64(v: ArrayBuffer | Uint8Array): string {
  return Buffer.from(v instanceof Uint8Array ? v : new Uint8Array(v)).toString("base64");
}
function unb64(v: string): Uint8Array { return new Uint8Array(Buffer.from(v, "base64")); }
function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  let different = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) different |= (a[i % a.length] || 0) ^ (b[i % b.length] || 0);
  return different === 0;
}
function base32Encode(data: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, current = 0, out = "";
  for (const byte of data) {
    current = (current << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(current >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits) out += alphabet[(current << (5 - bits)) & 31];
  return out;
}
function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.toUpperCase().replace(/[=\s]/g, "");
  const out: number[] = []; let bits = 0, current = 0;
  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("invalid");
    current = (current << 5) | index; bits += 5;
    if (bits >= 8) { out.push((current >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

/* Requirement 3: AES-GCM at rest for the retained authenticator secret. */
async function encryptValue(value: string): Promise<EncryptedValue> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(12);
  return { iv: b64(iv), ciphertext: b64(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value))) };
}
async function decryptValue(value: EncryptedValue): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["decrypt"]);
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, key, unb64(value.ciphertext)));
}
async function protectedHash(value: string): Promise<string> {
  const raw = encoder.encode(value), input = new Uint8Array(hashPepper.length + raw.length);
  input.set(hashPepper); input.set(raw, hashPepper.length);
  return b64(await crypto.subtle.digest("SHA-256", input));
}

/*
 Task requirement: every credential validation does exactly two SHA-256
 calculations over fixed-width fields, then constant-time compares. Invalid and
 unknown login values are represented by a fixed invalid field, rather than
 taking a shorter/plaintext comparison route.
*/
function normalizedLogin(value: unknown): { value: string; valid: boolean } {
  if (typeof value !== "string") return { value: "", valid: false };
  const canonical = value.normalize("NFKC").trim().toLowerCase();
  return { value: canonical, valid: /^[a-z0-9._@-]{1,128}$/.test(canonical) };
}
function fixedField(value: unknown, valid: boolean, label: number): Uint8Array {
  const field = new Uint8Array(258);
  field[0] = label;
  if (!valid || typeof value !== "string") { field[1] = 255; return field; }
  const raw = encoder.encode(value);
  if (raw.length > 255) { field[1] = 255; return field; }
  field[1] = raw.length;
  field.set(raw, 2);
  return field;
}
async function credentialHash(value: unknown, valid: boolean, label: number): Promise<Uint8Array> {
  const field = fixedField(value, valid, label);
  const input = new Uint8Array(hashPepper.length + field.length);
  input.set(hashPepper); input.set(field, hashPepper.length);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}
const DEMO_LOGIN_HASH = await credentialHash(DEMO_LOGIN, true, 1);
const DEMO_PASSWORD_HASH = await credentialHash(DEMO_PASSWORD, true, 2);
async function uniformlyValidateCredentials(login: unknown, password: unknown): Promise<{ valid: boolean; login: string }> {
  const normalized = normalizedLogin(login);
  const passwordValid = typeof password === "string" && encoder.encode(password).length <= 255;
  const submittedLoginHash = await credentialHash(normalized.value, normalized.valid, 1);
  const submittedPasswordHash = await credentialHash(password, passwordValid, 2);
  const loginMatch = ctEqual(submittedLoginHash, DEMO_LOGIN_HASH) ? 1 : 0;
  const passwordMatch = ctEqual(submittedPasswordHash, DEMO_PASSWORD_HASH) ? 1 : 0;
  return { valid: (loginMatch & passwordMatch) === 1, login: normalized.valid ? normalized.value : "invalid-login" };
}

async function totpForStep(secret: string, step: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const message = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { message[i] = Number(n & 255n); n >>= 8n; }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[digest.length - 1] & 15;
  const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(number % 1000000).padStart(6, "0");
}
function sixDigits(): string {
  for (;;) {
    const r = randomBytes(3), n = (r[0] << 16) | (r[1] << 8) | r[2];
    if (n < 16000000) return String(n % 1000000).padStart(6, "0");
  }
}
async function uniqueIdentityCode(): Promise<{ code: string; hash: string }> {
  for (;;) {
    const code = sixDigits(), hash = await protectedHash(code);
    if (!activeIdentityHashes.has(hash)) { activeIdentityHashes.add(hash); return { code, hash }; }
  }
}
function clearChallenge(s: Session): void {
  if (s.identityHash) activeIdentityHashes.delete(s.identityHash);
  s.identityHash = undefined; s.identityExpires = undefined; s.identityUsed = undefined;
}
function accountFor(id: string): Account {
  let account = accounts.get(id);
  if (!account) {
    account = {
      id, totpSecret: undefined, totpUsedSteps: new Set(),
      totpAttempts: { failures: 0, lockUntil: 0 },
      recoveryAttempts: { failures: 0, lockUntil: 0 },
      mfaEnabled: false, recoveryCodes: new Map(),
    };
    accounts.set(id, account);
  }
  return account;
}
function cookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const piece of (request.headers.get("cookie") || "").split(";")) {
    const at = piece.indexOf("=");
    if (at > 0) result[piece.slice(0, at).trim()] = piece.slice(at + 1).trim();
  }
  return result;
}
function sessionCookie(id: string): string {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_IDLE_MS / 1000}`;
}
function expiredCookie(): string { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function createSession(userId?: string): [string, Session] {
  const id = token(), now = Date.now();
  const session: Session = { userId, csrf: token(), createdAt: now, lastSeen: now, identityVerified: false, identityAttempts: { failures: 0, lockUntil: 0 } };
  sessions.set(id, session); return [id, session];
}
function destroySession(id: string): void { const s = sessions.get(id); if (s) clearChallenge(s); sessions.delete(id); }
function readSession(request: Request): { id: string; session: Session } | undefined {
  const id = cookies(request).mfa_session;
  if (!id || !/^[a-f0-9]{64}$/.test(id)) return;
  const session = sessions.get(id);
  if (!session) return;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) { destroySession(id); return; }
  session.lastSeen = now;
  return { id, session };
}
function authenticated(request: Request): { id: string; session: Session; account: Account } | undefined {
  const active = readSession(request);
  return active?.session.userId ? { ...active, account: accountFor(active.session.userId) } : undefined;
}
function forbiddenIdentity(body: Record<string, unknown>): boolean {
  return ["userId", "accountId", "email", "identity", "account", "customerId"].some(k => Object.prototype.hasOwnProperty.call(body, k));
}
function csrfValid(body: any, session: Session): boolean {
  return !!body && typeof body.csrf === "string" && /^[a-f0-9]{64}$/.test(body.csrf) && body.csrf === session.csrf && !forbiddenIdentity(body);
}
function safeOtp(x: unknown): x is string { return typeof x === "string" && /^\d{6}$/.test(x); }
function safeRecovery(x: unknown): x is string { return typeof x === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(x); }
function validRedirect(x: unknown): boolean { return x === undefined || ["#/signin", "#/identity", "#/setup", "#/confirmed", "#/recovery"].includes(x as string); }
function allowed(s: AttemptState): boolean { return Date.now() >= s.lockUntil; }
function fail(s: AttemptState): void {
  if (!allowed(s)) return;
  s.failures++;
  if (s.failures >= MAX_FAILURES) { s.failures = 0; s.lockUntil = Date.now() + LOCK_MS; }
}
function reset(s: AttemptState): void { s.failures = 0; s.lockUntil = 0; }
function signInState(login: string, bucket: string): AttemptState {
  const key = `${bucket}|${login}`;
  let state = signInAttempts.get(key);
  if (!state) { state = { failures: 0, lockUntil: 0 }; signInAttempts.set(key, state); }
  if (signInAttempts.size > 10000) {
    for (const [k, v] of signInAttempts) if (v.lockUntil < Date.now() - LOCK_MS) signInAttempts.delete(k);
  }
  return state;
}
function recoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", bytes: number[] = [];
  while (bytes.length < 12) {
    const byte = randomBytes(1)[0], limit = 256 - (256 % alphabet.length);
    if (byte < limit) bytes.push(byte);
  }
  const raw = bytes.map(x => alphabet[x % alphabet.length]).join("");
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8)}`;
}
async function newRecoveryCodes(account: Account): Promise<string[]> {
  account.recoveryCodes.clear();
  const out: string[] = [];
  for (let i = 0; i < 8; i++) { const code = recoveryCode(); out.push(code); account.recoveryCodes.set(await protectedHash(code), false); }
  return out;
}

function trustedOrigin(origin: string | null): boolean {
  return !!origin && /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(origin);
}
function headers(nonce?: string, origin?: string | null): Headers {
  const h = new Headers({
    "Content-Security-Policy": nonce ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'` : "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
  });
  if (trustedOrigin(origin)) { h.set("Access-Control-Allow-Origin", origin!); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); }
  return h;
}
function reply(data: unknown, status = 200, extra?: Record<string, string>, origin?: string | null): Response {
  const h = headers(undefined, origin); h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) for (const [k, v] of Object.entries(extra)) h.set(k, v);
  return new Response(JSON.stringify(data), { status, headers: h });
}
async function bodyOf(request: Request): Promise<Record<string, unknown> | undefined> {
  const text = await request.text();
  if (text.length > 4096) return;
  try { const x = JSON.parse(text); return x && typeof x === "object" && !Array.isArray(x) ? x : undefined; } catch { return; }
}

function page(nonce: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>Northstar Bank — MFA enrolment</title>
<style nonce="${nonce}">
:root{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#10233d;background:#edf3f8}*{box-sizing:border-box}body{margin:0;min-width:280px}.shell{width:min(100%,520px);min-height:100vh;margin:auto;padding:20px 18px 30px;background:#fff;box-shadow:0 0 25px #b9c6d3}header{border-bottom:1px solid #d7e0ea;padding-bottom:16px;margin-bottom:20px}.brand{font-size:14px;font-weight:800;letter-spacing:.08em;color:#176b59;text-transform:uppercase}.title{font-size:26px;margin:7px 0 0}h2{font-size:22px;margin:0 0 10px}p{font-size:16px;line-height:1.5;color:#40536a}.hint{font-size:14px;color:#5d6d80}.card{background:#f6f9fc;border:1px solid #d9e3ed;border-radius:12px;padding:16px;margin:16px 0}.success{border-left:4px solid #168163}label{display:block;font-weight:700;margin:16px 0 7px}input{width:100%;font-size:18px;padding:13px;border:1px solid #91a4b7;border-radius:8px}button{width:100%;border:0;border-radius:8px;background:#086a58;color:white;font-size:16px;font-weight:750;padding:14px;margin-top:18px;cursor:pointer}button.secondary{background:#e3ebf1;color:#15324b}button:focus,input:focus,a:focus{outline:3px solid #e8a72a;outline-offset:2px}code{display:block;overflow-wrap:anywhere;background:#e8f0f6;border-radius:6px;padding:10px;font-size:14px}ul.codes{list-style:none;padding:0;margin:12px 0}.codes li{background:#edf5f2;padding:10px;margin:5px 0;border-radius:6px;font-family:ui-monospace,monospace}.error{background:#fff0ef;border-left:4px solid #c1302d;color:#74201d;padding:11px;margin:14px 0;border-radius:5px}nav{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}nav a{color:#075b4c;font-weight:700}.logs{margin-top:28px;border-top:1px solid #d7e0ea;padding-top:15px}.logs summary{font-weight:750}.logbox{max-height:160px;overflow:auto;background:#101d2c;color:#d8f3e9;font:12px/1.4 ui-monospace,monospace;padding:10px;border-radius:8px;white-space:pre-wrap}
</style></head><body><main class="shell"><header><div class="brand">Northstar Bank</div><h1 class="title">MFA enrolment</h1></header><section id="app" aria-live="polite"><p>Loading secure enrolment…</p></section><details class="logs" open><summary>Logs (test simulation)</summary><div id="logbox" class="logbox">No client simulation values yet.</div></details></main>
<script nonce="${nonce}">(function(){"use strict";
var state={csrf:"",auth:false,identity:false,mfa:false,secret:"",codes:[]},app=document.getElementById("app"),box=document.getElementById("logbox");
function log(x){console.log(x);box.textContent=(box.textContent==="No client simulation values yet."?"":box.textContent+"\\n")+x;box.scrollTop=box.scrollHeight}
function error(x){var d=document.createElement("div");d.className="error";d.textContent=x;app.prepend(d)}
async function api(path,data){var r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(data||{})}),x;try{x=await r.json()}catch(e){throw Error("Unable to complete that request.")}if(!r.ok||!x.ok)throw Error(x.error||"Unable to complete that request.");if(x.csrf)state.csrf=x.csrf;return x}
async function status(){var x=await api("/api/status",{});state.auth=x.auth===true;state.identity=x.identity===true;state.mfa=x.mfa===true}
function el(n,t){var x=document.createElement(n);if(t)x.textContent=t;return x}function link(t,h){var a=el("a",t);a.href=h;return a}
function nav(){var n=el("nav");if(state.auth)n.append(link("Authenticator","#/setup"),link("Recovery codes","#/recovery"),link("Log out","#/logout"));return n}
function put(f){app.replaceChildren(f,nav())}function title(h,p){var f=document.createDocumentFragment();f.append(el("h2",h),el("p",p));return f}
function signin(){var f=title("Sign in","Use the trusted demo credentials to begin MFA enrolment."),c=el("div","Demo credentials: Login name Marcus · Password Northstar!2025"),form=el("form"),a=el("input"),b=el("input"),go=el("button","Sign in");c.className="card hint";a.required=true;a.autocomplete="username";b.required=true;b.type="password";b.autocomplete="current-password";form.append(el("label","Login name"),a,el("label","Password"),b,go);form.onsubmit=async function(e){e.preventDefault();try{var x=await api("/api/signin",{login:a.value,password:b.value,csrf:state.csrf,redirect:"#/identity"});state.auth=true;state.identity=false;state.mfa=false;state.secret="";state.codes=[];log("Simulated identity verification code: "+x.testCode);location.hash="#/identity"}catch(x){error(x.message)}};f.append(c,form);put(f)}
function identity(){if(!state.auth){location.hash="#/signin";return}var f=title("Verify your identity","We sent a short-lived verification code to your registered contact method."),c=el("div","Test simulation: the code is available in the Logs panel and browser console."),form=el("form"),i=el("input"),go=el("button","Verify identity");c.className="card hint";i.inputMode="numeric";i.maxLength=6;i.autocomplete="one-time-code";form.append(el("label","Verification code"),i,go);form.onsubmit=async function(e){e.preventDefault();try{await api("/api/identity/verify",{code:i.value,csrf:state.csrf});state.identity=true;location.hash="#/setup"}catch(x){error(x.message)}};f.append(c,form);put(f)}
function b32(v){var a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",bits=0,n=0,o=[];v=v.replace(/[=\\s]/g,"").toUpperCase();for(var j=0;j<v.length;j++){var q=a.indexOf(v[j]);if(q<0)throw Error("bad");n=(n<<5)|q;bits+=5;if(bits>=8){o.push((n>>>(bits-8))&255);bits-=8}}return Uint8Array.from(o)}
async function totp(s){var k=await crypto.subtle.importKey("raw",b32(s),{name:"HMAC",hash:"SHA-1"},false,["sign"]),step=Math.floor(Date.now()/30000),m=new Uint8Array(8),z=BigInt(step);for(var j=7;j>=0;j--){m[j]=Number(z&255n);z>>=8n}var d=new Uint8Array(await crypto.subtle.sign("HMAC",k,m)),o=d[d.length-1]&15,n=((d[o]&127)<<24)|(d[o+1]<<16)|(d[o+2]<<8)|d[o+3];return String(n%1000000).padStart(6,"0")}
function setup(){if(!state.auth){location.hash="#/signin";return}if(!state.identity){location.hash="#/identity";return}var f=title("Set up an authenticator","Use an authenticator app to scan the provisioning value, or enter the manual secret."),start=el("button",state.secret?"Create replacement authenticator secret":"Create authenticator secret"),d=el("div"),form=el("form"),i=el("input"),go=el("button","Enable MFA and show recovery codes");d.className="card";i.inputMode="numeric";i.maxLength=6;i.autocomplete="one-time-code";form.append(el("label","Authenticator code"),i,go);form.hidden=!state.secret;start.onclick=async function(){try{var x=await api("/api/mfa/provision",{csrf:state.csrf});state.secret=x.manualSecret;d.replaceChildren(el("p","Manual secret (enter this in your authenticator):"),el("code",x.manualSecret),el("p","Provisioning representation:"),el("code",x.provisioningUri),el("p","Test code logged. Codes rotate every 30 seconds."));d.lastChild.className="hint";form.hidden=false;log("Simulated current authenticator code: "+await totp(state.secret))}catch(x){error(x.message)}};form.onsubmit=async function(e){e.preventDefault();try{var x=await api("/api/mfa/verify",{otp:i.value,csrf:state.csrf});state.mfa=true;state.codes=x.recoveryCodes;state.secret="";log("Simulated recovery codes: "+x.recoveryCodes.join(", "));location.hash="#/confirmed"}catch(x){error(x.message)}};f.append(start,d,form);put(f)}
function codes(a){var u=el("ul");u.className="codes";a.forEach(function(x){u.append(el("li",x))});return u}
function confirmed(){if(!state.mfa){location.hash="#/setup";return}var f=title("MFA is enabled","Store these recovery codes somewhere secure. Each code works once."),c=el("div");c.className="card success";c.append(codes(state.codes),el("p","They are shown only in this browser flow and were also logged for this simulation."));f.append(c,link("Manage recovery codes","#/recovery"));put(f)}
function recovery(){if(!state.mfa){location.hash="#/setup";return}var f=title("Recovery codes","Use a code if your authenticator is unavailable, or replace the remaining code set."),form=el("form"),i=el("input"),go=el("button","Use recovery code"),regen=el("button","Generate replacement recovery codes");i.placeholder="ABCD-EFGH-JKLM";i.autocomplete="one-time-code";form.append(el("label","Recovery code"),i,go);form.onsubmit=async function(e){e.preventDefault();try{await api("/api/mfa/recovery/use",{code:i.value.toUpperCase(),csrf:state.csrf});var x=el("div","Recovery code accepted and permanently used.");x.className="card success";f.insertBefore(x,form)}catch(x){error(x.message)}};regen.className="secondary";regen.onclick=async function(){try{var x=await api("/api/mfa/recovery/regenerate",{csrf:state.csrf});state.codes=x.recoveryCodes;log("Replacement recovery codes: "+x.recoveryCodes.join(", "));location.hash="#/confirmed"}catch(x){error(x.message)}};f.append(form,regen);put(f)}
async function logout(){try{await api("/api/logout",{csrf:state.csrf});state={csrf:"",auth:false,identity:false,mfa:false,secret:"",codes:[]};await api("/api/bootstrap",{});location.hash="#/signin"}catch(x){error(x.message)}}
function render(){var r=location.hash||(state.auth?(state.identity?(state.mfa?"#/recovery":"#/setup"):"#/identity"):"#/signin");if(r==="#/signin")signin();else if(r==="#/identity")identity();else if(r==="#/setup")setup();else if(r==="#/confirmed")confirmed();else if(r==="#/recovery")recovery();else if(r==="#/logout")logout();else location.hash="#/signin"}window.addEventListener("hashchange",render);(async function(){try{await api("/api/bootstrap",{});await status();render()}catch(e){app.textContent="Unable to start secure enrolment."}})();
})();</script></body></html>`;
}

async function handleApi(request: Request, path: string, clientBucket: string): Promise<Response> {
  const origin = request.headers.get("origin");
  if (request.method === "OPTIONS") {
    const h = headers(undefined, origin);
    h.set("Access-Control-Allow-Methods", "POST, OPTIONS"); h.set("Access-Control-Allow-Headers", "Content-Type");
    return new Response(null, { status: 204, headers: h });
  }
  if (request.method !== "POST") return reply({ ok: false, error: "Request unavailable." }, 405, undefined, origin);
  const body = await bodyOf(request);
  if (!body) return reply({ ok: false, error: "Unable to complete that request." }, 400, undefined, origin);

  if (path === "/api/bootstrap") {
    const current = readSession(request);
    if (current) return reply({ ok: true, csrf: current.session.csrf }, 200, undefined, origin);
    const [id, s] = createSession();
    return reply({ ok: true, csrf: s.csrf }, 200, { "Set-Cookie": sessionCookie(id) }, origin);
  }
  if (path === "/api/status") {
    const active = authenticated(request);
    return active ? reply({ ok: true, auth: true, identity: active.session.identityVerified, mfa: active.account.mfaEnabled, csrf: active.session.csrf }, 200, undefined, origin) : reply({ ok: true, auth: false }, 200, undefined, origin);
  }

  if (path === "/api/signin") {
    const existing = readSession(request);
    const credentials = await uniformlyValidateCredentials(body.login, body.password);
    const limiter = signInState(credentials.login, clientBucket);
    const allowedKeys = ["login", "password", "csrf", "redirect"];
    const structureValid = Object.keys(body).every(k => allowedKeys.includes(k)) && validRedirect(body.redirect);
    const requestValid = !!existing && csrfValid(body, existing.session) && structureValid;

    /*
     Task requirement: locked, unknown-login, and wrong-password attempts all
     return precisely the same generic response. The map survives session
     creation/destruction; it is keyed by server-observed client bucket + login.
    */
    if (!requestValid || !allowed(limiter) || !credentials.valid) {
      if (requestValid) fail(limiter);
      return reply({ ok: false, error: "Unable to continue sign-in." }, 400, undefined, origin);
    }

    reset(limiter); // Reset only after the complete successful authentication.
    destroySession(existing!.id); // Requirement 5: rotate session after authentication.
    const [id, session] = createSession(TRUSTED_ACCOUNT_ID);
    accountFor(TRUSTED_ACCOUNT_ID);
    const challenge = await uniqueIdentityCode();
    session.identityHash = challenge.hash; session.identityExpires = Date.now() + OTP_LIFETIME_MS;
    session.identityUsed = false; session.identityVerified = false; reset(session.identityAttempts);
    /* Test-only value is returned to this newly authenticated browser, never server logged. */
    return reply({ ok: true, csrf: session.csrf, testCode: challenge.code }, 200, { "Set-Cookie": sessionCookie(id) }, origin);
  }

  const active = authenticated(request);
  if (!active) return reply({ ok: false, error: "Your secure session is unavailable. Please sign in again." }, 401, { "Set-Cookie": expiredCookie() }, origin);
  if (!csrfValid(body, active.session)) return reply({ ok: false, error: "Unable to complete that request." }, 403, undefined, origin);

  if (path === "/api/identity/verify") {
    const s = active.session;
    const submittedHash = safeOtp(body.code) ? await protectedHash(body.code) : "";
    const good = safeOtp(body.code) && allowed(s.identityAttempts) && !s.identityUsed && !!s.identityExpires && Date.now() <= s.identityExpires && !!s.identityHash && submittedHash === s.identityHash;
    if (!good) { fail(s.identityAttempts); return reply({ ok: false, error: "That verification could not be accepted. Please try again later." }, 400, undefined, origin); }
    s.identityUsed = true; s.identityVerified = true; activeIdentityHashes.delete(s.identityHash!); reset(s.identityAttempts);
    return reply({ ok: true, csrf: s.csrf }, 200, undefined, origin);
  }

  if (!active.session.identityVerified) return reply({ ok: false, error: "Identity verification is required first." }, 403, undefined, origin);

  if (path === "/api/mfa/provision") {
    const secret = base32Encode(randomBytes(20));
    active.account.totpSecret = await encryptValue(secret); active.account.totpUsedSteps.clear(); reset(active.account.totpAttempts);
    const label = "NorthstarBank:Marcus";
    return reply({ ok: true, csrf: active.session.csrf, manualSecret: secret, provisioningUri: `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=NorthstarBank&period=30&digits=6` }, 200, undefined, origin);
  }
  if (path === "/api/mfa/verify") {
    const account = active.account;
    if (!safeOtp(body.otp) || !account.totpSecret || !allowed(account.totpAttempts)) { fail(account.totpAttempts); return reply({ ok: false, error: "That authenticator code could not be accepted. Please try again later." }, 400, undefined, origin); }
    const secret = await decryptValue(account.totpSecret), now = Math.floor(Date.now() / 30000);
    let accepted: number | undefined;
    for (const step of [now - 1, now, now + 1]) if (!account.totpUsedSteps.has(step) && body.otp === await totpForStep(secret, step)) { accepted = step; break; }
    if (accepted === undefined) { fail(account.totpAttempts); return reply({ ok: false, error: "That authenticator code could not be accepted. Please try again later." }, 400, undefined, origin); }
    account.totpUsedSteps.add(accepted);
    for (const old of account.totpUsedSteps) if (old < now - 3) account.totpUsedSteps.delete(old);
    reset(account.totpAttempts); account.mfaEnabled = true;
    return reply({ ok: true, csrf: active.session.csrf, recoveryCodes: await newRecoveryCodes(account) }, 200, undefined, origin);
  }
  if (path === "/api/mfa/recovery/use") {
    const account = active.account;
    if (!account.mfaEnabled || !safeRecovery(body.code) || !allowed(account.recoveryAttempts)) { fail(account.recoveryAttempts); return reply({ ok: false, error: "That recovery code could not be accepted. Please try again later." }, 400, undefined, origin); }
    const hash = await protectedHash(body.code);
    if (account.recoveryCodes.get(hash) !== false) { fail(account.recoveryAttempts); return reply({ ok: false, error: "That recovery code could not be accepted." }, 400, undefined, origin); }
    account.recoveryCodes.set(hash, true); reset(account.recoveryAttempts);
    return reply({ ok: true, csrf: active.session.csrf }, 200, undefined, origin);
  }
  if (path === "/api/mfa/recovery/regenerate") {
    if (!active.account.mfaEnabled) return reply({ ok: false, error: "Unable to complete that request." }, 403, undefined, origin);
    return reply({ ok: true, csrf: active.session.csrf, recoveryCodes: await newRecoveryCodes(active.account) }, 200, undefined, origin);
  }
  if (path === "/api/logout") {
    destroySession(active.id);
    return reply({ ok: true }, 200, { "Set-Cookie": expiredCookie() }, origin);
  }
  return reply({ ok: false, error: "Request unavailable." }, 404, undefined, origin);
}

const port = Number(Bun.env.PORT || 3000);
Bun.serve({
  port, hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request, server) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") return new Response("HTTPS required", { status: 400, headers: headers() });
      /*
       The address comes from Bun's server socket API, not spoofable client
       headers such as X-Forwarded-For. The fallback remains server controlled.
      */
      const address = server.requestIP(request)?.address || "unavailable-client";
      const bucket = address.includes(":") ? address.split(":").slice(0, 4).join(":") : address;
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = token(16), h = headers(nonce, request.headers.get("origin"));
        h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname, bucket);
      return new Response("Not found", { status: 404, headers: headers(undefined, request.headers.get("origin")) });
    } catch {
      return new Response("Unable to process request.", { status: 500, headers: headers() });
    }
  },
});
console.log(`MFA enrolment demo listening at https://localhost:${port}`);
