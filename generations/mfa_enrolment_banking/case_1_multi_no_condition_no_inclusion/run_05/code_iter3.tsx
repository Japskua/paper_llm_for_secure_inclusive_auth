
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/*
 * MFA Enrolment System
 * Requirements 1–5: all state is deterministic in-memory demo state. Production
 * deployments would use durable encrypted storage and a credential provider.
 */

type AttemptState = { failures: number; lockUntil: number };
type EncryptedValue = { iv: string; ciphertext: string };
type Session = {
  userId?: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  identityVerified: boolean;
  identityHash?: string;
  identityExpires?: number;
  identityUsed?: boolean;
  identityAttempts: AttemptState;
};
type Account = {
  id: string;
  totpSecret?: EncryptedValue;
  totpUsedSteps: Set<number>;
  totpAttempts: AttemptState;
  recoveryAttempts: AttemptState;
  mfaEnabled: boolean;
  recoveryCodes: Map<string, boolean>;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const activeIdentityHashes = new Set<string>();

const encryptionKeyBytes = crypto.getRandomValues(new Uint8Array(32));
const hashPepper = crypto.getRandomValues(new Uint8Array(32));
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_LIFETIME_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;

/*
 * Trusted mock credential. No submitted identifier is ever mapped to an account:
 * successful authentication always establishes this one server-owned principal.
 */
const TRUSTED_ACCOUNT_ID = "acct_trusted_marcus_demo";
const DEMO_LOGIN = "marcus";
const DEMO_PASSWORD = "Northstar!2025";

function randomBytes(size: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(size));
}
function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (v) => v.toString(16).padStart(2, "0")).join("");
}
function randomToken(bytes = 32): string {
  return hex(randomBytes(bytes));
}
function b64(bytes: ArrayBuffer | Uint8Array): string {
  return Buffer.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)).toString("base64");
}
function fromB64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}
function base32Encode(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0, result = "";
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
function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.toUpperCase().replace(/=|\s/g, "");
  let bits = 0, current = 0;
  const out: number[] = [];
  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("invalid base32");
    current = (current << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/* Requirement 3: AES-GCM protects retained TOTP material. */
async function encryptValue(value: string): Promise<EncryptedValue> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: b64(iv), ciphertext: b64(ciphertext) };
}
async function decryptValue(value: EncryptedValue): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encryptionKeyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(value.iv) },
    key,
    fromB64(value.ciphertext),
  );
  return decoder.decode(plain);
}
async function protectedHash(value: string): Promise<string> {
  const encoded = encoder.encode(value);
  const input = new Uint8Array(hashPepper.length + encoded.length);
  input.set(hashPepper);
  input.set(encoded, hashPepper.length);
  return b64(await crypto.subtle.digest("SHA-256", input));
}
async function totpForStep(secret: string, step: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"],
  );
  const message = new Uint8Array(8);
  let counter = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    message[i] = Number(counter & 255n);
    counter >>= 8n;
  }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[digest.length - 1] & 15;
  const number = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3];
  return String(number % 1000000).padStart(6, "0");
}

/* Requirement 5: cryptographic, unbiased six-digit code generation. */
function secureSixDigitCode(): string {
  while (true) {
    const bytes = randomBytes(3);
    const value = (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
    const limit = Math.floor(0x1000000 / 1000000) * 1000000;
    if (value < limit) return String(value % 1000000).padStart(6, "0");
  }
}
async function uniqueIdentityCode(): Promise<{ code: string; hash: string }> {
  for (;;) {
    const code = secureSixDigitCode();
    const hash = await protectedHash(code);
    if (!activeIdentityHashes.has(hash)) {
      activeIdentityHashes.add(hash);
      return { code, hash };
    }
  }
}
function clearIdentityChallenge(session: Session): void {
  if (session.identityHash) activeIdentityHashes.delete(session.identityHash);
  session.identityHash = undefined;
  session.identityExpires = undefined;
  session.identityUsed = undefined;
}
function accountFor(id: string): Account {
  let account = accounts.get(id);
  if (!account) {
    account = {
      id,
      totpUsedSteps: new Set(),
      totpAttempts: { failures: 0, lockUntil: 0 },
      recoveryAttempts: { failures: 0, lockUntil: 0 },
      mfaEnabled: false,
      recoveryCodes: new Map(),
    };
    accounts.set(id, account);
  }
  return account;
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const at = item.indexOf("=");
    if (at > 0) result[item.slice(0, at).trim()] = item.slice(at + 1).trim();
  }
  return result;
}
function sessionCookie(id: string): string {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_IDLE_MS / 1000}`;
}
function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function createSession(userId?: string): [string, Session] {
  const id = randomToken();
  const now = Date.now();
  const session: Session = {
    userId,
    csrf: randomToken(),
    createdAt: now,
    lastSeen: now,
    identityVerified: false,
    identityAttempts: { failures: 0, lockUntil: 0 },
  };
  sessions.set(id, session);
  return [id, session];
}
function destroySession(id: string): void {
  const session = sessions.get(id);
  if (session) clearIdentityChallenge(session);
  sessions.delete(id);
}

/* Requirement 1/5: every protected route obtains account only from this session. */
function readSession(request: Request): { id: string; session: Session } | undefined {
  const id = parseCookies(request).mfa_session;
  if (!id || !/^[a-f0-9]{64}$/.test(id)) return undefined;
  const session = sessions.get(id);
  if (!session) return undefined;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    destroySession(id);
    return undefined;
  }
  session.lastSeen = now;
  return { id, session };
}
function authenticated(request: Request): { id: string; session: Session; account: Account } | undefined {
  const active = readSession(request);
  if (!active?.session.userId) return undefined;
  return { ...active, account: accountFor(active.session.userId) };
}
function hasForbiddenIdentity(body: Record<string, unknown>): boolean {
  return ["userId", "accountId", "email", "identity", "account", "customerId"].some((key) =>
    Object.prototype.hasOwnProperty.call(body, key)
  );
}
function stateChangingValid(body: any, session: Session): boolean {
  return !!body && typeof body.csrf === "string" &&
    /^[a-f0-9]{64}$/.test(body.csrf) &&
    body.csrf === session.csrf &&
    !hasForbiddenIdentity(body);
}
function safeOtp(value: any): boolean {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function safeRecovery(value: any): boolean {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}
function validRedirect(value: any): boolean {
  return value === undefined || ["#/signin", "#/identity", "#/setup", "#/confirmed", "#/recovery"].includes(value);
}
function attemptAllowed(state: AttemptState): boolean {
  return Date.now() >= state.lockUntil;
}
function failedAttempt(state: AttemptState): void {
  state.failures++;
  if (state.failures >= MAX_FAILURES) {
    state.lockUntil = Date.now() + LOCK_MS;
    state.failures = 0;
  }
}
function resetAttempts(state: AttemptState): void {
  state.failures = 0;
  state.lockUntil = 0;
}
function generateRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = randomBytes(12);
  let raw = "";
  for (const byte of bytes) raw += alphabet[byte % alphabet.length];
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}
async function newRecoveryCodes(account: Account): Promise<string[]> {
  account.recoveryCodes.clear();
  const plain: string[] = [];
  for (let i = 0; i < 8; i++) {
    const code = generateRecoveryCode();
    plain.push(code);
    account.recoveryCodes.set(await protectedHash(code), false);
  }
  return plain;
}

function securityHeaders(nonce?: string, origin?: string | null): Headers {
  const headers = new Headers({
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'`
      : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
  });
  if (origin && /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(data: unknown, status = 200, extras?: Record<string, string>, origin?: string | null): Response {
  const headers = securityHeaders(undefined, origin);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extras) for (const [key, value] of Object.entries(extras)) headers.set(key, value);
  return new Response(JSON.stringify(data), { status, headers });
}
async function bodyOf(request: Request): Promise<any | undefined> {
  const text = await request.text();
  if (text.length > 4096) return undefined;
  try {
    const value = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light"><title>Northstar Bank — MFA enrolment</title>
<style nonce="${nonce}">
:root{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#10233d;background:#edf3f8}*{box-sizing:border-box}body{margin:0;min-width:280px}.shell{width:min(100%,520px);min-height:100vh;margin:auto;background:#fff;box-shadow:0 0 25px #b9c6d3;padding:20px 18px 30px}header{border-bottom:1px solid #d7e0ea;padding-bottom:16px;margin-bottom:20px}.brand{font-size:14px;font-weight:800;letter-spacing:.08em;color:#176b59;text-transform:uppercase}.title{font-size:26px;line-height:1.15;margin:7px 0 0}h2{font-size:22px;margin:0 0 10px}p{font-size:16px;line-height:1.5;color:#40536a}.hint{font-size:14px;color:#5d6d80}.card{background:#f6f9fc;border:1px solid #d9e3ed;border-radius:12px;padding:16px;margin:16px 0}.success{border-left:4px solid #168163}label{display:block;font-weight:700;margin:16px 0 7px}input{width:100%;font-size:18px;padding:13px;border:1px solid #91a4b7;border-radius:8px;background:#fff;color:#10233d}button{width:100%;border:0;border-radius:8px;background:#086a58;color:#fff;font-size:16px;font-weight:750;padding:14px;margin-top:18px;cursor:pointer}button.secondary{background:#e3ebf1;color:#15324b}button:focus,input:focus,a:focus{outline:3px solid #e8a72a;outline-offset:2px}code{display:block;overflow-wrap:anywhere;background:#e8f0f6;border-radius:6px;padding:10px;color:#142c43;font-size:14px}ul.codes{list-style:none;padding:0;margin:12px 0}.codes li{background:#edf5f2;padding:10px;margin:5px 0;border-radius:6px;font-family:ui-monospace,monospace;font-size:16px;letter-spacing:.04em}nav{display:flex;gap:10px;flex-wrap:wrap;margin-top:22px}nav a{color:#075b4c;font-weight:700}.error{background:#fff0ef;border-left:4px solid #c1302d;color:#74201d;padding:11px;margin:14px 0;border-radius:5px}.logs{margin-top:28px;border-top:1px solid #d7e0ea;padding-top:15px}.logs summary{font-weight:750;color:#213d58;cursor:pointer}.logbox{max-height:160px;overflow:auto;background:#101d2c;color:#d8f3e9;font:12px/1.4 ui-monospace,monospace;padding:10px;border-radius:8px;white-space:pre-wrap}
</style></head><body><main class="shell">
<header><div class="brand">Northstar Bank</div><h1 class="title">MFA enrolment</h1></header>
<section id="app" aria-live="polite"><p>Loading secure enrolment…</p></section>
<details class="logs" open><summary>Logs (test simulation)</summary><div id="logbox" class="logbox">No client simulation values yet.</div></details>
</main><script nonce="${nonce}">
(function(){"use strict";
var state={csrf:"",auth:false,identity:false,mfa:false,secret:"",codes:[]},app=document.getElementById("app"),logbox=document.getElementById("logbox");
function log(m){console.log(m);logbox.textContent=(logbox.textContent==="No client simulation values yet."?"":logbox.textContent+"\\n")+m;logbox.scrollTop=logbox.scrollHeight}
function err(m){var e=document.createElement("div");e.className="error";e.textContent=m;app.prepend(e)}
async function api(path,data){var r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify(data||{})}),x;try{x=await r.json()}catch(e){throw new Error("Unable to complete that request.")}if(!r.ok||!x||!x.ok)throw new Error(x&&x.error?x.error:"Unable to complete that request.");if(x.csrf)state.csrf=x.csrf;return x}
async function status(){var x=await api("/api/status",{});state.auth=x.auth===true;state.identity=x.identity===true;state.mfa=x.mfa===true}
function link(t,h){var a=document.createElement("a");a.href=h;a.textContent=t;return a}
function nav(){var n=document.createElement("nav");if(state.auth)n.append(link("Authenticator","#/setup"),link("Recovery codes","#/recovery"),link("Log out","#/logout"));return n}
function put(f){app.replaceChildren(f,nav())}
function shell(title,text){var f=document.createDocumentFragment(),h=document.createElement("h2"),p=document.createElement("p");h.textContent=title;p.textContent=text;f.append(h,p);return f}
function signin(){var f=shell("Sign in","Use the trusted demo credentials to begin MFA enrolment."),c=document.createElement("div"),form=document.createElement("form"),l1=document.createElement("label"),i1=document.createElement("input"),l2=document.createElement("label"),i2=document.createElement("input"),b=document.createElement("button");c.className="card hint";c.textContent="Demo credentials: Login name Marcus · Password Northstar!2025";l1.textContent="Login name";i1.autocomplete="username";i1.required=true;l2.textContent="Password";i2.type="password";i2.autocomplete="current-password";i2.required=true;b.textContent="Sign in";form.append(l1,i1,l2,i2,b);form.onsubmit=async function(e){e.preventDefault();try{var r=await api("/api/signin",{login:i1.value,password:i2.value,csrf:state.csrf,redirect:"#/identity"});state.auth=true;state.identity=false;state.mfa=false;state.secret="";state.codes=[];log("Simulated identity verification code: "+r.testCode);location.hash="#/identity"}catch(x){err(x.message)}};f.append(c,form);put(f)}
function identity(){if(!state.auth){location.hash="#/signin";return}var f=shell("Verify your identity","We sent a short-lived verification code to your registered contact method."),c=document.createElement("div"),form=document.createElement("form"),l=document.createElement("label"),i=document.createElement("input"),b=document.createElement("button");c.className="card hint";c.textContent="Test simulation: the code is available in the Logs panel and browser console.";l.textContent="Verification code";i.inputMode="numeric";i.autocomplete="one-time-code";i.maxLength=6;b.textContent="Verify identity";form.append(l,i,b);form.onsubmit=async function(e){e.preventDefault();try{await api("/api/identity/verify",{code:i.value,csrf:state.csrf});state.identity=true;location.hash="#/setup"}catch(x){err(x.message)}};f.append(c,form);put(f)}
function b32(v){var a="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",bits=0,val=0,out=[];v=v.replace(/=|\\s/g,"").toUpperCase();for(var j=0;j<v.length;j++){var n=a.indexOf(v[j]);if(n<0)throw new Error("Invalid secret");val=(val<<5)|n;bits+=5;if(bits>=8){out.push((val>>>(bits-8))&255);bits-=8}}return new Uint8Array(out)}
async function clientTotp(s){var k=await crypto.subtle.importKey("raw",b32(s),{name:"HMAC",hash:"SHA-1"},false,["sign"]),step=Math.floor(Date.now()/30000),m=new Uint8Array(8),c=BigInt(step);for(var j=7;j>=0;j--){m[j]=Number(c&255n);c>>=8n}var d=new Uint8Array(await crypto.subtle.sign("HMAC",k,m)),o=d[d.length-1]&15,n=((d[o]&127)<<24)|(d[o+1]<<16)|(d[o+2]<<8)|d[o+3];return String(n%1000000).padStart(6,"0")}
function setup(){if(!state.auth){location.hash="#/signin";return}if(!state.identity){location.hash="#/identity";return}var f=shell("Set up an authenticator","Use an authenticator app to scan the provisioning value, or enter the manual secret."),start=document.createElement("button"),details=document.createElement("div"),form=document.createElement("form"),l=document.createElement("label"),i=document.createElement("input"),b=document.createElement("button");start.textContent=state.secret?"Create a replacement authenticator secret":"Create authenticator secret";details.className="card";l.textContent="Authenticator code";i.inputMode="numeric";i.autocomplete="one-time-code";i.maxLength=6;b.textContent="Enable MFA and show recovery codes";form.append(l,i,b);form.hidden=!state.secret;start.onclick=async function(){try{var r=await api("/api/mfa/provision",{csrf:state.csrf});state.secret=r.manualSecret;details.replaceChildren();var p=document.createElement("p"),s=document.createElement("code"),q=document.createElement("p"),u=document.createElement("code"),h=document.createElement("p");p.textContent="Manual secret (enter this in your authenticator):";s.textContent=r.manualSecret;q.className="hint";q.textContent="Provisioning representation:";u.textContent=r.provisioningUri;h.className="hint";h.textContent="Test code logged. Codes rotate every 30 seconds.";details.append(p,s,q,u,h);form.hidden=false;log("Simulated current authenticator code: "+await clientTotp(state.secret))}catch(x){err(x.message)}};form.onsubmit=async function(e){e.preventDefault();try{var r=await api("/api/mfa/verify",{otp:i.value,csrf:state.csrf});state.mfa=true;state.codes=r.recoveryCodes;state.secret="";log("Simulated recovery codes: "+r.recoveryCodes.join(", "));location.hash="#/confirmed"}catch(x){err(x.message)}};f.append(start,details,form);put(f)}
function list(c){var u=document.createElement("ul");u.className="codes";c.forEach(function(x){var l=document.createElement("li");l.textContent=x;u.append(l)});return u}
function confirmed(){if(!state.mfa){location.hash="#/setup";return}var f=shell("MFA is enabled","Store these recovery codes somewhere secure. Each code works once."),c=document.createElement("div"),p=document.createElement("p");c.className="card success";p.className="hint";p.textContent="They are shown only in this browser flow and were also logged for this simulation.";c.append(list(state.codes),p);f.append(c,link("Manage recovery codes","#/recovery"));put(f)}
function recovery(){if(!state.mfa){location.hash="#/setup";return}var f=shell("Recovery codes","Use a code if your authenticator is unavailable, or replace the remaining code set."),form=document.createElement("form"),l=document.createElement("label"),i=document.createElement("input"),b=document.createElement("button"),r=document.createElement("button");l.textContent="Recovery code";i.placeholder="ABCD-EFGH-JKLM";i.autocomplete="one-time-code";b.textContent="Use recovery code";form.append(l,i,b);form.onsubmit=async function(e){e.preventDefault();try{await api("/api/mfa/recovery/use",{code:i.value.toUpperCase(),csrf:state.csrf});var d=document.createElement("div");d.className="card success";d.textContent="Recovery code accepted and permanently used.";f.insertBefore(d,form)}catch(x){err(x.message)}};r.className="secondary";r.textContent="Generate replacement recovery codes";r.onclick=async function(){try{var x=await api("/api/mfa/recovery/regenerate",{csrf:state.csrf});state.codes=x.recoveryCodes;log("Replacement recovery codes: "+x.recoveryCodes.join(", "));location.hash="#/confirmed"}catch(x){err(x.message)}};f.append(form,r);put(f)}
async function logout(){try{await api("/api/logout",{csrf:state.csrf});state={csrf:"",auth:false,identity:false,mfa:false,secret:"",codes:[]};await api("/api/bootstrap",{});location.hash="#/signin"}catch(x){err(x.message)}}
function render(){var r=location.hash||(state.auth?(state.identity?(state.mfa?"#/recovery":"#/setup"):"#/identity"):"#/signin");if(r==="#/signin")signin();else if(r==="#/identity")identity();else if(r==="#/setup")setup();else if(r==="#/confirmed")confirmed();else if(r==="#/recovery")recovery();else if(r==="#/logout")logout();else location.hash="#/signin"}window.addEventListener("hashchange",render);(async function(){try{await api("/api/bootstrap",{});await status();render()}catch(e){app.textContent="Unable to start secure enrolment."}})();
})();
</script></body></html>`;
}

async function handleApi(request: Request, path: string): Promise<Response> {
  const origin = request.headers.get("origin");
  if (request.method === "OPTIONS") {
    const headers = securityHeaders(undefined, origin);
    headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type");
    return new Response(null, { status: 204, headers });
  }
  if (request.method !== "POST") return json({ ok: false, error: "Request unavailable." }, 405, undefined, origin);
  const body = await bodyOf(request);
  if (!body) return json({ ok: false, error: "Unable to complete that request." }, 400, undefined, origin);

  if (path === "/api/bootstrap") {
    const existing = readSession(request);
    if (existing) return json({ ok: true, csrf: existing.session.csrf }, 200, undefined, origin);
    const [id, session] = createSession();
    return json({ ok: true, csrf: session.csrf }, 200, { "Set-Cookie": sessionCookie(id) }, origin);
  }

  if (path === "/api/status") {
    const active = authenticated(request);
    if (!active) return json({ ok: true, auth: false }, 200, undefined, origin);
    return json({
      ok: true,
      auth: true,
      identity: active.session.identityVerified,
      mfa: active.account.mfaEnabled,
      csrf: active.session.csrf,
    }, 200, undefined, origin);
  }

  if (path === "/api/signin") {
    const existing = readSession(request);
    const validCredentials = typeof body.login === "string" && typeof body.password === "string" &&
      body.login === DEMO_LOGIN && body.password === DEMO_PASSWORD;
    const permittedKeys = ["login", "password", "csrf", "redirect"];
    const noUnexpected = Object.keys(body).every((key) => permittedKeys.includes(key));

    /*
     * Requirement task: login cannot select an account. Exact trusted mock
     * credentials are validated server-side and establish only server constant
     * TRUSTED_ACCOUNT_ID; email/account/user identity input is rejected.
     */
    if (!existing || !stateChangingValid(body, existing.session) || !validCredentials ||
      !validRedirect(body.redirect) || !noUnexpected) {
      return json({ ok: false, error: "Unable to continue sign-in." }, 400, undefined, origin);
    }

    destroySession(existing.id); // Requirement 5: rotate session after authentication.
    const [newId, session] = createSession(TRUSTED_ACCOUNT_ID);
    accountFor(TRUSTED_ACCOUNT_ID);
    const challenge = await uniqueIdentityCode();
    session.identityHash = challenge.hash;
    session.identityExpires = Date.now() + OTP_LIFETIME_MS;
    session.identityUsed = false;
    session.identityVerified = false;
    resetAttempts(session.identityAttempts);

    /*
     * Requirement task: this test-only value is returned solely as part of the
     * just-established trusted authenticated demo session, never in logs/URLs.
     */
    return json(
      { ok: true, csrf: session.csrf, testCode: challenge.code },
      200,
      { "Set-Cookie": sessionCookie(newId) },
      origin,
    );
  }

  const active = authenticated(request);
  if (!active) {
    return json(
      { ok: false, error: "Your secure session is unavailable. Please sign in again." },
      401,
      { "Set-Cookie": expiredCookie() },
      origin,
    );
  }
  if (!stateChangingValid(body, active.session)) {
    return json({ ok: false, error: "Unable to complete that request." }, 403, undefined, origin);
  }

  if (path === "/api/identity/verify") {
    const session = active.session;
    if (!safeOtp(body.code) || !attemptAllowed(session.identityAttempts) || session.identityUsed ||
      !session.identityExpires || Date.now() > session.identityExpires ||
      !session.identityHash || await protectedHash(body.code) !== session.identityHash) {
      failedAttempt(session.identityAttempts);
      return json({ ok: false, error: "That verification could not be accepted. Please try again later." }, 400, undefined, origin);
    }
    session.identityUsed = true;
    session.identityVerified = true;
    activeIdentityHashes.delete(session.identityHash);
    resetAttempts(session.identityAttempts);
    return json({ ok: true, csrf: session.csrf }, 200, undefined, origin);
  }

  /* MFA setup/recovery are exclusively scoped to active.session.userId above. */
  if (!active.session.identityVerified) {
    return json({ ok: false, error: "Identity verification is required first." }, 403, undefined, origin);
  }

  if (path === "/api/mfa/provision") {
    const secret = base32Encode(randomBytes(20));
    active.account.totpSecret = await encryptValue(secret);
    active.account.totpUsedSteps.clear();
    resetAttempts(active.account.totpAttempts);
    const issuer = "NorthstarBank";
    const label = "NorthstarBank:Marcus";
    return json({
      ok: true,
      csrf: active.session.csrf,
      manualSecret: secret,
      provisioningUri: `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${issuer}&period=30&digits=6`,
    }, 200, undefined, origin);
  }

  if (path === "/api/mfa/verify") {
    const account = active.account;
    if (!safeOtp(body.otp) || !account.totpSecret || !attemptAllowed(account.totpAttempts)) {
      failedAttempt(account.totpAttempts);
      return json({ ok: false, error: "That authenticator code could not be accepted. Please try again later." }, 400, undefined, origin);
    }
    const secret = await decryptValue(account.totpSecret);
    const nowStep = Math.floor(Date.now() / 30000);
    let acceptedStep: number | undefined;
    for (const candidate of [nowStep - 1, nowStep, nowStep + 1]) {
      if (!account.totpUsedSteps.has(candidate) && body.otp === await totpForStep(secret, candidate)) {
        acceptedStep = candidate;
        break;
      }
    }
    if (acceptedStep === undefined) {
      failedAttempt(account.totpAttempts);
      return json({ ok: false, error: "That authenticator code could not be accepted. Please try again later." }, 400, undefined, origin);
    }
    account.totpUsedSteps.add(acceptedStep);
    for (const old of account.totpUsedSteps) if (old < nowStep - 3) account.totpUsedSteps.delete(old);
    resetAttempts(account.totpAttempts);
    account.mfaEnabled = true;
    const recoveryCodes = await newRecoveryCodes(account);
    return json({ ok: true, csrf: active.session.csrf, recoveryCodes }, 200, undefined, origin);
  }

  if (path === "/api/mfa/recovery/use") {
    const account = active.account;
    if (!account.mfaEnabled || !attemptAllowed(account.recoveryAttempts) || !safeRecovery(body.code)) {
      if (!attemptAllowed(account.recoveryAttempts) || !safeRecovery(body.code)) failedAttempt(account.recoveryAttempts);
      return json({ ok: false, error: "That recovery code could not be accepted. Please try again later." }, 400, undefined, origin);
    }
    const codeHash = await protectedHash(body.code);
    if (account.recoveryCodes.get(codeHash) !== false) {
      failedAttempt(account.recoveryAttempts);
      return json({ ok: false, error: "That recovery code could not be accepted." }, 400, undefined, origin);
    }
    account.recoveryCodes.set(codeHash, true);
    resetAttempts(account.recoveryAttempts);
    return json({ ok: true, csrf: active.session.csrf }, 200, undefined, origin);
  }

  if (path === "/api/mfa/recovery/regenerate") {
    if (!active.account.mfaEnabled) {
      return json({ ok: false, error: "Unable to complete that request." }, 403, undefined, origin);
    }
    const recoveryCodes = await newRecoveryCodes(active.account);
    return json({ ok: true, csrf: active.session.csrf, recoveryCodes }, 200, undefined, origin);
  }

  if (path === "/api/logout") {
    destroySession(active.id);
    return json({ ok: true }, 200, { "Set-Cookie": expiredCookie() }, origin);
  }

  return json({ ok: false, error: "Request unavailable." }, 404, undefined, origin);
}

const port = Number(Bun.env.PORT || 3000);
Bun.serve({
  port,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") {
        return new Response("HTTPS required", { status: 400, headers: securityHeaders() });
      }
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = randomToken(16);
        const headers = securityHeaders(nonce, request.headers.get("origin"));
        headers.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers });
      }
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      return new Response("Not found", {
        status: 404,
        headers: securityHeaders(undefined, request.headers.get("origin")),
      });
    } catch {
      return new Response("Unable to process request.", { status: 500, headers: securityHeaders() });
    }
  },
});
console.log(`MFA enrolment demo listening at https://localhost:${port}`);
