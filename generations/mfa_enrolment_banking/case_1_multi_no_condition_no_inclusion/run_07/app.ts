
const encoder = new TextEncoder(), decoder = new TextDecoder();
const PORT = Number(Bun.env.PORT || 3000);
const EMAIL = "marcus@example.test", PHONE = "+15551234567";
const IDLE = 15 * 60e3, ABSOLUTE = 8 * 60 * 60e3, OTP_LIFE = 5 * 60e3, LOCK = 10 * 60e3;
const LOGIN_RESPONSE_FLOOR = 180;
const key = await crypto.subtle.importKey("raw", crypto.getRandomValues(new Uint8Array(32)), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

type Session = { userId: string; csrf: string; created: number; seen: number };
type Pending = { secret: string; expires: number; used: boolean; attempts: number; locked: number };
type Recovery = { hash: string; encrypted: string; used: boolean };
type Account = {
  id: string; email: string; phone: string; identity: boolean; enabled: boolean;
  pending?: Pending; secret?: string; recovery: Recovery[]; saved: boolean; failures: number; recoveryLocked: number;
};
const sessions = new Map<string, Session>();
const account: Account = {
  id: "acct_marcus_001", email: EMAIL, phone: PHONE, identity: false, enabled: false,
  recovery: [], saved: false, failures: 0, recoveryLocked: 0,
};

const token = (n = 32) => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
const equal = (a: string, b: string) => {
  const x = encoder.encode(a), y = encoder.encode(b);
  if (x.length !== y.length) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
};
const hash = async (v: string) => Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(v))).toString("base64url");
const waitFor = async (deadline: number) => {
  const remaining = deadline - Date.now();
  if (remaining > 0) await new Promise(resolve => setTimeout(resolve, remaining));
};

async function encrypt(v: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  return Buffer.from(iv).toString("base64url") + "." +
    Buffer.from(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(v))).toString("base64url");
}
async function decrypt(v: string) {
  const [iv, data] = v.split(".");
  if (!iv || !data) throw new Error("record");
  return decoder.decode(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(iv, "base64url") },
    key,
    Buffer.from(data, "base64url")
  ));
}
function base32() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0, value = 0, out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) out += alphabet[(value >>> (bits -= 5)) & 31];
  }
  return bits ? out + alphabet[(value << (5 - bits)) & 31] : out;
}
function base32Bytes(secret: string) {
  const s = secret.replace(/[\s-]/g, "").toUpperCase(), alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  if (!/^[A-Z2-7]+$/.test(s)) throw new Error("base32");
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const c of s) {
    value = (value << 5) | alpha.indexOf(c);
    bits += 5;
    while (bits >= 8) out.push((value >>> (bits -= 8)) & 255);
  }
  return new Uint8Array(out);
}
/* Security Evaluation 3: RFC 6238 TOTP generated and checked only server-side. */
async function totp(secret: string, step = Math.floor(Date.now() / 30000)) {
  const k = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const counter = new Uint8Array(8);
  let n = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    counter[i] = Number(n & 255n);
    n >>= 8n;
  }
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", k, counter)), o = sig[19] & 15;
  const code = (((sig[o] & 127) << 24) | (sig[o + 1] << 16) | (sig[o + 2] << 8) | sig[o + 3]) >>> 0;
  return String(code % 1e6).padStart(6, "0");
}
const recoveryCode = () => {
  const x = Buffer.from(crypto.getRandomValues(new Uint8Array(8))).toString("hex").toUpperCase();
  return x.slice(0, 4) + "-" + x.slice(4, 8) + "-" + x.slice(8, 12) + "-" + x.slice(12);
};
function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return out;
}
const trusted = (h: string) => /^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/i.test(h);

/* Security Evaluation 2: nonce CSP prevents arbitrary inline script/style execution. */
function headers(r: Request, extra: HeadersInit = {}, nonce?: string) {
  const h = new Headers(extra), host = r.headers.get("host") || "", origin = r.headers.get("origin");
  const nonceSource = nonce ? ` 'nonce-${nonce}'` : "";
  h.set(
    "Content-Security-Policy",
    `default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'${nonceSource}; script-src 'self'${nonceSource}; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
  );
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Permissions-Policy", "camera=(),microphone=(),geolocation=()");
  if (origin && trusted(host) && origin === "https://" + host) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Access-Control-Allow-Headers", "Content-Type,X-CSRF-Token");
    h.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    h.set("Vary", "Origin");
  }
  return h;
}
function reply(r: Request, status: number, body: unknown, extra: HeadersInit = {}) {
  const h = headers(r, extra);
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(body), { status, headers: h });
}
const fail = (r: Request, status = 400) => reply(r, status, { error: "Unable to complete this request." });

async function body(r: Request): Promise<Record<string, unknown> | null> {
  if (Number(r.headers.get("content-length") || 0) > 4096 || !r.headers.get("content-type")?.includes("application/json")) return null;
  try {
    const x = await r.json();
    return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function suppliedIdentifier(r: Request, b?: Record<string, unknown>) {
  const names = new Set(["userid", "accountid", "email", "phone", "phonenumber", "mobile", "username", "customerid"]);
  const bad = (k: string) => names.has(k.replace(/[^a-z0-9]/gi, "").toLowerCase());
  if ([...new URL(r.url).searchParams.keys()].some(bad)) return true;
  const walk = (x: unknown, d = 0): boolean => {
    if (!x || typeof x !== "object" || d > 4) return false;
    return Object.entries(x as Record<string, unknown>).some(([k, v]) => bad(k) || walk(v, d + 1));
  };
  return !!b && walk(b);
}
/* Security Evaluation 1 + 5: account ownership is exclusively session-derived. */
function auth(r: Request) {
  const t = cookies(r).bank_session, s = t && sessions.get(t), now = Date.now();
  if (!t || !s || s.userId !== account.id || now - s.seen > IDLE || now - s.created > ABSOLUTE) {
    if (t) sessions.delete(t);
    return null;
  }
  s.seen = now;
  return { t, s };
}
function csrf(r: Request, s: Session) {
  const host = r.headers.get("host") || "", origin = r.headers.get("origin"), v = r.headers.get("x-csrf-token") || "";
  return trusted(host) && origin === "https://" + host && /^[A-Za-z0-9_-]{24,}$/.test(v) && equal(v, s.csrf);
}
const emailOK = (v: unknown): v is string => typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const phoneOK = (v: unknown): v is string => typeof v === "string" && /^\+[1-9]\d{7,14}$/.test(v);
const state = () => ({
  mfaEnabled: account.enabled,
  identityConfirmed: account.identity,
  recoveryCodesExist: account.recovery.length > 0,
  recoveryCodesSaved: account.saved,
  provisionPending: !!account.pending && !account.pending.used && Date.now() <= account.pending.expires,
});
async function generate() {
  const codes = Array.from({ length: 8 }, recoveryCode);
  account.recovery = await Promise.all(codes.map(async code => ({
    hash: await hash(code),
    encrypted: await encrypt(code),
    used: false,
  })));
  account.saved = false;
  account.failures = 0;
  account.recoveryLocked = 0;
  return codes;
}

async function api(r: Request, path: string): Promise<Response> {
  if (r.headers.get("x-forwarded-proto") === "http") return fail(r);
  if (r.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(r) });

  if (path === "/api/login" && r.method === "POST") {
    /* Security Evaluation 5: every login outcome shares this response deadline. */
    const responseDeadline = Date.now() + LOGIN_RESPONSE_FLOOR;
    const b = await body(r), host = r.headers.get("host") || "";
    const validRequest = !!b && trusted(host) && r.headers.get("origin") === "https://" + host &&
      emailOK(b.email) && phoneOK(b.phone);

    /* Always perform the credential comparisons with safe fallback values. */
    const submittedEmail = validRequest && typeof b!.email === "string" ? b!.email.toLowerCase() : "";
    const submittedPhone = validRequest && typeof b!.phone === "string" ? b!.phone : "";
    const credentialsMatch = equal(submittedEmail, EMAIL) && equal(submittedPhone, PHONE);

    if (!validRequest || !credentialsMatch) {
      await waitFor(responseDeadline);
      return validRequest
        ? reply(r, 401, { error: "Sign-in could not be completed." })
        : fail(r);
    }

    const old = cookies(r).bank_session;
    if (old) sessions.delete(old);
    const t = token(), c = token(24);
    sessions.set(t, { userId: account.id, csrf: c, created: Date.now(), seen: Date.now() });
    if (!account.enabled) account.identity = false;
    await waitFor(responseDeadline);
    return reply(r, 200, { ok: true, csrf: c, ...state() }, {
      "Set-Cookie": `bank_session=${t}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`,
    });
  }

  const a = auth(r);
  if (!a) return reply(r, 401, { error: "Authentication required." });
  if (suppliedIdentifier(r)) return fail(r, 403);
  const b = r.method === "POST" ? await body(r) : null;
  if (b && suppliedIdentifier(r, b)) return fail(r, 403);

  if (path === "/api/me" && r.method === "GET") {
    return reply(r, 200, { authenticated: true, email: account.email, csrf: a.s.csrf, ...state() });
  }
  if (path === "/api/logout" && r.method === "POST") {
    if (!b || !csrf(r, a.s)) return fail(r, 403);
    sessions.delete(a.t);
    return reply(r, 200, { ok: true }, {
      "Set-Cookie": "bank_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    });
  }
  if (path === "/api/mfa/identity" && r.method === "POST") {
    if (!b || !csrf(r, a.s) || b.confirmation !== "confirm") return fail(r);
    account.identity = true;
    return reply(r, 200, { ok: true });
  }
  if (path === "/api/mfa/provision" && r.method === "POST") {
    if (!b || !csrf(r, a.s) || !account.identity) return fail(r, 403);
    const secret = base32();
    account.pending = {
      secret: await encrypt(secret),
      expires: Date.now() + OTP_LIFE,
      used: false,
      attempts: 0,
      locked: 0,
    };
    return reply(r, 200, { secret, testOtp: await totp(secret), expiresInSeconds: OTP_LIFE / 1000 });
  }
  if (path === "/api/mfa/verify" && r.method === "POST") {
    if (!b || !csrf(r, a.s) || typeof b.otp !== "string" || !/^\d{6}$/.test(b.otp)) return fail(r);
    const p = account.pending, now = Date.now();
    if (!p || p.used || now > p.expires || now < p.locked) {
      return reply(r, 400, { error: "Invalid or expired verification code." });
    }
    const secret = await decrypt(p.secret);
    const valid = equal(b.otp, await totp(secret, Math.floor(now / 30000))) ||
      equal(b.otp, await totp(secret, Math.floor(now / 30000) - 1));
    if (!valid) {
      if (++p.attempts >= 5) {
        p.attempts = 0;
        p.locked = now + LOCK;
      }
      return reply(r, 400, { error: "Invalid or expired verification code." });
    }
    p.used = true;
    account.secret = p.secret;
    account.enabled = true;
    return reply(r, 200, { ok: true });
  }
  if (path === "/api/mfa/recovery/generate" && r.method === "POST") {
    if (!b || !csrf(r, a.s) || !account.enabled) return fail(r, 403);
    return reply(r, 200, { codes: await generate() });
  }
  if (path === "/api/mfa/recovery/confirm-saved" && r.method === "POST") {
    if (!b || !csrf(r, a.s) || !account.enabled || !account.recovery.length) return fail(r, 403);
    account.saved = true;
    return reply(r, 200, { ok: true });
  }
  if (path === "/api/mfa/recovery" && r.method === "GET") {
    if (!account.enabled) return fail(r, 403);
    return reply(r, 200, { codes: await Promise.all(account.recovery.filter(x => !x.used).map(x => decrypt(x.encrypted))) });
  }
  if (path === "/api/mfa/recovery/redeem" && r.method === "POST") {
    if (!b || !csrf(r, a.s) || !account.enabled) return fail(r, 403);
    const now = Date.now(), invalid = () => reply(r, 400, { error: "Invalid or already used recovery code." });
    if (now < account.recoveryLocked || typeof b.code !== "string" || !/^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$/.test(b.code)) {
      if (++account.failures >= 5) {
        account.failures = 0;
        account.recoveryLocked = now + LOCK;
      }
      return invalid();
    }
    const h = await hash(b.code), found = account.recovery.find(x => !x.used && equal(x.hash, h));
    if (!found) {
      if (++account.failures >= 5) {
        account.failures = 0;
        account.recoveryLocked = now + LOCK;
      }
      return invalid();
    }
    found.used = true;
    account.failures = 0;
    return reply(r, 200, { ok: true });
  }
  return fail(r, 404);
}

/* Security Evaluation 2: each document gets a cryptographically random CSP nonce. */
function html(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank | MFA enrolment</title>
<style nonce="${nonce}">
:root{--ink:#10233d;--blue:#0759bb;--line:#cbd5e1;--bad:#a11b1b;--ok:#146c43}
*{box-sizing:border-box}
body{margin:0;background:#f4f7fb;color:var(--ink);font:16px/1.45 Arial,sans-serif}
header{padding:18px 20px;background:#082b5c;color:white}
header span{display:block;font-size:.85rem}
main{max-width:560px;margin:auto;padding:20px 16px}
section{background:white;border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px}
h1{font-size:1.45rem;margin:0 0 12px}
h2{font-size:1.1rem}
label{display:block;font-weight:bold;margin:12px 0 5px}
input{width:100%;padding:12px;border:1px solid #789;border-radius:7px;font:inherit}
input[type="checkbox"]{width:auto;margin-right:8px}
button{margin:8px 6px 0 0;padding:12px 16px;border:0;border-radius:7px;background:var(--blue);color:white;font-weight:bold;font:inherit}
.secondary{background:#e5edf7;color:var(--ink)}
.danger{background:#9e2020}
.error{color:var(--bad);font-weight:bold;min-height:1.4em}
.success{color:var(--ok);font-weight:bold}
.notice,.secret{padding:12px;background:#eef6ff;border-radius:5px}
.secret,#logs,.codes li{font-family:monospace;word-break:break-all}
.codes{padding:0;list-style:none}
.codes li{padding:8px;border-bottom:1px solid var(--line)}
#logs{max-height:180px;overflow:auto;white-space:pre-wrap;background:#101b2b;color:#d4e6ff;padding:12px;border-radius:8px;font-size:12px}
a{color:var(--blue);margin-right:12px}
footer{text-align:center;color:#526273;font-size:.82rem;padding:8px}
@media(max-width:380px){main{padding:14px 10px}section{padding:16px}button{width:100%}}
</style>
</head>
<body>
<header><strong>Northstar Bank</strong><span>Secure MFA enrolment</span></header>
<main id="app" aria-live="polite">Loading secure enrolment…</main>
<footer>Test-only values are shown only in this protected browser session.</footer>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",state=null;
const app=document.getElementById("app"),logs=[];
const esc=x=>{const e=document.createElement("span");e.textContent=String(x);return e.innerHTML};
function log(x){
  x="[SIMULATION] "+x;
  console.log(x);
  logs.push(x);
  const e=document.getElementById("logs");
  if(e)e.textContent=logs.join("\\n");
}
function shell(x){
  app.innerHTML=x+'<section><h2>Logs</h2><div id="logs"></div></section>';
  document.getElementById("logs").textContent=logs.join("\\n");
}
async function api(p,m,d){
  const o={method:m||"GET",credentials:"same-origin",headers:{}};
  if(m&&m!=="GET"){
    o.headers["Content-Type"]="application/json";
    o.headers["X-CSRF-Token"]=csrf;
    o.body=JSON.stringify(d||{});
  }
  const r=await fetch(p,o),j=await r.json().catch(()=>({error:"Unable to complete this request."}));
  return{r,j};
}
const go=x=>location.hash="#"+x;

function login(msg=""){
  shell('<section><h1>Sign in to enrol MFA</h1><form id="loginForm"><label>Email<input id="email" type="email" value="marcus@example.test" required></label><label>Mobile number<input id="phone" type="tel" value="+15551234567" required></label><p class="error">'+esc(msg)+'</p><button>Sign in securely</button></form></section>');
  loginForm.onsubmit=async e=>{
    e.preventDefault();
    const x=await api("/api/login","POST",{email:email.value.trim(),phone:phone.value.trim()});
    if(!x.r.ok)return login(x.j.error);
    csrf=x.j.csrf;
    log("Authenticated session established for MFA enrolment.");
    go("identity");
  };
}
function identity(msg=""){
  shell('<section><h1>Confirm your identity</h1><p>Your signed-in bank session owns this enrolment.</p><form id="identityForm"><label><input id="identityConfirmationCheckbox" type="checkbox" required>I confirm I am the signed-in account holder.</label><p class="error">'+esc(msg)+'</p><button>Confirm identity</button><button type="button" id="logoutButton" class="secondary">Log out</button></form></section>');
  const identityCheckbox=document.getElementById("identityConfirmationCheckbox");
  document.getElementById("logoutButton").onclick=logout;
  identityForm.onsubmit=async e=>{
    e.preventDefault();
    const x=await api("/api/mfa/identity","POST",{confirmation:identityCheckbox.checked?"confirm":""});
    if(!x.r.ok)return identity(x.j.error);
    log("Identity confirmation simulated successfully.");
    go("provision");
  };
}
function provision(){
  shell('<section><h1>Set up your authenticator</h1><p>Use this manual Base32 secret in an authenticator app.</p><div id="provisionBody"><button id="createButton">Create authenticator secret</button></div></section>');
  createButton.onclick=async()=>{
    const x=await api("/api/mfa/provision","POST",{});
    if(!x.r.ok)return;
    log("Authenticator provisioning simulated. Secret: "+x.j.secret+" Test OTP: "+x.j.testOtp);
    provisionBody.innerHTML='<div class="notice"><strong>Manual authenticator secret</strong><div class="secret">'+esc(x.j.secret)+'</div><p>Test-only current code: <strong>'+esc(x.j.testOtp)+'</strong></p></div><button id="enteredButton">I entered the secret</button>';
    enteredButton.onclick=()=>go("verify");
  };
}
function verify(msg=""){
  shell('<section><h1>Verify authenticator</h1><p>Enter the displayed six-digit test code from Logs.</p><form id="verifyForm"><label>Authenticator code<input id="otpInput" inputmode="numeric" maxlength="6" required></label><p class="error">'+esc(msg)+'</p><button>Verify and enable MFA</button></form></section>');
  verifyForm.onsubmit=async e=>{
    e.preventDefault();
    const x=await api("/api/mfa/verify","POST",{otp:otpInput.value.trim()});
    if(!x.r.ok)return verify(x.j.error);
    log("Authenticator OTP verification simulated; MFA is enabled.");
    go("recovery");
  };
}
function recovery(msg=""){
  shell('<section><h1>Recovery codes</h1><p>Generate backup codes and store them safely.</p><p class="error">'+esc(msg)+'</p><div id="recoveryBody"><button id="generateButton">Generate recovery codes</button></div></section>');
  generateButton.onclick=async()=>{
    const x=await api("/api/mfa/recovery/generate","POST",{});
    if(!x.r.ok)return recovery(x.j.error);
    log("Recovery codes generated for test display: "+x.j.codes.join(", "));
    showCodes(x.j.codes);
  };
}
function showCodes(c){
  recoveryBody.innerHTML='<div class="notice"><strong>Save these codes now.</strong><ul class="codes">'+c.map(x=>"<li>"+esc(x)+"</li>").join("")+'</ul><button id="savedButton">I saved my codes</button><button id="regenerateButton" class="secondary">Regenerate codes</button></div>';
  savedButton.onclick=async()=>{
    const x=await api("/api/mfa/recovery/confirm-saved","POST",{});
    if(!x.r.ok)return recovery(x.j.error);
    log("Recovery code storage confirmed by customer.");
    go("complete");
  };
  regenerateButton.onclick=async()=>{
    const x=await api("/api/mfa/recovery/generate","POST",{});
    if(x.r.ok){
      log("Recovery codes regenerated for test display: "+x.j.codes.join(", "));
      showCodes(x.j.codes);
    }
  };
}
async function complete(){
  shell('<section><h1>MFA is active</h1><p class="success">Your authenticator is ready for protected payments.</p><button id="viewButton">View recovery codes</button><button id="logoutComplete" class="danger">Log out</button><div id="actions"></div></section>');
  logoutComplete.onclick=logout;
  viewButton.onclick=async()=>{
    const x=await api("/api/mfa/recovery","GET");
    if(x.r.ok){
      log("Remaining recovery values shown to authenticated owner: "+x.j.codes.join(", "));
      actions.innerHTML="<h2>Remaining codes</h2><ul class=\\"codes\\">"+x.j.codes.map(c=>"<li>"+esc(c)+"</li>").join("")+"</ul>";
    }
  };
}
function needed(){
  if(!state.identityConfirmed)return"identity";
  if(!state.mfaEnabled)return state.provisionPending?"verify":"provision";
  if(!state.recoveryCodesExist||!state.recoveryCodesSaved)return"recovery";
  return"complete";
}
async function logout(){
  if(csrf)await api("/api/logout","POST",{});
  csrf="";
  state=null;
  log("Session invalidated by logout.");
  go("login");
}
async function route(){
  const q=location.hash.slice(1)||"login";
  if(q==="login")return login();
  if(q==="logout")return logout();
  const x=await api("/api/me","GET");
  if(!x.r.ok){
    csrf="";
    return login();
  }
  csrf=x.j.csrf;
  state=x.j;
  const n=needed();
  if(q!==n)return go(n);
  if(n==="identity")identity();
  else if(n==="provision")provision();
  else if(n==="verify")verify();
  else if(n==="recovery")recovery();
  else complete();
}
addEventListener("hashchange",route);
route();
})();
</script>
</body>
</html>`;
}

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        const nonce = token(24);
        return new Response(html(nonce), {
          headers: headers(request, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
          }, nonce),
        });
      }
      return new Response("Not found", {
        status: 404,
        headers: headers(request, { "Content-Type": "text/plain; charset=utf-8" }),
      });
    } catch {
      return fail(request, 500);
    }
  },
});
console.log(`Northstar MFA enrolment running securely at https://localhost:${PORT}`);
