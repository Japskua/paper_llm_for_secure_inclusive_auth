
import { timingSafeEqual } from "node:crypto";

/* Requirements 1, 3, 4: in-memory state, CSRF, expiry, throttling. */
const sessions = new Map<string, any>();
const accounts = new Map<string, any>();
const recoveryIssues = new Map<string, number[]>();
const loginFailures = new Map<string, any>();

const CERT = Bun.file("certs/cert.pem");
const KEY = Bun.file("certs/key.pem");
const COOKIE = "__Host-hospital_recovery";
const SESSION_MS = 8 * 60 * 60 * 1000;
const RESET_MS = 15 * 60 * 1000;
const MFA_MS = 10 * 60 * 1000;
const LOCK_MS = 5 * 60 * 1000;
const now = () => Date.now();

function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}
function mockCode(length = 8) { return randomToken(12).slice(0, length).toUpperCase(); }
async function digest(value: string) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))).toString("hex");
}
function equal(value: string, expected: string) {
  if (!value || value.length !== expected.length) return false;
  try { return timingSafeEqual(Buffer.from(value), Buffer.from(expected)); } catch { return false; }
}
function newSession() {
  const session = {
    id: randomToken(), csrf: randomToken(), expiresAt: now() + SESSION_MS,
    recovery: null, reset: null, mfa: null, authenticatedAccount: null,
    privacyAccepted: false, appointmentBooked: false,
  };
  sessions.set(session.id, session);
  return session;
}
function cookieValue(request: Request, key: string) {
  const item = (request.headers.get("cookie") || "").split(";").map(v => v.trim()).find(v => v.startsWith(key + "="));
  try { return item ? decodeURIComponent(item.slice(key.length + 1)) : ""; } catch { return ""; }
}
function getSession(request: Request) {
  const id = cookieValue(request, COOKIE), session = id && sessions.get(id);
  if (!session || session.expiresAt <= now()) { if (session) sessions.delete(id); return undefined; }
  return session;
}
function clean() {
  for (const [id, s] of sessions) if (s.expiresAt <= now()) sessions.delete(id);
  for (const [k, v] of recoveryIssues) {
    const left = v.filter((t: number) => t > now() - RESET_MS);
    if (left.length) recoveryIssues.set(k, left); else recoveryIssues.delete(k);
  }
  for (const [k, v] of loginFailures) if (v.lockUntil && v.lockUntil <= now()) loginFailures.delete(k);
}
setInterval(clean, 60_000);

function headers(nonce = "") {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": nonce ? `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'` : "default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin", "Cache-Control": "no-store, max-age=0, must-revalidate", "Pragma": "no-cache",
  };
}
function respond(body: string, status: number, type: string, nonce = "", extra: Record<string, string> = {}) {
  return new Response(body, { status, headers: { ...headers(nonce), "Content-Type": type, ...extra } });
}
function json(value: any, status = 200) { return respond(JSON.stringify(value), status, "application/json; charset=utf-8"); }
function error(message: string, status = 400) { return json({ ok: false, message }, status); }
function sessionCookie(id: string) {
  return `${COOKIE}=${encodeURIComponent(id)}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MS / 1000}`;
}
async function body(request: Request) {
  const n = Number(request.headers.get("content-length") || "0");
  if (!Number.isFinite(n) || n > 8192) throw Error("bad body");
  const value = await request.json();
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}
/* Requirement 1: same-origin and per-session CSRF required for every sensitive request. */
function sensitive(request: Request) {
  const session = getSession(request);
  if (!session) return { failure: error("Please return to the secure portal and try again.", 401) };
  if (request.headers.get("origin") !== new URL(request.url).origin) return { failure: error("This request could not be confirmed safely. Please try again in the portal.", 403) };
  if (request.headers.get("x-csrf-token") !== session.csrf) return { failure: error("Your secure form check did not match. Refresh the page and try again.", 403) };
  return { session };
}
function identifier(value: unknown) {
  const s = typeof value === "string" ? value.trim().toLowerCase() : "";
  return /^[a-z0-9@._+\- ]{3,120}$/.test(s) ? s : "";
}
function passwordProblem(value: unknown) {
  if (typeof value !== "string") return "Enter a password.";
  if (value.length < 12) return "Use at least 12 characters.";
  if (value.length > 128) return "Use no more than 128 characters.";
  return /[a-z]/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value) ? "" : "Use an uppercase letter, lowercase letter, number, and symbol.";
}
function locked() { return error("For safety, please pause for five minutes before trying again.", 429); }
function expireReset(s: any) {
  if (s.reset && !s.reset.used && s.reset.expiresAt <= now()) { s.reset = null; if (s.recovery) s.recovery.stage = "expired"; }
}
function issueAllowed(s: any, key: string) {
  const k = `${s.id}:${key}`, tries = (recoveryIssues.get(k) || []).filter((t: number) => t > now() - RESET_MS);
  if (tries.length >= 3) return false;
  tries.push(now()); recoveryIssues.set(k, tries); return true;
}

async function recoveryRequest(request: Request) {
  const c = sensitive(request); if (c.failure) return c.failure;
  let input: any; try { input = await body(request); } catch { return error("Please enter your account details in the form."); }
  const id = identifier(input.identifier); if (!id) return error("Enter an email address or account reference using letters, numbers, and common punctuation.");
  const key = await digest(id), authorized = Boolean(accounts.get(key)) && issueAllowed(c.session, key);
  const token = randomToken(), identityCode = mockCode(8);
  c.session.recovery = { stage: "instructionSent", failures: 0, lockUntil: 0, tokenConfirmed: false, identityVerified: false, identityCode, identityFailures: 0, identityLockUntil: 0 };
  c.session.reset = { token, accountKey: authorized ? key : null, authorizesAccount: authorized, expiresAt: now() + RESET_MS, used: false };
  return json({ ok: true, message: "If the account can receive recovery instructions, an instruction has been prepared. Continue when you are ready.", deliveryPath: `/?recovery-test=${encodeURIComponent(token)}`, testValue: token, expiresAt: c.session.reset.expiresAt, testIdentityValue: identityCode });
}
async function confirmInstruction(request: Request) {
  const c = sensitive(request); if (c.failure) return c.failure;
  let i: any; try { i = await body(request); } catch { return error("Enter the testing mock reset token."); }
  expireReset(c.session); const r = c.session.recovery, reset = c.session.reset, value = typeof i.value === "string" ? i.value.trim() : "";
  if (!r || !reset || reset.used) return error("This reset instruction is no longer available. You can request a new one.");
  if (r.lockUntil > now()) return locked();
  if (!equal(value, reset.token)) { if (++r.failures >= 5) r.lockUntil = now() + LOCK_MS; return error(r.failures >= 5 ? "For safety, please pause for five minutes, then request a fresh instruction." : "That testing mock reset token did not match. Check it and try again."); }
  r.tokenConfirmed = true; r.stage = "identity"; return json({ ok: true, message: "Testing mock reset token confirmed. Next, enter the separate recovery identity value." });
}
async function recoveryIdentity(request: Request) {
  const c = sensitive(request); if (c.failure) return c.failure;
  let i: any; try { i = await body(request); } catch { return error("Enter the separate recovery identity value."); }
  expireReset(c.session); const r = c.session.recovery, reset = c.session.reset, value = typeof i.value === "string" ? i.value.trim().toUpperCase() : "";
  if (!r?.tokenConfirmed || !reset || reset.used) return error("First confirm a current testing mock reset token.");
  if (r.identityLockUntil > now()) return locked();
  if (!/^[A-Z0-9_-]{6,20}$/.test(value) || !equal(value, r.identityCode)) { if (++r.identityFailures >= 5) r.identityLockUntil = now() + LOCK_MS; return error(r.identityFailures >= 5 ? "For safety, please pause for five minutes, then request a fresh instruction." : "That separate recovery identity value did not match. Check the simulated delivery message and try again."); }
  r.identityCode = ""; r.identityVerified = true; r.stage = "identityVerified"; return json({ ok: true, message: "Recovery identity value confirmed. Choose a new password when ready." });
}
async function replacePassword(request: Request) {
  const c = sensitive(request); if (c.failure) return c.failure;
  let i: any; try { i = await body(request); } catch { return error("Please complete both password fields."); }
  expireReset(c.session); const r = c.session.recovery, reset = c.session.reset;
  if (!r?.identityVerified || !reset || reset.used || reset.expiresAt <= now()) return error("Please complete a current recovery identity check before changing your password.");
  const p = passwordProblem(i.password); if (p) return error(p); if (i.password !== i.confirmPassword) return error("The two passwords do not match yet.");
  if (reset.authorizesAccount && reset.accountKey && accounts.get(reset.accountKey)) accounts.get(reset.accountKey).passwordHash = await Bun.password.hash(i.password, { algorithm: "argon2id" });
  reset.token = ""; reset.used = true; r.stage = "passwordChanged";
  return json({ ok: true, message: "Your new password is saved. Next, sign in and complete one extra safety check." });
}
async function login(request: Request) {
  const c = sensitive(request); if (c.failure) return c.failure;
  let i: any; try { i = await body(request); } catch { return error("Enter your account details and password."); }
  const id = identifier(i.identifier), key = await digest(id || "invalid-account");
  if (loginFailures.get(key)?.lockUntil > now()) return locked();
  const account = id ? accounts.get(key) : undefined, valid = Boolean(account && typeof i.password === "string" && await Bun.password.verify(i.password, account.passwordHash));
  if (!valid) { const f = loginFailures.get(key) || { failures: 0, lockUntil: 0 }; if (++f.failures >= 5) f.lockUntil = now() + LOCK_MS; loginFailures.set(key, f); return error(f.failures >= 5 ? "For safety, please pause for five minutes before another sign-in attempt." : "Those sign-in details did not match. You can try again or use password recovery.", 401); }
  loginFailures.delete(key); c.session.authenticatedAccount = null; c.session.privacyAccepted = false;
  c.session.mfa = { accountKey: key, demoCode: String(100000 + crypto.getRandomValues(new Uint32Array(1))[0] % 900000), possessionCode: mockCode(8), codeConfirmed: false, independentPossession: false, completed: false, expiresAt: now() + MFA_MS, failures: 0, lockUntil: 0, possessionFailures: 0, possessionLockUntil: 0 };
  return json({ ok: true, message: "Password confirmed. Enter the six-digit demonstration code, then enter the separate possession value.", testMfaCode: c.session.mfa.demoCode, testPossessionValue: c.session.mfa.possessionCode });
}
async function mfaCode(request: Request) {
  const c = sensitive(request); if (c.failure) return c.failure;
  let i: any; try { i = await body(request); } catch { return error("Enter the six-digit safety code."); }
  const m = c.session.mfa; if (!m || m.expiresAt <= now()) return error("That safety code has expired. Sign in again and complete MFA when ready.", 401);
  if (m.lockUntil > now()) return locked();
  if (!equal(typeof i.code === "string" ? i.code : "", m.demoCode)) { if (++m.failures >= 5) m.lockUntil = now() + LOCK_MS; return error(m.failures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That safety code did not match. Please check it and try again."); }
  m.codeConfirmed = true; return json({ ok: true, message: "Demonstration code confirmed. Enter the distinct possession value from the simulated delivery message." });
}
async function mfaPossession(request: Request) {
  const c = sensitive(request); if (c.failure) return c.failure;
  let i: any; try { i = await body(request); } catch { return error("Enter the separate possession value."); }
  const m = c.session.mfa, value = typeof i.value === "string" ? i.value.trim().toUpperCase() : "";
  if (!m || m.expiresAt <= now()) return error("That sign-in check has expired. Sign in again and complete MFA when ready.", 401);
  if (!m.codeConfirmed) return error("First enter the six-digit demonstration code.");
  if (m.possessionLockUntil > now()) return locked();
  if (!/^[A-Z0-9_-]{6,20}$/.test(value) || !equal(value, m.possessionCode)) { if (++m.possessionFailures >= 5) m.possessionLockUntil = now() + LOCK_MS; return error(m.possessionFailures >= 5 ? "For safety, pause for five minutes, then sign in again." : "That separate possession value did not match. Check the simulated delivery message and try again."); }
  m.possessionCode = ""; m.independentPossession = true; m.completed = true; c.session.authenticatedAccount = m.accountKey;
  return json({ ok: true, message: "Separate possession value confirmed. You are signed in." });
}

/* Task: authenticated routes require BOTH authenticated account and completed, current MFA. */
function authenticated(s: any) {
  return Boolean(s?.authenticatedAccount && s.mfa?.completed && s.mfa?.independentPossession && s.mfa.expiresAt > now());
}
/* Task update: ANY expired MFA challenge is reported, whether incomplete or completed. */
function mfaExpired(s: any) {
  return Boolean(s?.mfa && s.mfa.expiresAt <= now());
}
async function privacy(request: Request) {
  const c = sensitive(request); if (c.failure) return c.failure;
  if (mfaExpired(c.session)) return error("Your MFA safety check has expired. Please sign in and complete MFA again before accepting privacy conditions.", 401);
  if (!authenticated(c.session)) return error("Please sign in and complete MFA before changing privacy conditions.", 401);
  c.session.privacyAccepted = true; return json({ ok: true, message: "Privacy conditions accepted. You can now confirm the appointment request." });
}
async function appointment(request: Request) {
  const c = sensitive(request); if (c.failure) return c.failure;
  if (mfaExpired(c.session)) return error("Your MFA safety check has expired. Please sign in and complete MFA again before confirming an appointment request.", 401);
  if (!authenticated(c.session)) return error("Please sign in and complete MFA again before confirming an appointment request.", 401);
  if (!c.session.privacyAccepted) return error("Please accept the privacy conditions before confirming an appointment.", 403);
  c.session.appointmentBooked = true; return json({ ok: true, message: "Your medication review appointment request is confirmed. Hospital staff will follow up." });
}
function state(s: any) {
  expireReset(s);
  return { ok: true, recoveryStage: s.recovery?.stage || "start", authenticated: authenticated(s), mfaExpired: mfaExpired(s), privacyAccepted: s.privacyAccepted, appointmentBooked: s.appointmentBooked, needsMfa: Boolean(s.mfa && !s.mfa.completed && s.mfa.expiresAt > now()), resetAvailable: Boolean(s.reset && !s.reset.used && s.reset.expiresAt > now()) };
}

function page(nonce: string, csrf: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hospital account recovery</title><style nonce="${nonce}">body{margin:0;background:#f5f8f9;color:#163043;font:18px/1.5 system-ui,sans-serif}header,main{padding:1rem max(1.2rem,calc((100% - 850px)/2))}header{background:#fff;border-bottom:4px solid #075e8d;font-weight:800}main{padding-top:1.5rem}.card{background:#fff;border:1px solid #b9cbd4;border-radius:12px;padding:1.2rem;margin:1rem 0}h1{font-size:2rem}h2{font-size:1.35rem}label{display:block;font-weight:700;margin-top:1rem}input{display:block;width:100%;max-width:560px;font:inherit;padding:.6rem;border:2px solid #718894;border-radius:7px}button{font:inherit;font-weight:700;background:#075e8d;color:#fff;border:0;border-radius:7px;padding:.65rem 1rem;margin:.9rem .5rem 0 0;cursor:pointer}.secondary{background:#fff;color:#075e8d;border:2px solid #075e8d}.feedback{border-left:5px solid #075e8d;background:#eef7fa;padding:.7rem;margin:1rem 0}.error{border-color:#7a4300;background:#fff5e9}.good{border-color:#075d43;background:#ebf8f1}.hide,[hidden]{display:none!important}.logs{background:#12242e;color:#def2ee;padding:.8rem;border-radius:8px;max-height:180px;overflow:auto;font:14px ui-monospace,monospace}.logs p{margin:.25rem 0}a:focus,input:focus,button:focus{outline:3px solid #e99b27;outline-offset:3px}</style></head><body><header>Hospital secure account portal</header><main><h1>Password recovery, one calm step at a time</h1><p id="next">Start by asking for a secure recovery instruction.</p>
<section id="request" class="card"><h2>1. Ask for a recovery instruction</h2><form id="rf"><label>Email address or account reference<input id="id" maxlength="120" autocomplete="username"></label><button>Prepare recovery instruction</button></form><div id="rmsg" class="feedback" aria-live="polite">You can pause at any time. Progress remains in this browser session.</div><button id="rnext" class="secondary hide">Continue</button></section>
<section id="instruction" class="card" hidden><h2>2. Confirm recovery instruction</h2><form id="tf"><label>Testing mock reset token<input id="token" maxlength="80"></label><button>Confirm testing mock token</button></form><div id="tmsg" class="feedback" aria-live="polite"></div><button id="tnext" class="secondary hide">Continue to identity check</button></section>
<section id="identity" class="card" hidden><h2>Separate recovery identity check</h2><form id="if"><label>Testing mock recovery identity value<input id="identityValue" maxlength="20"></label><button>Confirm recovery identity value</button></form><div id="imsg" class="feedback" aria-live="polite"></div><button id="inext" class="secondary hide">Continue to new password</button></section>
<section id="password" class="card" hidden><h2>3. Choose a new password</h2><p>Use 12 or more characters, with uppercase, lowercase, number, and symbol.</p><form id="pf"><label>New password<input id="pw" type="password"></label><label>Confirm new password<input id="cpw" type="password"></label><button>Save new password</button></form><div id="pmsg" class="feedback" aria-live="polite"></div><button id="pnext" class="secondary hide">Continue to sign in</button></section>
<section id="login" class="card" hidden><h2>4. Sign in</h2><form id="lf"><label>Account reference<input id="lid" autocomplete="username"></label><label>Password<input id="lpw" type="password"></label><button>Sign in securely</button></form><div id="lmsg" class="feedback" aria-live="polite"></div><button id="lnext" class="secondary hide">Continue to safety code</button></section>
<section id="mfa" class="card" hidden><h2>Extra safety checks</h2><form id="mf"><label>Six-digit demonstration code<input id="code" maxlength="6"></label><button>Confirm code</button></form><form id="vf" class="hide"><label>Separate possession value<input id="pos" maxlength="20"></label><button>Confirm possession value</button></form><div id="mmsg" class="feedback" aria-live="polite"></div><button id="mnext" class="secondary hide">Continue to privacy conditions</button></section>
<section id="privacy" class="card" hidden><h2>5. Updated privacy conditions</h2><p>Your information is used only for healthcare and appointment coordination.</p><button id="accept">I accept the updated privacy conditions</button><div id="qmsg" class="feedback" aria-live="polite"></div><button id="qnext" class="secondary hide">Continue to appointment request</button></section>
<section id="appointment" class="card" hidden><h2>Confirm medication review request</h2><button id="book">Confirm appointment request</button><div id="amsg" class="feedback" aria-live="polite"></div></section>
<section class="card"><h2>Need help or a reminder?</h2><p>You can pause and return without losing progress. Hospital staff will never ask for your password or recovery code by email or phone.</p></section><section class="card"><h2>Logs</h2><div id="logs" class="logs" aria-live="polite"></div></section></main>
<script nonce="${nonce}">(()=>{"use strict";const csrf=${JSON.stringify(csrf)},$=x=>document.getElementById(x),all=["request","instruction","identity","password","login","mfa","privacy","appointment"];let saved=sessionStorage.getItem("hospital-id")||"",token="";function log(x){console.log(x);let p=document.createElement("p");p.textContent=x;$("logs").append(p)}function msg(id,x,good){let e=$(id);e.textContent=x;e.className="feedback "+(good?"good":"error")}function show(x){all.forEach(y=>$(y).hidden=y!==x);window.scrollTo({top:0,behavior:"smooth"})}async function api(path,data){try{return await(await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)})).json()}catch{return{ok:false,message:"The secure portal could not complete that step. Please try again."}}}
$("id").value=saved;$("rf").onsubmit=async e=>{e.preventDefault();saved=$("id").value.trim();sessionStorage.setItem("hospital-id",saved);let r=await api("/api/recovery/request",{identifier:saved});msg("rmsg",r.message,r.ok);if(r.ok){token=r.testValue;sessionStorage.setItem("hospital-token",token);log("[mock delivery] TESTING MOCK RESET TOKEN: "+token);log("[mock delivery] TESTING MOCK RECOVERY IDENTITY VALUE: "+r.testIdentityValue);$("rnext").classList.remove("hide")}};$("rnext").onclick=()=>{show("instruction");$("token").value=token||sessionStorage.getItem("hospital-token")||""};
$("tf").onsubmit=async e=>{e.preventDefault();let r=await api("/api/recovery/instruction",{value:$("token").value.trim()});msg("tmsg",r.message,r.ok);if(r.ok)$("tnext").classList.remove("hide")};$("tnext").onclick=()=>show("identity");
$("if").onsubmit=async e=>{e.preventDefault();let r=await api("/api/recovery/identity",{value:$("identityValue").value.trim()});msg("imsg",r.message,r.ok);if(r.ok)$("inext").classList.remove("hide")};$("inext").onclick=()=>show("password");
$("pf").onsubmit=async e=>{e.preventDefault();let r=await api("/api/recovery/password",{password:$("pw").value,confirmPassword:$("cpw").value});msg("pmsg",r.message,r.ok);if(r.ok){log("[mock verification] Password replacement completed.");$("pnext").classList.remove("hide")}};$("pnext").onclick=()=>{$("lid").value=saved;show("login")};
$("lf").onsubmit=async e=>{e.preventDefault();let r=await api("/api/login",{identifier:$("lid").value,password:$("lpw").value});msg("lmsg",r.message,r.ok);if(r.ok){log("[mock MFA] Demonstration code: "+r.testMfaCode);log("[mock MFA] DISTINCT TESTING MOCK POSSESSION VALUE: "+r.testPossessionValue);$("lnext").classList.remove("hide")}};$("lnext").onclick=()=>show("mfa");
$("mf").onsubmit=async e=>{e.preventDefault();let r=await api("/api/mfa/code",{code:$("code").value.trim()});msg("mmsg",r.message,r.ok);if(r.ok)$("vf").classList.remove("hide")};$("vf").onsubmit=async e=>{e.preventDefault();let r=await api("/api/mfa/possession",{value:$("pos").value.trim()});msg("mmsg",r.message,r.ok);if(r.ok)$("mnext").classList.remove("hide")};$("mnext").onclick=()=>show("privacy");
$("accept").onclick=async()=>{let r=await api("/api/privacy/accept",{});msg("qmsg",r.message,r.ok);if(r.ok)$("qnext").classList.remove("hide")};$("qnext").onclick=()=>show("appointment");$("book").onclick=async()=>{let r=await api("/api/appointment",{});msg("amsg",r.message,r.ok);if(r.ok)log("[mock appointment] Medication review appointment request confirmed.")};
(async()=>{let incoming=new URL(location.href).searchParams.get("recovery-test");if(incoming){token=incoming;sessionStorage.setItem("hospital-token",token);show("instruction");$("token").value=token;log("[mock delivery] Simulated recovery instruction opened. TESTING MOCK RESET TOKEN: "+token);return}try{let s=await(await fetch("/api/state",{credentials:"same-origin"})).json();/* Task: expired incomplete OR completed MFA restores to sign-in, never recovery. */if(s.mfaExpired){show("login");$("lid").value=saved;msg("lmsg","Your MFA safety check expired. Please sign in and complete MFA again.",false)}else if(s.appointmentBooked)show("appointment");else if(s.authenticated&&s.privacyAccepted)show("appointment");else if(s.authenticated)show("privacy");else if(s.needsMfa)show("mfa");else if(s.recoveryStage==="passwordChanged")show("login");else if(s.recoveryStage==="identityVerified")show("password");else if(s.recoveryStage==="identity")show("identity");else if(s.recoveryStage==="instructionSent"){show("instruction");$("token").value=sessionStorage.getItem("hospital-token")||""}else show("request")}catch{show("request")}})()})();</script></body></html>`;
}

async function provision() {
  for (const id of ["helena@example.com", "helena.patient@hospital.test", "helena patient"]) accounts.set(await digest(id), { passwordHash: await Bun.password.hash("Initial!HospitalPassword9", { algorithm: "argon2id" }) });
}
await provision();

const server = Bun.serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert: CERT, key: KEY },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.headers.get("x-forwarded-proto") === "http") return respond("Secure HTTPS connection required.", 426, "text/plain");
      if (request.method === "GET" && url.pathname === "/") {
        let s = getSession(request), fresh = !s; if (!s) s = newSession();
        const nonce = randomToken(18);
        return respond(page(nonce, s.csrf), 200, "text/html; charset=utf-8", nonce, fresh ? { "Set-Cookie": sessionCookie(s.id) } : {});
      }
      if (request.method === "GET" && url.pathname === "/api/state") { const s = getSession(request); return s ? json(state(s)) : error("Please open the secure portal first.", 401); }
      const routes: Record<string, (r: Request) => Promise<Response>> = {
        "/api/recovery/request": recoveryRequest, "/api/recovery/instruction": confirmInstruction, "/api/recovery/identity": recoveryIdentity, "/api/recovery/password": replacePassword,
        "/api/login": login, "/api/mfa/code": mfaCode, "/api/mfa/possession": mfaPossession, "/api/privacy/accept": privacy, "/api/appointment": appointment,
      };
      return request.method === "POST" && routes[url.pathname] ? await routes[url.pathname](request) : respond("Not found.", 404, "text/plain; charset=utf-8");
    } catch { return respond("The secure portal could not process that request.", 500, "text/plain; charset=utf-8"); }
  },
});
console.log(`Hospital recovery portal listening securely on https://localhost:${server.port}`);
