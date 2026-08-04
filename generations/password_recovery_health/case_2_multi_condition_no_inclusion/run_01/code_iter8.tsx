
import { randomBytes, timingSafeEqual } from "node:crypto";

/*
  Password Recovery Demo — requirements 1–5:
  session-bound CSRF, safe validation, TLS/security headers, short-lived
  single-use codes, throttling, bcrypt password hashing, MFA, and safe-use UI.
*/

type Reset = { token: string; expiresAt: number; used: boolean };
type Session = {
  id: string; csrf: string; expiresAt: number;
  reset?: Reset; verifiedUntil?: number; passwordHash?: string;
  pendingMfa?: boolean; authenticated?: boolean; privacyAccepted?: boolean;
};

const sessions = new Map<string, Session>();
const limits = new Map<string, number[]>();
const COOKIE = "__Host-recovery_session";
const SESSION_MS = 30 * 60_000;
const RESET_MS = 10 * 60_000;
const MFA_CODE = "246810";
const FACTOR = "LOCAL-RECOVERY-FACTOR";
let server: ReturnType<typeof Bun.serve>;

function random(bytes = 32) { return randomBytes(bytes).toString("base64url"); }
function same(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
function cookies(request: Request) {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function clearRecovery(s: Session) { s.reset = undefined; s.verifiedUntil = undefined; }
function cleanSession(s: Session) {
  const now = Date.now();
  if (s.reset && now > s.reset.expiresAt) clearRecovery(s);
  if (s.verifiedUntil && now > s.verifiedUntil) clearRecovery(s);
}
function cleanup() {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now > s.expiresAt) sessions.delete(id); else cleanSession(s);
  }
  for (const [key, times] of limits) {
    const current = times.filter(t => now - t < 15 * 60_000);
    if (current.length) limits.set(key, current); else limits.delete(key);
  }
}
function sessionFor(request: Request) {
  cleanup();
  const s = sessions.get(cookies(request)[COOKIE]);
  if (!s || Date.now() > s.expiresAt) return undefined;
  cleanSession(s);
  return s;
}
function makeSession(): Session {
  return { id: random(), csrf: random(), expiresAt: Date.now() + SESSION_MS };
}
function headers(nonce?: string) {
  return new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": `default-src 'self'; script-src 'self'; style-src 'nonce-${nonce || "none"}'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "Content-Type": "application/json; charset=utf-8",
  });
}
function reply(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: headers() });
}
function error(status = 400) {
  return reply({ ok: false, message: "We could not complete that request. Please try again." }, status);
}
async function data(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || 0) > 8192) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; }
}
/* Requirement 1: every sensitive POST requires a unique session CSRF token. */
function csrf(request: Request, s: Session) {
  const value = request.headers.get("x-csrf-token") || "";
  return value.length === s.csrf.length && same(value, s.csrf);
}
function address(request: Request) {
  try { return server.requestIP(request)?.address || "unknown"; } catch { return "unknown"; }
}
/* Requirement 4: deterministic in-memory throttling by client and subject. */
function allowed(kind: string, request: Request, subject: string, max = 5) {
  const key = `${kind}|${address(request)}|${subject}`, now = Date.now();
  const history = (limits.get(key) || []).filter(t => now - t < 15 * 60_000);
  if (history.length >= max) { limits.set(key, history); return false; }
  history.push(now); limits.set(key, history); return true;
}
function validPassword(value: unknown) {
  if (typeof value !== "string") return "Choose a stronger password.";
  if (value.length < 12 || value.length > 128) return "Use 12 to 128 characters.";
  if (/\s/.test(value)) return "Passwords cannot contain spaces.";
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/\d/.test(value) || !/[^A-Za-z0-9]/.test(value)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  return null;
}
function recoveryAuthorized(s: Session) {
  const ok = !!s.reset && !!s.verifiedUntil && s.reset.used &&
    Date.now() <= s.reset.expiresAt && Date.now() <= s.verifiedUntil;
  if (!ok) clearRecovery(s);
  return ok;
}

async function api(request: Request, path: string) {
  const s = sessionFor(request);
  if (!s) return error(403);

  if (request.method === "GET" && path === "/api/session/state") {
    return reply({ ok: true, authenticated: !!s.authenticated, privacyAccepted: !!s.authenticated && !!s.privacyAccepted, passwordSetup: !!s.passwordHash });
  }
  if (request.method !== "POST" || !csrf(request, s)) return error(403);
  const input = await data(request);
  if (!input) return error();

  /* Identifier lookup is intentionally non-authorizing and non-enumerating. */
  if (path === "/api/recovery/request") {
    const message = "If an account is eligible for recovery, instructions will be sent through its registered recovery channel.";
    if (!allowed("request", request, "generic", 3)) {
      return reply({ ok: false, message }, 429);
    }
    return reply({ ok: true, message });
  }
  if (path === "/api/recovery/authorize-factor") {
    if (!allowed("factor", request, s.id)) return reply({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    const factor = typeof input.factor === "string" ? input.factor : "";
    if (!same(factor, FACTOR)) return reply({ ok: false, message: "The recovery factor could not be verified." });
    const token = random(24);
    s.reset = { token, expiresAt: Date.now() + RESET_MS, used: false };
    s.verifiedUntil = undefined; s.authenticated = false; s.pendingMfa = false; s.privacyAccepted = false;
    return reply({ ok: true, message: "Recovery factor verified. A session-scoped recovery code is ready.", testCode: token, resetPath: `/?code=${encodeURIComponent(token)}#verify` });
  }
  if (path === "/api/recovery/verify") {
    if (!allowed("verify", request, s.id)) return reply({ ok: false, message: "Too many attempts. Request a new recovery code." }, 429);
    const code = typeof input.code === "string" ? input.code : "", r = s.reset;
    if (!r || r.used || Date.now() > r.expiresAt || !/^[A-Za-z0-9_-]{12,128}$/.test(code) || !same(r.token, code)) {
      cleanSession(s); return reply({ ok: false, message: "That code is invalid, expired, or already used." });
    }
    r.used = true; s.verifiedUntil = Date.now() + RESET_MS;
    return reply({ ok: true, message: "Code verified. You may now choose a new password." });
  }
  if (path === "/api/recovery/reset-password") {
    if (!recoveryAuthorized(s)) return error(403);
    if (!allowed("reset", request, s.id)) return reply({ ok: false, message: "Too many attempts. Request a new recovery code." }, 429);
    const issue = validPassword(input.password);
    if (issue) return reply({ ok: false, message: issue });
    if (input.password !== input.confirmPassword) return reply({ ok: false, message: "The password confirmation does not match." });
    s.passwordHash = await Bun.password.hash(input.password as string, { algorithm: "bcrypt", cost: 12 });
    clearRecovery(s); s.pendingMfa = true;
    return reply({ ok: true, message: "Password securely set. Verify the security code to continue.", testMfaCode: MFA_CODE });
  }
  if (path === "/api/login") {
    if (!allowed("login", request, s.id)) return reply({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    if (typeof input.password !== "string" || !s.passwordHash || !(await Bun.password.verify(input.password, s.passwordHash))) {
      return reply({ ok: false, message: "The sign-in details could not be verified." });
    }
    s.pendingMfa = true;
    return reply({ ok: true, message: "A security code has been prepared for this demonstration.", testMfaCode: MFA_CODE });
  }
  if (path === "/api/mfa/verify") {
    if (!s.pendingMfa) return error(403);
    if (!allowed("mfa", request, s.id)) return reply({ ok: false, message: "Too many incorrect codes. Please start again later." }, 429);
    if (typeof input.code !== "string" || !same(input.code, MFA_CODE)) return reply({ ok: false, message: "The security code could not be verified." });
    s.authenticated = true; s.pendingMfa = false;
    return reply({ ok: true, message: "Security verification complete." });
  }
  if (path === "/api/privacy/accept") {
    if (!s.authenticated) return error(403);
    if (input.accept !== true) return reply({ ok: false, message: "Please confirm that you have read the updated conditions." });
    s.privacyAccepted = true;
    return reply({ ok: true, message: "The updated privacy conditions have been accepted." });
  }
  return error(404);
}

function page(s: Session, nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="csrf-token" content="${s.csrf}"><title>Hospital account recovery</title>
<style nonce="${nonce}">:root{--b:#075a9c;--n:#12314b;--l:#c9d4dd;--s:#edf5f8;--e:#a32222;--o:#125d38}*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:#172b3a;font:16px Arial,sans-serif;line-height:1.5}header{background:var(--n);color:white;padding:1.2rem}header div,main{max-width:760px;margin:auto}h1{font-size:1.45rem;margin:0}h2{margin-top:0;font-size:1.3rem}main{padding:1.5rem 1rem 3rem}.card{background:white;border:1px solid var(--l);border-radius:10px;padding:1.35rem;box-shadow:0 1px 3px #0001}label{display:block;font-weight:bold;margin:1rem 0 .3rem}input{width:100%;padding:.72rem;border:1px solid #718292;border-radius:5px;font-size:1rem}button{background:var(--b);color:white;border:0;border-radius:5px;padding:.72rem 1rem;font-size:1rem;font-weight:bold;cursor:pointer;margin-top:1rem}button:disabled{opacity:.6}a{color:var(--b);font-weight:bold;cursor:pointer}nav{margin:0 0 1rem;display:flex;gap:.8rem;flex-wrap:wrap}.notice{background:var(--s);border-left:4px solid var(--b);padding:.85rem;margin:1rem 0}.warning{border-left-color:#b16a00;background:#fff8e8}.status{min-height:1.5rem;margin:1rem 0 0;font-weight:bold}.error{color:var(--e)}.success{color:var(--o)}.small{font-size:.9rem}.check{display:flex;gap:.55rem;font-weight:normal}.check input{width:auto}#logs{background:#10212d;color:#d7f3e3;border-radius:7px;padding:.8rem;min-height:5.5rem;max-height:180px;overflow:auto;white-space:pre-wrap;font:.8rem monospace}.logs-card{margin-top:1rem}footer{max-width:760px;margin:0 auto 2rem;padding:0 1rem}code{word-break:break-all}</style><script src="/app.js" defer></script></head><body>
<header><div><h1>Hospital account access</h1><div class="small">Secure recovery and privacy acknowledgement</div></div></header><main><nav><a href="#recovery">Recover password</a><a href="#login">Sign in</a><a href="#privacy">Privacy conditions</a></nav><div id="app" aria-live="polite"></div><section class="card logs-card"><h2>Logs</h2><p class="small">Simulated delivery events are visible here and in the browser console.</p><div id="logs" role="log">Ready.</div></section></main><footer class="small"><strong>Stay safe:</strong> Hospital staff will never ask you to share your password or verification code by email, phone, or text.</footer></body></html>`;
}

const CLIENT = String.raw`"use strict";
const app=document.getElementById("app"), logs=document.getElementById("logs"), csrf=document.querySelector('meta[name="csrf-token"]').content;
function log(x){console.log(x);const d=document.createElement("div");d.textContent=x;logs.prepend(d)}
function view(x){app.innerHTML=x}
function status(x,ok){const e=document.getElementById("status");if(e){e.textContent=x||"";e.className="status "+(ok?"success":"error")}}
function route(){return(location.hash||"#recovery").slice(1)}
function go(x){location.hash=x}
async function api(path,payload){try{const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(payload)});return await r.json()}catch{return{ok:false,message:"We could not complete that request."}}}
async function state(){try{return await(await fetch("/api/session/state",{credentials:"same-origin",cache:"no-store"})).json()}catch{return{}}}
function busy(f,on){const b=f.querySelector("button");if(b){b.disabled=on;b.textContent=on?"Please wait…":b.dataset.label}}
function recovery(){view('<section class="card"><h2>Reset your password</h2><p>Enter an email or account identifier. The response is identical whether an account exists or is eligible.</p><form id="f"><label>Email or account identifier</label><input name="identifier" maxlength="128" required><button data-label="Request recovery">Request recovery</button></form><p id="status" class="status"></p><p class="small"><a href="#factor">Verify recovery factor</a></p></section>');f.onsubmit=async e=>{e.preventDefault();busy(f,1);const r=await api("/api/recovery/request",{identifier:f.identifier.value});busy(f,0);status(r.message,r.ok)}}
function factor(){view('<section class="card"><h2>Verify recovery factor</h2><div class="notice warning">For this local evaluation enter: <code>LOCAL-RECOVERY-FACTOR</code>. It only creates a disposable account in this browser session.</div><form id="f"><label>Recovery factor</label><input name="factor" maxlength="128" required><button data-label="Verify recovery factor">Verify recovery factor</button></form><p id="status" class="status"></p></section>');f.onsubmit=async e=>{e.preventDefault();busy(f,1);const r=await api("/api/recovery/authorize-factor",{factor:f.factor.value});busy(f,0);status(r.message,r.ok);if(r.ok){log("SIMULATED session-scoped recovery delivery: reset code "+r.testCode);const p=document.createElement("p"),a=document.createElement("a");p.className="notice warning";a.href=r.resetPath;a.textContent="Open the simulated recovery link";p.append("Evaluation-only simulated delivery: ",a);f.after(p)}}}
function verify(){const code=new URLSearchParams(location.search).get("code")||"";view('<section class="card"><h2>Verify recovery code</h2><p>Open an authorized recovery link or enter a code manually.</p><form id="f"><label>Recovery code</label><input name="code" maxlength="128" required><button data-label="Verify code">Verify code</button></form><p id="status" class="status"></p></section>');f.code.value=code;f.onsubmit=async e=>{e.preventDefault();busy(f,1);const r=await api("/api/recovery/verify",{code:f.code.value});busy(f,0);status(r.message,r.ok);if(r.ok){/* Explicit render fixes link/manual transition after URL code removal. */history.replaceState(null,"","/#reset");reset()}}}
function reset(){view('<section class="card"><h2>Choose a new password</h2><div class="notice">Use 12–128 characters with uppercase, lowercase, a number, and a symbol. Never share your password.</div><form id="f"><label>New password</label><input name="password" type="password" minlength="12" maxlength="128" required><label>Confirm new password</label><input name="confirm" type="password" minlength="12" maxlength="128" required><button data-label="Set secure password">Set secure password</button></form><p id="status" class="status"></p></section>');f.onsubmit=async e=>{e.preventDefault();if(f.password.value!==f.confirm.value)return status("The password confirmation does not match.",false);busy(f,1);const r=await api("/api/recovery/reset-password",{password:f.password.value,confirmPassword:f.confirm.value});busy(f,0);status(r.message,r.ok);if(r.ok){log("SIMULATED MFA delivery: test security code "+r.testMfaCode);setTimeout(()=>go("mfa"),250)}}}
function login(){view('<section class="card"><h2>Sign in</h2><form id="f"><label>Password</label><input name="password" type="password" required><button data-label="Sign in">Sign in</button></form><p id="status" class="status"></p></section>');f.onsubmit=async e=>{e.preventDefault();busy(f,1);const r=await api("/api/login",{password:f.password.value});busy(f,0);status(r.message,r.ok);if(r.ok){log("SIMULATED MFA delivery: test security code "+r.testMfaCode);setTimeout(()=>go("mfa"),250)}}}
function mfa(){view('<section class="card"><h2>Security verification</h2><div class="notice warning">The simulated code was written to Logs. Never disclose a real code.</div><form id="f"><label>Security code</label><input name="code" required><button data-label="Verify security code">Verify security code</button></form><p id="status" class="status"></p></section>');f.onsubmit=async e=>{e.preventDefault();busy(f,1);const r=await api("/api/mfa/verify",{code:f.code.value});busy(f,0);status(r.message,r.ok);if(r.ok)setTimeout(()=>go("privacy"),250)}}
function privacy(){view('<section class="card"><h2>Updated privacy conditions</h2><p>Please review and accept the updated conditions so appointment booking can continue.</p><form id="f"><label class="check"><input id="accept" type="checkbox"><span>I have read and accept the updated privacy conditions.</span></label><button data-label="Accept conditions">Accept conditions</button></form><p id="status" class="status"></p></section>');f.onsubmit=async e=>{e.preventDefault();busy(f,1);const r=await api("/api/privacy/accept",{accept:accept.checked});busy(f,0);status(r.message,r.ok);if(r.ok)setTimeout(()=>go("confirmation"),250)}}
function done(){view('<section class="card"><h2>Privacy conditions accepted</h2><p>Your acknowledgement has been recorded. No patient or account identifiers are displayed.</p></section>')}
async function render(){const r=route();if(r==="privacy"||r==="confirmation"){const s=await state();if(!s.authenticated||(r==="confirmation"&&!s.privacyAccepted)){view('<section class="card"><h2>Access required</h2><p>Please sign in and complete security verification.</p><a href="#login">Go to sign in</a></section>');return}}({recovery,factor,verify,reset,login,mfa,privacy,confirmation:done}[r]||recovery)()}
addEventListener("hashchange",render);render();`;

setInterval(cleanup, 60_000);
server = Bun.serve({
  port: 3000,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") return error(400);
      if (request.method === "GET" && url.pathname === "/app.js") {
        const h = headers(); h.set("Content-Type", "application/javascript; charset=utf-8");
        return new Response(CLIENT, { headers: h });
      }
      if (request.method === "GET" && url.pathname === "/") {
        let s = sessionFor(request), fresh = false;
        if (!s) { s = makeSession(); sessions.set(s.id, s); fresh = true; }
        const nonce = random(18), h = headers(nonce);
        h.set("Content-Type", "text/html; charset=utf-8");
        if (fresh) h.set("Set-Cookie", `${COOKIE}=${s.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`);
        return new Response(page(s, nonce), { headers: h });
      }
      if ((request.method === "GET" || request.method === "POST") && url.pathname.startsWith("/api/")) return api(request, url.pathname);
      return error(404);
    } catch { return error(500); }
  }
});
console.log(`Secure hospital recovery demo running at https://localhost:${server.port}`);
