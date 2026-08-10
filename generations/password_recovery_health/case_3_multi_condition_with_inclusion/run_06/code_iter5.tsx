
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

/*
  Password Recovery System
  Security requirements:
  - Account data is server-only and keyed only by internal account IDs.
  - CSRF validates every state-changing request.
  - Reset tokens are random, bound to an internal account, single-use, and short-lived.
  - HTTPS, HSTS, CSP, secure cookies, bcrypt, MFA, and throttling are enabled.
  Inclusivity requirements:
  - Clear numbered recovery steps, saved progress, no page countdown, help, and visible logs.
*/

const HTTPS_PORT = 3443;
const HTTP_PORT = 3000;
const RESET_LIFETIME_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const WINDOW_MS = 10 * 60 * 1000;
const MFA_CODE = "246810";
const SIMULATION_MODE = true;

/* Server-only mock account model. No account identifier is returned to browsers. */
type Account = {
  id: string;
  recoveryChannel: string;
  passwordHash: string;
  privacyAccepted: boolean;
};

const demoAccount: Account = {
  id: "acct_7cba6f1d_server_only",
  recoveryChannel: "helena.demo@hospital.test",
  passwordHash: await (Bun.password as any).hash("Initial!Password2025", { algorithm: "bcrypt", cost: 10 }),
  privacyAccepted: false,
};
const accounts = new Map<string, Account>([[demoAccount.id, demoAccount]]);

type Attempt = { count: number; started: number; lockedUntil: number };
type ResetRecord = { token: string; accountId: string; expiresAt: number; used: boolean };
type Session = {
  id: string;
  csrf: string;
  reset?: ResetRecord;
  verifiedReset?: string;
  mfaSent?: boolean;
  mfaVerified?: boolean;
  authenticatedAccountId?: string;
  attempts: Record<string, Attempt>;
};

const sessions = new Map<string, Session>();
const globalAttempts = new Map<string, Attempt>();

function token(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}
function cookies(request: Request) {
  const output: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) {
      try { output[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch {}
    }
  }
  return output;
}
function createSession(): Session {
  const session: Session = { id: token(), csrf: token(), attempts: {} };
  sessions.set(session.id, session);
  return session;
}
function getSession(request: Request, create = false) {
  const found = sessions.get(cookies(request).hospital_session || "");
  return found || (create ? createSession() : undefined);
}
function sessionCookie(session: Session) {
  return `hospital_session=${encodeURIComponent(session.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`;
}
function headers() {
  return new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
  });
}
function reply(data: unknown, status = 200, extra?: HeadersInit) {
  const h = headers();
  h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) for (const [k, v] of new Headers(extra)) h.set(k, v);
  return new Response(JSON.stringify(data), { status, headers: h });
}
function fail(status = 400) {
  return reply({ ok: false, message: "We could not complete that step. Please check your entry and try again." }, status);
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch { return null; }
}
/* Requirement 1: CSRF protection for all sensitive POST actions. */
async function guarded(request: Request): Promise<{ session: Session; body: Record<string, unknown> } | Response> {
  const session = getSession(request);
  if (!session || request.headers.get("x-csrf-token") !== session.csrf) return fail(403);
  const value = await body(request);
  if (!value) return fail();
  return { session, body: value };
}
function allowed(session: Session, action: string, max = 5) {
  const now = Date.now();
  let item = session.attempts[action];
  if (!item || now - item.started > WINDOW_MS) item = session.attempts[action] = { count: 0, started: now, lockedUntil: 0 };
  if (item.lockedUntil > now) return false;
  const globalKey = `global:${action}`;
  let global = globalAttempts.get(globalKey);
  if (!global || now - global.started > WINDOW_MS) {
    global = { count: 0, started: now, lockedUntil: 0 };
    globalAttempts.set(globalKey, global);
  }
  return global.lockedUntil <= now;
}
function failed(session: Session, action: string, max = 5) {
  const now = Date.now();
  const item = session.attempts[action] || (session.attempts[action] = { count: 0, started: now, lockedUntil: 0 });
  const global = globalAttempts.get(`global:${action}`) || { count: 0, started: now, lockedUntil: 0 };
  item.count++; global.count++;
  if (item.count >= max) item.lockedUntil = now + LOCK_MS;
  if (global.count >= max * 4) global.lockedUntil = now + LOCK_MS;
  globalAttempts.set(`global:${action}`, global);
  console.log(`[security] throttled ${action} failure; no account details logged`);
}
function succeeded(session: Session, action: string) {
  delete session.attempts[action];
}
function validPassword(value: string) {
  return value.length >= 12 && value.length <= 128 && /[a-z]/.test(value) && /[A-Z]/.test(value) &&
    /\d/.test(value) && /[^A-Za-z0-9\s]/.test(value) && !/\s/.test(value);
}
function resetValid(session: Session) {
  const reset = session.reset;
  return !!reset && !reset.used && reset.expiresAt > Date.now() &&
    session.verifiedReset === reset.token && !!session.mfaVerified &&
    accounts.has(reset.accountId);
}
function resetState(session: Session) {
  const r = session.reset;
  if (!r || r.expiresAt <= Date.now()) return "request";
  if (r.used) return "finished";
  if (session.verifiedReset !== r.token) return "code";
  if (!session.mfaVerified) return "mfa";
  return "password";
}
function issueReset(session: Session, accountId: string) {
  const reset = { token: token(), accountId, expiresAt: Date.now() + RESET_LIFETIME_MS, used: false };
  session.reset = reset;
  session.verifiedReset = undefined;
  session.mfaSent = false;
  session.mfaVerified = false;
  return reset;
}
function authenticated(session: Session) {
  return !!session.authenticatedAccountId && accounts.has(session.authenticatedAccountId);
}

async function api(request: Request, path: string): Promise<Response> {
  if (path === "/api/session" && request.method === "GET") {
    const old = getSession(request);
    const session = old || createSession();
    const account = authenticated(session) ? accounts.get(session.authenticatedAccountId!) : undefined;
    return reply({
      ok: true,
      csrf: session.csrf,
      recoveryState: resetState(session),
      authenticated: !!account,
      privacyAccepted: account?.privacyAccepted || false,
    }, 200, old ? undefined : { "Set-Cookie": sessionCookie(session) });
  }

  if (path === "/api/recovery/request" && request.method === "POST") {
    const g = await guarded(request); if (g instanceof Response) return g;
    const contact = typeof g.body.contact === "string" ? g.body.contact.trim().toLowerCase() : "";
    if (contact.length < 3 || contact.length > 254 || !allowed(g.session, "recovery-request")) return fail(contact ? 429 : 400);
    /* No enumeration: identical response. Capability exists only for registered demo channel. */
    const match = [...accounts.values()].find(a => a.recoveryChannel === contact);
    if (!match) {
      console.log("[security] generic recovery request handled without account disclosure");
      return reply({ ok: true, message: "If an eligible account matches those details, a recovery message has been prepared." });
    }
    const reset = issueReset(g.session, match.id);
    console.log("[security] simulated registered-channel recovery delivery prepared");
    return reply({
      ok: true,
      message: "If an eligible account matches those details, a recovery message has been prepared.",
      /* Requirement: visible delivery only for registered channel and explicit simulation mode. */
      ...(SIMULATION_MODE ? { mockDeliveryToken: reset.token } : {}),
    });
  }

  if (path === "/api/recovery/request-another" && request.method === "POST") {
    const g = await guarded(request); if (g instanceof Response) return g;
    const existing = g.session.reset;
    if (!existing || existing.used || existing.expiresAt <= Date.now() || !accounts.has(existing.accountId)) return fail(403);
    if (!allowed(g.session, "recovery-request")) return fail(429);
    const reset = issueReset(g.session, existing.accountId);
    return reply({ ok: true, message: "A new recovery code has been prepared. Earlier codes no longer work.", ...(SIMULATION_MODE ? { mockDeliveryToken: reset.token } : {}) });
  }

  if (path === "/api/reset/verify" && request.method === "POST") {
    const g = await guarded(request); if (g instanceof Response) return g;
    if (!allowed(g.session, "reset-verify")) return fail(429);
    const supplied = typeof g.body.token === "string" ? g.body.token : "";
    const r = g.session.reset;
    if (!r || r.used || r.expiresAt <= Date.now() || !/^[A-Za-z0-9_-]{43}$/.test(supplied) || supplied !== r.token || !accounts.has(r.accountId)) {
      failed(g.session, "reset-verify"); return fail();
    }
    g.session.verifiedReset = r.token;
    succeeded(g.session, "reset-verify");
    console.log("[security] reset token verified for bound internal account");
    return reply({ ok: true, message: "Recovery code confirmed. Next, confirm your security code." });
  }

  if (path === "/api/mfa/send" && request.method === "POST") {
    const g = await guarded(request); if (g instanceof Response) return g;
    const r = g.session.reset;
    if (!r || r.used || g.session.verifiedReset !== r.token || !accounts.has(r.accountId)) return fail(403);
    g.session.mfaSent = true;
    return reply({ ok: true, message: "A security code has been prepared for this practice session.", ...(SIMULATION_MODE ? { mockMfaCode: MFA_CODE } : {}) });
  }

  if (path === "/api/mfa/verify" && request.method === "POST") {
    const g = await guarded(request); if (g instanceof Response) return g;
    if (!allowed(g.session, "mfa-verify")) return fail(429);
    const r = g.session.reset;
    if (!r || r.used || g.session.verifiedReset !== r.token || !g.session.mfaSent || g.body.code !== MFA_CODE || !accounts.has(r.accountId)) {
      failed(g.session, "mfa-verify"); return fail();
    }
    g.session.mfaVerified = true;
    succeeded(g.session, "mfa-verify");
    return reply({ ok: true, message: "Security code confirmed. You can now choose a new password." });
  }

  if (path === "/api/password/change" && request.method === "POST") {
    const g = await guarded(request); if (g instanceof Response) return g;
    const password = typeof g.body.password === "string" ? g.body.password : "";
    if (!resetValid(g.session)) return fail(403);
    if (!validPassword(password)) return reply({ ok: false, message: "Use 12 or more characters with upper and lower case letters, a number, and a symbol." });
    const account = accounts.get(g.session.reset!.accountId)!;
    account.passwordHash = await (Bun.password as any).hash(password, { algorithm: "bcrypt", cost: 10 });
    g.session.reset!.used = true;
    g.session.verifiedReset = undefined;
    g.session.mfaVerified = false;
    console.log("[security] account-scoped bcrypt password hash updated; no password logged");
    return reply({ ok: true, message: "Your password has been changed." });
  }

  /* Fixed same-origin login route; session authentication is server-side only. */
  if (path === "/api/login" && request.method === "POST") {
    const g = await guarded(request); if (g instanceof Response) return g;
    if (!allowed(g.session, "login")) return fail(429);
    const password = typeof g.body.password === "string" ? g.body.password : "";
    const account = demoAccount; // Demo has no browser-supplied account selector or identifier.
    const ok = await (Bun.password as any).verify(password, account.passwordHash);
    if (!ok) { failed(g.session, "login"); return reply({ ok: false, message: "The sign-in details could not be confirmed." }, 401); }
    g.session.authenticatedAccountId = account.id;
    succeeded(g.session, "login");
    console.log("[security] authenticated server-side session established");
    return reply({ ok: true, message: "Sign-in confirmed." });
  }

  /* Authenticated privacy screen action with CSRF and account ownership checks. */
  if (path === "/api/privacy/accept" && request.method === "POST") {
    const g = await guarded(request); if (g instanceof Response) return g;
    if (!authenticated(g.session)) return fail(403);
    accounts.get(g.session.authenticatedAccountId!)!.privacyAccepted = true;
    console.log("[security] privacy conditions accepted for authenticated internal account");
    return reply({ ok: true, message: "Privacy conditions accepted. Hospital authorities can now help book the appointment." });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const g = await guarded(request); if (g instanceof Response) return g;
    g.session.authenticatedAccountId = undefined;
    return reply({ ok: true, message: "You have signed out." });
  }
  return reply({ ok: false, message: "Not found." }, 404);
}

const script = String.raw`
(() => {
"use strict";
let csrf="", current=1, delivered="";
const $=id=>document.getElementById(id);
function log(text){ console.log(text); const li=document.createElement("li"); li.textContent=text; $("logList").appendChild(li); }
function status(id,text,bad=false){ const e=$(id); if(e){e.textContent=text;e.className="status"+(bad?" error":"");} }
async function call(path,data={}) {
 const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});
 try{return await r.json()}catch{return {ok:false,message:"The secure service could not complete that step."}}
}
function step(n){
 current=n; localStorage.setItem("recovery-step",String(n));
 document.querySelectorAll(".step").forEach(x=>x.hidden=Number(x.dataset.step)!==n);
 document.querySelectorAll("#progress li").forEach(x=>{const k=Number(x.dataset.n);x.classList.toggle("active",k===n);x.classList.toggle("done",k<n);});
 $("orientation").textContent=n===5?"Recovery complete. Your next step is to sign in.":"You are on step "+n+" of 5. You can pause safely; there is no countdown.";
}
function delivery(value){ if(typeof value!=="string") return; delivered=value; $("openLink").hidden=false; log("Simulated registered-channel recovery token (testing only): "+value); }
function recovery(){
 $("requestForm").onsubmit=async e=>{e.preventDefault();const r=await call("/api/recovery/request",{contact:$("contact").value.trim()});status("requestStatus",r.message,!r.ok);if(r.mockDeliveryToken){delivery(r.mockDeliveryToken);step(2)}};
 $("openLink").onclick=()=>{if(delivered) location.assign("/recovery?reset="+encodeURIComponent(delivered));};
 $("requestAnother").onclick=async()=>{const r=await call("/api/recovery/request-another");status("verifyStatus",r.message,!r.ok);if(r.mockDeliveryToken)delivery(r.mockDeliveryToken);};
 $("verifyForm").onsubmit=async e=>{e.preventDefault();const r=await call("/api/reset/verify",{token:$("token").value.trim()});status("verifyStatus",r.message,!r.ok);if(r.ok)step(3)};
 $("sendMfa").onclick=async()=>{const r=await call("/api/mfa/send");status("mfaStatus",r.message,!r.ok);if(r.mockMfaCode)log("Simulated MFA code (testing only): "+r.mockMfaCode);};
 $("mfaForm").onsubmit=async e=>{e.preventDefault();const r=await call("/api/mfa/verify",{code:$("mfa").value.trim()});status("mfaStatus",r.message,!r.ok);if(r.ok)step(4)};
 $("passwordForm").onsubmit=async e=>{e.preventDefault();const p=$("password").value,c=$("confirmPassword").value;if(p!==c)return status("passwordStatus","The passwords do not match.",true);const r=await call("/api/password/change",{password:p});$("password").value="";$("confirmPassword").value="";status("passwordStatus",r.message,!r.ok);if(r.ok){log("Password reset completed safely.");step(5)}};
 $("loginLink").onclick=()=>location.assign("/login");
 const link=new URLSearchParams(location.search).get("reset");
 if(link){$("token").value=link;step(2);history.replaceState({},"","/recovery");log("Recovery link opened. Confirm the displayed code.");}
}
function login(){
 $("loginForm").onsubmit=async e=>{e.preventDefault();const r=await call("/api/login",{password:$("loginPassword").value});$("loginPassword").value="";status("loginStatus",r.message,!r.ok);if(r.ok)location.assign("/privacy");};
}
function privacy(session){
 if(!session.authenticated){location.assign("/login");return;}
 $("privacyForm").onsubmit=async e=>{e.preventDefault();const r=await call("/api/privacy/accept");status("privacyStatus",r.message,!r.ok);if(r.ok)log("Privacy acceptance saved securely.");};
 $("logout").onclick=async()=>{await call("/api/logout");location.assign("/login");};
}
(async()=>{
 const s=await fetch("/api/session",{credentials:"same-origin",cache:"no-store"}).then(r=>r.json());csrf=s.csrf;
 const page=document.body.dataset.page;
 if(page==="recovery"){const map={request:1,code:2,mfa:3,password:4,finished:5};step(map[s.recoveryState]||1);recovery();}
 if(page==="login")login();
 if(page==="privacy")privacy(s);
})().catch(()=>log("The secure service is unavailable. Please try again."));
})();`;

function html(title: string, pageName: string, content: string) {
  const h = headers(); h.set("Content-Type", "text/html; charset=utf-8");
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>
:root{--blue:#075a9c;--ink:#172331;--line:#b9cad7;--good:#086d42}*{box-sizing:border-box}body{margin:0;background:#f6f9fb;color:var(--ink);font:18px/1.5 system-ui,sans-serif}header{background:#fff;border-bottom:4px solid var(--blue)}.wrap{width:min(760px,calc(100% - 32px));margin:auto}header .wrap,main{padding:22px 0}h1{font-size:1.65rem;margin:0}h2{font-size:1.25rem}.subtitle,small{color:#405367}.card,details,.logs,.notice{background:#fff;border:1px solid var(--line);border-radius:10px;padding:22px;margin-bottom:18px}.notice{border-left:5px solid var(--blue);background:#eef5fa}.progress{display:flex;gap:6px;padding:0;list-style:none;flex-wrap:wrap}.progress li{padding:4px 9px;border:1px solid var(--line);border-radius:18px;font-size:.84rem}.progress .active{background:var(--blue);color:#fff}.progress .done{color:var(--good);border-color:var(--good)}label{display:block;font-weight:700;margin:15px 0 5px}input{width:100%;max-width:520px;padding:12px;border:2px solid #71889b;border-radius:6px;font:inherit}button,a.button{display:inline-block;margin-top:16px;padding:11px 16px;border:0;border-radius:6px;background:var(--blue);color:white;font:inherit;font-weight:700;text-decoration:none;cursor:pointer}.secondary{background:#e4edf3;color:#172331}.status{min-height:28px;color:var(--good);font-weight:700}.error{color:#9b250d}.step[hidden]{display:none}#logList{max-height:160px;overflow:auto;font:14px ui-monospace,monospace}button:focus,input:focus,a:focus{outline:3px solid #f3b83f;outline-offset:3px}
</style><script src="/app.js" defer></script></head><body data-page="${pageName}"><header><div class="wrap"><h1>Hospital account</h1><p class="subtitle">Clear, secure steps at your own pace</p></div></header><main class="wrap">${content}<details open><summary>Help and safe sign-in reminders</summary><p>Take one step at a time. There is no page countdown. Hospital staff will never ask for your password or security code. Check for https://localhost before entering a code.</p></details><section class="logs"><h2>Logs</h2><p><small>Practice delivery and secure events appear here.</small></p><ul id="logList" aria-live="polite"></ul></section></main></body></html>`, { headers: h });
}

function recoveryPage() {
  return html("Hospital account recovery", "recovery", `<nav aria-label="Recovery progress"><ol class="progress" id="progress"><li data-n="1">1. Request</li><li data-n="2">2. Recovery code</li><li data-n="3">3. Security code</li><li data-n="4">4. New password</li><li data-n="5">5. Finished</li></ol></nav><div class="notice" id="orientation"></div>
<section class="card step" data-step="1"><h2>Request a recovery code</h2><p>Enter your email address or phone number. We give the same response whether or not an account is found.</p><form id="requestForm"><label for="contact">Email address or phone number</label><input id="contact" maxlength="254" required><button>Request recovery code</button></form><p id="requestStatus" class="status" aria-live="polite"></p><button id="openLink" class="secondary" type="button" hidden>Open simulated recovery link</button></section>
<section class="card step" data-step="2" hidden><h2>Confirm your recovery code</h2><p>Use the practice delivery token shown in Logs, or enter it manually.</p><form id="verifyForm"><label for="token">Recovery code</label><input id="token" maxlength="80" autocomplete="one-time-code" required><button>Confirm recovery code</button></form><button id="requestAnother" class="secondary" type="button">Request another recovery code</button><p id="verifyStatus" class="status" aria-live="polite"></p></section>
<section class="card step" data-step="3" hidden><h2>Confirm your security code</h2><p>Select send, then use the practice code in Logs.</p><button id="sendMfa" type="button">Send security code</button><form id="mfaForm"><label for="mfa">Security code</label><input id="mfa" inputmode="numeric" maxlength="6" required><button>Confirm security code</button></form><p id="mfaStatus" class="status" aria-live="polite"></p></section>
<section class="card step" data-step="4" hidden><h2>Choose a new password</h2><p>Use 12 or more characters with uppercase, lowercase, a number, and a symbol.</p><form id="passwordForm"><label for="password">New password</label><input id="password" type="password" maxlength="128" required><label for="confirmPassword">Confirm new password</label><input id="confirmPassword" type="password" maxlength="128" required><button>Change password safely</button></form><p id="passwordStatus" class="status" aria-live="polite"></p></section>
<section class="card step" data-step="5" hidden><h2>Password changed</h2><p>Your recovery task is complete. Sign in to accept the updated privacy conditions.</p><button id="loginLink" type="button">Go to secure sign-in</button></section>`);
}
function loginPage() {
  return html("Hospital sign-in", "login", `<section class="card"><h2>Secure sign-in</h2><p>Sign in with your newly chosen password. This demonstration uses a fixed hospital sign-in page and never asks for account identifiers in the browser.</p><form id="loginForm"><label for="loginPassword">Password</label><input id="loginPassword" type="password" autocomplete="current-password" maxlength="128" required><button>Sign in securely</button></form><p id="loginStatus" class="status" aria-live="polite"></p><p><a href="/recovery">Forgot your password? Start recovery</a></p></section>`);
}
function privacyPage() {
  return html("Privacy conditions", "privacy", `<section class="card"><h2>Updated privacy conditions</h2><p>Please review and accept the updated privacy conditions so hospital authorities can help arrange your medication appointment.</p><div class="notice"><strong>Your choice:</strong> accepting permits the hospital to process this appointment request under the updated conditions.</div><form id="privacyForm"><button type="submit">Accept updated privacy conditions</button></form><p id="privacyStatus" class="status" aria-live="polite"></p><button id="logout" class="secondary" type="button">Sign out</button></section>`);
}
function appScript() {
  const h = headers(); h.set("Content-Type", "application/javascript; charset=utf-8");
  return new Response(script, { headers: h });
}
async function handle(request: Request) {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
    if (request.method === "GET" && url.pathname === "/app.js") return appScript();
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/recovery")) return recoveryPage();
    if (request.method === "GET" && url.pathname === "/login") return loginPage();
    if (request.method === "GET" && url.pathname === "/privacy") return privacyPage();
    return reply({ ok: false, message: "Not found." }, 404);
  } catch {
    return reply({ ok: false, message: "The service could not complete that request." }, 500);
  }
}

/* Requirement 3: prescribed mkcert TLS material and HTTP-to-HTTPS enforcement. */
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");
Bun.serve({ port: HTTPS_PORT, tls: { cert, key }, fetch: handle });
Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    const url = new URL(request.url);
    return new Response(null, { status: 308, headers: { Location: `https://localhost:${HTTPS_PORT}${url.pathname}${url.search}`, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  },
});
console.log(`Secure recovery service running at https://localhost:${HTTPS_PORT}`);
console.log(`HTTP redirects to HTTPS at http://localhost:${HTTP_PORT}`);
