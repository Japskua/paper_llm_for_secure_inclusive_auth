
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";

/*
 Password Recovery System
 Requirement 1: server-side records, session-specific CSRF, access checks.
 Requirement 2: escaped client output and restrictive CSP.
 Requirement 3: TLS, secure headers, short-lived single-use reset tokens.
 Requirement 4: bcrypt passwords, MFA simulation, password policy, throttling.
 Requirement 5: no user-controlled redirects or outbound URLs.
*/

const HTTPS_PORT = 3443;
const HTTP_PORT = 3000;
const RESET_LIFETIME_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const WINDOW_MS = 10 * 60 * 1000;
const MFA_CODE = "246810";
const INITIAL_DEMO_PASSWORD = "HelenaCare#2025";

type Attempt = { count: number; started: number; lockedUntil: number };
type ResetRecord = { token: string; accountId: string; expiresAt: number; used: boolean };
type Account = {
  id: string;
  recoveryEmail: string;
  passwordHash: string;
  privacyAccepted: boolean;
};
type Session = {
  id: string;
  csrf: string;
  reset?: ResetRecord;
  resetVerified?: boolean;
  mfaSent?: boolean;
  mfaVerified?: boolean;
  authenticatedAccountId?: string;
  attempts: Record<string, Attempt>;
};

/*
 Requirement task: this bcrypt value is generated during secure startup from
 HelenaCare#2025, which meets validPassword(): 12+ characters, uppercase,
 lowercase, number, symbol, and no whitespace. It is never sent to the client.
*/
const demoAccount: Account = {
  id: "acct_internal_only",
  recoveryEmail: "helena.demo@hospital.test",
  passwordHash: "",
  privacyAccepted: false,
};

const accounts = new Map([[demoAccount.id, demoAccount]]);
const sessions = new Map<string, Session>();
const globalAttempts = new Map<string, Attempt>();

function token(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

function validPassword(value: string) {
  return value.length >= 12 &&
    value.length <= 128 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /\d/.test(value) &&
    /[^A-Za-z0-9\s]/.test(value) &&
    !/\s/.test(value);
}

function parseCookies(request: Request) {
  const result: Record<string, string> = {};
  for (const pair of (request.headers.get("cookie") || "").split(";")) {
    const index = pair.indexOf("=");
    if (index <= 0) continue;
    try {
      result[pair.slice(0, index).trim()] = decodeURIComponent(pair.slice(index + 1).trim());
    } catch {}
  }
  return result;
}

function createSession(): Session {
  const session: Session = { id: token(), csrf: token(), attempts: {} };
  sessions.set(session.id, session);
  return session;
}

function getSession(request: Request, create = false) {
  const existing = sessions.get(parseCookies(request).hospital_session || "");
  return existing || (create ? createSession() : undefined);
}

function sessionCookie(session: Session) {
  return `hospital_session=${encodeURIComponent(session.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`;
}

/* Requirement 2 and 3: CSP, HSTS, clickjacking, MIME and cache protections. */
function secureHeaders() {
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

function json(value: unknown, status = 200, extra?: HeadersInit) {
  const headers = secureHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) for (const [key, value] of new Headers(extra)) headers.set(key, value);
  return new Response(JSON.stringify(value), { status, headers });
}

function genericFailure(status = 400) {
  return json({ ok: false, message: "We could not complete that step. Please check your entry and try again." }, status);
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/* Requirement 1: all sensitive state-changing requests require session CSRF. */
async function guarded(request: Request): Promise<{ session: Session; data: Record<string, unknown> } | Response> {
  const session = getSession(request);
  if (!session || request.headers.get("x-csrf-token") !== session.csrf) return genericFailure(403);
  const data = await requestBody(request);
  return data ? { session, data } : genericFailure();
}

function isAllowed(session: Session, action: string, maximum = 5) {
  const now = Date.now();
  let entry = session.attempts[action];
  if (!entry || (now - entry.started > WINDOW_MS && entry.lockedUntil <= now)) {
    entry = session.attempts[action] = { count: 0, started: now, lockedUntil: 0 };
  }
  if (entry.lockedUntil > now) return false;
  const key = `global:${action}`;
  let global = globalAttempts.get(key);
  if (!global || (now - global.started > WINDOW_MS && global.lockedUntil <= now)) {
    global = { count: 0, started: now, lockedUntil: 0 };
    globalAttempts.set(key, global);
  }
  return global.lockedUntil <= now && entry.count < maximum;
}

function failure(session: Session, action: string, maximum = 5) {
  const now = Date.now();
  const entry = session.attempts[action] || (session.attempts[action] = { count: 0, started: now, lockedUntil: 0 });
  const key = `global:${action}`;
  const global = globalAttempts.get(key) || { count: 0, started: now, lockedUntil: 0 };
  entry.count++;
  global.count++;
  if (entry.count >= maximum) entry.lockedUntil = now + LOCK_MS;
  if (global.count >= maximum * 4) global.lockedUntil = now + LOCK_MS;
  globalAttempts.set(key, global);
  console.log(`[security] ${action} failed; no private account detail logged`);
}

function success(session: Session, action: string) {
  delete session.attempts[action];
}

function normalizeEmail(value: unknown) {
  if (typeof value !== "string") return "";
  const email = value.trim().toLowerCase();
  return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(email) &&
    email.length <= 254 ? email : "";
}

function resetExpired(session: Session) {
  return !!session.reset && session.reset.expiresAt <= Date.now();
}

function resetReady(session: Session) {
  const reset = session.reset;
  return !!reset && !reset.used && reset.expiresAt > Date.now() &&
    !!session.resetVerified && !!session.mfaVerified && accounts.has(reset.accountId);
}

function recoveryState(session: Session) {
  const reset = session.reset;
  if (!reset || reset.expiresAt <= Date.now()) return "request";
  if (reset.used) return "finished";
  if (!session.resetVerified) return "code";
  if (!session.mfaVerified) return "mfa";
  return "password";
}

function issueReset(session: Session, accountId: string) {
  const reset: ResetRecord = { token: token(), accountId, expiresAt: Date.now() + RESET_LIFETIME_MS, used: false };
  session.reset = reset;
  session.resetVerified = false;
  session.mfaSent = false;
  session.mfaVerified = false;
  return reset;
}

function expired() {
  return json({
    ok: false,
    status: "expired-recovery",
    message: "Your recovery code expired. Return to step 1 to request a new one."
  }, 410);
}

async function api(request: Request, path: string): Promise<Response> {
  if (path === "/api/session" && request.method === "GET") {
    const old = getSession(request);
    const session = old || createSession();
    const account = session.authenticatedAccountId ? accounts.get(session.authenticatedAccountId) : undefined;
    return json({
      ok: true,
      csrf: session.csrf,
      recoveryState: recoveryState(session),
      recoveryExpired: resetExpired(session),
      authenticated: !!account,
      privacyAccepted: !!account?.privacyAccepted,
    }, 200, old ? undefined : { "Set-Cookie": sessionCookie(session) });
  }

  if (path === "/api/recovery/request" && request.method === "POST") {
    const g = await guarded(request);
    if (g instanceof Response) return g;
    const email = normalizeEmail(g.data.email);
    if (!email) return genericFailure();
    const account = [...accounts.values()].find(item => item.recoveryEmail === email);
    console.log("[security] generic registered-email recovery request handled");
    if (!account) {
      return json({ ok: true, message: "If an eligible account matches that email address, a recovery message has been prepared." });
    }
    const reset = issueReset(g.session, account.id);
    console.log("[security] simulated recovery delivery prepared");
    return json({
      ok: true,
      message: "If an eligible account matches that email address, a recovery message has been prepared.",
      mockDeliveryToken: reset.token,
    });
  }

  if (path === "/api/reset/verify" && request.method === "POST") {
    const g = await guarded(request);
    if (g instanceof Response) return g;
    if (resetExpired(g.session)) return expired();
    if (!isAllowed(g.session, "reset-verify")) return genericFailure(429);
    const supplied = typeof g.data.token === "string" ? g.data.token : "";
    const reset = g.session.reset;
    if (!reset || reset.used || !/^[A-Za-z0-9_-]{43}$/.test(supplied) || supplied !== reset.token) {
      failure(g.session, "reset-verify");
      return genericFailure();
    }
    g.session.resetVerified = true;
    success(g.session, "reset-verify");
    console.log("[security] bound recovery token verified");
    return json({ ok: true, message: "Recovery code confirmed. Next, confirm your security code." });
  }

  if (path === "/api/mfa/send" && request.method === "POST") {
    const g = await guarded(request);
    if (g instanceof Response) return g;
    if (resetExpired(g.session)) return expired();
    const reset = g.session.reset;
    if (!reset || reset.used || !g.session.resetVerified) return genericFailure(403);
    g.session.mfaSent = true;
    console.log("[security] simulated MFA delivery prepared");
    return json({ ok: true, message: "A security code has been prepared for this practice session.", mockMfaCode: MFA_CODE });
  }

  if (path === "/api/mfa/verify" && request.method === "POST") {
    const g = await guarded(request);
    if (g instanceof Response) return g;
    if (resetExpired(g.session)) return expired();
    if (!isAllowed(g.session, "mfa-verify")) return genericFailure(429);
    if (!g.session.reset || !g.session.resetVerified || !g.session.mfaSent || g.data.code !== MFA_CODE) {
      failure(g.session, "mfa-verify");
      return genericFailure();
    }
    g.session.mfaVerified = true;
    success(g.session, "mfa-verify");
    console.log("[security] simulated MFA code verified");
    return json({ ok: true, message: "Security code confirmed. You can now choose a new password." });
  }

  if (path === "/api/password/change" && request.method === "POST") {
    const g = await guarded(request);
    if (g instanceof Response) return g;
    if (resetExpired(g.session)) return expired();
    const password = typeof g.data.password === "string" ? g.data.password : "";
    if (!resetReady(g.session)) return genericFailure(403);
    if (!validPassword(password)) {
      return json({ ok: false, message: "Use 12 or more characters with upper and lower case letters, a number, and a symbol." });
    }
    const account = accounts.get(g.session.reset!.accountId)!;
    account.passwordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
    g.session.reset!.used = true;
    g.session.resetVerified = false;
    g.session.mfaVerified = false;
    console.log("[security] bcrypt password hash changed; password not logged");
    return json({ ok: true, message: "Your password has been changed." });
  }

  if (path === "/api/login" && request.method === "POST") {
    const g = await guarded(request);
    if (g instanceof Response) return g;
    if (!isAllowed(g.session, "login")) return genericFailure(429);
    const password = typeof g.data.password === "string" ? g.data.password : "";
    const verified = await Bun.password.verify(password, demoAccount.passwordHash);
    if (!verified) {
      failure(g.session, "login");
      return json({ ok: false, message: "The sign-in details could not be confirmed." }, 401);
    }
    g.session.authenticatedAccountId = demoAccount.id;
    success(g.session, "login");
    console.log("[security] authenticated server-side session established");
    return json({ ok: true, message: "Sign-in confirmed." });
  }

  if (path === "/api/privacy/accept" && request.method === "POST") {
    const g = await guarded(request);
    if (g instanceof Response) return g;
    if (!g.session.authenticatedAccountId || !accounts.has(g.session.authenticatedAccountId)) return genericFailure(403);
    accounts.get(g.session.authenticatedAccountId)!.privacyAccepted = true;
    console.log("[security] privacy conditions accepted");
    return json({ ok: true, message: "Privacy conditions accepted. Hospital authorities can now help book the appointment." });
  }

  if (path === "/api/logout" && request.method === "POST") {
    const g = await guarded(request);
    if (g instanceof Response) return g;
    g.session.authenticatedAccountId = undefined;
    return json({ ok: true, message: "You have signed out." });
  }

  return json({ ok: false, message: "Not found." }, 404);
}

const client = String.raw`
"use strict";
let csrf="",state={},delivered="";
const $=id=>document.getElementById(id);
function log(t){console.log(t);const li=document.createElement("li");li.textContent=t;$("logs").append(li)}
function msg(id,t,bad=false){const e=$(id);e.textContent=t||"";e.className="status"+(bad?" bad":"")}
async function load(){const r=await fetch("/api/session",{credentials:"same-origin",cache:"no-store"});state=await r.json();csrf=state.csrf}
async function post(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});return r.json()}
function view(name){document.querySelectorAll(".view").forEach(x=>x.hidden=x.dataset.view!==name)}
function step(n){document.querySelectorAll(".step").forEach(x=>x.hidden=+x.dataset.step!==n);document.querySelectorAll("#progress li").forEach(x=>x.className=(+x.dataset.n===n?"active":+x.dataset.n<n?"done":""));$("orient").textContent=n===5?"Recovery complete. Your next step is to sign in.":"You are on step "+n+" of 5. You can pause safely; there is no countdown."}
function render(){const p=location.pathname;if(p==="/login"){view("login");return}if(p==="/privacy"){if(!state.authenticated){history.replaceState({},"","/login");view("login")}else{view("privacy");if(state.privacyAccepted)msg("privacyMsg","These privacy conditions have already been accepted.")}return}view("recovery");step(({request:1,code:2,mfa:3,password:4,finished:5})[state.recoveryState]||1)}
function go(p){history.pushState({},"",p);render()}
$("request").onsubmit=async e=>{e.preventDefault();const r=await post("/api/recovery/request",{email:$("email").value.trim()});msg("requestMsg",r.message,!r.ok);if(r.mockDeliveryToken){delivered=r.mockDeliveryToken;log("Simulated registered-email recovery token (testing only): "+delivered);$("open").hidden=false;step(2)}};
$("open").onclick=()=>{$("token").value=delivered;step(2);log("Simulated recovery link opened securely.")};
$("verify").onsubmit=async e=>{e.preventDefault();const r=await post("/api/reset/verify",{token:$("token").value.trim()});msg("verifyMsg",r.message,!r.ok);if(r.ok)step(3);if(r.status==="expired-recovery")step(1)};
$("send").onclick=async()=>{const r=await post("/api/mfa/send");msg("mfaMsg",r.message,!r.ok);if(r.mockMfaCode)log("Simulated MFA code (testing only): "+r.mockMfaCode)};
$("mfaForm").onsubmit=async e=>{e.preventDefault();const r=await post("/api/mfa/verify",{code:$("mfa").value.trim()});msg("mfaMsg",r.message,!r.ok);if(r.ok)step(4)};
$("passwordForm").onsubmit=async e=>{e.preventDefault();if($("password").value!==$("confirm").value)return msg("passwordMsg","The passwords do not match.",true);const r=await post("/api/password/change",{password:$("password").value});$("password").value="";$("confirm").value="";msg("passwordMsg",r.message,!r.ok);if(r.ok){log("Password reset completed safely.");await load();step(5)}};
$("toLogin").onclick=()=>go("/login");
$("loginForm").onsubmit=async e=>{e.preventDefault();const r=await post("/api/login",{password:$("loginPassword").value});$("loginPassword").value="";msg("loginMsg",r.message,!r.ok);if(r.ok){await load();go("/privacy")}};
$("forgot").onclick=e=>{e.preventDefault();go("/recovery")};
$("privacyForm").onsubmit=async e=>{e.preventDefault();const r=await post("/api/privacy/accept");msg("privacyMsg",r.message,!r.ok);if(r.ok){log("Privacy acceptance saved securely.");await load()}};
$("logout").onclick=async()=>{await post("/api/logout");await load();go("/login")};
document.querySelectorAll("[data-go]").forEach(a=>a.onclick=e=>{e.preventDefault();go(a.dataset.go)});
window.onpopstate=render;
load().then(render).catch(()=>log("The secure service is unavailable. Please try again."));
`;

function page() {
  const headers = secureHeaders();
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hospital account</title><style>
:root{--blue:#075a9c;--ink:#172331;--line:#b9cad7;--good:#086d42}*{box-sizing:border-box}body{margin:0;background:#f6f9fb;color:var(--ink);font:18px/1.5 system-ui,sans-serif}.wrap{width:min(760px,calc(100% - 32px));margin:auto}header{background:#fff;border-bottom:4px solid var(--blue)}header .wrap,main{padding:22px 0}h1{font-size:1.65rem;margin:0}h2{font-size:1.25rem}.topnav{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px}.topnav a{color:var(--blue);font-weight:700}.card,.notice,details,.logbox{background:#fff;border:1px solid var(--line);border-radius:10px;padding:22px;margin-bottom:18px}.notice{border-left:5px solid var(--blue);background:#eef5fa}.progress{display:flex;gap:6px;flex-wrap:wrap;padding:0;list-style:none}.progress li{font-size:.84rem;border:1px solid var(--line);border-radius:18px;padding:4px 9px}.progress .active{background:var(--blue);color:#fff}.progress .done{border-color:var(--good);color:var(--good)}label{display:block;font-weight:700;margin:15px 0 5px}input{width:100%;max-width:520px;padding:12px;border:2px solid #71889b;border-radius:6px;font:inherit}button{margin-top:16px;padding:11px 16px;border:0;border-radius:6px;background:var(--blue);color:#fff;font:inherit;font-weight:700;cursor:pointer}.secondary{background:#e4edf3;color:var(--ink)}.status{min-height:28px;color:var(--good);font-weight:700}.status.bad{color:#9b250d}.view[hidden],.step[hidden]{display:none}#logs{max-height:160px;overflow:auto;font:14px ui-monospace,monospace}button:focus,input:focus,a:focus{outline:3px solid #f3b83f;outline-offset:3px}
</style><script src="/app.js" defer></script></head><body><header><div class="wrap"><h1>Hospital account</h1><p>Clear, secure steps at your own pace</p><nav class="topnav"><a href="/recovery" data-go="/recovery">Password recovery</a><a href="/login" data-go="/login">Secure sign-in</a><a href="/privacy" data-go="/privacy">Privacy conditions</a></nav></div></header><main class="wrap">
<section class="view" data-view="recovery"><ol class="progress" id="progress"><li data-n="1">1. Request</li><li data-n="2">2. Recovery code</li><li data-n="3">3. Security code</li><li data-n="4">4. New password</li><li data-n="5">5. Finished</li></ol><div class="notice" id="orient"></div>
<section class="card step" data-step="1"><h2>Request a recovery code</h2><p>Enter your registered email address. We give the same response whether or not an account is found.</p><form id="request"><label for="email">Email address</label><input id="email" type="email" maxlength="254" required><button>Request recovery code</button></form><p id="requestMsg" class="status" aria-live="polite"></p><button id="open" type="button" class="secondary" hidden>Open simulated recovery link</button></section>
<section class="card step" data-step="2" hidden><h2>Confirm your recovery code</h2><p>Use the practice delivery token shown in Logs, or enter it manually.</p><form id="verify"><label for="token">Recovery code</label><input id="token" maxlength="80" required><button>Confirm recovery code</button></form><p id="verifyMsg" class="status" aria-live="polite"></p></section>
<section class="card step" data-step="3" hidden><h2>Confirm your security code</h2><p>Select send, then use the practice code in Logs.</p><button id="send" type="button">Send security code</button><form id="mfaForm"><label for="mfa">Security code</label><input id="mfa" maxlength="6" required><button>Confirm security code</button></form><p id="mfaMsg" class="status" aria-live="polite"></p></section>
<section class="card step" data-step="4" hidden><h2>Choose a new password</h2><p>Use 12 or more characters with uppercase, lowercase, a number, and a symbol.</p><form id="passwordForm"><label for="password">New password</label><input id="password" type="password" maxlength="128" required><label for="confirm">Confirm new password</label><input id="confirm" type="password" maxlength="128" required><button>Change password safely</button></form><p id="passwordMsg" class="status" aria-live="polite"></p></section>
<section class="card step" data-step="5" hidden><h2>Password changed</h2><p>Your recovery task is complete. Sign in to accept the updated privacy conditions.</p><button id="toLogin" type="button">Go to secure sign-in</button></section></section>
<section class="view" data-view="login" hidden><section class="card"><h2>Secure sign-in</h2><p>Sign in with your password. This fixed hospital page never asks for account identifiers in the browser.</p><form id="loginForm"><label for="loginPassword">Password</label><input id="loginPassword" type="password" maxlength="128" required><button>Sign in securely</button></form><p id="loginMsg" class="status" aria-live="polite"></p><p><a href="/recovery" id="forgot">Forgot your password? Start recovery</a></p></section></section>
<section class="view" data-view="privacy" hidden><section class="card"><h2>Updated privacy conditions</h2><p>Please accept the updated privacy conditions so hospital authorities can help arrange your medication appointment.</p><div class="notice"><strong>Your choice:</strong> accepting permits hospital processing of this appointment request.</div><form id="privacyForm"><button>Accept updated privacy conditions</button></form><p id="privacyMsg" class="status" aria-live="polite"></p><button id="logout" type="button" class="secondary">Sign out</button></section></section>
<details open><summary>Help and safe sign-in reminders</summary><p>Take one step at a time. There is no page countdown. Hospital staff will never ask for your password or security code. Check for https://localhost before entering a code.</p></details><section class="logbox"><h2>Logs</h2><ul id="logs" aria-live="polite"></ul></section></main></body></html>`, { headers });
}

function appScript() {
  const headers = secureHeaders();
  headers.set("Content-Type", "application/javascript; charset=utf-8");
  return new Response(client, { headers });
}

async function handle(request: Request) {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
    if (request.method === "GET" && url.pathname === "/app.js") return appScript();
    if (request.method === "GET" && ["/", "/recovery", "/login", "/privacy"].includes(url.pathname)) return page();
    return json({ ok: false, message: "Not found." }, 404);
  } catch {
    return json({ ok: false, message: "The service could not complete that request." }, 500);
  }
}

/* Requirement 3: mkcert TLS and HTTP-to-HTTPS enforcement. */
async function start() {
  if (!validPassword(INITIAL_DEMO_PASSWORD)) throw new Error("Invalid initial password policy");
  demoAccount.passwordHash = await Bun.password.hash(INITIAL_DEMO_PASSWORD, { algorithm: "bcrypt", cost: 10 });

  const cert = readFileSync("certs/cert.pem", "utf8");
  const key = readFileSync("certs/key.pem", "utf8");

  Bun.serve({ port: HTTPS_PORT, tls: { cert, key }, fetch: handle });
  Bun.serve({
    port: HTTP_PORT,
    fetch(request) {
      const url = new URL(request.url);
      return new Response(null, {
        status: 308,
        headers: {
          Location: `https://localhost:${HTTPS_PORT}${url.pathname}${url.search}`,
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      });
    },
  });

  console.log(`Secure recovery service running at https://localhost:${HTTPS_PORT}`);
  console.log(`HTTP redirects to HTTPS at http://localhost:${HTTP_PORT}`);
}

start().catch(() => console.log("Secure recovery service could not start."));
