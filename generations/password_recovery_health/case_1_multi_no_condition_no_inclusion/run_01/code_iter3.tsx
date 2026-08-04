
import { randomBytes, timingSafeEqual } from "node:crypto";

/*
  Password Recovery System — single-file Bun TLS server + vanilla HTML SPA.

  Requirement 1: session-bound CSRF and authorization state checks.
  Requirement 2: client uses textContent / DOM APIs, never untrusted HTML.
  Requirement 3: TLS-only server, secure headers, random expiring reset tokens.
  Requirement 4: bcrypt password hashing, MFA, strong passwords, global throttles.
  Requirement 5: fixed local navigation and anti-phishing guidance.
*/

type Session = {
  id: string;
  csrf: string;
  createdAt: number;
  ownershipPending: boolean;
  ownershipProven: boolean;
  resetVerified: boolean;
  passwordUpdated: boolean;
  mfaComplete: boolean;
  privacyAccepted: boolean;
};

type ResetRecord = {
  token: string;
  sessionId: string;
  expiresAt: number;
  used: boolean;
};

type ThrottleRecord = {
  attempts: number[];
  blockedUntil: number;
  touchedAt: number;
};

const SESSION_COOKIE = "__Host-hospital_recovery";
const SESSION_AGE_SECONDS = 30 * 60;
const RESET_AGE_MS = 10 * 60_000;
const THROTTLE_MAX_RECORDS = 128;

const MOCK_OWNERSHIP_PROOF = "ACADEMIC-PROOF-4821";
const MOCK_MFA_CODE = "482913";

const sessions = new Map<string, Session>();
const resetTokens = new Map<string, ResetRecord>();
const sharedThrottle = new Map<string, ThrottleRecord>();

let mockPasswordHash = await Bun.password.hash("Initial-Demo-Password!9", {
  algorithm: "bcrypt",
  cost: 10,
});

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function nonce(): string {
  return randomToken(18);
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  const raw = request.headers.get("cookie") || "";
  for (const item of raw.split(";")) {
    const index = item.indexOf("=");
    if (index > 0) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}

function newSession(): Session {
  return {
    id: randomToken(),
    csrf: randomToken(),
    createdAt: Date.now(),
    ownershipPending: false,
    ownershipProven: false,
    resetVerified: false,
    passwordUpdated: false,
    mfaComplete: false,
    privacyAccepted: false,
  };
}

function sessionFor(request: Request, create = false): { session?: Session; isNew: boolean } {
  const id = parseCookies(request)[SESSION_COOKIE];
  const current = id ? sessions.get(id) : undefined;

  if (current && Date.now() - current.createdAt < SESSION_AGE_SECONDS * 1000) {
    return { session: current, isNew: false };
  }

  if (!create) return { isNew: false };

  const session = newSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function sessionCookie(session: Session): string {
  return `${SESSION_COOKIE}=${session.id}; Path=/; Max-Age=${SESSION_AGE_SECONDS}; HttpOnly; Secure; SameSite=Strict`;
}

function securityHeaders(scriptNonce: string, contentType = "text/html; charset=utf-8"): Headers {
  return new Headers({
    "Content-Type": contentType,
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy":
      `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; ` +
      `form-action 'self'; connect-src 'self'; img-src 'self'; style-src 'nonce-${scriptNonce}'; ` +
      `script-src 'nonce-${scriptNonce}'`,
  });
}

function json(body: Record<string, unknown>, status = 200, cookie?: string): Response {
  const headers = securityHeaders(nonce(), "application/json; charset=utf-8");
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(status = 400): Response {
  return json({ ok: false, message: "We could not process that request. Please try again." }, status);
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  if (!(request.headers.get("content-type") || "").includes("application/json")) return null;
  const raw = await request.text();
  if (raw.length > 4096) return null;
  try {
    const body = JSON.parse(raw);
    return body && typeof body === "object" && !Array.isArray(body)
      ? body as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* Requirement 1: every sensitive POST validates a unique session CSRF secret. */
function csrfSession(request: Request, data: Record<string, unknown>): Session | null {
  const { session } = sessionFor(request);
  if (!session || typeof data.csrf !== "string") return null;
  return constantTimeEqual(session.csrf, data.csrf) ? session : null;
}

/*
  Requirement 4: Non-session-bound throttle identity.

  This server has no configured trusted reverse proxy. Therefore it deliberately
  uses a fixed global action scope and never reads X-Forwarded-For, Forwarded,
  cookies, or any client-controlled request header. A new cookie/session or a
  spoofed header cannot reset a limit. If deployed behind a trusted proxy, this
  can be replaced only with server-configured, proxy-authenticated peer identity.
*/
function throttleScope(_request: Request): string {
  return "global-server-action-limiter";
}

function throttleKey(request: Request, action: string): string {
  return `${action}:${throttleScope(request)}`;
}

function trimThrottleRecords(): void {
  if (sharedThrottle.size <= THROTTLE_MAX_RECORDS) return;
  const excess = [...sharedThrottle.entries()]
    .sort((a, b) => a[1].touchedAt - b[1].touchedAt)
    .slice(0, sharedThrottle.size - THROTTLE_MAX_RECORDS);
  for (const [key] of excess) sharedThrottle.delete(key);
}

function isSharedBlocked(request: Request, action: string): boolean {
  const record = sharedThrottle.get(throttleKey(request, action));
  return !!record && record.blockedUntil > Date.now();
}

/*
  Registers only failed security proofs. The action key is independent of
  browser session state and each action has its own counter.
*/
function registerSharedFailure(
  request: Request,
  action: string,
  limit: number,
  windowMs: number,
  blockMs: number,
): void {
  const now = Date.now();
  const key = throttleKey(request, action);
  let record = sharedThrottle.get(key);

  if (!record) {
    record = { attempts: [], blockedUntil: 0, touchedAt: now };
    sharedThrottle.set(key, record);
    trimThrottleRecords();
  }

  record.touchedAt = now;
  record.attempts = record.attempts.filter((time) => now - time < windowMs);
  record.attempts.push(now);

  if (record.attempts.length >= limit) {
    record.attempts = [];
    record.blockedUntil = now + blockMs;
  }
}

function validPassword(password: string): string | null {
  if (password.length < 12 || password.length > 128) return "Use 12 to 128 characters.";
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) ||
      !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  return null;
}

/* Requirement 3: expire sensitive server state and old limiter records. */
setInterval(() => {
  const now = Date.now();

  for (const [token, record] of resetTokens) {
    if (record.used || record.expiresAt < now) resetTokens.delete(token);
  }
  for (const [id, session] of sessions) {
    if (now - session.createdAt > SESSION_AGE_SECONDS * 1000) sessions.delete(id);
  }
  for (const [key, record] of sharedThrottle) {
    if (record.blockedUntil < now && now - record.touchedAt > 30 * 60_000) {
      sharedThrottle.delete(key);
    }
  }
}, 60_000).unref();

function page(scriptNonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital Account Recovery</title>
<style nonce="${scriptNonce}">
:root{color-scheme:light;--navy:#12314a;--blue:#1769aa;--pale:#eef6fa;--line:#bfd0db;--red:#a12d2d;--green:#16683b}
*{box-sizing:border-box}body{margin:0;min-height:100vh;font:17px/1.55 Arial,Helvetica,sans-serif;color:#17242d;background:#f4f7f8}
header{background:var(--navy);color:#fff;padding:1.2rem;border-bottom:5px solid #4aa7bb}header div,main,footer{max-width:760px;margin:auto}h1{margin:0;font-size:1.45rem}h2{margin-top:0;color:var(--navy);line-height:1.25}h3{color:var(--navy);font-size:1.05rem}
main{padding:2rem 1rem 1rem}.card{background:#fff;border:1px solid var(--line);border-radius:8px;padding:1.5rem;box-shadow:0 1px 2px #00000012}label{display:block;margin:1rem 0 .3rem;font-weight:bold}
input{width:100%;padding:.7rem;border:2px solid #748896;border-radius:4px;font:inherit}input:focus{outline:3px solid #87cce0;outline-offset:1px}input[type=checkbox]{width:auto;margin:.15rem .55rem 0 0;transform:scale(1.25)}
.check{display:flex;align-items:flex-start;font-weight:normal;margin-top:1rem}button{margin-top:1.25rem;padding:.75rem 1.1rem;border:0;border-radius:4px;background:var(--blue);color:#fff;font-size:1rem;font-weight:bold;cursor:pointer}button:hover{background:#0c527f}button:disabled{background:#70818b;cursor:wait}
.notice{margin:1rem 0;padding:.8rem 1rem;border-left:5px solid #287da1;background:var(--pale)}.success{border-left-color:var(--green);background:#ebf8ef}.error{border-left-color:var(--red);background:#fff0f0;color:#6c1717}
.conditions{padding:1rem;border:1px solid var(--line);border-radius:4px;background:#f8fbfc}.guidance{margin-top:1.5rem;padding-top:1rem;border-top:1px solid var(--line);font-size:.96rem}.guidance strong{color:var(--navy)}.small{color:#43545e;font-size:.92rem}
#logs{max-height:180px;overflow:auto;padding:.8rem;border-radius:4px;background:#10232d;color:#d9f5e4;white-space:pre-wrap;font:13px/1.4 ui-monospace,monospace}footer{padding:1rem;color:#42535d;font-size:.9rem}
</style>
</head>
<body>
<header><div><h1>Hospital Account Portal</h1></div></header>
<main>
<div id="app" aria-live="polite">Loading secure recovery…</div>
<section aria-label="Mock operation logs"><h2>Logs</h2><p class="small">Academic simulation activity shown from the browser console.</p><pre id="logs">Ready.</pre></section>
</main>
<footer>Verified localhost portal · Secure password recovery demonstration</footer>
<script nonce="${scriptNonce}">
(() => {
"use strict";
let csrf="";
const app=document.getElementById("app"), logs=document.getElementById("logs");
const el=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n};
function logMock(event,details){console.log("[Hospital recovery mock]",event,details);const line=event+" "+JSON.stringify(details);logs.textContent=logs.textContent==="Ready."?line:logs.textContent+"\\n"+line;logs.scrollTop=logs.scrollHeight}
function card(title){const s=el("section");s.className="card";s.append(el("h2",title));return s}
function notice(text,kind){const n=el("p",text);n.className="notice"+(kind?" "+kind:"");return n}
function guide(){const a=el("aside");a.className="guidance";a.append(el("strong","Protect your account: "),document.createTextNode("Hospital staff never ask for your password or verification codes by email or phone. Use only this verified localhost portal. Never forward a recovery link or code."));return a}
function field(form,label,type,name,auto){const l=el("label",label),i=document.createElement("input");l.htmlFor=name;i.type=type;i.id=name;i.name=name;i.required=true;i.autocomplete=auto||"off";form.append(l,i);return i}
async function api(path,data){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-Requested-With":"HospitalRecovery"},body:JSON.stringify(Object.assign({},data,{csrf}))});const p=await r.json().catch(()=>({ok:false,message:"A secure response could not be read."}));return {r,p}}
function replace(s){s.append(guide());app.replaceChildren(s)}
function request(message){
 const s=card("Reset your password");s.append(el("p","Enter a non-identifying academic test identifier. The same response is returned for every submitted identifier."));if(message)s.append(notice(message,"success"));
 const f=document.createElement("form"),id=field(f,"Academic test identifier","text","academic-identifier","username"),b=el("button","Continue to ownership proof"),out=el("div");id.maxLength=100;id.placeholder="Example: academic-test-user";b.type="submit";f.append(b,out);
 f.addEventListener("submit",async e=>{e.preventDefault();b.disabled=true;const x=await api("/api/request-reset",{identifier:id.value});b.disabled=false;out.replaceChildren(notice(x.p.message||"If eligible, continue with account ownership proof.","success"));if(x.p.ok){logMock("Reset request accepted with privacy-preserving response",{next:"ownership-proof"});setTimeout(ownership,200)}});
 s.append(f);replace(s)
}
function ownership(message){
 const s=card("Prove account ownership");s.append(el("p","Before recovery instructions are issued, complete the simulated academic account-ownership proof."),el("p","Testing proof value: ACADEMIC-PROOF-4821"));logMock("Ownership proof challenge simulated",{proof:"ACADEMIC-PROOF-4821"});if(message)s.append(notice(message,"error"));
 const f=document.createElement("form"),p=field(f,"Ownership proof","text","ownership-proof","one-time-code"),b=el("button","Verify ownership");p.maxLength=64;b.type="submit";f.append(b);
 f.addEventListener("submit",async e=>{e.preventDefault();b.disabled=true;const x=await api("/api/prove-ownership",{proof:p.value.trim()});b.disabled=false;if(x.p.ok&&x.p.delivery){logMock("Reset delivery simulated",x.p.delivery);code("A simulated recovery link and code have been delivered. They are visible in the Logs panel for this academic test.")}else ownership(x.p.message||"The ownership proof cannot be verified.")});
 s.append(f);replace(s)
}
function code(message){
 const s=card("Verify recovery code");s.append(el("p","Open the simulated recovery link in this same browser, or enter the recovery code manually."));if(message)s.append(notice(message,message.includes("delivered")?"success":"error"));
 const f=document.createElement("form"),t=field(f,"Recovery code","text","recovery-code","one-time-code"),b=el("button","Verify code");t.maxLength=100;t.pattern="[A-Za-z0-9_-]+";b.type="submit";f.append(b);
 f.addEventListener("submit",async e=>{e.preventDefault();b.disabled=true;const x=await api("/api/verify-token",{token:t.value.trim()});b.disabled=false;x.p.ok?password():code(x.p.message||"This recovery code cannot be used.")});
 s.append(f);replace(s)
}
function password(){
 const s=card("Choose a new password");s.append(el("p","Use at least 12 characters, including uppercase, lowercase, a number, and a symbol."));
 const f=document.createElement("form"),p=field(f,"New password","password","new-password","new-password"),c=field(f,"Confirm new password","password","confirm-password","new-password"),b=el("button","Update password"),out=el("div");b.type="submit";f.append(b,out);
 f.addEventListener("submit",async e=>{e.preventDefault();if(p.value!==c.value){out.replaceChildren(notice("The passwords do not match.","error"));return}b.disabled=true;const x=await api("/api/change-password",{password:p.value,confirmation:c.value});b.disabled=false;if(x.p.ok){logMock("MFA challenge simulated",{code:x.p.mfaCode,purpose:"post-reset verification"});mfa()}else out.replaceChildren(notice(x.p.message||"Password update could not be completed.","error"))});
 s.append(f);replace(s)
}
function mfa(message){
 const s=card("Confirm account security");s.append(el("p","Enter the six-digit verification code from the simulated secure authenticator step."));if(message)s.append(notice(message,"error"));
 const f=document.createElement("form"),c=field(f,"Verification code","text","mfa-code","one-time-code"),b=el("button","Confirm and continue");c.inputMode="numeric";c.maxLength=6;c.pattern="[0-9]{6}";b.type="submit";f.append(b);
 f.addEventListener("submit",async e=>{e.preventDefault();b.disabled=true;const x=await api("/api/verify-mfa",{code:c.value.trim()});b.disabled=false;x.p.ok?privacy():mfa(x.p.message||"That verification code cannot be used.")});
 s.append(f);replace(s)
}
function privacy(message){
 const s=card("Updated privacy conditions");s.append(el("p","Your password reset and security verification are complete. Review and affirmatively accept the updated conditions before appointment booking can continue."));if(message)s.append(notice(message,"error"));
 const d=el("div");d.className="conditions";d.append(el("h3","Privacy conditions"),el("p","I understand that hospital authorities may process the minimum necessary account information to arrange my medication review appointment."),el("p","I understand that I may withdraw this consent through the hospital's verified account support process."));
 const f=document.createElement("form"),l=el("label"),c=document.createElement("input"),b=el("button","Accept conditions and continue");l.className="check";c.type="checkbox";c.required=true;c.id="privacy-consent";l.htmlFor=c.id;l.append(c,document.createTextNode(" I have read and accept the updated privacy conditions."));b.type="submit";f.append(l,b);
 f.addEventListener("submit",async e=>{e.preventDefault();if(!c.checked){privacy("Please affirmatively check the consent box before continuing.");return}b.disabled=true;const x=await api("/api/accept-privacy",{accepted:true});b.disabled=false;if(x.p.ok){logMock("Privacy conditions consent recorded",{accepted:true});complete()}else privacy(x.p.message||"Consent could not be recorded.")});
 s.append(d,f);replace(s)
}
function complete(){
 const s=card("Appointment booking may continue");s.append(notice("Your password has been reset, multi-factor verification is complete, and you accepted the updated privacy conditions. Hospital authorities may now continue appointment booking.","success"),el("p","For your safety, do not share your new password or any verification code."));
 const b=el("button","Return to recovery start");b.type="button";b.addEventListener("click",()=>{history.replaceState({},"","/");request()});s.append(b);app.replaceChildren(s)
}
async function boot(){
 try{const r=await fetch("/api/session",{credentials:"same-origin"}),s=await r.json();csrf=typeof s.csrf==="string"?s.csrf:"";const token=new URLSearchParams(location.search).get("token");
 if(token&&/^[A-Za-z0-9_-]{20,100}$/.test(token)){history.replaceState({},"","/");const x=await api("/api/verify-token",{token});x.p.ok?password():code(x.p.message||"This recovery link cannot be used.")}
 else if(s.privacyAccepted)complete();else if(s.mfaComplete)privacy();else if(s.passwordUpdated)mfa();else if(s.resetVerified)password();else if(s.ownershipPending&&!s.ownershipProven)ownership();else request()
 }catch{app.replaceChildren(notice("The secure portal is temporarily unavailable. Please refresh and try again.","error"))}
}
boot();
})();
</script>
</body>
</html>`;
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "GET" && path === "/api/session") {
    const result = sessionFor(request, true);
    const session = result.session!;
    return json({
      ok: true,
      csrf: session.csrf,
      ownershipPending: session.ownershipPending,
      ownershipProven: session.ownershipProven,
      resetVerified: session.resetVerified,
      passwordUpdated: session.passwordUpdated,
      mfaComplete: session.mfaComplete,
      privacyAccepted: session.privacyAccepted,
    }, 200, result.isNew ? sessionCookie(session) : undefined);
  }

  if (request.method === "POST" && path === "/api/request-reset") {
    const data = await requestBody(request);
    if (!data) return genericError();
    const session = csrfSession(request, data);
    if (!session) return genericError(403);

    /*
      Privacy preserving: identifier is deliberately not read, stored, or
      compared. The UI receives the same successful response in every case.
    */
    session.ownershipPending = true;
    session.ownershipProven = false;
    return json({
      ok: true,
      message: "If eligible, continue with account ownership proof.",
      next: "ownership-proof",
    });
  }

  /*
    Requirement 4 / requested change:
    ownership proof has a dedicated failure action key. Blocking is checked
    before inspecting proof input, and every invalid proof registers a failure.
    This is global and not session/cookie/header-bound.
  */
  if (request.method === "POST" && path === "/api/prove-ownership") {
    const data = await requestBody(request);
    if (!data) return genericError();
    const session = csrfSession(request, data);
    if (!session || !session.ownershipPending || session.ownershipProven) return genericError(403);

    const ownershipAction = "ownership-proof-failure";
    if (isSharedBlocked(request, ownershipAction)) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }

    const proof = typeof data.proof === "string" ? data.proof : "";
    if (!constantTimeEqual(proof, MOCK_OWNERSHIP_PROOF)) {
      registerSharedFailure(request, ownershipAction, 5, 10 * 60_000, 5 * 60_000);
      return json({ ok: false, message: "The ownership proof cannot be verified." });
    }

    session.ownershipProven = true;
    const token = randomToken(32);
    resetTokens.set(token, {
      token,
      sessionId: session.id,
      expiresAt: Date.now() + RESET_AGE_MS,
      used: false,
    });

    return json({
      ok: true,
      message: "Recovery instructions have been simulated.",
      delivery: {
        token,
        resetLink: `/reset?token=${token}`,
        expiresInMinutes: 10,
      },
    });
  }

  if (request.method === "POST" && path === "/api/verify-token") {
    const data = await requestBody(request);
    if (!data) return genericError();
    const session = csrfSession(request, data);
    if (!session) return genericError(403);

    const tokenAction = "reset-token-failure";
    if (isSharedBlocked(request, tokenAction)) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }

    const token = typeof data.token === "string" ? data.token : "";
    const record = resetTokens.get(token);
    const valid = /^[A-Za-z0-9_-]{20,100}$/.test(token) &&
      !!record &&
      record.expiresAt >= Date.now() &&
      !record.used &&
      record.sessionId === session.id;

    if (!valid) {
      registerSharedFailure(request, tokenAction, 5, 10 * 60_000, 5 * 60_000);
      return json({ ok: false, message: "This recovery code cannot be verified." });
    }

    record!.used = true;
    session.resetVerified = true;
    return json({ ok: true });
  }

  if (request.method === "POST" && path === "/api/change-password") {
    const data = await requestBody(request);
    if (!data) return genericError();
    const session = csrfSession(request, data);
    if (!session || !session.resetVerified || session.passwordUpdated) return genericError(403);

    const password = typeof data.password === "string" ? data.password : "";
    const confirmation = typeof data.confirmation === "string" ? data.confirmation : "";
    if (password !== confirmation) return json({ ok: false, message: "The passwords do not match." });

    const policyError = validPassword(password);
    if (policyError) return json({ ok: false, message: policyError });

    /* Requirement 4: only bcrypt hash is retained, never plaintext. */
    mockPasswordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
    session.passwordUpdated = true;
    return json({ ok: true, mfaCode: MOCK_MFA_CODE });
  }

  if (request.method === "POST" && path === "/api/verify-mfa") {
    const data = await requestBody(request);
    if (!data) return genericError();
    const session = csrfSession(request, data);
    if (!session || !session.passwordUpdated) return genericError(403);

    const mfaAction = "mfa-failure";
    if (isSharedBlocked(request, mfaAction)) {
      return json({ ok: false, message: "Too many attempts. Please wait before trying again." }, 429);
    }

    const code = typeof data.code === "string" ? data.code : "";
    if (!constantTimeEqual(code, MOCK_MFA_CODE)) {
      registerSharedFailure(request, mfaAction, 5, 10 * 60_000, 5 * 60_000);
      return json({ ok: false, message: "That verification code cannot be verified." });
    }

    session.mfaComplete = true;
    return json({ ok: true });
  }

  if (request.method === "POST" && path === "/api/accept-privacy") {
    const data = await requestBody(request);
    if (!data) return genericError();
    const session = csrfSession(request, data);
    if (!session || !session.mfaComplete) return genericError(403);

    if (data.accepted !== true) {
      return json({ ok: false, message: "Affirmative consent is required before continuing." });
    }

    session.privacyAccepted = true;
    return json({ ok: true });
  }

  /* Requirement 5: fixed same-origin SPA routes; no user-controlled redirect. */
  if (request.method === "GET" && (path === "/" || path === "/reset")) {
    const result = sessionFor(request, true);
    const scriptNonce = nonce();
    const headers = securityHeaders(scriptNonce);
    if (result.isNew) headers.set("Set-Cookie", sessionCookie(result.session!));
    return new Response(page(scriptNonce), { status: 200, headers });
  }

  return new Response("Not found", {
    status: 404,
    headers: securityHeaders(nonce(), "text/plain; charset=utf-8"),
  });
}

async function safeFetch(request: Request): Promise<Response> {
  try {
    return await handle(request);
  } catch {
    /* Requirement 3: no diagnostics, stack trace, or data are exposed. */
    return new Response("The secure portal is temporarily unavailable.", {
      status: 500,
      headers: securityHeaders(nonce(), "text/plain; charset=utf-8"),
    });
  }
}

/*
  Requirement 3: TLS is mandatory. The application does not start without the
  supplied localhost certificate and key.
*/
const port = Number(Bun.env.PORT || 3000);
const httpPort = Number(Bun.env.HTTP_PORT || 8080);
const certFile = Bun.file("certs/cert.pem");
const keyFile = Bun.file("certs/key.pem");

let certificate: string;
let privateKey: string;

try {
  if (!(await certFile.exists()) || !(await keyFile.exists())) throw new Error("missing TLS material");
  certificate = await certFile.text();
  privateKey = await keyFile.text();
  if (!certificate || !privateKey) throw new Error("empty TLS material");
} catch {
  console.error("Configuration error.");
  process.exit(1);
}

Bun.serve({
  port,
  tls: { cert: certificate!, key: privateKey! },
  fetch: safeFetch,
});

/* HTTP only redirects to the fixed verified localhost TLS origin. */
Bun.serve({
  port: httpPort,
  fetch(request) {
    const url = new URL(request.url);
    return Response.redirect(`https://localhost:${port}${url.pathname}${url.search}`, 308);
  },
});
