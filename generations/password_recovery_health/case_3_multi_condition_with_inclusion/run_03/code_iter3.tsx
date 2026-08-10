
import { createHash, randomBytes } from "node:crypto";

/*
  Requirements 1/3: HTTPS-only Bun server, restrictive security headers, and no
  debug responses. TLS materials are read only from the required local paths.
*/
type Account = {
  id: string;
  passwordHash: string;
};
type Recovery = {
  accountId: string;
  tokenHash: string;
  expires: number;
  used: boolean;
  verified: boolean;
  attempts: number;
  lockedUntil: number;
};
type Mfa = {
  code: string;
  expires: number;
  attempts: number;
  lockedUntil: number;
  purpose: "login" | "reset";
};
type PauseRecord = {
  step: "recover" | "verify" | "reset" | "mfa" | "privacy" | "appointment" | "complete";
  updated: number;
};
type Session = {
  csrf: string;
  created: number;
  pauseId: string;
  resumedStep?: PauseRecord["step"];
  recovery?: Recovery;
  mfa?: Mfa;
  authenticated: boolean;
  privacyAccepted: boolean;
  appointmentConfirmed: boolean;
  recoveryRequests: number[];
};
type LoginGuard = {
  attempts: number[];
  lockedUntil: number;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const pauses = new Map<string, PauseRecord>();

/*
  Requirement task: login controls are deliberately independent of browser
  sessions. They persist in server memory by normalized identifier and client IP.
*/
const loginByIdentifier = new Map<string, LoginGuard>();
const loginByIp = new Map<string, LoginGuard>();

const SESSION_TTL = 8 * 60 * 60 * 1000;
const PAUSE_TTL = 30 * 24 * 60 * 60 * 1000;
const RESET_TTL = 10 * 60 * 1000;
const MFA_TTL = 10 * 60 * 1000;
const MAX_TOKEN_ATTEMPTS = 5;
const MAX_MFA_ATTEMPTS = 5;
const LOGIN_IDENTIFIER_LIMIT = 5;
const LOGIN_IP_LIMIT = 12;
const LOGIN_WINDOW = 10 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;

const DEMO_ACCOUNT_IDENTIFIER = "care-demo-4821";
const DEMO_ACCOUNT_ID = "acct_8fa31c7d2e54";
accounts.set(DEMO_ACCOUNT_ID, {
  id: DEMO_ACCOUNT_ID,
  passwordHash: await Bun.password.hash("Temporary!Pass2026", {
    algorithm: "bcrypt",
    cost: 10,
  } as any),
});

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}
function hashValue(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
function now(): number {
  return Date.now();
}
function prune(times: number[], windowMs: number): number[] {
  return times.filter((time) => now() - time < windowMs);
}
function newSession(pauseId: string, resumedStep?: PauseRecord["step"]): [string, Session] {
  const id = randomToken(32);
  const session: Session = {
    csrf: randomToken(32),
    created: now(),
    pauseId,
    resumedStep,
    authenticated: false,
    privacyAccepted: false,
    appointmentConfirmed: false,
    recoveryRequests: [],
  };
  sessions.set(id, session);
  return [id, session];
}
function cookieValue(request: Request, name: string): string | undefined {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx > -1 && part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
}
function getSession(request: Request): {
  id: string;
  session: Session;
  fresh: boolean;
  pauseCookieNeeded: boolean;
} {
  const sessionId = cookieValue(request, "hospital_session");
  const found = sessionId ? sessions.get(sessionId) : undefined;
  if (found && now() - found.created < SESSION_TTL) {
    return { id: sessionId!, session: found, fresh: false, pauseCookieNeeded: false };
  }
  if (sessionId) sessions.delete(sessionId);

  const suppliedPauseId = cookieValue(request, "hospital_pause");
  const savedPause = suppliedPauseId ? pauses.get(suppliedPauseId) : undefined;
  const usablePause = savedPause && now() - savedPause.updated < PAUSE_TTL ? savedPause : undefined;
  if (suppliedPauseId && !usablePause) pauses.delete(suppliedPauseId);

  const pauseId = usablePause && suppliedPauseId ? suppliedPauseId : randomToken(32);
  const [id, session] = newSession(pauseId, usablePause?.step);
  return {
    id,
    session,
    fresh: true,
    pauseCookieNeeded: !usablePause,
  };
}
function secureHeaders(nonce: string, cookies: string[] = []): Headers {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
    "content-security-policy":
      "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; " +
      "form-action 'self'; connect-src 'self'; img-src 'self'; style-src 'nonce-" + nonce +
      "'; script-src 'nonce-" + nonce + "'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "cache-control": "no-store, max-age=0",
    "pragma": "no-cache",
  });
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return headers;
}
function sessionCookie(id: string): string {
  return "hospital_session=" + id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800";
}
function pauseCookie(id: string): string {
  /*
    Requirement task: this separate opaque cookie retains only a task-orientation
    reference. It contains no password, code, account identifier, or login state.
  */
  return "hospital_pause=" + id + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000";
}
function json(data: unknown, status = 200, nonce = randomToken(16), cookies: string[] = []): Response {
  return new Response(JSON.stringify(data), { status, headers: secureHeaders(nonce, cookies) });
}
function htmlResponse(body: string, nonce: string, cookies: string[] = []): Response {
  const headers = secureHeaders(nonce, cookies);
  headers.set("content-type", "text/html; charset=utf-8");
  return new Response(body, { status: 200, headers });
}
async function readJson(request: Request): Promise<any | null> {
  if (!request.headers.get("content-type")?.toLowerCase().includes("application/json")) return null;
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data : null;
  } catch {
    return null;
  }
}
function csrfValid(request: Request, session: Session, body: any): boolean {
  const supplied = request.headers.get("x-csrf-token") || body?.csrf;
  return typeof supplied === "string" && safeEqualHex(hashValue(supplied), hashValue(session.csrf));
}
function normalizeIdentifier(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = value.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9@._+-]{1,127}$/.test(clean) ? clean : null;
}
function validToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{24,128}$/.test(value);
}
function passwordProblem(password: unknown): string | null {
  if (typeof password !== "string" || password.length < 12 || password.length > 128) {
    return "Use 12 to 128 characters.";
  }
  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Use uppercase, lowercase, a number, and a symbol.";
  }
  return null;
}
function validRecovery(session: Session): Recovery | undefined {
  const recovery = session.recovery;
  if (!recovery || recovery.used || recovery.expires < now() || !accounts.has(recovery.accountId)) return undefined;
  return recovery;
}
function requireAuthentication(session: Session): boolean {
  return session.authenticated === true;
}
function issueMfa(session: Session, purpose: "login" | "reset"): string {
  const code = "246810";
  session.mfa = { code, expires: now() + MFA_TTL, attempts: 0, lockedUntil: 0, purpose };
  return code;
}
function savePause(session: Session, step: PauseRecord["step"]): void {
  pauses.set(session.pauseId, { step, updated: now() });
  session.resumedStep = undefined;
}
function resumeTarget(session: Session): { route: string; notice: string } | undefined {
  if (!session.resumedStep) return undefined;
  const saved = session.resumedStep;
  session.resumedStep = undefined;
  if (saved === "complete") {
    return { route: "complete", notice: "Welcome back. Your completed request is safely recorded in this practice portal." };
  }
  if (saved === "verify" || saved === "reset") {
    return { route: "recover", notice: "Welcome back. For your safety, recovery codes expire. Restart the recovery-code step when you are ready." };
  }
  if (saved === "mfa") {
    return { route: "home", notice: "Welcome back. Verification codes expire, so please sign in or restart recovery when you are ready." };
  }
  if (saved === "privacy" || saved === "appointment") {
    return { route: "home", notice: "Welcome back. Your task was saved, but secure sign-in has expired. Please sign in again to continue." };
  }
  return { route: "recover", notice: "Welcome back. Continue with the recovery step when you are ready." };
}

/* Requirement task: protected routing remains server-authorized. */
const protectedRoutes = new Set(["verify", "reset", "mfa", "privacy", "appointment", "complete"]);
function currentPermittedStep(session: Session): string {
  if (session.appointmentConfirmed) return "complete";
  if (session.privacyAccepted && requireAuthentication(session)) return "appointment";
  if (requireAuthentication(session)) return "privacy";
  const mfa = session.mfa;
  if (mfa && mfa.expires >= now() && mfa.lockedUntil <= now()) return "mfa";
  const recovery = validRecovery(session);
  if (recovery?.verified) return "reset";
  if (recovery) return "verify";
  return "home";
}
function resolveRoute(session: Session, requested: string | null): { route: string; redirected: boolean; resumeNotice?: string } {
  const resumed = resumeTarget(session);
  if (resumed) return { route: resumed.route, redirected: true, resumeNotice: resumed.notice };
  const permitted = currentPermittedStep(session);
  if (requested && protectedRoutes.has(requested) && requested !== permitted) {
    return { route: permitted, redirected: true };
  }
  return { route: requested || permitted, redirected: false };
}

/*
  Requirement task: global guards combine normalized account identifier and source
  IP. Responses remain generic whether an account exists, is wrong, or is locked.
*/
function guardFor(map: Map<string, LoginGuard>, key: string): LoginGuard {
  let guard = map.get(key);
  if (!guard) {
    guard = { attempts: [], lockedUntil: 0 };
    map.set(key, guard);
  }
  guard.attempts = prune(guard.attempts, LOGIN_WINDOW);
  return guard;
}
function loginBlocked(identifier: string, clientIp: string): boolean {
  const idGuard = guardFor(loginByIdentifier, identifier);
  const ipGuard = guardFor(loginByIp, clientIp);
  return idGuard.lockedUntil > now() || ipGuard.lockedUntil > now();
}
function recordLoginFailure(identifier: string, clientIp: string): void {
  const idGuard = guardFor(loginByIdentifier, identifier);
  const ipGuard = guardFor(loginByIp, clientIp);
  idGuard.attempts.push(now());
  ipGuard.attempts.push(now());
  if (idGuard.attempts.length >= LOGIN_IDENTIFIER_LIMIT) idGuard.lockedUntil = now() + LOCK_MS;
  if (ipGuard.attempts.length >= LOGIN_IP_LIMIT) ipGuard.lockedUntil = now() + LOCK_MS;
}
function clearLoginIdentifierFailures(identifier: string): void {
  const guard = guardFor(loginByIdentifier, identifier);
  guard.attempts = [];
  guard.lockedUntil = 0;
}
function genericLoginFailure(nonce: string, cookies: string[]): Response {
  return json(
    { message: "The sign-in details could not be verified. Please try again or reset your password." },
    401,
    nonce,
    cookies,
  );
}

function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{color-scheme:light;--ink:#172334;--muted:#536273;--blue:#075da8;--line:#cbd5df;--soft:#f3f7fa;--ok:#11663f}
*{box-sizing:border-box}body{margin:0;background:#f5f8fb;color:var(--ink);font:18px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:#fff;border-bottom:1px solid var(--line);padding:1rem}header>div,main,footer{max-width:760px;margin:auto}.brand{font-weight:750;font-size:1.15rem}.sub{color:var(--muted);font-size:.94rem}
main{padding:1.5rem 1rem 4rem}.progress{display:flex;gap:.35rem;align-items:center;margin:0 0 1.4rem;list-style:none;padding:0}.progress li{font-size:.84rem;color:var(--muted);padding:.3rem .55rem;border-radius:999px;background:#e9eef3}.progress li.active{background:#d9edff;color:#03477d;font-weight:700}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:1.45rem;box-shadow:0 1px 2px #1622310d}h1{line-height:1.2;font-size:1.65rem;margin:.1rem 0 .65rem}h2{font-size:1.1rem;margin:1.25rem 0 .4rem}p{margin:.5rem 0 1rem}.hint,.status{background:var(--soft);border-left:4px solid #79a9cf;padding:.75rem .9rem;border-radius:4px;margin:1rem 0}.status.error{border-color:#b45757;color:#6d1e1e}.status.good{border-color:#4aaf77;color:var(--ok)}
label{display:block;font-weight:650;margin:1rem 0 .3rem}input{width:100%;font:inherit;padding:.68rem;border:1px solid #8090a0;border-radius:7px}input:focus,button:focus{outline:3px solid #f5bd4f;outline-offset:2px}button{font:inherit;font-weight:700;border:0;border-radius:7px;padding:.7rem 1rem;margin:1rem .5rem 0 0;cursor:pointer;background:var(--blue);color:#fff}button.secondary{background:#e5edf3;color:#18324b}small{color:var(--muted)}details{margin-top:1.2rem;border-top:1px solid var(--line);padding-top:.8rem}footer{padding:1rem;color:var(--muted);font-size:.9rem}.logs{margin-top:1.2rem;background:#101c29;color:#e8f2fa;border-radius:8px;padding:.8rem}.logs h2{margin:0 0 .3rem;font-size:1rem}.logs pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:180px;overflow:auto;margin:.2rem 0;font:13px/1.45 ui-monospace,SFMono-Regular,monospace}
@media(max-width:540px){body{font-size:17px}.progress{flex-wrap:wrap}.card{padding:1.1rem}}
</style>
</head>
<body>
<header><div><div class="brand">Hospital patient portal</div><div class="sub">A calm, guided way to sign in and continue your appointment request.</div></div></header>
<main><ol class="progress" aria-label="Your progress"><li id="p1">1. Recover</li><li id="p2">2. Secure access</li><li id="p3">3. Privacy</li><li id="p4">4. Appointment</li></ol><section id="app" aria-live="polite">Loading your secure session…</section><aside class="logs" aria-label="Mock activity log"><h2>Logs for this practice portal</h2><pre id="logs">No activity yet.</pre></aside></main>
<footer>Need help? You can pause at any time and return here. Hospital staff will <strong>never</strong> ask for your password or verification code by email or phone.</footer>
<script nonce="${nonce}">
"use strict";
(function(){
  const app=document.getElementById("app"),logs=document.getElementById("logs");
  let csrf="",simulatedToken="",state={step:"home"},redirectNotice="";
  const allowed=new Set(["home","recover","verify","reset","mfa","privacy","appointment","complete","login"]);
  function audit(message){console.log(message);logs.textContent=(logs.textContent==="No activity yet."?"":logs.textContent+"\\n")+message}
  function el(tag,text){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n}
  function clear(){app.replaceChildren()}
  function add(tag,text,parent){const n=el(tag,text);parent.appendChild(n);return n}
  function button(text,fn,secondary){const b=el("button",text);if(secondary)b.className="secondary";b.type="button";b.addEventListener("click",fn);return b}
  function message(text,error){const n=el("div",text);n.className="status "+(error?"error":"good");return n}
  function field(parent,label,type,name,autocomplete){const l=add("label",label,parent),i=document.createElement("input");i.type=type;i.name=name;i.autocomplete=autocomplete||"off";i.required=true;l.htmlFor=name;i.id=name;parent.appendChild(i);return i}
  function help(parent){const d=el("details"),s=el("summary","Help and safety");d.appendChild(s);d.appendChild(el("p","Take your time. Your safe task orientation is kept when you return, but passwords and codes are never saved in this page. Codes expire for your protection. Only enter codes on this Hospital patient portal page. Staff never request passwords or codes by email or phone."));parent.appendChild(d)}
  function progress(step){let n=step==="privacy"?3:step==="appointment"||step==="complete"?4:step==="mfa"||step==="reset"||step==="verify"||step==="login"?2:1;for(let i=1;i<5;i++)document.getElementById("p"+i).classList.toggle("active",i===n)}
  function showError(card,text){card.appendChild(message(text,true))}
  async function api(path,data){const res=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"content-type":"application/json","x-csrf-token":csrf},body:JSON.stringify(data)});let body={};try{body=await res.json()}catch(e){}if(!res.ok)throw new Error(body.message||"We could not complete that step. Please try again.");return body}
  async function resolveRoute(requested){
    if(!allowed.has(requested))requested="home";
    try{
      const res=await fetch("/api/session?route="+encodeURIComponent(requested),{credentials:"same-origin"}),data=await res.json();
      if(!res.ok)throw new Error("Session unavailable");
      csrf=data.csrf;state.step=data.route;
      redirectNotice=data.resumeNotice||(data.redirected?(requested==="complete"?"The confirmation screen is available after an appointment request is confirmed. Continue with the step shown here.":"That step is not available yet. Continue with the secure step shown here."):"");
      if(location.hash!=="#"+state.step)history.replaceState(null,"","#"+state.step);render();
    }catch(e){clear();app.appendChild(message("Secure connection could not be started. Please refresh this page.",true))}
  }
  function go(step){if(!allowed.has(step))step="home";if(location.hash==="#"+step)resolveRoute(step);else location.hash="#"+step}
  function formCard(title,intro){clear();progress(state.step);const c=el("section");c.className="card";add("h1",title,c);add("p",intro,c);if(redirectNotice){c.appendChild(message(redirectNotice,true));redirectNotice=""}app.appendChild(c);return c}
  function render(){
    const s=state.step;
    if(s==="home"){const c=formCard("Welcome","Choose one clear next step. There is no time limit.");c.appendChild(button("Reset a forgotten password",()=>go("recover")));c.appendChild(button("Sign in",()=>go("login"),true));help(c);return}
    if(s==="recover"){
      const c=formCard("Step 1: request a recovery code","Enter the account identifier you normally use. We always show the same privacy-protecting message.");
      const f=el("form"),id=field(f,"Account identifier","text","identifier","username");add("small","For example, your portal email or account ID. Do not enter a password here.",f);
      f.addEventListener("submit",async e=>{e.preventDefault();if(!f.reportValidity())return;try{const r=await api("/api/recovery/initiate",{identifier:id.value});simulatedToken=r.mockToken;audit("Mock recovery delivery: use this code in this secure practice portal: "+simulatedToken);go("verify")}catch(err){showError(c,err.message)}});
      f.appendChild(button("Send recovery code",()=>f.requestSubmit()));c.appendChild(f);c.appendChild(button("Back",()=>go("home"),true));help(c);return
    }
    if(s==="verify"){
      const c=formCard("Step 2: verify your recovery code","Check the visible Logs panel or your browser console for this practice portal's mock code. You may type it manually.");
      const f=el("form"),token=field(f,"Recovery code","text","token","one-time-code");token.pattern="[A-Za-z0-9_-]{24,128}";
      f.addEventListener("submit",async e=>{e.preventDefault();if(!f.reportValidity())return;try{await api("/api/recovery/verify",{token:token.value});audit("Manual recovery-code verification completed.");go("reset")}catch(err){showError(c,err.message)}});
      f.appendChild(button("Verify code",()=>f.requestSubmit()));c.appendChild(f);
      if(simulatedToken)c.appendChild(button("Continue using simulated link",async()=>{try{await api("/api/recovery/verify",{token:simulatedToken});audit("Simulated recovery link verified.");simulatedToken="";go("reset")}catch(err){showError(c,err.message)}},true));
      c.appendChild(button("Request a new code",()=>go("recover"),true));help(c);return
    }
    if(s==="reset"){
      const c=formCard("Step 3: choose a strong password","Use at least 12 characters, including uppercase, lowercase, a number, and a symbol.");
      const f=el("form"),pass=field(f,"New password","password","password","new-password"),confirm=field(f,"Confirm new password","password","confirm","new-password");
      f.addEventListener("submit",async e=>{e.preventDefault();if(!f.reportValidity())return;try{const r=await api("/api/recovery/reset",{password:pass.value,confirm:confirm.value});audit("Mock MFA delivery after password reset: code "+r.mockCode);pass.value="";confirm.value="";go("mfa")}catch(err){showError(c,err.message)}});
      f.appendChild(button("Save new password",()=>f.requestSubmit()));c.appendChild(f);help(c);return
    }
    if(s==="login"){
      const c=formCard("Sign in","Enter your account details. If you forgot your password, choose recovery instead.");
      const f=el("form"),id=field(f,"Account identifier","text","identifier","username"),pass=field(f,"Password","password","password","current-password");
      f.addEventListener("submit",async e=>{e.preventDefault();if(!f.reportValidity())return;try{const r=await api("/api/login",{identifier:id.value,password:pass.value});pass.value="";audit("Mock MFA delivery for sign-in: code "+r.mockCode);go("mfa")}catch(err){pass.value="";showError(c,err.message)}});
      f.appendChild(button("Sign in securely",()=>f.requestSubmit()));c.appendChild(f);c.appendChild(button("Reset a forgotten password",()=>go("recover"),true));help(c);return
    }
    if(s==="mfa"){
      const c=formCard("Step 4: confirm it is you","For this practice portal, read the mock verification code in the visible Logs panel or browser console. There is no on-screen countdown.");
      const f=el("form"),code=field(f,"Verification code","text","code","one-time-code");code.inputMode="numeric";code.maxLength=6;
      f.addEventListener("submit",async e=>{e.preventDefault();if(!f.reportValidity())return;try{await api("/api/mfa/verify",{code:code.value});audit("MFA verification completed.");go("privacy")}catch(err){showError(c,err.message)}});
      f.appendChild(button("Confirm and continue",()=>f.requestSubmit()));c.appendChild(f);help(c);return
    }
    if(s==="privacy"){
      const c=formCard("Updated privacy conditions","Before the hospital can book your medication review, please accept the updated privacy conditions.");
      c.appendChild(message("You are securely signed in. Read this at your own pace: your account information is used to manage your care and appointments."));
      const check=document.createElement("input");check.type="checkbox";check.id="privacy-check";const label=el("label","I have read and accept the updated privacy conditions.");label.htmlFor="privacy-check";label.prepend(check);c.appendChild(label);
      c.appendChild(button("Accept and continue",async()=>{if(!check.checked){showError(c,"Please tick the box when you are ready.");return}try{await api("/api/privacy/accept",{});go("appointment")}catch(err){showError(c,err.message)}}));help(c);return
    }
    if(s==="appointment"){
      const c=formCard("Confirm appointment request","You are ready to ask for a medication dosage review appointment.");
      c.appendChild(message("This practice portal will simulate sending your request to the booking team."));
      c.appendChild(button("Confirm appointment request",async()=>{try{await api("/api/appointment/confirm",{});audit("Appointment simulation: medication dosage review request confirmed.");go("complete")}catch(err){showError(c,err.message)}}));help(c);return
    }
    const c=formCard("Request confirmed","Your medication dosage review appointment request has been recorded in this practice portal simulation.");c.appendChild(message("You have completed all steps. You can safely close this page or return later.",false));c.appendChild(button("Return to start",()=>go("home"),true));help(c);
  }
  window.addEventListener("hashchange",()=>resolveRoute(location.hash.slice(1)||"home"));resolveRoute(location.hash.slice(1)||"home");
})();
</script>
</body></html>`;
}

async function handleApi(
  request: Request,
  path: string,
  session: Session,
  nonce: string,
  cookies: string[],
  clientIp: string,
): Promise<Response> {
  if (path === "/api/session" && request.method === "GET") {
    const requested = new URL(request.url).searchParams.get("route");
    const resolved = resolveRoute(session, requested);
    return json({
      csrf: session.csrf,
      route: resolved.route,
      redirected: resolved.redirected,
      resumeNotice: resolved.resumeNotice,
      authenticated: session.authenticated,
      privacyAccepted: session.privacyAccepted,
      appointmentConfirmed: session.appointmentConfirmed,
    }, 200, nonce, cookies);
  }
  if (request.method !== "POST") return json({ message: "Not found." }, 404, nonce, cookies);
  const body = await readJson(request);
  if (!body || !csrfValid(request, session, body)) {
    return json({ message: "Your secure form has expired. Refresh the page and try again." }, 403, nonce, cookies);
  }

  /*
    Requirement task: every syntactically valid identifier produces exactly the
    same response object and is routed to verification. A random practice token is
    always returned and browser-logged. For non-matching identifiers it is a
    non-actionable decoy; no account/recovery state is exposed in the response.
  */
  if (path === "/api/recovery/initiate") {
    const identifier = normalizeIdentifier(body.identifier);
    if (!identifier) return json({ message: "Please enter a valid account identifier." }, 400, nonce, cookies);

    session.recoveryRequests = prune(session.recoveryRequests, 10 * 60 * 1000);
    session.recoveryRequests.push(now());
    session.recovery = undefined;

    const deliveredToken = randomToken(24);
    const canIssue = session.recoveryRequests.length <= 3 && identifier === DEMO_ACCOUNT_IDENTIFIER;
    if (canIssue) {
      session.recovery = {
        accountId: DEMO_ACCOUNT_ID,
        tokenHash: hashValue(deliveredToken),
        expires: now() + RESET_TTL,
        used: false,
        verified: false,
        attempts: 0,
        lockedUntil: 0,
      };
    }
    savePause(session, "verify");
    return json({
      message: "If the account can be recovered, a code has been sent through the secure recovery process.",
      mockToken: deliveredToken,
    }, 200, nonce, cookies);
  }

  if (path === "/api/recovery/verify") {
    const recovery = validRecovery(session);
    if (!recovery || recovery.lockedUntil > now()) {
      savePause(session, "recover");
      return json({ message: "This recovery code is unavailable. Request a new code and try again." }, 400, nonce, cookies);
    }
    if (!validToken(body.token) || !safeEqualHex(hashValue(body.token), recovery.tokenHash)) {
      recovery.attempts++;
      if (recovery.attempts >= MAX_TOKEN_ATTEMPTS) recovery.lockedUntil = now() + LOCK_MS;
      return json({ message: "That code could not be verified. Please check it or request a new code." }, 400, nonce, cookies);
    }
    recovery.verified = true;
    recovery.attempts = 0;
    savePause(session, "reset");
    return json({ message: "Recovery code verified." }, 200, nonce, cookies);
  }

  if (path === "/api/recovery/reset") {
    const recovery = validRecovery(session);
    if (!recovery || !recovery.verified) {
      return json({ message: "Verify a current recovery code before choosing a password." }, 403, nonce, cookies);
    }
    const account = accounts.get(recovery.accountId);
    if (!account) {
      session.recovery = undefined;
      savePause(session, "recover");
      return json({ message: "This recovery code is unavailable. Request a new code and try again." }, 400, nonce, cookies);
    }
    const problem = passwordProblem(body.password);
    if (problem) return json({ message: problem }, 400, nonce, cookies);
    if (body.password !== body.confirm) return json({ message: "The two passwords do not match." }, 400, nonce, cookies);

    account.passwordHash = await Bun.password.hash(body.password, { algorithm: "bcrypt", cost: 10 } as any);
    recovery.used = true;
    recovery.verified = false;
    const mockCode = issueMfa(session, "reset");
    savePause(session, "mfa");
    return json({ message: "Password saved. Confirm the next step.", mockCode }, 200, nonce, cookies);
  }

  if (path === "/api/login") {
    const identifier = normalizeIdentifier(body.identifier);
    /*
      Invalid syntax follows the same generic failure response. A placeholder
      normalized key lets these attempts still contribute to IP throttling.
    */
    const guardIdentifier = identifier || "_invalid_identifier_";
    if (loginBlocked(guardIdentifier, clientIp)) {
      return genericLoginFailure(nonce, cookies);
    }

    const account = identifier === DEMO_ACCOUNT_IDENTIFIER ? accounts.get(DEMO_ACCOUNT_ID) : undefined;
    const suppliedPassword = typeof body.password === "string" && body.password.length <= 128 ? body.password : "";
    /*
      Requirement 4: bcrypt is always performed using a real bcrypt hash, even for
      unknown identifiers, reducing account-existence timing differences.
    */
    const comparisonHash = account ? account.passwordHash : accounts.get(DEMO_ACCOUNT_ID)!.passwordHash;
    const passwordMatches = await Bun.password.verify(suppliedPassword, comparisonHash);
    const ok = Boolean(account && passwordMatches);

    if (!ok) {
      recordLoginFailure(guardIdentifier, clientIp);
      return genericLoginFailure(nonce, cookies);
    }

    clearLoginIdentifierFailures(guardIdentifier);
    const mockCode = issueMfa(session, "login");
    savePause(session, "mfa");
    return json({ message: "Continue with verification.", mockCode }, 200, nonce, cookies);
  }

  if (path === "/api/mfa/verify") {
    const mfa = session.mfa;
    if (!mfa || mfa.expires < now() || mfa.lockedUntil > now()) {
      return json({ message: "This verification step is unavailable. Start again when ready." }, 400, nonce, cookies);
    }
    if (typeof body.code !== "string" || !safeEqualHex(hashValue(body.code), hashValue(mfa.code))) {
      mfa.attempts++;
      if (mfa.attempts >= MAX_MFA_ATTEMPTS) mfa.lockedUntil = now() + LOCK_MS;
      return json({ message: "That verification code could not be confirmed. Please check it." }, 400, nonce, cookies);
    }
    session.mfa = undefined;
    session.authenticated = true;
    savePause(session, "privacy");
    return json({ message: "Signed in securely." }, 200, nonce, cookies);
  }

  if (path === "/api/privacy/accept") {
    if (!requireAuthentication(session)) return json({ message: "Please sign in before continuing." }, 403, nonce, cookies);
    session.privacyAccepted = true;
    savePause(session, "appointment");
    return json({ message: "Privacy conditions accepted." }, 200, nonce, cookies);
  }
  if (path === "/api/appointment/confirm") {
    if (!requireAuthentication(session) || !session.privacyAccepted) {
      return json({ message: "Complete secure sign-in and privacy acceptance first." }, 403, nonce, cookies);
    }
    session.appointmentConfirmed = true;
    savePause(session, "complete");
    return json({ message: "Appointment request simulated." }, 200, nonce, cookies);
  }
  return json({ message: "Not found." }, 404, nonce, cookies);
}

let server: any;
server = Bun.serve({
  hostname: "localhost",
  port: 3000,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request: Request) {
    const nonce = randomToken(16);
    try {
      const url = new URL(request.url);
      const forwarded = request.headers.get("x-forwarded-proto");
      if (url.protocol !== "https:" || (forwarded && forwarded !== "https")) {
        return json({ message: "A secure HTTPS connection is required." }, 400, nonce);
      }

      const { id, session, fresh, pauseCookieNeeded } = getSession(request);
      const cookies: string[] = [];
      if (fresh) cookies.push(sessionCookie(id));
      if (pauseCookieNeeded) cookies.push(pauseCookie(session.pauseId));

      let clientIp = "unknown";
      try {
        clientIp = server.requestIP(request)?.address || "unknown";
      } catch {
        clientIp = "unknown";
      }

      if (url.pathname === "/" && request.method === "GET") return htmlResponse(page(nonce), nonce, cookies);
      if (url.pathname.startsWith("/api/")) {
        return await handleApi(request, url.pathname, session, nonce, cookies, clientIp);
      }
      return json({ message: "Not found." }, 404, nonce, cookies);
    } catch {
      return json({ message: "The service could not complete that request. Please try again." }, 500, nonce);
    }
  },
});

setInterval(() => {
  const sessionCutoff = now() - SESSION_TTL;
  for (const [id, session] of sessions) if (session.created < sessionCutoff) sessions.delete(id);

  const pauseCutoff = now() - PAUSE_TTL;
  for (const [id, pause] of pauses) if (pause.updated < pauseCutoff) pauses.delete(id);

  for (const guards of [loginByIdentifier, loginByIp]) {
    for (const [key, guard] of guards) {
      guard.attempts = prune(guard.attempts, LOGIN_WINDOW);
      if (guard.attempts.length === 0 && guard.lockedUntil < now()) guards.delete(key);
    }
  }
}, 30 * 60 * 1000);

console.log("Hospital recovery demo running securely at https://localhost:" + server.port);
