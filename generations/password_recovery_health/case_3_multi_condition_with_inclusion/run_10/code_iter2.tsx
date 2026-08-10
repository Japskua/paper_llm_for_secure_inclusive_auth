
import { readFileSync } from "node:fs";

/*
  Password Recovery System
  Single-file Bun HTTPS server and vanilla HTML client.
  Requirement mappings are noted in concise comments throughout.
*/

type Stage =
  | "start"
  | "requested"
  | "verified"
  | "mfa"
  | "passwordChanged"
  | "authenticated"
  | "privacyAccepted";

type Attempt = { count: number; blockedUntil: number };

type Account = {
  id: string;
  identifier: string;
  passwordHash: string;
};

type Session = {
  id: string;
  csrf: string;
  stage: Stage;
  accountId?: string;
  resetToken?: string;
  resetExpires?: number;
  resetUsed?: boolean;
  manualCode?: string;
  mfaCode?: string;
  authenticated: boolean;
  privacyAccepted: boolean;
  attempts: Map<string, Attempt>;
};

const sessions = new Map<string, Session>();

/*
  OWASP Authentication: password hashes are scoped to internal account records.
  Account identifiers are never returned by the portal or API.
*/
const initialPasswordHash = await Bun.password.hash("HospitalDemo!2026", { algorithm: "bcrypt" });
const accounts = new Map<string, Account>([
  [
    "account-helen",
    {
      id: "account-helen",
      identifier: "helena@example.com",
      passwordHash: initialPasswordHash,
    },
  ],
  /*
    A non-loginable internal sink preserves generic recovery responses for
    unrecognised identifiers without changing a real account.
  */
  [
    "recovery-sink",
    {
      id: "recovery-sink",
      identifier: "",
      passwordHash: initialPasswordHash,
    },
  ],
]);

const RECOVERY_SINK_ACCOUNT_ID = "recovery-sink";
const RESET_LIFETIME_MS = 10 * 60 * 1000;
const TEST_RECOVERY_CODE = "RECOVERY-DEMO-482913";
const TEST_MFA_CODE = "246810";

function randomValue(bytes = 32): string {
  const value = new Uint8Array(bytes);
  crypto.getRandomValues(value);
  return Buffer.from(value).toString("base64url");
}

function createSession(): Session {
  return {
    id: randomValue(32),
    csrf: randomValue(32),
    stage: "start",
    authenticated: false,
    privacyAccepted: false,
    attempts: new Map(),
  };
}

function cookieSessionId(request: Request): string | undefined {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\s*)recovery_session=([A-Za-z0-9_-]{20,})/);
  return match?.[1];
}

function getSession(request: Request): { session: Session; isNew: boolean } {
  const id = cookieSessionId(request);
  if (id && sessions.has(id)) return { session: sessions.get(id)!, isNew: false };
  const session = createSession();
  sessions.set(session.id, session);
  return { session, isNew: true };
}

function securityHeaders(nonce: string): Headers {
  return new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":
      `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; ` +
      "img-src 'self' data:; connect-src 'self'; font-src 'none'; object-src 'none'; " +
      "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cache-Control": "no-store, max-age=0, private",
    Pragma: "no-cache",
  });
}

function attachSessionCookie(headers: Headers, session: Session, isNew: boolean): void {
  if (isNew) {
    headers.append(
      "Set-Cookie",
      `recovery_session=${session.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`,
    );
  }
}

function json(
  body: Record<string, unknown>,
  session: Session,
  isNew: boolean,
  status = 200,
): Response {
  const headers = securityHeaders(randomValue(16));
  headers.set("Content-Type", "application/json; charset=utf-8");
  attachSessionCookie(headers, session, isNew);
  return new Response(JSON.stringify(body), { status, headers });
}

function textResponse(text: string, status = 400): Response {
  const headers = securityHeaders(randomValue(16));
  headers.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(text, { status, headers });
}

/* OWASP: per-session throttling, without account-specific error disclosure. */
function allowed(session: Session, action: string): boolean {
  const now = Date.now();
  const attempt = session.attempts.get(action);
  return !attempt || attempt.blockedUntil <= now;
}

function recordFailure(session: Session, action: string): void {
  const now = Date.now();
  const current = session.attempts.get(action) || { count: 0, blockedUntil: 0 };
  current.count += 1;
  if (current.count >= 5) {
    current.blockedUntil = now + 60_000;
    current.count = 0;
  }
  session.attempts.set(action, current);
}

function clearAttempts(session: Session, action: string): void {
  session.attempts.delete(action);
}

function stageData(session: Session): Record<string, unknown> {
  return {
    stage: session.stage,
    csrf: session.csrf,
    authenticated: session.authenticated,
    privacyAccepted: session.privacyAccepted,
  };
}

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9@._+\- ]{3,120}$/.test(value);
}

function validCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9-]{4,100}$/.test(value);
}

function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 12 && value.length <= 128;
}

function strongPassword(password: string): boolean {
  return (
    password.length >= 12 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

/* Internal lookup only: account records and identifiers never leave the server. */
function findAccountByIdentifier(identifier: string): Account | undefined {
  const normalized = identifier.trim().toLowerCase();
  for (const account of accounts.values()) {
    if (account.identifier && timingSafeEqual(normalized, account.identifier)) return account;
  }
  return undefined;
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function csrfValid(request: Request, session: Session, body: Record<string, unknown> | null): boolean {
  const token = request.headers.get("x-csrf-token") || body?.csrf;
  return typeof token === "string" && token.length === session.csrf.length &&
    timingSafeEqual(token, session.csrf);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

/* Inclusivity: application shell has persistent steps, help, restart, and saved non-sensitive progress. */
function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Hospital account recovery</title>
<style nonce="${nonce}">
:root { color-scheme: light; --ink:#17324d; --muted:#526679; --line:#d5e0e8; --blue:#075c9d; --soft:#f3f8fb; --good:#176b47; --warn:#8a4b00; }
* { box-sizing:border-box; }
body { margin:0; background:#f5f8fa; color:var(--ink); font:18px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
header { background:#fff; border-bottom:1px solid var(--line); padding:1rem; }
.header-inner, main { max-width:760px; margin:auto; }
.brand { font-weight:750; font-size:1.15rem; }
.sub { color:var(--muted); font-size:.94rem; }
main { padding:1.5rem 1rem 3rem; }
.progress { display:flex; list-style:none; padding:0; margin:0 0 1.5rem; gap:.35rem; }
.progress li { flex:1; text-align:center; color:var(--muted); font-size:.74rem; border-top:5px solid var(--line); padding-top:.35rem; }
.progress li.active { color:var(--blue); border-color:var(--blue); font-weight:700; }
.card { background:#fff; border:1px solid var(--line); border-radius:12px; padding:1.35rem; box-shadow:0 2px 8px #1630470b; }
h1 { font-size:1.55rem; line-height:1.2; margin:.1rem 0 .75rem; }
h2 { font-size:1.1rem; margin:1.5rem 0 .4rem; }
p { margin:.55rem 0; }
.next { background:var(--soft); border-left:4px solid var(--blue); padding:.8rem; margin:1rem 0; }
label { display:block; font-weight:700; margin:1rem 0 .3rem; }
input { display:block; width:100%; padding:.7rem; border:2px solid #9aabba; border-radius:7px; font:inherit; }
input:focus { outline:3px solid #82c6ef; outline-offset:2px; border-color:var(--blue); }
button { font:inherit; font-weight:700; border:0; border-radius:7px; padding:.72rem 1rem; margin-top:1rem; cursor:pointer; background:var(--blue); color:white; }
button.secondary { background:white; color:var(--blue); border:1px solid var(--blue); margin-left:.5rem; }
.notice { padding:.75rem; border-radius:7px; margin:1rem 0; }
.notice.error { background:#fff1ee; color:#7b250e; border:1px solid #e6b6a8; }
.notice.success { background:#edfaf3; color:var(--good); border:1px solid #a8d9bf; }
.help, .logs { margin-top:1.2rem; background:#fff; border:1px solid var(--line); border-radius:10px; padding:1rem; }
summary { cursor:pointer; font-weight:700; }
.logs { font-size:.86rem; }
#logList { margin:.5rem 0 0; padding-left:1.2rem; color:var(--muted); overflow-wrap:anywhere; }
.actions { display:flex; flex-wrap:wrap; align-items:center; }
.small { font-size:.9rem; color:var(--muted); }
a { color:#075c9d; }
@media (max-width:520px) { body { font-size:17px; } .progress li { font-size:.64rem; } .card { padding:1rem; } }
</style>
</head>
<body>
<header><div class="header-inner"><div class="brand">Hospital account access</div><div class="sub">A calm, guided recovery process</div></div></header>
<main>
<nav aria-label="Recovery progress"><ol class="progress" id="progress">
<li data-step="1">1. Request</li><li data-step="2">2. Verify</li><li data-step="3">3. Confirm</li><li data-step="4">4. Sign in</li>
</ol></nav>
<section class="card" id="app" aria-live="polite"><p>Preparing your secure recovery page…</p></section>
<aside class="help" aria-label="Help">
<details><summary>Need help?</summary>
<p>You can pause at any time. Your non-sensitive step is saved only in this browser. For safety, hospital staff will never ask for your password or recovery code by email, phone, or message.</p>
<p>If you need account assistance, use your hospital's verified phone number from an official letter or website. Do not use links sent by unexpected messages.</p>
</details>
</aside>
<section class="logs" aria-label="Logs"><strong>Logs</strong><ul id="logList"><li>Secure recovery page ready.</li></ul></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let state = { stage:"start", csrf:"", authenticated:false, privacyAccepted:false };
let linkToken = "";
const app = document.getElementById("app");
const progress = document.getElementById("progress");
const savedKey = "hospital-recovery-progress-v1";

function say(message) {
  console.log(message);
  const item = document.createElement("li");
  item.textContent = message;
  document.getElementById("logList").appendChild(item);
}
function setMessage(target, message, kind) {
  const box = document.createElement("div");
  box.className = "notice " + kind;
  box.textContent = message;
  target.prepend(box);
}
async function api(path, data) {
  const response = await fetch(path, {
    method:"POST",
    credentials:"same-origin",
    headers:{"Content-Type":"application/json","X-CSRF-Token":state.csrf},
    body:JSON.stringify(data || {})
  });
  let result = {};
  try { result = await response.json(); } catch { result = { message:"Please try again." }; }
  if (!response.ok) throw new Error(typeof result.message === "string" ? result.message : "Please try again.");
  if (result.csrf) state.csrf = result.csrf;
  return result;
}
async function loadState() {
  const response = await fetch("/api/state", { credentials:"same-origin", cache:"no-store" });
  if (!response.ok) throw new Error("Unable to prepare this secure page.");
  state = await response.json();
  linkToken = new URLSearchParams(location.search).get("token") || "";
  try {
    const saved = JSON.parse(localStorage.getItem(savedKey) || "{}");
    if (saved.step && state.stage === "start") say("A saved recovery reminder is available. You may continue or restart.");
  } catch {}
  render();
}
function saveProgress() {
  const nonSensitive = { step:state.stage, savedAt:"saved" };
  localStorage.setItem(savedKey, JSON.stringify(nonSensitive));
}
function updateProgress() {
  let n = 1;
  if (["requested","verified"].includes(state.stage)) n = 2;
  if (["mfa","passwordChanged"].includes(state.stage)) n = 3;
  if (["authenticated","privacyAccepted"].includes(state.stage)) n = 4;
  progress.querySelectorAll("li").forEach((item, index) => item.classList.toggle("active", index < n));
}
function restartButton() {
  const button = document.createElement("button");
  button.type = "button"; button.className = "secondary"; button.textContent = "Restart recovery";
  button.addEventListener("click", async () => {
    try {
      await api("/api/restart", {});
      localStorage.removeItem(savedKey);
      linkToken = "";
      state.stage = "start"; state.authenticated = false; state.privacyAccepted = false;
      say("Recovery restarted. No password was saved.");
      render();
    } catch (e) { setMessage(app, e.message, "error"); }
  });
  return button;
}
function shell(title, intro, next) {
  app.replaceChildren();
  const h = document.createElement("h1"); h.textContent = title;
  const p = document.createElement("p"); p.textContent = intro;
  const guide = document.createElement("p"); guide.className = "next"; guide.textContent = "Next step: " + next;
  app.append(h,p,guide);
  updateProgress();
}
function formButton(text) {
  const b = document.createElement("button"); b.type="submit"; b.textContent=text; return b;
}
function input(form, labelText, type, name, hint) {
  const label=document.createElement("label"); label.htmlFor=name; label.textContent=labelText;
  const field=document.createElement("input"); field.id=name; field.name=name; field.type=type; field.required=true;
  field.autocomplete = type === "password" ? "new-password" : "username";
  form.append(label,field);
  if (hint) { const p=document.createElement("p"); p.className="small"; p.textContent=hint; form.append(p); }
  return field;
}
function renderStart() {
  shell("Reset your password", "We will guide you one small step at a time. This does not rush or time out while you are using the page.", "Enter the account identifier you use for hospital access.");
  const safe=document.createElement("p"); safe.className="small"; safe.textContent="For your safety, passwords and recovery codes must never be shared by email or with support staff.";
  const form=document.createElement("form");
  const id=input(form,"Account identifier","text","identifier","For example, the email address or identifier you normally use.");
  form.append(formButton("Request recovery code"));
  form.addEventListener("submit", async event => {
    event.preventDefault();
    try {
      const result=await api("/api/recovery-request",{identifier:id.value});
      state.stage=result.stage; saveProgress();
      say("Recovery delivery simulation: manual recovery code: " + result.resetToken);
      say("Recovery delivery simulation: verification URL: " + result.verificationUrl);
      render();
    } catch(e) { setMessage(form,e.message,"error"); }
  });
  app.append(safe,form);
}
function noteMfaDelivery(result) {
  if (typeof result.testMfaCode === "string") {
    say("MFA delivery simulation: confirmation code: " + result.testMfaCode);
  }
}
function renderVerify() {
  shell("Verify your recovery", "A recovery method has been prepared. You can enter the recovery code manually.", "Enter the recovery code, then select Verify.");
  const form=document.createElement("form");
  const code=input(form,"Recovery code","text","code","Use the recovery code delivered when you requested recovery.");
  if (linkToken) {
    const note=document.createElement("p"); note.className="notice success";
    note.textContent="A recovery link was detected. Select Verify recovery link to continue.";
    form.append(note);
    const linkButton=document.createElement("button"); linkButton.type="button"; linkButton.textContent="Verify recovery link";
    linkButton.addEventListener("click", async () => {
      try {
        const r=await api("/api/verify",{token:linkToken});
        state.stage=r.stage; saveProgress();
        say("Recovery link verified.");
        noteMfaDelivery(r);
        render();
      } catch(e) { setMessage(form,e.message,"error"); }
    });
    form.append(linkButton);
  }
  form.append(formButton("Verify code"),restartButton());
  form.addEventListener("submit", async event => {
    event.preventDefault();
    try {
      const r=await api("/api/verify",{code:code.value});
      state.stage=r.stage; saveProgress();
      say("Recovery code verified.");
      noteMfaDelivery(r);
      render();
    } catch(e) { setMessage(form,e.message,"error"); }
  });
  app.append(form);
}
function renderMfa() {
  shell("Confirm it is you", "This extra confirmation helps protect your account.", "Enter the six-digit confirmation code delivered after recovery verification.");
  const form=document.createElement("form");
  const code=input(form,"Confirmation code","text","mfa","Use the six-digit confirmation code that was just delivered for this evaluation.");
  form.append(formButton("Confirm code"),restartButton());
  form.addEventListener("submit", async event => {
    event.preventDefault();
    try { const r=await api("/api/mfa",{code:code.value}); state.stage=r.stage; saveProgress(); say("MFA confirmation completed."); render(); }
    catch(e) { setMessage(form,e.message,"error"); }
  });
  app.append(form);
}
function renderPassword() {
  shell("Choose a new password", "Choose a password that is private and difficult for others to guess. We will not display or save it in this browser.", "Enter the same strong password twice.");
  const policy=document.createElement("p"); policy.className="small"; policy.textContent="Password policy: at least 12 characters, including uppercase and lowercase letters, a number, and a symbol.";
  const form=document.createElement("form");
  const p1=input(form,"New password","password","newPassword","");
  const p2=input(form,"Repeat new password","password","repeatPassword","");
  form.append(formButton("Save new password"),restartButton());
  form.addEventListener("submit", async event => {
    event.preventDefault();
    try { const r=await api("/api/password-change",{password:p1.value,repeat:p2.value}); state.stage=r.stage; saveProgress(); say("Password changed securely. Password values were not logged."); render(); }
    catch(e) { setMessage(form,e.message,"error"); }
  });
  app.append(policy,form);
}
function renderLogin() {
  shell("Sign in with your new password", "Your password reset is complete. Sign in to review and accept the updated privacy conditions.", "Enter your normal account identifier and your new password.");
  const form=document.createElement("form");
  const id=input(form,"Account identifier","text","loginId","");
  const pass=input(form,"New password","password","loginPassword","");
  pass.autocomplete="current-password";
  form.append(formButton("Sign in"));
  form.addEventListener("submit", async event => {
    event.preventDefault();
    try { const r=await api("/api/login",{identifier:id.value,password:pass.value}); state.stage=r.stage; state.authenticated=true; localStorage.removeItem(savedKey); say("Secure sign-in completed."); render(); }
    catch(e) { setMessage(form,e.message,"error"); }
  });
  app.append(form);
}
function renderPrivacy() {
  shell("Review privacy conditions", "You are signed in. Please confirm that you have reviewed the updated privacy conditions so hospital staff can continue with appointment support.", "Select Confirm privacy conditions when you are ready.");
  const details=document.createElement("p"); details.textContent="Your information is handled through your hospital account. This demonstration does not display patient records or private details.";
  const button=document.createElement("button"); button.type="button"; button.textContent="Confirm privacy conditions";
  button.addEventListener("click", async () => {
    try { const r=await api("/api/privacy-confirm",{}); state.stage=r.stage; state.privacyAccepted=true; say("Privacy conditions confirmed."); render(); }
    catch(e) { setMessage(app,e.message,"error"); }
  });
  app.append(details,button);
}
function renderDone() {
  shell("Confirmation complete", "The updated privacy conditions have been confirmed. You can now return to your hospital's official appointment service when you are ready.", "You may safely close this page.");
  const p=document.createElement("p"); p.className="notice success"; p.textContent="Your recovery task is complete.";
  app.append(p);
}
function render() {
  if (state.stage === "start") renderStart();
  else if (state.stage === "requested") renderVerify();
  else if (state.stage === "verified") renderMfa();
  else if (state.stage === "mfa") renderPassword();
  else if (state.stage === "passwordChanged") renderLogin();
  else if (state.stage === "authenticated") renderPrivacy();
  else renderDone();
}
loadState().catch(() => {
  app.textContent="This secure page could not be prepared. Please refresh and try again.";
});
})();
</script>
</body></html>`;
}

/* Sensitive API boundary: every mutation requires the session's CSRF token. */
async function handleApi(request: Request, session: Session, isNew: boolean, pathname: string): Promise<Response> {
  if (pathname === "/api/state" && request.method === "GET") {
    return json(stageData(session), session, isNew);
  }
  if (request.method !== "POST") return json({ message: "Request not available." }, session, isNew, 405);

  const body = await requestBody(request);
  if (!body || !csrfValid(request, session, body)) {
    return json({ message: "This secure form needs to be refreshed before continuing." }, session, isNew, 403);
  }

  if (pathname === "/api/recovery-request") {
    if (!allowed(session, "recovery")) {
      return json({ message: "Too many requests. Please pause for one minute, then try again." }, session, isNew, 429);
    }
    if (!validIdentifier(body.identifier)) {
      recordFailure(session, "recovery");
      return json({ message: "Enter the account identifier using letters, numbers, and standard email characters." }, session, isNew, 400);
    }

    /*
      Broken Access Control: bind this recovery transaction to one internal
      account record. Unknown identifiers use a non-loginable sink, while the
      outward response remains identical and cannot enumerate accounts.
    */
    const account = findAccountByIdentifier(body.identifier);
    session.accountId = account?.id || RECOVERY_SINK_ACCOUNT_ID;
    recordFailure(session, "recovery");
    session.stage = "requested";
    session.resetToken = randomValue(32);
    session.resetExpires = Date.now() + RESET_LIFETIME_MS;
    session.resetUsed = false;
    session.manualCode = TEST_RECOVERY_CODE;
    session.mfaCode = undefined;
    session.authenticated = false;
    session.privacyAccepted = false;

    /* Evaluation-only mock delivery: same-origin URL and token are deliberately returned. */
    const verificationUrl =
      `https://localhost:3000/verify?token=${encodeURIComponent(session.resetToken)}`;
    return json({
      stage: session.stage,
      resetToken: session.resetToken,
      verificationUrl,
    }, session, isNew);
  }

  if (pathname === "/api/verify") {
    if (!allowed(session, "verify")) {
      return json({ message: "Too many attempts. Please pause for one minute, then try again." }, session, isNew, 429);
    }
    if (
      session.stage !== "requested" ||
      session.resetUsed ||
      !session.accountId ||
      !session.resetExpires ||
      Date.now() > session.resetExpires
    ) {
      recordFailure(session, "verify");
      return json({ message: "This recovery step is no longer available. Please restart recovery." }, session, isNew, 400);
    }
    const codeOK = validCode(body.code) && timingSafeEqual(body.code, session.manualCode || "");
    const tokenOK = validCode(body.token) && timingSafeEqual(body.token, session.resetToken || "");
    if (!codeOK && !tokenOK) {
      recordFailure(session, "verify");
      return json({ message: "That code could not be verified. Check it and try again, or restart recovery." }, session, isNew, 400);
    }

    /* Security Misconfiguration: token and manual code are single-use. */
    clearAttempts(session, "verify");
    session.resetUsed = true;
    session.resetToken = undefined;
    session.manualCode = undefined;
    session.stage = "verified";
    session.mfaCode = TEST_MFA_CODE;
    return json({ stage: session.stage, testMfaCode: TEST_MFA_CODE }, session, isNew);
  }

  if (pathname === "/api/mfa") {
    if (!allowed(session, "mfa")) {
      return json({ message: "Too many attempts. Please pause for one minute, then try again." }, session, isNew, 429);
    }
    if (session.stage !== "verified" || !validCode(body.code) || !timingSafeEqual(body.code, session.mfaCode || "")) {
      recordFailure(session, "mfa");
      return json({ message: "That confirmation code could not be verified. Please try again." }, session, isNew, 400);
    }
    clearAttempts(session, "mfa");
    session.stage = "mfa";
    return json({ stage: session.stage }, session, isNew);
  }

  if (pathname === "/api/password-change") {
    if (!allowed(session, "password")) {
      return json({ message: "Too many attempts. Please pause for one minute, then try again." }, session, isNew, 429);
    }
    const password = body.password;
    const repeat = body.repeat;
    const account = session.accountId ? accounts.get(session.accountId) : undefined;
    if (
      session.stage !== "mfa" ||
      !account ||
      !session.resetExpires ||
      Date.now() > session.resetExpires
    ) {
      recordFailure(session, "password");
      return json({ message: "This secure reset step is unavailable. Please restart recovery." }, session, isNew, 400);
    }
    if (!validPassword(password) || !validPassword(repeat) || password !== repeat) {
      recordFailure(session, "password");
      return json({ message: "Passwords must match and be between 12 and 128 characters." }, session, isNew, 400);
    }
    if (!strongPassword(password)) {
      recordFailure(session, "password");
      return json({ message: "Use at least 12 characters with uppercase, lowercase, a number, and a symbol." }, session, isNew, 400);
    }

    /* Account-scoped update: no global password hash is shared between accounts. */
    account.passwordHash = await Bun.password.hash(password, { algorithm: "bcrypt" });
    session.mfaCode = undefined;
    session.resetExpires = undefined;
    session.stage = "passwordChanged";
    clearAttempts(session, "password");
    return json({ stage: session.stage }, session, isNew);
  }

  if (pathname === "/api/login") {
    if (!allowed(session, "login")) {
      return json({ message: "Too many sign-in attempts. Please pause for one minute, then try again." }, session, isNew, 429);
    }

    const boundAccount = session.accountId ? accounts.get(session.accountId) : undefined;
    const enteredAccount = validIdentifier(body.identifier)
      ? findAccountByIdentifier(body.identifier)
      : undefined;

    if (
      session.stage !== "passwordChanged" ||
      !validPassword(body.password) ||
      !boundAccount ||
      !enteredAccount ||
      enteredAccount.id !== boundAccount.id ||
      boundAccount.id === RECOVERY_SINK_ACCOUNT_ID
    ) {
      recordFailure(session, "login");
      return json({ message: "The sign-in details could not be confirmed. Please try again." }, session, isNew, 400);
    }

    /* Authentication verifies only the account bound to this reset session. */
    const okay = await Bun.password.verify(body.password, boundAccount.passwordHash);
    if (!okay) {
      recordFailure(session, "login");
      return json({ message: "The sign-in details could not be confirmed. Please try again." }, session, isNew, 400);
    }
    clearAttempts(session, "login");
    session.authenticated = true;
    session.stage = "authenticated";
    return json(stageData(session), session, isNew);
  }

  if (pathname === "/api/privacy-confirm") {
    if (!session.authenticated || session.stage !== "authenticated") {
      return json({ message: "Please sign in before confirming privacy conditions." }, session, isNew, 403);
    }
    session.privacyAccepted = true;
    session.stage = "privacyAccepted";
    return json(stageData(session), session, isNew);
  }

  if (pathname === "/api/restart") {
    session.stage = "start";
    session.accountId = undefined;
    session.resetToken = undefined;
    session.resetExpires = undefined;
    session.resetUsed = false;
    session.manualCode = undefined;
    session.mfaCode = undefined;
    session.authenticated = false;
    session.privacyAccepted = false;
    session.attempts.clear();
    return json(stageData(session), session, isNew);
  }

  return json({ message: "Request not available." }, session, isNew, 404);
}

/* Security Misconfiguration: HTTPS-only Bun listener and rejection of proxy-marked insecure traffic. */
const cert = readFileSync("certs/cert.pem");
const key = readFileSync("certs/key.pem");

Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert, key },
  async fetch(request) {
    try {
      if (request.headers.get("x-forwarded-proto") === "http") {
        return textResponse("HTTPS is required.", 400);
      }

      const url = new URL(request.url);
      const { session, isNew } = getSession(request);

      if (url.pathname.startsWith("/api/")) {
        return await handleApi(request, session, isNew, url.pathname);
      }

      /* Only same-file UI routes are served; query token is not rendered into HTML. */
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/verify" || url.pathname === "/recovery")) {
        const nonce = randomValue(16);
        const headers = securityHeaders(nonce);
        headers.set("Content-Type", "text/html; charset=utf-8");
        attachSessionCookie(headers, session, isNew);
        return new Response(page(nonce), { status: 200, headers });
      }

      return textResponse("Page not found.", 404);
    } catch {
      return textResponse("The secure service is temporarily unavailable.", 503);
    }
  },
});

console.log("Secure recovery service running at https://localhost:3000");
