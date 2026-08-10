
import { randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Password Recovery System
 * Single-file Bun HTTPS server and inline vanilla-JS SPA.
 * Security sections map to OWASP requirements in the task specification.
 */

type Recovery = {
  token: string;
  expiresAt: number;
  used: boolean;
  verified: boolean;
  mfaVerified: boolean;
  mfaCode: string;
  real: boolean;
};

type Session = {
  csrf: string;
  createdAt: number;
  recovery?: Recovery;
  authenticated: boolean;
};

type RateRecord = {
  attempts: number;
  windowStart: number;
  blockedUntil: number;
};

const sessions = new Map<string, Session>();
const rateLimits = new Map<string, RateRecord>();

const SESSION_COOKIE = "hospital_recovery_session";
const SESSION_AGE_SECONDS = 60 * 60 * 24;
const RESET_TOKEN_MS = 15 * 60 * 1000;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_BLOCK_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 5;

/*
 * Authentication requirement:
 * The mock account has no browser-visible username, patient data, or identifier.
 * Its initial credential is represented only by this precomputed bcrypt hash.
 */
const RECOVERY_EMAIL = "helena@example.test";
let accountPasswordHash = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
let privacyAccepted = false;

function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("hex");
}

function createSession(): { id: string; session: Session } {
  const id = randomToken(32);
  const session: Session = {
    csrf: randomToken(32),
    createdAt: Date.now(),
    authenticated: false
  };
  sessions.set(id, session);
  return { id, session };
}

function parseCookies(request: Request): Record<string, string> {
  const result: Record<string, string> = {};
  for (const piece of (request.headers.get("cookie") || "").split(";")) {
    const splitAt = piece.indexOf("=");
    if (splitAt <= 0) continue;
    try {
      result[piece.slice(0, splitAt).trim()] = decodeURIComponent(piece.slice(splitAt + 1).trim());
    } catch {
      // Ignore malformed cookie values.
    }
  }
  return result;
}

/* Security Misconfiguration requirement: server-side session lifetime enforcement. */
function findSession(request: Request): { id: string; session: Session } | null {
  const id = parseCookies(request)[SESSION_COOKIE];
  if (!id || !/^[a-f0-9]{64}$/.test(id)) return null;
  const session = sessions.get(id);
  if (!session) return null;
  if (Date.now() - session.createdAt > SESSION_AGE_SECONDS * 1000) {
    sessions.delete(id);
    return null;
  }
  return { id, session };
}

function cookieFor(id: string): string {
  return `${SESSION_COOKIE}=${encodeURIComponent(id)}; Path=/; Max-Age=${SESSION_AGE_SECONDS}; Secure; HttpOnly; SameSite=Strict`;
}

/* Security Misconfiguration requirement: secure headers on every response. */
function securityHeaders(nonce = ""): Headers {
  const headers = new Headers();
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set(
    "Content-Security-Policy",
    `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`
  );
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Cache-Control", "no-store, max-age=0, private");
  headers.set("Pragma", "no-cache");
  return headers;
}

function json(data: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = securityHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => headers.set(key, value));
  return new Response(JSON.stringify(data), { status, headers });
}

function html(body: string, nonce: string, cookie?: string): Response {
  const headers = securityHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  if (cookie) headers.set("Set-Cookie", cookie);
  return new Response(body, { status: 200, headers });
}

function peerIdentity(request: Request, server: any): string {
  try {
    const peer = server?.requestIP?.(request);
    if (peer && typeof peer.address === "string" && peer.address.length <= 128) {
      return `peer:${peer.address}`;
    }
  } catch {
    // Fall through to the conservative local deployment key.
  }
  return "local-deployment";
}

function rateKey(action: string, protectedContext: string, peer: string): string {
  return `${action}:${protectedContext}:${peer}`;
}

/* Authentication requirement: temporary rate blocking for sensitive attempts. */
function rateAllowed(key: string): boolean {
  const now = Date.now();
  const record = rateLimits.get(key);
  if (!record) {
    rateLimits.set(key, { attempts: 1, windowStart: now, blockedUntil: 0 });
    return true;
  }
  if (record.blockedUntil > now) return false;
  if (now - record.windowStart > RATE_WINDOW_MS) {
    record.attempts = 1;
    record.windowStart = now;
    record.blockedUntil = 0;
    return true;
  }
  record.attempts++;
  if (record.attempts > MAX_ATTEMPTS) {
    record.blockedUntil = now + RATE_BLOCK_MS;
    return false;
  }
  return true;
}

function safeEqual(first: string, second: string): boolean {
  const a = Buffer.from(first);
  const b = Buffer.from(second);
  return a.length === b.length && timingSafeEqual(a, b);
}

function validPassword(password: unknown): password is string {
  return typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 128 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password);
}

function validEmail(email: unknown): email is string {
  return typeof email === "string" &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function emailRateContext(value: unknown): string {
  if (typeof value !== "string") return "invalid-email";
  return value.trim().toLowerCase().slice(0, 254) || "invalid-email";
}

function recoveryRateContext(session: Session): string {
  return session.recovery?.token || "no-recovery-context";
}

async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4096 || !request.headers.get("content-type")?.includes("application/json")) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* Broken Access Control requirement: session + per-session CSRF validation. */
function protectedSession(request: Request): { id: string; session: Session } | null {
  const current = findSession(request);
  if (!current) return null;
  const csrf = request.headers.get("x-csrf-token") || "";
  if (!/^[a-f0-9]{64}$/.test(csrf) || !safeEqual(csrf, current.session.csrf)) return null;
  return current;
}

/*
 * Server-authoritative recovery state. Browser storage is only a convenience;
 * this state is always used to decide whether a client may continue.
 */
function authoritativeStage(session: Session): string {
  if (session.authenticated) return privacyAccepted ? "complete" : "privacy";
  const recovery = session.recovery;
  if (!recovery || recovery.used || recovery.expiresAt < Date.now()) return "request";
  if (!recovery.real) return "request";
  if (!recovery.verified) return "confirm-token";
  if (!recovery.mfaVerified) return "choose-password";
  return "safety-check";
}

function stageMessage(stage: string): string {
  if (stage === "request") return "To protect your account, recovery needs to start again. Request a new recovery code when you are ready.";
  if (stage === "confirm-token") return "Your recovery code is ready to confirm. Continue with this calm next step.";
  if (stage === "choose-password") return "Your recovery code was confirmed. Please choose your new password next.";
  if (stage === "safety-check") return "Your safety check was confirmed, but your password was not saved. Please choose it again so nothing is kept in browser storage.";
  if (stage === "signin") return "Your password was changed. Please sign in to continue.";
  if (stage === "privacy") return "You are signed in. Review the privacy statement when ready.";
  return "Your privacy conditions were already accepted.";
}

function genericBlocked(): Response {
  return json({
    ok: false,
    message: "For safety, please pause and try again later. Your progress has not been removed."
  }, 429);
}

async function handleApi(request: Request, pathname: string, peer: string): Promise<Response> {
  if (pathname === "/api/bootstrap" && request.method === "GET") {
    let current = findSession(request);
    let cookie: string | undefined;
    if (!current) {
      current = createSession();
      cookie = cookieFor(current.id);
    }
    const stage = authoritativeStage(current.session);
    return json({
      ok: true,
      csrf: current.session.csrf,
      authenticated: current.session.authenticated,
      privacyPending: current.session.authenticated && !privacyAccepted,
      recoveryStage: stage,
      recoveryMessage: stageMessage(stage)
    }, 200, cookie ? { "Set-Cookie": cookie } : undefined);
  }

  if (request.method !== "POST") {
    return json({ ok: false, message: "This action is not available." }, 405);
  }

  const current = protectedSession(request);
  if (!current) {
    return json({ ok: false, message: "Your secure page needs to be refreshed before continuing." }, 403);
  }

  const body = await requestBody(request);
  if (!body) return json({ ok: false, message: "Please use the form and try again." }, 400);

  if (pathname === "/api/recovery/initiate") {
    const email = body.email;
    if (!rateAllowed(rateKey("recovery-initiate", emailRateContext(email), peer))) return genericBlocked();
    if (!validEmail(email)) return json({ ok: false, message: "Enter an email address in the usual format." }, 400);

    /*
     * Account enumeration protection:
     * Every valid email creates the identical shaped successful response and test
     * delivery. Only a real account receives a server-valid, session-bound token.
     */
    const token = randomToken(32);
    const real = email.trim().toLowerCase() === RECOVERY_EMAIL;
    current.session.recovery = {
      token,
      expiresAt: Date.now() + RESET_TOKEN_MS,
      used: false,
      verified: false,
      mfaVerified: false,
      mfaCode: "481516",
      real
    };

    return json({
      ok: true,
      message: "If an account can use that address, a recovery message has been prepared. Check your secure delivery and continue with the code.",
      testDeliveryToken: token
    });
  }

  if (pathname === "/api/recovery/verify-token") {
    if (!rateAllowed(rateKey("recovery-verify-token", recoveryRateContext(current.session), peer))) return genericBlocked();
    const token = body.token;
    const recovery = current.session.recovery;
    const valid = typeof token === "string" &&
      /^[a-f0-9]{64}$/.test(token) &&
      !!recovery &&
      recovery.real &&
      !recovery.used &&
      recovery.expiresAt >= Date.now() &&
      safeEqual(token, recovery.token);

    if (!valid) {
      return json({ ok: false, message: "That code cannot be confirmed. Check it carefully or request a new recovery message." }, 400);
    }

    recovery.verified = true;
    return json({
      ok: true,
      message: "Code confirmed. Choose a new password, then complete one more safety check.",
      testMfaCode: recovery.mfaCode
    });
  }

  if (pathname === "/api/recovery/verify-mfa") {
    if (!rateAllowed(rateKey("recovery-verify-mfa", recoveryRateContext(current.session), peer))) return genericBlocked();
    const code = body.code;
    const recovery = current.session.recovery;
    const valid = typeof code === "string" &&
      /^\d{6}$/.test(code) &&
      !!recovery &&
      recovery.real &&
      recovery.verified &&
      !recovery.used &&
      recovery.expiresAt >= Date.now() &&
      safeEqual(code, recovery.mfaCode);

    if (!valid) {
      return json({ ok: false, message: "That safety code cannot be confirmed. Please check the six digits and try again." }, 400);
    }

    recovery.mfaVerified = true;
    return json({ ok: true, message: "Safety check complete. Your new password is ready to be saved." });
  }

  if (pathname === "/api/recovery/password-update") {
    if (!rateAllowed(rateKey("recovery-password-update", recoveryRateContext(current.session), peer))) return genericBlocked();
    const password = body.password;
    const recovery = current.session.recovery;
    if (!recovery || !recovery.real || !recovery.verified || !recovery.mfaVerified || recovery.used || recovery.expiresAt < Date.now()) {
      return json({ ok: false, message: "Please restart recovery and complete the safety steps before saving a password." }, 403);
    }
    if (!validPassword(password)) {
      return json({ ok: false, message: "Use at least 12 characters with an uppercase letter, lowercase letter, number, and symbol." }, 400);
    }

    accountPasswordHash = await Bun.password.hash(password, { algorithm: "bcrypt", cost: 10 });
    recovery.used = true;
    recovery.token = randomToken(32);
    return json({ ok: true, message: "Your password has been changed. You can now sign in." });
  }

  if (pathname === "/api/authenticate") {
    if (!rateAllowed(rateKey("login", "mock-hospital-account", peer))) return genericBlocked();
    const password = body.password;
    if (typeof password !== "string" || password.length > 128) {
      return json({ ok: false, message: "The sign-in details could not be confirmed. Please try again." }, 400);
    }
    const matches = await Bun.password.verify(password, accountPasswordHash);
    if (!matches) {
      return json({ ok: false, message: "The sign-in details could not be confirmed. Please try again." }, 401);
    }
    current.session.authenticated = true;
    return json({ ok: true, message: "Signed in securely. Please review the privacy statement." });
  }

  if (pathname === "/api/privacy/accept") {
    if (!current.session.authenticated) {
      return json({ ok: false, message: "Please sign in before accepting the privacy statement." }, 403);
    }
    if (body.accept !== true) return json({ ok: false, message: "Please confirm that you have read the statement." }, 400);
    privacyAccepted = true;
    return json({ ok: true, message: "Privacy conditions accepted. Hospital staff can now continue with appointment booking." });
  }

  return json({ ok: false, message: "This secure action is not available." }, 404);
}

/* Accessibility/UI requirements: focused, stable, low-distraction SPA. */
function page(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hospital account recovery</title>
<style>
:root{color-scheme:light;--blue:#075a9d;--ink:#17212b;--soft:#f2f7fa;--line:#c8d4dc;--good:#126b42}
*{box-sizing:border-box}body{margin:0;font:18px/1.55 Arial,Helvetica,sans-serif;color:var(--ink);background:var(--soft)}
header{background:#fff;border-bottom:4px solid var(--blue)}.wrap{width:min(760px,calc(100% - 32px));margin:auto}header .wrap{padding:22px 0 18px}
h1{margin:0;font-size:1.55rem}main{padding:26px 0 44px}.progress,.card,.help,.logs{background:#fff;border:1px solid var(--line);border-radius:8px;padding:20px;margin-bottom:18px}
.progress ol{display:flex;flex-wrap:wrap;gap:8px 18px;padding-left:24px;margin:8px 0 0}.progress li{color:#52616d}.progress li.active{color:var(--blue);font-weight:bold}.progress li.done{color:var(--good)}
h2{margin-top:0;font-size:1.38rem}p{max-width:65ch}label{display:block;font-weight:bold;margin:18px 0 5px}
input{display:block;width:100%;max-width:530px;padding:12px;border:2px solid #71818c;border-radius:5px;font:inherit}
input:focus,button:focus,a:focus{outline:4px solid #f4bf38;outline-offset:3px}button{margin-top:20px;padding:12px 18px;border:0;border-radius:5px;background:var(--blue);color:#fff;font:inherit;font-weight:bold;cursor:pointer}
button:hover{background:#034879}.feedback{border-left:5px solid var(--blue);background:#eaf4fb;padding:12px;margin:17px 0;font-weight:bold}.feedback.error{border-color:#a43120;background:#fff0ed}.feedback.success{border-color:var(--good);background:#ecf8f1}
.help{border-left:6px solid #f4bf38}.help h2,.logs h2{font-size:1.1rem}.logs{font-size:.9rem}#logList{margin:0;padding-left:22px;max-height:130px;overflow:auto}.muted{color:#4b5963}.privacy-box{border:1px solid var(--line);padding:14px;background:#f8fbfc}
@media(max-width:560px){body{font-size:17px}}
</style>
</head>
<body>
<header><div class="wrap"><h1>Hospital account recovery</h1><p class="muted">A calm, step-by-step way to return to your account.</p></div></header>
<main class="wrap">
<nav class="progress" aria-label="Recovery progress"><strong>Your steps</strong><ol id="progressList"></ol></nav>
<section id="app" class="card" aria-live="polite" aria-atomic="true"></section>
<aside class="help" aria-label="Help and safe authentication guidance">
<h2>Need help?</h2>
<p>You can pause, refresh, and return later. The secure service checks your next step when you return.</p>
<p><strong>Stay safe:</strong> hospital staff will never ask for your password or a security code by email. Do not share either one with anyone.</p>
<p>If you need support, contact the hospital through its usual published phone number. Support can explain the steps but cannot reveal private account information.</p>
</aside>
<section class="logs" aria-label="Simulation logs"><h2>Logs</h2><p class="muted">Test delivery and verification messages appear here and in the browser console.</p><ul id="logList"></ul></section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
const app=document.getElementById("app"),progressList=document.getElementById("progressList"),logList=document.getElementById("logList");
const storageKey="hospital-recovery-progress-v2";
const steps=["Request","Confirm code","New password","Safety check","Sign in","Privacy"];
let csrf="",state={step:1,email:""},pendingPassword="";

function text(node,value){node.textContent=String(value)}
function log(message){console.log(message);const li=document.createElement("li");text(li,message);logList.appendChild(li)}
function notice(message,type){const box=document.createElement("div");box.className="feedback "+(type||"");text(box,message);return box}
function readSaved(){try{const saved=JSON.parse(localStorage.getItem(storageKey)||"{}");if(saved&&Number.isInteger(saved.step)&&saved.step>=1&&saved.step<=6){state.step=saved.step;state.email=typeof saved.email==="string"?saved.email.slice(0,254):""}}catch(_){}}
function save(){localStorage.setItem(storageKey,JSON.stringify({step:state.step,email:state.email}))}
function stageStep(stage){return({request:1,"confirm-token":2,"choose-password":3,"safety-check":3,signin:5,privacy:6,complete:7})[stage]||1}
function progress(){progressList.replaceChildren();steps.forEach((name,index)=>{const li=document.createElement("li");if(index+1===state.step)li.className="active";if(index+1<state.step)li.className="done";text(li,(index+1)+". "+name);progressList.appendChild(li)})}
function input(labelValue,type,name,value,hint){const label=document.createElement("label"),field=document.createElement("input"),id="field-"+name;label.htmlFor=id;text(label,labelValue);field.id=id;field.name=name;field.type=type;field.value=value||"";field.required=true;field.autocomplete=type==="password"?"new-password":"email";if(hint)field.setAttribute("aria-describedby",hint);return{label,input:field}}
function button(form,label){const b=document.createElement("button");b.type="submit";text(b,label);form.appendChild(b)}
async function api(path,data){const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});return response.json().catch(()=>({ok:false,message:"Please refresh and try again."}))}

function render(message,type){
save();progress();app.replaceChildren();
if(state.step===7){const title=document.createElement("h2"),p=document.createElement("p");text(title,"All set");text(p,"You have completed the steps. You may now safely close this page.");app.append(title,notice(message||"Privacy conditions accepted. Hospital staff can now continue with appointment booking.","success"),p);return}
const title=document.createElement("h2"),intro=document.createElement("p");
if(state.step===1){
text(title,"Step 1: Request a recovery code");text(intro,"Enter the email address you use for your hospital account. We will give the same response whether or not an account can use it.");app.append(title,intro);if(message)app.append(notice(message,type));
const form=document.createElement("form"),f=input("Email address","email","email",state.email);f.input.autocomplete="email";form.append(f.label,f.input);button(form,"Request recovery code");
form.addEventListener("submit",async e=>{e.preventDefault();const email=f.input.value.trim();if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)){render("Please enter an email address in the usual format.","error");return}const result=await api("/api/recovery/initiate",{email});if(!result.ok){render(result.message,"error");return}state.email=email;state.step=2;log("[delivery simulation] Reset token: "+result.testDeliveryToken);log("[delivery simulation] Recovery request prepared. Continue by entering the token.");render(result.message,"success")});return}
if(state.step===2){
text(title,"Step 2: Confirm your recovery code");text(intro,"Enter the recovery token from your secure delivery. For this practice system, the token is also in the browser console and Logs panel.");app.append(title,intro);if(message)app.append(notice(message,type));
const form=document.createElement("form"),f=input("Recovery token","text","token","","token-hint"),hint=document.createElement("p");f.input.autocomplete="one-time-code";f.input.maxLength=64;f.input.pattern="[a-fA-F0-9]{64}";hint.id="token-hint";hint.className="muted";text(hint,"This is 64 letters and numbers. There is no rush.");form.append(f.label,f.input,hint);button(form,"Confirm code");
form.addEventListener("submit",async e=>{e.preventDefault();const token=f.input.value.trim().toLowerCase();if(!/^[a-f0-9]{64}$/.test(token)){render("Enter the full 64-character recovery token.","error");return}const result=await api("/api/recovery/verify-token",{token});if(!result.ok){render(result.message,"error");return}state.step=3;log("[delivery simulation] MFA safety code: "+result.testMfaCode);log("[verification simulation] Recovery token accepted.");render(result.message,"success")});return}
if(state.step===3){
text(title,"Step 3: Choose a new password");text(intro,"Make a password with at least 12 characters, including an uppercase letter, lowercase letter, number, and symbol. It is not saved on this device.");app.append(title,intro);if(message)app.append(notice(message,type));
const form=document.createElement("form"),first=input("New password","password","new-password",""),second=input("Repeat new password","password","repeat-password","");form.append(first.label,first.input,second.label,second.input);button(form,"Continue to safety check");
form.addEventListener("submit",e=>{e.preventDefault();const password=first.input.value,valid=password.length>=12&&/[a-z]/.test(password)&&/[A-Z]/.test(password)&&/\\d/.test(password)&&/[^A-Za-z0-9]/.test(password);if(!valid){render("Use at least 12 characters with uppercase, lowercase, number, and symbol.","error");return}if(password!==second.input.value){render("The two passwords do not match. Please try again.","error");return}pendingPassword=password;state.step=4;render("Password choice ready. Complete the safety check next.","success")});return}
if(state.step===4){
text(title,"Step 4: Complete the safety check");text(intro,"Enter the six-digit safety code from your secure delivery. In this practice system it is also shown in the browser console and Logs panel.");app.append(title,intro);if(message)app.append(notice(message,type));
const form=document.createElement("form"),f=input("Six-digit safety code","text","mfa","","mfa-hint"),hint=document.createElement("p");f.input.inputMode="numeric";f.input.maxLength=6;f.input.pattern="\\\\d{6}";hint.id="mfa-hint";hint.className="muted";text(hint,"Recovery is time-limited. You can request a new recovery code at any time if you need one.");form.append(f.label,f.input,hint);button(form,"Confirm safety code");
form.addEventListener("submit",async e=>{e.preventDefault();const code=f.input.value.trim();if(!/^\\d{6}$/.test(code)){render("Enter the six-digit safety code.","error");return}const checked=await api("/api/recovery/verify-mfa",{code});if(!checked.ok){render(checked.message,"error");return}if(!pendingPassword){state.step=3;render("For safety, please choose your new password again. Passwords are never kept in browser storage.","error");return}const updated=await api("/api/recovery/password-update",{password:pendingPassword});pendingPassword="";if(!updated.ok){render(updated.message,"error");return}state.step=5;log("[verification simulation] Safety code confirmed and password saved.");render(updated.message,"success")});return}
if(state.step===5){
text(title,"Step 5: Sign in");text(intro,"Use your new password to securely sign in. This confirms that your recovery is complete.");app.append(title,intro);if(message)app.append(notice(message,type));
const form=document.createElement("form"),f=input("Password","password","login-password","");f.input.autocomplete="current-password";form.append(f.label,f.input);button(form,"Sign in securely");
form.addEventListener("submit",async e=>{e.preventDefault();const result=await api("/api/authenticate",{password:f.input.value});if(!result.ok){render(result.message,"error");return}state.step=6;log("[verification simulation] Sign-in confirmed.");render(result.message,"success")});return}
text(title,"Step 6: Accept the updated privacy conditions");text(intro,"You are signed in. Read the short statement below, then confirm acceptance so hospital staff can continue with appointment booking.");app.append(title,intro);if(message)app.append(notice(message,type));
const statement=document.createElement("div"),heading=document.createElement("strong"),detail=document.createElement("p");statement.className="privacy-box";text(heading,"Privacy statement");text(detail,"Your healthcare account information is handled only for care and appointment services. You can ask the hospital for help understanding these conditions.");statement.append(heading,detail);app.append(statement);
const form=document.createElement("form"),label=document.createElement("label"),check=document.createElement("input");check.type="checkbox";check.required=true;check.style.width="auto";check.style.display="inline-block";check.style.marginRight="10px";label.append(check,document.createTextNode("I have read and accept the updated privacy conditions."));form.append(label);button(form,"Accept privacy conditions");
form.addEventListener("submit",async e=>{e.preventDefault();const result=await api("/api/privacy/accept",{accept:check.checked});if(!result.ok){render(result.message,"error");return}localStorage.removeItem(storageKey);state.step=7;log("[verification simulation] Privacy conditions accepted.");render(result.message,"success")})
}

async function start(){
readSaved();
try{
const response=await fetch("/api/bootstrap",{credentials:"same-origin"}),data=await response.json();csrf=data.csrf||"";
const secureStep=stageStep(data.recoveryStage),savedStep=state.step;
if(secureStep!==savedStep||data.recoveryStage==="safety-check"){
state.step=secureStep;
const explanation=data.recoveryMessage||"Your secure recovery step was checked.";
render(explanation,secureStep===1&&savedStep>1?"error":"success");
return;
}
render();
}catch(_){app.replaceChildren(notice("A secure connection could not be prepared. Please refresh the page.","error"))}
}
start();
})();
</script>
</body>
</html>`;
}

async function main() {
  try {
    const certFile = Bun.file("certs/cert.pem");
    const keyFile = Bun.file("certs/key.pem");
    if (!(await certFile.exists()) || !(await keyFile.exists())) {
      console.log("Secure server could not start: TLS certificate files are unavailable.");
      return;
    }

    Bun.serve({
      hostname: "0.0.0.0",
      port: 3000,
      tls: {
        cert: await certFile.text(),
        key: await keyFile.text()
      },
      fetch: async (request, server) => {
        try {
          const url = new URL(request.url);
          if (url.pathname === "/" && request.method === "GET") {
            let current = findSession(request);
            let cookie: string | undefined;
            if (!current) {
              current = createSession();
              cookie = cookieFor(current.id);
            }
            const nonce = randomToken(16);
            return html(page(nonce), nonce, cookie);
          }
          if (url.pathname.startsWith("/api/")) {
            return await handleApi(request, url.pathname, peerIdentity(request, server));
          }
          return json({ ok: false, message: "Page not found." }, 404);
        } catch {
          return json({ ok: false, message: "The secure service could not complete that request." }, 500);
        }
      }
    });

    console.log("Hospital recovery HTTPS server listening on https://localhost:3000");
  } catch {
    console.log("Secure server could not start. Check TLS certificate configuration.");
  }
}

main();
