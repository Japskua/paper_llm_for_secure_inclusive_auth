
/**
 * MFA Enrolment System
 * Single-file Bun HTTPS server and responsive vanilla-JS mobile SPA.
 * Run with: bun app.ts
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_FAILURES = 5;
const TRUSTED_ORIGIN = "https://localhost:3000";
const INTERNAL_ROUTES = new Set(["signin", "identity", "setup", "confirm", "recovery", "complete"]);

// Security §3: a process-local AES key protects simulated MFA seeds at rest.
const encryptionKey = await crypto.subtle.importKey(
  "raw",
  crypto.getRandomValues(new Uint8Array(32)),
  { name: "AES-GCM" },
  false,
  ["encrypt", "decrypt"],
);

type Session = {
  id: string;
  owner: "marcus@example.com";
  csrf: string;
  createdAt: number;
  lastSeen: number;
  stage: string;
};

type ExpiringCode = {
  hash: string;
  expiresAt: number;
  used: boolean;
  failures: number;
  lockedUntil: number;
};

const sessions = new Map<string, Session>();
const account = {
  email: "marcus@example.com",
  password: "BankPass!42",
  identity: null as ExpiringCode | null,
  authenticator: null as ExpiringCode | null,
  encryptedSecret: "",
  backupHashes: [] as string[],
  mfaEnabled: false,
};

function bytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}
function token(length = 32): string {
  return Buffer.from(bytes(length)).toString("base64url");
}
function numberCode(): string {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return String(value[0] % 1_000_000).padStart(6, "0");
}
async function hash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Buffer.from(digest).toString("base64url");
}
async function encrypt(value: string): Promise<string> {
  const iv = bytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(value));
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(encrypted).toString("base64url")}`;
}
async function decrypt(value: string): Promise<string> {
  const [ivText, cipherText] = value.split(".");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivText, "base64url") },
    encryptionKey,
    Buffer.from(cipherText, "base64url"),
  );
  return decoder.decode(plain);
}
function cookieMap(request: Request): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) out[part.slice(0, at).trim()] = decodeURIComponent(part.slice(at + 1).trim());
  }
  return out;
}
function sessionCookie(id: string): string {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function csrfCookie(value: string): string {
  return `mfa_csrf=${encodeURIComponent(value)}; Path=/; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function clearCookies(): string[] {
  return [
    "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
    "mfa_csrf=; Path=/; Secure; SameSite=Strict; Max-Age=0",
  ];
}

// Security §2: restrictive response security configuration, including clickjacking protection.
const baseHeaders = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};
function json(data: unknown, status = 200, extra: HeadersInit = {}): Response {
  return new Response(JSON.stringify(data), { status, headers: { ...baseHeaders, ...extra } });
}
function page(): Response {
  return new Response(HTML, {
    headers: {
      ...baseHeaders,
      "Content-Type": "text/html; charset=utf-8",
    },
  });
}
function genericError(status = 400): Response {
  return json({ ok: false, message: "We could not complete that step. Please try again." }, status);
}
function originAllowed(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || origin === TRUSTED_ORIGIN;
}
async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  const length = Number(request.headers.get("content-length") || "0");
  if (length > 4000) return null;
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body as Record<string, unknown>;
  } catch {
    return null;
  }
}
function authenticated(request: Request): Session | null {
  const id = cookieMap(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || session.owner !== account.email || now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
// Security §1: every state change has same-origin + per-session CSRF validation.
function csrf(request: Request, session: Session): boolean {
  return originAllowed(request) && request.headers.get("x-csrf-token") === session.csrf;
}
function codeStatus(item: ExpiringCode | null, code: string): "ok" | "locked" | "invalid" {
  const now = Date.now();
  if (!item || item.used || item.expiresAt < now) return "invalid";
  if (item.lockedUntil > now) return "locked";
  return "pending";
}
async function checkCode(item: ExpiringCode | null, code: string): Promise<"ok" | "locked" | "invalid"> {
  const status = codeStatus(item, code);
  if (status !== "pending" || !item) return status === "pending" ? "invalid" : status;
  const expected = await hash(code);
  if (expected === item.hash) {
    item.used = true;
    return "ok";
  }
  item.failures++;
  if (item.failures >= MAX_FAILURES) item.lockedUntil = Date.now() + LOCKOUT_MS;
  return item.lockedUntil > Date.now() ? "locked" : "invalid";
}
function makeCode(value: string): Promise<ExpiringCode> {
  return hash(value).then((hashed) => ({
    hash: hashed,
    expiresAt: Date.now() + CODE_LIFETIME_MS,
    used: false,
    failures: 0,
    lockedUntil: 0,
  }));
}
function requireSession(request: Request): Session | Response {
  const session = authenticated(request);
  return session || json({ ok: false, message: "Please sign in again to continue." }, 401);
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 120;
}
function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 8 && value.length <= 128;
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

// Security §4: routes never accept account identifiers, preventing IDOR/manipulated user IDs.
async function api(request: Request, pathname: string): Promise<Response> {
  if (!originAllowed(request)) return json({ ok: false, message: "This request is not allowed." }, 403);

  if (pathname === "/api/signin" && request.method === "POST") {
    const body = await readBody(request);
    const cookieCsrf = cookieMap(request).mfa_csrf;
    if (!body || !cookieCsrf || request.headers.get("x-csrf-token") !== cookieCsrf || !validEmail(body.email) || !validPassword(body.password)) {
      return json({ ok: false, message: "Check your email and password, then try again." }, 400);
    }
    // Generic result avoids account enumeration. Session ID is rotated on authentication.
    if (body.email !== account.email || body.password !== account.password) {
      return json({ ok: false, message: "Check your email and password, then try again." }, 401);
    }
    const id = token(32);
    const freshCsrf = token(24);
    const stage = account.mfaEnabled ? "complete" : "identity";
    sessions.set(id, { id, owner: account.email, csrf: freshCsrf, createdAt: Date.now(), lastSeen: Date.now(), stage });
    return json({ ok: true, stage, csrf: freshCsrf, message: "Signed in. Next, verify your identity." }, 200, {
      "Set-Cookie": `${sessionCookie(id)}, ${csrfCookie(freshCsrf)}`,
    });
  }

  if (pathname === "/api/me" && request.method === "GET") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    return json({ ok: true, stage: session.stage, email: "marcus@example.com", csrf: session.csrf });
  }

  if (pathname === "/api/identity/send" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const sentCode = numberCode();
    account.identity = await makeCode(sentCode);
    session.stage = "identity";
    // Simulated only: returned to UI so browser console can demonstrate delivery.
    return json({ ok: true, code: sentCode, message: "A 6-digit identity code is ready. You can reveal it below." });
  }

  if (pathname === "/api/identity/verify" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const body = await readBody(request);
    if (!body || !validOtp(body.code)) return json({ ok: false, message: "Enter the 6 digits, for example 123456." }, 400);
    const result = await checkCode(account.identity, body.code);
    if (result === "locked") return json({ ok: false, message: "Too many tries. Request a fresh code and try again in 15 minutes." }, 429);
    if (result !== "ok") return json({ ok: false, message: "That code did not match. Check all 6 digits or request a new code." }, 400);
    session.stage = "setup";
    return json({ ok: true, stage: "setup", message: "Identity checked. Next, set up your authenticator." });
  }

  if (pathname === "/api/authenticator/setup" && request.method === "GET") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (session.stage !== "setup" && session.stage !== "confirm") return json({ ok: false, message: "Complete identity verification first." }, 403);
    let secret: string;
    if (!account.encryptedSecret) {
      secret = Buffer.from(bytes(20)).toString("base64url").toUpperCase();
      account.encryptedSecret = await encrypt(secret);
    } else {
      secret = await decrypt(account.encryptedSecret);
    }
    const uri = `otpauth://totp/Local%20Bank:marcus%40example.com?secret=${secret}&issuer=Local%20Bank&algorithm=SHA1&digits=6&period=30`;
    return json({ ok: true, secret, uri, message: "Scan the QR code, or copy the setup key." });
  }

  if (pathname === "/api/authenticator/send" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session) || (session.stage !== "setup" && session.stage !== "confirm")) return genericError(403);
    const otp = numberCode();
    account.authenticator = await makeCode(otp);
    session.stage = "confirm";
    return json({ ok: true, code: otp, message: "A practice authenticator code is ready. Enter it when you are ready." });
  }

  if (pathname === "/api/authenticator/verify" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const body = await readBody(request);
    if (!body || !validOtp(body.code)) return json({ ok: false, message: "Enter 6 digits, for example 123456." }, 400);
    const result = await checkCode(account.authenticator, body.code);
    if (result === "locked") return json({ ok: false, message: "Too many tries. Request a fresh practice code and try again in 15 minutes." }, 429);
    if (result !== "ok") return json({ ok: false, message: "That code did not match. Request a fresh practice code and try again." }, 400);
    session.stage = "recovery";
    return json({ ok: true, stage: "recovery", message: "Authenticator confirmed. Next, save your recovery codes." });
  }

  if (pathname === "/api/recovery/create" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session) || session.stage !== "recovery") return genericError(403);
    const codes = Array.from({ length: 8 }, () => `${token(4).toUpperCase()}-${token(4).toUpperCase()}`);
    account.backupHashes = await Promise.all(codes.map((code) => hash(code)));
    return json({ ok: true, codes, message: "Your recovery codes are ready. Save them somewhere private." });
  }

  if (pathname === "/api/recovery/finish" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session) || session.stage !== "recovery" || account.backupHashes.length !== 8) return genericError(403);
    account.mfaEnabled = true;
    session.stage = "complete";
    return json({ ok: true, stage: "complete", message: "MFA is now on." });
  }

  if (pathname === "/api/logout" && request.method === "POST") {
    const session = requireSession(request);
    if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    sessions.delete(session.id);
    return json({ ok: true, message: "Signed out." }, 200, { "Set-Cookie": clearCookies().join(", ") });
  }

  return genericError(404);
}

const HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · MFA setup</title>
<style>
:root{--ink:#14283d;--muted:#506477;--blue:#075bc7;--blue2:#e9f3ff;--green:#087948;--red:#b42318;--line:#c9d6e1;--paper:#fff;--bg:#f4f8fb}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}
button,input{font:inherit;letter-spacing:inherit} button{cursor:pointer} .shell{width:min(100%,580px);margin:auto;min-height:100vh;background:var(--paper);padding:22px 20px 42px}
header{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:24px}.brand{font-weight:800;font-size:1.15rem;color:#063d82}.step{font-size:.92rem;color:var(--muted);margin-top:5px}
h1{font-size:1.65rem;line-height:1.3;margin:0 0 14px;letter-spacing:.02em}h2{font-size:1.12rem;margin:0 0 8px}p{margin:0 0 17px}.lead{font-size:1.05rem}.icon{font-size:1.45rem;margin-right:8px}
.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:18px 0;background:#fff}.hint{background:#f5faff;border-left:5px solid var(--blue);padding:13px 15px;border-radius:5px;color:#29445c;font-size:.94rem}
label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;padding:13px;border:2px solid #8499ac;border-radius:8px;background:#fff;color:var(--ink);font-size:1.1rem}input:focus{outline:3px solid #80b8f6;outline-offset:2px;border-color:var(--blue)}.code-input{text-align:center;font-weight:bold;font-size:1.45rem;letter-spacing:.22em}
.primary{width:100%;border:0;border-radius:9px;padding:15px 16px;background:var(--blue);color:white;font-weight:800;margin-top:23px;min-height:56px}.primary:hover{background:#034b9f}.secondary,.text-btn{border:2px solid var(--blue);color:#064d9e;background:#fff;border-radius:8px;padding:10px 13px;font-weight:700}.text-btn{border:0;padding:4px;text-decoration:underline}.buttons{display:grid;gap:10px;margin-top:13px}.message{padding:12px 14px;border-radius:8px;margin:16px 0;font-weight:700}.success{background:#e5f6ed;color:#075a36}.error{background:#fff0ef;color:var(--red)}.hidden{display:none!important}
.progress{display:flex;gap:5px;margin:0 0 22px}.progress span{height:7px;flex:1;border-radius:9px;background:#d7e0e8}.progress .on{background:var(--blue)}
.secret{word-break:break-all;background:#f4f7f9;border:1px solid var(--line);padding:12px;border-radius:7px;font-family:monospace;letter-spacing:.08em}.qr{width:196px;height:196px;margin:15px auto;border:9px solid white;outline:1px solid var(--ink);display:grid;grid-template-columns:repeat(13,1fr);gap:2px;padding:7px;background:white}.qr i{background:#12324b}.qr i:nth-child(3n),.qr i:nth-child(5n){background:white}.codes{list-style:none;padding:0;margin:12px 0}.codes li{font-family:monospace;font-size:1.05rem;border-bottom:1px solid var(--line);padding:7px 3px;letter-spacing:.07em}.logs{margin-top:32px;border-top:2px solid var(--line);padding-top:16px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#0e2436;color:#dff5ff;border-radius:8px;padding:12px;font:12px/1.55 monospace;min-height:62px}.small{font-size:.9rem;color:var(--muted)}footer{margin-top:24px}.logout{color:#6b1a14}
@media(max-width:370px){.shell{padding:17px 15px}.qr{width:174px;height:174px}body{font-size:16px}}
</style>
</head>
<body>
<main class="shell">
<header><div class="brand">🏦 Local Bank</div><div id="stepText" class="step">Secure account setup</div></header>
<section id="app" aria-live="polite"><p>Loading your secure setup…</p></section>
<section class="logs" aria-label="Simulation logs"><h2>🧾 Logs</h2><p class="small">Simulation messages appear here and in the browser console.</p><pre id="logs">Ready.</pre></section>
</main>
<script>
(() => {
"use strict";
const app=document.getElementById("app"), stepText=document.getElementById("stepText"), logs=document.getElementById("logs");
let csrf="", shownIdentity="", shownOtp="", setupData=null, recoveryCodes=[];
const stages={signin:0,identity:1,setup:2,confirm:3,recovery:4,complete:5};
function log(message){console.log(message); logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+message}
function cookie(name){const part=document.cookie.split("; ").find(x=>x.startsWith(name+"="));return part?decodeURIComponent(part.split("=").slice(1).join("=")):""}
function setStep(name){const n=stages[name]??0;stepText.textContent=name==="signin"?"Step 1 of 5 · Sign in":"Step "+Math.min(n+1,5)+" of 5 · MFA enrolment"}
function el(tag,attrs={},text=""){const node=document.createElement(tag);Object.entries(attrs).forEach(([k,v])=>{if(k==="class")node.className=v;else if(k.startsWith("on"))node.addEventListener(k.slice(2),v);else node.setAttribute(k,v)});if(text)node.textContent=text;return node}
function message(text,type="success"){return el("div",{class:"message "+type,role:"status"},text)}
function progress(n){const d=el("div",{class:"progress","aria-label":"Setup progress"});for(let i=1;i<=5;i++)d.append(el("span",{class:i<=n?"on":""}));return d}
async function api(path,method="GET",body){try{const r=await fetch(path,{method,headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:body?JSON.stringify(body):undefined,credentials:"same-origin"});const data=await r.json();if(r.status===401){csrf="";renderSignin(data.message);return null}return data}catch(e){return {ok:false,message:"Connection problem. Please try again."}}}
function clear(){app.replaceChildren()}
function help(){return el("p",{class:"hint"},"💡 Need help? You can take your time. You can safely request a new code whenever you need one.")}
function renderSignin(note=""){
 setStep("signin");clear(); app.append(el("h1",{},"Sign in to start MFA setup"),el("p",{class:"lead"},"🔐 We will guide you through five short steps. There is no reading timer."));
 if(note)app.append(message(note,note.includes("Signed")?"success":"error"));
 const form=el("form"); const email=el("input",{id:"email",type:"email",autocomplete:"username",inputmode:"email",placeholder:"name@example.com",required:""});const pass=el("input",{id:"password",type:"password",autocomplete:"current-password",placeholder:"Your password",required:""});
 form.append(el("label",{for:"email"},"Email"),email,el("p",{class:"small"},"Example: name@example.com"),el("label",{for:"password"},"Password"),pass);
 const submit=el("button",{class:"primary",type:"submit"},"Sign in");form.append(submit);form.addEventListener("submit",async e=>{e.preventDefault();csrf=cookie("mfa_csrf");const data=await api("/api/signin","POST",{email:email.value.trim(),password:pass.value});if(!data)return;if(!data.ok){app.insertBefore(message(data.message,"error"),form);return}csrf=data.csrf;log("Sign-in simulation completed.");renderIdentity(data.message)});app.append(form,help(),el("p",{class:"small"},"Demo sign-in: marcus@example.com · BankPass!42"));
}
function renderIdentity(note=""){
 setStep("identity");clear();app.append(progress(1),el("h1",{},"Verify it is you"),el("p",{class:"lead"},"📩 We will send one short code. You can reveal it in this safe demo."));
 if(note)app.append(message(note)); const send=el("button",{class:"primary",type:"button"},"Send identity code");send.onclick=async()=>{const d=await api("/api/identity/send","POST",{});if(d&&d.ok){shownIdentity=d.code;log("Simulated identity delivery code: "+d.code);renderIdentity(d.message)}else if(d)app.append(message(d.message,"error"))};app.append(send);
 if(shownIdentity){const reveal=el("button",{class:"text-btn",type:"button"},"Reveal demo code");const box=el("div",{class:"secret hidden"});box.textContent=shownIdentity;reveal.onclick=()=>box.classList.toggle("hidden");app.append(reveal,box);const form=el("form");const input=el("input",{class:"code-input",inputmode:"numeric",autocomplete:"one-time-code",pattern:"[0-9]{6}",maxlength:"6",placeholder:"123456",required:""});form.append(el("label",{},"Enter the 6-digit code"),input,el("p",{class:"small"},"Example: 123456"));form.append(el("button",{class:"primary",type:"submit"},"Check code"));form.addEventListener("submit",async e=>{e.preventDefault();const d=await api("/api/identity/verify","POST",{code:input.value.replace(/\\s/g,"")});if(d&&d.ok){shownIdentity="";renderSetup(d.message)}else if(d)form.prepend(message(d.message,"error"))});app.append(form)}
 app.append(help());
}
async function renderSetup(note=""){
 setStep("setup");clear(); const d=await api("/api/authenticator/setup");if(!d||!d.ok){renderSignin(d?.message||"Please sign in again.");return}setupData=d;
 app.append(progress(2),el("h1",{},"Set up your authenticator"),el("p",{class:"lead"},"📱 Use an authenticator app. Scan the QR code or copy the setup key."));
 if(note)app.append(message(note));const qr=el("div",{class:"qr","aria-label":"QR code setup option"});for(let i=0;i<169;i++)qr.append(el("i"));app.append(el("div",{class:"card"},el("h2",{},"QR code"),qr,el("p",{class:"small"},"Open your authenticator app and choose Scan QR code.")));
 const secret=el("div",{class:"secret"},d.secret);const copy=el("button",{class:"secondary",type:"button"},"Copy setup key");copy.onclick=async()=>{await navigator.clipboard?.writeText(d.secret);copy.textContent="Copied setup key ✓";log("Provisioning secret copied in browser simulation.");};app.append(el("h2",{},"Or enter this setup key"),secret,el("div",{class:"buttons"},copy));
 const uri=el("button",{class:"text-btn",type:"button"},"Show provisioning link");const uriBox=el("div",{class:"secret hidden"});uriBox.textContent=d.uri;uri.onclick=()=>uriBox.classList.toggle("hidden");app.append(uri,uriBox,el("p",{class:"small"},"You may paste the key or provisioning link. You do not need to type it."));
 const next=el("button",{class:"primary",type:"button"},"I added it to my app");next.onclick=async()=>{const x=await api("/api/authenticator/send","POST",{});if(x&&x.ok){shownOtp=x.code;log("Simulated authenticator OTP: "+x.code);renderConfirm(x.message)}else if(x)app.append(message(x.message,"error"))};app.append(next,help());
}
function renderConfirm(note=""){
 setStep("confirm");clear();app.append(progress(3),el("h1",{},"Check your authenticator"),el("p",{class:"lead"},"🔢 Enter the 6-digit code from your app. Take as long as you need."));
 if(note)app.append(message(note));const reveal=el("button",{class:"text-btn",type:"button"},"Reveal practice code in this demo");const box=el("div",{class:"secret hidden"});box.textContent=shownOtp;reveal.onclick=()=>box.classList.toggle("hidden");app.append(reveal,box);
 const form=el("form");const input=el("input",{class:"code-input",inputmode:"numeric",autocomplete:"one-time-code",pattern:"[0-9]{6}",maxlength:"6",placeholder:"123456",required:""});form.append(el("label",{},"Authenticator code"),input,el("p",{class:"small"},"Example: 123456"),el("button",{class:"primary",type:"submit"},"Confirm authenticator"));form.addEventListener("submit",async e=>{e.preventDefault();const d=await api("/api/authenticator/verify","POST",{code:input.value.replace(/\\s/g,"")});if(d&&d.ok){shownOtp="";renderRecovery(d.message)}else if(d)form.prepend(message(d.message,"error"))});app.append(form);
 const retry=el("button",{class:"text-btn",type:"button"},"Request a fresh practice code");retry.onclick=async()=>{const d=await api("/api/authenticator/send","POST",{});if(d&&d.ok){shownOtp=d.code;log("Simulated replacement authenticator OTP: "+d.code);renderConfirm(d.message)}};app.append(retry,help());
}
function renderRecovery(note=""){
 setStep("recovery");clear();app.append(progress(4),el("h1",{},"Save recovery codes"),el("p",{class:"lead"},"🗝️ These help if you lose your phone. Keep them somewhere private."));
 if(note)app.append(message(note));const make=el("button",{class:"primary",type:"button"},"Create recovery codes");make.onclick=async()=>{const d=await api("/api/recovery/create","POST",{});if(d&&d.ok){recoveryCodes=d.codes;log("Simulated recovery codes: "+d.codes.join(", "));renderRecovery(d.message)}else if(d)app.append(message(d.message,"error"))};if(!recoveryCodes.length){app.append(make,help());return}
 const list=el("ul",{class:"codes","aria-label":"Recovery codes"});recoveryCodes.forEach(c=>list.append(el("li",{},c)));app.append(el("div",{class:"card"},el("h2",{},"Your eight codes"),list));
 const copy=el("button",{class:"secondary",type:"button"},"Copy all codes");copy.onclick=async()=>{await navigator.clipboard?.writeText(recoveryCodes.join("\\n"));copy.textContent="Codes copied ✓"};const down=el("button",{class:"secondary",type:"button"},"Download text file");down.onclick=()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([recoveryCodes.join("\\n")],{type:"text/plain"}));a.download="local-bank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href)};app.append(el("div",{class:"buttons"},copy,down));
 const finish=el("button",{class:"primary",type:"button"},"I saved my codes");finish.onclick=async()=>{const d=await api("/api/recovery/finish","POST",{});if(d&&d.ok){recoveryCodes=[];renderComplete(d.message)}else if(d)app.append(message(d.message,"error"))};app.append(finish,help());
}
function renderComplete(note=""){
 setStep("complete");clear();app.append(progress(5),el("h1",{},"MFA is ready"),message(note||"MFA is now on."),el("p",{class:"lead"},"✅ Your authenticator and recovery codes are set up. You can now use this account securely."),el("p",{class:"hint"},"Keep recovery codes private. You can return to your account whenever you are ready."));
 const out=el("button",{class:"text-btn logout",type:"button"},"Sign out");out.onclick=async()=>{await api("/api/logout","POST",{});csrf="";shownIdentity="";shownOtp="";setupData=null;renderSignin("You are signed out.")};app.append(out);
}
async function init(){csrf=cookie("mfa_csrf");if(!csrf){csrf=crypto.getRandomValues(new Uint32Array(4)).join("");document.cookie="mfa_csrf="+encodeURIComponent(csrf)+"; Path=/; Secure; SameSite=Strict"}const me=await api("/api/me");if(me&&me.ok){csrf=me.csrf;if(me.stage==="identity")renderIdentity();else if(me.stage==="setup"||me.stage==="confirm")renderSetup();else if(me.stage==="recovery")renderRecovery();else renderComplete()}else renderSignin()}
init();
})();
</script>
</body>
</html>`;

Bun.serve({
  port: 3000,
  hostname: "localhost",
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/" && request.method === "GET") return page();
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      return genericError(404);
    } catch {
      // Security §2: production-safe generic failures; no stack traces or sensitive details.
      return genericError(500);
    }
  },
});
