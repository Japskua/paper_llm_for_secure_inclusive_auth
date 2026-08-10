
import { createHash } from "node:crypto";

/*
  MFA Enrolment System — single Bun file.
  Requirements 1–5: server-side session ownership, CSRF, TLS/security headers,
  cryptographic mock state, validation, rate limiting, and a mobile SPA.
*/

const PORT = Number(process.env.PORT || 3000);
const encoder = new TextEncoder();
const now = () => Date.now();

type Session = {
  accountId: string;
  csrf: string;
  createdAt: number;
  lastSeen: number;
};
type PendingIdentity = {
  accountId: string;
  codeHash: string;
  expiresAt: number;
  attempts: number;
  lockedUntil: number;
  used: boolean;
};
type Provisioning = {
  secretEncrypted: string;
  expectedOtpHash: string;
  expiresAt: number;
  attempts: number;
  lockedUntil: number;
  used: boolean;
};
type Account = {
  id: string;
  email: string;
  phone: string;
  mfaEnabled: boolean;
  authenticatorSecretEncrypted?: string;
  recoveryCodeHashes: string[];
};

const sessions = new Map<string, Session>();
const pendingIdentities = new Map<string, PendingIdentity>();
const provisions = new Map<string, Provisioning>();

const account: Account = {
  id: "acct_marcus_001",
  email: "marcus@example.test",
  phone: "+15551234567",
  mfaEnabled: false,
  recoveryCodeHashes: [],
};

/* Requirement 3: process-memory encryption key; no secrets are browser-persisted. */
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCK_MS = 10 * 60 * 1000;
const TRUSTED_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

function randomToken(bytes = 32): string {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return Buffer.from(value).toString("base64url");
}
function randomDigits(length = 6): string {
  const values = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(values, (v) => String(v % 10)).join("");
}
function randomRecoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const values = crypto.getRandomValues(new Uint8Array(10));
  let code = "";
  for (let i = 0; i < 10; i++) code += alphabet[values[i] % alphabet.length];
  return `${code.slice(0, 5)}-${code.slice(5)}`;
}
function hash(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}
async function strongHash(value: string): Promise<string> {
  return await Bun.password.hash(value, { algorithm: "argon2id" });
}
async function strongVerify(value: string, stored: string): Promise<boolean> {
  return await Bun.password.verify(value, stored);
}
async function encryptAtRest(plain: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(plain));
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(encrypted).toString("base64url")}`;
}
function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const result: Record<string, string> = {};
  for (const item of raw.split(";")) {
    const index = item.indexOf("=");
    if (index > 0) result[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return result;
}
function sessionCookie(id: string, age = SESSION_ABSOLUTE_MS / 1000): string {
  return `sid=${id}; Path=/; Max-Age=${Math.floor(age)}; HttpOnly; Secure; SameSite=Strict`;
}
function pendingCookie(id: string, age = CHALLENGE_MS / 1000): string {
  return `preauth=${id}; Path=/; Max-Age=${Math.floor(age)}; HttpOnly; Secure; SameSite=Strict`;
}
function clearCookie(name: string): string {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}
function localOriginAllowed(origin: string | null): boolean {
  if (!origin) return true;
  try {
    const url = new URL(origin);
    return url.protocol === "https:" && TRUSTED_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
}
/* Requirement 2: headers are applied to all responses, including errors. */
function headersFor(request: Request, extra: HeadersInit = {}): Headers {
  const headers = new Headers(extra);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  const origin = request.headers.get("origin");
  if (origin && localOriginAllowed(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  return headers;
}
function json(request: Request, body: unknown, status = 200, extra: HeadersInit = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: headersFor(request, extra) });
}
function genericError(request: Request, status = 400): Response {
  return json(request, { ok: false, message: "We could not complete that request. Please try again." }, status);
}
function isValidEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function isValidPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+[1-9]\d{7,14}$/.test(value);
}
function isOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function isRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value);
}
function sessionFor(request: Request): { id: string; value: Session } | null {
  const id = parseCookies(request).sid;
  if (!id) return null;
  const value = sessions.get(id);
  if (!value || now() - value.lastSeen > SESSION_IDLE_MS || now() - value.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  value.lastSeen = now();
  return { id, value };
}
/* Requirement 1: every MFA mutation checks both current account ownership and CSRF. */
function authorizedMfa(request: Request, requireCsrf = false): { id: string; value: Session } | null {
  const session = sessionFor(request);
  if (!session || session.value.accountId !== account.id) return null; // no client account ID is accepted
  if (requireCsrf) {
    const csrf = request.headers.get("x-csrf-token");
    if (!csrf || csrf.length > 128 || csrf !== session.value.csrf || !localOriginAllowed(request.headers.get("origin"))) return null;
  }
  return session;
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const result = await request.json();
    return result && typeof result === "object" && !Array.isArray(result) ? result as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function htmlHeaders(request: Request): Headers {
  const h = headersFor(request);
  h.set("Content-Type", "text/html; charset=utf-8");
  return h;
}

const page = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Northstar Bank — MFA enrolment</title>
<style>
:root{color-scheme:light;--navy:#092b4c;--blue:#1267b3;--pale:#edf6ff;--ink:#17212b;--muted:#5b6875;--line:#ccd7e1;--danger:#a92323;--ok:#13733a}
*{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:var(--ink);font:16px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:520px;min-height:100vh;margin:auto;background:#fff;box-shadow:0 0 20px #cbd3da;padding:0 20px 30px}
header{margin:0 -20px 24px;padding:20px;background:var(--navy);color:white}header p{margin:3px 0 0;font-size:.9rem;color:#d9edff}h1{font-size:1.3rem;margin:0}h2{font-size:1.4rem;line-height:1.2;margin:0 0 12px}h3{margin:20px 0 8px;font-size:1rem}
p{margin:9px 0}.muted{color:var(--muted);font-size:.92rem}.step{display:inline-block;background:#dcedfc;color:#124a79;border-radius:16px;padding:3px 10px;font-size:.82rem;font-weight:700;margin-bottom:13px}
label{display:block;margin:15px 0 5px;font-weight:650}input{width:100%;padding:12px;border:1px solid #94a8b9;border-radius:7px;font:inherit}input:focus{outline:3px solid #aad5f5;border-color:var(--blue)}
button{width:100%;margin-top:19px;padding:13px;border:0;border-radius:7px;background:var(--blue);color:#fff;font:700 1rem inherit;cursor:pointer}button.secondary{background:#e5edf3;color:#173955}button.danger{background:#a92323}.notice{padding:12px;border-radius:7px;background:var(--pale);border-left:4px solid var(--blue);margin:15px 0}.error{padding:11px;background:#fff0f0;color:#7e1919;border-left:4px solid var(--danger);margin:13px 0}.success{padding:11px;background:#ecf9f0;color:#075c2b;border-left:4px solid var(--ok);margin:13px 0}
.secret{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.05em;word-break:break-all;background:#f4f7f9;border:1px solid var(--line);padding:11px;border-radius:6px}.codes{list-style:none;padding:0;margin:10px 0}.codes li{font:700 1.04rem ui-monospace,monospace;padding:8px;border-bottom:1px solid var(--line);letter-spacing:.04em}
details{margin-top:23px;border-top:1px solid var(--line);padding-top:8px}summary{cursor:pointer;font-weight:650}#logs{max-height:155px;overflow:auto;background:#101b26;color:#d9f2ff;padding:9px;font:12px/1.35 ui-monospace,monospace;border-radius:6px;white-space:pre-wrap}.row{display:flex;gap:9px}.row button{width:auto;flex:1}.hidden{display:none}
@media(max-width:360px){main{padding-left:15px;padding-right:15px}header{margin-left:-15px;margin-right:-15px}.row{display:block}}
</style>
</head>
<body>
<main>
<header><h1>Northstar Bank</h1><p>Secure MFA enrolment</p></header>
<section id="app" aria-live="polite">Loading secure enrolment…</section>
<details><summary>Logs (simulated browser delivery)</summary><div id="logs">No simulated delivery has occurred.</div></details>
</main>
<script>
(() => {
"use strict";
/* Browser-console mock requirement: this panel mirrors only browser-side simulated delivery. */
const app=document.getElementById("app"), logs=document.getElementById("logs");
const state={screen:"signin",csrf:"",provision:null,codes:[],message:"",error:"",status:null};
function logMock(label, value){const line="[MOCK] "+label+": "+value; console.log(line); logs.textContent=(logs.textContent==="No simulated delivery has occurred."?"":logs.textContent+"\\n")+line;}
function text(value){return document.createTextNode(String(value));}
function clear(el){while(el.firstChild)el.removeChild(el.firstChild);}
function el(tag, attrs={}, children=[]){const node=document.createElement(tag);for(const [k,v] of Object.entries(attrs)){if(k==="className")node.className=v;else if(k==="textContent")node.textContent=v;else node.setAttribute(k,v);}for(const child of children)node.append(child instanceof Node?child:text(child));return node;}
function field(form,label,type,name,placeholder){form.append(el("label",{for:name,textContent:label}));form.append(el("input",{id:name,name,type,required:"",autocomplete:"off",placeholder}));}
function button(label, cls){return el("button",{type:"submit",className:cls||"",textContent:label});}
function banner(){const out=[];if(state.error)out.push(el("p",{className:"error",textContent:state.error}));if(state.message)out.push(el("p",{className:"success",textContent:state.message}));return out;}
async function api(path, method="GET", payload){
 const options={method,credentials:"same-origin",headers:{}};
 if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=state.csrf;if(payload!==undefined)options.body=JSON.stringify(payload);}
 try{const r=await fetch(path,options);const d=await r.json();if(!r.ok)throw new Error(d.message||"Request unavailable.");return d;}catch(e){throw new Error("We could not complete that request. Please try again.");}
}
function resetMessage(){state.error="";state.message="";}
function render(){
 clear(app); resetMessage();
 if(state.screen==="signin") signIn(); else if(state.screen==="identity") identity(); else if(state.screen==="setup") setup(); else if(state.screen==="confirm") confirm(); else if(state.screen==="recovery") recovery(); else settings();
}
function screen(title, step, intro){const s=el("section");s.append(el("span",{className:"step",textContent:step}),el("h2",{textContent:title}),el("p",{className:"muted",textContent:intro}));return s;}
function signIn(){
 const s=screen("Sign in","Step 1 of 5","Use the demonstration account to begin secure enrolment.");
 const note=el("div",{className:"notice"});note.append(text("Demo account: "),el("strong",{textContent:"marcus@example.test"}),text(" · password: "),el("strong",{textContent:"Marcus!2025"}));s.append(note);
 const f=el("form");field(f,"Email address","email","email","marcus@example.test");field(f,"Mobile number","tel","phone","+15551234567");field(f,"Password","password","password","Enter password");f.append(button("Continue"));
 f.addEventListener("submit",async e=>{e.preventDefault();const d=new FormData(f);try{const r=await api("/api/signin","POST",{email:d.get("email"),phone:d.get("phone"),password:d.get("password")});state.screen="identity";logMock("Identity verification SMS test code",r.mockCode);render();}catch(e){state.error=e.message;render();}});
 s.append(...banner(),f);app.append(s);
}
function identity(){
 const s=screen("Verify your identity","Step 2 of 5","We sent a six-digit verification code to your registered mobile number.");
 s.append(el("div",{className:"notice",textContent:"For this academic mock, the delivery code is shown in the browser console Logs panel."}));
 const f=el("form");field(f,"Verification code","text","code","Six digits");f.querySelector("input").setAttribute("inputmode","numeric");f.append(button("Verify identity"));
 f.addEventListener("submit",async e=>{e.preventDefault();const d=new FormData(f);try{const r=await api("/api/verify-identity","POST",{code:d.get("code")});state.csrf=r.csrf;state.screen="setup";render();}catch(e){state.error=e.message;render();}});
 s.append(...banner(),f);app.append(s);
}
function setup(){
 const s=screen("Set up your authenticator","Step 3 of 5","Add this secret to an authenticator app. You may enter it manually.");
 const f=el("form");f.append(button("Generate authenticator setup"));
 f.addEventListener("submit",async e=>{e.preventDefault();try{const r=await api("/api/mfa/provision","POST",{});state.provision=r;logMock("Authenticator manual secret",r.manualSecret);logMock("Authenticator test verification code",r.mockOtp);state.screen="confirm";render();}catch(e){state.error=e.message;render();}});
 s.append(el("div",{className:"notice",textContent:"The setup secret is displayed only after you request it and is never stored by this browser."}),...banner(),f);app.append(s);
}
function confirm(){
 const s=screen("Confirm authenticator","Step 4 of 5","Enter the six-digit code from your authenticator app.");
 if(state.provision){s.append(el("h3",{textContent:"Manual setup secret"}),el("p",{className:"secret",textContent:state.provision.manualSecret}),el("p",{className:"muted",textContent:"Mock provisioning URI: "+state.provision.provisioningUri}),el("div",{className:"notice",textContent:"Testing note: the current mock code is available in Logs. This setup expires in five minutes."}));}
 const f=el("form");field(f,"Authenticator code","text","otp","Six digits");f.querySelector("input").setAttribute("inputmode","numeric");f.append(button("Confirm and enable MFA"));
 f.addEventListener("submit",async e=>{e.preventDefault();const d=new FormData(f);try{const r=await api("/api/mfa/verify-enrollment","POST",{otp:d.get("otp")});state.codes=r.recoveryCodes;state.provision=null;logMock("New recovery codes",r.recoveryCodes.join(", "));state.screen="recovery";render();}catch(e){state.error=e.message;render();}});
 s.append(...banner(),f);app.append(s);
}
function recovery(){
 const s=screen("Save recovery codes","Step 5 of 5","Keep these codes somewhere safe. Each code works once and will not be shown again.");
 const ul=el("ul",{className:"codes"});for(const code of state.codes)ul.append(el("li",{textContent:code}));s.append(ul,el("div",{className:"notice",textContent:"These recovery codes are in temporary page memory only. Copy them now; do not save them in this browser."}));
 const f=el("form");f.append(button("I have saved my codes"));f.addEventListener("submit",e=>{e.preventDefault();state.codes=[];state.screen="settings";render();});s.append(...banner(),f);app.append(s);
}
function settings(){
 const s=screen("MFA settings","Protected settings","Your account has multi-factor authentication enabled.");
 const status=el("div",{className:"success",textContent:"Authenticator app protection is active."});s.append(status);
 const use=el("form");use.append(el("h3",{textContent:"Use a recovery code"}));field(use,"Recovery code","text","recovery","ABCDE-23456");use.append(button("Use recovery code","secondary"));
 use.addEventListener("submit",async e=>{e.preventDefault();const d=new FormData(use);try{await api("/api/mfa/recovery-use","POST",{recoveryCode:d.get("recovery")});state.message="Recovery code accepted and consumed.";render();}catch(e){state.error=e.message;render();}});
 const regen=el("form");regen.append(el("h3",{textContent:"Need new codes?"}),el("p",{className:"muted",textContent:"Generating new codes invalidates all previous recovery codes."}),button("Regenerate recovery codes","secondary"));
 regen.addEventListener("submit",async e=>{e.preventDefault();try{const r=await api("/api/mfa/recovery-regenerate","POST",{});state.codes=r.recoveryCodes;logMock("Regenerated recovery codes",r.recoveryCodes.join(", "));state.screen="recovery";render();}catch(e){state.error=e.message;render();}});
 const logout=el("form");logout.append(button("Log out","danger"));logout.addEventListener("submit",async e=>{e.preventDefault();try{await api("/api/logout","POST",{});}finally{state.csrf="";state.provision=null;state.codes=[];state.screen="signin";state.message="You have been logged out.";render();}});
 s.append(...banner(),use,regen,logout);app.append(s);
}
render();
})();
</script>
</body>
</html>`;

async function route(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (request.headers.get("x-forwarded-proto") === "http") return genericError(request, 400);
  if (request.method === "OPTIONS") {
    if (!localOriginAllowed(request.headers.get("origin"))) return genericError(request, 403);
    return new Response(null, { status: 204, headers: headersFor(request) });
  }
  if (url.pathname === "/" && request.method === "GET") {
    return new Response(page, { headers: htmlHeaders(request) });
  }

  if (url.pathname === "/api/signin" && request.method === "POST") {
    const data = await body(request);
    if (!data || !isValidEmail(data.email) || !isValidPhone(data.phone) || typeof data.password !== "string" || data.password.length > 128) return genericError(request);
    // Generic response prevents account enumeration; this fixed account is the academic mock.
    if (data.email !== account.email || data.phone !== account.phone || data.password !== "Marcus!2025") return genericError(request, 401);
    const id = randomToken();
    const code = randomDigits(6);
    pendingIdentities.set(id, { accountId: account.id, codeHash: hash(code), expiresAt: now() + CHALLENGE_MS, attempts: 0, lockedUntil: 0, used: false });
    return json(request, { ok: true, mockCode: code }, 200, { "Set-Cookie": pendingCookie(id) });
  }

  if (url.pathname === "/api/verify-identity" && request.method === "POST") {
    const data = await body(request);
    const pendingId = parseCookies(request).preauth;
    const pending = pendingId ? pendingIdentities.get(pendingId) : undefined;
    if (!data || !isOtp(data.code) || !pending || pending.accountId !== account.id || pending.used || pending.expiresAt < now() || pending.lockedUntil > now()) return genericError(request, 401);
    if (hash(data.code) !== pending.codeHash) {
      pending.attempts++;
      if (pending.attempts >= MAX_ATTEMPTS) pending.lockedUntil = now() + LOCK_MS;
      return genericError(request, 401);
    }
    pending.used = true;
    pendingIdentities.delete(pendingId);
    // Requirement 5: new authenticated session ID prevents fixation.
    const sid = randomToken();
    const csrf = randomToken();
    sessions.set(sid, { accountId: account.id, csrf, createdAt: now(), lastSeen: now() });
    return json(request, { ok: true, csrf }, 200, { "Set-Cookie": `${sessionCookie(sid)}, ${clearCookie("preauth")}` });
  }

  if (url.pathname === "/api/mfa/status" && request.method === "GET") {
    const auth = authorizedMfa(request);
    if (!auth) return genericError(request, 401);
    return json(request, { ok: true, enabled: account.mfaEnabled, email: account.email });
  }

  if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
    const auth = authorizedMfa(request, true);
    if (!auth) return genericError(request, 403);
    const secret = randomToken(20);
    // Deterministic mock OTP is deliberately provided only to the authenticated UI/browser log.
    const mockOtp = "246810";
    provisions.set(auth.id, {
      secretEncrypted: await encryptAtRest(secret),
      expectedOtpHash: hash(mockOtp),
      expiresAt: now() + CHALLENGE_MS,
      attempts: 0,
      lockedUntil: 0,
      used: false,
    });
    const issuer = "NorthstarBank";
    const provisioningUri = `otpauth://totp/${issuer}:Marcus?secret=${secret}&issuer=${issuer}`;
    return json(request, { ok: true, manualSecret: secret, provisioningUri, mockOtp });
  }

  if (url.pathname === "/api/mfa/verify-enrollment" && request.method === "POST") {
    const auth = authorizedMfa(request, true);
    const data = await body(request);
    const provision = auth ? provisions.get(auth.id) : undefined;
    if (!auth || !data || !isOtp(data.otp) || !provision || provision.used || provision.expiresAt < now() || provision.lockedUntil > now()) return genericError(request, 403);
    if (hash(data.otp) !== provision.expectedOtpHash) {
      provision.attempts++;
      if (provision.attempts >= MAX_ATTEMPTS) provision.lockedUntil = now() + LOCK_MS;
      return genericError(request, 401);
    }
    provision.used = true;
    provisions.delete(auth.id);
    account.authenticatorSecretEncrypted = provision.secretEncrypted;
    account.mfaEnabled = true;
    const codes = Array.from({ length: 8 }, randomRecoveryCode);
    account.recoveryCodeHashes = await Promise.all(codes.map(strongHash));
    return json(request, { ok: true, recoveryCodes: codes });
  }

  if (url.pathname === "/api/mfa/recovery-use" && request.method === "POST") {
    const auth = authorizedMfa(request, true);
    const data = await body(request);
    if (!auth || !data || !isRecovery(data.recoveryCode) || !account.mfaEnabled) return genericError(request, 403);
    let matched = -1;
    for (let i = 0; i < account.recoveryCodeHashes.length; i++) {
      if (await strongVerify(data.recoveryCode, account.recoveryCodeHashes[i])) { matched = i; break; }
    }
    if (matched < 0) return genericError(request, 401);
    // Requirement 5: recovery verification is single-use.
    account.recoveryCodeHashes.splice(matched, 1);
    return json(request, { ok: true });
  }

  if (url.pathname === "/api/mfa/recovery-regenerate" && request.method === "POST") {
    const auth = authorizedMfa(request, true);
    if (!auth || !account.mfaEnabled) return genericError(request, 403);
    const codes = Array.from({ length: 8 }, randomRecoveryCode);
    account.recoveryCodeHashes = await Promise.all(codes.map(strongHash));
    return json(request, { ok: true, recoveryCodes: codes });
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const auth = authorizedMfa(request, true);
    if (!auth) return genericError(request, 403);
    sessions.delete(auth.id);
    provisions.delete(auth.id);
    return json(request, { ok: true }, 200, { "Set-Cookie": clearCookie("sid") });
  }

  return genericError(request, 404);
}

/* Requirement 2/3: Bun HTTPS server uses the supplied mkcert files; no HTTP listener exists. */
Bun.serve({
  port: PORT,
  tls: {
    cert: Bun.file("certs/cert.pem"),
    key: Bun.file("certs/key.pem"),
  },
  async fetch(request) {
    try {
      return await route(request);
    } catch {
      // Production-safe generic response; never expose stack traces or sensitive state.
      return genericError(request, 500);
    }
  },
});

console.log(`MFA enrolment server listening securely at https://localhost:${PORT}`);
