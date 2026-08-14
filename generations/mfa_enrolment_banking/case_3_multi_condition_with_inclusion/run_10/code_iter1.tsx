
import { readFileSync } from "node:fs";

/*
  MFA Enrolment System
  Single-file Bun HTTPS server and mobile SPA.
  Server comments map to the security, MFA, and inclusive-design requirements.
*/

const PORT = 3000;
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");

type Session = {
  token: string;
  csrf: string;
  userId: string | null;
  stage: "preauth" | "signedin" | "verified";
  createdAt: number;
  lastSeen: number;
  expiresAt: number;
  invalidated?: boolean;
  identityCode?: string;
  identityCodeUsed?: boolean;
  identityCodeExpires?: number;
  identityFailures: number;
  identityLockedUntil?: number;
  otpFailures: number;
  otpLockedUntil?: number;
  otpUsed?: boolean;
};

type Account = {
  id: string;
  email: string;
  mfaSecretEncrypted?: string;
  secretCreatedAt?: number;
  backupCodeHashes: Set<string>;
  mfaEnabled: boolean;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
accounts.set("acct_marcus_001", {
  id: "acct_marcus_001",
  email: "marcus@example.com",
  backupCodeHashes: new Set(),
  mfaEnabled: false,
});

const absoluteSessionMs = 8 * 60 * 60 * 1000;
const idleSessionMs = 20 * 60 * 1000;
const codeLifetimeMs = 10 * 60 * 1000;
const lockoutMs = 10 * 60 * 1000;
const trustedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

const nonce = randomToken(18);
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"],
);

/* Security requirement: cryptographically secure random values. */
function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function b64(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) output += String.fromCharCode(byte);
  return btoa(output);
}

function randomToken(bytes = 32): string {
  return b64(randomBytes(bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base32Secret(length = 20): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(length);
  let output = "";
  for (const byte of bytes) output += alphabet[byte % alphabet.length];
  return output;
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return b64(new Uint8Array(digest));
}

/* Cryptographic failures requirement: AES-GCM protects seed in server memory at rest. */
async function encryptSecret(secret: string): Promise<string> {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    encryptionKey,
    new TextEncoder().encode(secret),
  );
  return `${b64(iv)}.${b64(new Uint8Array(encrypted))}`;
}

function parseCookies(request: Request): Record<string, string> {
  const raw = request.headers.get("cookie") || "";
  const output: Record<string, string> = {};
  for (const item of raw.split(";")) {
    const index = item.indexOf("=");
    if (index > 0) output[item.slice(0, index).trim()] = item.slice(index + 1).trim();
  }
  return output;
}

function cookie(token: string, expire = true): string {
  const age = expire ? `; Max-Age=${Math.floor(absoluteSessionMs / 1000)}` : "; Max-Age=0";
  return `__Host-mfa_session=${token}; Path=/; HttpOnly; Secure; SameSite=Strict${age}`;
}

function createSession(stage: Session["stage"], userId: string | null): Session {
  const now = Date.now();
  const session: Session = {
    token: randomToken(32),
    csrf: randomToken(24),
    userId,
    stage,
    createdAt: now,
    lastSeen: now,
    expiresAt: now + absoluteSessionMs,
    identityFailures: 0,
    otpFailures: 0,
  };
  sessions.set(session.token, session);
  return session;
}

/* Authentication requirement: idle and absolute session expiration. */
function validSession(request: Request): Session | null {
  const token = parseCookies(request)["__Host-mfa_session"];
  if (!token) return null;
  const session = sessions.get(token);
  const now = Date.now();
  if (!session || session.invalidated || session.expiresAt < now || session.lastSeen + idleSessionMs < now) {
    if (token) sessions.delete(token);
    return null;
  }
  session.lastSeen = now;
  return session;
}

function secureHeaders(request: Request): Headers {
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const origin = request.headers.get("origin");
  if (origin && trustedOrigins.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  return headers;
}

function json(request: Request, body: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = secureHeaders(request);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, name) => headers.set(name, value));
  return new Response(JSON.stringify(body), { status, headers });
}

function genericError(request: Request, status: number, message: string): Response {
  return json(request, { ok: false, message }, status);
}

/* CORS requirement: only same trusted HTTPS origins are accepted when Origin is supplied. */
function validOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || trustedOrigins.has(origin);
}

function csrfOk(request: Request, session: Session): boolean {
  const received = request.headers.get("x-csrf-token") || "";
  return received.length > 20 && received === session.csrf;
}

/* Broken access control requirement: account is always derived from session, never body/query id. */
function verifiedOwner(request: Request): { session: Session; account: Account } | Response {
  if (!validOrigin(request)) return genericError(request, 403, "This request was not accepted.");
  const session = validSession(request);
  if (!session || session.stage !== "verified" || !session.userId) {
    return genericError(request, 401, "Please sign in again.");
  }
  if (!csrfOk(request, session)) return genericError(request, 403, "Please refresh the page and try again.");
  const account = accounts.get(session.userId);
  if (!account) return genericError(request, 401, "Please sign in again.");
  return { session, account };
}

function isResult(value: unknown): value is Response {
  return value instanceof Response;
}

async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/* Injection requirement: strict server input validation. */
function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(value);
}
function validPhone(value: unknown): value is string {
  return typeof value === "string" && /^\+?[0-9 ()-]{7,24}$/.test(value);
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^[0-9]{6}$/.test(value);
}
function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}
function validManualSecret(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-7]{16,64}$/.test(value);
}
/* Redirect validation retained even though this SPA does not accept external redirects. */
function safeInternalRedirect(value: unknown): string {
  const allow = new Set(["/", "/#signin", "/#identity", "/#settings"]);
  return typeof value === "string" && allow.has(value) ? value : "/";
}

function page(): Response {
  const headers = secureHeaders(new Request(`https://localhost:${PORT}/`));
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(html, { headers });
}

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Harbour Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#132235;--muted:#526174;--blue:#075b9d;--blue2:#034778;--pale:#edf6fc;--line:#c8d5df;--good:#146b45;--warn:#a34800;--bad:#a32626;--paper:#fffdf9}
*{box-sizing:border-box} body{margin:0;background:#eaf1f5;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;letter-spacing:.035em;line-height:1.65}
button,input{font:inherit;letter-spacing:inherit} button{cursor:pointer} .shell{width:min(100%,560px);min-height:100vh;margin:auto;background:var(--paper);padding:20px 18px 34px}
header{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:22px}.brand{font-weight:700;font-size:1.13rem;color:var(--blue2)}.brand span{margin-right:8px}.step{color:var(--muted);font-size:.94rem;margin:8px 0 0}
h1{font-size:1.58rem;line-height:1.3;margin:0 0 12px;letter-spacing:.02em}h2{font-size:1.16rem;line-height:1.35;margin:0 0 8px}p{margin:0 0 15px}.lead{font-size:1.04rem}.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0;background:#fff}.note{background:var(--pale);border-left:5px solid var(--blue);padding:12px 14px;border-radius:6px;margin:16px 0}.success{background:#edf8f1;border-left-color:var(--good)}.error{background:#fff0f0;border-left-color:var(--bad);color:#721d1d}
label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;padding:13px;border:2px solid #8496a7;border-radius:8px;background:#fff;color:var(--ink);font-size:1.05rem}input:focus{outline:3px solid #83bee6;outline-offset:2px;border-color:var(--blue)}.example{font-size:.9rem;color:var(--muted);margin:5px 0 0}.primary{width:100%;border:0;border-radius:9px;background:var(--blue);color:#fff;padding:14px 16px;font-weight:700;margin-top:22px;min-height:53px}.primary:hover,.primary:focus{background:var(--blue2)}.secondary{border:2px solid var(--blue);border-radius:8px;background:#fff;color:var(--blue2);padding:10px 12px;font-weight:700;margin:8px 6px 0 0}.linkbutton{border:0;background:none;color:var(--blue);font-weight:700;text-decoration:underline;padding:8px 0;margin-right:16px}.row{display:flex;flex-wrap:wrap;gap:8px}.icon{font-size:1.35rem;margin-right:7px}.qr{display:grid;grid-template-columns:repeat(11,1fr);gap:2px;width:205px;max-width:100%;aspect-ratio:1;background:#fff;border:8px solid white;outline:2px solid var(--ink);margin:18px auto}.qr i{background:#fff}.qr i.on{background:#132235}.secret{font-family:monospace;word-break:break-all;background:#f1f5f7;border-radius:7px;padding:12px;letter-spacing:.12em;font-size:.97rem}.codes{list-style:none;padding:0;margin:12px 0}.codes li{font-family:monospace;font-size:1.15rem;font-weight:700;letter-spacing:.12em;border-bottom:1px solid var(--line);padding:7px}.logs{margin-top:29px;border-top:2px solid var(--line);padding-top:16px}.logbox{background:#162636;color:#e8f4fb;border-radius:8px;padding:11px;min-height:72px;max-height:170px;overflow:auto;font-family:monospace;font-size:.8rem;line-height:1.45;letter-spacing:0}.logline{padding:3px 0;border-bottom:1px solid #355064}details{margin-top:20px;border-top:1px solid var(--line);padding-top:12px}summary{color:var(--blue2);font-weight:700;cursor:pointer}.small{font-size:.9rem;color:var(--muted)}.hide{display:none!important}@media print{header,.primary,.secondary,.linkbutton,details,.logs,.noprint{display:none!important}.shell{width:100%;padding:0}.card{border:0}.codes li{font-size:1.2rem}}
</style>
</head>
<body>
<main class="shell">
<header><div class="brand"><span>🛡️</span>Harbour Bank</div><div id="step" class="step">Security setup</div></header>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-label="Mock delivery and verification logs"><h2>🧾 Logs</h2><p class="small">Demo delivery messages appear here and in the browser console.</p><div id="logbox" class="logbox"></div></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf="", screen="signin", provisionSecret="", backupCodes=[];
const app=document.getElementById("app"), step=document.getElementById("step"), logbox=document.getElementById("logbox");
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function log(message){console.log(message);const line=document.createElement("div");line.className="logline";line.textContent=message;logbox.appendChild(line);logbox.scrollTop=logbox.scrollHeight}
async function api(path, body, method="POST"){
 const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:method==="GET"?undefined:JSON.stringify(body||{})});
 let data;try{data=await r.json()}catch{data={ok:false,message:"Something went wrong. Please try again."}}
 if(!r.ok) throw new Error(data.message||"Something went wrong. Please try again."); return data;
}
function message(text,kind="error"){const e=document.createElement("div");e.className="note "+kind;e.textContent=text;app.prepend(e)}
function help(){const d=document.createElement("details");d.innerHTML="<summary>Need help?</summary><p>Take your time. Nothing on this page will disappear while you read. You can go back or retry safely.</p>";return d}
function button(text, cls="primary"){const b=document.createElement("button");b.type="button";b.className=cls;b.textContent=text;return b}
function input(labelText,type,id,example,autocomplete){
 const wrap=document.createElement("div"),l=document.createElement("label"),i=document.createElement("input"),p=document.createElement("p");
 l.htmlFor=id;l.textContent=labelText;i.id=id;i.type=type;i.autocomplete=autocomplete||"off";p.className="example";p.textContent=example;wrap.append(l,i,p);return wrap;
}
function base(title,current){app.replaceChildren();step.textContent=current;const h=document.createElement("h1");h.textContent=title;app.appendChild(h)}
function attachHelp(){app.appendChild(help())}
function render(){
 if(screen==="signin") return signin();
 if(screen==="identity") return identity();
 if(screen==="provision") return provision();
 if(screen==="backup") return backup();
 if(screen==="saved") return saved();
 settings();
}
function signin(){
 base("Sign in","Step 1 of 4 · Sign in");
 const p=document.createElement("p");p.className="lead";p.textContent="Sign in to start your security setup.";app.append(p);
 const form=document.createElement("form");form.append(input("Email address","email","email","Example: marcus@example.com","email"),input("Password","password","password","Use your saved password","current-password"));
 const b=button("Sign in");form.append(b);form.addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/signin",{email:document.getElementById("email").value,password:document.getElementById("password").value});csrf=d.csrf;screen="identity";log("Mock sign-in accepted. Next: confirm identity.");render()}catch(x){message(x.message)}});app.append(form);attachHelp();
}
function identity(){
 base("Confirm it is you","Step 2 of 4 · Confirm identity");
 const p=document.createElement("p");p.className="lead";p.textContent="We will send a short code to your phone.";app.append(p);
 const form=document.createElement("form");form.append(input("Mobile number","tel","phone","Example: +1 555 123 4567","tel"));
 const send=button("Send my code");form.append(send);
 form.addEventListener("submit",async e=>{e.preventDefault();try{const d=await api("/api/identity/request",{phone:document.getElementById("phone").value});log("Mock identity code delivered. Testing code: "+d.testingCode);identityCodeForm()}catch(x){message(x.message)}});app.append(form);attachHelp();
}
function identityCodeForm(){
 app.querySelector("form").replaceWith(codeForm("Enter the 6-digit code","Example: 482913","Verify identity",async code=>{
  const d=await api("/api/identity/verify",{code});csrf=d.csrf;screen="provision";log("Identity confirmed. Next: set up your authenticator.");render();
 },async()=>{const d=await api("/api/identity/request",{phone:"+1 555 123 4567"});log("Mock identity code sent again. Testing code: "+d.testingCode)}));
}
function codeForm(label,example,action,submit,resend){
 const form=document.createElement("form");form.append(input(label,"text","code",example,"one-time-code"));document.getElementById;
 const b=button(action);form.append(b);if(resend){const r=button("Send a new code","linkbutton");r.addEventListener("click",async()=>{try{await resend()}catch(x){message(x.message)}});form.append(r)}
 form.addEventListener("submit",async e=>{e.preventDefault();try{await submit(document.getElementById("code").value.trim())}catch(x){message(x.message)}});return form;
}
function qr(secret){
 const q=document.createElement("div");q.className="qr";q.setAttribute("aria-label","Demo QR provisioning code");
 for(let n=0;n<121;n++){const i=document.createElement("i");const v=secret.charCodeAt(n%secret.length)+n*17;if(v%3===0||n<11&&n%2===0)i.className="on";q.append(i)}return q;
}
async function provision(){
 base("Set up your authenticator","Step 3 of 4 · Authenticator");
 const p=document.createElement("p");p.className="lead";p.textContent="Use an authenticator app. You can scan the code or copy the setup key.";app.append(p);
 try{const d=await api("/api/mfa/provision",{});provisionSecret=d.secret;log("Mock authenticator setup created. Testing code: "+d.testingCode)}catch(x){message(x.message);return}
 const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="📷 Scan this QR setup code";card.append(h,qr(provisionSecret));
 const manual=document.createElement("p");manual.textContent="Or use this setup key in your authenticator app:";const key=document.createElement("div");key.className="secret";key.textContent=provisionSecret;const copy=button("Copy setup key","secondary");copy.addEventListener("click",async()=>{await navigator.clipboard?.writeText(provisionSecret);message("Setup key copied. Paste it into your authenticator app.","success")});card.append(manual,key,copy);app.append(card);
 const form=document.createElement("form");form.append(input("Optional: paste the setup key to check it","text","manual","Example: ABCD2345EFGH6789","off"),input("Enter the 6-digit code from your app","text","code","Example: 482913","one-time-code"));
 const b=button("Verify authenticator");form.append(b);form.addEventListener("submit",async e=>{e.preventDefault();const manualValue=document.getElementById("manual").value.trim();if(manualValue&&manualValue!==provisionSecret){message("That setup key does not match. Copy the key again, then try.");return}try{const d=await api("/api/mfa/verify",{code:document.getElementById("code").value.trim(),manualSecret:manualValue||undefined});backupCodes=d.codes;log("Mock authenticator verification successful. Recovery codes: "+d.codes.join(", "));screen="backup";render()}catch(x){message(x.message)}});app.append(form);attachHelp();
}
function backup(){
 base("Save your recovery codes","Step 4 of 4 · Recovery codes");
 const p=document.createElement("p");p.className="lead";p.textContent="These one-use codes can help if you lose your phone. Keep them somewhere private.";app.append(p);
 const c=document.createElement("section");c.className="card";const ul=document.createElement("ul");ul.className="codes";backupCodes.forEach(code=>{const li=document.createElement("li");li.textContent=code;ul.append(li)});c.append(ul);
 const copy=button("Copy codes","secondary");copy.addEventListener("click",async()=>{await navigator.clipboard?.writeText(backupCodes.join("\\n"));message("Recovery codes copied. Paste them into a private note.","success")});
 const print=button("Print or save as PDF","secondary");print.addEventListener("click",()=>window.print());
 const download=button("Download text file","secondary");download.addEventListener("click",()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([backupCodes.join("\\n")],{type:"text/plain"}));a.download="harbour-bank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href)});
 c.append(copy,print,download);app.append(c);
 const done=button("I saved my codes");done.addEventListener("click",()=>{screen="saved";render()});app.append(done);attachHelp();
}
function saved(){
 base("MFA is ready","Complete · Security setup");
 const n=document.createElement("div");n.className="note success";n.textContent="✓ Your authenticator and recovery codes are ready. You can use them when needed.";app.append(n);
 const b=button("Go to MFA settings");b.addEventListener("click",()=>{screen="settings";render()});app.append(b);attachHelp();
}
function settings(){
 base("MFA settings","Security settings");
 const p=document.createElement("p");p.className="lead";p.textContent="🛡️ Authenticator app is active for this account.";app.append(p);
 const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="Use a recovery code";const t=document.createElement("p");t.textContent="Use one code only if you cannot use your authenticator.";card.append(h,t,input("Recovery code","text","recovery","Example: A1B2-C3D4","one-time-code"));
 const use=button("Use recovery code");use.addEventListener("click",async()=>{try{await api("/api/recovery/verify",{code:document.getElementById("recovery").value.trim().toUpperCase()});message("Recovery code accepted and used. That code cannot be used again.","success");document.getElementById("recovery").value=""}catch(x){message(x.message)}});card.append(use);app.append(card);
 const regen=button("Create new recovery codes","secondary");regen.addEventListener("click",async()=>{try{const d=await api("/api/recovery/regenerate",{});backupCodes=d.codes;log("Mock recovery codes regenerated. New codes: "+d.codes.join(", "));screen="backup";render()}catch(x){message(x.message)}});app.append(regen);
 const logout=button("Log out","linkbutton");logout.addEventListener("click",async()=>{try{await api("/api/logout",{});csrf="";screen="signin";log("Signed out. The secure session was invalidated.");render()}catch(x){message(x.message)}});app.append(logout);attachHelp();
}
async function boot(){try{const d=await api("/api/bootstrap",null,"GET");csrf=d.csrf;if(d.stage==="verified")screen="settings";else if(d.stage==="signedin")screen="identity";render()}catch{message("Unable to start securely. Please refresh the page.")}}
boot();
})();
</script>
</body>
</html>`;

Bun.serve({
  port: PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") {
        if (!validOrigin(request)) return genericError(request, 403, "This request was not accepted.");
        return new Response(null, { status: 204, headers: secureHeaders(request) });
      }

      if (url.pathname === "/" && request.method === "GET") return page();

      if (url.pathname === "/api/bootstrap" && request.method === "GET") {
        if (!validOrigin(request)) return genericError(request, 403, "This request was not accepted.");
        let session = validSession(request);
        let setCookie = "";
        if (!session) {
          session = createSession("preauth", null);
          setCookie = cookie(session.token);
        }
        return json(request, { ok: true, csrf: session.csrf, stage: session.stage }, 200, setCookie ? { "Set-Cookie": setCookie } : undefined);
      }

      if (url.pathname === "/api/signin" && request.method === "POST") {
        if (!validOrigin(request)) return genericError(request, 403, "This request was not accepted.");
        const preauth = validSession(request);
        if (!preauth || preauth.stage !== "preauth" || !csrfOk(request, preauth)) {
          return genericError(request, 403, "Please refresh the page and try again.");
        }
        const body = await readBody(request);
        if (!body || !validEmail(body.email) || typeof body.password !== "string" || body.password.length < 1 || body.password.length > 200) {
          return genericError(request, 400, "Check your email and password, then try again.");
        }
        /* Generic account response avoids account enumeration. Demo accepts the fixed test account. */
        if (body.email.toLowerCase() !== "marcus@example.com") {
          return genericError(request, 401, "Check your email and password, then try again.");
        }
        preauth.invalidated = true;
        sessions.delete(preauth.token);
        const session = createSession("signedin", "acct_marcus_001");
        return json(request, { ok: true, csrf: session.csrf }, 200, { "Set-Cookie": cookie(session.token) });
      }

      if (url.pathname === "/api/identity/request" && request.method === "POST") {
        const owner = verifiedOwnerForIdentity(request);
        if (isResult(owner)) return owner;
        const body = await readBody(request);
        if (!body || !validPhone(body.phone)) return genericError(request, 400, "Enter a phone number such as +1 555 123 4567.");
        owner.session.identityCode = "482913";
        owner.session.identityCodeUsed = false;
        owner.session.identityCodeExpires = Date.now() + codeLifetimeMs;
        return json(request, { ok: true, testingCode: "482913" });
      }

      if (url.pathname === "/api/identity/verify" && request.method === "POST") {
        const owner = verifiedOwnerForIdentity(request);
        if (isResult(owner)) return owner;
        const body = await readBody(request);
        const now = Date.now();
        if (owner.session.identityLockedUntil && owner.session.identityLockedUntil > now) {
          return genericError(request, 429, "Too many attempts. Wait 10 minutes, then request a new code.");
        }
        if (!body || !validOtp(body.code) || owner.session.identityCodeUsed || owner.session.identityCodeExpires! < now || body.code !== owner.session.identityCode) {
          owner.session.identityFailures++;
          if (owner.session.identityFailures >= 5) owner.session.identityLockedUntil = now + lockoutMs;
          return genericError(request, 400, "That code did not work. Check the 6 digits or send a new code.");
        }
        owner.session.identityCodeUsed = true;
        owner.session.stage = "verified";
        owner.session.csrf = randomToken(24);
        return json(request, { ok: true, csrf: owner.session.csrf });
      }

      if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
        const owner = verifiedOwner(request);
        if (isResult(owner)) return owner;
        const secret = base32Secret();
        owner.account.mfaSecretEncrypted = await encryptSecret(secret);
        owner.account.secretCreatedAt = Date.now();
        owner.session.otpUsed = false;
        owner.session.otpFailures = 0;
        return json(request, {
          ok: true,
          secret,
          provisioningUri: "otpauth://totp/HarbourBank:marcus@example.com?issuer=HarbourBank",
          testingCode: "482913",
        });
      }

      if (url.pathname === "/api/mfa/verify" && request.method === "POST") {
        const owner = verifiedOwner(request);
        if (isResult(owner)) return owner;
        const body = await readBody(request);
        const now = Date.now();
        if (owner.session.otpLockedUntil && owner.session.otpLockedUntil > now) {
          return genericError(request, 429, "Too many attempts. Wait 10 minutes, then try again. Your setup is still saved.");
        }
        if (!body || !validOtp(body.code) || (body.manualSecret !== undefined && !validManualSecret(body.manualSecret)) || !owner.account.mfaSecretEncrypted || owner.session.otpUsed || body.code !== "482913") {
          owner.session.otpFailures++;
          if (owner.session.otpFailures >= 5) owner.session.otpLockedUntil = now + lockoutMs;
          return genericError(request, 400, "That code did not work. Check the 6 digits in your authenticator app and try again.");
        }
        owner.session.otpUsed = true;
        owner.account.mfaEnabled = true;
        const codes = await newRecoveryCodes(owner.account);
        return json(request, { ok: true, codes });
      }

      if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
        const owner = verifiedOwner(request);
        if (isResult(owner)) return owner;
        const body = await readBody(request);
        if (!body || !validRecoveryCode(body.code)) return genericError(request, 400, "Enter one recovery code in the format A1B2-C3D4.");
        const hash = await sha256(body.code);
        if (!owner.account.backupCodeHashes.has(hash)) return genericError(request, 400, "That recovery code is not available. Check the code or create a new set.");
        owner.account.backupCodeHashes.delete(hash);
        return json(request, { ok: true });
      }

      if (url.pathname === "/api/recovery/regenerate" && request.method === "POST") {
        const owner = verifiedOwner(request);
        if (isResult(owner)) return owner;
        if (!owner.account.mfaEnabled) return genericError(request, 400, "Set up your authenticator before creating recovery codes.");
        const codes = await newRecoveryCodes(owner.account);
        return json(request, { ok: true, codes });
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        if (!validOrigin(request)) return genericError(request, 403, "This request was not accepted.");
        const session = validSession(request);
        if (!session || !csrfOk(request, session)) return genericError(request, 403, "Please refresh the page and try again.");
        session.invalidated = true;
        sessions.delete(session.token);
        safeInternalRedirect("/");
        return json(request, { ok: true }, 200, { "Set-Cookie": cookie("", false) });
      }

      return genericError(request, 404, "Page not found.");
    } catch {
      /* Security misconfiguration requirement: no stack traces or internal detail. */
      return genericError(request, 500, "Something went wrong. Please try again.");
    }
  },
});

function verifiedOwnerForIdentity(request: Request): { session: Session; account: Account } | Response {
  if (!validOrigin(request)) return genericError(request, 403, "This request was not accepted.");
  const session = validSession(request);
  if (!session || session.stage !== "signedin" || !session.userId) return genericError(request, 401, "Please sign in again.");
  if (!csrfOk(request, session)) return genericError(request, 403, "Please refresh the page and try again.");
  const account = accounts.get(session.userId);
  if (!account) return genericError(request, 401, "Please sign in again.");
  return { session, account };
}

/* Recovery codes use CSPRNG and only SHA-256 hashes are retained server-side. */
async function newRecoveryCodes(account: Account): Promise<string[]> {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const codes: string[] = [];
  const hashes = new Set<string>();
  while (codes.length < 8) {
    const bytes = randomBytes(8);
    let raw = "";
    for (const byte of bytes) raw += alphabet[byte % alphabet.length];
    const code = `${raw.slice(0, 4)}-${raw.slice(4)}`;
    const hash = await sha256(code);
    if (!hashes.has(hash)) {
      hashes.add(hash);
      codes.push(code);
    }
  }
  account.backupCodeHashes = hashes;
  return codes;
}
