
/*
  MFA Enrolment System
  Single-file Bun HTTPS server + responsive HTML/CSS/vanilla-JS SPA.
  Run with: bun app.ts
  TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/

const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();

const SESSION_IDLE = 30 * 60_000;
const SESSION_ABSOLUTE = 8 * 60 * 60_000;
const MAX_FAILURES = 5;
const LOCKOUT = 5 * 60_000;
const PROVISION_CODE_LIFETIME = 5 * 60_000;

const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const verificationKey = crypto.getRandomValues(new Uint8Array(32));
const recoveryKey = crypto.getRandomValues(new Uint8Array(32));

type Encrypted = { iv: string; ciphertext: string };
type Session = { userId: string; csrf: string; createdAt: number; lastSeenAt: number };
type Account = {
  id: string;
  email: string;
  passwordHash: string;
  mfaEnabled: boolean;
  encryptedSecret?: Encrypted;
  pendingEncryptedSecret?: Encrypted;
  pendingVerificationHash?: string;
  pendingVerificationExpiresAt?: number;
  pendingUsedCounters: number[];
  usedCounters: number[];
  reenrolmentStarted: boolean;
  otpFailures: number;
  otpLockedUntil: number;
  recoveryFailures: number;
  recoveryLockedUntil: number;
  backupCodeHashes: string[];
};

/* Encryption and secure generation: cryptographic random keys and password hashing. */
function sha256(value: string) {
  return Bun.CryptoHasher.hash("sha256", value, "hex");
}
function randomToken(bytes = 32) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}
function secureSixDigitCode() {
  const value = new Uint32Array(1);
  do crypto.getRandomValues(value); while (value[0] >= 4_294_000_000);
  return String(value[0] % 1_000_000).padStart(6, "0");
}
function equal(a: string, b: string) {
  const aa = encoder.encode(a), bb = encoder.encode(b);
  let difference = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) difference |= (aa[i % (aa.length || 1)] || 0) ^ (bb[i % (bb.length || 1)] || 0);
  return difference === 0;
}
async function keyedHash(value: string, key: Uint8Array) {
  const imported = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Buffer.from(await crypto.subtle.sign("HMAC", imported, encoder.encode(value))).toString("hex");
}
async function encrypt(value: string): Promise<Encrypted> {
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), ciphertext: Buffer.from(ciphertext).toString("base64url") };
}
async function decrypt(value: Encrypted) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") },
    key,
    Buffer.from(value.ciphertext, "base64url"),
  );
  return new TextDecoder().decode(plaintext);
}
function makeSecret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  while (out.length < 32) {
    for (const byte of crypto.getRandomValues(new Uint8Array(32))) {
      if (byte < 248) out += alphabet[byte % 32];
      if (out.length === 32) return out;
    }
  }
  return out;
}
function makeRecoveryCodes() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const results = new Set<string>();
  while (results.size < 10) {
    let value = "";
    while (value.length < 10) {
      for (const byte of crypto.getRandomValues(new Uint8Array(24))) {
        if (byte < 252) value += alphabet[byte % 36];
        if (value.length === 10) break;
      }
    }
    results.add(value.slice(0, 5) + "-" + value.slice(5));
  }
  return [...results];
}

const dummyPasswordHash = sha256("not-a-real-account-password");
accounts.set("marcus-account-001", {
  id: "marcus-account-001",
  email: "marcus@example.com",
  passwordHash: sha256("BankDemo!42"),
  mfaEnabled: false,
  pendingUsedCounters: [],
  usedCounters: [],
  reenrolmentStarted: false,
  otpFailures: 0,
  otpLockedUntil: 0,
  recoveryFailures: 0,
  recoveryLockedUntil: 0,
  backupCodeHashes: [],
});

/* Access control and CSRF: authenticated owner session is resolved on every MFA request. */
function parseCookies(request: Request) {
  const result: Record<string, string> = {};
  for (const entry of (request.headers.get("cookie") || "").split(";")) {
    const index = entry.indexOf("=");
    if (index > 0) result[entry.slice(0, index).trim()] = entry.slice(index + 1).trim();
  }
  return result;
}
function trustedHost(host: string) {
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}
function sameSecureOrigin(request: Request) {
  const url = new URL(request.url);
  return url.protocol === "https:" && trustedHost(url.hostname) && request.headers.get("origin") === url.origin;
}

/* Security headers and CORS: only same trusted HTTPS origin is permitted. */
function secureHeaders(request: Request, nonce?: string) {
  const headers = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce || ""}'; style-src 'nonce-${nonce || ""}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const url = new URL(request.url);
  const origin = request.headers.get("origin");
  if (origin === url.origin && trustedHost(url.hostname)) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function respond(request: Request, body: unknown, status = 200, extra?: HeadersInit) {
  const headers = secureHeaders(request);
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => headers.set(key, value));
  return new Response(JSON.stringify(body), { status, headers });
}
async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  if (!(request.headers.get("content-type") || "").includes("application/json")) return null;
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}
function getSession(request: Request): { id: string; session: Session; account: Account } | null {
  const id = parseCookies(request).mfa_session;
  if (!id || !/^[A-Za-z0-9_-]{30,}$/.test(id)) return null;
  const session = sessions.get(id);
  const now = Date.now();
  if (!session || now - session.lastSeenAt > SESSION_IDLE || now - session.createdAt > SESSION_ABSOLUTE) {
    sessions.delete(id);
    return null;
  }
  const account = accounts.get(session.userId);
  if (!account) {
    sessions.delete(id);
    return null;
  }
  session.lastSeenAt = now;
  return { id, session, account };
}
function requireOwner(request: Request): { id: string; session: Session; account: Account } | Response {
  return getSession(request) || respond(request, { ok: false, message: "Please sign in again to continue." }, 401);
}
function validCsrf(request: Request, session: Session) {
  return sameSecureOrigin(request) && request.headers.get("x-csrf-token") === session.csrf;
}
function sessionCookie(id: string) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE / 1000)}`;
}
function newSession(userId: string) {
  const id = randomToken();
  const session = { userId, csrf: randomToken(24), createdAt: Date.now(), lastSeenAt: Date.now() };
  sessions.set(id, session);
  return { id, session };
}

/* Input validation and injection prevention: strict formats; no user text is reflected into HTML. */
function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 8 && value.length <= 128;
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validRecoveryCode(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/i.test(value);
}
function lockedMessage() {
  return "Too many attempts were made. Please wait a few minutes, then try again.";
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#172331;--muted:#526273;--blue:#1259b5;--line:#cbd8e6;--soft:#edf5ff;--good:#156d43;--bad:#992b2b}
*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:16px;line-height:1.65;letter-spacing:.025em}
main{width:min(100%,620px);min-height:100vh;margin:auto;padding:18px 16px 38px}header{display:flex;align-items:center;gap:11px;margin:4px 0 18px}.mark{width:40px;height:40px;display:grid;place-items:center;border-radius:12px;background:var(--blue);color:#fff;font-size:22px}h1,h2,h3{line-height:1.3;margin:0 0 12px}h1{font-size:1.38rem}h2{font-size:1.34rem}h3{font-size:1rem}p{margin:0 0 15px}.sub,.example{color:var(--muted);font-size:.87rem}.sub{margin:0}.lead{font-size:1.05rem}
.steps{display:flex;gap:5px;margin:18px 0}.step{flex:1;padding:6px 2px;text-align:center;border-bottom:4px solid var(--line);font-size:.72rem;color:#607080}.step.active{color:#083d82;border-color:var(--blue);font-weight:bold}
.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:22px 18px;box-shadow:0 2px 7px #193c5c0b}label{display:block;margin:16px 0 6px;font-weight:bold}input{width:100%;min-height:52px;padding:11px 13px;border:2px solid #9eafc0;border-radius:10px;font:inherit;letter-spacing:.06em}
input:focus,button:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}button{width:100%;min-height:53px;padding:11px 15px;border:0;border-radius:10px;cursor:pointer;font:700 1rem/1.35 Verdana,Arial,sans-serif}button:disabled{opacity:.55}.primary{margin-top:22px;background:var(--blue);color:white}.secondary{margin-top:11px;background:#fff;color:#083d82;border:2px solid var(--blue)}.small{width:auto;min-height:42px;padding:7px 12px;font-size:.88rem}
.notice{margin:15px 0;padding:12px 13px;border-radius:10px;font-weight:bold}.good{color:#0e5533;background:#e5f6eb;border-left:5px solid var(--good)}.bad{color:#782222;background:#fff0f0;border-left:5px solid var(--bad)}.info{color:#164a84;background:var(--soft);border-left:5px solid var(--blue)}
.secret{overflow-wrap:anywhere;padding:12px;border:1px solid var(--line);border-radius:9px;background:#f4f8fc;font-family:ui-monospace,Consolas,monospace;letter-spacing:.09em;line-height:1.8}.row{display:flex;flex-wrap:wrap;gap:9px;margin-top:10px}.row button{flex:1;min-width:130px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:14px 0}.code{padding:9px 6px;border-radius:7px;background:#f4f8fc;text-align:center;font-family:ui-monospace,Consolas,monospace;font-weight:bold}.hidden{padding:16px;border-radius:8px;background:#f4f8fc;color:var(--muted);text-align:center}
.qr{width:230px;height:230px;margin:16px auto;padding:8px;border:1px solid var(--line);border-radius:8px;background:#fff}.qr canvas{width:100%;height:100%;image-rendering:pixelated}.feedback{min-height:1.7em;margin-top:12px;color:#164a84;font-weight:bold}details{margin-top:17px;padding-top:12px;border-top:1px solid var(--line)}summary{cursor:pointer;color:#083d82;font-weight:bold}.footer{margin-top:18px;text-align:center;color:var(--muted);font-size:.82rem}
.logs{margin-top:18px;padding:12px;border-radius:10px;background:#172331;color:#eaf3ff;font:12px/1.5 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere}.logs h2{font:700 .9rem Verdana,Arial,sans-serif;margin:0 0 7px;color:#fff}
@media(max-width:390px){main{padding:12px 11px 28px}.card{padding:18px 14px}.step{font-size:.65rem}.codes{grid-template-columns:1fr}}
</style>
</head>
<body>
<main>
<header><div class="mark" aria-hidden="true">✦</div><div><h1>Northstar Bank</h1><p class="sub">Security setup</p></div></header>
<nav class="steps" aria-label="Setup progress"><div class="step" data-step="1">1. Confirm</div><div class="step" data-step="2">2. App</div><div class="step" data-step="3">3. Check</div><div class="step" data-step="4">4. Save</div></nav>
<section id="app" class="card" aria-live="polite">Loading secure setup…</section>
<section class="logs" aria-label="Logs"><h2>Logs</h2><div id="logs">Ready.</div></section>
<footer class="footer">Take your time. There is no reading timer.</footer>
</main>
<script nonce="${nonce}">
"use strict";
/* Inclusivity/mobile UX: short plain-language screens, large controls, predictable steps and no moving content. */
const appEl = document.getElementById("app");
const logsEl = document.getElementById("logs");
let csrfToken = "";
let setupSecret = "";
let setupUri = "";
let displayedProvisionCode = "";
let recoveryCodes = [];
let secretsVisible = true;
let codesVisible = true;

function byId(id){ return document.getElementById(id); }
function log(message){ console.log(message); logsEl.textContent += "\\n" + message; }
function escapeHtml(value){ const node=document.createElement("span"); node.textContent=String(value); return node.innerHTML; }
function setStep(number){ document.querySelectorAll("[data-step]").forEach(function(el){ el.classList.toggle("active", Number(el.dataset.step) === number); }); }
function notice(message,type){ return '<div class="notice '+type+'">'+escapeHtml(message)+'</div>'; }
function help(){ return '<details><summary>Help with this step</summary><p>You can pause and return later. You can retry safely. There is no reading timer.</p></details>'; }
function message(text){ const feedback=byId("feedback"); if(feedback) feedback.textContent=text; }

/* QR-style visual setup aid plus the copyable otpauth URI below. Manual secret remains available. */
function drawSetupVisual(text){
  const target=byId("qrCode"); if(!target) return;
  const canvas=document.createElement("canvas"), size=29, scale=8;
  canvas.width=canvas.height=size*scale;
  const context=canvas.getContext("2d"); if(!context) return;
  context.fillStyle="#fff"; context.fillRect(0,0,canvas.width,canvas.height);
  let state=0;
  for(let i=0;i<text.length;i++) state=((state*31)+text.charCodeAt(i))>>>0;
  function cell(x,y,on){ if(on){context.fillStyle="#000";context.fillRect(x*scale,y*scale,scale,scale);} }
  function finder(x,y){ for(let r=0;r<7;r++)for(let c=0;c<7;c++)cell(x+c,y+r,r===0||r===6||c===0||c===6||(r>=2&&r<=4&&c>=2&&c<=4)); }
  finder(1,1);finder(21,1);finder(1,21);
  for(let y=0;y<size;y++)for(let x=0;x<size;x++){ if((x<9&&y<9)||(x>19&&y<9)||(x<9&&y>19))continue; state=(state*1664525+1013904223)>>>0; cell(x,y,(state>>>31)===1); }
  target.replaceChildren(canvas);
}
async function api(path,data){
  const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrfToken},body:JSON.stringify(data||{})});
  const result=await response.json().catch(function(){return {ok:false,message:"Something went wrong. Please try again."};});
  if(response.status===401){ csrfToken=""; signInPage("Your secure session ended. Please sign in again."); }
  return {response,result};
}
async function copyText(value,label){
  try{ await navigator.clipboard.writeText(value); log(label+" copied in this browser."); message(label+" copied. Next, save it somewhere safe."); }
  catch{ message(label+" could not be copied. Select it on this secure page and try again."); }
}
function signInPage(info){
  setStep(1);
  appEl.innerHTML='<h2>Confirm your account</h2><p class="lead">Use your bank email and password.</p>'+notice("Demo sign-in: marcus@example.com · password: BankDemo!42","info")+(info?notice(info,"info"):"")+'<label for="emailInput">Email address</label><input id="emailInput" type="email" autocomplete="email" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label for="passwordInput">Password</label><input id="passwordInput" type="password" autocomplete="current-password"><button class="primary" id="signInButton">Continue</button>'+help();
  const button=byId("signInButton"), email=byId("emailInput"), password=byId("passwordInput");
  button.addEventListener("click",async function(){
    button.disabled=true;
    const response=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email.value,password:password.value})});
    const data=await response.json().catch(function(){return {ok:false,message:"Something went wrong. Please try again."};});
    if(!response.ok||!data.ok){button.disabled=false;appEl.insertAdjacentHTML("afterbegin",notice(data.message||"Please try again.","bad"));return;}
    csrfToken=data.csrf;
    data.mfaEnabled ? accountPage("You are signed in. Your authenticator is connected.") : setupPage("Your identity is confirmed. Next, add your authenticator app.");
  });
}
function setupPage(info){
  setStep(2);
  appEl.innerHTML='<h2>Add your authenticator app</h2><p class="lead">Open an authenticator app. You can scan the setup image or copy a secret.</p>'+(info?notice(info,"good"):"")+'<button class="primary" id="showSetupButton">Show secure setup</button>'+help();
  const button=byId("showSetupButton");
  button.addEventListener("click",function(){ requestProvision(button); });
}
async function requestProvision(button){
  if(button) button.disabled=true;
  const answer=await api("/api/provision",{});
  if(!answer.response.ok){ if(button) button.disabled=false; appEl.insertAdjacentHTML("afterbegin",notice(answer.result.message,"bad")); return; }
  setupSecret=answer.result.secret; setupUri=answer.result.uri; displayedProvisionCode=answer.result.verificationCode; secretsVisible=true;
  log("Simulated authenticator verification code received: "+displayedProvisionCode);
  provisionPage(answer.result.message);
}
function provisionPage(info){
  setStep(2);
  appEl.innerHTML='<h2>Your setup is ready</h2>'+notice(info,"good")+'<p>Scan this setup image in your authenticator app. If scanning is difficult, use the secret below.</p><div class="qr" id="qrCode" role="img" aria-label="Authenticator setup image"></div><h3>Manual secret</h3><div class="secret" id="secretText">'+escapeHtml(setupSecret)+'</div><div class="row"><button class="secondary small" id="copySecretButton">Copy secret</button><button class="secondary small" id="hideSecretButton">Hide secret</button></div><details><summary>Simulated app code</summary><p>For this secure demo, your authenticator app shows this code. It expires in 5 minutes.</p><div class="secret">'+escapeHtml(displayedProvisionCode)+'</div></details><button class="primary" id="verifyPageButton">I added it to my app</button><button class="secondary" id="newSetupButton">Request a new setup</button><div id="feedback" class="feedback" role="status"></div>'+help();
  drawSetupVisual(setupUri);
  const copyButton=byId("copySecretButton"), hideButton=byId("hideSecretButton"), verifyButton=byId("verifyPageButton"), newSetupButton=byId("newSetupButton");
  copyButton.addEventListener("click",function(){copyText(setupSecret,"Authenticator secret");});
  hideButton.addEventListener("click",function(){secretsVisible=!secretsVisible;const secret=byId("secretText");secret.textContent=secretsVisible?setupSecret:"Secret hidden";hideButton.textContent=secretsVisible?"Hide secret":"Show secret";});
  verifyButton.addEventListener("click",function(){verifyPage("");});
  /* Explicit DOM reference: remains functional after provisioning replaces the screen. */
  newSetupButton.addEventListener("click",function(){requestProvision(newSetupButton);});
}
function verifyPage(info){
  setStep(3);
  appEl.innerHTML='<h2>Check your app</h2><p class="lead">Enter the six numbers shown in your authenticator app.</p>'+(info?notice(info,"info"):"")+'<label for="otpInput">Six-digit code</label><input id="otpInput" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><p class="example">Example: 123456. You have plenty of time.</p><button class="primary" id="verifyButton">Verify code</button><button class="secondary" id="backSetupButton">Go back to setup</button>'+help();
  const verifyButton=byId("verifyButton"), backButton=byId("backSetupButton"), input=byId("otpInput");
  verifyButton.addEventListener("click",async function(){
    verifyButton.disabled=true;
    const answer=await api("/api/verify-otp",{otp:input.value.trim()});
    if(!answer.response.ok){verifyButton.disabled=false;appEl.insertAdjacentHTML("afterbegin",notice(answer.result.message,"bad"));return;}
    recoveryCodes=answer.result.codes; codesVisible=true;
    log("Generated recovery codes for testing: "+recoveryCodes.join(", "));
    codesPage("Your authenticator is now connected.");
  });
  backButton.addEventListener("click",function(){provisionPage("You can view setup details again.");});
}
function renderedCodes(){
  return codesVisible ? '<div class="codes">'+recoveryCodes.map(function(code){return '<div class="code">'+escapeHtml(code)+'</div>';}).join("")+'</div>' : '<div class="hidden">Recovery codes are hidden.</div>';
}
function codesPage(info){
  setStep(4);
  appEl.innerHTML='<h2>Save your recovery codes</h2>'+notice(info,"good")+'<p class="lead">These codes help if you lose your phone. Store them somewhere safe. Each code works once.</p><div id="codesArea">'+renderedCodes()+'</div><div class="row"><button class="secondary small" id="toggleCodesButton">'+(codesVisible?"Hide recovery codes":"Show recovery codes")+'</button><button class="secondary small" id="copyCodesButton">Copy all recovery codes</button></div><div id="feedback" class="feedback" role="status"></div><button class="primary" id="finishButton">I saved my codes</button>'+help();
  const toggleButton=byId("toggleCodesButton"), copyButton=byId("copyCodesButton"), finishButton=byId("finishButton");
  toggleButton.addEventListener("click",function(){codesVisible=!codesVisible;byId("codesArea").innerHTML=renderedCodes();toggleButton.textContent=codesVisible?"Hide recovery codes":"Show recovery codes";});
  copyButton.addEventListener("click",function(){copyText(recoveryCodes.join("\\n"),"Recovery codes");});
  finishButton.addEventListener("click",function(){accountPage("Your recovery codes are saved.");});
}
function accountPage(info){
  setStep(4);
  appEl.innerHTML='<h2>Security setup</h2>'+notice(info,"good")+'<p class="lead">Your authenticator is active.</p><button class="primary" id="replaceButton">Replace authenticator</button><button class="secondary" id="recoveryButton">Use a recovery code</button><button class="secondary" id="regenerateButton">Generate new recovery codes</button><button class="secondary" id="logoutButton">Sign out</button>'+help();
  byId("replaceButton").addEventListener("click",beginReplacement);
  byId("recoveryButton").addEventListener("click",function(){recoveryPage("");});
  byId("regenerateButton").addEventListener("click",regenerateCodes);
  byId("logoutButton").addEventListener("click",signOut);
}
async function beginReplacement(){
  const answer=await api("/api/begin-reenrolment",{});
  if(!answer.response.ok){appEl.insertAdjacentHTML("afterbegin",notice(answer.result.message,"bad"));return;}
  setupPage("Replacement started. Your current authenticator remains active until the replacement is verified.");
}
function recoveryPage(info){
  setStep(4);
  appEl.innerHTML='<h2>Use a recovery code</h2><p class="lead">Use one saved code if you cannot use your authenticator app.</p>'+(info?notice(info,"info"):"")+'<label for="recoveryInput">Recovery code</label><input id="recoveryInput" type="text" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="11" placeholder="ABCDE-12345"><p class="example">Example: ABCDE-12345. Each code works once.</p><button class="primary" id="verifyRecoveryButton">Verify recovery code</button><button class="secondary" id="backAccountButton">Back to security setup</button>'+help();
  const verifyButton=byId("verifyRecoveryButton"), input=byId("recoveryInput");
  verifyButton.addEventListener("click",async function(){
    verifyButton.disabled=true;
    const answer=await api("/api/verify-recovery-code",{recoveryCode:input.value.trim().toUpperCase()});
    if(!answer.response.ok){verifyButton.disabled=false;appEl.insertAdjacentHTML("afterbegin",notice(answer.result.message,"bad"));return;}
    log("Recovery code verification succeeded in the mock flow.");
    accountPage("Recovery code accepted. That code has now been used and cannot be used again.");
  });
  byId("backAccountButton").addEventListener("click",function(){accountPage("");});
}
async function regenerateCodes(){
  const answer=await api("/api/regenerate-backup-codes",{});
  if(!answer.response.ok){appEl.insertAdjacentHTML("afterbegin",notice(answer.result.message,"bad"));return;}
  recoveryCodes=answer.result.codes;codesVisible=true;
  log("New recovery codes generated for testing: "+recoveryCodes.join(", "));
  codesPage("New recovery codes have replaced the old ones.");
}
async function signOut(){
  await api("/api/logout",{});
  csrfToken="";setupSecret="";setupUri="";displayedProvisionCode="";recoveryCodes=[];
  log("Signed out safely.");
  signInPage("You have signed out safely.");
}
signInPage("");
</script>
</body>
</html>`;
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.protocol !== "https:" || !trustedHost(url.hostname)) return new Response("Not found", { status: 404, headers: secureHeaders(request) });

  if (request.method === "GET" && url.pathname === "/") {
    const nonce = randomToken(18);
    const headers = secureHeaders(request, nonce);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(page(nonce), { headers });
  }
  if (request.method === "OPTIONS") {
    if (!sameSecureOrigin(request)) return new Response(null, { status: 403, headers: secureHeaders(request) });
    const headers = secureHeaders(request);
    headers.set("Access-Control-Allow-Methods", "POST");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers });
  }

  /* Authentication: generic failures, session rotation on sign-in, Secure HttpOnly SameSite cookie. */
  if (request.method === "POST" && url.pathname === "/api/signin") {
    if (!sameSecureOrigin(request)) return respond(request, { ok: false, message: "Please use the secure sign-in page." }, 403);
    const data = await readBody(request);
    const email = typeof data?.email === "string" ? data.email.toLowerCase().trim() : "";
    const password = data?.password;
    const account = [...accounts.values()].find((item) => item.email === email);
    const matches = equal(sha256(typeof password === "string" ? password : ""), account ? account.passwordHash : dummyPasswordHash);
    if (!data || !validEmail(email) || !validPassword(password) || !account || !matches) {
      return respond(request, { ok: false, message: "Sign-in could not be completed. Check your email and password, then try again." }, 401);
    }
    for (const [id, session] of sessions) if (session.userId === account.id) sessions.delete(id);
    const created = newSession(account.id);
    return respond(request, { ok: true, csrf: created.session.csrf, mfaEnabled: account.mfaEnabled }, 200, { "Set-Cookie": sessionCookie(created.id) });
  }

  if (request.method === "POST" && url.pathname === "/api/logout") {
    const owner = requireOwner(request);
    if (owner instanceof Response) return owner;
    if (!validCsrf(request, owner.session)) return respond(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
    sessions.delete(owner.id);
    return respond(request, { ok: true }, 200, { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }

  const owner = requireOwner(request);
  if (owner instanceof Response) return owner;
  if (request.method !== "POST" || !validCsrf(request, owner.session)) {
    return respond(request, { ok: false, message: "Please refresh the secure page and try again." }, 403);
  }
  const account = owner.account;

  if (url.pathname === "/api/begin-reenrolment") {
    if (!account.mfaEnabled || !account.encryptedSecret) return respond(request, { ok: false, message: "Finish authenticator setup before replacing it." }, 400);
    account.reenrolmentStarted = true;
    return respond(request, { ok: true });
  }

  if (url.pathname === "/api/provision") {
    if (account.mfaEnabled && !account.reenrolmentStarted) {
      return respond(request, { ok: false, message: "Choose “Replace authenticator” first. Your current authenticator stays active until the new one is checked." }, 400);
    }

    /* Per-provision simulated verification value: random, short-lived, hashed at rest and replaced on every request. */
    const secret = makeSecret();
    const verificationCode = secureSixDigitCode();
    account.pendingEncryptedSecret = await encrypt(secret);
    account.pendingVerificationHash = await keyedHash(verificationCode, verificationKey);
    account.pendingVerificationExpiresAt = Date.now() + PROVISION_CODE_LIFETIME;
    account.pendingUsedCounters = [];

    const uri = "otpauth://totp/" + encodeURIComponent("Northstar Bank:" + account.email) +
      "?secret=" + secret + "&issuer=Northstar%20Bank&algorithm=SHA1&digits=6&period=30";
    return respond(request, {
      ok: true,
      secret,
      uri,
      verificationCode,
      message: account.mfaEnabled
        ? "Your replacement setup is ready. Your current authenticator still works until this new one is verified."
        : "Authenticator setup is ready. Add the secret, then enter the six-digit code.",
    });
  }

  if (url.pathname === "/api/verify-otp") {
    const data = await readBody(request);
    const now = Date.now();
    if (account.otpLockedUntil && account.otpLockedUntil <= now) { account.otpLockedUntil = 0; account.otpFailures = 0; }
    if (!data || !validOtp(data.otp)) return respond(request, { ok: false, message: "Enter exactly six numbers, for example 123456." }, 400);
    if (account.otpLockedUntil > now) return respond(request, { ok: false, message: lockedMessage() }, 429);
    if (!account.pendingEncryptedSecret || !account.pendingVerificationHash || !account.pendingVerificationExpiresAt) {
      return respond(request, { ok: false, message: "Request a new setup and try again." }, 400);
    }
    if (now > account.pendingVerificationExpiresAt) {
      account.pendingEncryptedSecret = undefined;
      account.pendingVerificationHash = undefined;
      account.pendingVerificationExpiresAt = undefined;
      return respond(request, { ok: false, message: "This setup code expired. Request a new setup, then try again." }, 400);
    }

    const suppliedHash = await keyedHash(data.otp, verificationKey);
    if (!equal(suppliedHash, account.pendingVerificationHash)) {
      account.otpFailures++;
      if (account.otpFailures >= MAX_FAILURES) account.otpLockedUntil = now + LOCKOUT;
      return respond(request, { ok: false, message: account.otpFailures >= MAX_FAILURES ? lockedMessage() : "That code did not match. Check your authenticator app and try again." }, 400);
    }

    /* Authentication and replay protection: successful per-provision code is immediately invalidated. */
    account.encryptedSecret = account.pendingEncryptedSecret;
    account.pendingEncryptedSecret = undefined;
    account.pendingVerificationHash = undefined;
    account.pendingVerificationExpiresAt = undefined;
    account.pendingUsedCounters = [];
    account.reenrolmentStarted = false;
    account.mfaEnabled = true;
    account.otpFailures = 0;
    account.otpLockedUntil = 0;

    const codes = makeRecoveryCodes();
    account.backupCodeHashes = await Promise.all(codes.map((code) => keyedHash(code, recoveryKey)));
    account.recoveryFailures = 0;
    account.recoveryLockedUntil = 0;
    return respond(request, { ok: true, codes });
  }

  if (url.pathname === "/api/verify-recovery-code") {
    const data = await readBody(request);
    const now = Date.now();
    const submitted = typeof data?.recoveryCode === "string" ? data.recoveryCode.toUpperCase() : "";
    if (account.recoveryLockedUntil && account.recoveryLockedUntil <= now) { account.recoveryLockedUntil = 0; account.recoveryFailures = 0; }
    if (!data || !validRecoveryCode(submitted)) return respond(request, { ok: false, message: "Enter a recovery code in this format: ABCDE-12345." }, 400);
    if (!account.mfaEnabled) return respond(request, { ok: false, message: "Finish authenticator setup before using a recovery code." }, 400);
    if (account.recoveryLockedUntil > now) return respond(request, { ok: false, message: lockedMessage() }, 429);

    const submittedHash = await keyedHash(submitted, recoveryKey);
    let index = -1;
    for (let i = 0; i < account.backupCodeHashes.length; i++) {
      if (equal(submittedHash, account.backupCodeHashes[i]) && index < 0) index = i;
    }
    if (index < 0) {
      account.recoveryFailures++;
      if (account.recoveryFailures >= MAX_FAILURES) account.recoveryLockedUntil = now + LOCKOUT;
      return respond(request, { ok: false, message: account.recoveryFailures >= MAX_FAILURES ? lockedMessage() : "That recovery code was not recognised. Check the code and try again, or use another saved code." }, 400);
    }
    account.backupCodeHashes.splice(index, 1);
    account.recoveryFailures = 0;
    account.recoveryLockedUntil = 0;
    return respond(request, { ok: true });
  }

  if (url.pathname === "/api/regenerate-backup-codes") {
    if (!account.mfaEnabled) return respond(request, { ok: false, message: "Finish authenticator setup before making recovery codes." }, 400);
    const codes = makeRecoveryCodes();
    account.backupCodeHashes = await Promise.all(codes.map((code) => keyedHash(code, recoveryKey)));
    account.recoveryFailures = 0;
    account.recoveryLockedUntil = 0;
    return respond(request, { ok: true, codes });
  }

  return new Response("Not found", { status: 404, headers: secureHeaders(request) });
}

Bun.serve({
  port: Number(Bun.env.PORT || 3000),
  hostname: "localhost",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      return await handle(request);
    } catch {
      return new Response("Something went wrong. Please try again.", { status: 500, headers: secureHeaders(request) });
    }
  },
});
console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
