
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PEPPER = bytesToBase64(randomBytes(32));
const encryptionKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 },
  false,
  ["encrypt", "decrypt"]
);

/* Requirements: state is scoped to an authenticated account record, never a shared user object. */
type Session = { userId: string; csrf: string; createdAt: number; lastSeen: number };
type Verification = { hash: string; expiresAt: number; used: boolean };
type StoredCipher = { iv: string; data: string };
type Account = {
  id: string;
  email: string;
  identityVerified: boolean;
  identityCheck?: Verification;
  identityFailures: number;
  identityLockedUntil: number;
  identityLastSent: number;
  encryptedSeed?: StoredCipher;
  mfaEnabled: boolean;
  authenticatorFailures: number;
  authenticatorLockedUntil: number;
  provisioningLastSent: number;
  usedTotpSteps: Set<number>;
  backupHashes: Set<string>;
  recoveryFailures: number;
  recoveryWindowStarted: number;
  recoveryLockedUntil: number;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();

/* Configured mock account. Other identities are not authenticated. */
const mockAccount: Account = {
  id: "marcus-account",
  email: "marcus@example.test",
  identityVerified: false,
  identityFailures: 0,
  identityLockedUntil: 0,
  identityLastSent: 0,
  mfaEnabled: false,
  authenticatorFailures: 0,
  authenticatorLockedUntil: 0,
  provisioningLastSent: 0,
  usedTotpSteps: new Set(),
  backupHashes: new Set(),
  recoveryFailures: 0,
  recoveryWindowStarted: 0,
  recoveryLockedUntil: 0,
};
accounts.set(mockAccount.id, mockAccount);

const IDLE_MS = 30 * 60 * 1000;
const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const VERIFY_MS = 30 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const ISSUE_MS = 20 * 1000;
const MAX_FAILURES = 5;
const RECOVERY_WINDOW_MS = 10 * 60 * 1000;
const DEMO_IDENTITY_CODE = "123456";

/* Exact trusted-origin allow-list used for both CORS and CSRF validation. */
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

function randomBytes(length: number): Uint8Array {
  const values = new Uint8Array(length);
  crypto.getRandomValues(values);
  return values;
}
function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}
function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
function randomToken(bytes = 32): string {
  return bytesToBase64(randomBytes(bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
/* RFC 4648 Base32 alphabet: compatible with standard TOTP authenticator applications. */
function randomBase32(length: number): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const values = randomBytes(length);
  return Array.from(values, value => alphabet[value % alphabet.length]).join("");
}
function randomRecoveryCode(): string {
  const value = randomBase32(10);
  return value.slice(0, 5) + "-" + value.slice(5);
}
async function digest(value: string): Promise<string> {
  const output = await crypto.subtle.digest("SHA-256", encoder.encode(value + ":" + PEPPER));
  return bytesToBase64(new Uint8Array(output));
}
async function encryptSecret(secret: string): Promise<StoredCipher> {
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(secret));
  return { iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(encrypted)) };
}
async function decryptSecret(stored: StoredCipher): Promise<string> {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(stored.iv) },
    encryptionKey,
    base64ToBytes(stored.data)
  );
  return decoder.decode(decrypted);
}
function base32Bytes(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let buffer = 0, bits = 0;
  const result: number[] = [];
  for (const character of value.replace(/=|\s/g, "").toUpperCase()) {
    const n = alphabet.indexOf(character);
    if (n < 0) throw new Error("invalid seed");
    buffer = (buffer << 5) | n;
    bits += 5;
    if (bits >= 8) {
      result.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(result);
}
/* Requirements: RFC 6238 TOTP verification, with single-use accepted time steps. */
async function totp(secret: string, step: number): Promise<string> {
  const counter = new Uint8Array(8);
  let value = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    counter[i] = Number(value & 255n);
    value >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[mac.length - 1] & 15;
  const number = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 1000000).padStart(6, "0");
}

function cookieValue(request: Request, name: string): string | undefined {
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const piece = item.trim();
    if (piece.startsWith(name + "=")) return piece.slice(name.length + 1);
  }
}
function sessionCookie(id: string): string {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE_MS / 1000)}`;
}
function expiredCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

/* Requirements: security headers, CSP nonce, HSTS, and clickjacking protection. */
function baseHeaders(nonce?: string): Headers {
  const csp = nonce
    ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
  return new Headers({
    "Content-Security-Policy": csp,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
}
function responseJson(data: unknown, status = 200): Response {
  const headers = baseHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { status, headers });
}
function genericError(status = 400, message = "We could not complete that request. Please try again."): Response {
  return responseJson({ ok: false, message }, status);
}
function trustedOrigin(origin: string | null): boolean {
  return !!origin && TRUSTED_ORIGINS.has(origin);
}
function addCors(request: Request, response: Response): Response {
  const origin = request.headers.get("origin");
  if (trustedOrigin(origin)) {
    response.headers.set("Access-Control-Allow-Origin", origin!);
    response.headers.set("Access-Control-Allow-Credentials", "true");
  }
  response.headers.set("Vary", "Origin");
  response.headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
  response.headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  return response;
}
function authenticated(request: Request): { session: Session; account: Account } | undefined {
  const id = cookieValue(request, "mfa_session");
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  const account = session ? accounts.get(session.userId) : undefined;
  if (!session || !account || now - session.lastSeen > IDLE_MS || now - session.createdAt > ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return;
  }
  session.lastSeen = now;
  return { session, account };
}
function csrfOK(request: Request, session: Session): boolean {
  return trustedOrigin(request.headers.get("origin")) && request.headers.get("x-csrf-token") === session.csrf;
}
async function bodyJSON(request: Request): Promise<Record<string, unknown> | undefined> {
  if (!(request.headers.get("content-type") || "").includes("application/json")) return;
  const text = await request.text();
  if (text.length > 3000) return;
  try {
    const data = JSON.parse(text);
    return data && typeof data === "object" && !Array.isArray(data) ? data : undefined;
  } catch {
    return;
  }
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function validCode(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(value);
}
function locked(until: number): boolean {
  return Date.now() < until;
}
function failureMessage(kind: "identity" | "auth" | "recovery"): string {
  if (kind === "identity") return "Too many tries. Please wait 10 minutes before trying again.";
  if (kind === "auth") return "Too many authenticator tries. Please wait 10 minutes before trying again.";
  return "Too many recovery-code tries. Please wait 10 minutes before trying again.";
}
async function newVerification(code: string): Promise<Verification> {
  return { hash: await digest(code), expiresAt: Date.now() + VERIFY_MS, used: false };
}
async function createRecoveryCodes(account: Account): Promise<string[]> {
  const codes = Array.from({ length: 8 }, randomRecoveryCode);
  account.backupHashes = new Set(await Promise.all(codes.map(digest)));
  account.recoveryFailures = 0;
  account.recoveryWindowStarted = 0;
  account.recoveryLockedUntil = 0;
  return codes;
}
function recordRecoveryFailure(account: Account): boolean {
  const now = Date.now();
  if (!account.recoveryWindowStarted || now - account.recoveryWindowStarted > RECOVERY_WINDOW_MS) {
    account.recoveryWindowStarted = now;
    account.recoveryFailures = 0;
  }
  account.recoveryFailures++;
  if (account.recoveryFailures >= MAX_FAILURES) {
    account.recoveryFailures = 0;
    account.recoveryWindowStarted = 0;
    account.recoveryLockedUntil = now + LOCK_MS;
    return true;
  }
  return false;
}

/* Single-page mobile client. Mock delivery values remain only in browser console. */
const page = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · Security setup</title>
<style nonce="__NONCE__">
:root{--ink:#17243a;--muted:#536276;--blue:#075fc8;--line:#cbd6e3;--bad:#b42318;--good:#126b43}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font:17px/1.65 Arial,Verdana,Tahoma,sans-serif;letter-spacing:.025em}main{width:min(100%,620px);margin:auto;padding:18px 15px 42px}.brand{font-weight:bold;color:#064b9e;margin:5px 5px 18px}h1{font-size:1.55rem;line-height:1.3;margin:0 0 9px}p{margin:0 0 14px}.card{background:#fff;border:1px solid var(--line);border-radius:15px;padding:23px 19px;box-shadow:0 2px 8px #1935540d}.step{color:var(--blue);font-weight:bold;margin:0 0 12px}.icon{font-size:1.55rem;margin-right:8px}label{display:block;font-weight:bold;margin:18px 0 6px}input{width:100%;min-height:52px;border:2px solid #8ba0b8;border-radius:10px;padding:13px;font:inherit;letter-spacing:.05em}input:focus{outline:3px solid #8bc5ff;outline-offset:2px;border-color:var(--blue)}button{width:100%;min-height:53px;margin-top:16px;border:0;border-radius:10px;background:var(--blue);color:#fff;font:bold 1rem Arial,sans-serif;padding:12px;cursor:pointer}button.secondary{background:#fff;color:#064b9e;border:2px solid #1e70c7}button.small{width:auto;min-height:42px;margin:8px 8px 0 0;padding:7px 12px}.hint,details{color:var(--muted);font-size:.94rem}.notice{margin-top:16px;padding:12px;border-radius:9px;font-weight:bold}.error{background:#fff0ef;color:var(--bad);border-left:5px solid var(--bad)}.ok{background:#eaf8f0;color:var(--good);border-left:5px solid var(--good)}.secret{overflow-wrap:anywhere;background:#f5f8fc;border:1px dashed #7891ae;padding:12px;border-radius:8px;font-family:monospace;font-weight:bold}.hidden-secret{color:#536276;letter-spacing:.1em}.qr{display:block;width:min(100%,260px);height:auto;margin:16px auto;border:7px solid #fff;image-rendering:pixelated}.code-list{list-style:none;padding:0}.code-list li{margin:8px 0;padding:8px 10px;background:#f5f8fc;font-family:monospace;font-weight:bold;border-radius:7px}.checkline{display:flex;gap:10px;align-items:flex-start}.checkline input{width:23px;min-height:23px;margin-top:5px}.status{padding:10px;background:#eef6ff;border-radius:9px}summary{color:var(--blue);font-weight:bold;cursor:pointer}@media(max-width:370px){body{font-size:16px}.card{padding:18px 14px}}
</style></head><body><main><header><div class="brand">◆ Harbour Bank</div></header><section id="app" aria-live="polite"></section></main>
<script nonce="__NONCE__">
(()=>{"use strict";
const app=document.querySelector("#app");
const state={csrf:"",screen:"signin",identityCode:"",otp:"",secret:"",uri:"",codes:[],message:"",error:"",showUri:false,showSecret:false};
const esc=v=>String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const log=value=>console.log(value);
function msg(message,error=""){state.message=message;state.error=error}
function note(){return state.error?'<div class="notice error">'+esc(state.error)+"</div>":state.message?'<div class="notice ok">'+esc(state.message)+"</div>":""}
function help(text){return "<details><summary>Need help?</summary><p>"+esc(text)+"</p></details>"}
function shell(step,title,icon,text,inside,hint){return '<article class="card"><p class="step">'+step+'</p><h1><span class="icon">'+icon+"</span>"+title+"</h1><p>"+text+"</p>"+inside+note()+help(hint)+"</article>"}
async function api(path,data){let response;try{response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":state.csrf},body:JSON.stringify(data||{})})}catch{throw Error("Connection problem. Please try again.")}const json=await response.json().catch(()=>({message:"We could not complete that request."}));if(response.status===401){state.csrf="";state.screen="signin";render()}if(!response.ok)throw Error(json.message||"We could not complete that request.");return json}
async function copy(text,done){try{await navigator.clipboard.writeText(text);msg(done);render()}catch{msg("Copy was not available. You can select the text and copy it.");render()}}
function qrSvg(){return '<svg class="qr" viewBox="0 0 29 29" role="img" aria-label="Authenticator QR setup marker" xmlns="http://www.w3.org/2000/svg"><rect width="29" height="29" fill="white"/><g fill="#17243a"><path d="M1 1h7v7H1zM3 3v3h3V3zM21 1h7v7h-7zM23 3v3h3V3zM1 21h7v7H1zM3 23v3h3v-3zM10 2h2v2h-2zm4 0h2v2h-2zm3 2h2v2h-2zm-7 3h4v2h-4zm5 1h2v3h-2zm3 1h2v2h-2zm-8 4h2v2h-2zm3 0h4v2h-4zm5 1h2v4h-2zm3 0h3v2h-3zm-15 3h4v2h-4zm5 1h2v3h-2zm3 0h2v2h-2zm4 1h3v2h-3zm-13 3h2v2h-2zm3 1h4v2h-4zm6 0h2v3h-2zm4 1h4v2h-4zm-4 4h3v2h-3zm4 1h2v2h-2z"/></g></svg>'}
function render(){let html="";
if(state.screen==="signin")html=shell("Step 1 of 5","Sign in to start","👋","Use the email for your bank account.",'<form id="sign"><label>Email address<input id="email" type="email" autocomplete="username email" placeholder="marcus@example.test" required></label><p class="hint">Example: marcus@example.test</p><button>Continue</button></form>',"Use the demo account email shown in the example.");
if(state.screen==="identity")html=shell("Step 2 of 5","Check it is you","✉️","We sent a 6-digit check code in this safe demo.",'<form id="ident"><label>Check code<input id="identity" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456" required></label><button>Check code</button></form><button class="secondary" id="fillI">Use demo code</button><button class="secondary" id="resend">Send a new code</button>',"The demo code is in your browser console. There is plenty of time.");
if(state.screen==="setup"){const uri=state.showUri?esc(state.uri):'<span class="hidden-secret">Hidden for privacy</span>';const secret=state.showSecret?esc(state.secret):'<span class="hidden-secret">Hidden for privacy</span>';html=shell("Step 3 of 5","Add your authenticator","📱","Scan the QR option in your authenticator app. You can also reveal and copy the details.",qrSvg()+'<p class="hint">QR option: use your app scanner, then use the copied setup URI if your app asks for it.</p><p class="hint">Manual setup URI</p><div class="secret">'+uri+'</div><button class="small secondary" id="toggleUri">'+(state.showUri?"Hide setup URI":"Reveal setup URI")+'</button><button class="small secondary" id="copyUri">Copy setup URI</button><p class="hint">Manual secret</p><div class="secret">'+secret+'</div><button class="small secondary" id="toggleSecret">'+(state.showSecret?"Hide secret":"Reveal secret")+'</button><button class="small secondary" id="copySecret">Copy secret</button><button id="toOtp">I added the authenticator</button>',"The QR option, setup URI, and secret set up the same authenticator. Details stay hidden until you choose to reveal them.");}
if(state.screen==="otp")html=shell("Step 4 of 5","Confirm your authenticator","🔐","Enter the 6-digit code from your authenticator app.",'<form id="otpform"><label>Authenticator code<input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="Example: 123456" required></label><button>Confirm authenticator</button></form><button class="secondary" id="fillO">Use demo code</button><button class="secondary" id="restart">Show setup details again</button>',"The demo test code is in your browser console. You can retry without penalty unless the safety limit is reached.");
if(state.screen==="backup")html=shell("Step 5 of 5","Save your recovery codes","🧾","Keep these codes somewhere safe. Each works once if you lose your phone.",'<ul class="code-list">'+state.codes.map(code=>"<li>"+esc(code)+"</li>").join("")+'</ul><button class="small secondary" id="copyCodes">Copy all codes</button><label class="checkline"><input id="saved" type="checkbox"><span>I have saved my recovery codes.</span></label><button id="finish">Finish security setup</button>',"Copy the codes rather than typing them.");
if(state.screen==="settings")html=shell("Security settings","MFA is ready","✅","Your authenticator and recovery codes are active.",'<div class="status">🛡️ <strong>Authenticator:</strong> active</div><label>Test a recovery code<input id="recovery" autocapitalize="characters" placeholder="Example: ABCDE-FGHIJ"></label><button id="test">Test recovery code</button><button class="secondary" id="regen">Make new recovery codes</button><button class="secondary" id="logout">Sign out</button>',"New recovery codes replace old ones.");
app.innerHTML=html;bind()}
async function provision(){const result=await api("/api/authenticator/provision");state.secret=result.secret;state.uri=result.uri;state.otp=result.mockCode;state.showUri=false;state.showSecret=false;log("[Mock delivery] Authenticator test code: "+result.mockCode)}
function bind(){const $=selector=>document.querySelector(selector);
if(state.screen==="signin")$("#sign").onsubmit=async event=>{event.preventDefault();try{const result=await api("/api/signin",{email:$("#email").value});state.csrf=result.csrf;state.identityCode=result.mockCode;state.screen="identity";log("[Mock delivery] Identity check code: "+result.mockCode);render()}catch(error){msg("",error.message);render()}};
if(state.screen==="identity"){$("#ident").onsubmit=async event=>{event.preventDefault();try{await api("/api/identity/verify",{code:$("#identity").value});await provision();state.screen="setup";render()}catch(error){msg("",error.message);render()}};$("#fillI").onclick=()=>{$("#identity").value=state.identityCode};$("#resend").onclick=async()=>{try{const result=await api("/api/identity/send");state.identityCode=result.mockCode;log("[Mock delivery] Identity check code: "+result.mockCode);msg("A new demo code is in your browser console.");render()}catch(error){msg("",error.message);render()}}}
if(state.screen==="setup"){$("#toggleUri").onclick=()=>{state.showUri=!state.showUri;render()};$("#toggleSecret").onclick=()=>{state.showSecret=!state.showSecret;render()};$("#copyUri").onclick=()=>copy(state.uri,"Setup URI copied.");$("#copySecret").onclick=()=>copy(state.secret,"Secret copied.");$("#toOtp").onclick=()=>{state.screen="otp";msg("Your next step is to confirm the 6-digit code.");render()}}
if(state.screen==="otp"){$("#otpform").onsubmit=async event=>{event.preventDefault();try{const result=await api("/api/authenticator/verify",{code:$("#otp").value});state.codes=result.codes;log("[Mock delivery] Recovery codes: "+result.codes.join(", "));state.screen="backup";render()}catch(error){msg("",error.message);render()}};$("#fillO").onclick=()=>{$("#otp").value=state.otp};$("#restart").onclick=()=>{state.screen="setup";msg("Your existing setup details are available again.");render()}}
if(state.screen==="backup"){$("#copyCodes").onclick=()=>copy(state.codes.join("\\n"),"Recovery codes copied.");$("#finish").onclick=async()=>{if(!$("#saved").checked){msg("Please tick the box after you have saved the codes.");render();return}try{await api("/api/backup/confirm");state.codes=[];state.screen="settings";msg("Security setup is complete.");render()}catch(error){msg("",error.message);render()}}}
if(state.screen==="settings"){$("#test").onclick=async()=>{try{await api("/api/recovery/verify",{code:$("#recovery").value.toUpperCase()});msg("That recovery code worked and is now used.");render()}catch(error){msg("",error.message);render()}};$("#regen").onclick=async()=>{try{const result=await api("/api/recovery/regenerate");state.codes=result.codes;log("[Mock delivery] New recovery codes: "+result.codes.join(", "));state.screen="backup";render()}catch(error){msg("",error.message);render()}};$("#logout").onclick=async()=>{try{await api("/api/logout");state.csrf="";state.screen="signin";msg("You have signed out.");render()}catch(error){msg("",error.message);render()}}}}
render()
})()
</script></body></html>`;

function htmlResponse(): Response {
  const nonce = randomToken(18);
  const headers = baseHeaders(nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  return new Response(page.replaceAll("__NONCE__", nonce), { headers });
}
function authResponse(request: Request, response: Response): Response {
  return addCors(request, response);
}

async function route(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    if (!trustedOrigin(request.headers.get("origin"))) return genericError(403, "Request not allowed.");
    return addCors(request, new Response(null, { status: 204, headers: baseHeaders() }));
  }
  if (url.pathname === "/" && request.method === "GET") return htmlResponse();
  if (!url.pathname.startsWith("/api/")) return genericError(404, "Page not found.");

  /* Authentication binds a new rotated session to the configured account record. */
  if (url.pathname === "/api/signin" && request.method === "POST") {
    const data = await bodyJSON(request);
    if (!data || !validEmail(data.email) || !trustedOrigin(request.headers.get("origin"))) {
      return genericError(400, "Please enter an email address in the example format.");
    }
    const account = [...accounts.values()].find(item => item.email.toLowerCase() === data.email.toLowerCase());
    if (!account) return genericError(401, "We could not sign in with those details. Check the account email and try again.");
    if (locked(account.identityLockedUntil)) return genericError(429, failureMessage("identity"));

    for (const [id, session] of sessions) if (session.userId === account.id) sessions.delete(id);
    const id = randomToken();
    const csrf = randomToken();
    sessions.set(id, { userId: account.id, csrf, createdAt: Date.now(), lastSeen: Date.now() });

    account.identityVerified = false;
    account.identityCheck = await newVerification(DEMO_IDENTITY_CODE);
    account.identityLastSent = Date.now();

    const response = responseJson({ ok: true, csrf, mockCode: DEMO_IDENTITY_CODE });
    response.headers.set("Set-Cookie", sessionCookie(id));
    return authResponse(request, response);
  }

  const auth = authenticated(request);
  if (!auth) {
    const response = genericError(401, "Please sign in again to continue.");
    response.headers.set("Set-Cookie", expiredCookie());
    return authResponse(request, response);
  }
  const { session, account } = auth;

  /* Requirements: every state-changing MFA endpoint has origin and CSRF protection. */
  if (request.method !== "GET" && !csrfOK(request, session)) {
    return authResponse(request, genericError(403, "Your secure form check did not match. Refresh and try again."));
  }

  if (url.pathname === "/api/identity/send" && request.method === "POST") {
    if (locked(account.identityLockedUntil)) return authResponse(request, genericError(429, failureMessage("identity")));
    if (Date.now() - account.identityLastSent < ISSUE_MS) {
      return authResponse(request, genericError(429, "Please wait a short moment before requesting another code."));
    }
    account.identityCheck = await newVerification(DEMO_IDENTITY_CODE);
    account.identityLastSent = Date.now();
    return authResponse(request, responseJson({ ok: true, mockCode: DEMO_IDENTITY_CODE }));
  }

  if (url.pathname === "/api/identity/verify" && request.method === "POST") {
    const data = await bodyJSON(request);
    if (!data || !validCode(data.code)) {
      return authResponse(request, genericError(400, "Enter exactly 6 numbers, for example 123456."));
    }
    if (locked(account.identityLockedUntil)) return authResponse(request, genericError(429, failureMessage("identity")));
    const check = account.identityCheck;
    if (!check || check.used || Date.now() > check.expiresAt) {
      return authResponse(request, genericError(400, "That code is no longer available. Request a new code and try again."));
    }
    if ((await digest(data.code)) !== check.hash) {
      account.identityFailures++;
      if (account.identityFailures >= MAX_FAILURES) {
        account.identityLockedUntil = Date.now() + LOCK_MS;
        account.identityFailures = 0;
      }
      return authResponse(request, genericError(400, locked(account.identityLockedUntil)
        ? failureMessage("identity")
        : "That code does not match. Check the 6 numbers and try again."));
    }
    check.used = true;
    account.identityVerified = true;
    account.identityFailures = 0;
    return authResponse(request, responseJson({ ok: true }));
  }

  /* A provision request never replaces an existing seed or clears accepted TOTP-step history. */
  if (url.pathname === "/api/authenticator/provision" && request.method === "POST") {
    if (!account.identityVerified) {
      return authResponse(request, genericError(403, "Complete the identity check before setting up an authenticator."));
    }
    if (account.mfaEnabled) {
      return authResponse(request, genericError(403, "Your authenticator is already active. An authenticated replacement process is required to change it."));
    }
    if (locked(account.authenticatorLockedUntil)) return authResponse(request, genericError(429, failureMessage("auth")));

    let secret: string;
    if (account.encryptedSeed) {
      secret = await decryptSecret(account.encryptedSeed);
    } else {
      secret = randomBase32(32);
      account.encryptedSeed = await encryptSecret(secret);
    }
    account.provisioningLastSent = Date.now();

    const step = Math.floor(Date.now() / 30000);
    const mockCode = await totp(secret, step);
    const uri = "otpauth://totp/Harbour:Marcus?secret=" + encodeURIComponent(secret) + "&issuer=Harbour";
    return authResponse(request, responseJson({ ok: true, secret, uri, mockCode }));
  }

  if (url.pathname === "/api/authenticator/verify" && request.method === "POST") {
    const data = await bodyJSON(request);
    if (!data || !validCode(data.code)) {
      return authResponse(request, genericError(400, "Enter exactly 6 numbers, for example 123456."));
    }
    if (locked(account.authenticatorLockedUntil)) return authResponse(request, genericError(429, failureMessage("auth")));
    if (!account.encryptedSeed) {
      return authResponse(request, genericError(400, "Request authenticator setup before entering a code."));
    }

    const secret = await decryptSecret(account.encryptedSeed);
    const current = Math.floor(Date.now() / 30000);
    let matched: number | undefined;
    for (const step of [current - 1, current, current + 1]) {
      if (!account.usedTotpSteps.has(step) && data.code === await totp(secret, step)) {
        matched = step;
        break;
      }
    }
    if (matched === undefined) {
      account.authenticatorFailures++;
      if (account.authenticatorFailures >= MAX_FAILURES) {
        account.authenticatorLockedUntil = Date.now() + LOCK_MS;
        account.authenticatorFailures = 0;
      }
      return authResponse(request, genericError(400, locked(account.authenticatorLockedUntil)
        ? failureMessage("auth")
        : "That code does not match. Check the 6 numbers and try again."));
    }

    account.usedTotpSteps.add(matched);
    account.authenticatorFailures = 0;
    account.mfaEnabled = true;
    const codes = await createRecoveryCodes(account);
    return authResponse(request, responseJson({ ok: true, codes }));
  }

  if (url.pathname === "/api/backup/confirm" && request.method === "POST") {
    if (!account.mfaEnabled) return authResponse(request, genericError(403, "Set up an authenticator first."));
    return authResponse(request, responseJson({ ok: true }));
  }

  if (url.pathname === "/api/recovery/regenerate" && request.method === "POST") {
    if (!account.mfaEnabled) return authResponse(request, genericError(403, "Set up an authenticator first."));
    return authResponse(request, responseJson({ ok: true, codes: await createRecoveryCodes(account) }));
  }

  /* Requirements: per-account bounded recovery-code failure window and lockout. */
  if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
    if (!account.mfaEnabled) return authResponse(request, genericError(403, "Set up an authenticator first."));
    if (locked(account.recoveryLockedUntil)) return authResponse(request, genericError(429, failureMessage("recovery")));

    const data = await bodyJSON(request);
    if (!data || !validRecovery(data.code)) {
      return authResponse(request, genericError(400, "Enter a recovery code like ABCDE-FGHIJ."));
    }

    const hashed = await digest(data.code);
    if (!account.backupHashes.has(hashed)) {
      const nowLocked = recordRecoveryFailure(account);
      return authResponse(request, genericError(nowLocked ? 429 : 400, nowLocked
        ? failureMessage("recovery")
        : "That recovery code is not available. Check it or use another saved code."));
    }

    account.backupHashes.delete(hashed);
    account.recoveryFailures = 0;
    account.recoveryWindowStarted = 0;
    return authResponse(request, responseJson({ ok: true }));
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const id = cookieValue(request, "mfa_session");
    if (id) sessions.delete(id);
    const response = responseJson({ ok: true });
    response.headers.set("Set-Cookie", expiredCookie());
    return authResponse(request, response);
  }

  return authResponse(request, genericError(404, "Page not found."));
}

/* Requirements: TLS uses supplied mkcert certificate files. */
Bun.serve({
  port: 3000,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      return await route(request);
    } catch {
      return genericError(500, "We could not complete that request. Please try again.");
    }
  },
});
console.log("MFA enrolment server ready at https://localhost:3000");
