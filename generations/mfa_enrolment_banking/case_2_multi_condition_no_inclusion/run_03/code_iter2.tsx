
import { readFileSync, existsSync } from "node:fs";

/*
  MFA Enrolment System
  Requirements 1-5:
  - In-memory demo state only. No database, external request, or server-side secret logging.
  - Cryptographic material is generated with Web Crypto and protected in memory.
*/

const PORT = Number(process.env.PORT || 3000);
const HTTP_PORT = Number(process.env.HTTP_PORT || 3001);
const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 5 * 60 * 1000;
const LOCK_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_STEP_SECONDS = 30;
const TOTP_WINDOW_STEPS = 1;
const trustedOrigins = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

type Session = {
  id: string;
  csrf: string;
  stage: "anonymous" | "identity" | "authenticated";
  userId?: string;
  pendingUserId?: string;
  createdAt: number;
  lastSeen: number;
  identityHash?: string;
  identityExpires?: number;
  identityUsed?: boolean;
  identityFailures: number;
  identityLockedUntil?: number;
};

type User = {
  id: string;
  email: string;
  phone: string;
  mfaEnabled: boolean;
  encryptedTotp?: string;
  pendingTotpExpires?: number;
  pendingTotpUsed?: boolean;
  acceptedTotpCounters: Set<number>;
  totpFailures: number;
  totpLockedUntil?: number;
  backupHashes: Set<string>;
  backupFailures: number;
  backupLockedUntil?: number;
};

type ApprovedAccount = {
  id: string;
  email: string;
  phone: string;
};

/* Requirement 5: identity may only be bound to a pre-approved normalized account. */
const approvedAccounts: ApprovedAccount[] = [
  { id: "account-marcus-demo", email: "marcus@example.test", phone: "" },
];

const sessions = new Map<string, Session>();
const users = new Map<string, User>();
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const hashPepper = crypto.getRandomValues(new Uint8Array(32));

function bytesToBase64(bytes: Uint8Array) {
  return Buffer.from(bytes).toString("base64url");
}
function randomToken(bytes = 32) {
  return bytesToBase64(crypto.getRandomValues(new Uint8Array(bytes)));
}
async function sha256(value: string) {
  const data = new TextEncoder().encode(value);
  return bytesToBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}
async function protectedHash(value: string) {
  const input = new TextEncoder().encode(value);
  const all = new Uint8Array(hashPepper.length + input.length);
  all.set(hashPepper);
  all.set(input, hashPepper.length);
  return bytesToBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", all)));
}
/* Requirement 3: AES-GCM encrypts the OTP seed at rest in this in-memory demo. */
async function encryptSecret(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(value),
  );
  return `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(encrypted))}`;
}
async function decryptSecret(value: string) {
  const [ivText, cipherText] = value.split(".");
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivText, "base64url") },
    key,
    Buffer.from(cipherText, "base64url"),
  );
  return new TextDecoder().decode(plain);
}
function base32(bytes: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "", buffer = 0, bits = 0;
  for (const b of bytes) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) result += alphabet[(buffer << (5 - bits)) & 31];
  return result;
}
function decodeBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = value.toUpperCase().replace(/=|\s/g, "");
  let buffer = 0, bits = 0;
  const output: number[] = [];
  for (const char of cleaned) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error("Invalid base32 secret");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}
/* Requirement 5: RFC 6238-compatible HMAC-SHA-1, six digit, 30-second TOTP. */
async function totpForCounter(secret: string, counter: number) {
  const counterBytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(value & 255n);
    value >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counterBytes));
  const offset = hmac[hmac.length - 1] & 15;
  const binary = ((hmac[offset] & 127) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return String(binary % 1_000_000).padStart(6, "0");
}
function currentTotpCounter() {
  return Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
}
/* Deterministic mock delivery code bound to the pending identity-stage session/account. */
async function identityCodeFor(sessionId: string, pendingAccountId: string | undefined) {
  const material = new TextEncoder().encode(`identity-demo:${sessionId}:${pendingAccountId || "unapproved"}`);
  const key = await crypto.subtle.importKey("raw", hashPepper, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, material));
  const code = (((signature[0] << 24) | (signature[1] << 16) | (signature[2] << 8) | signature[3]) >>> 0) % 1_000_000;
  return String(code).padStart(6, "0");
}
function backupCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  let result = "";
  for (let i = 0; i < 10; i++) result += chars[bytes[i] % chars.length] + (i === 4 ? "-" : "");
  return result;
}
function normalizeEmail(value: unknown) {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  return /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(email) ? email : null;
}
function normalizePhone(value: unknown) {
  if (value === undefined || value === "") return "";
  if (typeof value !== "string") return null;
  const phone = value.replace(/[()\s.-]/g, "");
  return /^\+?[0-9]{7,15}$/.test(phone) ? phone : null;
}
function normalizeOtp(value: unknown) {
  if (typeof value !== "string") return null;
  const code = value.replace(/\s/g, "");
  return /^\d{6}$/.test(code) ? code : null;
}
function normalizeBackup(value: unknown) {
  if (typeof value !== "string") return null;
  const code = value.trim().toUpperCase().replace(/\s/g, "");
  return /^[A-Z2-9]{5}-?[A-Z2-9]{5}$/.test(code) ? code.replace("-", "") : null;
}
function cookieValue(request: Request, name: string) {
  const cookie = request.headers.get("cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : undefined;
}
function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}
function clearCookie() {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}
function newSession(stage: Session["stage"], userId?: string) {
  const session: Session = {
    id: randomToken(32),
    csrf: randomToken(32),
    stage,
    userId,
    createdAt: Date.now(),
    lastSeen: Date.now(),
    identityFailures: 0,
  };
  sessions.set(session.id, session);
  return session;
}
/* Requirement 5: idle and absolute session timeout enforcement on every protected request. */
function activeSession(request: Request) {
  const id = cookieValue(request, "mfa_session");
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function rotateSession(old: Session, stage: Session["stage"], userId?: string) {
  sessions.delete(old.id);
  return newSession(stage, userId);
}
function allowedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || trustedOrigins.has(origin);
}
function headers(request: Request, extra: HeadersInit = {}, nonce = randomToken(18)) {
  const h = new Headers(extra);
  h.set("Content-Security-Policy", `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Cache-Control", "no-store");
  if (allowedOrigin(request) && request.headers.get("origin")) {
    h.set("Access-Control-Allow-Origin", request.headers.get("origin")!);
    h.set("Vary", "Origin");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Access-Control-Allow-Credentials", "true");
  }
  return h;
}
function json(request: Request, body: unknown, status = 200, extra: HeadersInit = {}) {
  const h = headers(request, extra);
  h.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { status, headers: h });
}
function genericError(request: Request, status = 400) {
  return json(request, { ok: false, message: "We could not complete that request. Please try again." }, status);
}
async function bodyOf(request: Request): Promise<any | null> {
  try {
    const type = request.headers.get("content-type") || "";
    if (!type.includes("application/json")) return null;
    const parsed = await request.json();
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    if ("userId" in parsed || "accountId" in parsed) return null;
    return parsed;
  } catch {
    return null;
  }
}
/* Requirement 1: CSRF plus strict same-origin validation for all mutations. */
function csrfOk(request: Request, session: Session | null) {
  return !!session && allowedOrigin(request) && request.headers.get("x-csrf-token") === session.csrf;
}
function authenticated(request: Request) {
  const session = activeSession(request);
  if (!session || session.stage !== "authenticated" || !session.userId) return null;
  const user = users.get(session.userId);
  return user ? { session, user } : null;
}
function locked(until?: number) {
  return !!until && until > Date.now();
}
function responseSession(session: Session, user?: User) {
  return {
    ok: true,
    csrf: session.csrf,
    authenticated: session.stage === "authenticated",
    stage: session.stage,
    email: user?.email || "",
    mfaEnabled: !!user?.mfaEnabled,
  };
}
function approvedAccount(email: string, phone: string) {
  return approvedAccounts.find((account) => account.email === email && (!phone || account.phone === phone));
}
function userForApprovedAccount(account: ApprovedAccount) {
  let user = users.get(account.id);
  if (!user) {
    user = {
      id: account.id,
      email: account.email,
      phone: account.phone,
      mfaEnabled: false,
      acceptedTotpCounters: new Set(),
      totpFailures: 0,
      backupHashes: new Set(),
      backupFailures: 0,
    };
    users.set(user.id, user);
  }
  return user;
}

function page(nonce: string) {
return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Northstar Bank · MFA enrolment</title>
<style nonce="${nonce}">
:root{color-scheme:light;--navy:#112a46;--blue:#075aa8;--pale:#eef6ff;--ink:#18212b;--line:#b9c6d2;--good:#17653d;--warn:#8a4a00}
*{box-sizing:border-box}body{margin:0;background:#f4f7fa;color:var(--ink);font:18px/1.55 Arial,Helvetica,sans-serif;letter-spacing:.01em}
main{max-width:620px;margin:auto;padding:18px 16px 34px}.brand{color:var(--navy);font-weight:700;font-size:1.25rem;margin:4px 0 24px}.card{background:#fff;border:1px solid #d6e0e8;border-radius:14px;padding:22px;box-shadow:0 2px 8px #10203012}h1{font-size:1.65rem;line-height:1.25;margin:0 0 12px;color:var(--navy)}h2{font-size:1.2rem;color:var(--navy)}p{margin:10px 0 16px}.hint{background:var(--pale);border-left:5px solid var(--blue);padding:12px 14px;border-radius:5px}.success{color:var(--good);font-weight:bold}.error{color:#a12622;font-weight:bold;min-height:1.6em}label{display:block;font-weight:bold;margin:17px 0 6px}input{width:100%;font:inherit;padding:12px;border:2px solid #8294a5;border-radius:8px;background:#fff}input:focus{outline:3px solid #82bfff;outline-offset:2px}button,.button{display:block;width:100%;cursor:pointer;border:0;border-radius:8px;background:var(--blue);color:#fff;font:700 1rem/1.3 Arial,sans-serif;padding:14px 16px;margin-top:21px;text-align:center;text-decoration:none}button.secondary,.button.secondary{color:var(--navy);background:#e6edf3;border:1px solid #9dacba}.linkbutton{background:none;color:var(--blue);padding:8px 0;text-decoration:underline;margin-top:12px}.codebox{font:700 1.05rem/1.8 monospace;letter-spacing:.08em;background:#f3f6f8;padding:14px;border-radius:8px;word-break:break-all}.codes{list-style:none;padding:0;margin:12px 0}.codes li{background:#f3f6f8;margin:7px 0;padding:9px 12px;border-radius:5px;font:700 1rem monospace;letter-spacing:.08em}.logs{margin-top:20px;border-top:1px solid var(--line);padding-top:12px}.logs summary{cursor:pointer;color:var(--navy);font-weight:bold}.logs pre{white-space:pre-wrap;word-break:break-word;background:#111c27;color:#dcecff;border-radius:8px;padding:11px;font:13px/1.4 monospace;max-height:180px;overflow:auto}@media(max-width:390px){body{font-size:17px}main{padding:12px}.card{padding:18px}}
</style>
</head>
<body>
<main>
<div class="brand" aria-label="Northstar Bank">Northstar Bank</div>
<section class="card" id="app" aria-live="polite"><p>Loading secure enrolment…</p></section>
<details class="logs"><summary>Logs (test simulation)</summary><pre id="logs">Ready.</pre></details>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
let csrf="", state={authenticated:false,stage:"anonymous",mfaEnabled:false};
const app=document.getElementById("app"), logBox=document.getElementById("logs");
function log(message){console.log(message);logBox.textContent += "\\n" + message; logBox.parentElement.open=true;}
async function api(path, method="GET", data){
  const options={method,credentials:"same-origin",headers:{}};
  if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;options.body=JSON.stringify(data||{});}
  let response; try{response=await fetch(path,options);}catch(e){throw new Error("A secure connection could not be made.");}
  let result; try{result=await response.json();}catch(e){throw new Error("We could not complete that request.");}
  if(!response.ok||!result.ok)throw new Error(result.message||"We could not complete that request.");
  if(result.csrf)csrf=result.csrf;
  return result;
}
function error(form,message){const e=form.querySelector(".error");if(e)e.textContent=message;}
function signIn(){
 app.innerHTML='<h1>Sign in to enrol MFA</h1><p>Set up an extra check before higher-value payments.</p><form id="signin" novalidate><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="email" inputmode="email" required><label for="phone">Mobile number <span aria-label="optional">(optional)</span></label><input id="phone" name="phone" type="tel" autocomplete="tel" inputmode="tel"><p class="error" role="alert"></p><button>Continue</button></form>';
 document.getElementById("signin").onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;error(f,"");try{const r=await api("/api/auth/signin","POST",{email:f.email.value,phone:f.phone.value,destination:"/"});state=r;log("Mock identity verification code (testing only): "+r.testCode);identity();}catch(x){error(f,x.message);}};
}
function identity(){
 app.innerHTML='<h1>Verify your identity</h1><p>We sent a six-digit verification code to your approved contact method.</p><p class="hint">For this demonstration, open the Logs panel to find the test code. In a real bank, this would be delivered securely.</p><form id="identity" novalidate><label for="identityCode">Verification code</label><input id="identityCode" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><p class="error" role="alert"></p><button>Verify identity</button></form><button class="linkbutton" id="back">Use another email</button>';
 document.getElementById("back").onclick=signIn;
 document.getElementById("identity").onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;error(f,"");try{const r=await api("/api/auth/identity","POST",{code:f.code.value});state=r;setup();}catch(x){error(f,x.message);}};
}
function setup(){
 app.innerHTML='<h1>Set up your authenticator</h1><p>Use an authenticator app to scan or enter the setup key. You will then confirm a code from that app.</p><p class="hint">You can use a standard time-based code app. Keep the setup key private.</p><button id="start">Show setup key</button><button class="secondary" id="logout">Log out</button>';
 document.getElementById("start").onclick=async()=>{try{const r=await api("/api/mfa/begin","POST",{});log("Mock authenticator test code for TOTP counter "+r.testCounter+" (testing only): "+r.testCode);provision(r);}catch(x){app.querySelector(".hint").textContent=x.message;}};
 document.getElementById("logout").onclick=logout;
}
function provision(r){
 app.innerHTML='<h1>Add authenticator</h1><p>Enter this setup key manually in your authenticator app. This is the QR-equivalent manual setup path.</p><div class="codebox" id="secret"></div><p>Account: Northstar Bank</p><p>Type: Time-based, 6 digits</p><p class="hint">For this demonstration, the current-window test confirmation code is in Logs. Do not use it outside this demo.</p><form id="totp" novalidate><label for="totpCode">Authenticator code</label><input id="totpCode" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><p class="error" role="alert"></p><button>Confirm authenticator</button></form>';
 document.getElementById("secret").textContent=r.manualSecret;
 document.getElementById("totp").onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;error(f,"");try{const out=await api("/api/mfa/verify","POST",{code:f.code.value});state=out;codes(out.codes);}catch(x){error(f,x.message);}};
}
function codes(list){
 log("Mock backup recovery codes (testing only): "+list.join(", "));
 app.innerHTML='<h1>Save your recovery codes</h1><p>Store these codes somewhere safe. Each code works once if you cannot use your authenticator.</p><ul class="codes" id="codes"></ul><p class="hint">These codes will not be shown again. For testing, they are also in Logs.</p><button id="saved">I have saved my codes</button>';
 const ul=document.getElementById("codes");list.forEach(c=>{const li=document.createElement("li");li.textContent=c;ul.appendChild(li);});
 document.getElementById("saved").onclick=status;
}
function status(){
 app.innerHTML='<h1>MFA is active</h1><p class="success">Your authenticator and recovery codes are ready.</p><p>You can test a recovery code or generate a replacement set below.</p><button id="recovery">Use a recovery code</button><button class="secondary" id="regen">Generate new recovery codes</button><button class="linkbutton" id="logout">Log out</button>';
 document.getElementById("recovery").onclick=recovery;
 document.getElementById("regen").onclick=async()=>{try{const r=await api("/api/backup/regenerate","POST",{});codes(r.codes);}catch(x){alert(x.message);}};
 document.getElementById("logout").onclick=logout;
}
function recovery(){
 app.innerHTML='<h1>Confirm recovery code</h1><p>Enter one saved recovery code. It will be used up after confirmation.</p><form id="recover" novalidate><label for="backup">Recovery code</label><input id="backup" name="code" autocomplete="one-time-code" autocapitalize="characters" required><p class="error" role="alert"></p><button>Confirm recovery code</button></form><button class="linkbutton" id="cancel">Back to MFA status</button>';
 document.getElementById("cancel").onclick=status;
 document.getElementById("recover").onsubmit=async e=>{e.preventDefault();const f=e.currentTarget;error(f,"");try{await api("/api/backup/verify","POST",{code:f.code.value});app.innerHTML='<h1>Recovery code confirmed</h1><p class="success">That recovery code has been used and cannot be used again.</p><button id="continue">Return to MFA status</button>';document.getElementById("continue").onclick=status;}catch(x){error(f,x.message);}};
}
async function logout(){try{await api("/api/logout","POST",{});}catch(e){}csrf="";state={authenticated:false,stage:"anonymous",mfaEnabled:false};signIn();}
async function boot(){try{const r=await api("/api/bootstrap");state=r;if(r.authenticated){r.mfaEnabled?status():setup();}else if(r.stage==="identity")identity();else signIn();}catch(e){app.textContent="Unable to start secure enrolment.";}}
boot();
})();
</script>
</body></html>`;
}

async function handleApi(request: Request, url: URL) {
  if (request.method === "OPTIONS") {
    if (!allowedOrigin(request)) return genericError(request, 403);
    return new Response(null, { status: 204, headers: headers(request) });
  }
  if (!allowedOrigin(request)) return genericError(request, 403);

  if (url.pathname === "/api/bootstrap" && request.method === "GET") {
    let session = activeSession(request);
    if (!session) session = newSession("anonymous");
    const user = session.userId ? users.get(session.userId) : undefined;
    return json(request, responseSession(session, user), 200, { "Set-Cookie": sessionCookie(session.id) });
  }

  if (url.pathname === "/api/auth/signin" && request.method === "POST") {
    const session = activeSession(request);
    if (!csrfOk(request, session)) return genericError(request, 403);
    const body = await bodyOf(request);
    const email = normalizeEmail(body?.email);
    const phone = normalizePhone(body?.phone);
    const destination = body?.destination;
    if (!email || phone === null || (destination !== undefined && destination !== "/")) return genericError(request);

    /* Generic stage/response is retained whether or not this normalized identity is approved. */
    const account = approvedAccount(email, phone);
    const rotated = rotateSession(session!, "identity");
    rotated.pendingUserId = account?.id;
    const identityCode = await identityCodeFor(rotated.id, rotated.pendingUserId);
    rotated.identityHash = await protectedHash(identityCode);
    rotated.identityExpires = Date.now() + CODE_LIFETIME_MS;
    return json(request, { ...responseSession(rotated), testCode: identityCode }, 200, {
      "Set-Cookie": sessionCookie(rotated.id),
    });
  }

  if (url.pathname === "/api/auth/identity" && request.method === "POST") {
    const session = activeSession(request);
    if (!csrfOk(request, session) || session!.stage !== "identity") return genericError(request, 403);
    const body = await bodyOf(request);
    const code = normalizeOtp(body?.code);
    const validCode = !!code &&
      !locked(session!.identityLockedUntil) &&
      !session!.identityUsed &&
      !!session!.identityExpires &&
      session!.identityExpires >= Date.now() &&
      !!session!.identityHash &&
      await protectedHash(code) === session!.identityHash;

    if (!validCode || !session!.pendingUserId) {
      session!.identityFailures++;
      if (session!.identityFailures >= MAX_FAILURES) session!.identityLockedUntil = Date.now() + LOCK_MS;
      return genericError(request);
    }

    /* Requirement 1/5: authenticated session is created only for this exact approved pending account. */
    const account = approvedAccounts.find((item) => item.id === session!.pendingUserId);
    if (!account) return genericError(request);
    session!.identityUsed = true;
    const user = userForApprovedAccount(account);
    const rotated = rotateSession(session!, "authenticated", user.id);
    return json(request, responseSession(rotated, user), 200, { "Set-Cookie": sessionCookie(rotated.id) });
  }

  const auth = authenticated(request);
  if (!auth) return genericError(request, 401);

  if (url.pathname === "/api/mfa/status" && request.method === "GET") {
    return json(request, responseSession(auth.session, auth.user));
  }

  if (url.pathname === "/api/mfa/begin" && request.method === "POST") {
    if (!csrfOk(request, auth.session) || !(await bodyOf(request))) return genericError(request, 403);
    const secret = base32(crypto.getRandomValues(new Uint8Array(20)));
    const testCounter = currentTotpCounter();
    const testCode = await totpForCounter(secret, testCounter);
    auth.user.encryptedTotp = await encryptSecret(secret);
    auth.user.pendingTotpExpires = Date.now() + CODE_LIFETIME_MS;
    auth.user.pendingTotpUsed = false;
    auth.user.acceptedTotpCounters = new Set();
    auth.user.totpFailures = 0;
    auth.user.totpLockedUntil = undefined;
    return json(request, {
      ok: true,
      csrf: auth.session.csrf,
      manualSecret: secret,
      testCode,
      testCounter,
      testWindowSeconds: TOTP_STEP_SECONDS,
    });
  }

  if (url.pathname === "/api/mfa/verify" && request.method === "POST") {
    if (!csrfOk(request, auth.session)) return genericError(request, 403);
    const body = await bodyOf(request);
    const code = normalizeOtp(body?.code);
    let acceptedCounter: number | undefined;

    if (code && auth.user.encryptedTotp && !locked(auth.user.totpLockedUntil) &&
      !auth.user.pendingTotpUsed && auth.user.pendingTotpExpires && auth.user.pendingTotpExpires >= Date.now()) {
      try {
        const secret = await decryptSecret(auth.user.encryptedTotp);
        const current = currentTotpCounter();
        for (let offset = -TOTP_WINDOW_STEPS; offset <= TOTP_WINDOW_STEPS; offset++) {
          const counter = current + offset;
          if (counter >= 0 && !auth.user.acceptedTotpCounters.has(counter) && await totpForCounter(secret, counter) === code) {
            acceptedCounter = counter;
            break;
          }
        }
      } catch {
        acceptedCounter = undefined;
      }
    }

    if (acceptedCounter === undefined) {
      auth.user.totpFailures++;
      if (auth.user.totpFailures >= MAX_FAILURES) auth.user.totpLockedUntil = Date.now() + LOCK_MS;
      return genericError(request);
    }

    /* Requirement 5: the accepted standards-based TOTP time-step cannot be reused. */
    auth.user.acceptedTotpCounters.add(acceptedCounter);
    auth.user.pendingTotpUsed = true;
    auth.user.mfaEnabled = true;
    auth.user.totpFailures = 0;
    const codes = Array.from({ length: 8 }, backupCode);
    auth.user.backupHashes = new Set(await Promise.all(codes.map(protectedHash)));
    return json(request, { ok: true, csrf: auth.session.csrf, mfaEnabled: true, codes });
  }

  if (url.pathname === "/api/backup/verify" && request.method === "POST") {
    if (!csrfOk(request, auth.session)) return genericError(request, 403);
    const body = await bodyOf(request);
    const code = normalizeBackup(body?.code);
    const hash = code ? await protectedHash(code) : "";
    if (!auth.user.mfaEnabled || !code || locked(auth.user.backupLockedUntil) || !auth.user.backupHashes.has(hash)) {
      auth.user.backupFailures++;
      if (auth.user.backupFailures >= MAX_FAILURES) auth.user.backupLockedUntil = Date.now() + LOCK_MS;
      return genericError(request);
    }
    auth.user.backupHashes.delete(hash);
    auth.user.backupFailures = 0;
    return json(request, { ok: true, csrf: auth.session.csrf });
  }

  if (url.pathname === "/api/backup/regenerate" && request.method === "POST") {
    if (!csrfOk(request, auth.session) || !(await bodyOf(request)) || !auth.user.mfaEnabled) return genericError(request, 403);
    const codes = Array.from({ length: 8 }, backupCode);
    auth.user.backupHashes = new Set(await Promise.all(codes.map(protectedHash)));
    return json(request, { ok: true, csrf: auth.session.csrf, codes });
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    if (!csrfOk(request, auth.session) || !(await bodyOf(request))) return genericError(request, 403);
    sessions.delete(auth.session.id);
    return json(request, { ok: true }, 200, { "Set-Cookie": clearCookie() });
  }
  return genericError(request, 404);
}

async function fetch(request: Request) {
  try {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return await handleApi(request, url);
    if (url.pathname === "/" && request.method === "GET") {
      /* Requirement 2: a cryptographically random nonce is unique to this HTML response. */
      const nonce = randomToken(18);
      return new Response(page(nonce), {
        status: 200,
        headers: headers(request, { "Content-Type": "text/html; charset=utf-8" }, nonce),
      });
    }
    return genericError(request, 404);
  } catch {
    return genericError(request, 500);
  }
}

/* Requirement 2/3: HTTPS is primary. The companion HTTP listener only redirects to the trusted TLS origin. */
const certPath = "certs/cert.pem";
const keyPath = "certs/key.pem";
if (!existsSync(certPath) || !existsSync(keyPath)) {
  throw new Error("TLS certificates are required at certs/cert.pem and certs/key.pem.");
}

Bun.serve({
  port: PORT,
  tls: { cert: readFileSync(certPath), key: readFileSync(keyPath) },
  fetch,
});

Bun.serve({
  port: HTTP_PORT,
  fetch(request) {
    const url = new URL(request.url);
    const target = `https://localhost:${PORT}${url.pathname}${url.search}`;
    return new Response(null, { status: 308, headers: { Location: target, "Cache-Control": "no-store" } });
  },
});

console.log(`MFA demo available securely at https://localhost:${PORT}`);
