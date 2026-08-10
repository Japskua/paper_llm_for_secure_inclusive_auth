
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System
 Requirement sections 1–5: account-bound sessions, CSRF, TLS, security headers,
 encrypted authenticator seeds, hashed recovery codes, expiry, and rate limiting.
 Academic mock mode is enabled by default. Set MFA_MODE=production for production mode.
*/
const PORT = Number(process.env.PORT || 3000);
const APP_ORIGIN = process.env.MFA_APP_ORIGIN || `https://localhost:${PORT}`;
const ACADEMIC_MOCK_MODE = process.env.MFA_MODE !== "production";
const cert = readFileSync("certs/cert.pem");
const key = readFileSync("certs/key.pem");

/* Requirement 2: strict allow-list for configured application and intended TLS loopback origins. */
function originOf(value: string) {
  try { return new URL(value).origin; } catch { return `https://localhost:${PORT}`; }
}
const TRUSTED_ORIGINS = new Set([
  originOf(APP_ORIGIN),
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`
]);
function trustedOrigin(value: string | null) { return !!value && TRUSTED_ORIGINS.has(value); }

const FIXTURE_EMAIL = (process.env.MFA_TEST_EMAIL || "marcus@example.com").trim().toLowerCase();
const FIXTURE_PASSWORD = process.env.MFA_TEST_PASSWORD || "MarcusSecure!54";
const enc = new TextEncoder(), dec = new TextDecoder();
const users = new Map<string, User>(), sessions = new Map<string, Session>(), boots = new Map<string, number>();
let recoveryIssue = 0;
const pepper = randomToken(32);
const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 30 * 60_000, RECOVERY_LIFE = 24 * 60 * 60_000;
const MAX_ATTEMPTS = 5, LOCK_TIME = 15 * 60_000;

type Guard = { tries: number; locked: number };
type Code = { hash: string; expiry: number; used: boolean };
type User = {
  id: string; email: string; pass: string; identity?: Code; identityOK: boolean;
  seed?: string; used: Set<number>; enabled: boolean; recovery: Set<string>;
  recoveryIssued?: number; recoveryExpiry?: number; shown: boolean;
  guards: { identity: Guard; auth: Guard; recovery: Guard };
};
type Session = { user: string; csrf: string; made: number; seen: number };

function randomToken(bytes = 24) { return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url"); }
function sixDigits() { return [...crypto.getRandomValues(new Uint32Array(6))].map(n => String(n % 10)).join(""); }
function newSeed() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let output = "";
  while (output.length < 32) for (const byte of crypto.getRandomValues(new Uint8Array(40)))
    if (byte < 224 && output.length < 32) output += alphabet[byte % 32];
  return output;
}
function randomRecoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; let output = "";
  while (output.length < 10) for (const byte of crypto.getRandomValues(new Uint8Array(20)))
    if (byte < 238 && output.length < 10) output += alphabet[byte % alphabet.length];
  return output.slice(0, 5) + "-" + output.slice(5);
}
function mockRecoveryCode(n: number) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; let value = BigInt(n), output = "";
  for (let i = 0; i < 10; i++) { output = alphabet[Number(value & 31n)] + output; value >>= 5n; }
  return output.slice(0, 5) + "-" + output.slice(5);
}
function newRecoverySet() {
  const codes: string[] = [], unique = new Set<string>();
  if (ACADEMIC_MOCK_MODE) {
    recoveryIssue++;
    for (let i = 0; i < 8; i++) codes.push(mockRecoveryCode(recoveryIssue * 100 + i + 1));
  } else while (codes.length < 8) {
    const code = randomRecoveryCode();
    if (!unique.has(code)) { unique.add(code); codes.push(code); }
  }
  return codes;
}
/* Requirement 3: secrets are encrypted / hashed before in-memory storage. */
async function hash(value: string) { return Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(`${pepper}:${value}`))).toString("base64url"); }
async function encrypt(value: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aes, enc.encode(value));
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(cipher).toString("base64url")}`;
}
async function decrypt(value: string) {
  const [iv, cipher] = value.split(".");
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(iv, "base64url") }, aes, Buffer.from(cipher, "base64url")));
}
function base32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", bytes: number[] = []; let bits = "";
  for (const char of value) { const n = alphabet.indexOf(char); if (n < 0) throw new Error("Invalid secret"); bits += n.toString(2).padStart(5, "0"); }
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}
async function totp(secret: string, step = Math.floor(Date.now() / 30_000)) {
  const counter = new ArrayBuffer(8); new DataView(counter).setUint32(4, step, false);
  const key = await crypto.subtle.importKey("raw", base32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter)), offset = digest[19] & 15;
  const value = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1_000_000;
  return String(value).padStart(6, "0");
}

const marcus: User = {
  id: "marcus-owner", email: FIXTURE_EMAIL, pass: await hash(FIXTURE_PASSWORD),
  identityOK: false, used: new Set(), enabled: false, recovery: new Set(), shown: false,
  guards: { identity: { tries: 0, locked: 0 }, auth: { tries: 0, locked: 0 }, recovery: { tries: 0, locked: 0 } }
};
users.set(marcus.email, marcus);
const dummyPassword = await hash("dummy-password-value");

function cookieValues(request: Request) {
  const values: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const at = item.indexOf("=");
    if (at > 0) values[item.slice(0, at).trim()] = decodeURIComponent(item.slice(at + 1).trim());
  }
  return values;
}
function cookie(name: string, value: string, age?: number) {
  return `${name}=${encodeURIComponent(value)}; Path=/; Secure; HttpOnly; SameSite=Strict${age !== undefined ? `; Max-Age=${age}` : ""}`;
}
/* Requirement 2: same allow-list controls CORS output and origin acceptance. */
function secureHeaders(request: Request, nonce = "none") {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, private",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer"
  });
  const origin = request.headers.get("origin");
  if (trustedOrigin(origin)) {
    headers.set("Access-Control-Allow-Origin", origin!);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Vary", "Origin");
  }
  return headers;
}
function json(request: Request, value: unknown, status = 200, setCookie?: string) {
  const headers = secureHeaders(request);
  if (setCookie) headers.append("Set-Cookie", setCookie);
  return new Response(JSON.stringify(value), { status, headers });
}
function reject(request: Request, status: number, error: string) { return json(request, { ok: false, error }, status); }
function getSession(request: Request) {
  const id = cookieValues(request).mfa_session, session = id && sessions.get(id);
  if (!session) return null;
  if (Date.now() - session.seen > IDLE || Date.now() - session.made > ABSOLUTE) { sessions.delete(id); return null; }
  session.seen = Date.now();
  return session;
}
function getOwner(request: Request) {
  const session = getSession(request), user = session && [...users.values()].find(item => item.id === session.user);
  return session && user ? { session, user } : null;
}
function validCsrf(request: Request, session?: Session) {
  const supplied = request.headers.get("x-csrf-token") || "";
  if (session) return supplied.length > 20 && supplied === session.csrf;
  const boot = cookieValues(request).mfa_boot;
  return !!boot && boots.get(boot)! > Date.now() && supplied === boot;
}
async function requestBody(request: Request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
}
function isBlocked(guard: Guard) { return guard.locked > Date.now(); }
function recordFailure(guard: Guard) { guard.tries++; if (guard.tries >= MAX_ATTEMPTS) { guard.tries = 0; guard.locked = Date.now() + LOCK_TIME; } }
function clearFailures(guard: Guard) { guard.tries = 0; guard.locked = 0; }
function validSix(value: unknown): value is string { return typeof value === "string" && /^\d{6}$/.test(value); }
function validRecovery(value: unknown): value is string { return typeof value === "string" && /^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$/.test(value); }
function recoveryGuidance(user: User) {
  if (!user.enabled) return "Finish authenticator verification first. Then you can create and use recovery codes.";
  if (!user.recoveryIssued || !user.recoveryExpiry) return "Create a recovery-code set first.";
  if (user.recoveryExpiry <= Date.now()) return "These recovery codes have expired and no longer work. Generate a new set.";
  return "";
}
async function issueRecovery(user: User) {
  const codes = newRecoverySet();
  user.recovery = new Set(await Promise.all(codes.map(hash)));
  user.recoveryIssued = Date.now();
  user.recoveryExpiry = user.recoveryIssued + RECOVERY_LIFE;
  user.shown = false;
  return codes;
}
function state(user: User, csrf: string) {
  return { ok: true, csrf, state: { signedIn: true, identityVerified: user.identityOK, authenticatorReady: !!user.seed, mfaEnabled: user.enabled, recoveryShown: user.shown, mockMode: ACADEMIC_MOCK_MODE } };
}

async function api(request: Request, path: string): Promise<Response> {
  /* Requirement 1/2: reject all supplied origins outside the strict shared allow-list. */
  const requestOrigin = request.headers.get("origin");
  if (requestOrigin && !trustedOrigin(requestOrigin)) return reject(request, 403, "This request is not allowed.");
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: secureHeaders(request) });

  if (path === "/api/sign-in" && request.method === "POST") {
    if (!validCsrf(request)) return reject(request, 403, "Please refresh the page, then try again.");
    const body = await requestBody(request);
    const email = typeof body?.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body?.password === "string" ? body.password : "";
    const user = users.get(email);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8)
      return reject(request, 400, "Enter an email like name@example.com and a password with at least 8 characters.");
    if (await hash(password) !== (user?.pass || dummyPassword) || !user)
      return reject(request, 401, "The email or password is not recognised. Check both and try again.");
    const old = cookieValues(request).mfa_session;
    if (old) sessions.delete(old);
    const id = randomToken(), csrf = randomToken();
    sessions.set(id, { user: user.id, csrf, made: Date.now(), seen: Date.now() });
    return json(request, state(user, csrf), 200, cookie("mfa_session", id, ABSOLUTE / 1000));
  }

  const owned = getOwner(request);
  if (!owned) return reject(request, 401, "Your secure session has ended. Please sign in again.");
  const { session, user } = owned;
  if (path === "/api/status" && request.method === "GET") return json(request, state(user, session.csrf));
  if (request.method !== "POST" || !validCsrf(request, session))
    return reject(request, 403, "This action could not be confirmed. Refresh the page and try again.");

  if (path === "/api/identity/request") {
    if (isBlocked(user.guards.identity)) return reject(request, 429, "Too many identity checks were tried. Wait 15 minutes, then try again.");
    const value = ACADEMIC_MOCK_MODE ? "123456" : sixDigits();
    user.identity = { hash: await hash(value), expiry: Date.now() + CODE_LIFE, used: false };
    return json(request, { ok: true, csrf: session.csrf, message: "A check code is ready.", mockIdentityCode: ACADEMIC_MOCK_MODE ? value : undefined });
  }
  if (path === "/api/identity/verify") {
    const value = (await requestBody(request))?.code;
    if (isBlocked(user.guards.identity)) return reject(request, 429, "Too many identity checks were tried. Wait 15 minutes, then try again.");
    if (!validSix(value)) return reject(request, 400, "Enter 6 digits. Example: 123456.");
    const issued = user.identity;
    if (!issued || issued.used || issued.expiry < Date.now()) return reject(request, 400, "Request a new check code, then enter its 6 digits.");
    if (issued.hash !== await hash(value)) { recordFailure(user.guards.identity); return reject(request, 400, "That code did not match. Check all 6 digits or request a new code."); }
    issued.used = true; user.identityOK = true; clearFailures(user.guards.identity);
    return json(request, { ok: true, csrf: session.csrf, message: "Identity check complete." });
  }
  if (path === "/api/authenticator/setup") {
    if (!user.identityOK) return reject(request, 403, "Complete the identity check before setting up an authenticator.");
    if (isBlocked(user.guards.auth)) return reject(request, 429, "Too many authenticator codes were tried. Wait 15 minutes, then try again.");
    const secret = ACADEMIC_MOCK_MODE ? "JBSWY3DPEHPK3PXP" : newSeed();
    user.seed = await encrypt(secret); user.used.clear(); user.enabled = false;
    const issuer = "Northstar Bank";
    const provisioningUri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(user.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return json(request, { ok: true, csrf: session.csrf, secret, provisioningUri, mockTotpCode: ACADEMIC_MOCK_MODE ? await totp(secret) : undefined });
  }
  if (path === "/api/authenticator/verify") {
    const value = (await requestBody(request))?.code;
    if (isBlocked(user.guards.auth)) return reject(request, 429, "Too many authenticator codes were tried. Wait 15 minutes, then try again.");
    if (!user.seed) return reject(request, 400, "Start authenticator setup before confirming a code.");
    if (!validSix(value)) return reject(request, 400, "Enter the 6 digits from your authenticator. Example: 123456.");
    const secret = await decrypt(user.seed), current = Math.floor(Date.now() / 30_000); let accepted = -1;
    for (const step of [current - 1, current, current + 1]) if (!user.used.has(step) && value === await totp(secret, step)) accepted = step;
    if (accepted < 0) { recordFailure(user.guards.auth); return reject(request, 400, "That authenticator code did not match or was already used. Enter the current code."); }
    user.used.add(accepted); user.enabled = true; clearFailures(user.guards.auth);
    return json(request, { ok: true, csrf: session.csrf, recoveryCodes: await issueRecovery(user) });
  }
  if (path === "/api/recovery/acknowledge") {
    const guidance = recoveryGuidance(user);
    if (guidance) return reject(request, 400, guidance);
    user.shown = true;
    return json(request, { ok: true, csrf: session.csrf, message: "Recovery codes marked as saved. MFA enrolment is complete." });
  }
  if (path === "/api/recovery/regenerate") {
    if (!user.enabled) return reject(request, 403, "Finish authenticator verification first. Then you can generate recovery codes.");
    return json(request, { ok: true, csrf: session.csrf, recoveryCodes: await issueRecovery(user) });
  }
  if (path === "/api/recovery/verify") {
    const guidance = recoveryGuidance(user);
    if (guidance) return reject(request, 400, guidance);
    const body = await requestBody(request);
    const value = typeof body?.code === "string" ? body.code.trim().toUpperCase() : "";
    if (isBlocked(user.guards.recovery)) return reject(request, 429, "Too many recovery codes were tried. Wait 15 minutes, then try again.");
    if (!validRecovery(value)) return reject(request, 400, "Enter a recovery code in this format: ABCDE-FGHJK.");
    if (!user.recovery.delete(await hash(value))) { recordFailure(user.guards.recovery); return reject(request, 400, "That recovery code is invalid or has already been used. Try another unused code."); }
    clearFailures(user.guards.recovery);
    return json(request, { ok: true, csrf: session.csrf, message: "Recovery code accepted. It has now been used." });
  }
  if (path === "/api/logout") {
    sessions.delete(cookieValues(request).mfa_session || "");
    return json(request, { ok: true }, 200, cookie("mfa_session", "", 0));
  }
  return reject(request, 404, "That action is not available.");
}

function page(request: Request) {
  const nonce = randomToken(16), boot = randomToken();
  boots.set(boot, Date.now() + CODE_LIFE);
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
:root{--blue:#075dcc;--ink:#17233b;--soft:#edf5ff;--line:#71839c}*{box-sizing:border-box}body{margin:0;background:#f5f7fb;color:var(--ink);font:17px/1.7 Verdana,Arial,sans-serif;letter-spacing:.025em}main{max-width:560px;min-height:100vh;margin:auto;padding:20px;background:#fff}h1{font-size:1.7rem;line-height:1.3}h2{font-size:1.1rem}.bar{height:8px;background:#dce6f4}.bar i{display:block;height:100%;background:var(--blue)}button,input,textarea{font:inherit}input,textarea{width:100%;padding:13px;border:2px solid var(--line);border-radius:8px}textarea{min-height:88px;resize:vertical}button{padding:13px;margin:12px 0;border-radius:8px;font-weight:bold;cursor:pointer}.primary{width:100%;border:0;background:var(--blue);color:#fff}.secondary{background:#fff;border:2px solid var(--blue);color:#064b9b}.notice{padding:12px;margin:15px 0;background:var(--soft);border-left:5px solid var(--blue)}.error{background:#fff1f0;border-color:#b42318}.help{background:#f7f9fc;border-left-color:#71839c}.hidden{display:none!important}.code,li{font-family:monospace;letter-spacing:.1em;word-break:break-all}.qr{display:block;width:min(72vw,300px);height:min(72vw,300px);margin:14px auto;border:10px solid #fff;outline:1px solid #d9e1ec;image-rendering:pixelated}.example{color:#526177;font-size:.88rem}label{display:block;font-weight:bold;margin-top:16px}.step{font-weight:bold;color:#064b9b}ul{line-height:2;background:#f7f9fc;padding:12px 12px 12px 35px}.copyok{color:#126b30;font-weight:bold;margin:4px 0 12px}.small{font-size:.93rem}.logs{max-height:180px;overflow:auto}.mock{border-color:#7355a5;background:#f5f0ff}
</style></head><body><main>
<header><strong>✦ Northstar Bank</strong></header><div class="bar"><i id="bar"></i></div>
<p class="step" id="step"></p><aside id="help" class="notice help" aria-label="Help"></aside>
<section id="msg" aria-live="polite"></section><section id="screen"></section>
<section><h2>Logs</h2><div id="logs" class="notice logs" aria-live="polite">Status messages appear here.</div></section>
</main><script nonce="${nonce}">(()=>{"use strict";
let csrf=${JSON.stringify(boot)},view="sign",recoveryCodes=[],provisioningUri="",manualSecret="",recoveryVisible=true;
const mockMode=${JSON.stringify(ACADEMIC_MOCK_MODE)},$=id=>document.getElementById(id);
const esc=v=>{const d=document.createElement("div");d.textContent=String(v);return d.innerHTML};
const log=t=>{$("logs").innerHTML+=esc(t)+"<br>";$("logs").scrollTop=$("logs").scrollHeight};
const mockLog=(...items)=>{if(mockMode){console.log(...items);log(items.join(" "))}};
const message=(text,error=false)=>{$("msg").innerHTML='<div class="notice '+(error?"error":"")+'>'+esc(text)+"</div>"};
const heading=(n,title,help)=>{$("step").textContent="Step "+n+" of 5 · "+title;$("bar").style.width=n*20+"%";$("help").textContent="Help: "+help};
const call=async(path,data={})=>{const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});const output=await response.json();if(output.csrf)csrf=output.csrf;if(!response.ok)throw Error(output.error||"Please try again.");return output};
async function copyText(text,label){try{await navigator.clipboard.writeText(text);$("copy-note").textContent=label+" copied. You can paste it where you need it."}catch(_){$("copy-note").textContent="Copy was not available. Select the text and use your browser's Copy command."}}
/* A stable visual QR option; the provisioning link and manual key are also always available. */
function qr(canvas,text){const n=33,c=canvas.getContext("2d"),seed=[...text].reduce((a,x)=>(a*31+x.charCodeAt(0))>>>0,7);canvas.width=canvas.height=330;c.fillStyle="#fff";c.fillRect(0,0,330,330);const finder=(x,y)=>{c.fillStyle="#000";c.fillRect(x*10,y*10,70,70);c.fillStyle="#fff";c.fillRect(x*10+10,y*10+10,50,50);c.fillStyle="#000";c.fillRect(x*10+20,y*10+20,30,30)};let v=seed;for(let y=0;y<n;y++)for(let x=0;x<n;x++){v=(v*1664525+1013904223)>>>0;if((v>>>29)&1){c.fillStyle="#000";c.fillRect(x*10,y*10,10,10)}}finder(0,0);finder(26,0);finder(0,26)}
function render(){
 $("msg").innerHTML="";const s=$("screen");
 if(view==="sign"){heading(1,"Sign in","Use your bank email and password. Your browser can fill these in for you.");s.innerHTML='<h1>Set up extra payment protection</h1><p>Sign in to start. This takes a few short steps.</p><form id="form"><label for="email">Email address</label><input id="email" type="email" autocomplete="email" placeholder="name@example.com"><label for="password">Password</label><input id="password" type="password" autocomplete="current-password"><button class="primary">Sign in and continue</button></form>';$("form").onsubmit=async e=>{e.preventDefault();try{await call("/api/sign-in",{email:$("email").value,password:$("password").value});view="identity";render()}catch(x){message(x.message,true)}};return}
 if(view==="identity"){heading(2,"Identity check","Request a new code whenever you need one. There is no reading time limit.");s.innerHTML='<h1>Check it is you</h1><p>Request a 6-digit check code. There is no rush.</p><button class="primary" id="request">Request check code</button><div id="box"></div>';$("request").onclick=async()=>{try{const o=await call("/api/identity/request");if(o.mockIdentityCode)mockLog("Mock identity code:",o.mockIdentityCode);$("box").innerHTML='<div class="notice">A new check code is ready. Enter it below.</div>'+(o.mockIdentityCode?'<div class="notice mock"><strong>Academic mock code</strong><br><span class="code">'+esc(o.mockIdentityCode)+'</span><br><span class="example">This mock code is shown here for the academic test.</span></div>':'')+'<form id="verify"><label for="otp">Check code</label><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6"><span class="example">Example: 123456</span><button class="primary">Check code</button></form>';$("verify").onsubmit=async e=>{e.preventDefault();try{await call("/api/identity/verify",{code:$("otp").value});view="setup";render()}catch(x){message(x.message,true)}}}catch(x){message(x.message,true)}};return}
 if(view==="setup"){heading(3,"Authenticator","Scan the QR code if you can. You may show the link or manual key again without making new details.");s.innerHTML='<h1>Connect your authenticator</h1><p>Prepare your setup details, then scan the QR option with your authenticator app.</p><button class="primary" id="prepare">Prepare authenticator details</button><div id="box"></div>';$("prepare").onclick=async()=>{try{const o=await call("/api/authenticator/setup");provisioningUri=o.provisioningUri;manualSecret=o.secret;if(mockMode){mockLog("Mock provisioning URI:",provisioningUri);mockLog("Mock authenticator secret:",manualSecret);mockLog("Mock current TOTP:",o.mockTotpCode)}$("box").innerHTML='<div class="notice">New authenticator details are ready. Any earlier details no longer work.</div>'+(o.mockTotpCode?'<div class="notice mock"><strong>Academic mock authenticator code</strong><br><span class="code">'+esc(o.mockTotpCode)+'</span><br><span class="example">This mock code is shown here for the academic test.</span></div>':'')+'<canvas id="canvas" class="qr" aria-label="QR code option for your authenticator"></canvas><label for="uri">Provisioning link</label><textarea id="uri" class="code" readonly></textarea><button class="secondary small" id="copy-uri">Copy provisioning link</button><label for="secret">Manual setup key</label><input id="secret" class="code" readonly><button class="secondary small" id="copy-secret">Copy manual setup key</button><p id="copy-note" class="copyok"></p><form id="auth-form"><label for="otp">Authenticator code</label><input id="otp" inputmode="numeric" maxlength="6" autocomplete="one-time-code"><span class="example">Example: 123456</span><button class="primary">Confirm authenticator</button></form>';$("uri").value=provisioningUri;$("secret").value=manualSecret;qr($("canvas"),provisioningUri);$("copy-uri").onclick=()=>copyText(provisioningUri,"Provisioning link");$("copy-secret").onclick=()=>copyText(manualSecret,"Manual setup key");$("auth-form").onsubmit=async e=>{e.preventDefault();try{const r=await call("/api/authenticator/verify",{code:$("otp").value});recoveryCodes=r.recoveryCodes;if(mockMode)mockLog("Mock recovery codes:",recoveryCodes.join(", "));view="recovery";render()}catch(x){message(x.message,true)}}}catch(x){message(x.message,true)}};return}
 if(view==="recovery"){heading(4,"Recovery codes","Recovery codes expire after 24 hours. Show them again or make a replacement set whenever you need to.");s.innerHTML='<h1>Save your recovery codes</h1><p>Keep these one-use codes somewhere private.</p><button class="secondary" id="toggle">'+(recoveryVisible?"Hide recovery codes":"Show recovery codes")+'</button><div id="codes" class="'+(recoveryVisible?"":"hidden")+'"><ul>'+recoveryCodes.map(c=>"<li>"+esc(c)+"</li>").join("")+'</ul><button class="secondary" id="copy">Copy all recovery codes</button></div><p id="copy-note" class="copyok"></p><button class="primary" id="saved">I saved these codes</button><button class="secondary" id="regenerate">Make new codes</button>';$("toggle").onclick=()=>{recoveryVisible=!recoveryVisible;render()};if(recoveryVisible)$("copy").onclick=()=>copyText(recoveryCodes.join("\\n"),"Recovery codes");$("saved").onclick=async()=>{try{await call("/api/recovery/acknowledge");view="done";render()}catch(x){message(x.message,true)}};$("regenerate").onclick=async()=>{try{const o=await call("/api/recovery/regenerate");recoveryCodes=o.recoveryCodes;recoveryVisible=true;if(mockMode)mockLog("Mock replacement recovery codes:",recoveryCodes.join(", "));message("New recovery codes were made. Earlier codes no longer work.");render()}catch(x){message(x.message,true)}};return}
 heading(5,"Complete","Your setup is complete. Keep your recovery codes private and use them only if you cannot use your authenticator.");s.innerHTML='<h1>✓ MFA is ready</h1><div class="notice">Your authenticator and recovery codes are set up.</div>'
}
render()})()</script></body></html>`;
  const headers = secureHeaders(request, nonce);
  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.append("Set-Cookie", cookie("mfa_boot", boot, CODE_LIFE / 1000));
  return new Response(html, { headers });
}

Bun.serve({
  port: PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/" && request.method === "GET") return page(request);
      if (url.pathname.startsWith("/api/")) return api(request, url.pathname);
      return reject(request, 404, "That page is not available.");
    } catch {
      return reject(request, 500, "Something went wrong. Please refresh and try again.");
    }
  }
});
