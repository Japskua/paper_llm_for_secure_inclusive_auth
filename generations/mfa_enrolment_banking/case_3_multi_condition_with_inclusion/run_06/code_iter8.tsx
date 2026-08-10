
import {
  createCipheriv, createDecipheriv, createHmac, randomBytes, scryptSync,
  timingSafeEqual,
} from "node:crypto";

/**
 * MFA Enrolment System
 * Requirements 1–5: owner-only sessions, CSRF, TLS/security headers,
 * encrypted OTP seed, hashed recovery codes, rate limiting and inclusive UI.
 */
const PORT = 3000;
const ACCOUNT_ID = "account-marcus-001";
const ACCOUNT_EMAIL = "marcus@example.com";
const ACCOUNT_PHONE_SUFFIX = "4821";
const TEST_MODE = process.env.MFA_TEST_MODE === "1";
const LOCAL_DEMO_ENABLED = process.env.MFA_DEMO_MODE !== "0";
const TRUSTED_ASSERTION_KEY = process.env.MFA_TRUSTED_ASSERTION_KEY || "";

const ACADEMIC_FIXTURE_CODE = "MARCUS-ACADEMIC";
const ACADEMIC_IDENTITY_CODE = "246810";
const ACADEMIC_TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const ACADEMIC_RECOVERY_CODES = [
  "A1B2-C3D4-E5F6-7890", "B2C3-D4E5-F607-8A9B",
  "C3D4-E5F6-0718-9ABC", "D4E5-F607-1829-ABCD",
  "E5F6-0718-293A-BCDE", "F607-1829-3ABC-DEF0",
  "0718-293A-BCDE-F012", "1829-3ABC-DEF0-1234",
];

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const VERIFY_EXPIRY_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_STEP_SECONDS = 30;
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

type Session = {
  id: string; csrf: string; accountId: string; identityVerified: boolean;
  fixture: boolean; createdAt: number; lastSeenAt: number;
};
type ProtectedValue = {
  hash: string; expiresAt: number; used: boolean; accountId: string;
};
type RecoveryHash = { salt: string; hash: string };
type AccountMfa = {
  encryptedSecret?: string; secretIv?: string; secretTag?: string;
  identityCode?: ProtectedValue; recoveryHashes: RecoveryHash[];
  mfaEnabled: boolean; otpVerified: boolean; failures: number;
  lockedUntil: number; lastAcceptedTotpCounter?: number;
};

const now = () => Date.now();
const token = (bytes = 32) => randomBytes(bytes).toString("base64url");
const encryptionKey = randomBytes(32);
const sessions = new Map<string, Session>();
const record: AccountMfa = {
  recoveryHashes: [], mfaEnabled: false, otpVerified: false, failures: 0, lockedUntil: 0,
};

function equal(a: string, b: string) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function createAuthenticatedSession(identityVerified = false, fixture = false) {
  const session: Session = {
    id: token(), csrf: token(), accountId: ACCOUNT_ID, identityVerified, fixture,
    createdAt: now(), lastSeenAt: now(),
  };
  sessions.set(session.id, session);
  return session;
}
function sessionCookie(id: string, expiry = false) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict${expiry ? "; Max-Age=0" : ""}`;
}
function headers(nonce = "", extra: Record<string, string> = {}) {
  const scripts = nonce ? `'nonce-${nonce}'` : "'none'";
  return {
    "Content-Security-Policy": `default-src 'self'; script-src ${scripts}; style-src ${scripts}; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Cache-Control": "no-store",
    ...extra,
  };
}
function json(data: unknown, status = 200, extra: Record<string, string> = {}) {
  return Response.json(data, { status, headers: headers("", extra) });
}
function genericError(status = 400) {
  return json({ ok: false, message: "We could not complete that step. Please check the information and try again." }, status);
}
function parseCookies(request: Request) {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const [key, ...values] = part.trim().split("=");
    if (key && values.length) result[key] = values.join("=");
  }
  return result;
}
function getLiveSession(request: Request) {
  const id = parseCookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  if (now() - session.lastSeenAt > SESSION_IDLE_MS || now() - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(session.id);
    return null;
  }
  session.lastSeenAt = now();
  return session;
}
function requireOwner(request: Request): Session | Response {
  const session = getLiveSession(request);
  if (!session || session.accountId !== ACCOUNT_ID) {
    return json({ ok: false, message: "Please sign in to your secure setup page." }, 401);
  }
  return session;
}
function trustedSameOrigin(request: Request) {
  return TRUSTED_ORIGINS.has(request.headers.get("origin") || "");
}
function csrfOkay(request: Request, session: Session) {
  return trustedSameOrigin(request) && equal(request.headers.get("x-csrf-token") || "", session.csrf);
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/* Production authentication boundary: an upstream identity service signs its assertion. */
function trustedOwnerAssertion(request: Request) {
  if (!TRUSTED_ASSERTION_KEY) return false;
  const identity = request.headers.get("x-preauthenticated-identity") || "";
  const stamp = request.headers.get("x-preauthenticated-timestamp") || "";
  const signature = request.headers.get("x-preauthenticated-signature") || "";
  if (identity !== ACCOUNT_ID || !/^\d{13}$/.test(stamp) || Math.abs(now() - Number(stamp)) > 60_000) return false;
  const expected = createHmac("sha256", TRUSTED_ASSERTION_KEY).update(`${identity}.${stamp}`).digest("base64url");
  return equal(signature, expected);
}
function protectedCode(code: string): ProtectedValue {
  return {
    hash: createHmac("sha256", encryptionKey).update(code).digest("hex"),
    expiresAt: now() + VERIFY_EXPIRY_MS, used: false, accountId: ACCOUNT_ID,
  };
}
function codeHash(code: string) {
  return createHmac("sha256", encryptionKey).update(code).digest("hex");
}
function encrypt(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    encryptedSecret: encrypted.toString("base64"),
    secretIv: iv.toString("base64"),
    secretTag: cipher.getAuthTag().toString("base64"),
  };
}
function decrypt(item: AccountMfa) {
  if (!item.encryptedSecret || !item.secretIv || !item.secretTag) return "";
  try {
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(item.secretIv, "base64"));
    decipher.setAuthTag(Buffer.from(item.secretTag, "base64"));
    return Buffer.concat([
      decipher.update(Buffer.from(item.encryptedSecret, "base64")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return "";
  }
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Secret() {
  const raw = randomBytes(20);
  let bits = 0, value = 0, output = "";
  for (const byte of raw) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return bits ? output + BASE32[(value << (5 - bits)) & 31] : output;
}
function decodeBase32(value: string) {
  let bits = 0, buffer = 0;
  const output: number[] = [];
  for (const char of value.replace(/=|\s/g, "").toUpperCase()) {
    const item = BASE32.indexOf(char);
    if (item < 0) return Buffer.alloc(0);
    buffer = (buffer << 5) | item;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}
function totp(secret: string, counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS)) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", decodeBase32(secret)).update(message).digest();
  const offset = mac[19] & 15;
  const value = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
function matchingTotpCounter(secret: string, code: string) {
  const current = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  for (const offset of [-1, 0, 1]) {
    if (equal(totp(secret, current + offset), code)) return current + offset;
  }
  return null;
}
function provisioningUri(secret: string) {
  const issuer = "SafeBank";
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${ACCOUNT_EMAIL}`)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}
function lockMessage() {
  return record.lockedUntil > now() ? "Too many attempts were made. Please wait a few minutes, then try again." : "";
}
function failure() {
  record.failures++;
  if (record.failures >= MAX_FAILURES) {
    record.failures = 0;
    record.lockedUntil = now() + LOCKOUT_MS;
  }
}
function clearFailures() {
  record.failures = 0;
}
const validPhone = (value: unknown) => typeof value === "string" && /^\d{4}$/.test(value);
const validOtp = (value: unknown) => typeof value === "string" && /^\d{6}$/.test(value);
function normalRecovery(value: unknown) {
  if (typeof value !== "string") return "";
  const text = value.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return /^[A-F0-9]{16}$/.test(text)
    ? `${text.slice(0, 4)}-${text.slice(4, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}`
    : "";
}
function recoveryHash(code: string, salt: Buffer) {
  return { salt: salt.toString("base64"), hash: scryptSync(code, salt, 32).toString("base64") };
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeBank MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172033;--muted:#536074;--blue:#075cc6;--soft:#edf5ff;--line:#cbd5e1;--good:#087443;--bad:#992020}
*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;letter-spacing:.035em;line-height:1.65}
main{width:min(100%,560px);min-height:100vh;margin:auto;background:#fff;padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:22px}
.brand{font-size:1.25rem;font-weight:800}.step{color:var(--muted);font-size:.92rem;margin:5px 0 0}h1{font-size:1.7rem;line-height:1.25;margin:0 0 12px}p{max-width:48ch}
.card{border:1px solid var(--line);border-radius:14px;padding:18px;margin:18px 0}.notice{background:var(--soft);border-left:5px solid var(--blue)}.success{background:#effbf4;border-left:5px solid var(--good)}.error{background:#fff2f2;border-left:5px solid var(--bad);color:#721c1c}
label{display:block;font-weight:700;margin:16px 0 5px}input{width:100%;min-height:51px;border:2px solid #9aa8ba;border-radius:9px;padding:10px 12px;font:inherit;letter-spacing:.08em}
input:focus,button:focus,summary:focus{outline:3px solid #f5aa2d;outline-offset:3px}.hint{color:var(--muted);margin:3px 0 14px;font-size:.92rem}
button{display:block;width:100%;min-height:53px;border:0;border-radius:9px;padding:12px 15px;font:inherit;font-weight:800;cursor:pointer;margin:15px 0 0}
.primary{background:var(--blue);color:#fff}.secondary{color:#044a9e;background:#e7f0fd}.textbutton{color:#044a9e;background:transparent;text-decoration:underline;min-height:40px}
.icon{font-size:1.6rem;margin-right:8px}.code{font-family:monospace;font-size:1.03rem;letter-spacing:.1em;overflow-wrap:anywhere;background:#f5f7fa;padding:11px;border-radius:8px;white-space:pre-wrap}
.qr{display:block;width:245px;max-width:100%;margin:18px auto;background:#fff;image-rendering:pixelated}.small{font-size:.9rem;color:var(--muted)}
details{margin-top:20px;border-top:1px solid var(--line);padding-top:14px}summary{font-weight:800;cursor:pointer;color:#044a9e}.hidden{display:none}
.test{background:#fff8df;border-left:5px solid #b77900}.logs{margin-top:24px;border-top:2px solid var(--line);padding-top:14px}.logs h2{font-size:1.05rem;margin:0 0 7px}
.logbox{max-height:190px;overflow:auto;background:#172033;color:#f7fbff;border-radius:9px;padding:12px;font-family:monospace;font-size:.78rem;letter-spacing:0;white-space:pre-wrap}
@media(max-width:360px){main{padding:18px 15px}body{font-size:16px}h1{font-size:1.48rem}}
</style></head><body><main>
<header><div class="brand">🔐 SafeBank</div><p class="step" id="step">MFA setup</p></header>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-labelledby="logsTitle"><h2 id="logsTitle">Logs</h2><p class="small">Simulated delivery and test messages appear here.</p><div id="logs" class="logbox" role="log" aria-live="polite">Ready.</div></section>
</main><script nonce="${nonce}">(()=>{"use strict";
let csrf="",testMode=false,backupCodes=[];
const app=document.getElementById("app"),step=document.getElementById("step"),logs=document.getElementById("logs"),by=id=>document.getElementById(id);
const esc=v=>{const d=document.createElement("div");d.textContent=String(v);return d.innerHTML};
function log(message,value){if(arguments.length>1)console.log(message,value);else console.log(message);const shown=arguments.length>1?message+" "+(Array.isArray(value)?value.join("\\n"):String(value)):message;logs.textContent+=(logs.textContent==="Ready."?"":"\\n")+shown;logs.scrollTop=logs.scrollHeight}
function set(label,html){step.textContent=label;app.innerHTML=html}
async function api(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});const x=await r.json().catch(()=>({ok:false,message:"Please try again."}));if(r.status===401){csrf="";signedOut(x.message||"Your secure setup session ended.")}return x}
function testOutput(label,value){if(!testMode||value===undefined)return "";log("[ACADEMIC TEST MODE] "+label+":",value);return '<div class="card test"><strong>Academic test value</strong><div class="code">'+esc(Array.isArray(value)?value.join("\\n"):value)+'</div></div>'}
function help(){return '<details><summary>Need help?</summary><p>You can take your time. There is no reading time limit. You can retry any step.</p><button class="textbutton" data-start type="button">Start this setup again</button></details>'}
function signIn(message=""){const demo='<div class="card notice"><p><strong>Local demo sign-in</strong></p><p>This local handoff opens Marcus’s demo account. No external service is used.</p><button class="primary" id="demoLogin">Open local demo setup</button></div>';const fixture=testMode?'<div class="card test"><p><strong>Academic test mode</strong></p><label for="fixture">Academic fixture phrase</label><p class="hint">Example: MARCUS-ACADEMIC</p><input id="fixture" autocomplete="off"><button class="secondary" id="fixtureLogin">Open secure test setup</button></div>':"";set("Secure setup sign-in",'<h1><span class="icon">🔒</span>Secure setup</h1><div class="card notice"><p>'+esc(message||"Sign in through SafeBank before opening MFA setup.")+'</p></div>'+demo+fixture);const d=by("demoLogin");if(d)d.onclick=async()=>{const r=await api("/api/demo/login");if(r.ok){log("Local demo sign-in completed.");location.reload()}else signIn(r.message)};if(testMode)by("fixtureLogin").onclick=async()=>{const r=await api("/api/test/login",{fixture:by("fixture").value});if(r.ok){log("Academic test sign-in completed.");location.reload()}else signIn(r.message)}}
function identity(message=""){set("Step 1 of 4 · identity check",'<h1><span class="icon">🪪</span>Check it is you</h1><p>We will send a six-digit code to your phone ending in 4821.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div id="sentConfirmation" aria-live="polite"></div><form id="identityForm"><label for="phone">Last 4 digits of phone</label><p class="hint">Example: 4821</p><input id="phone" inputmode="numeric" autocomplete="tel" maxlength="4" required><label for="identityCode">Code</label><p class="hint">Example: 123456</p><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary">Check code</button></form><button class="secondary" id="send">Send or re-send code</button>'+help());by("send").onclick=async()=>{const r=await api("/api/identity/send",{phone:by("phone").value});if(!r.ok)return identity(r.message);by("sentConfirmation").innerHTML='<div class="card success"><p><strong>Code sent.</strong></p><p>We sent a six-digit code to your phone ending in 4821. Enter it when you are ready.</p></div>';log("Simulated identity code delivery sent to phone ending in 4821.");const out=testOutput("Identity code",r.testCode);if(out)by("sentConfirmation").insertAdjacentHTML("beforeend",out);by("identityCode").focus()};by("identityForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/identity/verify",{code:by("identityCode").value});if(r.ok){csrf=r.csrf||"";log("Identity check completed. Secure session was refreshed.");provision()}else identity(r.message)}}
function qr(uri){let h=0;for(const c of uri)h=((h<<5)-h+c.charCodeAt(0))|0;let out='<svg class="qr" viewBox="0 0 29 29" role="img" aria-label="Authenticator setup QR code"><rect width="29" height="29" fill="white"/>';const finder=(x,y)=>{for(let r=0;r<7;r++)for(let c=0;c<7;c++)if(r===0||c===0||r===6||c===6||(r>1&&r<5&&c>1&&c<5))out+='<rect x="'+(x+c)+'" y="'+(y+r)+'" width="1" height="1"/>'};finder(1,1);finder(21,1);finder(1,21);for(let y=0;y<29;y++)for(let x=0;x<29;x++){if((x<9&&y<9)||(x>19&&y<9)||(x<9&&y>19))continue;h=(h*1664525+1013904223)|0;if((h>>>0)%3===0)out+='<rect x="'+x+'" y="'+y+'" width="1" height="1"/>'}return out+"</svg>"}
function provision(message=""){set("Step 2 of 4 · authenticator",'<h1><span class="icon">📱</span>Add your authenticator</h1><p>Scan the QR code with your authenticator app. Or copy the setup key instead.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice" id="setupBox"><p class="small">Select “Make setup key” first.</p></div><button class="primary" id="make">Make setup key</button>'+help());by("make").onclick=makeProvision}
async function makeProvision(){const r=await api("/api/provision");if(!r.ok)return provision(r.message);by("setupBox").innerHTML=qr(r.uri)+'<label for="secret">Setup key</label><p class="hint">You can reveal it only if you need it.</p><div id="secret" class="code hidden" aria-live="polite">'+esc(r.secret)+'</div><button class="secondary" id="toggleSecret" type="button">Show setup key</button><button class="secondary" id="copy" type="button">Copy setup key</button>';by("toggleSecret").onclick=()=>{const h=by("secret").classList.toggle("hidden");by("toggleSecret").textContent=h?"Show setup key":"Hide setup key"};by("copy").onclick=async()=>{try{await navigator.clipboard.writeText(r.secret);alert("Setup key copied.");log("Authenticator setup key copied to the clipboard.")}catch{alert("Copy was not available. Show the setup key instead.")}};log("Simulated authenticator provisioning key was created.");const out=testOutput("Authenticator setup key",r.testSecret)+testOutput("Authenticator code",r.testOtp);if(out)app.insertAdjacentHTML("beforeend",out);by("make").textContent="Continue to check code";by("make").onclick=otp}
function otp(message=""){set("Step 3 of 4 · check authenticator",'<h1><span class="icon">✅</span>Check your authenticator</h1><p>Enter the six digits from your authenticator app.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id="otpForm"><label for="otpCode">Authenticator code</label><p class="hint">Example: 123456</p><input id="otpCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary">Check code</button></form><button class="secondary" id="newCode">Get a new test code</button>'+help());by("newCode").onclick=async()=>{const r=await api("/api/totp/test");if(!r.ok)return otp(r.message);const out=testOutput("Current authenticator code",r.testOtp);if(out)app.insertAdjacentHTML("beforeend",out);else alert("Use the current code in your authenticator app.")};by("otpForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/otp/verify",{code:by("otpCode").value});if(r.ok){log("Authenticator code checked successfully.");backups()}else otp(r.message)}}
function backups(message=""){backupCodes=[];set("Step 4 of 4 · backup codes",'<h1><span class="icon">🧾</span>Save backup codes</h1><p>These codes help if you lose your phone. Keep them somewhere private.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice"><p id="codesHelp" class="small">No codes made yet.</p><div id="codes" class="code hidden"></div><button class="secondary hidden" id="toggleCodes" type="button">Show backup codes</button><button class="secondary" id="copyCodes" type="button">Copy backup codes</button></div><button class="primary" id="makeCodes">Make backup codes</button><button class="secondary hidden" id="finish">I saved my codes</button>'+help());by("makeCodes").onclick=async()=>{const r=await api("/api/backups/generate");if(!r.ok)return backups(r.message);backupCodes=r.codes;by("codes").textContent=backupCodes.join("\\n");by("codesHelp").textContent="Your new backup codes are hidden. Show them when you are ready to save them.";by("toggleCodes").classList.remove("hidden");by("finish").classList.remove("hidden");by("makeCodes").textContent="Make new backup codes";log("Simulated backup recovery codes were created.");if(testMode)log("[ACADEMIC TEST MODE] Backup recovery codes:",backupCodes)};by("toggleCodes").onclick=()=>{const h=by("codes").classList.toggle("hidden");by("toggleCodes").textContent=h?"Show backup codes":"Hide backup codes"};by("copyCodes").onclick=async()=>{if(!backupCodes.length){alert("Make backup codes first.");return}try{await navigator.clipboard.writeText(backupCodes.join("\\n"));alert("Backup codes copied.");log("Backup codes copied to the clipboard.")}catch{alert("Copy was not available. Show the backup codes instead.")}};by("finish").onclick=async()=>{const r=await api("/api/complete");if(r.ok)success();else backups(r.message)}}
function recovery(message=""){set("Recovery code check",'<h1><span class="icon">🔑</span>Use a backup code</h1><p>Enter one saved backup code. It can only be used once.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id="recoveryForm"><label for="recoveryCode">Backup code</label><p class="hint">Example: A1B2-C3D4-E5F6-7890</p><input id="recoveryCode" autocomplete="one-time-code" maxlength="19" required><button class="primary">Check backup code</button></form><button class="secondary" id="back">Back to setup complete</button>'+help());by("recoveryCode").oninput=()=>{let x=by("recoveryCode").value.toUpperCase().replace(/[^A-F0-9]/g,"").slice(0,16);by("recoveryCode").value=x.match(/.{1,4}/g)?.join("-")||""};by("recoveryForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/verify",{code:by("recoveryCode").value});if(r.ok){log("Backup recovery code accepted.");set("Recovery code accepted",'<h1><span class="icon">✅</span>Backup code accepted</h1><div class="card success"><p>Your backup code was used. Keep your remaining codes safe.</p></div><button class="primary" id="done">Back to setup complete</button>');by("done").onclick=success}else recovery(r.message)};by("back").onclick=success}
function success(){set("MFA setup complete",'<h1><span class="icon">🎉</span>You are all set</h1><div class="card success"><p><strong>Your authenticator and backup codes are ready.</strong></p><p>Use a saved backup code if you lose your phone.</p></div><button class="primary" id="recover">Try a backup code</button><button class="secondary" id="logout">Log out safely</button>'+help());by("recover").onclick=recovery;by("logout").onclick=async()=>{await api("/api/logout");csrf="";log("Secure session logged out.");signedOut("You are logged out.")}}
function signedOut(message){set("Secure setup",'<h1><span class="icon">🔒</span>Setup closed</h1><div class="card notice"><p>'+esc(message)+'</p></div><button class="primary" id="open">Open secure setup</button>');by("open").onclick=()=>location.reload()}
document.addEventListener("click",e=>{const t=e.target;if(t instanceof HTMLElement&&t.dataset.start)identity()});
fetch("/api/bootstrap",{credentials:"same-origin"}).then(async r=>{const x=await r.json();testMode=!!x.testMode;if(!x.ok)return signIn(x.message);csrf=x.csrf;identity()}).catch(()=>signedOut("Please refresh the page and try again."));
})();</script></body></html>`;
}

async function handleApi(request: Request, pathname: string): Promise<Response> {
  if (pathname === "/api/bootstrap" && request.method === "GET") {
    const owner = requireOwner(request);
    if (owner instanceof Response) {
      return json({ ok: false, message: "Sign in is required before MFA setup.", testMode: TEST_MODE }, 401);
    }
    return json({ ok: true, csrf: owner.csrf, testMode: TEST_MODE && owner.fixture });
  }

  /*
   * Local/demo authentication handoff. This is deliberately separate from
   * academic fixtures and requires a browser-provided trusted same-origin Origin.
   */
  if (pathname === "/api/demo/login" && request.method === "POST") {
    if (!LOCAL_DEMO_ENABLED || !trustedSameOrigin(request)) {
      return json({ ok: false, message: "The local demo sign-in could not be completed." }, 403);
    }
    const session = createAuthenticatedSession(false, false);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(session.id) });
  }

  /*
   * Explicit academic fixture endpoint. A missing Origin is rejected so this
   * session-creating POST cannot be triggered cross-site.
   */
  if (pathname === "/api/test/login" && request.method === "POST") {
    if (!trustedSameOrigin(request)) {
      return json({ ok: false, message: "The academic fixture sign-in could not be completed." }, 403);
    }
    const data = await body(request);
    if (!TEST_MODE || !data || typeof data.fixture !== "string" || !equal(data.fixture, ACADEMIC_FIXTURE_CODE)) {
      return json({ ok: false, message: "The academic fixture sign-in could not be completed." }, 403);
    }
    const session = createAuthenticatedSession(false, true);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(session.id) });
  }

  if (request.method !== "POST") return genericError(405);
  const owner = requireOwner(request);
  if (owner instanceof Response) return owner;
  if (!csrfOkay(request, owner)) return genericError(403);
  const data = await body(request);
  if (!data) return genericError();

  if (pathname === "/api/logout") {
    sessions.delete(owner.id);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", true) });
  }

  const locked = lockMessage();
  if (locked) return json({ ok: false, message: locked }, 429);

  if (pathname === "/api/identity/send") {
    if (!validPhone(data.phone) || !equal(String(data.phone), ACCOUNT_PHONE_SUFFIX)) {
      failure();
      return json({ ok: false, message: "Those phone digits did not match. Enter the last four digits, for example 4821." }, 400);
    }
    const code = TEST_MODE && owner.fixture
      ? ACADEMIC_IDENTITY_CODE
      : String(randomBytes(4).readUInt32BE(0) % 1_000_000).padStart(6, "0");
    record.identityCode = protectedCode(code);
    return json(TEST_MODE && owner.fixture ? { ok: true, testCode: code } : { ok: true });
  }

  if (pathname === "/api/identity/verify") {
    if (!validOtp(data.code)) {
      failure();
      return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    }
    const value = record.identityCode;
    if (!value || value.accountId !== owner.accountId || value.used || value.expiresAt < now() || !equal(value.hash, codeHash(String(data.code)))) {
      failure();
      return json({ ok: false, message: "That code did not work. Check the six numbers or ask for a new code." }, 400);
    }
    value.used = true;
    clearFailures();
    sessions.delete(owner.id);
    const replacement = createAuthenticatedSession(true, owner.fixture);
    return json({ ok: true, csrf: replacement.csrf }, 200, { "Set-Cookie": sessionCookie(replacement.id) });
  }

  if (!owner.identityVerified) {
    return json({ ok: false, message: "Please complete the identity check first." }, 403);
  }

  if (pathname === "/api/provision") {
    const secret = TEST_MODE && owner.fixture ? ACADEMIC_TOTP_SECRET : base32Secret();
    Object.assign(record, encrypt(secret));
    record.lastAcceptedTotpCounter = undefined;
    record.otpVerified = false;
    record.mfaEnabled = false;
    const result: Record<string, unknown> = { ok: true, secret, uri: provisioningUri(secret) };
    if (TEST_MODE && owner.fixture) {
      result.testSecret = secret;
      result.testOtp = totp(secret);
    }
    return json(result);
  }

  if (pathname === "/api/totp/test") {
    const secret = decrypt(record);
    if (!secret) return json({ ok: false, message: "Make a setup key first." }, 400);
    return json(TEST_MODE && owner.fixture ? { ok: true, testOtp: totp(secret) } : { ok: true });
  }

  if (pathname === "/api/otp/verify") {
    if (!validOtp(data.code)) {
      failure();
      return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    }
    const secret = decrypt(record);
    const counter = secret ? matchingTotpCounter(secret, String(data.code)) : null;
    if (counter === null || record.lastAcceptedTotpCounter === counter) {
      failure();
      return json({
        ok: false,
        message: counter !== null
          ? "That code was already used. Wait for a new code, then try again."
          : "That code did not work. Check the six numbers or get a new code.",
      }, 400);
    }
    record.lastAcceptedTotpCounter = counter;
    record.otpVerified = true;
    clearFailures();
    return json({ ok: true });
  }

  if (pathname === "/api/backups/generate") {
    if (!record.otpVerified) {
      return json({ ok: false, message: "Please check your authenticator code first." }, 403);
    }
    const codes: string[] = TEST_MODE && owner.fixture ? [...ACADEMIC_RECOVERY_CODES] : [];
    if (!codes.length) {
      for (let i = 0; i < 8; i++) {
        const raw = randomBytes(8).toString("hex").toUpperCase();
        codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`);
      }
    }
    record.recoveryHashes = codes.map((code, i) =>
      recoveryHash(code, TEST_MODE && owner.fixture ? Buffer.alloc(16, i + 1) : randomBytes(16)),
    );
    return json({ ok: true, codes });
  }

  if (pathname === "/api/complete") {
    if (!record.recoveryHashes.length) {
      return json({ ok: false, message: "Make and save backup codes before continuing." }, 400);
    }
    record.mfaEnabled = true;
    return json({ ok: true });
  }

  if (pathname === "/api/recovery/verify") {
    if (!record.mfaEnabled) {
      return json({ ok: false, message: "MFA setup must be completed first. Finish saving your backup codes, then try again." }, 403);
    }
    const code = normalRecovery(data.code);
    if (!code) {
      failure();
      return json({ ok: false, message: "Enter a backup code in this format: A1B2-C3D4-E5F6-7890." }, 400);
    }
    let matched = -1;
    for (let i = 0; i < record.recoveryHashes.length; i++) {
      const item = record.recoveryHashes[i];
      const attempt = scryptSync(code, Buffer.from(item.salt, "base64"), 32).toString("base64");
      if (equal(attempt, item.hash)) matched = i;
    }
    if (matched < 0) {
      failure();
      return json({ ok: false, message: "That backup code did not work. Check it and try again." }, 400);
    }
    record.recoveryHashes.splice(matched, 1);
    clearFailures();
    return json({ ok: true });
  }

  return genericError(404);
}

const server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: "certs/cert.pem", key: "certs/key.pem" },
  async fetch(request) {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") {
        const origin = request.headers.get("origin") || "";
        if (!TRUSTED_ORIGINS.has(origin)) return new Response(null, { status: 403, headers: headers() });
        return new Response(null, {
          status: 204,
          headers: headers("", {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          }),
        });
      }

      if (url.pathname === "/" && request.method === "GET") {
        const nonce = randomBytes(24).toString("base64");
        const live = getLiveSession(request);
        if (!live && trustedOwnerAssertion(request)) {
          const session = createAuthenticatedSession(false, false);
          return new Response(page(nonce), {
            headers: headers(nonce, {
              "Content-Type": "text/html; charset=utf-8",
              "Set-Cookie": sessionCookie(session.id),
            }),
          });
        }
        return new Response(page(nonce), {
          headers: headers(nonce, { "Content-Type": "text/html; charset=utf-8" }),
        });
      }

      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      return new Response("Not found", {
        status: 404,
        headers: headers("", { "Content-Type": "text/plain; charset=utf-8" }),
      });
    } catch {
      return new Response("Something went wrong. Please try again.", {
        status: 500,
        headers: headers("", { "Content-Type": "text/plain; charset=utf-8" }),
      });
    }
  },
});

console.log(`MFA enrolment server listening on https://localhost:${server.port}`);
