
import {
  createCipheriv, createDecipheriv, createHmac, randomBytes, scryptSync,
  timingSafeEqual,
} from "node:crypto";

/**
 * MFA Enrolment System
 * Requirements 1–5: server-side owner checks, CSRF/origin protection,
 * TLS/security headers, encrypted OTP secrets, hashed recovery codes,
 * rate limiting, secure sessions, and accessible mobile UI.
 */
const PORT = 3000;
const ACCOUNT_ID = "account-marcus-001";
const ACCOUNT_EMAIL = "marcus@example.com";
const PHONE_SUFFIX = "4821";

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_EXPIRY_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_SECONDS = 30;
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

type Session = {
  id: string;
  csrf: string;
  accountId: string;
  identityVerified: boolean;
  mockMode: boolean;
  createdAt: number;
  lastSeenAt: number;
};
type TimedCode = {
  hash: string;
  accountId: string;
  expiresAt: number;
  used: boolean;
};
type RecoveryHash = { salt: string; hash: string };
type MfaRecord = {
  encryptedSecret?: string;
  secretIv?: string;
  secretTag?: string;
  identityCode?: TimedCode;
  recoveryHashes: RecoveryHash[];
  enrolmentId?: string;
  otpVerified: boolean;
  otpVerifiedEnrolment?: string;
  recoveryGeneratedEnrolment?: string;
  mfaEnabled: boolean;
  failures: number;
  lockedUntil: number;
  lastAcceptedCounter?: number;
};

const key = randomBytes(32);
const sessions = new Map<string, Session>();
const records = new Map<string, MfaRecord>();

const now = () => Date.now();
const token = (bytes = 32) => randomBytes(bytes).toString("base64url");

function recordFor(accountId: string): MfaRecord {
  let record = records.get(accountId);
  if (!record) {
    record = {
      recoveryHashes: [],
      otpVerified: false,
      mfaEnabled: false,
      failures: 0,
      lockedUntil: 0,
    };
    records.set(accountId, record);
  }
  return record;
}
function equal(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
function createSession(identityVerified = false): Session {
  const session: Session = {
    id: token(),
    csrf: token(),
    accountId: ACCOUNT_ID,
    identityVerified,
    mockMode: true,
    createdAt: now(),
    lastSeenAt: now(),
  };
  sessions.set(session.id, session);
  return session;
}
function cookie(value: string, expired = false) {
  return `mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${expired ? "; Max-Age=0" : ""}`;
}

/* Requirement 2: restrictive headers, no cache, no framing, and TLS HSTS. */
function secureHeaders(nonce = "", extra: Record<string, string> = {}) {
  const allowedScript = nonce ? `'nonce-${nonce}'` : "'none'";
  return {
    "Content-Security-Policy": `default-src 'self'; script-src ${allowedScript}; style-src ${allowedScript}; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Cache-Control": "no-store",
    ...extra,
  };
}
function json(value: unknown, status = 200, extra: Record<string, string> = {}) {
  return Response.json(value, { status, headers: secureHeaders("", extra) });
}
function genericError(status = 400) {
  return json({
    ok: false,
    message: "We could not complete that step. Please check the information and try again.",
  }, status);
}
function cookies(request: Request) {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const [name, ...values] = part.trim().split("=");
    if (name && values.length) result[name] = values.join("=");
  }
  return result;
}
function liveSession(request: Request): Session | null {
  const id = cookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  if (
    now() - session.lastSeenAt > SESSION_IDLE_MS ||
    now() - session.createdAt > SESSION_ABSOLUTE_MS
  ) {
    sessions.delete(session.id);
    return null;
  }
  session.lastSeenAt = now();
  return session;
}
/* Requirement 1: all protected routes use the account from HttpOnly session only. */
function requireOwner(request: Request): Session | Response {
  const session = liveSession(request);
  if (!session || session.accountId !== ACCOUNT_ID) {
    return json({ ok: false, message: "Please sign in to your secure setup page." }, 401);
  }
  return session;
}
function sameOrigin(request: Request) {
  return TRUSTED_ORIGINS.has(request.headers.get("origin") || "");
}
function csrfOkay(request: Request, session: Session) {
  return sameOrigin(request) && equal(request.headers.get("x-csrf-token") || "", session.csrf);
}
async function requestBody(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data)
      ? data as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

/* Requirement 3: OTP secret is AES-GCM encrypted at rest. */
function encryptSecret(secret: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return {
    encryptedSecret: encrypted.toString("base64"),
    secretIv: iv.toString("base64"),
    secretTag: cipher.getAuthTag().toString("base64"),
  };
}
function decryptSecret(record: MfaRecord) {
  if (!record.encryptedSecret || !record.secretIv || !record.secretTag) return "";
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(record.secretIv, "base64"),
    );
    decipher.setAuthTag(Buffer.from(record.secretTag, "base64"));
    return Buffer.concat([
      decipher.update(Buffer.from(record.encryptedSecret, "base64")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return "";
  }
}
function protectedCode(code: string, accountId: string): TimedCode {
  return {
    hash: createHmac("sha256", key).update(code).digest("hex"),
    accountId,
    expiresAt: now() + CODE_EXPIRY_MS,
    used: false,
  };
}
function codeHash(code: string) {
  return createHmac("sha256", key).update(code).digest("hex");
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function makeSecret() {
  const raw = randomBytes(20);
  let value = 0;
  let bits = 0;
  let out = "";
  for (const byte of raw) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return bits ? out + BASE32[(value << (5 - bits)) & 31] : out;
}
function base32Decode(value: string) {
  let buffer = 0;
  let bits = 0;
  const bytes: number[] = [];
  for (const char of value.replace(/[=\s]/g, "").toUpperCase()) {
    const item = BASE32.indexOf(char);
    if (item < 0) return Buffer.alloc(0);
    buffer = (buffer << 5) | item;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
function currentTotp(secret: string, counter = Math.floor(now() / 1000 / TOTP_SECONDS)) {
  const data = Buffer.alloc(8);
  data.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", base32Decode(secret)).update(data).digest();
  const offset = mac[19] & 15;
  const number = ((mac[offset] & 127) << 24) |
    (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}
function matchingCounter(secret: string, code: string) {
  const current = Math.floor(now() / 1000 / TOTP_SECONDS);
  for (const offset of [-1, 0, 1]) {
    if (equal(currentTotp(secret, current + offset), code)) return current + offset;
  }
  return null;
}
function uriFor(secret: string) {
  const issuer = "SafeBank";
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${ACCOUNT_EMAIL}`)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}
function lockedMessage(record: MfaRecord) {
  return record.lockedUntil > now()
    ? "Too many attempts were made. Please wait a few minutes, then try again."
    : "";
}
function fail(record: MfaRecord) {
  record.failures++;
  if (record.failures >= MAX_FAILURES) {
    record.failures = 0;
    record.lockedUntil = now() + LOCKOUT_MS;
  }
}
function clearFailures(record: MfaRecord) {
  record.failures = 0;
}
const validPhone = (value: unknown) => typeof value === "string" && /^\d{4}$/.test(value);
const validOtp = (value: unknown) => typeof value === "string" && /^\d{6}$/.test(value);
function normalRecovery(value: unknown) {
  if (typeof value !== "string") return "";
  const compact = value.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return /^[A-F0-9]{16}$/.test(compact)
    ? `${compact.slice(0, 4)}-${compact.slice(4, 8)}-${compact.slice(8, 12)}-${compact.slice(12)}`
    : "";
}
function hashRecovery(code: string, salt: Buffer): RecoveryHash {
  return { salt: salt.toString("base64"), hash: scryptSync(code, salt, 32).toString("base64") };
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeBank MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#142035;--muted:#526277;--blue:#075fc9;--pale:#edf5ff;--line:#cad5e3;--green:#087344;--red:#9a2020;--gold:#8d5e00}*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;letter-spacing:.035em;line-height:1.65}main{width:min(100%,570px);min-height:100vh;margin:auto;padding:22px 20px 40px;background:#fff}header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:24px}.brand{font-weight:800;font-size:1.28rem}.step{margin:4px 0 0;color:var(--muted);font-size:.91rem}h1{font-size:1.7rem;line-height:1.25;margin:0 0 12px}p{max-width:48ch}.card{border:1px solid var(--line);border-radius:13px;padding:17px;margin:17px 0}.notice{background:var(--pale);border-left:5px solid var(--blue)}.success{background:#effbf4;border-left:5px solid var(--green)}.error{background:#fff1f1;border-left:5px solid var(--red);color:#711a1a}.simulation{background:#fff8dd;border-left:5px solid var(--gold)}label{display:block;font-weight:800;margin:16px 0 4px}.hint,.small{color:var(--muted);font-size:.92rem;margin:2px 0 12px}input{display:block;width:100%;min-height:52px;border:2px solid #97a8bc;border-radius:9px;padding:10px 12px;font:inherit;letter-spacing:.11em}input:focus,button:focus,summary:focus{outline:3px solid #f4aa26;outline-offset:3px}button{width:100%;display:block;min-height:52px;border:0;border-radius:9px;padding:11px 14px;margin:14px 0 0;font:inherit;font-weight:800;cursor:pointer}.primary{background:var(--blue);color:#fff}.secondary{background:#e6f0fd;color:#064b9f}.textbutton{background:transparent;color:#064b9f;text-decoration:underline;min-height:38px}.icon{font-size:1.5rem;margin-right:8px}.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.08em;overflow-wrap:anywhere;white-space:pre-wrap;background:#f4f6f9;border-radius:8px;padding:11px}.hidden{display:none}.qr{display:grid;grid-template-columns:repeat(21,10px);width:210px;margin:15px auto;padding:9px;background:white;border:1px solid var(--line)}.qr i{width:10px;height:10px;background:white}.qr i.on{background:#111}.logs{border-top:2px solid var(--line);margin-top:26px;padding-top:13px}.logs h2{font-size:1.08rem;margin:0}.logbox{max-height:190px;overflow:auto;background:#142035;color:#f7fbff;padding:12px;border-radius:9px;font-family:ui-monospace,monospace;font-size:.78rem;line-height:1.5;letter-spacing:0;white-space:pre-wrap}details{border-top:1px solid var(--line);padding-top:14px;margin-top:20px}summary{font-weight:800;color:#064b9f;cursor:pointer}@media(max-width:360px){main{padding:18px 15px}body{font-size:16px}h1{font-size:1.48rem}}
</style>
</head>
<body><main>
<header><div class="brand">🔐 SafeBank</div><p class="step" id="step">MFA setup</p></header>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-labelledby="logsTitle"><h2 id="logsTitle">Logs</h2><p class="small">Simulation messages appear here too.</p><div class="logbox" id="logs" role="log" aria-live="polite">Ready.</div></section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",backupCodes=[];
const app=document.getElementById("app"),step=document.getElementById("step"),logs=document.getElementById("logs");
const by=id=>document.getElementById(id);
const esc=value=>{const d=document.createElement("div");d.textContent=String(value);return d.innerHTML};
function log(message,value){if(arguments.length>1)console.log(message,value);else console.log(message);const text=arguments.length>1?message+" "+(Array.isArray(value)?value.join("\\n"):String(value)):message;logs.textContent+=(logs.textContent==="Ready."?"":"\\n")+text;logs.scrollTop=logs.scrollHeight}
function showStep(title,html){step.textContent=title;app.innerHTML=html}
async function api(path,data={}){const response=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});const result=await response.json().catch(()=>({ok:false,message:"Please try again."}));if(response.status===401){csrf="";signedOut(result.message||"Your secure setup session ended.")}return result}
function help(){return '<details><summary>Need help?</summary><p>You can take your time. There is no reading time limit. You can retry any step.</p><button class="textbutton" type="button" data-restart>Start this setup again</button></details>'}
function simulation(label,value){log("[MOCK SIMULATION] "+label+":",value);return '<div class="card simulation"><strong>Mock simulation value</strong><p class="small">'+esc(label)+'</p><div class="code">'+esc(Array.isArray(value)?value.join("\\n"):value)+'</div></div>'}
function signIn(message=""){showStep("Mock secure sign-in",'<h1><span class="icon">🔒</span>Mock secure setup</h1><div class="card notice"><p>'+esc(message||"This is a standalone mock sign-in for the MFA practice flow. No bank password is needed.")+'</p></div><p>Choose the button below to begin as Marcus.</p><button class="primary" id="mockSignIn">Sign in to mock setup</button>'+help());by("mockSignIn").onclick=async()=>{const r=await api("/api/mock/login");if(r.ok){log("Mock sign-in completed. A protected server session was created.");location.reload()}else signIn(r.message)}}
function identity(message=""){showStep("Step 1 of 4 · identity check",'<h1><span class="icon">🪪</span>Check it is you</h1><p>We will send a six-digit code to your phone ending in 4821.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div id="sent"></div><form id="identityForm"><label for="phone">Last 4 digits of phone</label><p class="hint">Example: 4821</p><input id="phone" inputmode="numeric" autocomplete="tel" maxlength="4" required><label for="identityCode">Code</label><p class="hint">Example: 123456</p><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary">Check code</button></form><button class="secondary" id="send" type="button">Send or re-send code</button>'+help());by("send").onclick=async()=>{const r=await api("/api/identity/send",{phone:by("phone").value});if(!r.ok)return identity(r.message);by("sent").innerHTML='<div class="card success"><strong>Code sent.</strong><p>In this mock flow, the exact code is shown below. Enter it when you are ready.</p></div>'+simulation("Identity verification code",r.mockCode);log("Simulated identity code delivery was requested and completed.");by("identityCode").focus()};by("identityForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/identity/verify",{code:by("identityCode").value});if(!r.ok)return identity(r.message);csrf=r.csrf;log("Identity check completed. Your secure session was refreshed.");provision()}}
function fakeQr(seed){let cells="";let state=0;for(let n=0;n<seed.length;n++)state=(state*31+seed.charCodeAt(n))>>>0;for(let y=0;y<21;y++)for(let x=0;x<21;x++){const finder=(a,b)=>x>=a&&x<a+7&&y>=b&&y<b+7;let on=false;if(finder(0,0)||finder(14,0)||finder(0,14)){const ax=x<7?x:x>=14?x-14:x,ay=y<7?y:y>=14?y-14:y;on=ax===0||ay===0||ax===6||ay===6||(ax>=2&&ax<=4&&ay>=2&&ay<=4)}else{state=(state*1664525+1013904223)>>>0;on=!!(state&1)}cells+='<i class="'+(on?"on":"")+'"></i>'}return '<div class="qr" role="img" aria-label="Mock authenticator setup QR code">'+cells+'</div>'}
function provision(message=""){showStep("Step 2 of 4 · authenticator",'<h1><span class="icon">📱</span>Add your authenticator</h1><p>Scan the QR code with your authenticator app. Or copy the setup key instead.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice" id="setup"><p class="small">Select “Make setup key” first.</p></div><button class="primary" id="make">Make setup key</button>'+help());by("make").onclick=makeProvision}
async function makeProvision(){const r=await api("/api/provision");if(!r.ok)return provision(r.message);by("setup").innerHTML=fakeQr(r.secret)+'<label for="secret">Setup key</label><p class="hint">You can reveal it only if you need it.</p><div id="secret" class="code hidden">'+esc(r.secret)+'</div><button class="secondary" type="button" id="reveal">Show setup key</button><button class="secondary" type="button" id="copy">Copy setup key</button>'+simulation("Current mock authenticator code",r.mockOtp);by("reveal").onclick=()=>{const hidden=by("secret").classList.toggle("hidden");by("reveal").textContent=hidden?"Show setup key":"Hide setup key"};by("copy").onclick=async()=>{try{await navigator.clipboard.writeText(r.secret);log("Authenticator setup key copied.")}catch{log("Copy was unavailable. Choose Show setup key instead.")}};log("Simulated authenticator provisioning was created.");by("make").textContent="Continue to check code";by("make").onclick=()=>otp()}
function otp(message=""){showStep("Step 3 of 4 · check authenticator",'<h1><span class="icon">✅</span>Check your authenticator</h1><p>Enter the six digits from your authenticator app.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div id="testCode"></div><form id="otpForm"><label for="otpCode">Authenticator code</label><p class="hint">Example: 123456</p><input id="otpCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary">Check code</button></form><button class="secondary" type="button" id="newCode">Get current mock code</button>'+help());by("newCode").onclick=async()=>{const r=await api("/api/totp/mock");if(!r.ok)return otp(r.message);by("testCode").innerHTML='<div class="card success"><strong>Current mock code ready.</strong><p>You can use this code now.</p></div>'+simulation("Current authenticator code",r.mockOtp);log("Current mock authenticator code was requested.");by("otpCode").focus()};by("otpForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/otp/verify",{code:by("otpCode").value});if(!r.ok)return otp(r.message);log("Authenticator code checked.");backups()}}
function backups(message=""){backupCodes=[];showStep("Step 4 of 4 · backup codes",'<h1><span class="icon">🧾</span>Save backup codes</h1><p>These codes help if you lose your phone. Keep them somewhere private.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice"><p id="codeHelp" class="small">No codes made yet.</p><div id="codes" class="code hidden"></div><button class="secondary hidden" type="button" id="toggle">Show backup codes</button><button class="secondary" type="button" id="copyCodes">Copy backup codes</button></div><button class="primary" id="makeCodes">Make backup codes</button><button class="secondary hidden" type="button" id="finish">I saved my codes</button>'+help());by("makeCodes").onclick=async()=>{const r=await api("/api/backups/generate");if(!r.ok)return backups(r.message);backupCodes=r.codes;by("codes").textContent=backupCodes.join("\\n");by("codeHelp").textContent="Your new backup codes are hidden. Show them when you are ready to save them.";by("toggle").classList.remove("hidden");by("finish").classList.remove("hidden");by("makeCodes").textContent="Make new backup codes";log("Simulated backup recovery codes were created.",backupCodes);log("[MOCK SIMULATION] Backup recovery codes:",backupCodes)};by("toggle").onclick=()=>{const hidden=by("codes").classList.toggle("hidden");by("toggle").textContent=hidden?"Show backup codes":"Hide backup codes"};by("copyCodes").onclick=async()=>{if(!backupCodes.length){log("Make backup codes first, then copy them.");return}try{await navigator.clipboard.writeText(backupCodes.join("\\n"));log("Backup recovery codes copied.")}catch{log("Copy was unavailable. Choose Show backup codes instead.")}};by("finish").onclick=async()=>{const r=await api("/api/complete");if(r.ok)success();else backups(r.message)}}
function success(){showStep("MFA setup complete",'<h1><span class="icon">🎉</span>You are all set</h1><div class="card success"><p><strong>Your authenticator and backup codes are ready.</strong></p><p>You completed the mock MFA enrolment.</p></div><button class="primary" id="logout">Log out safely</button>');by("logout").onclick=async()=>{await api("/api/logout");csrf="";log("Secure session logged out.");signedOut("You are logged out.")}}
function signedOut(message){showStep("Secure setup",'<h1><span class="icon">🔒</span>Setup closed</h1><div class="card notice"><p>'+esc(message)+'</p></div><button class="primary" id="open">Open mock setup</button>');by("open").onclick=()=>location.reload()}
document.addEventListener("click",e=>{const target=e.target;if(target instanceof HTMLElement&&target.dataset.restart)identity()});
fetch("/api/bootstrap",{credentials:"same-origin"}).then(async r=>{const x=await r.json();if(!x.ok)return signIn(x.message);csrf=x.csrf;identity()}).catch(()=>signedOut("Please refresh the page and try again."));
})();
</script></body></html>`;
}

async function api(request: Request, path: string): Promise<Response> {
  if (path === "/api/bootstrap" && request.method === "GET") {
    const owner = requireOwner(request);
    if (owner instanceof Response) return json({ ok: false, message: "Sign in is required before MFA setup." }, 401);
    return json({ ok: true, csrf: owner.csrf });
  }

  /*
   * Explicit standalone mock sign-in. It needs no supplied authentication
   * headers, but still requires a trusted browser Origin. It creates a new
   * HttpOnly, Secure, SameSite session; every later mutation uses CSRF.
   */
  if (path === "/api/mock/login" && request.method === "POST") {
    if (!sameOrigin(request)) {
      return json({ ok: false, message: "The mock sign-in could not be completed." }, 403);
    }
    const session = createSession(false);
    return json({ ok: true }, 200, { "Set-Cookie": cookie(session.id) });
  }

  if (request.method !== "POST") return genericError(405);
  const owner = requireOwner(request);
  if (owner instanceof Response) return owner;
  if (!csrfOkay(request, owner)) return genericError(403);
  const data = await requestBody(request);
  if (!data) return genericError();

  if (path === "/api/logout") {
    sessions.delete(owner.id);
    return json({ ok: true }, 200, { "Set-Cookie": cookie("", true) });
  }

  const record = recordFor(owner.accountId);
  const locked = lockedMessage(record);
  if (locked) return json({ ok: false, message: locked }, 429);

  if (path === "/api/identity/send") {
    if (!validPhone(data.phone) || !equal(String(data.phone), PHONE_SUFFIX)) {
      fail(record);
      return json({
        ok: false,
        message: "Those phone digits did not match. Enter the last four digits, for example 4821.",
      }, 400);
    }
    const code = String(randomBytes(4).readUInt32BE(0) % 1_000_000).padStart(6, "0");
    record.identityCode = protectedCode(code, owner.accountId);
    /*
     * Task requirement: standalone mock code appears only in this mock API
     * response; server logging never contains the code.
     */
    return json({ ok: true, mockCode: code });
  }

  if (path === "/api/identity/verify") {
    if (!validOtp(data.code)) {
      fail(record);
      return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    }
    const code = record.identityCode;
    if (
      !code || code.accountId !== owner.accountId || code.used ||
      code.expiresAt < now() || !equal(code.hash, codeHash(String(data.code)))
    ) {
      fail(record);
      return json({
        ok: false,
        message: "That code did not work. Check the six numbers or ask for a new code.",
      }, 400);
    }
    code.used = true;
    clearFailures(record);
    sessions.delete(owner.id); // Requirement 5: rotate ID after authentication.
    const replacement = createSession(true);
    return json({ ok: true, csrf: replacement.csrf }, 200, {
      "Set-Cookie": cookie(replacement.id),
    });
  }

  if (!owner.identityVerified) {
    return json({ ok: false, message: "Please complete the identity check first." }, 403);
  }

  if (path === "/api/provision") {
    const secret = makeSecret();
    record.enrolmentId = token(18);
    record.recoveryHashes = [];
    record.recoveryGeneratedEnrolment = undefined;
    record.otpVerified = false;
    record.otpVerifiedEnrolment = undefined;
    record.lastAcceptedCounter = undefined;
    record.mfaEnabled = false;
    Object.assign(record, encryptSecret(secret));
    return json({
      ok: true,
      secret,
      uri: uriFor(secret),
      mockOtp: currentTotp(secret),
    });
  }

  if (path === "/api/totp/mock") {
    const secret = decryptSecret(record);
    if (!secret || !record.enrolmentId) {
      return json({ ok: false, message: "Make a setup key first." }, 400);
    }
    return json({ ok: true, mockOtp: currentTotp(secret) });
  }

  if (path === "/api/otp/verify") {
    if (!validOtp(data.code)) {
      fail(record);
      return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    }
    const secret = decryptSecret(record);
    const counter = secret ? matchingCounter(secret, String(data.code)) : null;
    if (!record.enrolmentId || counter === null || record.lastAcceptedCounter === counter) {
      fail(record);
      return json({
        ok: false,
        message: counter !== null
          ? "That code was already used. Get the current mock code, then try again."
          : "That code did not work. Check the six numbers or get the current mock code.",
      }, 400);
    }
    record.lastAcceptedCounter = counter;
    record.otpVerified = true;
    record.otpVerifiedEnrolment = record.enrolmentId;
    clearFailures(record);
    return json({ ok: true });
  }

  if (path === "/api/backups/generate") {
    if (!record.enrolmentId || !record.otpVerified || record.otpVerifiedEnrolment !== record.enrolmentId) {
      return json({ ok: false, message: "Please check your authenticator code first." }, 403);
    }
    const codes: string[] = [];
    while (codes.length < 8) {
      const raw = randomBytes(8).toString("hex").toUpperCase();
      codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`);
    }
    /* Requirement 3: only salted strong hashes are retained server-side. */
    record.recoveryHashes = codes.map(code => hashRecovery(code, randomBytes(16)));
    record.recoveryGeneratedEnrolment = record.enrolmentId;
    return json({ ok: true, codes });
  }

  if (path === "/api/complete") {
    if (!record.enrolmentId || !record.otpVerified || record.otpVerifiedEnrolment !== record.enrolmentId) {
      return json({ ok: false, message: "Please check your authenticator code before continuing." }, 400);
    }
    if (!record.recoveryHashes.length || record.recoveryGeneratedEnrolment !== record.enrolmentId) {
      return json({ ok: false, message: "Make new backup codes for this setup before continuing." }, 400);
    }
    record.mfaEnabled = true;
    return json({ ok: true });
  }

  if (path === "/api/recovery/verify") {
    if (!record.mfaEnabled) return json({ ok: false, message: "MFA setup must be completed first." }, 403);
    const code = normalRecovery(data.code);
    if (!code) {
      fail(record);
      return json({
        ok: false,
        message: "Enter a backup code in this format: A1B2-C3D4-E5F6-7890.",
      }, 400);
    }
    let matched = -1;
    for (let index = 0; index < record.recoveryHashes.length; index++) {
      const saved = record.recoveryHashes[index];
      const attempt = scryptSync(code, Buffer.from(saved.salt, "base64"), 32).toString("base64");
      if (equal(attempt, saved.hash)) matched = index;
    }
    if (matched < 0) {
      fail(record);
      return json({ ok: false, message: "That backup code did not work. Check it and try again." }, 400);
    }
    record.recoveryHashes.splice(matched, 1);
    clearFailures(record);
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

      /* Requirement 2: CORS is only ever granted to known local TLS origins. */
      if (request.method === "OPTIONS") {
        const origin = request.headers.get("origin") || "";
        if (!TRUSTED_ORIGINS.has(origin)) {
          return new Response(null, { status: 403, headers: secureHeaders() });
        }
        return new Response(null, {
          status: 204,
          headers: secureHeaders("", {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          }),
        });
      }

      if (url.pathname === "/" && request.method === "GET") {
        const nonce = randomBytes(24).toString("base64");
        return new Response(page(nonce), {
          headers: secureHeaders(nonce, { "Content-Type": "text/html; charset=utf-8" }),
        });
      }
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);

      return new Response("Not found", {
        status: 404,
        headers: secureHeaders("", { "Content-Type": "text/plain; charset=utf-8" }),
      });
    } catch {
      /* Requirement 2: no debug details or stack trace are returned. */
      return new Response("Something went wrong. Please try again.", {
        status: 500,
        headers: secureHeaders("", { "Content-Type": "text/plain; charset=utf-8" }),
      });
    }
  },
});

console.log(`MFA enrolment server listening on https://localhost:${server.port}`);
