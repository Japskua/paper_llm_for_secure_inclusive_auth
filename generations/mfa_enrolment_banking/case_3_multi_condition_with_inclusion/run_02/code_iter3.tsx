
/*
 MFA Enrolment System
 Requirements 1: MFA API routes use the authenticated Marcus session only and CSRF/origin checks.
 Requirements 2: TLS-only serving, secure headers, strict cookies, generic errors, no permissive CORS.
 Requirements 3: cryptographic random values, encrypted OTP secret, salted slow-KDF recovery codes.
 Requirements 4: validated inputs and contextual browser output encoding.
 Requirements 5: rotated sessions, time-based OTPs, single-use recovery codes, rate limiting and lockouts.
*/

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type Session = {
  userId: "marcus-account";
  csrf: string;
  created: number;
  lastSeen: number;
};

type RecoveryRecord = {
  salt: string;
  derived: string;
  consumed: boolean;
};

type MfaState = {
  encryptedSecret?: string;
  verified: boolean;
  recoveryCodes: RecoveryRecord[];
  usedTotpCounters: Set<string>;
  failedAttempts: number;
  lockedUntil: number;
  recoveryFailedAttempts: number;
  recoveryLockedUntil: number;
};

type FailedAttemptRecord = {
  failures: number;
  lockedUntil: number;
  expiresAt: number;
};

const sessions = new Map<string, Session>();
const mfaStates = new Map<string, MfaState>();
const loginFailures = new Map<string, FailedAttemptRecord>();

const SESSION_IDLE_MS = 30 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const LOCKOUT_MS = 5 * 60_000;
const ATTEMPT_EXPIRY_MS = 20 * 60_000;
const MAX_FAILED_ATTEMPTS = 5;
const TRUSTED_ORIGIN = "https://localhost:3000";
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));

let server: ReturnType<typeof Bun.serve> | undefined;

function randomToken(bytes = 32): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("base64url");
}

function base32Secret(bytes = 20): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const input = crypto.getRandomValues(new Uint8Array(bytes));
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function recoveryCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const values = crypto.getRandomValues(new Uint8Array(12));
  let result = "";
  for (const value of values) result += alphabet[value % alphabet.length];
  return result.slice(0, 4) + "-" + result.slice(4, 8) + "-" + result.slice(8, 12);
}

function recoveryCodes(): string[] {
  return Array.from({ length: 8 }, recoveryCode);
}

function secureCookie(name: string, value: string, maxAge?: number): string {
  const age = maxAge === undefined ? "" : `; Max-Age=${maxAge}`;
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${age}`;
}

function securityHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    "Content-Security-Policy":
      "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    ...extra,
  };
}

function apiResponse(data: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: securityHeaders({ "Content-Type": "application/json; charset=utf-8", ...extra }),
  });
}

function cookieValue(request: Request, name: string): string | undefined {
  const part = (request.headers.get("cookie") || "").split(";").map((item) => item.trim())
    .find((item) => item.startsWith(name + "="));
  return part?.slice(name.length + 1);
}

function trustedOrigin(request: Request): boolean {
  return request.headers.get("origin") === TRUSTED_ORIGIN;
}

function requireSession(request: Request): { id: string; session: Session } | null {
  const id = cookieValue(request, "sid");
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!id || !session || now - session.lastSeen > SESSION_IDLE_MS || now - session.created > SESSION_ABSOLUTE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return { id, session };
}

function csrfIsValid(request: Request, session: Session): boolean {
  return trustedOrigin(request) && request.headers.get("x-csrf-token") === session.csrf;
}

async function requestBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const parsed = await request.json();
    return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function getState(userId: string): MfaState {
  let state = mfaStates.get(userId);
  if (!state) {
    state = {
      verified: false,
      recoveryCodes: [],
      usedTotpCounters: new Set(),
      failedAttempts: 0,
      lockedUntil: 0,
      recoveryFailedAttempts: 0,
      recoveryLockedUntil: 0,
    };
    mfaStates.set(userId, state);
  }
  return state;
}

/* Task: privacy-preserving login attempt key: normalized proof plus server-observed client IP. */
function clientIp(request: Request): string {
  try {
    return server?.requestIP(request)?.address || "unknown-client";
  } catch {
    return "unknown-client";
  }
}

async function loginAttemptKey(proof: string, request: Request): Promise<string> {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(`${proof}\u0000${clientIp(request)}`));
  return Buffer.from(bytes).toString("base64url");
}

function cleanupFailedAttempts(now = Date.now()): void {
  for (const [key, record] of loginFailures) {
    if (record.expiresAt <= now && record.lockedUntil <= now) loginFailures.delete(key);
  }
}

function loginIsLocked(key: string, now: number): boolean {
  const record = loginFailures.get(key);
  if (!record) return false;
  if (record.expiresAt <= now && record.lockedUntil <= now) {
    loginFailures.delete(key);
    return false;
  }
  return record.lockedUntil > now;
}

function recordLoginFailure(key: string, now: number): void {
  const record = loginFailures.get(key) || { failures: 0, lockedUntil: 0, expiresAt: now + ATTEMPT_EXPIRY_MS };
  record.failures += 1;
  record.expiresAt = now + ATTEMPT_EXPIRY_MS;
  if (record.failures >= MAX_FAILED_ATTEMPTS) {
    record.failures = 0;
    record.lockedUntil = now + LOCKOUT_MS;
  }
  loginFailures.set(key, record);
}

/* Requirement 3: AES-GCM protects the in-memory OTP shared secret at rest. */
async function encryptAtRest(value: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return Buffer.from(iv).toString("base64url") + "." + Buffer.from(cipher).toString("base64url");
}

async function decryptAtRest(value: string): Promise<string> {
  const [iv, cipher] = value.split(".");
  if (!iv || !cipher) throw new Error("invalid encrypted secret");
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(iv, "base64url") },
    key,
    Buffer.from(cipher, "base64url"),
  );
  return decoder.decode(plain);
}

function base32Decode(value: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let buffer = 0;
  const output: number[] = [];
  for (const character of value.replace(/=+$/g, "").toUpperCase()) {
    const position = alphabet.indexOf(character);
    if (position < 0) throw new Error("invalid base32");
    buffer = (buffer << 5) | position;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

async function totpForCounter(secret: string, counter: bigint): Promise<string> {
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const bytes = new Uint8Array(8);
  let value = counter;
  for (let index = 7; index >= 0; index--) {
    bytes[index] = Number(value & 255n);
    value >>= 8n;
  }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  const offset = digest[digest.length - 1] & 15;
  const code = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3];
  return String(code % 1_000_000).padStart(6, "0");
}

async function currentTotp(secret: string): Promise<{ code: string; counter: bigint }> {
  const counter = BigInt(Math.floor(Date.now() / 30_000));
  return { code: await totpForCounter(secret, counter), counter };
}

async function deriveRecovery(value: string, salt: string): Promise<string> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(value), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: Buffer.from(salt, "base64url"), iterations: 150_000, hash: "SHA-256" },
    material,
    256,
  );
  return Buffer.from(bits).toString("base64url");
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) difference |= (a[i] || 0) ^ (b[i] || 0);
  return difference === 0;
}

async function createRecoveryRecords(codes: string[]): Promise<RecoveryRecord[]> {
  return Promise.all(codes.map(async (code) => {
    const salt = randomToken(16);
    return { salt, derived: await deriveRecovery(code, salt), consumed: false };
  }));
}

function pageHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecureBank MFA</title>
<style>
:root{font-family:Verdana,Arial,sans-serif;color:#14213d;background:#f3f7fb;letter-spacing:.035em;line-height:1.65}*{box-sizing:border-box}body{margin:0}.wrap{max-width:540px;margin:auto;padding:18px}.brand{font-weight:bold;color:#174c88}.card,.logs{background:white;border-radius:16px;padding:22px;box-shadow:0 2px 13px #14213d1a;margin:13px 0}h1{font-size:1.55rem;line-height:1.3;margin:0 0 9px}p{margin:9px 0}.step{font-weight:bold;color:#315b96}.icon{font-size:2rem}label{display:block;font-weight:bold;margin-top:15px}small{display:block;color:#405169;font-weight:normal;font-size:.88rem}input{width:100%;min-height:51px;border:2px solid #62748b;border-radius:9px;padding:10px;font:inherit;font-size:1rem;margin-top:5px}.code{letter-spacing:.16em;font-size:1.16rem}button{width:100%;min-height:51px;border:0;border-radius:9px;background:#075bb5;color:white;font:inherit;font-weight:bold;margin-top:16px;padding:10px;cursor:pointer}button.secondary{background:white;color:#075bb5;border:2px solid #075bb5;margin-top:9px}button:focus,input:focus{outline:3px solid #e49b24;outline-offset:2px}.hint,.error,.notice,.warning{padding:12px;border-radius:9px;margin-top:16px}.hint{background:#edf4ff}.error{background:#ffe9e9;color:#761b1b}.notice{background:#e7f7ed}.warning{background:#fff4d9}.secret,.codes{background:#f1f5f9;border-radius:9px;padding:13px;overflow-wrap:anywhere;line-height:1.9}.qr{width:190px;height:190px;margin:10px auto;display:grid;grid-template-columns:repeat(15,1fr);border:8px solid white;background:white}.qr i{background:#14213d}.logs h2{font-size:1rem;margin:0}.logs pre{white-space:pre-wrap;overflow-wrap:anywhere;font: .78rem/1.5 Verdana,Arial,sans-serif;margin:7px 0 0;color:#30465f}@media(max-width:390px){.wrap{padding:12px}.card,.logs{padding:18px}h1{font-size:1.38rem}}
</style>
</head>
<body>
<main class="wrap">
<p class="brand">SecureBank · account protection</p>
<section class="card" id="app" aria-live="polite"></section>
<section class="logs" aria-label="Logs"><h2>Logs</h2><pre id="logs">Ready.</pre></section>
</main>
<script>
(function(){
var csrf="",secret="",uri="",visible=false;
var app=document.getElementById("app"),logs=document.getElementById("logs");
function esc(v){return String(v).replace(/[&<>"']/g,function(c){return({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]})}
function log(message){console.log(message);logs.textContent+=(logs.textContent?"\\n":"")+message}
async function api(path,method,data){var r=await fetch(path,{method:method||"GET",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:data===undefined?undefined:JSON.stringify(data)});var p;try{p=await r.json()}catch(_){throw Error("Something went wrong. Please try again.")}if(!r.ok)throw Error(p.error||"Something went wrong. Please try again.");return p}
function hint(){return '<aside class="hint"><strong>💡 Need help?</strong><br>You can retry safely. There is no reading deadline.</aside>'}
function copy(text){navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(text).then(function(){var x=document.getElementById("copy-msg");if(x)x.textContent="Copied. You can paste it where you need it."}):null}
function fakeQr(text){var s="",seed=0;for(var a=0;a<text.length;a++)seed=(seed*31+text.charCodeAt(a))>>>0;for(var i=0;i<225;i++){seed=(seed*1664525+1013904223)>>>0;if((seed>>>29)&1)s+="<i></i>";else s+="<b></b>"}return '<div class="qr" role="img" aria-label="Authenticator setup QR-style setup aid">'+s+'</div>'}
function error(message,retry){app.innerHTML='<div class="icon">⚠️</div><h1>Please check that</h1><p class="error">'+esc(message)+'</p><button id="retry">Try again</button>'+hint();document.getElementById("retry").onclick=retry||identity}
function identity(){app.innerHTML='<p class="step">Step 1 of 4</p><div class="icon">🪪</div><h1>Confirm it is you</h1><p>Enter the two details from your account opening.</p><label>Date of birth <small>Example: 14 June 1971</small></label><input id="dob" autocomplete="bday" placeholder="14 June 1971"><label>Last four account digits <small>Example: 4821</small></label><input id="end" inputmode="numeric" maxlength="4" placeholder="4821"><button id="go">Confirm identity</button>'+hint();document.getElementById("go").onclick=async function(){try{var r=await api("/api/login","POST",{dateOfBirth:document.getElementById("dob").value,accountEnding:document.getElementById("end").value});csrf=r.csrf;log("Mock identity verification confirmed for Marcus. Starting MFA enrolment.");setup()}catch(e){error(e.message,identity)}}}
function renderSetup(message){app.innerHTML='<p class="step">Step 2 of 4</p><div class="icon">📱</div><h1>Add your authenticator</h1><p>Use your authenticator app to scan the setup aid, or reveal and copy the setup key.</p>'+fakeQr(uri)+'<p class="secret">'+(visible?esc(secret):"•••• •••• •••• •••• ••••")+'</p><button class="secondary" id="reveal">'+(visible?"Hide":"Reveal")+" setup key</button><button class=\"secondary\" id=\"copy\">Copy setup key</button><button class=\"secondary\" id=\"link\">Copy setup link</button><p id=\"copy-msg\"></p>"+(message?'<p class="error">'+esc(message)+'</p>':"")+'<label>Enter the 6-digit code from your app <small>Example: 123456</small></label><input class="code" id="otp" autocomplete="one-time-code" inputmode="numeric" maxlength="6"><button id="verify">Verify code</button>'+hint();document.getElementById("reveal").onclick=function(){visible=!visible;renderSetup()};document.getElementById("copy").onclick=function(){copy(secret)};document.getElementById("link").onclick=function(){copy(uri)};document.getElementById("verify").onclick=async function(){try{await api("/api/mfa/verify","POST",{otp:document.getElementById("otp").value});log("Mock authenticator code verified.");codes()}catch(e){renderSetup(e.message)}}}
async function setup(){try{var r=await api("/api/mfa/provision","POST",{});secret=r.secret;uri=r.provisioningUri;visible=false;log("Mock authenticator setup key: "+secret);log("Mock test verification code: "+r.mockOtp);renderSetup()}catch(e){error(e.message,identity)}}
function codeScreen(list){app.innerHTML='<p class="step">Step 3 of 4</p><div class="icon">🧾</div><h1>Save your recovery codes</h1><p>Keep these somewhere safe. Each code works once.</p><div class="codes">'+list.map(esc).join("<br>")+'</div><button class="secondary" id="copycodes">Copy recovery codes</button><p id="copy-msg"></p><button id="done">I have saved them</button>'+hint();document.getElementById("copycodes").onclick=function(){copy(list.join("\\n"))};document.getElementById("done").onclick=complete}
async function codes(){try{var r=await api("/api/mfa/backup-codes","POST",{});log("Mock backup recovery codes: "+r.codes.join(", "));codeScreen(r.codes)}catch(e){error(e.message,renderSetup)}}
function complete(){app.innerHTML='<p class="step">Step 4 of 4</p><div class="icon">✅</div><h1>MFA is ready</h1><p>Your authenticator is set up and recovery codes have been shown.</p><p class="notice"><strong>What happens next:</strong><br>Use your authenticator when asked to confirm a payment.</p><button id="out">Sign out</button><button class="secondary" id="manage">Recovery code options</button>';document.getElementById("out").onclick=out;document.getElementById("manage").onclick=options}
function options(){app.innerHTML='<div class="icon">🧾</div><h1>Recovery code options</h1><p>You can test a recovery code or make a replacement set.</p><button id="use">Use a recovery code</button><button class="secondary" id="new">Regenerate recovery codes</button><button class="secondary" id="back">Back</button>'+hint();document.getElementById("use").onclick=use;document.getElementById("new").onclick=async function(){try{var r=await api("/api/mfa/backup-codes/regenerate","POST",{});log("Mock replacement recovery codes: "+r.codes.join(", "));codeScreen(r.codes)}catch(e){error(e.message,options)}};document.getElementById("back").onclick=complete}
function use(message){app.innerHTML='<div class="icon">🔑</div><h1>Use a recovery code</h1><p>Enter one saved recovery code. It will work once.</p>'+(message?'<p class="error">'+esc(message)+'</p>':"")+'<label>Recovery code <small>Example: ABCD-EFGH-JKLM</small></label><input id="rc" autocomplete="one-time-code" autocapitalize="characters" placeholder="ABCD-EFGH-JKLM"><button id="check">Use recovery code</button><button class="secondary" id="back">Back</button>'+hint();document.getElementById("back").onclick=options;document.getElementById("check").onclick=async function(){try{await api("/api/mfa/recovery/verify","POST",{code:document.getElementById("rc").value});app.innerHTML='<div class="icon">✅</div><h1>Recovery code accepted</h1><p>This recovery code has now been used and cannot be used again.</p><button id="done">Done</button>';document.getElementById("done").onclick=complete}catch(e){use(e.message)}}}
async function out(){try{await api("/api/logout","POST",{})}catch(_){}csrf="";secret="";uri="";log("Signed out. Session removed.");identity()}
identity();
}());
</script>
</body>
</html>`;
}

const certificate = Bun.file("certs/cert.pem");
const privateKey = Bun.file("certs/key.pem");

if (!(await certificate.exists()) || !(await privateKey.exists())) {
  console.error("Secure server could not start.");
  process.exit(1);
}

try {
  server = Bun.serve({
    port: 3000,
    tls: { cert: certificate, key: privateKey },
    fetch: async (request: Request): Promise<Response> => {
      const url = new URL(request.url);
      const path = url.pathname;

      if (request.method === "GET" && path === "/") {
        return new Response(pageHtml(), { headers: securityHeaders({ "Content-Type": "text/html; charset=utf-8" }) });
      }

      if (request.method === "POST" && path === "/api/login") {
        if (!trustedOrigin(request)) {
          return apiResponse({ error: "Please use the SecureBank page to continue." }, 403);
        }

        cleanupFailedAttempts();
        const input = await requestBody(request);
        const dob = typeof input.dateOfBirth === "string" ? input.dateOfBirth.trim().replace(/\s+/g, " ") : "";
        const ending = typeof input.accountEnding === "string" ? input.accountEnding.trim() : "";
        const normalizedProof = `${dob.toLowerCase()}|${ending}`;
        const attemptKey = await loginAttemptKey(normalizedProof, request);
        const now = Date.now();

        /* Task: server-side lockout occurs before account-proof verification. */
        if (loginIsLocked(attemptKey, now)) {
          return apiResponse({ error: "Too many attempts. Please wait a few minutes, then try again." }, 429);
        }

        const verifiedMarcus = /^(14 june 1971|14\/06\/1971|1971-06-14)$/i.test(dob) && ending === "4821";
        if (!verifiedMarcus) {
          recordLoginFailure(attemptKey, now);
          return apiResponse({ error: "We could not confirm those details. Check them and try again." }, 400);
        }

        /* Successful authentication resets this proof/IP's tracked failures and rotates the session ID. */
        loginFailures.delete(attemptKey);
        const sid = randomToken();
        const csrf = randomToken();
        sessions.set(sid, { userId: "marcus-account", csrf, created: now, lastSeen: now });
        return apiResponse({ csrf }, 200, {
          "Set-Cookie": secureCookie("sid", sid, Math.floor(SESSION_ABSOLUTE_MS / 1000)),
        });
      }

      const authenticated = requireSession(request);
      if (!authenticated) {
        return apiResponse({ error: "Your session ended. Please sign in again." }, 401, {
          "Set-Cookie": secureCookie("sid", "", 0),
        });
      }

      if (request.method !== "GET" && !csrfIsValid(request, authenticated.session)) {
        return apiResponse({ error: "Your secure form token was missing. Please try again." }, 403);
      }

      /* Requirement 1: no endpoint accepts a user ID; authenticated owner exclusively selects state. */
      const state = getState(authenticated.session.userId);

      if (request.method === "POST" && path === "/api/mfa/provision") {
        const now = Date.now();

        /*
         Task: provisioning cannot bypass an active TOTP lockout.
         Importantly, failedAttempts and lockedUntil are intentionally never reset here.
        */
        if (now < state.lockedUntil) {
          return apiResponse({ error: "Too many attempts. Please wait a few minutes, then try again." }, 429);
        }

        const secret = base32Secret(20);
        state.encryptedSecret = await encryptAtRest(secret);
        state.verified = false;
        state.recoveryCodes = [];
        state.usedTotpCounters.clear();

        const test = await currentTotp(secret);
        const provisioningUri = "otpauth://totp/" + encodeURIComponent("SecureBank:Marcus") +
          "?secret=" + secret + "&issuer=SecureBank&algorithm=SHA1&digits=6&period=30";
        return apiResponse({ secret, provisioningUri, mockOtp: test.code });
      }

      if (request.method === "POST" && path === "/api/mfa/verify") {
        const input = await requestBody(request);
        const otp = typeof input.otp === "string" ? input.otp.trim() : "";
        const now = Date.now();

        if (now < state.lockedUntil) {
          return apiResponse({ error: "Too many attempts. Please wait a few minutes, then try again." }, 429);
        }

        let matched: bigint | null = null;
        if (/^\d{6}$/.test(otp) && state.encryptedSecret) {
          const secret = await decryptAtRest(state.encryptedSecret);
          const current = BigInt(Math.floor(now / 30_000));
          for (const offset of [-1n, 0n, 1n]) {
            const counter = current + offset;
            if (constantTimeEqual(otp, await totpForCounter(secret, counter)) &&
              !state.usedTotpCounters.has(counter.toString())) {
              matched = counter;
              break;
            }
          }
        }

        if (matched === null) {
          state.failedAttempts++;
          if (state.failedAttempts >= MAX_FAILED_ATTEMPTS) {
            state.failedAttempts = 0;
            state.lockedUntil = now + LOCKOUT_MS;
          }
          return apiResponse({
            error: "That code did not work. Check the 6 digits in your authenticator app and try again.",
          }, 400);
        }

        state.usedTotpCounters.add(matched.toString());
        state.failedAttempts = 0;
        state.verified = true;
        return apiResponse({ ok: true });
      }

      if (request.method === "POST" && path === "/api/mfa/backup-codes") {
        if (!state.encryptedSecret || !state.verified) {
          return apiResponse({ error: "Verify your authenticator code before creating recovery codes." }, 400);
        }
        if (state.recoveryCodes.length) {
          return apiResponse({ error: "Your recovery codes already exist. Use Recovery code options to replace them." }, 400);
        }
        const codes = recoveryCodes();
        state.recoveryCodes = await createRecoveryRecords(codes);
        return apiResponse({ codes });
      }

      if (request.method === "POST" && path === "/api/mfa/backup-codes/regenerate") {
        if (!state.encryptedSecret || !state.verified) {
          return apiResponse({ error: "Verify your authenticator before replacing recovery codes." }, 400);
        }
        const codes = recoveryCodes();
        state.recoveryCodes = await createRecoveryRecords(codes);
        return apiResponse({ codes });
      }

      if (request.method === "POST" && path === "/api/mfa/recovery/verify") {
        const now = Date.now();

        /* Task: recovery-code lockout is checked before format and matching work. */
        if (now < state.recoveryLockedUntil) {
          return apiResponse({ error: "Too many recovery code attempts. Please wait a few minutes, then try again." }, 429);
        }

        const input = await requestBody(request);
        const code = typeof input.code === "string" ? input.code.trim().toUpperCase() : "";

        const failedRecovery = (): Response => {
          state.recoveryFailedAttempts++;
          if (state.recoveryFailedAttempts >= MAX_FAILED_ATTEMPTS) {
            state.recoveryFailedAttempts = 0;
            state.recoveryLockedUntil = now + LOCKOUT_MS;
          }
          return apiResponse({
            error: "That recovery code did not work. Check the code and try another saved code.",
          }, 400);
        };

        /* Invalid format counts as a failed attempt too. */
        if (!/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(code)) {
          failedRecovery();
          return apiResponse({
            error: "Enter a recovery code in the example format: ABCD-EFGH-JKLM.",
          }, 400);
        }

        let match: RecoveryRecord | undefined;
        for (const record of state.recoveryCodes) {
          if (record.consumed) continue;
          const candidate = await deriveRecovery(code, record.salt);
          if (constantTimeEqual(candidate, record.derived)) {
            match = record;
            break;
          }
        }

        if (!match) return failedRecovery();

        match.consumed = true;
        /* Task: a valid, single-use recovery code clears its failure history. */
        state.recoveryFailedAttempts = 0;
        state.recoveryLockedUntil = 0;
        return apiResponse({ ok: true });
      }

      if (request.method === "POST" && path === "/api/logout") {
        sessions.delete(authenticated.id);
        return apiResponse({ ok: true }, 200, { "Set-Cookie": secureCookie("sid", "", 0) });
      }

      return apiResponse({ error: "Page not found." }, 404);
    },
    error() {
      return new Response("Something went wrong. Please try again.", {
        status: 500,
        headers: securityHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
      });
    },
  });

  console.log(`Secure MFA app running at https://localhost:${server.port}`);
} catch {
  console.error("Secure server could not start.");
  process.exit(1);
}
