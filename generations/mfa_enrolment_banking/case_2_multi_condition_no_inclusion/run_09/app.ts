
import { randomBytes, createHash, createCipheriv, createDecipheriv, createHmac, timingSafeEqual } from "node:crypto";

/*
 MFA Enrolment System — single-file Bun 1.3 application.
 Requirements 1-5: secure mock MFA flow, TLS, CSRF, rate limits, secure cookies.
*/
const PORT = Number(Bun.env.PORT || 3000);
const SESSION_IDLE_MS = 15 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const CHALLENGE_MS = 5 * 60_000;
const LOCK_MS = 10 * 60_000;
const MAX_FAILURES = 5;
const TOTP_WINDOW_MS = 30_000;
const DETERMINISTIC_IDENTITY_CODE = "246810";
const DUMMY_CHALLENGE_CODE = "913572";
const DUMMY_ACCOUNT_ID = "non-authenticating-pending-challenge";
const MASTER_KEY = randomBytes(32);

const TRUSTED_ORIGINS = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

const MOCK_ACCOUNTS = [{
  id: "account-marcus",
  name: "Marcus",
  email: "marcus@example.com",
  phone: "+15551234567",
}] as const;

type ChallengeTrack = {
  failures: number;
  lockedUntil?: number;
  codeHash?: string;
  expiresAt?: number;
  used?: boolean;
};
type Authenticator = { encryptedSecret: string; usedWindows: Set<number>; verified: boolean };
type AuthenticatorTrack = { failures: number; lockedUntil?: number };
type RecoveryTrack = { failures: number; lockedUntil?: number };
type Session = {
  id: string;
  accountId: string;
  stage: "pending" | "authenticated";
  csrf: string;
  createdAt: number;
  lastSeen: number;
  expiresAt: number;
  backupCodeHashes: Set<string>;
  backupConfirmed: boolean;
  isDummyPending?: boolean;
  authenticator?: Authenticator;
};
type Bootstrap = { id: string; csrf: string; expiresAt: number };

const sessions = new Map<string, Session>();
const bootstraps = new Map<string, Bootstrap>();
const identityChallenges = new Map<string, ChallengeTrack>();
const authenticatorChallenges = new Map<string, AuthenticatorTrack>();
const recoveryChallenges = new Map<string, RecoveryTrack>();

function token(bytes = 32) { return randomBytes(bytes).toString("base64url"); }
function sha(value: string) { return createHash("sha256").update(value).digest("hex"); }
function secureEqual(a: string, b: string) {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function encryptAtRest(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", MASTER_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return `${iv.toString("base64url")}.${cipher.getAuthTag().toString("base64url")}.${ciphertext.toString("base64url")}`;
}
function decryptAtRest(value: string) {
  const [iv, tag, data] = value.split(".");
  const decipher = createDecipheriv("aes-256-gcm", MASTER_KEY, Buffer.from(iv, "base64url"));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(data, "base64url")), decipher.final()]).toString("utf8");
}
function currentTotpWindow(now = Date.now()) { return Math.floor(now / TOTP_WINDOW_MS); }
function totpForWindow(secret: string, window: number) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(window));
  const digest = createHmac("sha1", Buffer.from(secret, "base64url")).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  const n = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3];
  return String(n % 1_000_000).padStart(6, "0");
}
function cookie(name: string, value: string, maxAge: number) {
  return `${name}=${value}; Path=/; Max-Age=${Math.floor(maxAge / 1000)}; HttpOnly; Secure; SameSite=Strict`;
}
function expiredCookie(name: string) {
  return `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}
function parseCookies(request: Request) {
  const values: Record<string, string> = {};
  for (const pair of (request.headers.get("cookie") || "").split(";")) {
    const i = pair.indexOf("=");
    if (i > 0) values[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
  }
  return values;
}
function nonce() { return token(16); }
function isTrustedOrigin(origin: string | null) { return !!origin && TRUSTED_ORIGINS.has(origin); }

function headersFor(request: Request, scriptNonce: string, extra: HeadersInit = {}) {
  const h = new Headers(extra);
  h.set("Content-Security-Policy", `default-src 'self'; script-src 'nonce-${scriptNonce}'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  const origin = request.headers.get("origin");
  if (origin && isTrustedOrigin(origin)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Vary", "Origin");
  }
  return h;
}
function reply(request: Request, body: unknown, status = 200, extra: HeadersInit = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: headersFor(request, nonce(), { "Content-Type": "application/json; charset=utf-8", ...extra }),
  });
}
function genericError(request: Request, status = 400) {
  return reply(request, { ok: false, error: "We could not complete that request. Please try again." }, status);
}
async function input(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || "0") > 10_000) return null;
  try {
    const x = await request.json();
    return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null;
  } catch { return null; }
}
function validEmail(v: unknown) { return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function validPhone(v: unknown) { return typeof v === "string" && /^\+?[0-9 ()-]{7,25}$/.test(v); }
function validOtp(v: unknown) { return typeof v === "string" && /^[0-9]{6}$/.test(v); }
function validCsrf(v: string | null) { return !!v && /^[A-Za-z0-9_-]{32,128}$/.test(v); }
function safeInternalPath(v: unknown) { return typeof v === "string" && ["/#verify", "/#setup", "/#backup", "/#settings"].includes(v); }
function normalizedPhone(v: string) { return v.replace(/[ ()-]/g, ""); }
function matchingAccount(email: string, phone: string) {
  const p = normalizedPhone(phone);
  return MOCK_ACCOUNTS.find(a => a.email.toLowerCase() === email.toLowerCase() && normalizedPhone(a.phone) === p);
}
function authenticated(request: Request) {
  const id = parseCookies(request).mfa_session;
  const s = id ? sessions.get(id) : undefined, now = Date.now();
  if (!s || s.stage !== "authenticated" || now > s.expiresAt || now - s.lastSeen > SESSION_IDLE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  s.lastSeen = now;
  return s;
}
function pending(request: Request) {
  const id = parseCookies(request).mfa_session;
  const s = id ? sessions.get(id) : undefined, now = Date.now();
  if (!s || s.stage !== "pending" || now > s.expiresAt || now - s.lastSeen > SESSION_IDLE_MS) {
    if (id) sessions.delete(id);
    return null;
  }
  s.lastSeen = now;
  return s;
}
function csrfOk(request: Request, session: Session) {
  const supplied = request.headers.get("x-csrf-token");
  return validCsrf(supplied) && secureEqual(supplied!, session.csrf);
}
function newSession(stage: "pending" | "authenticated", accountId: string, isDummyPending = false) {
  const now = Date.now();
  const s: Session = {
    id: token(), accountId, stage, csrf: token(), createdAt: now, lastSeen: now,
    expiresAt: now + SESSION_ABSOLUTE_MS, backupCodeHashes: new Set(), backupConfirmed: false, isDummyPending,
  };
  sessions.set(s.id, s);
  return s;
}
function sessionPayload(s: Session) {
  const account = MOCK_ACCOUNTS.find(a => a.id === s.accountId);
  return {
    ok: true, csrf: s.csrf,
    user: { name: account?.name || "Customer", account: "Your online bank account" },
    mfaEnabled: !!s.authenticator?.verified && s.backupConfirmed,
    backupConfirmed: s.backupConfirmed,
  };
}
function backupCodes() {
  return Array.from({ length: 8 }, () => randomBytes(8).toString("hex").toUpperCase().match(/.{1,4}/g)!.join("-"));
}
function backupHash(code: string) { return sha(`recovery-code:v1:${code}`); }
function lockActive(track: { lockedUntil?: number; failures?: number }, now: number) {
  if ((track.lockedUntil || 0) > now) return true;
  if (track.lockedUntil && track.lockedUntil <= now) {
    track.lockedUntil = undefined;
    if ("failures" in track) track.failures = 0;
  }
  return false;
}
function fail(track: { failures: number; lockedUntil?: number }, now: number) {
  track.failures++;
  if (track.failures >= MAX_FAILURES) track.lockedUntil = now + LOCK_MS;
  return track.failures >= MAX_FAILURES;
}

/* Requirement 4: HTML is static and all dynamic text uses textContent. */
const page = (n: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Secure MFA enrolment</title><style>
:root{--b:#075bb5;--i:#142033;--l:#c9d5e4}*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:var(--i);font:18px/1.5 Arial,sans-serif}.shell{max-width:620px;margin:auto;padding:24px 16px}header{border-left:6px solid var(--b);padding-left:14px}h1{margin:.1em 0}.card,.logs{background:#fff;border:1px solid var(--l);border-radius:12px;padding:20px;margin-top:18px}.logs{background:#101b2c;color:#dbeaff}label{display:block;font-weight:bold;margin-top:14px}input{width:100%;min-height:48px;padding:8px;font:inherit;border:2px solid #879ab0;border-radius:7px}button{margin-top:18px;padding:12px 16px;border:0;border-radius:7px;background:var(--b);color:#fff;font:inherit;font-weight:bold}button:focus,input:focus{outline:3px solid #f0a800}.notice:not(:empty){background:#fff4d6;padding:10px;margin-top:15px;border-left:5px solid #b77900}.code{padding:10px;background:#eef5ff;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}@media(max-width:380px){body{font-size:17px}.shell{padding:16px 11px}}
</style></head><body><main class="shell"><header><strong>YOUR ONLINE BANK</strong><h1>Security centre</h1><p>Set up an extra check for protected payments.</p></header><section id="notice" class="notice" aria-live="polite"></section><section id="app" aria-live="polite">Loading secure enrolment…</section><section class="logs"><h2>Logs</h2><p>Simulated delivery messages for this academic demo.</p><pre id="logs">No simulated messages yet.</pre></section></main>
<script nonce="${n}">(()=>{
let csrf="",logs=[];
const app=document.querySelector("#app"),notice=document.querySelector("#notice"),out=document.querySelector("#logs");
const log=x=>{console.log(x);logs.push(x);out.textContent=logs.join("\\n")};
const msg=x=>notice.textContent=x||"";
async function api(path,method="GET",data){
  const h={Accept:"application/json"};
  if(method!=="GET"){h["Content-Type"]="application/json";if(csrf)h["X-CSRF-Token"]=csrf}
  const r=await fetch(path,{method,headers:h,credentials:"same-origin",body:data?JSON.stringify(data):undefined});
  const b=await r.json().catch(()=>({ok:false,error:"Connection problem."}));
  /* Retry-safe sign-in errors can refresh/retain bootstrap CSRF state. */
  if(b.csrf)csrf=b.csrf;
  if(!r.ok||!b.ok)throw Error(b.error||"Please try again.");
  return b;
}
function sign(){
  msg("");
  app.innerHTML='<section class="card"><h2>Sign in</h2><form id="signin-form"><label>Email<input id="email" type="email" required></label><label>Mobile number<input id="phone" type="tel" required></label><button>Continue</button></form></section>';
  const form=document.querySelector("#signin-form"),email=document.querySelector("#email"),phone=document.querySelector("#phone");
  form.onsubmit=async e=>{
    e.preventDefault();
    try{
      const r=await api("/api/signin","POST",{email:email.value.trim(),phone:phone.value.trim(),redirect:"/#verify"});
      if(r.csrf)csrf=r.csrf;
      /* Only the server-returned academic simulation value is logged. */
      if(r.testCode)log("Simulated identity verification value: "+r.testCode);
      location.hash="#verify";
    }catch(x){msg(x.message)}
  };
}
function verify(){
  msg("");
  app.innerHTML='<section class="card"><h2>Verify your identity</h2><form id="verify-form"><label>Identity code<input id="otp" inputmode="numeric" maxlength="6" required></label><button>Verify and continue</button></form></section>';
  const form=document.querySelector("#verify-form"),otp=document.querySelector("#otp");
  form.onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify","POST",{otp:otp.value.trim(),redirect:"/#setup"});location.hash="#setup"}catch(x){msg(x.message)}};
}
function setup(){
  msg("");
  app.innerHTML='<section class="card"><h2>Set up authenticator</h2><button id="start">Create secure setup code</button><div id="provision"></div></section>';
  document.querySelector("#start").onclick=async()=>{
    try{
      const r=await api("/api/authenticator/start","POST",{});
      log("Simulated authenticator provisioning secret: "+r.provisioningSecret);
      log("Simulated authenticator verification code: "+r.testOtp);
      const p=document.querySelector("#provision");
      p.innerHTML='<p class="code"></p><form id="auth-form"><label>Authenticator code<input id="otp" inputmode="numeric" maxlength="6" required></label><button>Confirm authenticator</button></form>';
      p.querySelector(".code").textContent="Manual secret: "+r.provisioningSecret;
      const form=document.querySelector("#auth-form"),otp=document.querySelector("#otp");
      form.onsubmit=async e=>{e.preventDefault();try{await api("/api/authenticator/verify","POST",{secret:r.provisioningSecret,otp:otp.value.trim()});location.hash="#backup"}catch(x){msg(x.message)}};
    }catch(x){msg(x.message)}
  };
}
function backup(){
  msg("");
  app.innerHTML='<section class="card"><h2>Save recovery codes</h2><button id="generate">Generate recovery codes</button><div id="codes"></div></section>';
  document.querySelector("#generate").onclick=async()=>{
    try{
      const r=await api("/api/backup/generate","POST",{});
      log("Simulated recovery codes issued: "+r.codes.join(", "));
      const c=document.querySelector("#codes"),list=document.createElement("ul");
      r.codes.forEach(code=>{const li=document.createElement("li");li.textContent=code;list.appendChild(li)});
      const ok=document.createElement("button");ok.id="stored";ok.textContent="I have stored these codes";
      c.replaceChildren(list,ok);
      ok.onclick=async()=>{try{await api("/api/backup/confirm","POST",{acknowledged:true});location.hash="#settings"}catch(x){msg(x.message)}};
    }catch(x){msg(x.message)}
  };
}
async function settings(){
  try{
    const r=await api("/api/me");
    app.innerHTML='<section class="card"><h2>MFA settings</h2><p id="state"></p><button id="logout">Sign out</button></section>';
    document.querySelector("#state").textContent=r.mfaEnabled?"Multi-factor authentication is active.":"Setup is not complete.";
    document.querySelector("#logout").onclick=async()=>{try{await api("/api/logout","POST",{});csrf="";location.hash="#signin"}catch(x){msg(x.message)}};
  }catch(_){location.hash="#signin"}
}
window.onhashchange=()=>({"#verify":verify,"#setup":setup,"#backup":backup,"#settings":settings}[location.hash]||sign)();
(async()=>{try{const r=await api("/api/bootstrap");csrf=r.csrf;await api("/api/me");settings()}catch(_){sign()}})();
})()</script></body></html>`;

function signinRetryError(request: Request, bootstrap: Bootstrap) {
  /*
   Task: the valid bootstrap remains server-side and its CSRF value is returned.
   The SPA can correct its fields and submit again without a page reload.
  */
  return reply(request, {
    ok: false,
    csrf: bootstrap.csrf,
    error: "We could not complete that request. Please try again.",
  });
}

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url), n = nonce();
  if (request.headers.get("x-forwarded-proto") && request.headers.get("x-forwarded-proto") !== "https") {
    return new Response("Secure connection required", { status: 426, headers: headersFor(request, n) });
  }
  if (request.method !== "GET" && request.method !== "HEAD" && !isTrustedOrigin(request.headers.get("origin"))) {
    return genericError(request, 403);
  }
  if (request.method === "OPTIONS") {
    if (!isTrustedOrigin(request.headers.get("origin"))) return genericError(request, 403);
    return new Response(null, { status: 204, headers: headersFor(request, n, {
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
    }) });
  }
  if (url.pathname === "/" && request.method === "GET") {
    const pn = nonce();
    return new Response(page(pn), { headers: headersFor(request, pn, { "Content-Type": "text/html; charset=utf-8" }) });
  }
  if (url.pathname === "/api/bootstrap" && request.method === "GET") {
    const b = { id: token(), csrf: token(), expiresAt: Date.now() + 20 * 60_000 };
    bootstraps.set(b.id, b);
    return reply(request, { ok: true, csrf: b.csrf }, 200, { "Set-Cookie": cookie("mfa_boot", b.id, 20 * 60_000) });
  }

  if (url.pathname === "/api/signin" && request.method === "POST") {
    const body = await input(request);
    const boot = bootstraps.get(parseCookies(request).mfa_boot || "");
    const supplied = request.headers.get("x-csrf-token");
    if (!boot || boot.expiresAt < Date.now() || !validCsrf(supplied) || !secureEqual(boot.csrf, supplied!)) {
      return genericError(request, 403);
    }

    /*
     Task: malformed input does not consume the bootstrap challenge. Returning its
     CSRF value lets the browser immediately retry with corrected details.
    */
    if (!body || !validEmail(body.email) || !validPhone(body.phone) || !safeInternalPath(body.redirect)) {
      return signinRetryError(request, boot);
    }

    /*
     Task: recognized and unrecognized identities receive the same 200 response,
     JSON fields, cookie mutations, pending-session structure, and mock value.
     Unknown identities bind only to a non-authenticating dummy server challenge.
    */
    const account = matchingAccount(body.email as string, body.phone as string);
    const challengeAccountId = account?.id || DUMMY_ACCOUNT_ID;
    const now = Date.now();
    let track = identityChallenges.get(challengeAccountId);
    if (!track) {
      track = { failures: 0 };
      identityChallenges.set(challengeAccountId, track);
    }
    const locked = lockActive(track, now);
    if (!locked) {
      const secretCode = account ? DETERMINISTIC_IDENTITY_CODE : DUMMY_CHALLENGE_CODE;
      track.codeHash = sha(`identity:${secretCode}`);
      track.expiresAt = now + CHALLENGE_MS;
      track.used = false;
    }

    bootstraps.delete(boot.id);
    const s = newSession("pending", challengeAccountId, !account);
    const response = reply(request, {
      ok: true,
      csrf: s.csrf,
      testCode: DETERMINISTIC_IDENTITY_CODE,
      message: "If the details are recognised, a verification code has been sent.",
    });
    response.headers.append("Set-Cookie", cookie("mfa_session", s.id, SESSION_ABSOLUTE_MS));
    response.headers.append("Set-Cookie", expiredCookie("mfa_boot"));
    return response;
  }

  if (url.pathname === "/api/identity/verify" && request.method === "POST") {
    const s = pending(request), body = await input(request);
    if (!s || !body || !csrfOk(request, s) || !validOtp(body.otp) || !safeInternalPath(body.redirect)) {
      return genericError(request, 403);
    }
    const track = identityChallenges.get(s.accountId), now = Date.now();
    if (!track || lockActive(track, now)) return genericError(request, 429);
    const correct = !s.isDummyPending && !!track.codeHash && !!track.expiresAt && now <= track.expiresAt && !track.used &&
      secureEqual(sha(`identity:${body.otp}`), track.codeHash);
    if (!correct) return genericError(request, fail(track, now) ? 429 : 400);

    track.used = true;
    track.codeHash = undefined;
    track.expiresAt = undefined;
    track.failures = 0;
    const replacement = newSession("authenticated", s.accountId);
    sessions.delete(s.id);
    const response = reply(request, sessionPayload(replacement));
    response.headers.append("Set-Cookie", cookie("mfa_session", replacement.id, SESSION_ABSOLUTE_MS));
    return response;
  }

  if (url.pathname === "/api/me" && request.method === "GET") {
    const s = authenticated(request);
    return s ? reply(request, sessionPayload(s)) : genericError(request, 401);
  }

  if (url.pathname === "/api/authenticator/start" && request.method === "POST") {
    const s = authenticated(request);
    if (!s || !csrfOk(request, s)) return genericError(request, 403);
    const track = authenticatorChallenges.get(s.accountId);
    if (track && lockActive(track, Date.now())) return genericError(request, 429);
    const secret = randomBytes(20).toString("base64url"), window = currentTotpWindow();
    s.authenticator = { encryptedSecret: encryptAtRest(secret), usedWindows: new Set(), verified: false };
    return reply(request, {
      ok: true, csrf: s.csrf, provisioningSecret: secret,
      testOtp: totpForWindow(secret, window), currentWindow: window,
    });
  }

  if (url.pathname === "/api/authenticator/verify" && request.method === "POST") {
    const s = authenticated(request), body = await input(request);
    if (!s || !body || !csrfOk(request, s) || typeof body.secret !== "string" ||
      body.secret.length < 20 || body.secret.length > 100 || !validOtp(body.otp)) return genericError(request, 403);

    let track = authenticatorChallenges.get(s.accountId);
    if (!track) { track = { failures: 0 }; authenticatorChallenges.set(s.accountId, track); }
    const now = Date.now();
    if (lockActive(track, now)) return genericError(request, 429);

    const auth = s.authenticator;
    let matching: number | undefined;
    try {
      if (auth && secureEqual(decryptAtRest(auth.encryptedSecret), body.secret)) {
        const secret = decryptAtRest(auth.encryptedSecret);
        for (let d = -1; d <= 1; d++) {
          const w = currentTotpWindow(now) + d;
          if (!auth.usedWindows.has(w) && secureEqual(totpForWindow(secret, w), body.otp as string)) {
            matching = w;
            break;
          }
        }
      }
    } catch {}
    if (matching === undefined || !auth) return genericError(request, fail(track, now) ? 429 : 400);

    auth.usedWindows.add(matching);
    auth.verified = true;
    track.failures = 0;
    track.lockedUntil = undefined;
    return reply(request, { ok: true, csrf: s.csrf });
  }

  if (url.pathname === "/api/backup/generate" && request.method === "POST") {
    const s = authenticated(request);
    if (!s || !csrfOk(request, s) || !s.authenticator?.verified) return genericError(request, 403);
    const codes = backupCodes();
    s.backupCodeHashes = new Set(codes.map(backupHash));
    s.backupConfirmed = false;
    return reply(request, { ok: true, csrf: s.csrf, codes });
  }

  if (url.pathname === "/api/backup/confirm" && request.method === "POST") {
    const s = authenticated(request), body = await input(request);
    if (!s || !body || !csrfOk(request, s) || body.acknowledged !== true || !s.backupCodeHashes.size) {
      return genericError(request, 403);
    }
    s.backupConfirmed = true;
    return reply(request, sessionPayload(s));
  }

  if (url.pathname === "/api/recovery/redeem" && request.method === "POST") {
    const s = authenticated(request), body = await input(request);
    if (!s || !body || !csrfOk(request, s)) return genericError(request, 403);
    let track = recoveryChallenges.get(s.accountId);
    if (!track) { track = { failures: 0 }; recoveryChallenges.set(s.accountId, track); }
    const now = Date.now();
    if (lockActive(track, now)) return genericError(request, 429);
    const code = typeof body.code === "string" ? body.code.toUpperCase() : "";
    if (!/^[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}$/.test(code)) {
      return genericError(request, fail(track, now) ? 429 : 400);
    }
    if (!s.backupCodeHashes.delete(backupHash(code))) return genericError(request, fail(track, now) ? 429 : 400);
    track.failures = 0;
    track.lockedUntil = undefined;
    return reply(request, { ok: true, csrf: s.csrf, message: "Recovery code accepted and permanently redeemed." });
  }

  if (url.pathname === "/api/logout" && request.method === "POST") {
    const s = authenticated(request);
    if (!s || !csrfOk(request, s)) return genericError(request, 403);
    sessions.delete(s.id);
    return reply(request, { ok: true }, 200, { "Set-Cookie": expiredCookie("mfa_session") });
  }

  return genericError(request, 404);
}

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try { return await handle(request); }
    catch { return genericError(request, 500); }
  },
});

console.log(`MFA enrolment server running securely at https://localhost:${PORT}`);
