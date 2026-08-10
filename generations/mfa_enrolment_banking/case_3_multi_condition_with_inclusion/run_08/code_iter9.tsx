
import { readFileSync } from "fs";

/* Requirements 1–5: owner-bound in-memory demo state, CSRF, encrypted TOTP,
   salted recovery-code hashes, lockouts, secure sessions, and TLS-only service. */
const accounts = new Map<string, Account>();
const sessions = new Map<string, Session>();
const bootstrapTokens = new Map<string, number>();
const encKey = crypto.getRandomValues(new Uint8Array(32));
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RECOVERY_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const ORIGINS = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
const IDLE = 30 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 15 * 60_000, LOCKOUT = 10 * 60_000, STEP = 30_000;

type Challenge = { salt: string; hash: string; expires: number; used: boolean };
type Secret = { iv: string; data: string };
type Recovery = { salt: string; hash: string; used: boolean };
type Account = {
  id: string; email: string; mfa: boolean; secret?: Secret; usedSteps: Set<number>; recoveries: Recovery[];
  identityFailures: number; identityLockedUntil: number;
  authFailures: number; authLockedUntil: number;
  recoveryFailures: number; recoveryLockedUntil: number;
};
type Session = {
  id: string; accountId: string; csrf: string; created: number; seen: number;
  identityVerified: boolean; identity?: Challenge;
};

const marcus: Account = {
  id: "acct_marcus_demo", email: "marcus@example.com", mfa: false, usedSteps: new Set(), recoveries: [],
  identityFailures: 0, identityLockedUntil: 0, authFailures: 0, authLockedUntil: 0,
  recoveryFailures: 0, recoveryLockedUntil: 0,
};
accounts.set(marcus.id, marcus);

const random = (n = 32) => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
const hash = (v: string) => new Bun.CryptoHasher("sha256").update(v).digest("hex");
function equal(a: string, b: string) {
  if (a.length !== b.length) return false;
  let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function safeObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v) &&
    !["id", "accountId", "userId", "redirect", "next"].some(k => k in (v as Record<string, unknown>));
}
const validEmail = (v: unknown) => typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const validPassword = (v: unknown) => typeof v === "string" && v.length > 0 && v.length <= 128;
const validOtp = (v: unknown) => typeof v === "string" && /^\d{6}$/.test(v);
const validRecovery = (v: unknown) => typeof v === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(v);

function makeSeed() { return [...crypto.getRandomValues(new Uint8Array(32))].map(x => BASE32[x & 31]).join(""); }
function grouped(v: string) { return v.match(/.{1,4}/g)!.join("-"); }
function makeRecovery() {
  const v = [...crypto.getRandomValues(new Uint8Array(10))].map(x => RECOVERY_CHARS[x & 31]).join("");
  return v.slice(0, 5) + "-" + v.slice(5);
}
function identityCode(sessionId: string) {
  return String(parseInt(hash("identity-demo|" + sessionId).slice(0, 12), 16) % 1_000_000).padStart(6, "0");
}
function challenge(code: string): Challenge {
  const salt = random(24);
  return { salt, hash: hash(salt + code), expires: Date.now() + CODE_LIFE, used: false };
}
function lockActive(until: number) { return Date.now() < until; }
function expireAuthLock(account: Account) {
  if (account.authLockedUntil && Date.now() >= account.authLockedUntil) {
    account.authLockedUntil = 0; account.authFailures = 0;
  }
}
function expireRecoveryLock(account: Account) {
  if (account.recoveryLockedUntil && Date.now() >= account.recoveryLockedUntil) {
    account.recoveryLockedUntil = 0; account.recoveryFailures = 0;
  }
}
function expireIdentityLock(account: Account) {
  if (account.identityLockedUntil && Date.now() >= account.identityLockedUntil) {
    account.identityLockedUntil = 0; account.identityFailures = 0;
  }
}
async function encryptSecret(value: string): Promise<Secret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encKey, "AES-GCM", false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), data: Buffer.from(data).toString("base64url") };
}
async function decryptSecret(secret: Secret) {
  const key = await crypto.subtle.importKey("raw", encKey, "AES-GCM", false, ["decrypt"]);
  const data = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(secret.iv, "base64url") }, key, Buffer.from(secret.data, "base64url"));
  return decoder.decode(data);
}
function base32Bytes(v: string) {
  const out: number[] = []; let buffer = 0, bits = 0;
  for (const c of v) { buffer = (buffer << 5) | BASE32.indexOf(c); bits += 5; if (bits >= 8) { out.push((buffer >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
async function totp(secret: string, count: number) {
  const counter = new Uint8Array(8); let n = BigInt(count);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signed[19] & 15;
  const value = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}

/* Requirement 2: restrictive headers, no sensitive caching, trusted CORS only. */
function headers(nonce: string) {
  return {
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", Vary: "Origin",
  };
}
function json(data: unknown, status = 200, nonce = "") { return Response.json(data, { status, headers: headers(nonce) }); }
function fail(message = "We could not complete that request. Please try again.", status = 400, nonce = "") { return json({ ok: false, message }, status, nonce); }
function cookies(req: Request) {
  return Object.fromEntries((req.headers.get("cookie") || "").split(";").map(x => {
    const p = x.indexOf("="); return p < 0 ? ["", ""] : [x.slice(0, p).trim(), decodeURIComponent(x.slice(p + 1))];
  }));
}
function sessionCookie(v: string, age?: number) { return `mfa_session=${encodeURIComponent(v)}; Path=/; HttpOnly; Secure; SameSite=Strict${age === undefined ? "" : "; Max-Age=" + age}`; }
function bootstrapCookie(v: string) { return `signin_csrf=${encodeURIComponent(v)}; Path=/; Secure; SameSite=Strict; Max-Age=600`; }
function getSession(req: Request) {
  const s = sessions.get(cookies(req).mfa_session || "");
  if (!s) return null;
  if (Date.now() - s.seen > IDLE || Date.now() - s.created > ABSOLUTE) { sessions.delete(s.id); return null; }
  s.seen = Date.now(); return s;
}
function owner(req: Request, nonce: string) {
  const session = getSession(req), account = session && accounts.get(session.accountId);
  return session && account ? { session, account } : { error: fail("Please sign in again to continue.", 401, nonce) };
}
function csrf(req: Request, session: Session, nonce: string) { return equal(req.headers.get("x-csrf-token") || "", session.csrf) ? null : fail("Your secure page has changed. Refresh the page and try again.", 403, nonce); }
async function readBody(req: Request) { const x = await req.json().catch(() => null); return safeObject(x) ? x : null; }

async function api(req: Request, path: string, nonce: string): Promise<Response> {
  if (path === "/api/csrf-bootstrap" && req.method === "GET") {
    const token = random(); bootstrapTokens.set(token, Date.now() + 600_000);
    const out = json({ ok: true, csrf: token }, 200, nonce); out.headers.set("Set-Cookie", bootstrapCookie(token)); return out;
  }
  if (path === "/api/signin" && req.method === "POST") {
    const data = await readBody(req), token = req.headers.get("x-login-csrf") || "", expiry = bootstrapTokens.get(token);
    bootstrapTokens.delete(token);
    if (!ORIGINS.has(req.headers.get("origin") || "") || !expiry || expiry < Date.now() || !equal(token, cookies(req).signin_csrf || "")) return fail("Please refresh the sign-in page and try again.", 403, nonce);
    if (!data || !validEmail(data.email) || !validPassword(data.password)) return fail("Enter a valid email address and password.", 400, nonce);
    if (!equal(String(data.email).toLowerCase(), marcus.email) || !equal(String(data.password), "MarcusDemo!2025")) return fail("We could not sign you in. Check your email and password, then try again.", 401, nonce);
    for (const [id, s] of sessions) if (s.accountId === marcus.id) sessions.delete(id);
    const session: Session = { id: random(), accountId: marcus.id, csrf: random(), created: Date.now(), seen: Date.now(), identityVerified: false };
    sessions.set(session.id, session);
    const out = json({ ok: true, next: "#identity" }, 200, nonce); out.headers.set("Set-Cookie", sessionCookie(session.id)); return out;
  }

  const current = owner(req, nonce);
  if ("error" in current) return current.error;
  const { session, account } = current;
  if (path === "/api/session" && req.method === "GET") return json({
    ok: true, csrf: session.csrf, identityVerified: session.identityVerified, mfa: account.mfa,
    provisioned: !!account.secret, recoveryCount: account.recoveries.length,
  }, 200, nonce);

  if (req.method !== "POST") return fail("That page is not available.", 404, nonce);
  const data = await readBody(req); if (!data) return fail(undefined, 400, nonce);
  const protectedError = csrf(req, session, nonce); if (protectedError) return protectedError;

  if (path === "/api/logout") {
    sessions.delete(session.id); const out = json({ ok: true }, 200, nonce); out.headers.set("Set-Cookie", sessionCookie("", 0)); return out;
  }

  /* Task: identity lockout is account scoped and survives code re-requests/new sessions. */
  if (path === "/api/identity/request") {
    expireIdentityLock(account);
    if (lockActive(account.identityLockedUntil)) return fail("Too many identity-code attempts. Please wait a few minutes before requesting another code.", 429, nonce);
    session.identity = challenge(identityCode(session.id));
    return json({ ok: true, simulatedCode: identityCode(session.id) }, 200, nonce);
  }
  if (path === "/api/identity/verify") {
    if (!validOtp(data.code)) return fail("Enter exactly six digits, for example 123456.", 400, nonce);
    expireIdentityLock(account);
    if (lockActive(account.identityLockedUntil)) return fail("Too many identity-code attempts. Please wait a few minutes before trying again.", 429, nonce);
    const c = session.identity;
    if (!c) return fail("Request a new code, then try again.", 400, nonce);
    if (c.used) return fail("That code was already used. Request a new code.", 400, nonce);
    if (Date.now() > c.expires) return fail("That code has expired. Request a new code.", 400, nonce);
    if (!equal(hash(c.salt + String(data.code)), c.hash)) {
      account.identityFailures++;
      if (account.identityFailures >= 5) { account.identityLockedUntil = Date.now() + LOCKOUT; return fail("Too many attempts. Please wait a few minutes before trying again.", 429, nonce); }
      return fail("That code does not match. Check the six digits, or request a new code.", 400, nonce);
    }
    c.used = true; account.identityFailures = 0; session.identityVerified = true;
    return json({ ok: true, next: account.mfa ? "#saved" : "#setup" }, 200, nonce);
  }
  if (!session.identityVerified) return fail("Please complete the identity check before changing MFA settings.", 403, nonce);

  if (path === "/api/authenticator/provision") {
    expireAuthLock(account);
    const value = makeSeed(); account.secret = await encryptSecret(value); account.usedSteps.clear();
    const issuer = "Local Bank", label = issuer + ":" + account.email;
    const uri = `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(value)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    /* Task: do not reset auth failure/lockout state here. */
    return json({ ok: true, secret: grouped(value), provisioningUri: uri, simulatedOtp: await totp(value, Math.floor(Date.now() / STEP)) }, 200, nonce);
  }
  if (path === "/api/authenticator/confirm") {
    if (!validOtp(data.code)) return fail("Enter exactly six digits, for example 123456.", 400, nonce);
    if (!account.secret) return fail("Show a setup key before confirming your authenticator.", 400, nonce);
    expireAuthLock(account);
    if (lockActive(account.authLockedUntil)) return fail("Too many attempts. Please wait a few minutes, then try again.", 429, nonce);
    const secret = await decryptSecret(account.secret), now = Math.floor(Date.now() / STEP); let matched = -1;
    for (const step of [now - 1, now, now + 1]) if (equal(await totp(secret, step), String(data.code))) { matched = step; break; }
    if (matched < 0 || account.usedSteps.has(matched)) {
      account.authFailures++;
      if (account.authFailures >= 5) { account.authLockedUntil = Date.now() + LOCKOUT; return fail("Too many attempts. Please wait a few minutes before trying again.", 429, nonce); }
      return fail(matched >= 0 ? "That authenticator code was already used. Show a new code and try again." : "That code does not match your authenticator. Check the six digits and try again.", 400, nonce);
    }
    account.usedSteps.add(matched); account.authFailures = 0; account.authLockedUntil = 0; account.mfa = true;
    return json({ ok: true, next: "#recovery" }, 200, nonce);
  }
  if (path === "/api/recovery/generate") {
    if (!account.mfa) return fail("Connect your authenticator before creating recovery codes.", 403, nonce);
    const codes = Array.from({ length: 8 }, makeRecovery);
    account.recoveries = codes.map(code => { const salt = random(24); return { salt, hash: hash(salt + code), used: false }; });
    return json({ ok: true, codes }, 200, nonce);
  }

  /* Task: owner-authorized, CSRF-protected, constant-time salted-hash recovery verification. */
  if (path === "/api/recovery/verify") {
    if (!account.mfa) return fail("Set up your authenticator before using a recovery code.", 403, nonce);
    if (!validRecovery(data.code)) return fail("Enter a recovery code like ABCDE-FGHIJ. Use capital letters, one dash, and no spaces.", 400, nonce);
    expireRecoveryLock(account);
    if (lockActive(account.recoveryLockedUntil)) return fail("Too many recovery-code attempts. Please wait a few minutes before trying again.", 429, nonce);
    const code = String(data.code);
    let matching: Recovery | undefined, usedMatch = false;
    for (const recovery of account.recoveries) {
      const matches = equal(hash(recovery.salt + code), recovery.hash);
      if (matches && recovery.used) usedMatch = true;
      if (matches && !recovery.used) matching = recovery;
    }
    if (matching) {
      matching.used = true; account.recoveryFailures = 0; account.recoveryLockedUntil = 0;
      return json({ ok: true, message: "Recovery code accepted. It is now marked as used." }, 200, nonce);
    }
    account.recoveryFailures++;
    if (account.recoveryFailures >= 5) { account.recoveryLockedUntil = Date.now() + LOCKOUT; return fail("Too many attempts. Please wait a few minutes before trying again.", 429, nonce); }
    if (usedMatch) return fail("That recovery code was already used. Use a different saved code.", 400, nonce);
    return fail("That recovery code is not recognised. Check the format and try a different saved code.", 400, nonce);
  }
  return fail("That page is not available.", 404, nonce);
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank security setup</title>
<style nonce="${nonce}">
:root{--blue:#075e9e;--ink:#17212c;--muted:#53616e;--line:#c8d5df;--soft:#eef7fc}*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font:18px/1.7 Atkinson Hyperlegible,"OpenDyslexic","Segoe UI",Verdana,Arial,sans-serif;letter-spacing:.035em}.shell{max-width:620px;min-height:100vh;margin:auto;padding:20px;background:#fff}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--line);padding-bottom:12px}.brand{font-weight:800;color:#034a7c}button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.link{border:0;background:none;color:var(--blue);text-decoration:underline;padding:6px}.hide{display:none!important}.progress{display:flex;gap:6px;margin:19px 0}.progress i{height:8px;flex:1;background:#d8e1e6;border-radius:9px}.progress .on{background:var(--blue)}h1{font-size:1.7rem;line-height:1.3;margin:18px 0 8px}h2{font-size:1.15rem}.lead,.example{color:var(--muted)}.hint,.success,.error{padding:13px 14px;margin:16px 0;border-radius:8px;background:var(--soft);border-left:5px solid #2184bd}.success{background:#eef9f2;border-color:#156c43}.error{background:#fff1f1;border-color:#8d2424;color:#702020}label{display:block;font-weight:800;margin-top:16px}input{width:100%;min-height:53px;border:2px solid #8497a5;border-radius:8px;padding:10px;font-size:1.08rem}input:focus{outline:3px solid #82c9ee;outline-offset:2px}.primary,.secondary{width:100%;min-height:54px;border-radius:9px;padding:9px;margin-top:18px;font-weight:800}.primary{border:0;background:var(--blue);color:#fff}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue)}.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em}.secret{padding:14px;background:#f3f6f8;overflow-wrap:anywhere;min-height:56px}.qr{font:700 15px/1 ui-monospace,monospace;letter-spacing:0;word-break:break-all;padding:15px;background:#f3f6f8;border:2px dashed #7992a2}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0;list-style:none}.codes li{padding:9px;background:#f1f5f7;font-family:ui-monospace,Consolas,monospace}.logs{margin-top:28px;border-top:2px solid var(--line)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#17222c;color:#d9f2ff;padding:12px;border-radius:8px;font:14px/1.55 ui-monospace,Consolas,monospace}@media(max-width:390px){.shell{padding:16px}.codes{grid-template-columns:1fr}body{font-size:17px}}
</style></head><body><main class="shell"><header class="top"><span class="brand">🏦 Local Bank</span><button class="link hide" id="logout">Log out</button></header><nav class="progress" aria-label="Setup progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></nav><section id="app" aria-live="polite"></section><section class="logs" aria-label="Activity logs"><h2>🔎 Activity logs</h2><p class="example">Safe activity messages appear here. Private codes are never shown in this panel.</p><pre id="logs">Ready.</pre></section></main>
<script nonce="${nonce}">(function(){"use strict";
var app=document.querySelector("#app"),logs=document.querySelector("#logs"),logout=document.querySelector("#logout"),csrf="",loginCsrf="",provision=null,recoveryCodes=[],notice="";
var routes=new Set(["#signin","#identity","#setup","#confirm","#recovery","#use-recovery","#saved"]);
function esc(v){var e=document.createElement("span");e.textContent=String(v);return e.innerHTML}
function log(m){console.log(m);logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+m}
function privateDemo(label,value){console.log(label,value)}
function go(r){location.hash=routes.has(r)?r:"#signin"}
function progress(n){for(var i=1;i<5;i++)document.querySelector("#p"+i).classList.toggle("on",i<=n)}
function help(){return '<p><button class="link" data-help>Need help?</button></p>'}
function attachHelp(){document.querySelectorAll("[data-help]").forEach(function(b){b.onclick=function(){alert("Take your time. You can retry safely. Use the example beside each box.")}})}
function error(m){var e=document.querySelector("#form-error");if(e){e.className="error";e.textContent=m;e.focus()}}
function takeNotice(){var n=notice;notice="";return n?'<div class="success">'+esc(n)+"</div>":""}
async function api(path,method,data){method=method||"GET";var o={method:method,headers:{Accept:"application/json"}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(data||{})}try{return await (await fetch(path,o)).json()}catch(e){return {ok:false,message:"We could not connect securely. Please try again."}}}
async function bootstrap(){var r=await api("/api/csrf-bootstrap");if(r.ok)loginCsrf=r.csrf}
async function session(){var r=await api("/api/session");if(r.ok){csrf=r.csrf;logout.classList.remove("hide");return r}return null}
function signin(){progress(0);app.innerHTML='<h1>🔐 Sign in</h1><p class="lead">Start your security setup.</p><div class="hint">Demo email: <b>marcus@example.com</b><br>Demo password: <b>MarcusDemo!2025</b></div><form id="form"><div id="form-error" tabindex="-1"></div><label>Email address</label><input name="email" type="email" autocomplete="username" placeholder="name@example.com" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button class="primary">Sign in</button></form>'+help();document.querySelector("#form").onsubmit=async function(e){e.preventDefault();if(!loginCsrf)await bootstrap();var f=new FormData(e.target);try{var r=await (await fetch("/api/signin",{method:"POST",headers:{Accept:"application/json","Content-Type":"application/json","X-Login-CSRF":loginCsrf},body:JSON.stringify({email:f.get("email"),password:f.get("password")})})).json();if(!r.ok)return error(r.message);log("Sign-in complete. Secure session created.");notice="Signed in successfully. Next: get your identity code.";go(r.next)}catch(x){error("We could not connect securely. Please try again.")}};attachHelp()}
function identity(){progress(1);app.innerHTML='<h1>🪪 Check it is you</h1>'+takeNotice()+'<p class="lead">Get a six-digit identity code for this demo.</p><div class="hint">There is no reading timer. Take as long as you need.</div><div id="form-error" tabindex="-1"></div><button id="get" class="primary">Get identity code</button>'+help();var request=async function(){var r=await api("/api/identity/request","POST",{});if(!r.ok)return error(r.message);privateDemo("Simulated identity code:",r.simulatedCode);log("Identity code requested. It is shown only in the browser console.");entry()};document.querySelector("#get").onclick=request;attachHelp();function entry(){app.innerHTML='<h1>🪪 Enter your identity code</h1><div class="success">Your identity code was requested. Next: enter the six digits.</div><form id="form"><div id="form-error" tabindex="-1"></div><label>Six-digit code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><button class="primary">Check code</button></form><button id="again" class="secondary">Re-request identity code</button>'+help();document.querySelector("#form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/identity/verify","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return error(r.message);notice="Identity check complete. Next: set up your authenticator.";go(r.next)};document.querySelector("#again").onclick=request;attachHelp()}}
async function createProvision(){var r=await api("/api/authenticator/provision","POST",{});if(!r.ok)return error(r.message);provision=r;privateDemo("Simulated authenticator verification OTP:",r.simulatedOtp);log("Authenticator setup created. Demo code is shown only in the browser console.");showProvision()}
function setup(){progress(2);app.innerHTML='<h1>📱 Set up your authenticator</h1>'+takeNotice()+'<p class="lead">Use the setup address or copy a setup key. You do not need to write anything down.</p><div class="hint">Your authenticator app will give you a six-digit code.</div><div id="form-error" tabindex="-1"></div><button id="show" class="primary">Show setup options</button>'+help();document.querySelector("#show").onclick=createProvision;attachHelp()}
function showProvision(){progress(2);app.innerHTML='<h1>📱 Add this to your app</h1><div class="success">Setup created. Scan this setup address with a QR-capable authenticator app, or copy the key below.</div><p class="lead"><b>QR setup address:</b></p><div class="qr" id="uri"></div><p class="lead"><b>Manual setup key:</b></p><div id="private"></div><button id="toggle" class="secondary">Hide setup key</button><button id="copy" class="secondary">Copy setup key</button><button id="next" class="primary">I added it — continue</button><button id="new" class="link">Show a new setup key</button>'+help();document.querySelector("#uri").textContent=provision.provisioningUri;var shown=true,box=document.querySelector("#private");function draw(){box.innerHTML=shown?'<div class="secret code"></div>':'<div class="hint">Setup key is hidden. Select reveal when you are ready.</div>';if(shown)box.firstChild.textContent=provision.secret;document.querySelector("#toggle").textContent=shown?"Hide setup key":"Reveal setup key"}draw();document.querySelector("#toggle").onclick=function(){shown=!shown;draw()};document.querySelector("#copy").onclick=function(){navigator.clipboard.writeText(provision.secret).then(function(){alert("Setup key copied.")}).catch(function(){alert("Select the setup key and copy it.")})};document.querySelector("#next").onclick=function(){go("#confirm")};document.querySelector("#new").onclick=createProvision;attachHelp()}
function confirm(){progress(3);app.innerHTML='<h1>✅ Check your authenticator</h1><p class="lead">Enter the six digits from your app.</p><div class="hint">Take your time. If needed, show setup options again and try again.</div><form id="form"><div id="form-error" tabindex="-1"></div><label>Authenticator code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><button class="primary">Confirm authenticator</button></form><button id="retry" class="secondary">Show setup options again</button>'+help();document.querySelector("#form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/authenticator/confirm","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return error(r.message);log("Authenticator confirmed.");notice="Authenticator confirmed. Next: create your recovery codes.";go(r.next)};document.querySelector("#retry").onclick=function(){provision?showProvision():go("#setup")};attachHelp()}
function recovery(){progress(4);app.innerHTML='<h1>🧾 Save recovery codes</h1>'+takeNotice()+'<p class="lead">These help if you cannot use your authenticator.</p><div class="hint">Save them somewhere private. Each code works once.</div><div id="form-error" tabindex="-1"></div><button id="create" class="primary">Create recovery codes</button><button id="test" class="link">Use a recovery code instead</button>'+help();document.querySelector("#create").onclick=async function(){var r=await api("/api/recovery/generate","POST",{});if(!r.ok)return error(r.message);recoveryCodes=r.codes;privateDemo("Simulated recovery-code set:",recoveryCodes);log("Recovery codes created. They are shown only on this protected screen and in the browser console.");showCodes()};document.querySelector("#test").onclick=function(){go("#use-recovery")};attachHelp()}
function showCodes(){app.innerHTML='<h1>🧾 Your recovery codes</h1><div class="success">Recovery codes created. Next: copy or save them privately.</div><div id="private"></div><button id="toggle" class="secondary">Hide recovery codes</button><button id="copy" class="secondary">Copy all codes</button><button id="done" class="primary">I saved my codes</button><button id="test" class="link">Test a recovery code</button>'+help();var shown=true,box=document.querySelector("#private");function draw(){box.innerHTML=shown?'<ul class="codes"></ul>':'<div class="hint">Recovery codes are hidden. Select reveal when ready.</div>';if(shown)recoveryCodes.forEach(function(c){var li=document.createElement("li");li.textContent=c;box.firstChild.appendChild(li)});document.querySelector("#toggle").textContent=shown?"Hide recovery codes":"Reveal recovery codes"}draw();document.querySelector("#toggle").onclick=function(){shown=!shown;draw()};document.querySelector("#copy").onclick=function(){navigator.clipboard.writeText(recoveryCodes.join("\\n")).then(function(){alert("Recovery codes copied.")}).catch(function(){alert("Select the codes and copy them.")})};document.querySelector("#done").onclick=function(){go("#saved")};document.querySelector("#test").onclick=function(){go("#use-recovery")};attachHelp()}
function useRecovery(){progress(4);app.innerHTML='<h1>🔑 Use a recovery code</h1><p class="lead">Use one saved code if you cannot use your authenticator.</p><div class="hint">Example: <b>ABCDE-FGHIJ</b><br>Each code works once. Take your time.</div><form id="form"><div id="form-error" tabindex="-1"></div><label>Recovery code</label><input class="code" name="code" autocomplete="one-time-code" autocapitalize="characters" maxlength="11" placeholder="ABCDE-FGHIJ" required><button class="primary">Check recovery code</button></form><button id="back" class="secondary">Back to recovery codes</button>'+help();document.querySelector("#form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/recovery/verify","POST",{code:String(new FormData(e.target).get("code")||"").toUpperCase()});if(!r.ok)return error(r.message);notice=r.message+" Next: finish setup.";log("A recovery code was accepted and marked used.");go("#saved")};document.querySelector("#back").onclick=function(){go("#recovery")};attachHelp()}
function saved(){progress(4);app.innerHTML='<h1>🎉 Security setup complete</h1>'+takeNotice()+'<div class="success">Your authenticator is connected and your recovery codes are saved.</div><button id="use" class="secondary">Use a recovery code</button><button id="start" class="primary">Finish</button>'+help();document.querySelector("#start").onclick=function(){alert("Security setup is complete.")};document.querySelector("#use").onclick=function(){go("#use-recovery")};attachHelp()}
async function render(){var route=routes.has(location.hash)?location.hash:"#signin";if(route==="#signin"){await bootstrap();signin();return}var state=await session();if(!state){go("#signin");return}if(!state.identityVerified&&route!=="#identity"){go("#identity");return}if(!state.mfa&&["#recovery","#use-recovery","#saved"].includes(route)){go(state.provisioned?"#confirm":"#setup");return}if(state.mfa&&state.recoveryCount===0&&["#saved","#use-recovery"].includes(route)){go("#recovery");return}({"#identity":identity,"#setup":setup,"#confirm":confirm,"#recovery":recovery,"#use-recovery":useRecovery,"#saved":saved})[route]()}
logout.onclick=async function(){var r=await api("/api/logout","POST",{});if(r.ok){csrf="";provision=null;recoveryCodes=[];log("Secure session ended.");go("#signin")}};addEventListener("hashchange",render);render()})();</script></body></html>`;
}

const certificate = readFileSync("certs/cert.pem");
const privateKey = readFileSync("certs/key.pem");

/* Requirement 3: TLS-only Bun server with supplied localhost certificates. */
Bun.serve({
  port: 3000,
  tls: { cert: certificate, key: privateKey },
  fetch: async request => {
    const nonce = random(18);
    try {
      const url = new URL(request.url), origin = request.headers.get("origin");
      if (request.headers.get("x-forwarded-proto") === "http") return new Response("Secure connection required.", { status: 426, headers: headers(nonce) });
      if (origin && !ORIGINS.has(origin)) return new Response("Not allowed.", { status: 403, headers: headers(nonce) });
      const cors = origin ? { "Access-Control-Allow-Origin": origin } : {};
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...headers(nonce), ...cors, "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token, X-Login-CSRF" } });
      if (url.pathname.startsWith("/api/")) {
        const out = await api(request, url.pathname, nonce);
        for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
        return out;
      }
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) return new Response(page(nonce), { headers: { ...headers(nonce), ...cors, "Content-Type": "text/html; charset=utf-8" } });
      return new Response("Page not found.", { status: 404, headers: headers(nonce) });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: headers(nonce) });
    }
  },
});
