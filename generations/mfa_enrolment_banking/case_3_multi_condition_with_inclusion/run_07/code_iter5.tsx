
/**
 * MFA Enrolment System
 * Single-file Bun HTTPS server and responsive vanilla-JS mobile SPA.
 * Run with: bun app.ts
 *
 * Academic mode is the default. Set MFA_PRODUCTION_MODE=true for
 * production-style simulated delivery without exposing raw identity codes.
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_LIFETIME_MS = 10 * 60 * 1000;
const LOCKOUT_MS = 15 * 60 * 1000;
const RESEND_INTERVAL_MS = 60 * 1000;
const MAX_FAILURES = 5;
const TRUSTED_ORIGIN = "https://localhost:3000";
const TEST_MODE = Bun.env.MFA_DEMO_MODE === "true";
const ACADEMIC_MODE = Bun.env.MFA_PRODUCTION_MODE !== "true";
const TEST_SECRET = "JBSWY3DPEHPK3PXPX";
const TEST_IDENTITY_CODE = "123456";
const TEST_RECOVERY_CODES = [
  "DEMO0001-CODE0001", "DEMO0002-CODE0002", "DEMO0003-CODE0003", "DEMO0004-CODE0004",
  "DEMO0005-CODE0005", "DEMO0006-CODE0006", "DEMO0007-CODE0007", "DEMO0008-CODE0008",
];

const encryptionKey = await crypto.subtle.importKey(
  "raw", crypto.getRandomValues(new Uint8Array(32)), { name: "AES-GCM" }, false, ["encrypt", "decrypt"],
);

type Stage = "identity" | "setup" | "confirm" | "recovery" | "complete";
type Session = { id: string; owner: "marcus@example.com"; csrf: string; createdAt: number; lastSeen: number; stage: Stage };
type ExpiringCode = { hash: string; expiresAt: number; used: boolean; failures: number; lockedUntil: number; nextSendAt: number };
type TotpProtection = { failures: number; lockedUntil: number; acceptedCounters: Set<number> };

const sessions = new Map<string, Session>();
const account = {
  email: "marcus@example.com" as const,
  password: "BankPass!42",
  identity: null as ExpiringCode | null,
  encryptedSecret: "",
  backupHashes: [] as string[],
  totp: { failures: 0, lockedUntil: 0, acceptedCounters: new Set<number>() } as TotpProtection,
  mfaEnabled: false,
};

function now() { return Date.now(); }
function bytes(length: number) { return crypto.getRandomValues(new Uint8Array(length)); }
function token(length = 32) { return Buffer.from(bytes(length)).toString("base64url"); }
function numberCode() {
  if (TEST_MODE || ACADEMIC_MODE) return TEST_IDENTITY_CODE;
  const value = new Uint32Array(1); crypto.getRandomValues(value);
  return String(value[0] % 1_000_000).padStart(6, "0");
}
function base32(value: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let output = "", buffer = 0, bits = 0;
  for (const byte of value) {
    buffer = (buffer << 8) | byte; bits += 8;
    while (bits >= 5) { output += alphabet[(buffer >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}
function fromBase32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = value.toUpperCase().replace(/[\s=]/g, "");
  if (!/^[A-Z2-7]+$/.test(clean)) throw new Error("Invalid Base32 secret");
  let buffer = 0, bits = 0; const output: number[] = [];
  for (const char of clean) {
    buffer = (buffer << 5) | alphabet.indexOf(char); bits += 5;
    if (bits >= 8) { output.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(output);
}
async function hash(value: string) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", encoder.encode(value))).toString("base64url");
}
async function encrypt(value: string) {
  const iv = bytes(12);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, encoder.encode(value));
  return `${Buffer.from(iv).toString("base64url")}.${Buffer.from(encrypted).toString("base64url")}`;
}
async function decrypt(value: string) {
  const [ivText, cipherText] = value.split(".");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivText, "base64url") }, encryptionKey, Buffer.from(cipherText, "base64url"),
  );
  return decoder.decode(plain);
}

/* Security §3: RFC 6238 TOTP, HMAC-SHA-1, six digits, 30-second steps. */
async function totpForCounter(secret: string, counter: number) {
  const key = await crypto.subtle.importKey("raw", fromBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const data = new Uint8Array(8); let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) { data[i] = Number(c & 255n); c >>= 8n; }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  const offset = digest[digest.length - 1] & 15;
  const value = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function verifyTotp(code: string): Promise<"ok" | "invalid" | "locked"> {
  const state = account.totp, current = now();
  if (state.lockedUntil > current) return "locked";
  if (!account.encryptedSecret) return "invalid";
  const secret = await decrypt(account.encryptedSecret), center = Math.floor(current / 30_000);
  for (const counter of [center - 1, center, center + 1]) {
    if (code === await totpForCounter(secret, counter)) {
      if (state.acceptedCounters.has(counter)) return "invalid";
      state.acceptedCounters.add(counter);
      for (const used of state.acceptedCounters) if (used < center - 2) state.acceptedCounters.delete(used);
      state.failures = 0; return "ok";
    }
  }
  state.failures++;
  if (state.failures >= MAX_FAILURES) state.lockedUntil = current + LOCKOUT_MS;
  return state.lockedUntil > current ? "locked" : "invalid";
}

function cookieMap(request: Request) {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) out[part.slice(0, at).trim()] = decodeURIComponent(part.slice(at + 1).trim());
  }
  return out;
}
function sessionCookie(id: string) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function csrfCookie(value: string) {
  return `mfa_csrf=${encodeURIComponent(value)}; Path=/; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`;
}
function clearCookies() {
  return ["mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0", "mfa_csrf=; Path=/; Secure; SameSite=Strict; Max-Age=0"];
}

/* Security §2: strict headers, no permissive CORS, no debug detail. */
const baseHeaders = {
  "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};
function json(data: unknown, status = 200, cookies: string[] = []) {
  const headers = new Headers(baseHeaders);
  for (const value of cookies) headers.append("Set-Cookie", value);
  return new Response(JSON.stringify(data), { status, headers });
}
function page() { return new Response(HTML, { headers: { ...baseHeaders, "Content-Type": "text/html; charset=utf-8" } }); }
function genericError(status = 400) { return json({ ok: false, message: "We could not complete that step. Please try again." }, status); }
function originAllowed(request: Request) { const origin = request.headers.get("origin"); return !origin || origin === TRUSTED_ORIGIN; }
async function readBody(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || "0") > 4000) return null;
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
}
function authenticated(request: Request): Session | null {
  const id = cookieMap(request).mfa_session, session = id ? sessions.get(id) : undefined, current = now();
  if (!session || session.owner !== account.email || current - session.lastSeen > SESSION_IDLE_MS || current - session.createdAt > SESSION_ABSOLUTE_MS) {
    if (id) sessions.delete(id); return null;
  }
  session.lastSeen = current; return session;
}
function csrf(request: Request, session: Session) { return originAllowed(request) && request.headers.get("x-csrf-token") === session.csrf; }
function codeStatus(item: ExpiringCode | null): "ok" | "locked" | "invalid" | "pending" {
  const current = now();
  if (!item || item.used || item.expiresAt < current) return "invalid";
  return item.lockedUntil > current ? "locked" : "pending";
}
function timeMessage(at: number) { return new Date(at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
async function checkCode(item: ExpiringCode | null, code: string): Promise<"ok" | "locked" | "invalid"> {
  const status = codeStatus(item);
  if (status !== "pending" || !item) return status === "locked" ? "locked" : "invalid";
  if (await hash(code) === item.hash) { item.used = true; return "ok"; }
  item.failures++;
  if (item.failures >= MAX_FAILURES) item.lockedUntil = now() + LOCKOUT_MS;
  return item.lockedUntil > now() ? "locked" : "invalid";
}
function requireSession(request: Request): Session | Response { return authenticated(request) || json({ ok: false, message: "Please sign in again to continue." }, 401); }
function expectedStage(session: Session, allowed: Stage[]) { return allowed.includes(session.stage) ? null : json({ ok: false, message: "Please complete the current setup step first." }, 403); }
function validEmail(value: unknown): value is string { return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 120; }
function validPassword(value: unknown): value is string { return typeof value === "string" && value.length >= 8 && value.length <= 128; }
function validOtp(value: unknown): value is string { return typeof value === "string" && /^\d{6}$/.test(value); }

/* Security §1/§4: clients never supply account IDs; each endpoint authorizes owner session. */
async function api(request: Request, pathname: string): Promise<Response> {
  if (!originAllowed(request)) return json({ ok: false, message: "This request is not allowed." }, 403);

  if (pathname === "/api/signin" && request.method === "POST") {
    const body = await readBody(request), cookieCsrf = cookieMap(request).mfa_csrf;
    if (!body || !cookieCsrf || request.headers.get("x-csrf-token") !== cookieCsrf || !validEmail(body.email) || !validPassword(body.password))
      return json({ ok: false, message: "Check your email and password, then try again." }, 400);
    if (body.email !== account.email || body.password !== account.password)
      return json({ ok: false, message: "Check your email and password, then try again." }, 401);
    const id = token(32), freshCsrf = token(24), stage: Stage = account.mfaEnabled ? "complete" : "identity";
    sessions.set(id, { id, owner: account.email, csrf: freshCsrf, createdAt: now(), lastSeen: now(), stage });
    /* Task: return modes on sign-in so the identity screen is labelled immediately. */
    return json({
      ok: true, stage, csrf: freshCsrf, academicMode: ACADEMIC_MODE, testMode: TEST_MODE,
      message: stage === "complete" ? "Signed in." : "Signed in. Next, verify your identity.",
    }, 200, [sessionCookie(id), csrfCookie(freshCsrf)]);
  }

  if (pathname === "/api/me" && request.method === "GET") {
    const session = requireSession(request); if (session instanceof Response) return session;
    const identity = account.identity;
    return json({
      ok: true, stage: session.stage, email: account.email, csrf: session.csrf, testMode: TEST_MODE, academicMode: ACADEMIC_MODE,
      identitySent: !!identity && !identity.used && identity.expiresAt >= now(),
      identityLockedUntil: identity?.lockedUntil || 0, identityNextSendAt: identity?.nextSendAt || 0,
    });
  }

  if (pathname === "/api/identity/send" && request.method === "POST") {
    const session = requireSession(request); if (session instanceof Response) return session;
    if (!csrf(request, session) || expectedStage(session, ["identity"])) return genericError(403);
    const current = now(), previous = account.identity;
    if (previous && previous.lockedUntil > current) return json({ ok: false, lockedUntil: previous.lockedUntil, message: `Identity checks are paused until ${timeMessage(previous.lockedUntil)}. Please wait before requesting another code.` }, 429);
    if (previous && previous.nextSendAt > current) return json({ ok: false, nextSendAt: previous.nextSendAt, message: `You can request another code at ${timeMessage(previous.nextSendAt)}.` }, 429);
    const sentCode = numberCode();
    account.identity = { hash: await hash(sentCode), expiresAt: current + CODE_LIFETIME_MS, used: false, failures: previous?.failures || 0, lockedUntil: previous?.lockedUntil || 0, nextSendAt: current + RESEND_INTERVAL_MS };
    if (!ACADEMIC_MODE) return json({ ok: true, nextSendAt: account.identity.nextSendAt, message: "A new identity code has been sent by the simulated secure delivery service." });
    return json({ ok: true, code: sentCode, nextSendAt: account.identity.nextSendAt, message: "Your simulated identity code is ready. Check the browser console or reveal it below." });
  }

  if (pathname === "/api/identity/verify" && request.method === "POST") {
    const session = requireSession(request); if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["identity"]); if (stageError) return stageError;
    const body = await readBody(request);
    if (!body || !validOtp(body.code)) return json({ ok: false, message: "Enter the 6 digits, for example 123456." }, 400);
    const result = await checkCode(account.identity, body.code);
    if (result === "locked") { const locked = account.identity?.lockedUntil || now() + LOCKOUT_MS; return json({ ok: false, lockedUntil: locked, message: `Too many tries. Identity checks are paused until ${timeMessage(locked)}.` }, 429); }
    if (result !== "ok") return json({ ok: false, message: "That code did not match. Check all 6 digits or request another code." }, 400);
    session.stage = "setup"; return json({ ok: true, stage: "setup", message: "Identity checked. Next, set up your authenticator." });
  }

  if (pathname === "/api/authenticator/setup" && request.method === "GET") {
    const session = requireSession(request); if (session instanceof Response) return session;
    const stageError = expectedStage(session, ["setup"]); if (stageError) return stageError;
    if (!account.encryptedSecret) return json({ ok: true, provisioned: false, message: "Create your setup key to continue." });
    const secret = await decrypt(account.encryptedSecret);
    const uri = `otpauth://totp/Local%20Bank:marcus%40example.com?secret=${secret}&issuer=Local%20Bank&algorithm=SHA1&digits=6&period=30`;
    return json({ ok: true, provisioned: true, secret, uri, message: "Scan the QR code, or copy the setup key into your authenticator app." });
  }

  if (pathname === "/api/authenticator/setup" && request.method === "POST") {
    const session = requireSession(request); if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["setup"]); if (stageError) return stageError;
    if (!account.encryptedSecret) {
      account.encryptedSecret = await encrypt(TEST_MODE ? TEST_SECRET : base32(bytes(20)));
      account.totp = { failures: 0, lockedUntil: 0, acceptedCounters: new Set<number>() };
    }
    const secret = await decrypt(account.encryptedSecret);
    const uri = `otpauth://totp/Local%20Bank:marcus%40example.com?secret=${secret}&issuer=Local%20Bank&algorithm=SHA1&digits=6&period=30`;
    return json({ ok: true, provisioned: true, secret, uri, message: "Your authenticator setup key is ready." });
  }

  if (pathname === "/api/authenticator/confirm" && request.method === "POST") {
    const session = requireSession(request); if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["setup", "confirm"]); if (stageError) return stageError;
    if (!account.encryptedSecret) return json({ ok: false, message: "Create a setup key first." }, 400);
    session.stage = "confirm";
    const testCode = TEST_MODE ? await totpForCounter(await decrypt(account.encryptedSecret), Math.floor(now() / 30_000)) : undefined;
    return json({ ok: true, stage: "confirm", ...(TEST_MODE ? { testCode } : {}), message: "Now enter the current code shown in the authenticator app you configured." });
  }

  if (pathname === "/api/authenticator/verify" && request.method === "POST") {
    const session = requireSession(request); if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["confirm"]); if (stageError) return stageError;
    const body = await readBody(request);
    if (!body || !validOtp(body.code)) return json({ ok: false, message: "Enter 6 digits, for example 123456." }, 400);
    const result = await verifyTotp(body.code);
    if (result === "locked") return json({ ok: false, message: "Too many tries. Please wait, then try a new code shown by your app." }, 429);
    if (result !== "ok") return json({ ok: false, message: "That code did not match or was already used. Open your authenticator app and enter its current 6-digit code." }, 400);
    session.stage = "recovery"; return json({ ok: true, stage: "recovery", message: "Authenticator confirmed. Next, save your recovery codes." });
  }

  if (pathname === "/api/recovery/create" && request.method === "POST") {
    const session = requireSession(request); if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["recovery"]); if (stageError) return stageError;
    const replacing = account.backupHashes.length > 0;
    const codes = TEST_MODE ? [...TEST_RECOVERY_CODES] : Array.from({ length: 8 }, () => `${token(4).toUpperCase()}-${token(4).toUpperCase()}`);
    account.backupHashes = await Promise.all(codes.map(hash));
    return json({ ok: true, codes, replacing, message: replacing ? "Your old recovery codes were replaced. Save this new set somewhere private." : "Your recovery codes are ready. Save them somewhere private." });
  }

  if (pathname === "/api/recovery/finish" && request.method === "POST") {
    const session = requireSession(request); if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    const stageError = expectedStage(session, ["recovery"]);
    if (stageError || account.backupHashes.length !== 8) return genericError(403);
    account.mfaEnabled = true; session.stage = "complete";
    return json({ ok: true, stage: "complete", message: "MFA is now on." });
  }

  if (pathname === "/api/logout" && request.method === "POST") {
    const session = requireSession(request); if (session instanceof Response) return session;
    if (!csrf(request, session)) return genericError(403);
    sessions.delete(session.id); return json({ ok: true, message: "Signed out." }, 200, clearCookies());
  }
  return genericError(404);
}

const HTML = String.raw`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · MFA setup</title>
<style>
:root{--ink:#14283d;--muted:#506477;--blue:#075bc7;--red:#b42318;--line:#c9d6e1;--paper:#fff;--bg:#f4f8fb}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Verdana,Arial,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.035em}button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.shell{width:min(100%,580px);margin:auto;min-height:100vh;background:var(--paper);padding:22px 20px 42px}header{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:24px}.brand{font-weight:800;font-size:1.15rem;color:#063d82}.step{font-size:.92rem;color:var(--muted);margin-top:5px}h1{font-size:1.65rem;line-height:1.3;margin:0 0 14px}h2{font-size:1.12rem;margin:0 0 8px}p{margin:0 0 17px}.lead{font-size:1.05rem}.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:18px 0;background:#fff}.hint{background:#f5faff;border-left:5px solid var(--blue);padding:13px 15px;border-radius:5px;color:#29445c;font-size:.94rem}label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;padding:13px;border:2px solid #8499ac;border-radius:8px;background:#fff;color:var(--ink);font-size:1.1rem}input:focus{outline:3px solid #80b8f6;outline-offset:2px;border-color:var(--blue)}.code-input{text-align:center;font-weight:bold;font-size:1.45rem;letter-spacing:.22em}.primary{width:100%;border:0;border-radius:9px;padding:15px 16px;background:var(--blue);color:white;font-weight:800;margin-top:23px;min-height:56px}.secondary,.text-btn{border:2px solid var(--blue);color:#064d9e;background:#fff;border-radius:8px;padding:10px 13px;font-weight:700}.text-btn{border:0;padding:4px;text-decoration:underline}.buttons{display:grid;gap:10px;margin-top:13px}.message{padding:12px 14px;border-radius:8px;margin:16px 0;font-weight:700}.success{background:#e5f6ed;color:#075a36}.error{background:#fff0ef;color:var(--red)}.hidden{display:none!important}.progress{display:flex;gap:5px;margin:0 0 22px}.progress span{height:7px;flex:1;border-radius:9px;background:#d7e0e8}.progress .on{background:var(--blue)}.secret{word-break:break-all;background:#f4f7f9;border:1px solid var(--line);padding:12px;border-radius:7px;font-family:monospace;letter-spacing:.08em;user-select:all}.qr{display:block;width:245px;height:245px;max-width:100%;margin:15px auto;border:9px solid white;outline:1px solid var(--ink);image-rendering:pixelated}.codes{list-style:none;padding:0;margin:12px 0}.codes li{font-family:monospace;font-size:1.05rem;border-bottom:1px solid var(--line);padding:7px 3px;letter-spacing:.07em;user-select:all}.logs{margin-top:32px;border-top:2px solid var(--line);padding-top:16px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#0e2436;color:#dff5ff;border-radius:8px;padding:12px;font:12px/1.55 monospace;min-height:62px}.small{font-size:.9rem;color:var(--muted)}.logout{color:#6b1a14}.copy-status{margin:9px 0 0;font-size:.9rem;color:var(--red);font-weight:700}.demo{background:#fff7d6;border-left-color:#a76800}@media(max-width:370px){.shell{padding:17px 15px}.qr{width:210px;height:210px}body{font-size:16px}}
</style></head>
<body><main class="shell">
<header><div class="brand">🏦 Local Bank</div><div id="stepText" class="step">Secure account setup</div></header>
<section id="app" aria-live="polite"><p>Loading your secure setup…</p></section>
<section class="logs" aria-label="Simulation logs"><h2>🧾 Logs</h2><p class="small">Simulation messages appear here and in the browser console.</p><pre id="logs">Ready.</pre></section>
</main><script>
(()=>{
"use strict";
const app=document.getElementById("app"),stepText=document.getElementById("stepText"),logs=document.getElementById("logs");
let csrf="",shownIdentity="",testTotp="",recoveryCodes=[],testMode=false,academicMode=false,identitySent=false;
const stages={signin:0,identity:1,setup:2,confirm:3,recovery:4,complete:5};
function log(message){console.log(message);logs.textContent+=(logs.textContent==="Ready."?"\n":"\n")+message}
function cookie(name){const part=document.cookie.split("; ").find(x=>x.startsWith(name+"="));return part?decodeURIComponent(part.split("=").slice(1).join("=")):""}
function setStep(name){const n=stages[name]??0;stepText.textContent=name==="signin"?"Step 1 of 5 · Sign in":"Step "+Math.min(n+1,5)+" of 5 · MFA enrolment"}
function el(tag,attrs={},text=""){const node=document.createElement(tag);Object.entries(attrs).forEach(([k,v])=>{if(k==="class")node.className=v;else if(k.startsWith("on"))node.addEventListener(k.slice(2),v);else node.setAttribute(k,v)});if(text)node.textContent=text;return node}
function message(text,type="success"){return el("div",{class:"message "+type,role:"status"},text)}
function progress(n){const d=el("div",{class:"progress","aria-label":"Setup progress"});for(let i=1;i<=5;i++)d.append(el("span",{class:i<=n?"on":""}));return d}
async function api(path,method="GET",body){try{const r=await fetch(path,{method,headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:body?JSON.stringify(body):undefined,credentials:"same-origin"}),data=await r.json();if(r.status===401){csrf="";renderSignin(data.message);return null}return data}catch{return{ok:false,message:"Connection problem. Please try again."}}}
function clear(){app.replaceChildren()}
function help(){return el("p",{class:"hint"},"💡 Need help? You can take your time. You can safely retry a step whenever you need one.")}
function copyControl(text,label,successText){const wrap=el("div"),button=el("button",{class:"secondary",type:"button"},label),status=el("p",{class:"copy-status hidden",role:"status"});button.onclick=async()=>{status.classList.add("hidden");try{if(!navigator.clipboard)throw Error();await navigator.clipboard.writeText(text);button.textContent=successText;log("Clipboard copy completed.")}catch{status.textContent="Copy did not work. Select the text shown above, then use your browser’s Copy option.";status.classList.remove("hidden")}};wrap.append(button,status);return wrap}

/* Task: local standards-compliant QR encoder (QR Model 2, byte mode, EC level L). */
function qrCanvas(payload){
  const raw=new TextEncoder().encode(payload),dataWords=[19,34,55,80,108,136,156,194,232,274];
  let version=1;
  while(version<=10 && raw.length+(version<10?2:3)>dataWords[version-1])version++;
  if(version>10)throw Error("Provisioning link is too long");
  const size=17+version*4,blocks=version<=5?1:version<=9?2:4;
  const capacity=dataWords[version-1],ecc=( [26,44,70,100,134,172,196,242,292,346][version-1]-capacity)/blocks;
  const bits=[];
  const add=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1)};
  add(4,4);add(raw.length,version<10?8:16);for(const b of raw)add(b,8);
  for(let i=0;i<Math.min(4,capacity*8-bits.length);i++)bits.push(0);
  while(bits.length%8)bits.push(0);
  const data=[];for(let i=0;i<bits.length;i+=8)data.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));
  for(let p=0;data.length<capacity;p++)data.push(p%2?0x11:0xec);
  const mul=(a,b)=>{let r=0;while(b){if(b&1)r^=a;a=(a<<1)^(a&128?0x11d:0);b>>>=1}return r};
  const poly=[1];for(let i=0;i<ecc;i++){const next=Array(poly.length+1).fill(0);for(let j=0;j<poly.length;j++){next[j]^=poly[j];next[j+1]^=mul(poly[j],1<<i)}poly.splice(0,poly.length,...next)}
  const per=capacity/blocks,parts=[],ecParts=[];
  for(let b=0;b<blocks;b++){const part=data.slice(b*per,(b+1)*per),rem=Array(ecc).fill(0);for(const value of part){const f=value^rem.shift();rem.push(0);for(let j=0;j<ecc;j++)rem[j]^=mul(poly[j+1],f)}parts.push(part);ecParts.push(rem)}
  const stream=[];for(let i=0;i<per;i++)for(const p of parts)stream.push(p[i]);for(let i=0;i<ecc;i++)for(const p of ecParts)stream.push(p[i]);
  const m=Array.from({length:size},()=>Array(size).fill(null));
  const put=(x,y,v)=>{if(x>=0&&y>=0&&x<size&&y<size)m[y][x]=v};
  const finder=(x,y)=>{for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++)put(x+dx,y+dy,dx>=0&&dx<=6&&dy>=0&&dy<=6&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4)))};
  finder(0,0);finder(size-7,0);finder(0,size-7);
  for(let i=8;i<size-8;i++){put(i,6,i%2===0);put(6,i,i%2===0)}
  const align=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50]][version-1];
  for(const y of align)for(const x of align){if(m[y][x]!==null)continue;for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)put(x+dx,y+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1)}
  let fmt=(0x08<<10);for(let i=14;i>=10;i--)if((fmt>>i)&1)fmt^=0x537<<(i-10);fmt=((0x08<<10)|fmt)^0x5412;
  for(let i=0;i<15;i++){const b=!!((fmt>>i)&1);if(i<6)put(8,i,b);else if(i<8)put(8,i+1,b);else put(8,size-15+i,b);if(i<8)put(size-i-1,8,b);else if(i<9)put(15-i,8,b);else put(14-i,8,b)}
  put(8,size-8,true);
  let bit=0,up=true;
  for(let right=size-1;right>0;right-=2){if(right===6)right--;for(let row=0;row<size;row++){const y=up?size-1-row:row;for(let j=0;j<2;j++){const x=right-j;if(m[y][x]!==null)continue;const value=bit<stream.length*8?((stream[bit>>>3]>>>(7-(bit&7)))&1):0;bit++;m[y][x]=!!(value^((x+y)%2===0))}}up=!up}
  const scale=7,c=document.createElement("canvas");c.width=c.height=size*scale;c.className="qr";c.setAttribute("aria-label","Scannable QR code for authenticator setup.");const ctx=c.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,c.width,c.height);ctx.fillStyle="#000";for(let y=0;y<size;y++)for(let x=0;x<size;x++)if(m[y][x])ctx.fillRect(x*scale,y*scale,scale,scale);return c;
}

function renderSignin(note=""){setStep("signin");clear();app.append(el("h1",{},"Sign in to start MFA setup"),el("p",{class:"lead"},"🔐 We will guide you through five short steps. There is no reading timer."));if(note)app.append(message(note,note.includes("Signed")?"success":"error"));const form=el("form"),email=el("input",{type:"email",autocomplete:"username",inputmode:"email",placeholder:"name@example.com",required:""}),pass=el("input",{type:"password",autocomplete:"current-password",placeholder:"Your password",required:""});form.append(el("label",{},"Email"),email,el("p",{class:"small"},"Example: name@example.com"),el("label",{},"Password"),pass,el("button",{class:"primary",type:"submit"},"Sign in"));form.onsubmit=async e=>{e.preventDefault();csrf=cookie("mfa_csrf");const d=await api("/api/signin","POST",{email:email.value.trim(),password:pass.value});if(!d)return;if(!d.ok){form.prepend(message(d.message,"error"));return}csrf=d.csrf;testMode=!!d.testMode;academicMode=!!d.academicMode;log("Sign-in simulation completed.");if(d.stage==="complete")renderComplete(d.message);else renderIdentity(d.message)};app.append(form,help(),el("p",{class:"small"},"Demo sign-in: marcus@example.com · BankPass!42"))}
function renderIdentity(note=""){setStep("identity");clear();app.append(progress(1),el("h1",{},"Verify it is you"),el("p",{class:"lead"},"📩 We will send one short code."));if(academicMode)app.append(message("Academic simulation mode is enabled. The identity code is logged in your browser console.","success"));if(note)app.append(message(note));const form=el("form"),input=el("input",{class:"code-input",inputmode:"numeric",autocomplete:"one-time-code",pattern:"[0-9]{6}",maxlength:"6",placeholder:"123456",required:""});form.append(el("label",{},"Enter the 6-digit code"),input,el("p",{class:"small"},"Example: 123456"),el("button",{class:"primary",type:"submit"},"Check code"));form.onsubmit=async e=>{e.preventDefault();const d=await api("/api/identity/verify","POST",{code:input.value.replace(/\s/g,"")});if(d&&d.ok){shownIdentity="";identitySent=false;renderSetup(d.message)}else if(d)form.prepend(message(d.message,"error"))};const send=el("button",{class:identitySent?"secondary":"primary",type:"button"},identitySent?"Send another code":"Send identity code");send.onclick=async()=>{const d=await api("/api/identity/send","POST",{});if(d&&d.ok){identitySent=true;shownIdentity=d.code||"";if(academicMode)log("ACADEMIC SIMULATION identity code: "+(shownIdentity||"not exposed"));else log("Secure identity-code delivery simulated.");renderIdentity(d.message)}else if(d)app.prepend(message(d.message,"error"))};if(identitySent){app.append(form);if(academicMode){const reveal=el("button",{class:"text-btn",type:"button"},"Reveal simulated code"),box=el("div",{class:"secret hidden"},shownIdentity||"No code is available. Send another code.");reveal.onclick=()=>box.classList.toggle("hidden");app.append(reveal,box)}app.append(el("div",{class:"buttons"},send))}else app.append(send);app.append(help())}
async function renderSetup(note=""){setStep("setup");clear();let d=await api("/api/authenticator/setup");if(!d||!d.ok){renderSignin(d?.message||"Please sign in again.");return}if(!d.provisioned){d=await api("/api/authenticator/setup","POST",{});if(!d||!d.ok){app.append(message(d?.message||"Please try again.","error"));return}}app.append(progress(2),el("h1",{},"Set up your authenticator"),el("p",{class:"lead"},"📱 In your authenticator app, scan this QR code. Or copy the setup key instead."));if(note)app.append(message(note));app.append(el("div",{class:"card"},el("h2",{},"QR code"),qrCanvas(d.uri),el("p",{class:"small"},"Open your authenticator app and choose Scan QR code.")),el("h2",{},"Or enter this setup key"),el("div",{class:"secret"},d.secret),el("div",{class:"buttons"},copyControl(d.secret,"Copy setup key","Copied setup key ✓")));const uri=el("button",{class:"text-btn",type:"button"},"Show provisioning link"),uriBox=el("div",{class:"secret hidden"},d.uri);uri.onclick=()=>uriBox.classList.toggle("hidden");app.append(uri,uriBox,el("p",{class:"small"},"You may paste the key or provisioning link. You do not need to type it."));const next=el("button",{class:"primary",type:"button"},"I added it to my app");next.onclick=async()=>{const x=await api("/api/authenticator/confirm","POST",{});if(x&&x.ok){testTotp=x.testCode||"";if(testMode)log("TEST ONLY current authenticator code: "+testTotp);renderConfirm(x.message)}else if(x)app.append(message(x.message,"error"))};app.append(next,help())}
function renderConfirm(note=""){setStep("confirm");clear();app.append(progress(3),el("h1",{},"Check your authenticator"),el("p",{class:"lead"},"🔢 Open the authenticator app you just configured. Enter the current 6-digit code it shows."),el("p",{class:"small"},"Example: 123456. Take as long as you need."));if(note)app.append(message(note));if(testMode&&testTotp){const reveal=el("button",{class:"text-btn",type:"button"},"Reveal test authenticator code"),box=el("div",{class:"secret hidden"},testTotp);reveal.onclick=()=>box.classList.toggle("hidden");app.append(reveal,box)}const form=el("form"),input=el("input",{class:"code-input",inputmode:"numeric",autocomplete:"one-time-code",pattern:"[0-9]{6}",maxlength:"6",placeholder:"123456",required:""});form.append(el("label",{},"Authenticator code"),input,el("p",{class:"small"},"Example: 123456"),el("button",{class:"primary",type:"submit"},"Confirm authenticator"));form.onsubmit=async e=>{e.preventDefault();const d=await api("/api/authenticator/verify","POST",{code:input.value.replace(/\s/g,"")});if(d&&d.ok){testTotp="";renderRecovery(d.message)}else if(d)form.prepend(message(d.message,"error"))};app.append(form,help())}
function renderRecovery(note=""){setStep("recovery");clear();app.append(progress(4),el("h1",{},"Save recovery codes"),el("p",{class:"lead"},"🗝️ These help if you lose your phone. Keep them somewhere private."));if(note)app.append(message(note));const create=async()=>{const d=await api("/api/recovery/create","POST",{});if(d&&d.ok){recoveryCodes=d.codes;if(testMode)log("TEST ONLY recovery codes: "+d.codes.join(", "));renderRecovery(d.message)}else if(d)app.append(message(d.message,"error"))};if(!recoveryCodes.length){const make=el("button",{class:"primary",type:"button"},"Create recovery codes");make.onclick=create;app.append(make,help());return}const list=el("ul",{class:"codes","aria-label":"Recovery codes"});recoveryCodes.forEach(c=>list.append(el("li",{},c)));const replace=el("button",{class:"secondary",type:"button"},"Replace recovery codes");replace.onclick=async()=>{if(confirm("Replace recovery codes? Your old set will stop working. Make sure you can save the new set."))await create()};app.append(el("div",{class:"card"},el("h2",{},"Your eight codes"),list),el("div",{class:"buttons"},copyControl(recoveryCodes.join("\n"),"Copy all codes","Codes copied ✓"),replace),el("p",{class:"small"},"Replacing codes makes your old recovery codes stop working."));const finish=el("button",{class:"primary",type:"button"},"I saved my codes");finish.onclick=async()=>{const d=await api("/api/recovery/finish","POST",{});if(d&&d.ok){recoveryCodes=[];renderComplete(d.message)}else if(d)app.append(message(d.message,"error"))};app.append(finish,help())}
function renderComplete(note=""){setStep("complete");clear();app.append(progress(5),el("h1",{},"MFA is ready"),message(note||"MFA is now on."),el("p",{class:"lead"},"✅ Your authenticator and recovery codes are set up."),el("p",{class:"hint"},"Keep recovery codes private. You can return to your account whenever you are ready."));const out=el("button",{class:"text-btn logout",type:"button"},"Sign out");out.onclick=async()=>{await api("/api/logout","POST",{});csrf="";shownIdentity="";testTotp="";recoveryCodes=[];identitySent=false;renderSignin("You are signed out.")};app.append(out)}
async function init(){csrf=cookie("mfa_csrf");if(!csrf){csrf=crypto.getRandomValues(new Uint32Array(4)).join("");document.cookie="mfa_csrf="+encodeURIComponent(csrf)+"; Path=/; Secure; SameSite=Strict"}const me=await api("/api/me");if(me&&me.ok){csrf=me.csrf;testMode=!!me.testMode;academicMode=!!me.academicMode;identitySent=!!me.identitySent;if(me.stage==="identity")renderIdentity();else if(me.stage==="setup")renderSetup();else if(me.stage==="confirm")renderConfirm();else if(me.stage==="recovery")renderRecovery();else renderComplete()}else renderSignin()}
init();
})();
</script></body></html>`;

Bun.serve({
  port: 3000,
  hostname: "localhost",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.pathname === "/" && request.method === "GET") return page();
      if (url.pathname.startsWith("/api/")) return await api(request, url.pathname);
      return genericError(404);
    } catch { return genericError(500); }
  },
});
