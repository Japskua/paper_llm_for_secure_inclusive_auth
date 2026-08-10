
import { serve, file } from "bun";

/* Requirements 1–5: secure in-memory academic simulation. No sensitive values
   are server-logged; OTP secrets are AES-GCM encrypted and recovery codes hashed. */
const PORT = 3000;
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 10 * 60_000;
const LOCK = 5 * 60_000, MAX_FAILURES = 5;
const origins = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);

type Challenge = { hash: string; expires: number; used: boolean };
type Encrypted = { iv: string; data: string };
type Session = { id: string; csrf: string; created: number; seen: number; user?: string; identity: boolean; identityCode?: Challenge };
type Account = {
  id: string; email: string; otp?: Encrypted; acceptedTotpCounters: Set<number>;
  recovery: Set<string>; recoveryExpires?: number; recoveryFailures: number; recoveryLocked: number;
  generated: boolean; confirmed: boolean; mfa: boolean; setup: boolean;
  identityFailures: number; identityLocked: number; authFailures: number; authLocked: number;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const loginFailures = new Map<string, { failures: number; locked: number }>();
const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const pepper = secureHex(32);

accounts.set("marcus-account", {
  id: "marcus-account", email: "marcus@example.com", otp: undefined, acceptedTotpCounters: new Set(),
  recovery: new Set(), recoveryFailures: 0, recoveryLocked: 0, generated: false, confirmed: false,
  mfa: false, setup: false, identityFailures: 0, identityLocked: 0, authFailures: 0, authLocked: 0
});

function bytes(n: number) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
function secureHex(n: number) { return [...bytes(n)].map(x => x.toString(16).padStart(2, "0")).join(""); }
function randomFrom(chars: string, length: number) {
  const result: string[] = [], limit = 256 - 256 % chars.length;
  while (result.length < length) for (const b of bytes(length * 2)) {
    if (b < limit) { result.push(chars[b % chars.length]); if (result.length === length) break; }
  }
  return result.join("");
}
function otp() { return randomFrom("0123456789", 6); }
function base32Secret() { return randomFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32); }
function recoveryCode() { return [0, 1, 2].map(() => randomFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 4)).join("-"); }
function recoverySet() { const set = new Set<string>(); while (set.size < 8) set.add(recoveryCode()); return [...set]; }
function b64(v: Uint8Array) { return Buffer.from(v).toString("base64"); }
function unb64(v: string) { return new Uint8Array(Buffer.from(v, "base64")); }
async function hash(value: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pepper + ":" + value)))); }
async function encrypt(value: string): Promise<Encrypted> {
  const iv = bytes(12);
  return { iv: b64(iv), data: b64(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(value)))) };
}
async function decrypt(value: Encrypted) {
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, aesKey, unb64(value.data)));
}
function equal(a: string, b: string) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  if (x.length !== y.length) return false;
  let different = 0; for (let i = 0; i < x.length; i++) different |= x[i] ^ y[i];
  return different === 0;
}
function six(v: unknown): v is string { return typeof v === "string" && /^\d{6}$/.test(v); }
function rec(v: unknown): v is string { return typeof v === "string" && /^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$/.test(v); }

/* Requirement 3 and task: RFC 6238 TOTP. Validation returns the matched
   counter so a successful enrolment can accept each counter only once. */
function decodeBase32(input: string) {
  const text = input.replace(/=+$/g, "").toUpperCase();
  if (!/^[A-Z2-7]+$/.test(text)) throw new Error("invalid");
  let value = 0, bits = 0; const result: number[] = [];
  for (const char of text) {
    value = (value << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char); bits += 5;
    if (bits >= 8) { result.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(result);
}
async function totpForCounter(secret: string, counter: number) {
  const key = await crypto.subtle.importKey("raw", decodeBase32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const message = new Uint8Array(8); let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) { message[i] = Number(n & 255n); n >>= 8n; }
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = mac[19] & 15;
  const value = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function matchedTotpCounter(encrypted: Encrypted | undefined, code: string): Promise<number | null> {
  if (!encrypted || !six(code)) return null;
  try {
    const secret = await decrypt(encrypted), current = Math.floor(Date.now() / 30_000);
    for (const offset of [-1, 0, 1]) {
      const counter = current + offset;
      if (equal(await totpForCounter(secret, counter), code)) return counter;
    }
  } catch { /* Generic invalid result: no secret is exposed. */ }
  return null;
}
async function currentTotp(encrypted: Encrypted) {
  return totpForCounter(await decrypt(encrypted), Math.floor(Date.now() / 30_000));
}

function getCookie(req: Request, name: string) {
  for (const part of (req.headers.get("cookie") || "").split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
}
function newSession(): Session { const now = Date.now(); return { id: secureHex(32), csrf: secureHex(32), created: now, seen: now, identity: false }; }
function sessionCookie(id: string, age = ABSOLUTE) {
  return `mfa_session=${encodeURIComponent(id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(age / 1000)}`;
}
function current(req: Request) {
  const id = getCookie(req, "mfa_session"), session = id && sessions.get(id);
  if (!session) return;
  if (Date.now() - session.seen > IDLE || Date.now() - session.created > ABSOLUTE) { sessions.delete(session.id); return; }
  session.seen = Date.now(); return session;
}
/* Requirement 2: restrictive transport, clickjacking, CSP, and cache headers. */
function headers(nonce?: string) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8", "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  });
  h.set("Content-Security-Policy", nonce
    ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; frame-ancestors 'none'");
  return h;
}
function json(data: unknown, status = 200, h = headers()) { return new Response(JSON.stringify(data), { status, headers: h }); }
function fail(message = "We could not complete that step. Please try again.", status = 400) { return json({ ok: false, message }, status); }
async function body(req: Request): Promise<Record<string, unknown> | null> {
  try { const value = await req.json(); return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null; } catch { return null; }
}
function csrf(req: Request, session: Session) { const value = req.headers.get("x-csrf-token"); return !!value && equal(value, session.csrf); }
function owner(req: Request): { s: Session; a: Account } | Response {
  const s = current(req); if (!s?.user) return fail("Please sign in again to continue.", 401);
  const a = accounts.get(s.user); return a ? { s, a } : fail("Please sign in again to continue.", 401);
}
function verified(req: Request) {
  const result = owner(req);
  return result instanceof Response || result.s.identity ? result : fail("Please finish identity check before changing MFA settings.", 403);
}
function state(s: Session, a?: Account) {
  return { ok: true, csrf: s.csrf, loggedIn: !!s.user, identityVerified: s.identity, mfaEnabled: !!a?.mfa,
    authenticatorSetupStarted: !!a?.setup, recoveryGenerated: !!a?.generated, recoveryConfirmed: !!a?.confirmed };
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank MFA</title><style nonce="${nonce}">
:root{--blue:#075fc6;--ink:#172334;--muted:#536276;--line:#cbd6e2}*{box-sizing:border-box}body{margin:0;background:#f2f5f8;color:var(--ink);font:17px/1.7 Verdana,"Trebuchet MS",Arial,sans-serif;letter-spacing:.025em}main{max-width:560px;margin:auto;padding:18px 16px 35px}header{display:flex;gap:10px;align-items:center;margin-bottom:16px}.logo{width:42px;height:42px;display:grid;place-items:center;border-radius:50%;background:var(--blue);color:#fff;font-weight:bold}h1{font-size:1.35rem;margin:0}h2{font-size:1.3rem;line-height:1.3;margin:0 0 8px}.card,.logs{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px 17px}.steps,.hint{color:var(--muted);font-size:.9rem}.now{color:var(--blue);font-weight:bold}.notice{background:#edf6ff;border-left:5px solid var(--blue);border-radius:5px;padding:10px 12px;margin:14px 0}.error{background:#fff0f0;border-color:#a12828;color:#721b1b}.good{background:#effaf3;border-color:#146c43;color:#145535}label{display:block;font-weight:bold;margin:16px 0 5px}input{width:100%;min-height:51px;padding:9px 11px;border:2px solid #91a5b9;border-radius:9px;font:inherit;letter-spacing:.05em}input:focus{outline:3px solid #8ac5ff;border-color:var(--blue)}button{min-height:45px;padding:10px 15px;border-radius:9px;cursor:pointer;font:inherit;letter-spacing:.02em}.primary{width:100%;margin-top:17px;border:2px solid var(--blue);background:var(--blue);color:#fff;font-weight:bold}.secondary,.link{margin-top:10px;border:1px solid #62768b;background:#fff;color:#164f88}.link{min-height:auto;border:0;text-decoration:underline}.row{display:flex;flex-wrap:wrap;gap:8px}.secret{overflow-wrap:anywhere;border:1px solid var(--line);border-radius:8px;padding:10px;background:#f5f7f9;font-family:monospace}.qr{display:grid;grid-template-columns:repeat(25,7px);width:max-content;margin:15px auto;padding:14px;background:#fff;border:1px solid var(--line)}.q{width:7px;height:7px;background:#fff}.q.on{background:#000}.codes{display:grid;grid-template-columns:1fr 1fr;gap:7px;padding:0;list-style:none;font:14px monospace}.codes li{padding:8px;border:1px solid var(--line);border-radius:7px;background:#f5f7f9;text-align:center}.footer{display:flex;justify-content:space-between;margin:12px 2px}.logs{margin-top:15px;padding:13px}.logs h2{font-size:1rem}.logs p,#log{margin:0;color:var(--muted);font-size:.76rem;white-space:pre-wrap;overflow-wrap:anywhere;max-height:180px;overflow:auto}details{margin-top:16px;padding-top:10px;border-top:1px solid var(--line)}summary{color:#164f88;font-weight:bold;cursor:pointer}[hidden]{display:none!important}@media(max-width:360px){body{font-size:16px}.codes{grid-template-columns:1fr}.qr{grid-template-columns:repeat(25,6px)}.q{width:6px;height:6px}}
</style></head><body><main><header><div class="logo">HB</div><div><h1>Harbour Bank</h1><div class="hint">MFA enrolment</div></div></header><div id="app">Loading secure setup…</div><section class="logs"><h2>Logs</h2><p>Testing-only generated values appear here and in this browser console only.</p><div id="log"></div></section></main>
<script nonce="${nonce}">(()=>{"use strict";
let token="",st,view="signin",idCode=null,setup=null,codes=null,shown=true;
const A=document.getElementById("app"),L=document.getElementById("log"),$=id=>document.getElementById(id);
const log=text=>{console.log(text);const line=document.createElement("div");line.textContent=text;L.append(line)};
async function api(path,method="GET",data){const options={method,headers:{}};if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=token;options.body=JSON.stringify(data||{})}const response=await fetch(path,options),result=await response.json();if(result.csrf)token=result.csrf;if(!response.ok||!result.ok)throw Error(result.message);return result}
async function refresh(){st=await api("/api/state")}function msg(text){const e=$("msg");if(e){e.textContent=text;e.hidden=false}}
function shell(step,title,icon,text,content){A.innerHTML='<div class="steps">Step <span class="now">'+step+'</span> of 5</div><section class="card"><h2>'+icon+" "+title+'</h2><p>'+text+'</p><div id="msg" class="notice error" hidden></div>'+content+'<details><summary>Need help?</summary><p>Take your time. You can retry or request a new code without penalty.</p></details></section><nav class="footer"><button class="link" id="help" type="button">Help</button><button class="link" id="out" type="button">Log out</button></nav>';$("help").onclick=()=>{view="help";render()};$("out").onclick=logout}
function render(){({signin,identity,setupPage,authenticatorConfirm,backup,manage,recover,done,help}[view]||help)()}
function signin(){shell("1","Sign in","🔐","Use the email for your new bank account.",'<div class="notice">Practice sign-in: <code>marcus@example.com</code> and <code>bank-demo</code>.</div><form id="signin-form"><label>Email address<input id="email" type="email" autocomplete="username" placeholder="marcus@example.com" required></label><label>Password<input id="password" type="password" autocomplete="current-password" required></label><button class="primary">Continue</button></form>');$("signin-form").onsubmit=async e=>{e.preventDefault();try{await api("/api/login","POST",{email:$("email").value,password:$("password").value});await refresh();log("SIMULATION: Sign-in accepted.");view=route();render()}catch(error){msg(error.message)}}}
function identity(){shell("2","Check it is you","✉️","We will send a short practice code to your account email.",'<div class="notice">There is no rush. The code has 6 numbers, like <code>123456</code>.</div><button class="primary" id="send" type="button">Send my code</button>');$("send").onclick=async()=>{try{const x=await api("/api/identity/send","POST");idCode=x.testCode;log("TESTING ONLY — displayed identity OTP: "+idCode);identityEntry()}catch(error){msg(error.message)}}}
function identityEntry(){shell("2","Enter the email code","✉️","Enter the practice code shown in this browser.",'<div class="notice good">Practice email code: <code id="pc"></code></div><form id="identity-form"><label>Email code<input id="identity-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required></label><button class="primary">Check code</button></form><button class="secondary" id="again" type="button">Send a new code</button>');$("pc").textContent=idCode;$("identity-form").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify","POST",{code:$("identity-code").value});idCode=null;await refresh();log("SIMULATION: Identity check completed.");view=route();render()}catch(error){msg(error.message)}};$("again").onclick=identity}
function qr(text){let seed=0;for(const ch of text)seed=(seed*31+ch.charCodeAt(0))>>>0;let html="";for(let y=0;y<25;y++)for(let x=0;x<25;x++){const finder=(x<7&&y<7)||(x>17&&y<7)||(x<7&&y>17);const bit=finder?((x%6===0||y%6===0||(x%6>1&&x%6<5&&y%6>1&&y%6<5))):(((seed=(seed*1664525+1013904223)>>>0)>>>31)===1);html+='<i class="q '+(bit?"on":"")+'"></i>'}return '<div class="qr" role="img" aria-label="QR-style setup code. You may instead copy the setup key.">'+html+"</div>"}
async function practice(){const x=await api("/api/authenticator/practice-code","POST");if(setup)setup.testCode=x.testCode;log("TESTING ONLY — current authenticator practice code: "+x.testCode);return x.testCode}
function setupPage(){shell("3","Set up your authenticator","📱","Scan the code or copy the setup key into your authenticator app.",'<button class="primary" id="make" type="button">Show setup options</button>');$("make").onclick=async()=>{try{setup=await api("/api/authenticator/setup","POST");await refresh();log("TESTING ONLY — provisioning secret: "+setup.secret);log("TESTING ONLY — provisioning URI: "+setup.uri);log("TESTING ONLY — authenticator verification code: "+setup.testCode);options()}catch(error){msg(error.message)}}}
function options(){shell("3","Add this to your app","📱","Use the QR option, or paste this setup key manually.",qr(setup.uri)+'<label>Setup key</label><div class="secret" id="key"></div><div class="row"><button class="secondary" id="copy" type="button">Copy setup key</button><button class="secondary" id="hide" type="button">Hide key</button></div><div class="notice">Practice check code: <code id="tc"></code><br>You can request a new practice code at any time. Retries have no penalty.</div><button class="secondary" id="new-code" type="button">Get a new practice code</button><button class="primary" id="ready" type="button">I added it to my app</button>');$("key").textContent=shown?setup.secret:"••••••••••••••••";$("tc").textContent=setup.testCode;$("copy").onclick=async()=>{try{await navigator.clipboard.writeText(setup.secret);log("SIMULATION: Setup key copied.")}catch{msg("Copy did not work. Select the key and copy it.")}};$("hide").onclick=()=>{shown=!shown;options()};$("new-code").onclick=async()=>{try{$("tc").textContent=await practice()}catch(error){msg(error.message)}};$("ready").onclick=()=>{view="authenticatorConfirm";render()}}
function authenticatorConfirm(){shell("4","Check your authenticator","✅","Enter the 6-number practice code. There is no time limit for reading or retries.",'<div class="notice">Practice check code: <code id="tc"></code><br>You can request a new practice code at any time. Retries have no penalty.</div><button class="secondary" id="new-code" type="button">Get a new practice code</button><form id="auth-form"><label>Authenticator code<input id="auth-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required></label><button class="primary">Check authenticator</button></form><button class="secondary" id="show" type="button">Show setup key again</button>');$("tc").textContent=setup?.testCode||"Request a practice code";$("new-code").onclick=async()=>{try{$("tc").textContent=await practice()}catch(error){msg(error.message)}};$("auth-form").onsubmit=async e=>{e.preventDefault();try{await api("/api/authenticator/confirm","POST",{code:$("auth-code").value});setup=null;await refresh();log("SIMULATION: Authenticator confirmed.");view=route();render()}catch(error){msg(error.message)}};$("show").onclick=()=>setup?options():setupPage()}
function backup(){shell("5","Save backup codes","🧾","Keep these codes somewhere safe. Each code works once.",'<button class="primary" id="create" type="button">Show my backup codes</button>');$("create").onclick=generate}
async function generate(){try{const x=await api("/api/recovery/generate","POST",{confirmRegenerate:true});codes=x.codes;await refresh();log("TESTING ONLY — generated backup recovery codes: "+codes.join(", "));list()}catch(error){msg(error.message)}}
function list(){shell("5","Your backup codes","🧾","Copy or write down these short codes.",'<ul class="codes" id="code-list"></ul><button class="secondary" id="copy-codes" type="button">Copy all codes</button><button class="primary" id="check" type="button">I saved them — check one</button>');codes.forEach(code=>{const item=document.createElement("li");item.textContent=code;$("code-list").append(item)});$("copy-codes").onclick=async()=>{try{await navigator.clipboard.writeText(codes.join("\\n"));log("SIMULATION: Backup codes copied.")}catch{msg("Copy did not work. Select the codes and copy them.")}};$("check").onclick=()=>{view="recover";render()}}
function manage(){shell("5","Manage backup codes","🧾","Codes cannot be shown again after leaving their screen.",'<div class="notice">Replacement codes permanently invalidate every old code.</div><button class="primary" id="regen" type="button">Generate replacement codes</button><button class="secondary" id="check" type="button">Check a saved code</button>');$("regen").onclick=()=>{if(confirm("Replace all current backup codes?"))generate()};$("check").onclick=()=>{view="recover";render()}}
function recover(){shell("5","Check one backup code","🔎","Enter one unused backup code to confirm recovery.",'<form id="recovery-form"><label>Backup code<input id="recovery-code" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" maxlength="14" placeholder="ABCD-EFGH-IJKL" required></label><button class="primary">Check backup code</button></form><button class="secondary" id="back" type="button">'+(codes?"Show my codes again":"Manage backup codes")+"</button>");$("recovery-form").onsubmit=async e=>{e.preventDefault();try{await api("/api/recovery/verify","POST",{code:$("recovery-code").value.toUpperCase()});codes=null;await refresh();log("SIMULATION: A backup code was checked and used once.");view=route();render()}catch(error){msg(error.message)}};$("back").onclick=()=>{if(codes)list();else{view="manage";render()}}}
function done(){shell("5","MFA is ready","🎉","Your authenticator is connected and backup codes are saved.",'<div class="notice good">Setup complete.</div><button class="primary" id="finish" type="button">Finish securely</button>');$("finish").onclick=logout}
function help(){shell("Help","Help with MFA","💡","Use one step at a time. Nothing on this page moves or times your reading.",'<button class="primary" id="return-setup" type="button">Return to setup</button>');$("return-setup").onclick=async()=>{await refresh();view=route();render()}}
function route(){return !st?.loggedIn?"signin":!st.identityVerified?"identity":!st.mfaEnabled?(st.authenticatorSetupStarted?"authenticatorConfirm":"setupPage"):!st.recoveryGenerated?"backup":!st.recoveryConfirmed?(codes?"recover":"manage"):"done"}
async function logout(){try{await api("/api/logout","POST")}catch{}token="";st=null;idCode=setup=codes=null;shown=true;log("SIMULATION: You have been logged out securely.");boot()}
async function boot(){try{await refresh();view=route();render()}catch{A.textContent="We could not open secure setup. Please refresh this page."}}boot()})();
</script></body></html>`;
}

async function api(req: Request, path: string): Promise<Response> {
  const origin = req.headers.get("origin");
  if (origin && !origins.has(origin)) return fail("This request was not accepted. Please use this page directly.", 403);

  if (path === "/api/state" && req.method === "GET") {
    let s = current(req), cookie: string | undefined;
    if (!s) { s = newSession(); sessions.set(s.id, s); cookie = sessionCookie(s.id); }
    const h = headers(); if (cookie) h.set("Set-Cookie", cookie);
    return json(state(s, s.user ? accounts.get(s.user) : undefined), 200, h);
  }
  if (path === "/api/login" && req.method === "POST") {
    const old = current(req), b = await body(req);
    if (!old || !csrf(req, old)) return fail("Please refresh the page and try again.", 403);
    const email = typeof b?.email === "string" ? b.email.trim().toLowerCase() : "";
    const password = typeof b?.password === "string" ? b.password : "";
    const now = Date.now(), attempts = loginFailures.get(email) || { failures: 0, locked: 0 };
    if (attempts.locked > now) return fail("Too many sign-in attempts. Please wait a few minutes, then try again.", 429);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email) || email.length > 254 || password.length > 256 || email !== "marcus@example.com" || password !== "bank-demo") {
      attempts.failures++; if (attempts.failures >= MAX_FAILURES) { attempts.failures = 0; attempts.locked = now + LOCK; }
      loginFailures.set(email, attempts);
      return fail(attempts.locked ? "Too many sign-in attempts. Please wait a few minutes, then try again." : "We could not sign you in. Check your email and password, then try again.", attempts.locked ? 429 : 401);
    }
    loginFailures.delete(email); sessions.delete(old.id);
    const s = newSession(); s.user = "marcus-account"; sessions.set(s.id, s);
    const h = headers(); h.set("Set-Cookie", sessionCookie(s.id)); return json(state(s, accounts.get(s.user)), 200, h);
  }
  if (path === "/api/logout" && req.method === "POST") {
    const s = current(req); if (!s || !csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    sessions.delete(s.id); const h = headers(); h.set("Set-Cookie", sessionCookie("", 0)); return json({ ok: true }, 200, h);
  }
  if (path === "/api/identity/send" && req.method === "POST") {
    const r = owner(req); if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    if (r.a.identityLocked > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes.", 429);
    const code = otp(); r.s.identityCode = { hash: await hash(code), expires: Date.now() + CODE_LIFE, used: false };
    return json({ ok: true, csrf: r.s.csrf, testCode: code });
  }
  if (path === "/api/identity/verify" && req.method === "POST") {
    const r = owner(req); if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req), challenge = r.s.identityCode;
    if (!six(b?.code)) return fail("Enter all 6 numbers from the email code.");
    if (r.a.identityLocked > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes.", 429);
    if (!challenge || challenge.used || challenge.expires < Date.now()) return fail("That code is no longer available. Send a new code and try again.");
    if (!equal(await hash(b.code), challenge.hash)) {
      if (++r.a.identityFailures >= MAX_FAILURES) { r.a.identityFailures = 0; r.a.identityLocked = Date.now() + LOCK; return fail("Too many incorrect codes. Please wait a few minutes.", 429); }
      return fail("That code does not match. Check the 6 numbers or send a new code.");
    }
    challenge.used = true; r.a.identityFailures = 0; r.s.identity = true; return json(state(r.s, r.a));
  }
  if (path === "/api/authenticator/setup" && req.method === "POST") {
    const r = verified(req); if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    if (r.a.authLocked > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes.", 429);
    const secret = base32Secret();
    r.a.otp = await encrypt(secret); r.a.setup = true; r.a.mfa = false;
    /* New enrolment gets a new one-time counter history. */
    r.a.acceptedTotpCounters = new Set();
    const testCode = await currentTotp(r.a.otp);
    return json({ ok: true, csrf: r.s.csrf, secret, uri: `otpauth://totp/Harbour:marcus?secret=${secret}&issuer=Harbour`, testCode });
  }
  /* Task: protected, CSRF-validated current practice code endpoint. It decrypts
     only to calculate the current code and never replaces the stored secret. */
  if (path === "/api/authenticator/practice-code" && req.method === "POST") {
    const r = verified(req); if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    if (!r.a.setup || !r.a.otp) return fail("Show setup options again before requesting a practice code.", 403);
    return json({ ok: true, csrf: r.s.csrf, testCode: await currentTotp(r.a.otp) });
  }
  if (path === "/api/authenticator/confirm" && req.method === "POST") {
    const r = verified(req); if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req);
    if (!six(b?.code)) return fail("Enter the 6-number authenticator code.");
    if (r.a.authLocked > Date.now()) return fail("Too many incorrect codes. Please wait a few minutes.", 429);
    if (!r.a.setup || !r.a.otp) return fail("Show setup options again, then enter the authenticator code.");
    const counter = await matchedTotpCounter(r.a.otp, b.code);
    if (counter === null) {
      if (++r.a.authFailures >= MAX_FAILURES) { r.a.authFailures = 0; r.a.authLocked = Date.now() + LOCK; return fail("Too many incorrect codes. Please wait a few minutes.", 429); }
      return fail("That code does not match this authenticator. Check it and try again.");
    }
    /* Task: reject a previously accepted counter. Record only after validation
       succeeds, making confirmation TOTP single-use for this enrolment. */
    if (r.a.acceptedTotpCounters.has(counter)) return fail("That authenticator code was already used. Get a new practice code and try again.");
    r.a.acceptedTotpCounters.add(counter);
    r.a.authFailures = 0; r.a.mfa = true; return json(state(r.s, r.a));
  }
  if (path === "/api/recovery/generate" && req.method === "POST") {
    const r = verified(req); if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    if (!r.a.mfa) return fail("Finish authenticator setup before creating backup codes.", 403);
    const b = await body(req);
    if (r.a.recovery.size && b?.confirmRegenerate !== true) return fail("Please confirm that you want to replace your current backup codes.");
    const codes = recoverySet(); r.a.recovery = new Set(await Promise.all(codes.map(hash)));
    r.a.recoveryExpires = Date.now() + 365 * 24 * 60 * 60_000; r.a.recoveryFailures = 0; r.a.recoveryLocked = 0; r.a.generated = true; r.a.confirmed = false;
    return json({ ok: true, csrf: r.s.csrf, codes });
  }
  if (path === "/api/recovery/verify" && req.method === "POST") {
    const r = verified(req); if (r instanceof Response) return r;
    if (!csrf(req, r.s)) return fail("Please refresh the page and try again.", 403);
    const b = await body(req), a = r.a;
    if (!a.generated) return fail("Create backup codes before checking one.", 403);
    if (!rec(b?.code)) return fail("Enter a backup code in this format: ABCD-EFGH-IJKL.");
    if (a.recoveryLocked > Date.now()) return fail("Too many incorrect backup codes. Please wait a few minutes.", 429);
    if (!a.recoveryExpires || a.recoveryExpires < Date.now()) return fail("These backup codes have expired. Generate a new set.");
    const candidate = await hash(b.code); let found: string | undefined;
    for (const value of a.recovery) if (equal(value, candidate)) { found = value; break; }
    if (!found) {
      if (++a.recoveryFailures >= MAX_FAILURES) { a.recoveryFailures = 0; a.recoveryLocked = Date.now() + LOCK; return fail("Too many incorrect backup codes. Please wait a few minutes.", 429); }
      return fail("That backup code is not available. Check the code and try another saved code.");
    }
    a.recovery.delete(found); a.recoveryFailures = 0; a.confirmed = true; return json(state(r.s, a));
  }
  return fail("This secure page is not available.", 404);
}

serve({
  port: PORT,
  tls: { cert: file("certs/cert.pem"), key: file("certs/key.pem") },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.protocol !== "https:") return fail("Please use the secure HTTPS address.", 403);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = secureHex(18), h = headers(nonce); h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      return fail("This secure page is not available.", 404);
    } catch { return fail("We could not complete that request. Please try again.", 500); }
  }
});
