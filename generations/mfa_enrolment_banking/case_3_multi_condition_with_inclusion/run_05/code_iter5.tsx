
import { serve } from "bun";

/* Requirements 1–5: TLS, secure in-memory mock state, authorization and CSRF. */
const cert = await Bun.file("certs/cert.pem").text();
const key = await Bun.file("certs/key.pem").text();
const enc = new TextEncoder(), dec = new TextDecoder();
const IDLE = 30 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 15 * 60_000, LOCK = 10 * 60_000, MAX = 5;
const ORIGIN = /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/;
const PERIOD = 30;

type Verify = { code: string; expires: number; used: boolean; attempts: number; locked: number };
type Stored = { iv: string; cipher: string };
type Session = { id: string; accountId: string; csrf: string; created: number; seen: number };
type Account = {
  id: string; email: string; identityVerified: boolean; mfaEnabled: boolean;
  identity?: Verify; auth?: Verify; pending?: Stored; secret?: Stored; usedSteps: number[];
  backups: { salt: string; hash: string; used: boolean }[]; recoveryAttempts: number; recoveryLocked: number;
};

const accounts = new Map<string, Account>();
accounts.set("acct-marcus", {
  id: "acct-marcus", email: "marcus@example.com", identityVerified: false, mfaEnabled: false,
  usedSteps: [], backups: [], recoveryAttempts: 0, recoveryLocked: 0
});
const sessions = new Map<string, Session>();
const tickets = new Map<string, number>();
const loginFailures = new Map<string, { attempts: number; locked: number }>();
const encryptionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

function token(n = 32) { const a = new Uint8Array(n); crypto.getRandomValues(a); return Buffer.from(a).toString("base64url"); }
function six() { const a = new Uint32Array(1); crypto.getRandomValues(a); return String(a[0] % 900000 + 100000); }
function secret() { const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", a = new Uint8Array(20); crypto.getRandomValues(a); return [...a].map(x => chars[x % 32]).join(""); }
function recovery() { const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", a = new Uint8Array(10); crypto.getRandomValues(a); return [...a].map(x => chars[x % chars.length]).join(""); }
function b64(a: ArrayBuffer | Uint8Array) { return Buffer.from(a).toString("base64url"); }
function unb64(s: string) { return new Uint8Array(Buffer.from(s, "base64url")); }
async function hash(s: string) { return b64(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
async function crypt(s: string): Promise<Stored> {
  const iv = new Uint8Array(12); crypto.getRandomValues(iv);
  return { iv: b64(iv), cipher: b64(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, encryptionKey, enc.encode(s))) };
}
async function decrypt(s: Stored) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(s.iv) }, encryptionKey, unb64(s.cipher)));
}
function base32(s: string) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", out: number[] = []; let value = 0, bits = 0;
  for (const char of s.replace(/[\s=]/g, "").toUpperCase()) {
    const n = chars.indexOf(char); if (n < 0) throw new Error("Bad setup key");
    value = value << 5 | n; bits += 5;
    if (bits >= 8) { bits -= 8; out.push(value >> bits & 255); }
  }
  return new Uint8Array(out);
}
async function totp(s: string, counter: number) {
  const msg = new Uint8Array(8); let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) { msg[i] = Number(n & 255n); n >>= 8n; }
  const k = await crypto.subtle.importKey("raw", base32(s), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg)), o = mac[19] & 15;
  return String((((mac[o] & 127) << 24) | mac[o + 1] << 16 | mac[o + 2] << 8 | mac[o + 3]) % 1_000_000).padStart(6, "0");
}
async function backups() {
  const plain = Array.from({ length: 8 }, recovery), stored = [];
  for (const code of plain) { const salt = token(16); stored.push({ salt, hash: await hash(salt + ":" + code), used: false }); }
  return { plain, stored };
}
function verifyNew(): Verify { return { code: six(), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, locked: 0 }; }
function lockText() { return "Too many tries were made for this code. Please wait 10 minutes, then request a fresh code."; }

/* Requirement 1: identity comes exclusively from the HttpOnly session cookie. */
function auth(req: Request) {
  const m = (req.headers.get("cookie") || "").match(/(?:^|;\s*)mfa_session=([^;]+)/);
  const session = m && sessions.get(m[1]); if (!session) return null;
  const now = Date.now();
  if (now - session.seen > IDLE || now - session.created > ABSOLUTE) { sessions.delete(session.id); return null; }
  const account = accounts.get(session.accountId); if (!account) { sessions.delete(session.id); return null; }
  session.seen = now; return { session, account };
}
function headers(req: Request, nonce?: string) {
  const h = new Headers({
    "Content-Security-Policy": nonce ? `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains", "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store"
  });
  const origin = req.headers.get("origin");
  if (origin && ORIGIN.test(origin)) {
    h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true");
    h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token"); h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); h.set("Vary", "Origin");
  }
  return h;
}
function reply(req: Request, data: unknown, status = 200, extra?: HeadersInit) {
  const h = headers(req); h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(data), { status, headers: h });
}
async function body(req: Request) {
  if (!(req.headers.get("content-type") || "").includes("application/json")) return null;
  const text = await req.text(); if (text.length > 4000) return null;
  try { const x = JSON.parse(text); return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null; } catch { return null; }
}
function field(b: Record<string, unknown> | null, key: string, max = 200) { const x = b?.[key]; return typeof x === "string" && x.length <= max ? x.trim() : ""; }
function csrf(req: Request, s: Session, b: Record<string, unknown> | null) { const x = req.headers.get("x-csrf-token") || field(b, "csrf"); return x.length >= 32 && x === s.csrf; }
function cookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`; }
function failCSRF(req: Request) { return reply(req, { error: "Your page check expired. Refresh the page, then try again." }, 403); }
function validOTP(s: string) { return /^\d{6}$/.test(s); }
function validRecovery(s: string) { return /^[A-Z2-9]{10}$/.test(s); }
function safe(req: Request) { const o = req.headers.get("origin"); return !o || ORIGIN.test(o); }

function checkCode(v: Verify | undefined, code: string) {
  const now = Date.now();
  if (!v) return { ok: false, error: "Request a new code, then try again." };
  if (v.locked > now) return { ok: false, error: lockText() };
  if (v.used || v.expires < now) return { ok: false, error: "This code is no longer available. Request a new code and try again." };
  if (v.code !== code) {
    v.attempts++;
    if (v.attempts >= MAX) v.locked = now + LOCK;
    return { ok: false, error: v.locked > now ? lockText() : "That code does not match. Check the six digits and try again." };
  }
  v.used = true; return { ok: true, error: "" };
}

async function api(req: Request, path: string) {
  if (!safe(req)) return reply(req, { error: "Request not allowed." }, 403);
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: headers(req) });
  if (path === "/api/bootstrap" && req.method === "GET") {
    const t = token(); tickets.set(t, Date.now() + 600_000); return reply(req, { csrf: t });
  }
  if (path === "/api/signin" && req.method === "POST") {
    const b = await body(req), ticket = field(b, "csrf"), until = tickets.get(ticket); tickets.delete(ticket);
    if (!until || until < Date.now()) return failCSRF(req);
    const email = field(b, "email", 120).toLowerCase(), password = field(b, "password"), state = loginFailures.get(email);
    if (state?.locked && state.locked > Date.now()) return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    const a = accounts.get("acct-marcus");
    if (!a || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email !== a.email || password !== "BankPass1!") {
      const s = state || { attempts: 0, locked: 0 }; s.attempts++; if (s.attempts >= MAX) { s.attempts = 0; s.locked = Date.now() + LOCK; } loginFailures.set(email, s);
      return reply(req, { error: "We could not sign you in with those details. Check them and try again." }, 401);
    }
    loginFailures.delete(email); const id = token(), s = { id, accountId: a.id, csrf: token(), created: Date.now(), seen: Date.now() }; sessions.set(id, s);
    return reply(req, { csrf: s.csrf, step: a.identityVerified ? (a.mfaEnabled ? "settings" : "provision") : "identity" }, 200, { "Set-Cookie": cookie(id) });
  }
  const who = auth(req); if (!who) return reply(req, { error: "Your signed-in session ended. Please sign in again." }, 401);
  const { session, account } = who, b = req.method === "POST" ? await body(req) : null;
  if (path === "/api/me" && req.method === "GET") return reply(req, { email: account.email, csrf: session.csrf, mfaEnabled: account.mfaEnabled });
  if (!csrf(req, session, b) && req.method === "POST") return failCSRF(req);

  if (path === "/api/identity/request" && req.method === "POST") {
    /* Task: new requests have a new independent attempt count; current-code rate limit remains. */
    if (account.identity?.locked > Date.now()) return reply(req, { error: lockText() }, 429);
    account.identity = verifyNew();
    return reply(req, { message: "A fresh verification code was sent. Earlier code tries do not count against this new code.", testCode: account.identity.code });
  }
  if (path === "/api/identity/verify" && req.method === "POST") {
    const code = field(b, "code", 6); if (!validOTP(code)) return reply(req, { error: "Enter six digits, for example 123456." }, 400);
    const checked = checkCode(account.identity, code); if (!checked.ok) return reply(req, { error: checked.error }, 400);
    account.identityVerified = true; return reply(req, { message: "Identity confirmed.", next: "provision" });
  }
  if (path === "/api/provision" && req.method === "POST") {
    if (!account.identityVerified) return reply(req, { error: "Please confirm your identity before setting up an authenticator." }, 403);
    if (account.auth?.locked > Date.now()) return reply(req, { error: lockText() }, 429);
    const s = secret(); account.pending = await crypt(s); account.usedSteps = []; account.auth = verifyNew();
    return reply(req, { secret: s, testOtp: await totp(s, Math.floor(Date.now() / 1000 / PERIOD)), email: account.email });
  }
  if (path === "/api/authenticator/activate" && req.method === "POST") {
    if (!account.identityVerified || !account.pending) return reply(req, { error: "Start the authenticator setup again, then enter the new code." }, 400);
    if (account.auth?.locked > Date.now()) return reply(req, { error: lockText() }, 429);
    const otp = field(b, "otp", 6), manual = field(b, "manualSecret", 64).replace(/\s/g, "").toUpperCase();
    if (!validOTP(otp)) return reply(req, { error: "Enter six digits from your authenticator, for example 123456." }, 400);
    let s = ""; try { s = await decrypt(account.pending); } catch { account.pending = undefined; return reply(req, { error: "Start the authenticator setup again, then enter the new code." }, 400); }
    if (manual && manual !== s) return reply(req, { error: "The setup key does not match this page. Copy the key again, then try." }, 400);
    const now = Math.floor(Date.now() / 1000 / PERIOD); let used: number | null = null;
    for (let i = -1; i <= 1; i++) if (!account.usedSteps.includes(now + i) && await totp(s, now + i) === otp) { used = now + i; break; }
    if (used === null) {
      account.auth!.attempts++; if (account.auth!.attempts >= MAX) account.auth!.locked = Date.now() + LOCK;
      return reply(req, { error: account.auth!.locked > Date.now() ? lockText() : "That code does not match your authenticator. Check the six digits and try again." }, 400);
    }
    account.usedSteps.push(used); account.secret = account.pending; account.pending = undefined; account.auth = undefined; account.mfaEnabled = true;
    const x = await backups(); account.backups = x.stored; account.recoveryAttempts = 0; account.recoveryLocked = 0;
    return reply(req, { message: "Authenticator confirmed.", recoveryCodes: x.plain });
  }
  if (path === "/api/recovery/confirm" && req.method === "POST") {
    if (!account.mfaEnabled) return reply(req, { error: "Set up your authenticator before completing enrolment." }, 400);
    return reply(req, { message: "MFA enrolment is complete." });
  }
  if (path === "/api/recovery/regenerate" && req.method === "POST") {
    if (!account.mfaEnabled) return reply(req, { error: "MFA is not active on this account." }, 400);
    const x = await backups(); account.backups = x.stored; account.recoveryAttempts = 0; account.recoveryLocked = 0;
    return reply(req, { message: "New recovery codes are ready. Older codes no longer work.", recoveryCodes: x.plain });
  }
  if (path === "/api/recovery/use" && req.method === "POST") {
    if (!account.mfaEnabled) return reply(req, { error: "MFA is not active on this account." }, 400);
    if (account.recoveryLocked > Date.now()) return reply(req, { error: "Too many recovery-code attempts were made. Please wait 10 minutes, then try again." }, 429);
    if (account.recoveryLocked) { account.recoveryLocked = 0; account.recoveryAttempts = 0; }
    const code = field(b, "code", 20).replace(/[-\s]/g, "").toUpperCase(); let found = false;
    if (validRecovery(code)) for (const saved of account.backups) if (!saved.used && await hash(saved.salt + ":" + code) === saved.hash) { saved.used = true; found = true; break; }
    if (!found) {
      account.recoveryAttempts++; if (account.recoveryAttempts >= MAX) { account.recoveryAttempts = 0; account.recoveryLocked = Date.now() + LOCK; }
      return reply(req, { error: account.recoveryLocked > Date.now() ? "Too many recovery-code attempts were made. Please wait 10 minutes, then try again." : "That recovery code cannot be used. Check it, or use another unused code." }, 400);
    }
    account.recoveryAttempts = 0; return reply(req, { message: "Recovery code accepted. That code has now been used and cannot be used again." });
  }
  if (path === "/api/logout" && req.method === "POST") {
    sessions.delete(session.id); return reply(req, { message: "Signed out." }, 200, { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  return reply(req, { error: "That service is not available." }, 404);
}

const HTML = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank – MFA setup</title>
<style nonce="__NONCE__">
:root{--ink:#162235;--muted:#536174;--paper:#f5f8fc;--card:#fff;--blue:#0759bd;--dark:#063f8a;--line:#d4ddea;--good:#12623c;--bad:#a22929;--focus:#ee9b00}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:"Atkinson Hyperlegible","OpenDyslexic",Verdana,Arial,sans-serif;font-size:17px;line-height:1.68;letter-spacing:.028em}button,input{font:inherit;letter-spacing:.025em}button{cursor:pointer}.shell{max-width:630px;margin:auto;padding:17px 15px 42px}header{display:flex;gap:11px;align-items:center;margin:4px 0 20px}.mark{width:44px;height:44px;border-radius:14px;display:grid;place-items:center;background:var(--blue);color:#fff;font-size:23px}h1{font-size:1.35rem;line-height:1.2;margin:0}h2{font-size:1.36rem;line-height:1.3;margin:0 0 10px}p{margin:0 0 14px}.small,.hint{color:var(--muted);font-size:.9rem}.steps{display:flex;gap:5px;margin-bottom:18px}.step{flex:1;padding:6px 3px;border-radius:8px;background:#e5eaf2;color:var(--muted);font-size:.7rem;text-align:center;line-height:1.3}.step.current{background:#dceaff;color:var(--dark);font-weight:bold}.card{padding:22px;background:var(--card);border:1px solid var(--line);border-radius:17px;box-shadow:0 2px 8px #18385a0b}.cue{display:flex;gap:10px;align-items:center;color:var(--dark);font-weight:bold;margin-bottom:10px;font-size:1.05rem}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;min-height:50px;padding:11px 13px;border:2px solid #adbacd;border-radius:10px;color:var(--ink);background:#fff}input:focus,button:focus{outline:3px solid var(--focus);outline-offset:2px}.code{font-size:1.18rem;letter-spacing:.14em}.primary,.secondary{width:100%;min-height:52px;padding:10px 14px;border-radius:11px;font-weight:bold;margin-top:18px}.primary{border:0;background:var(--blue);color:#fff}.primary:hover{background:var(--dark)}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue);margin-top:10px}.notice{padding:11px 13px;border-radius:10px;background:#e7f5ec;color:var(--good);font-weight:bold;margin:12px 0}.error{background:#fff0f0;color:var(--bad)}.noticebox:empty{display:none}details{border-top:1px solid var(--line);margin-top:19px;padding-top:12px;color:var(--muted)}summary{color:var(--blue);font-weight:bold;cursor:pointer}.secret{padding:10px;border-radius:10px;background:#f0f4f9;word-break:break-all;font-family:monospace;letter-spacing:.1em}.qr{width:250px;height:250px;max-width:100%;display:block;margin:15px auto;background:#fff;image-rendering:pixelated;box-shadow:0 0 0 1px var(--line)}.codes{list-style:none;padding:0;margin:13px 0}.codes li{font-family:monospace;font-weight:bold;letter-spacing:.1em;padding:7px;border-bottom:1px solid var(--line)}.hiddenvalue{padding:12px;border-radius:10px;background:#f0f4f9;color:var(--muted)}.top{display:flex;justify-content:space-between;align-items:center}.link{border:0;background:transparent;color:var(--blue);text-decoration:underline;font-weight:bold;padding:5px}.logs{margin-top:18px;border:1px solid var(--line);border-radius:13px;background:#fff;padding:13px}.logs h2{font-size:1rem}.logline{font-family:monospace;font-size:.78rem;overflow-wrap:anywhere;padding:5px 0;border-bottom:1px solid #edf0f5}.logline:last-child{border:0}@media print{header,.steps,button,details,.logs,.noticebox{display:none!important}.card{box-shadow:none;border:0}}
</style></head><body><main class="shell"><header><div class="mark" aria-hidden="true">⚓</div><div><h1>Harbour Bank</h1><div class="small">MFA enrolment</div></div></header><nav class="steps" id="steps" aria-label="Setup progress"></nav><section id="app" aria-live="polite"><div class="card">Loading your secure page…</div></section><section class="logs" aria-label="Browser simulation logs"><h2>Logs</h2><div id="logs">No simulation messages yet.</div></section></main>
<script nonce="__NONCE__">
(function(){"use strict";
var app=document.getElementById("app"),steps=document.getElementById("steps"),logs=document.getElementById("logs"),csrf="",setupSecret="",currentCodes=[];
function E(t,x,c){var n=document.createElement(t);if(x!==undefined)n.textContent=x;if(c)n.className=c;return n}function clear(){app.replaceChildren()}function btn(x,c){var b=E("button",x,c||"primary");b.type="button";return b}function inp(t,n,p){var i=document.createElement("input");i.type=t;i.name=n;i.placeholder=p||"";return i}function box(){var n=E("div",undefined,"noticebox");n.setAttribute("role","status");return n}function say(n,x,b){n.replaceChildren(E("div",x,"notice"+(b?" error":"")))}function help(x){var d=document.createElement("details");d.append(E("summary","Help"),E("p",x));return d}function log(x){console.log(x);if(logs.textContent==="No simulation messages yet.")logs.replaceChildren();logs.append(E("div",x,"logline"))}function draw(a){steps.replaceChildren();[["signin","1 · Sign in"],["identity","2 · Confirm"],["provision","3 · App"],["recovery","4 · Codes"]].forEach(function(x){steps.append(E("div",x[1],"step"+(x[0]===a?" current":"")))})}
async function req(path,data,method){var o={method:method||"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},credentials:"same-origin"};if(o.method!=="GET")o.body=JSON.stringify(data||{});var r=await fetch(path,o),j;try{j=await r.json()}catch(e){throw Error("Something went wrong. Please try again.")}if(!r.ok)throw Error(j.error||"Something went wrong. Please try again.");if(j.csrf)csrf=j.csrf;return j}
function submit(f,text,n,fn){var b=btn(text);f.append(b);f.onsubmit=function(e){e.preventDefault();b.disabled=true;say(n,"");fn().catch(function(e){say(n,e.message,true)}).finally(function(){b.disabled=false})}}
function copy(x,name){navigator.clipboard.writeText(x).then(function(){log(name+" copied to clipboard.")}).catch(function(){log("Copy was not available. Select the visible value and copy it instead.")})}

/* Task: standards-based QR version 10-L encoder. Format bits use both ISO/IEC 18004 format-information locations correctly. */
function qrCanvas(text){
 var N=57,CAP=274,bytes=new TextEncoder().encode(text),bits=[],i,j;function put(v,l){for(var q=l-1;q>=0;q--)bits.push(v>>>q&1)}put(4,4);put(bytes.length,16);bytes.forEach(function(x){put(x,8)});for(i=0;i<Math.min(4,CAP*8-bits.length);i++)bits.push(0);while(bits.length%8)bits.push(0);var data=[];for(i=0;i<bits.length;i+=8){var z=0;for(j=0;j<8;j++)z=z<<1|bits[i+j];data.push(z)}for(i=0;data.length<CAP;i++)data.push(i%2?17:236);
 var ex=[],lg=[],v=1;for(i=0;i<255;i++){ex[i]=v;lg[v]=i;v<<=1;if(v&256)v^=285}for(i=255;i<512;i++)ex[i]=ex[i-255];function mul(a,b){return!a||!b?0:ex[lg[a]+lg[b]]}function gen(d){var p=[1];for(var k=0;k<d;k++){var q=[];for(i=0;i<=p.length;i++)q[i]=(i<p.length?p[i]:0)^(i?mul(p[i-1],ex[k]):0);p=q}return p}function ecc(a){var g=gen(18),r=new Array(18).fill(0);a.forEach(function(x){var f=x^r.shift();r.push(0);for(var k=0;k<18;k++)r[k]^=mul(g[k+1],f)});return r}
 var blocks=[],at=0;for(i=0;i<4;i++){var len=i<2?68:69;blocks.push(data.slice(at,at+=len))}var es=blocks.map(ecc),stream=[];for(i=0;i<69;i++)for(j=0;j<4;j++)if(i<blocks[j].length)stream.push(blocks[j][i]);for(i=0;i<18;i++)for(j=0;j<4;j++)stream.push(es[j][i]);
 var m=Array.from({length:N},function(){return Array(N).fill(false)}),used=Array.from({length:N},function(){return Array(N).fill(false)});function set(r,c,x){if(r>=0&&c>=0&&r<N&&c<N){m[r][c]=!!x;used[r][c]=true}}function finder(r,c){for(var y=-1;y<=7;y++)for(var x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))}
 finder(0,0);finder(0,N-7);finder(N-7,0);for(i=8;i<N-8;i++){set(6,i,i%2===0);set(i,6,i%2===0)}[6,28,50].forEach(function(r){[6,28,50].forEach(function(c){if((r<9&&c<9)||(r<9&&c>N-9)||(r>N-9&&c<9))return;for(var y=-2;y<=2;y++)for(var x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(y),Math.abs(x))!==1)})});for(i=0;i<9;i++){if(!used[i][8])set(i,8,0);if(!used[8][i])set(8,i,0);if(!used[i][N-8])set(i,N-8,0);if(!used[N-8][i])set(N-8,i,0)}set(N-8,8,1);
 function rem(x,p){var d=p.toString(2).length;x<<=d-1;while(x.toString(2).length>=d)x^=p<<(x.toString(2).length-d);return x}var format=((8<<10)|rem(8,1335))^21522;
 for(i=0;i<15;i++){var bit=format>>>i&1;if(i<6)set(i,8,bit);else if(i<8)set(i+1,8,bit);else set(N-15+i,8,bit);if(i<8)set(8,N-i-1,bit);else if(i<9)set(8,15-i,bit);else set(8,14-i,bit)}
 var bi=0,up=true;for(var col=N-1;col>0;col-=2){if(col===6)col--;for(i=0;i<N;i++){var row=up?N-1-i:i;for(var side=0;side<2;side++){var c=col-side;if(!used[row][c]){var bit=bi<stream.length?stream[bi>>3]>>>(7-(bi&7))&1:0;bi++;if((row+c)%2===0)bit^=1;m[row][c]=!!bit}}up=!up}
 var canvas=document.createElement("canvas"),scale=4;canvas.width=canvas.height=N*scale;canvas.className="qr";canvas.setAttribute("role","img");canvas.setAttribute("aria-label","Scannable QR code for Harbour Bank authenticator setup");var ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,canvas.width,canvas.height);ctx.fillStyle="#000";for(i=0;i<N;i++)for(j=0;j<N;j++)if(m[i][j])ctx.fillRect(j*scale,i*scale,scale,scale);return canvas
}
function signin(){draw("signin");clear();var c=E("section",undefined,"card"),n=box(),f=document.createElement("form"),email=inp("email","email","name@example.com"),pass=inp("password","password","Your password");email.autocomplete="email";pass.autocomplete="current-password";c.append(E("div","🔐 Sign in","cue"),E("h2","Set up extra payment protection"),E("p","Sign in first. You will take this one step at a time."),n);f.append(E("label","Email address"),email,E("p","Example: marcus@example.com","hint"),E("label","Password"),pass,E("p","Demo: marcus@example.com / BankPass1!","hint"));submit(f,"Sign in securely",n,async function(){var j=await req("/api/signin",{email:email.value,password:pass.value,csrf:csrf});csrf=j.csrf;log("Sign-in simulation complete.");j.step==="settings"?settings():j.step==="provision"?provisionStart():identity()});c.append(f,help("Use the demo details shown above. No information is saved in your browser."));app.append(c)}
function identity(){draw("identity");clear();var c=E("section",undefined,"card"),n=box(),f=document.createElement("form"),send=btn("Send verification code"),code=inp("text","code","123456");code.inputMode="numeric";code.maxLength=6;code.autocomplete="one-time-code";code.className="code";send.onclick=async function(){send.disabled=true;try{var j=await req("/api/identity/request",{});log("Identity verification test code: "+j.testCode);say(n,j.message);send.textContent="Send another code"}catch(e){say(n,e.message,true)}finally{send.disabled=false}};c.append(E("div","🪪 Confirm your identity","cue"),E("h2","Get a short verification code"),E("p","Select send. You can request another code whenever you need."),n,send);f.append(E("label","Six-digit code"),code,E("p","Example: 123456","hint"));submit(f,"Confirm identity",n,async function(){await req("/api/identity/verify",{code:code.value});log("Identity verification completed.");provisionStart()});c.append(f,help("The test code appears in Logs after you select Send. A new request gives you a fresh code and a fresh set of tries."));app.append(c)}
function provisionStart(){draw("provision");clear();var c=E("section",undefined,"card"),n=box(),b=btn("Create my setup key");b.onclick=async function(){b.disabled=true;try{var j=await req("/api/provision",{});setupSecret=j.secret;log("Current authenticator test OTP: "+j.testOtp);provision(j.email)}catch(e){say(n,e.message,true)}finally{b.disabled=false}};c.append(E("div","📱 Authenticator app","cue"),E("h2","Make your setup key"),E("p","Use an authenticator app. You can scan a QR option or copy the setup key."),n,b,help("Choose this when you are ready. Starting again creates a different setup key."));app.append(c)}
function provision(email){draw("provision");clear();var c=E("section",undefined,"card"),n=box(),f=document.createElement("form"),uri="otpauth://totp/"+encodeURIComponent("Harbour Bank:"+email)+"?secret="+encodeURIComponent(setupSecret)+"&issuer=Harbour%20Bank&algorithm=SHA1&digits=6&period=30",reveal=btn("Show setup key","secondary"),holder=E("div","Setup key is hidden until you choose Show setup key.","hiddenvalue");reveal.setAttribute("aria-expanded","false");reveal.onclick=function(){var open=reveal.getAttribute("aria-expanded")!=="true";reveal.setAttribute("aria-expanded",String(open));reveal.textContent=open?"Hide setup key":"Show setup key";holder.replaceChildren();if(open){var s=E("div",setupSecret,"secret");s.setAttribute("aria-label","Setup key "+setupSecret.split("").join(" "));holder.append(s)}else holder.textContent="Setup key is hidden until you choose Show setup key."};c.append(E("div","📷 Scan or copy","cue"),E("h2","Add this to your authenticator app"),E("p","Scan the QR code first. If scanning is difficult, reveal and copy the setup key."),n,qrCanvas(uri),E("p","Setup key","hint"),holder,reveal);var cp=btn("Copy setup key","secondary");cp.onclick=function(){copy(setupSecret,"Setup key")};var cu=btn("Copy authenticator QR link","secondary");cu.onclick=function(){copy(uri,"Authenticator setup link")};c.append(cp,cu);var manual=inp("text","manual","Paste setup key here if needed"),otp=inp("text","otp","123456");otp.inputMode="numeric";otp.maxLength=6;otp.autocomplete="one-time-code";otp.className="code";f.append(E("label","Manual setup key (optional)"),manual,E("p","Paste it only if your app asks you to confirm it.","hint"),E("label","Six-digit code from your app"),otp,E("p","Example: 123456. The current test value is in Logs.","hint"));submit(f,"Confirm authenticator",n,async function(){var j=await req("/api/authenticator/activate",{manualSecret:manual.value,otp:otp.value});setupSecret="";currentCodes=j.recoveryCodes||[];log("Authenticator verification completed. Recovery codes: "+currentCodes.join(", "));recovery(false)});var again=btn("Start setup again","secondary");again.onclick=provisionStart;c.append(f,again,help("There is no time limit for reading. The authenticator code changes normally in your app."));app.append(c)}
function recovery(regen){draw("recovery");clear();var c=E("section",undefined,"card"),n=box(),holder=E("div","Recovery codes are hidden until you choose Show recovery codes.","hiddenvalue"),showCodes=btn("Show recovery codes","secondary"),f=document.createElement("form");showCodes.setAttribute("aria-expanded","false");showCodes.onclick=function(){var open=showCodes.getAttribute("aria-expanded")!=="true";showCodes.setAttribute("aria-expanded",String(open));showCodes.textContent=open?"Hide recovery codes":"Show recovery codes";holder.replaceChildren();if(open){var list=E("ul",undefined,"codes");currentCodes.forEach(function(x){list.append(E("li",x))});holder.append(list)}else holder.textContent="Recovery codes are hidden until you choose Show recovery codes."};c.append(E("div","🧾 Recovery codes","cue"),E("h2",regen?"Your new recovery codes":"Save these recovery codes"),E("p","Each code works once if you cannot use your authenticator. Keep them somewhere private."),n,holder,showCodes);var cp=btn("Copy all recovery codes","secondary");cp.onclick=function(){copy(currentCodes.join("\n"),"Recovery codes")};c.append(cp);var tick=inp("checkbox","saved");tick.id="saved";var lab=E("label"," I have saved these codes somewhere private.");lab.htmlFor="saved";lab.style.display="inline";f.append(tick,lab);submit(f,regen?"Return to settings":"Finish MFA setup",n,async function(){if(!tick.checked)throw Error("Please tick the box after you have saved the codes.");await req("/api/recovery/confirm",{});log("MFA enrolment completed.");settings()});c.append(f,help("You may copy before continuing. Do not share these codes."));app.append(c)}
function recoveryUse(){draw("recovery");clear();var c=E("section",undefined,"card"),n=box(),f=document.createElement("form"),code=inp("text","recovery","ABCDE12345");code.autocomplete="one-time-code";code.className="code";c.append(E("div","🧾 Use a recovery code","cue"),E("h2","Use one saved recovery code"),E("p","Use this only when you cannot use your authenticator. Each code works once."),n);f.append(E("label","Recovery code"),code,E("p","Example: ABCDE12345. Hyphens and spaces are allowed.","hint"));submit(f,"Use recovery code",n,async function(){var j=await req("/api/recovery/use",{code:code.value});say(n,j.message);log("Recovery code accepted and marked as used.");code.value=""});var back=btn("Back to MFA settings","secondary");back.onclick=settings;c.append(f,back,help("If a code has already been used, choose another saved recovery code."));app.append(c)}
function settings(){draw("recovery");clear();var c=E("section",undefined,"card"),n=box(),top=E("div",undefined,"top"),out=btn("Sign out","link");out.onclick=async function(){out.disabled=true;try{await req("/api/logout",{});csrf="";setupSecret="";currentCodes=[];log("Signed out. Secure session invalidated.");boot()}catch(e){say(n,e.message,true)}finally{out.disabled=false}};top.append(E("strong","🔐 MFA settings"),out);var use=btn("Use a recovery code","secondary");use.onclick=recoveryUse;var regenerate=btn("Make new recovery codes");regenerate.onclick=async function(){regenerate.disabled=true;try{var j=await req("/api/recovery/regenerate",{});currentCodes=j.recoveryCodes||[];log("Recovery codes regenerated: "+currentCodes.join(", "));recovery(true)}catch(e){say(n,e.message,true)}finally{regenerate.disabled=false}};c.append(top,E("h2","Your authenticator is active"),E("p","Your account has extra protection for higher-value payments."),n,use,regenerate,help("Use a saved recovery code if you cannot use your authenticator. New recovery codes replace older ones."));app.append(c)}
async function boot(){try{var j=await req("/api/bootstrap",null,"GET");csrf=j.csrf;signin()}catch(e){clear();app.append(E("div","This secure page could not start. Refresh and try again.","notice error"))}}boot()
})();
</script></body></html>`;

function page(req: Request) {
  const nonce = token(24), h = headers(req, nonce); h.set("Content-Type", "text/html; charset=utf-8");
  return new Response(HTML.replaceAll("__NONCE__", nonce), { headers: h });
}

serve({
  port: Number(process.env.PORT || 3000),
  tls: { cert, key },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (url.pathname.startsWith("/api/")) return await api(req, url.pathname);
      if (url.pathname === "/" && req.method === "GET") return page(req);
      return new Response("Not found.", { status: 404, headers: headers(req) });
    } catch {
      return new Response("Something went wrong. Please try again.", { status: 500, headers: headers(req) });
    }
  }
});
