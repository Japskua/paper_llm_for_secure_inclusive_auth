
import { timingSafeEqual } from "node:crypto";

/*
 MFA Enrolment System — Requirements 1–5:
 owner-bound HTTPS sessions, CSRF checks, encrypted seeds, hashed recovery
 codes, input validation, secure headers, rate limits, and no server secret logs.
*/

type Stage = "signed-in" | "identity" | "setup" | "otp" | "recovery" | "complete";
type Protected = { hash: string; expires: number; used: boolean; tries: number };
type Recovery = { salt: string; hash: string; used: boolean };
type Encrypted = { iv: string; data: string };
type Session = {
  id: string; csrf: string; authenticated: boolean; stage: Stage; created: number; seen: number;
  email?: string; identity?: Protected; encryptedOtp?: Encrypted; otpExpires?: number;
  otpUsed: boolean; fails: number; locked?: number; recoveries: Recovery[];
};

const sessions = new Map<string, Session>();
const encoder = new TextEncoder(), decoder = new TextDecoder();
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 15 * 60_000, LOCK = 5 * 60_000;
const ORIGINS = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
const identityKey = crypto.getRandomValues(new Uint8Array(32));
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const emailExpected = "marcus@example.com", passwordExpected = "bank-demo";
const now = () => Date.now();
const b64 = (v: Uint8Array) => Buffer.from(v).toString("base64url");
const unb64 = (v: string) => new Uint8Array(Buffer.from(v, "base64url"));
const random = (n = 32) => b64(crypto.getRandomValues(new Uint8Array(n)));

function equal(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
async function hmac(key: Uint8Array, value: string) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(new Uint8Array(await crypto.subtle.sign("HMAC", k, encoder.encode(value))));
}
const identityHash = (code: string) => hmac(identityKey, code);
async function recoveryHash(code: string, salt: string) {
  const k = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations: 210000 }, k, 256);
  return b64(new Uint8Array(bits));
}

/* Requirement 3: AES-GCM encryption for retained authenticator seed. */
async function encryptSeed(secret: string): Promise<Encrypted> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(secret));
  return { iv: b64(iv), data: b64(new Uint8Array(data)) };
}
async function decryptSeed(value?: Encrypted) {
  if (!value) return null;
  try {
    const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
    return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, key, unb64(value.data)));
  } catch { return null; }
}
function base32() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", bytes = crypto.getRandomValues(new Uint8Array(20));
  let out = "", bits = 0, value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits ? out + alphabet[(value << (5 - bits)) & 31] : out;
}
function base32Bytes(input: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, value = 0; const out: number[] = [];
  for (const char of input.replace(/[\s=]/g, "").toUpperCase()) {
    const n = alphabet.indexOf(char); if (n < 0) return null;
    value = (value << 5) | n; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
function sixDigitRandom() {
  const a = new Uint32Array(1);
  do crypto.getRandomValues(a); while (a[0] >= 4294000000);
  return String(a[0] % 1_000_000).padStart(6, "0");
}
function recoveryCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", bytes = crypto.getRandomValues(new Uint8Array(9));
  return Array.from(bytes.slice(0, 5), b => alphabet[b % alphabet.length]).join("") + "-" +
    Array.from(bytes.slice(5), b => alphabet[b % alphabet.length]).join("");
}
async function totp(secret: string, counter = Math.floor(now() / 30_000)) {
  const bytes = base32Bytes(secret); if (!bytes) return null;
  const msg = new Uint8Array(8); let c = counter;
  for (let i = 7; i >= 0; i--) { msg[i] = c & 255; c = Math.floor(c / 256); }
  const key = await crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const d = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg)), o = d[19] & 15;
  const value = ((d[o] & 127) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
async function validTotp(secret: string, code: string) {
  const c = Math.floor(now() / 30_000);
  for (const offset of [-1, 0, 1]) {
    const candidate = await totp(secret, c + offset);
    if (candidate && equal(candidate, code)) return true;
  }
  return false;
}

function headers(html = false, nonce = "") {
  return new Headers({
    "Content-Type": html ? "text/html; charset=utf-8" : "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": html
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'"
  });
}
function response(data: unknown, status = 200, extra?: Record<string, string>) {
  const h = headers(); Object.entries(extra || {}).forEach(([k, v]) => h.set(k, v));
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (error: string, status = 400) => response({ ok: false, error }, status);
function getCookie(req: Request, key: string) {
  return (req.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(key + "="))?.slice(key.length + 1);
}
const cookie = (id: string) => `mfa_session=${id}; Path=/; Max-Age=${ABSOLUTE / 1000}; HttpOnly; Secure; SameSite=Strict`;
const expiredCookie = "mfa_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";

function createSession() {
  const s: Session = { id: random(), csrf: random(), authenticated: false, stage: "signed-in", created: now(), seen: now(), otpUsed: false, fails: 0, recoveries: [] };
  sessions.set(s.id, s); return s;
}
function session(req: Request, needsAuth = false): Session | null {
  const id = getCookie(req, "mfa_session"), s = id ? sessions.get(id) : undefined;
  if (!s) return null;
  if (now() - s.seen > IDLE || now() - s.created > ABSOLUTE) { sessions.delete(s.id); return null; }
  if (needsAuth && !s.authenticated) return null;
  s.seen = now(); return s;
}
function owner(req: Request): Session | Response { return session(req, true) || fail("Your secure session has ended. Please sign in again.", 401); }
function csrf(req: Request, s: Session) {
  const origin = req.headers.get("origin"), v = req.headers.get("x-csrf-token") || "";
  return origin !== null && ORIGINS.has(origin) && /^[A-Za-z0-9_-]{40,60}$/.test(v) && equal(v, s.csrf);
}
async function json(req: Request) {
  if (Number(req.headers.get("content-length") || 0) > 4096) return null;
  try { const value = await req.json(); return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null; } catch { return null; }
}
function text(v: Record<string, unknown> | null, key: string, max: number) {
  const x = v?.[key]; return typeof x === "string" && x.length <= max ? x.trim() : null;
}
const locked = (s: Session) => !!s.locked && s.locked > now();
function failed(s: Session) { if (++s.fails >= 5) { s.fails = 0; s.locked = now() + LOCK; } }
async function issueIdentity(s: Session) {
  const code = sixDigitRandom();
  s.identity = { hash: await identityHash(code), expires: now() + CODE_LIFE, used: false, tries: 0 };
  return code;
}
async function issueRecoveries(s: Session) {
  const codes = Array.from({ length: 6 }, recoveryCode);
  s.recoveries = await Promise.all(codes.map(async code => {
    const salt = random(16); return { salt, hash: await recoveryHash(code, salt), used: false };
  }));
  return codes;
}

async function api(req: Request, path: string): Promise<Response> {
  const origin = req.headers.get("origin");
  if (origin !== null && !ORIGINS.has(origin)) return fail("This request is not allowed.", 403);

  if (path === "/api/bootstrap" && req.method === "GET") {
    let s = session(req), set = "";
    if (!s) { s = createSession(); set = cookie(s.id); }
    return response({ ok: true, csrf: s.csrf, authenticated: s.authenticated, stage: s.stage }, 200, set ? { "Set-Cookie": set } : undefined);
  }
  if (path === "/api/sign-in" && req.method === "POST") {
    const old = session(req); if (!old || !csrf(req, old)) return fail("Please refresh the page and try signing in again.", 403);
    const body = await json(req), email = text(body, "email", 120) || "", password = text(body, "password", 200) || "";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !equal(email.toLowerCase(), emailExpected) || !equal(password, passwordExpected))
      return fail("We could not sign you in. Check your email and password, then try again.", 401);
    sessions.delete(old.id);
    const s = createSession(); s.authenticated = true; s.email = emailExpected; s.stage = "identity";
    const identityCode = await issueIdentity(s);
    /* Demo requirement: delivered only in HTTPS response to its authenticated owner, never server logged. */
    return response({ ok: true, csrf: s.csrf, stage: s.stage, message: "A six-digit check code is ready.", identityCode }, 200, { "Set-Cookie": cookie(s.id) });
  }
  if (path === "/api/state" && req.method === "GET") {
    const s = owner(req); return s instanceof Response ? s : response({ ok: true, csrf: s.csrf, stage: s.stage, email: s.email, locked: locked(s) });
  }
  if (path === "/api/identity/resend" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "identity") return fail("Please complete the earlier step first.", 409);
    const identityCode = await issueIdentity(s);
    return response({ ok: true, message: "A new check code is ready. The earlier code no longer works.", identityCode });
  }
  if (path === "/api/identity/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "identity") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const b = await json(req), phone = text(b, "phone", 24), code = text(b, "code", 6);
    if (!phone || !/^\+?[0-9 ()-]{7,24}$/.test(phone) || !code || !/^\d{6}$/.test(code))
      return fail("Enter a phone number like +1 555 010 0200 and six digits like 123456.");
    const i = s.identity;
    if (!i || i.used || i.expires < now()) return fail("That check code is no longer active. Choose send a new code and try again.");
    if (!equal(await identityHash(code), i.hash)) {
      if (++i.tries >= 5) { i.tries = 0; s.locked = now() + LOCK; }
      return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match. Check the six digits and try again.");
    }
    i.used = true; s.stage = "setup";
    return response({ ok: true, stage: s.stage, message: "Identity check complete. Next, add your authenticator." });
  }
  if ((path === "/api/authenticator/setup" || path === "/api/authenticator/refresh") && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    const refresh = path.endsWith("refresh");
    if ((!refresh && s.stage !== "setup") || (refresh && s.stage !== "otp")) return fail("Please complete the earlier step first.", 409);
    const secret = base32(); s.encryptedOtp = await encryptSeed(secret); s.otpExpires = now() + CODE_LIFE; s.otpUsed = false; s.stage = "otp";
    const issuer = "Northstar Bank";
    const provisioningUri = `otpauth://totp/${encodeURIComponent(issuer + ":" + s.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return response({ ok: true, stage: s.stage, secret, provisioningUri, authenticatorOtp: await totp(secret), message: "Authenticator details are ready. Scan or copy them, then enter the six-digit code." });
  }
  if (path === "/api/otp/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "otp") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const code = text(await json(req), "code", 6);
    if (!code || !/^\d{6}$/.test(code)) return fail("Enter six numbers, for example 123456.");
    const secret = await decryptSeed(s.encryptedOtp);
    if (!secret || !s.otpExpires || s.otpUsed || s.otpExpires < now()) return fail("Choose get fresh setup details and try again.");
    if (!(await validTotp(secret, code))) { failed(s); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match your active authenticator. Check the six numbers and try again."); }
    s.otpUsed = true; s.stage = "recovery"; const recoveryCodes = await issueRecoveries(s);
    return response({ ok: true, stage: s.stage, recoveryCodes, message: "Authenticator confirmed. Your recovery codes are ready." });
  }
  if (path === "/api/recovery/generate" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "recovery" && s.stage !== "complete") return fail("Please complete the earlier step first.", 409);
    return response({ ok: true, recoveryCodes: await issueRecoveries(s), message: "New recovery codes are ready. The old ones no longer work." });
  }
  if (path === "/api/recovery/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const code = text(await json(req), "recoveryCode", 10)?.toUpperCase();
    if (!code || !/^[A-Z0-9]{5}-[A-Z0-9]{4}$/.test(code)) return fail("Enter a recovery code like NORTH-1234.");
    let found: Recovery | undefined;
    for (const r of s.recoveries) if (!r.used && equal(await recoveryHash(code, r.salt), r.hash)) { found = r; break; }
    if (!found) { failed(s); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That recovery code does not match an unused code. Check it and try again."); }
    found.used = true; return response({ ok: true, message: "That recovery code worked and is now used." });
  }
  if (path === "/api/recovery/complete" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "recovery") return fail("Please complete the earlier step first.", 409);
    s.stage = "complete"; return response({ ok: true, stage: s.stage, message: "MFA enrolment is complete." });
  }
  if (path === "/api/logout" && req.method === "POST") {
    const s = session(req); if (!s || !csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    sessions.delete(s.id); return response({ ok: true, message: "You have signed out." }, 200, { "Set-Cookie": expiredCookie });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank — MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172033;--blue:#0759b8;--muted:#536074;--line:#c9d5e3;--soft:#eef6ff}*{box-sizing:border-box}body{margin:0;background:#f2f6fa;color:var(--ink);font:17px/1.7 system-ui,-apple-system,"Segoe UI",Arial,Verdana,sans-serif;letter-spacing:.035em}.shell{max-width:540px;min-height:100vh;margin:auto;background:#fff;padding:20px 18px 34px}.brand{font-size:19px;font-weight:750;color:#063a78;border-bottom:1px solid var(--line);padding-bottom:14px}.top{margin:17px 0 23px;color:var(--muted);font-size:14px;font-weight:700}.bar{height:9px;background:#dbe4ee;border-radius:8px}.bar span{display:block;height:100%;border-radius:8px;background:var(--blue)}.card{border:1px solid var(--line);border-radius:16px;padding:22px 18px}.icon{width:48px;height:48px;display:grid;place-items:center;background:var(--soft);border-radius:13px;font-size:28px}h1{font-size:27px;line-height:1.3;margin:14px 0 10px}p{margin:0 0 14px}label{display:block;font-weight:750;margin:15px 0 5px}input{width:100%;min-height:51px;padding:11px;border:2px solid #9dabbb;border-radius:10px;font:inherit}.code{text-align:center;font-size:23px;font-weight:750;letter-spacing:.18em}.primary{width:100%;min-height:54px;margin-top:20px;border:0;border-radius:10px;background:var(--blue);color:#fff;font:inherit;font-weight:750}.secondary,.link,.copy{border:0;background:#fff;color:var(--blue);font:inherit;font-weight:750;text-decoration:underline;padding:11px 1px}.copy{border:1px solid var(--blue);border-radius:8px;padding:5px 9px;text-decoration:none}.notice{margin-bottom:14px;padding:10px;border-radius:9px;background:#e7f7ee;color:#075d36;font-size:15px}.bad{background:#fff0ef;color:#8b1d16}.hint,.example{font-size:14px;color:var(--muted)}.secret{display:flex;gap:8px;padding:9px;border:1px solid var(--line);border-radius:10px;background:#f5f8fc}.secret code{overflow-wrap:anywhere;flex:1}.qr{margin:18px auto;text-align:center}.qr canvas{max-width:100%;height:auto;image-rendering:pixelated;border:8px solid #fff;outline:1px solid var(--line)}.codes{list-style:none;padding:0}.codes li{display:flex;justify-content:space-between;align-items:center;padding:8px;margin:7px 0;border:1px solid var(--line);border-radius:9px}.logs{margin-top:20px;border:1px solid var(--line);border-radius:10px;padding:10px;background:#f7fafc}.logs summary{font-weight:750}.logs pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 ui-monospace,monospace}[hidden]{display:none!important}@media(max-width:380px){.shell{padding:15px 13px}.card{padding:18px 14px}h1{font-size:24px}}
</style></head><body><main class="shell"><header class="brand">✦ Northstar Bank</header><section class="top"><span id="step">Getting started</span><span id="count" style="float:right">Step 1 of 6</span><div class="bar"><span id="progress" style="width:16.67%"></span></div></section><section id="app" aria-live="polite">Loading secure setup…</section><details class="logs"><summary>Logs</summary><pre id="logs">Demo messages appear here.</pre></details><footer class="hint">Take your time. There is no reading timer.</footer></main>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),step=document.querySelector("#step"),count=document.querySelector("#count"),progress=document.querySelector("#progress"),logs=document.querySelector("#logs");let csrf="",state={stage:"signed-in"},secret="",uri="",codes=[];const q=x=>document.querySelector(x);
function log(label,value){console.log("[MFA demo] "+label,value);logs.textContent+=(logs.textContent==="Demo messages appear here."?"":"\\n")+label+" "+(Array.isArray(value)?value.join(", "):value)}
async function req(path,method="GET",body){const o={method,credentials:"same-origin",headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(body||{})}const r=await fetch(path,o),d=await r.json().catch(()=>({}));if(!r.ok||!d.ok)throw Error(d.error||"Please try again.");if(d.csrf)csrf=d.csrf;return d}
function note(t,b){const n=q("#notice");if(n){n.textContent=t;n.className="notice "+(b?"bad":"");n.hidden=false}}
function bind(id,event,fn){const e=q("#"+id);if(e)e.addEventListener(event,fn)}
function copy(value,label){navigator.clipboard?.writeText(value).then(()=>note(label+" copied."),()=>note("Select the text and copy it using your browser.",true))}
function head(){const m={signed-in:[1,"Sign in"],identity:[2,"Identity check"],setup:[3,"Authenticator setup"],otp:[4,"Confirm code"],recovery:[5,"Save recovery codes"],complete:[6,"Finished"]}[state.stage]||[1,"Sign in"];step.textContent=m[1];count.textContent="Step "+m[0]+" of 6";progress.style.width=(m[0]*100/6)+"%"}

/* QR Model 2 encoder: UTF-8 byte mode, Reed-Solomon ECC, masks, BCH format/version bits and version/block selection. */
function qrCanvas(payload){
 const data=new TextEncoder().encode(payload),caps=[19,34,55,80,108,136,156,194,232,274],eccs=[7,10,15,20,26,18,20,24,30,18],blocks=[1,1,1,1,1,2,2,2,2,4],align=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50]];
 let v=1;while(v<=10&&data.length+(v<10?2:3)>caps[v-1])v++;if(v>10)throw Error("Setup link is too long.");
 const n=17+4*v,dc=caps[v-1],ec=eccs[v-1],nb=blocks[v-1],bits=[0,1,0,0];const add=(x,l)=>{for(let i=l-1;i>=0;i--)bits.push(x>>>i&1)};add(data.length,v<10?8:16);for(const x of data)add(x,8);while(bits.length%8)bits.push(0);
 const raw=[];for(let i=0;i<bits.length;i+=8)raw.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));for(let k=0;raw.length<dc;k++)raw.push(k%2?17:236);
 const ex=[],lg=[];let z=1;for(let i=0;i<255;i++){ex[i]=z;lg[z]=i;z<<=1;if(z&256)z^=285}for(let i=255;i<512;i++)ex[i]=ex[i-255];const mul=(a,b)=>a&&b?ex[lg[a]+lg[b]]:0;
 let gen=[1];for(let i=0;i<ec;i++){const g=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){g[j]^=gen[j];g[j+1]^=mul(gen[j],ex[i])}gen=g}
 const rem=a=>{const r=Array(ec).fill(0);for(const x of a){const f=x^r.shift();r.push(0);for(let j=0;j<ec;j++)r[j]^=mul(gen[j+1],f)}return r};
 const short=Math.floor(dc/nb),extra=dc%nb,db=[],eb=[];let p=0;for(let i=0;i<nb;i++){db.push(raw.slice(p,p+short+(i>=nb-extra?1:0)));p+=db[i].length;eb.push(rem(db[i]))}const cw=[];for(let i=0;i<short+1;i++)for(const b of db)if(i<b.length)cw.push(b[i]);for(let i=0;i<ec;i++)for(const b of eb)cw.push(b[i]);const stream=[];for(const x of cw)addBits(x,8);function addBits(x,l){for(let i=l-1;i>=0;i--)stream.push(x>>>i&1)}
 const bch=(x,poly)=>{let d=x;while(Math.floor(Math.log2(d))>=Math.floor(Math.log2(poly)))d^=poly<<(Math.floor(Math.log2(d))-Math.floor(Math.log2(poly)));return d};
 function matrix(mask){
  const a=Array.from({length:n},()=>Array(n).fill(false)),fixed=Array.from({length:n},()=>Array(n).fill(false));const put=(r,c,x)=>{if(r>=0&&c>=0&&r<n&&c<n){a[r][c]=!!x;fixed[r][c]=true}};
  const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)put(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4)))};
  finder(0,0);finder(0,n-7);finder(n-7,0);for(const r of align[v-1])for(const c of align[v-1])if(!fixed[r][c])for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)put(r+y,c+x,Math.max(Math.abs(y),Math.abs(x))!==1);
  for(let i=8;i<n-8;i++){put(6,i,i%2===0);put(i,6,i%2===0)}put(n-8,8,true);
  const f=((1<<3|mask)<<10|bch((1<<3|mask)<<10,0x537))^0x5412;for(let i=0;i<6;i++)put(i,8,f>>>i&1);put(7,8,f>>>6&1);put(8,8,f>>>7&1);put(8,7,f>>>8&1);for(let i=9;i<15;i++)put(8,14-i,f>>>i&1);for(let i=0;i<8;i++)put(8,n-1-i,f>>>i&1);for(let i=8;i<15;i++)put(n-15+i,8,f>>>i&1);
  if(v>=7){const x=v<<12|bch(v<<12,0x1f25);for(let i=0;i<18;i++){put(Math.floor(i/3),n-11+i%3,x>>>i&1);put(n-11+i%3,Math.floor(i/3),x>>>i&1)}}
  const flip=(r,c)=>[(r+c)%2===0,r%2===0,c%3===0,(r+c)%3===0,(Math.floor(r/2)+Math.floor(c/3))%2===0,(r*c)%2+(r*c)%3===0,((r*c)%2+(r*c)%3)%2===0,((r+c)%2+(r*c)%3)%2===0][mask];let k=0,up=true;
  for(let c=n-1;c>0;c-=2){if(c===6)c--;for(let i=0;i<n;i++){const r=up?n-1-i:i;for(const col of [c,c-1])if(!fixed[r][col])a[r][col]=!!((stream[k++]||0)^flip(r,col))}up=!up}return a;
 }
 function penalty(a){let s=0;for(let r=0;r<n;r++)for(let c=0;c<n;c++){let run=1;while(c+run<n&&a[r][c]===a[r][c+run])run++;if(run>=5)s+=run-2;run=1;while(r+run<n&&a[r][c]===a[r+run][c])run++;if(run>=5)s+=run-2}for(let r=0;r<n-1;r++)for(let c=0;c<n-1;c++)if(a[r][c]===a[r+1][c]&&a[r][c]===a[r][c+1]&&a[r][c]===a[r+1][c+1])s+=3;for(let r=0;r<n;r++)for(let c=0;c<n-6;c++)if([1,0,1,1,1,0,1].every((x,i)=>a[r][c+i]===!!x)&&(c>=4&&[0,0,0,0].every((x,i)=>a[r][c-4+i]===!!x)||c+11<=n&&[0,0,0,0].every((x,i)=>a[r][c+7+i]===!!x)))s+=40;let dark=0;for(const row of a)for(const x of row)dark+=x;s+=Math.floor(Math.abs(dark*20-n*n*10)/n/n)*10;return s}
 let best=matrix(0),score=penalty(best);for(let m=1;m<8;m++){const x=matrix(m),p=penalty(x);if(p<score){best=x;score=p}}const can=document.createElement("canvas");can.width=can.height=n*5;const ctx=can.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,can.width,can.height);ctx.fillStyle="#172033";for(let r=0;r<n;r++)for(let c=0;c<n;c++)if(best[r][c])ctx.fillRect(c*5,r*5,5,5);can.setAttribute("role","img");can.setAttribute("aria-label","QR code for the authenticator setup link");return can;
}
function render(message,bad){head();const n=message?'<div id="notice" class="notice '+(bad?"bad":"")+'">'+message+'</div>':'<div id="notice" hidden></div>';
if(state.stage==="signed-in"){app.innerHTML='<article class="card"><div class="icon">🔐</div><h1>Sign in to start MFA setup</h1><p>Use the demo account. We will guide you one step at a time.</p>'+n+'<form id="form"><label for="email">Email address</label><input id="email" type="email" autocomplete="username" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" placeholder="bank-demo"><button class="primary">Sign in</button></form></article>';bind("form","submit",async e=>{e.preventDefault();try{let d=await req("/api/sign-in","POST",{email:q("#email").value,password:q("#password").value});csrf=d.csrf;state.stage=d.stage;log("Identity verification code:",d.identityCode);render(d.message)}catch(x){note(x.message,true)}})}
else if(state.stage==="identity"){app.innerHTML='<article class="card"><div class="icon">🪪</div><h1>Check it is you</h1><p>Enter your phone number and the six-digit code.</p>'+n+'<form id="form"><label for="phone">Phone number</label><input id="phone" type="tel" autocomplete="tel" placeholder="+1 555 010 0200"><label for="code">Six-digit check code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><button class="primary">Check my identity</button></form><button id="resend" class="secondary">Send a new code</button></article>';bind("form","submit",async e=>{e.preventDefault();try{let d=await req("/api/identity/verify","POST",{phone:q("#phone").value,code:q("#code").value});state.stage=d.stage;render(d.message)}catch(x){note(x.message,true)}});bind("resend","click",async()=>{try{let d=await req("/api/identity/resend","POST",{});log("New identity verification code:",d.identityCode);note(d.message)}catch(x){note(x.message,true)}})}
else if(state.stage==="setup"){app.innerHTML='<article class="card"><div class="icon">📱</div><h1>Add your authenticator</h1><p>We will show a QR option and copyable manual details.</p>'+n+'<button id="go" class="primary">Show authenticator setup</button></article>';bind("go","click",async()=>{try{let d=await req("/api/authenticator/setup","POST",{});state.stage=d.stage;secret=d.secret;uri=d.provisioningUri;log("Authenticator code:",d.authenticatorOtp);render(d.message)}catch(x){note(x.message,true)}})}
else if(state.stage==="otp"){if(!secret){app.innerHTML='<article class="card"><div class="icon">📱</div><h1>Get fresh setup details</h1><p>Your details are not kept after a page refresh.</p>'+n+'<button id="fresh" class="primary">Get fresh setup details</button></article>';bind("fresh","click",fresh)}else{app.innerHTML='<article class="card"><div class="icon">▦</div><h1>Scan or copy the details</h1><p>Scan this with an authenticator app. Or show and copy the manual secret.</p>'+n+'<div id="qr" class="qr"></div><button id="show" class="link">Show manual Base32 secret</button><div id="manual" hidden><label for="sv">Manual Base32 secret</label><div class="secret"><code id="sv"></code><button id="copy" class="copy" type="button">Copy</button></div><label for="uv">Authenticator setup link</label><div class="secret"><code id="uv"></code><button id="copyuri" class="copy" type="button">Copy</button></div></div><button id="fresh" class="secondary">Get fresh setup details</button><form id="form"><label for="code">Six-digit authenticator code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><button class="primary">Confirm authenticator</button></form></article>';q("#qr").append(qrCanvas(uri));q("#sv").textContent=secret;q("#uv").textContent=uri;bind("show","click",()=>{let m=q("#manual");m.hidden=!m.hidden;q("#show").textContent=m.hidden?"Show manual Base32 secret":"Hide manual Base32 secret"});bind("copy","click",()=>copy(secret,"Base32 secret"));bind("copyuri","click",()=>copy(uri,"Authenticator setup link"));bind("fresh","click",fresh);bind("form","submit",async e=>{e.preventDefault();try{let d=await req("/api/otp/verify","POST",{code:q("#code").value});state.stage=d.stage;codes=d.recoveryCodes;log("Recovery codes:",codes);render(d.message)}catch(x){note(x.message,true)}})}}
else if(state.stage==="recovery"){const list=codes.map((c,i)=>'<li><code>'+c+'</code><button class="copy" type="button" data-i="'+i+'">Copy</button></li>').join("");app.innerHTML='<article class="card"><div class="icon">🗝️</div><h1>Save your recovery codes</h1><p>Keep these somewhere safe. Each code works once.</p>'+n+'<ul class="codes">'+list+'</ul><button id="all" class="secondary">Copy all codes</button><button id="new" class="secondary">Make new codes</button><button id="finish" class="primary">I have saved my codes</button></article>';document.querySelectorAll("[data-i]").forEach(b=>b.addEventListener("click",()=>copy(codes[+b.dataset.i],"Recovery code")));bind("all","click",()=>copy(codes.join("\\n"),"Recovery codes"));bind("new","click",async()=>{try{let d=await req("/api/recovery/generate","POST",{});codes=d.recoveryCodes;log("Replacement recovery codes:",codes);render(d.message)}catch(x){note(x.message,true)}});bind("finish","click",async()=>{try{let d=await req("/api/recovery/complete","POST",{});state.stage=d.stage;render(d.message)}catch(x){note(x.message,true)}})}
else{app.innerHTML='<article class="card"><div class="icon">✓</div><h1>MFA is ready</h1><p>Your authenticator is connected and recovery codes have been created.</p>'+n+'<details><summary>Test a recovery code</summary><form id="form"><label for="rc">Recovery code</label><input id="rc" autocomplete="one-time-code" placeholder="NORTH-1234"><button class="secondary">Check this recovery code</button></form></details><button id="out" class="primary">Sign out safely</button></article>';bind("form","submit",async e=>{e.preventDefault();try{let d=await req("/api/recovery/verify","POST",{recoveryCode:q("#rc").value});note(d.message)}catch(x){note(x.message,true)}});bind("out","click",async()=>{try{let d=await req("/api/logout","POST",{});csrf="";state.stage="signed-in";secret=uri="";codes=[];render(d.message)}catch(x){note(x.message,true)}})}}
async function fresh(){try{let d=await req("/api/authenticator/refresh","POST",{});secret=d.secret;uri=d.provisioningUri;log("Fresh authenticator code:",d.authenticatorOtp);render(d.message)}catch(x){note(x.message,true)}}
(async()=>{try{let d=await req("/api/bootstrap");csrf=d.csrf;state.stage=d.authenticated?d.stage:"signed-in";if(d.authenticated){let x=await req("/api/state");state=x;csrf=x.csrf}render()}catch{app.textContent="We could not start secure setup. Please refresh the page."}})()})()</script></body></html>`;
}

const server = Bun.serve({
  hostname: "0.0.0.0", port: 3000,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (req.method === "OPTIONS") {
        const origin = req.headers.get("origin"); if (!origin || !ORIGINS.has(origin)) return fail("This request is not allowed.", 403);
        const h = headers(); h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token"); h.set("Vary", "Origin");
        return new Response(null, { status: 204, headers: h });
      }
      if (url.pathname === "/" && req.method === "GET") { const nonce = random(18); return new Response(page(nonce), { headers: headers(true, nonce) }); }
      if (url.pathname.startsWith("/api/")) return api(req, url.pathname);
      return fail("That page is not available.", 404);
    } catch { return fail("Something went wrong. Please try again.", 500); }
  }
});
console.log(`MFA demo HTTPS server running at https://localhost:${server.port}`);
