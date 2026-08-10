
import { timingSafeEqual } from "node:crypto";

/*
 MFA Enrolment System — requirements 1–5:
 Single Bun HTTPS server and mobile HTML/CSS/JS SPA. All MFA state is in memory.
*/

type Stage = "signed-in" | "identity" | "setup" | "otp" | "recovery" | "complete";
type Cipher = { iv: string; ciphertext: string };
type Recovery = { salt: string; hash: string; used: boolean; expiresAt: number };
type Session = {
  id: string; csrf: string; authenticated: boolean; email?: string; userId?: string;
  stage: Stage; createdAt: number; lastSeen: number;
  identityHash?: string; identityExpires?: number; identityUsed?: boolean; identityFails: number;
  encryptedOtpSecret?: Cipher; otpUsed?: boolean; otpFails: number;
  recoveryFails: number; lockedUntil?: number; recoveryCodes: Recovery[];
};

const sessions = new Map<string, Session>();
const enc = new TextEncoder();
const MASTER_KEY = crypto.getRandomValues(new Uint8Array(32));
const IDLE = 20 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 15 * 60_000;
const LOCK = 5 * 60_000, RECOVERY_LIFE = 365 * 24 * 60 * 60_000;
const IDENTITY_TEST_CODE = "246810";

const token = (n = 32) => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
const hash = async (s: string) => Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(s))).toString("base64url");
const same = (a: string, b: string) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};
const now = () => Date.now();

async function encrypt(value: string): Promise<Cipher> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", MASTER_KEY, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), ciphertext: Buffer.from(ciphertext).toString("base64url") };
}
async function decrypt(value: Cipher): Promise<string> {
  const key = await crypto.subtle.importKey("raw", MASTER_KEY, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") }, key, Buffer.from(value.ciphertext, "base64url")
  );
  return new TextDecoder().decode(plain);
}

/* Requirement 3: standards-compatible Base32 secret and TOTP. */
function base32Secret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let out = "", bits = 0, value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits ? out + alphabet[(value << (5 - bits)) & 31] : out;
}
function base32Decode(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0, bits = 0; const out: number[] = [];
  for (const c of input.replace(/=|\s/g, "").toUpperCase()) {
    const n = alphabet.indexOf(c); if (n < 0) throw new Error("Invalid authenticator secret");
    value = (value << 5) | n; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function totp(secret: string, step: number): Promise<string> {
  const counter = new Uint8Array(8);
  let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = digest[19] & 15;
  const value = ((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
/* Current period plus one before/after provides ordinary device clock skew tolerance. */
async function validTotp(secret: string, code: string): Promise<boolean> {
  const step = Math.floor(now() / 30_000);
  for (const offset of [-1, 0, 1]) if (same(await totp(secret, step + offset), code)) return true;
  return false;
}

function cookie(req: Request, key: string) {
  return (req.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(key + "="))?.slice(key.length + 1);
}
function sessionCookie(id: string) { return `mfa_session=${id}; Path=/; Max-Age=${ABSOLUTE / 1000}; HttpOnly; Secure; SameSite=Strict`; }
const clearCookie = () => "mfa_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";

function headers(nonce?: string) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'"
  });
  return h;
}
function reply(data: unknown, status = 200, extra?: Record<string, string>) {
  const h = headers(); for (const [k, v] of Object.entries(extra || {})) h.set(k, v);
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (message: string, status = 400) => reply({ ok: false, error: message }, status);
function trusted(req: Request) {
  const origin = req.headers.get("origin");
  return !origin || /^https:\/\/(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(origin);
}
function makeSession() {
  const s: Session = { id: token(), csrf: token(), authenticated: false, stage: "signed-in", createdAt: now(), lastSeen: now(), identityFails: 0, otpFails: 0, recoveryFails: 0, recoveryCodes: [] };
  sessions.set(s.id, s); return s;
}
function current(req: Request, auth = false): Session | null {
  const id = cookie(req, "mfa_session"), s = id && sessions.get(id);
  if (!s) return null;
  if (now() - s.lastSeen > IDLE || now() - s.createdAt > ABSOLUTE) { sessions.delete(s.id); return null; }
  if (auth && !s.authenticated) return null;
  s.lastSeen = now(); return s;
}
function owner(req: Request): Session | Response {
  return current(req, true) || fail("Your secure session has ended. Please sign in again.", 401);
}
function csrf(req: Request, s: Session) {
  const t = req.headers.get("x-csrf-token") || "";
  return trusted(req) && /^[A-Za-z0-9_-]{40,60}$/.test(t) && same(t, s.csrf);
}
async function body(req: Request): Promise<Record<string, unknown> | null> {
  if (Number(req.headers.get("content-length") || 0) > 4096) return null;
  try {
    const v = await req.json();
    if (!v || typeof v !== "object" || Array.isArray(v) || "userId" in v || "accountId" in v || "redirect" in v) return null;
    return v as Record<string, unknown>;
  } catch { return null; }
}
function field(b: Record<string, unknown> | null, name: string, max: number) {
  const v = b?.[name]; return typeof v === "string" && v.length <= max ? v.trim() : null;
}
const locked = (s: Session) => !!s.lockedUntil && s.lockedUntil > now();
function failed(s: Session, key: "identityFails" | "otpFails" | "recoveryFails") {
  if (++s[key] >= 5) { s[key] = 0; s.lockedUntil = now() + LOCK; }
}
function recovery(): string {
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", b = crypto.getRandomValues(new Uint8Array(8));
  const s = Array.from(b, x => a[x % a.length]).join(""); return s.slice(0, 4) + "-" + s.slice(4);
}
async function createRecovery(s: Session) {
  const codes = Array.from({ length: 6 }, recovery);
  s.recoveryCodes = await Promise.all(codes.map(async code => {
    const salt = token(16); return { salt, hash: await hash(salt + ":" + code), used: false, expiresAt: now() + RECOVERY_LIFE };
  }));
  return codes;
}
async function provision(s: Session) {
  const secret = base32Secret();
  s.encryptedOtpSecret = await encrypt(secret); s.otpUsed = false; s.otpFails = 0;
  const issuer = "Northstar Bank", label = issuer + ":" + (s.email || "marcus@example.com");
  const provisioningUri = `otpauth://totp/${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  /* Test OTP is deliberately returned only for the required browser mock log. */
  return { secret, provisioningUri, testOtp: await totp(secret, Math.floor(now() / 30_000)) };
}

async function api(req: Request, path: string): Promise<Response> {
  if (!trusted(req)) return fail("This request is not allowed.", 403);

  if (path === "/api/bootstrap" && req.method === "GET") {
    let s = current(req), set: string | undefined;
    if (!s) { s = makeSession(); set = sessionCookie(s.id); }
    return reply({ ok: true, csrf: s.csrf, authenticated: s.authenticated, stage: s.stage }, 200, set ? { "Set-Cookie": set } : undefined);
  }
  if (path === "/api/sign-in" && req.method === "POST") {
    const old = current(req); if (!old || !csrf(req, old)) return fail("Please refresh the page and try signing in again.", 403);
    const b = await body(req), email = field(b, "email", 120), password = field(b, "password", 200);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password) return fail("Enter an email like name@example.com and your password.");
    if (email.toLowerCase() !== "marcus@example.com" || password !== "bank-demo") return fail("We could not sign you in. Check your email and password, then try again.", 401);
    sessions.delete(old.id); const s = makeSession();
    s.authenticated = true; s.userId = "account-owner-marcus"; s.email = "marcus@example.com"; s.stage = "identity";
    s.identityHash = await hash(IDENTITY_TEST_CODE); s.identityExpires = now() + CODE_LIFE;
    return reply({ ok: true, csrf: s.csrf, stage: s.stage, testIdentityCode: IDENTITY_TEST_CODE, message: "We sent a six-digit check code." }, 200, { "Set-Cookie": sessionCookie(s.id) });
  }
  if (path === "/api/state" && req.method === "GET") {
    const s = owner(req); return s instanceof Response ? s : reply({ ok: true, stage: s.stage, email: s.email, csrf: s.csrf, locked: locked(s) });
  }
  if (path === "/api/identity/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "identity") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const b = await body(req), code = field(b, "code", 6), phone = field(b, "phone", 24);
    if (!code || !/^\d{6}$/.test(code) || !phone || !/^\+?[0-9 ()-]{7,24}$/.test(phone)) return fail("Enter a six-digit code like 246810 and a phone number like +1 555 010 0200.");
    if (s.identityUsed || !s.identityHash || !s.identityExpires || now() > s.identityExpires) return fail("That check code is no longer active. Choose send a new code and try again.");
    if (!same(await hash(code), s.identityHash)) { failed(s, "identityFails"); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match. Check the six digits and try again."); }
    s.identityUsed = true; s.stage = "setup"; return reply({ ok: true, stage: s.stage, message: "Identity check complete. Next, add your authenticator." });
  }
  if (path === "/api/identity/resend" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "identity") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    s.identityHash = await hash(IDENTITY_TEST_CODE); s.identityExpires = now() + CODE_LIFE; s.identityUsed = false;
    return reply({ ok: true, testIdentityCode: IDENTITY_TEST_CODE, message: "A new check code is ready. Your previous tries are still counted." });
  }
  if ((path === "/api/authenticator/setup" || path === "/api/authenticator/refresh") && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    const fresh = path.endsWith("refresh");
    if ((fresh && s.stage !== "otp") || (!fresh && s.stage !== "setup")) return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const d = await provision(s); s.stage = "otp";
    return reply({ ok: true, stage: s.stage, ...d, message: fresh ? "Fresh authenticator setup details are ready. The previous setup details no longer work." : "Authenticator details are ready. Add them, then enter its six-digit code." });
  }
  if (path === "/api/otp/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "otp") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const code = field(await body(req), "code", 6);
    if (!code || !/^\d{6}$/.test(code)) return fail("Enter six numbers, for example 123456.");
    if (s.otpUsed || !s.encryptedOtpSecret) return fail("Choose get fresh setup details and try again.");
    let ok = false; try { ok = await validTotp(await decrypt(s.encryptedOtpSecret), code); } catch { ok = false; }
    if (!ok) { failed(s, "otpFails"); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match. Check the six numbers in your authenticator and try again."); }
    s.otpUsed = true; s.stage = "recovery"; const codes = await createRecovery(s);
    return reply({ ok: true, stage: s.stage, recoveryCodes: codes, message: "Authenticator confirmed. Your recovery codes are ready." });
  }
  if (path === "/api/recovery/generate" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "recovery" && s.stage !== "complete") return fail("Please complete the earlier step first.", 409);
    return reply({ ok: true, recoveryCodes: await createRecovery(s), message: "New recovery codes are ready. The old ones no longer work." });
  }
  if (path === "/api/recovery/complete" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "recovery") return fail("Please complete the earlier step first.", 409);
    s.stage = "complete"; return reply({ ok: true, stage: s.stage, message: "MFA enrolment is complete." });
  }
  if (path === "/api/recovery/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const code = field(await body(req), "recoveryCode", 9)?.toUpperCase();
    if (!code || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(code)) return fail("Enter a recovery code like ABCD-EFGH.");
    let hit: Recovery | undefined;
    for (const r of s.recoveryCodes) if (!r.used && r.expiresAt > now() && same(await hash(r.salt + ":" + code), r.hash)) hit = r;
    if (!hit) { failed(s, "recoveryFails"); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That recovery code does not match an unused code. Check it and try again."); }
    hit.used = true; return reply({ ok: true, message: "That recovery code worked and is now used. Your other codes still work." });
  }
  if (path === "/api/logout" && req.method === "POST") {
    const s = current(req); if (!s || !csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    sessions.delete(s.id); return reply({ ok: true, message: "You have signed out." }, 200, { "Set-Cookie": clearCookie() });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank — MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172033;--muted:#536074;--blue:#0759b8;--line:#cad5e2;--soft:#eef6ff}*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:var(--ink);font:17px/1.65 Arial,Verdana,sans-serif;letter-spacing:.035em}button,input{font:inherit;letter-spacing:.035em}.shell{width:min(100%,540px);min-height:100vh;margin:auto;background:#fff;padding:20px 18px 36px}.brand{font-weight:bold;color:#063a78;border-bottom:1px solid var(--line);padding-bottom:15px;font-size:19px}.progress{margin:18px 0 24px}.progress div{display:flex;justify-content:space-between;color:var(--muted);font-size:14px;font-weight:bold}.bar{height:9px;background:#dce5ef;border-radius:9px;margin-top:7px}.bar span{display:block;height:100%;background:var(--blue);border-radius:9px}.card{border:1px solid var(--line);border-radius:16px;padding:23px 19px}.icon{font-size:28px;background:var(--soft);border-radius:13px;width:48px;height:48px;display:grid;place-items:center}h1{font-size:27px;line-height:1.25;margin:14px 0 10px}p{margin:0 0 15px}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;min-height:51px;border:2px solid #9eacbd;border-radius:10px;padding:12px}.code{font-size:23px;font-weight:bold;letter-spacing:.18em;text-align:center}.primary{width:100%;min-height:54px;margin-top:20px;border:0;border-radius:10px;background:var(--blue);color:#fff;font-weight:bold}.secondary,.copy{color:var(--blue);font-weight:bold;background:#fff;border:0;text-decoration:underline;padding:10px 1px}.copy{border:1px solid var(--blue);border-radius:8px;padding:6px 9px;text-decoration:none}.notice{padding:11px;border-radius:10px;margin-bottom:15px;font-size:15px;background:#e8f7ef;color:#075d36}.bad{background:#fff0ef;color:#8b1d16}.example{font-size:14px;color:var(--muted);margin:6px 0}.secret{display:flex;gap:8px;align-items:center;border:1px solid var(--line);background:#f5f8fc;border-radius:10px;padding:9px}.secret code{flex:1;overflow-wrap:anywhere;font-size:13px}.qr{text-align:center;margin:18px 0}canvas{width:220px;height:220px;image-rendering:pixelated;border:9px solid #fff;outline:1px solid var(--line)}.codes{list-style:none;padding:0}.codes li{display:flex;justify-content:space-between;align-items:center;border:1px solid var(--line);padding:8px;margin:7px 0;border-radius:9px}.logs{margin-top:22px;border-top:1px solid var(--line);padding-top:12px}.logbox{background:#101b2d;color:#dff1ff;border-radius:10px;padding:11px;min-height:70px;max-height:180px;overflow:auto;font:12px/1.5 monospace;letter-spacing:0;white-space:pre-wrap}.hint,details{font-size:14px;color:var(--muted)}[hidden]{display:none!important}@media(max-width:380px){.shell{padding:15px 13px}.card{padding:19px 15px}h1{font-size:24px}canvas{width:190px;height:190px}}
</style></head><body><main class="shell"><header class="brand">✦ Northstar Bank</header><section class="progress"><div><span id="pt">Getting started</span><span id="pc">Step 1 of 6</span></div><p class="bar"><span id="pb" style="width:16%"></span></p></section><section id="app" aria-live="polite">Loading secure setup…</section><section class="logs"><h2>Logs</h2><p class="hint">Mock delivery values appear here and in the browser console.</p><div id="logs" class="logbox">Ready.</div></section><footer class="hint">Take your time. There is no reading timer.</footer></main>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),logs=document.querySelector("#logs"),pt=document.querySelector("#pt"),pc=document.querySelector("#pc"),pb=document.querySelector("#pb");let csrf="",state={stage:"signed-in"},secret="",uri="",codes=[];
function log(x){console.log(x);logs.textContent+="\\\\n"+x;logs.scrollTop=logs.scrollHeight}
async function req(path,method="GET",body){let o={method,credentials:"same-origin",headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(body||{})}let r=await fetch(path,o),d=await r.json().catch(()=>({}));if(!r.ok||!d.ok)throw Error(d.error||"Please try again.");if(d.csrf)csrf=d.csrf;return d}
function notice(t,b){let n=document.querySelector("#notice");if(n){n.textContent=t;n.className="notice "+(b?"bad":"");n.hidden=false}}
function bind(id,event,fn){let e=document.querySelector("#"+id);if(e)e.addEventListener(event,fn)}
function copy(v,label){navigator.clipboard?.writeText(v).then(()=>notice(label+" copied."),()=>notice("Select the text and copy it using your browser.",true))}
function progress(s){let x={ "signed-in":[1,"Sign in"],identity:[2,"Identity check"],setup:[3,"Authenticator setup"],otp:[4,"Confirm code"],recovery:[5,"Save recovery codes"],complete:[6,"Finished"]}[s]||[1,"Sign in"];pt.textContent=x[1];pc.textContent="Step "+x[0]+" of 6";pb.style.width=(x[0]*100/6)+"%"}

/* Standards-compliant QR Code Model 2, Version 10-L, byte mode, mask 0.
   Version 10 byte character count is 16 bits. RS block layout is 68,68,69,69:
   the unequal blocks are encoded independently and then correctly interleaved. */
function qr(text){
 const c=document.querySelector("#qr");if(!c||!text)return;const N=57,DATA=274,EC=18,blens=[68,68,69,69],bytes=[...new TextEncoder().encode(text)];if(bytes.length>DATA-3)return;
 let bits=[];const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push(v>>>i&1)};put(4,4);put(bytes.length,16);bytes.forEach(x=>put(x,8));put(0,Math.min(4,DATA*8-bits.length));while(bits.length%8)bits.push(0);
 let data=[];for(let i=0;i<bits.length;i+=8){let v=0;for(let j=0;j<8;j++)v=v*2+bits[i+j];data.push(v)}for(let i=0;data.length<DATA;i++)data.push(i%2?0x11:0xec);
 const mul=(a,b)=>{let r=0;while(b){if(b&1)r^=a;a=(a<<1)^((a&128)?0x11d:0);b>>>=1}return r};let gen=[1],root=1;
 for(let i=0;i<EC;i++){gen.push(0);for(let j=gen.length-1;j>0;j--)gen[j]=gen[j-1]^mul(gen[j],root);gen[0]=mul(gen[0],root);root=mul(root,2)}
 const rs=b=>{let r=Array(EC).fill(0);for(const v of b){let f=v^r.shift();r.push(0);for(let i=0;i<EC;i++)r[i]^=mul(gen[i+1],f)}return r};
 let db=[],at=0;for(const n of blens){db.push(data.slice(at,at+n));at+=n}let eb=db.map(rs),words=[];
 for(let i=0;i<69;i++)for(const b of db)if(i<b.length)words.push(b[i]);for(let i=0;i<EC;i++)for(const b of eb)words.push(b[i]);let stream=[];words.forEach(v=>putStream(v));function putStream(v){for(let i=7;i>=0;i--)stream.push(v>>>i&1)}
 let m=Array.from({length:N},()=>Array(N).fill(null)),set=(x,y,v)=>{if(x>=0&&y>=0&&x<N&&y<N)m[y][x]=v};
 function finder(x,y){for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++)set(x+dx,y+dy,dx>=0&&dx<=6&&dy>=0&&dy<=6&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4)))}
 finder(0,0);finder(N-7,0);finder(0,N-7);for(let i=8;i<N-8;i++){if(m[6][i]===null)set(i,6,i%2===0);if(m[i][6]===null)set(6,i,i%2===0)}
 for(const y of [6,28,50])for(const x of [6,28,50]){if((x===6&&y===6)||(x===6&&y===50)||(x===50&&y===6))continue;for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(x+dx,y+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1)}
 const bch=(v,p)=>{let q=p;while((q>>>Math.floor(Math.log2(q)))&&(Math.floor(Math.log2(v))>=Math.floor(Math.log2(q))))v^=q<<(Math.floor(Math.log2(v))-Math.floor(Math.log2(q)));return v};
 let vb=(10<<12)|bch(10<<12,0x1f25);for(let i=0;i<18;i++){let z=!!(vb>>>i&1);set(N-11+i%3,Math.floor(i/3),z);set(Math.floor(i/3),N-11+i%3,z)}
 let fmt=((1<<3)|0);fmt=((fmt<<10)|bch(fmt<<10,0x537))^0x5412;for(let i=0;i<6;i++)set(8,i,!!(fmt>>>i&1));set(8,7,!!(fmt>>>6&1));set(8,8,!!(fmt>>>7&1));set(7,8,!!(fmt>>>8&1));for(let i=9;i<15;i++)set(14-i,8,!!(fmt>>>i&1));for(let i=0;i<8;i++)set(N-1-i,8,!!(fmt>>>i&1));for(let i=8;i<15;i++)set(8,N-15+i,!!(fmt>>>i&1));set(8,N-8,true);
 let k=0,up=true;for(let r=N-1;r>0;r-=2){if(r===6)r--;for(let z=0;z<N;z++){let y=up?N-1-z:z;for(let d=0;d<2;d++){let x=r-d;if(m[y][x]===null){let v=k<stream.length?stream[k++]:0;set(x,y,!!(v^(((x+y)&1)===0))}}}up=!up}
 let scale=5;c.width=c.height=N*scale;let ctx=c.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,c.width,c.height);ctx.fillStyle="#111";for(let y=0;y<N;y++)for(let x=0;x<N;x++)if(m[y][x])ctx.fillRect(x*scale,y*scale,scale,scale)
}
function render(msg,bad){progress(state.stage);let n=msg?'<div id="notice" class="notice '+(bad?"bad":"")+'">'+msg+'</div>':'<div id="notice" hidden></div>';
if(state.stage==="signed-in"){app.innerHTML='<article class="card"><div class="icon">🔐</div><h1>Sign in to start MFA setup</h1><p>Use the demo account. We will guide you one step at a time.</p>'+n+'<form id="f"><label>Email address</label><input id="email" type="email" autocomplete="username" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label>Password</label><input id="password" type="password" autocomplete="current-password" placeholder="bank-demo"><button class="primary">Sign in</button></form></article>';bind("f","submit",async e=>{e.preventDefault();try{let d=await req("/api/sign-in","POST",{email:email.value,password:password.value});csrf=d.csrf;state.stage=d.stage;log("Mock identity check code: "+d.testIdentityCode);render(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="identity"){app.innerHTML='<article class="card"><div class="icon">🪪</div><h1>Check it is you</h1><p>Enter your phone number and the six-digit code we sent.</p>'+n+'<form id="f"><label>Phone number</label><input id="phone" type="tel" autocomplete="tel" placeholder="+1 555 010 0200"><label>Six-digit check code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="246810"><button class="primary">Check my identity</button></form><button id="resend" class="secondary">Send a new code</button></article>';bind("f","submit",async e=>{e.preventDefault();try{let d=await req("/api/identity/verify","POST",{phone:phone.value,code:code.value});state.stage=d.stage;render(d.message)}catch(x){notice(x.message,true)}});bind("resend","click",async()=>{try{let d=await req("/api/identity/resend","POST",{});log("Mock identity check code: "+d.testIdentityCode);notice(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="setup"){app.innerHTML='<article class="card"><div class="icon">📱</div><h1>Add your authenticator</h1><p>Use an authenticator app. We will show a QR code and copyable setup details.</p>'+n+'<button id="go" class="primary">Show authenticator setup</button></article>';bind("go","click",async()=>{try{let d=await req("/api/authenticator/setup","POST",{});state.stage=d.stage;secret=d.secret;uri=d.provisioningUri;log("Mock authenticator OTP: "+d.testOtp);render(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="otp"){app.innerHTML='<article class="card"><div class="icon">▦</div><h1>Scan or copy the setup details</h1><p>Scan this code in your authenticator app. You can also copy the manual details.</p>'+n+'<div class="qr"><canvas id="qr" role="img" aria-label="Scannable authenticator QR code"></canvas></div><label>Manual Base32 secret</label><div class="secret"><code id="sv"></code><button id="cs" class="copy">Copy</button></div><label>Authenticator setup link</label><div class="secret"><code id="uv"></code><button id="cu" class="copy">Copy</button></div><button id="fresh" class="secondary">Get fresh setup details</button><form id="f"><label>Six-digit authenticator code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><button class="primary">Confirm authenticator</button></form></article>';sv.textContent=secret;uv.textContent=uri;qr(uri);bind("cs","click",()=>copy(secret,"Base32 secret"));bind("cu","click",()=>copy(uri,"Authenticator setup link"));bind("fresh","click",async()=>{try{let d=await req("/api/authenticator/refresh","POST",{});secret=d.secret;uri=d.provisioningUri;log("Mock authenticator OTP: "+d.testOtp);render(d.message)}catch(x){notice(x.message,true)}});bind("f","submit",async e=>{e.preventDefault();try{let d=await req("/api/otp/verify","POST",{code:code.value});state.stage=d.stage;codes=d.recoveryCodes;log("Mock recovery codes: "+codes.join(", "));render(d.message)}catch(x){notice(x.message,true)}})}
else if(state.stage==="recovery"){let list=codes.length?codes.map((x,i)=>'<li><code>'+x+'</code><button class="copy cp" data-i="'+i+'">Copy</button></li>').join(""):"<li>Codes are not shown after refresh.</li>";app.innerHTML='<article class="card"><div class="icon">🗝️</div><h1>Save your recovery codes</h1><p>Keep these codes somewhere safe. Each code works once.</p>'+n+'<ul class="codes">'+list+'</ul><button id="all" class="secondary">Copy all codes</button><button id="new" class="secondary">Make new codes</button><button id="finish" class="primary">I have saved my codes</button></article>';document.querySelectorAll(".cp").forEach(x=>x.addEventListener("click",()=>copy(codes[+x.dataset.i],"Recovery code")));bind("all","click",()=>copy(codes.join("\\n"),"Recovery codes"));bind("new","click",async()=>{try{let d=await req("/api/recovery/generate","POST",{});codes=d.recoveryCodes;log("Mock replacement recovery codes: "+codes.join(", "));render(d.message)}catch(x){notice(x.message,true)}});bind("finish","click",async()=>{try{let d=await req("/api/recovery/complete","POST",{});state.stage=d.stage;render(d.message)}catch(x){notice(x.message,true)}})}
else{app.innerHTML='<article class="card"><div class="icon">✓</div><h1>MFA is ready</h1><p>Your authenticator is connected and recovery codes have been created.</p>'+n+'<details><summary>Test a recovery code</summary><form id="f"><label>Recovery code</label><input id="rc" autocomplete="one-time-code" placeholder="ABCD-EFGH"><button class="secondary">Check this recovery code</button></form></details><button id="out" class="primary">Sign out safely</button></article>';bind("f","submit",async e=>{e.preventDefault();try{let d=await req("/api/recovery/verify","POST",{recoveryCode:rc.value});notice(d.message)}catch(x){notice(x.message,true)}});bind("out","click",async()=>{try{let d=await req("/api/logout","POST",{});csrf="";state.stage="signed-in";secret=uri="";codes=[];render(d.message)}catch(x){notice(x.message,true)}})}}
(async()=>{try{let d=await req("/api/bootstrap");csrf=d.csrf;state.stage=d.authenticated?d.stage:"signed-in";if(d.authenticated){let x=await req("/api/state");state=x;csrf=x.csrf}render()}catch{app.textContent="We could not start secure setup. Please refresh the page."}})()})()</script></body></html>`;
}

const server = Bun.serve({
  port: 3000, hostname: "0.0.0.0",
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") {
        if (!trusted(request)) return fail("This request is not allowed.", 403);
        const h = headers(); h.set("Access-Control-Allow-Origin", url.origin);
        h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
        return new Response(null, { status: 204, headers: h });
      }
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = token(18), h = headers(nonce); h.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: h });
      }
      if (url.pathname.startsWith("/api/")) return api(request, url.pathname);
      return fail("That page is not available.", 404);
    } catch { return fail("Something went wrong. Please try again.", 500); }
  }
});
console.log(`MFA demo HTTPS server running at https://localhost:${server.port}`);
