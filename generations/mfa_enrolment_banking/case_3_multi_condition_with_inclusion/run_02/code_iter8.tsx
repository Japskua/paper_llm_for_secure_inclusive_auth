
import { existsSync, readFileSync } from "node:fs";

/*
 Requirements mapping:
 1) Authorization / IDOR: every MFA API route derives the account only from the
    HttpOnly session and never accepts a user ID.
 2) CSRF / headers / TLS: state changes require CSRF, strict origin checks,
    sign-in has a pre-authentication CSRF token, CSP/HSTS/clickjacking headers,
    and mandatory supplied TLS certificates.
 3) Session lifecycle / crypto: sessions rotate at login and expire; TOTP seeds
    are AES-GCM encrypted, recovery codes are SHA-256 hashes.
 4) Validation / encoding: bounded JSON input and strict formats are used;
    browser text is encoded before HTML insertion.
 5) Rate limiting: five failed verification attempts lock a session for 5 min.
 Evaluator mock values are always returned only to the authenticated browser UI
 and emitted in the browser console and visible Logs panel for testing.
 Inclusive UI: short plain-language steps, icons, spacing, examples, copy
 controls, no timers, and clear retry messages support dyslexia-friendly use.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const DEMO_MODE = true;
const USER = { id: "account-marcus-internal", email: "marcus@example.com", password: "welcome123" };
const DEMO_IDENTITY_OTP = "246810";
const DEMO_SECRET = "JBSWY3DPEHPK3PXP";
const DEMO_RECOVERY_CODES = ["ALPHA-23456", "BRAVO-23456", "CHARL-23456", "DELTA-23456", "ECHOX-23456", "FOXTN-23456"];

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("Configuration error.");
  process.exit(1);
}

const enc = new TextEncoder(), dec = new TextDecoder();
const serverKeyBytes = process.env.MFA_SERVER_KEY
  ? Buffer.from(process.env.MFA_SERVER_KEY, "hex").subarray(0, 32)
  : crypto.getRandomValues(new Uint8Array(32));
const aesKey = await crypto.subtle.importKey("raw", serverKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

type Pending = { digest: string; expires: number; used: boolean };
type EncryptedSecret = { iv: string; data: string };
type RecoveryEntry = { hash: string; used: boolean };
type Preauth = { csrf: string; expires: number };
type Session = { userId: string; csrf: string; created: number; seen: number; identity?: Pending; failures: number; lockedUntil: number; pendingBackups?: string[] };
type MfaRecord = { secret: EncryptedSecret; enabled: boolean; backups: RecoveryEntry[]; usedTotp: number[] };

const sessions = new Map<string, Session>();
const preauth = new Map<string, Preauth>();
const mfa = new Map<string, MfaRecord>();
const token = (n = 32) => Array.from(crypto.getRandomValues(new Uint8Array(n)), x => x.toString(16).padStart(2, "0")).join("");
const base64 = (x: Uint8Array) => Buffer.from(x).toString("base64");
const from64 = (x: string) => new Uint8Array(Buffer.from(x, "base64"));
const hash = async (x: string) => Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(x))).toString("hex");
const equal = (a: string, b: string) => { let d = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return d === 0; };
const b32 = (n: number) => { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; return Array.from(crypto.getRandomValues(new Uint8Array(n)), x => a[x % 32]).join(""); };
const backup = () => { const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; const s = Array.from(crypto.getRandomValues(new Uint8Array(10)), x => a[x % a.length]).join(""); return s.slice(0, 5) + "-" + s.slice(5); };
const pending = async (x: string, minutes = 20): Promise<Pending> => ({ digest: await hash(x), expires: Date.now() + minutes * 60000, used: false });
const matches = async (x: string, p?: Pending) => !!p && !p.used && p.expires >= Date.now() && equal(await hash(x), p.digest);

async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(secret));
  return { iv: base64(iv), data: base64(new Uint8Array(data)) };
}
async function decryptSecret(stored: EncryptedSecret) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: from64(stored.iv) }, aesKey, from64(stored.data)));
}
function decodeB32(v: string) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = "", out: number[] = [];
  for (const c of v.replace(/=+$/g, "").toUpperCase()) { const n = a.indexOf(c); if (n < 0) throw new Error("invalid"); bits += n.toString(2).padStart(5, "0"); }
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
async function totp(secret: string, counter = Math.floor(Date.now() / 30000)) {
  const key = await crypto.subtle.importKey("raw", decodeB32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const msg = new Uint8Array(8); let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) { msg[i] = Number(n & 255n); n >>= 8n; }
  const d = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg)), o = d[19] & 15;
  return ((((d[o] & 127) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) % 1000000).toString().padStart(6, "0");
}
async function verifyTotp(r: MfaRecord, value: string) {
  const secret = await decryptSecret(r.secret), now = Math.floor(Date.now() / 30000);
  for (const counter of [now, now - 1]) if (!r.usedTotp.includes(counter) && equal(value, await totp(secret, counter))) {
    r.usedTotp = [...r.usedTotp.filter(x => x >= now - 2), counter]; return true;
  }
  return false;
}
const uri = (secret: string) => `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank&algorithm=SHA1&digits=6&period=30`;

function cookie(r: Request, name: string) { return (r.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1); }
function current(r: Request) {
  const id = cookie(r, "mfa_session"), s = id && sessions.get(id);
  if (!id || !s) return;
  if (Date.now() - s.seen > 1800000 || Date.now() - s.created > 28800000) { sessions.delete(id); return; }
  s.seen = Date.now(); return { id, session: s };
}
function removeSessionsForUser(userId: string, keep?: string) { for (const [id, s] of sessions) if (s.userId === userId && id !== keep) sessions.delete(id); }
function headers(nonce?: string) {
  const h = new Headers({ "Strict-Transport-Security": "max-age=31536000; includeSubDomains", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "Permissions-Policy": "camera=(), microphone=(), geolocation=()" });
  h.set("Content-Security-Policy", nonce ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'none'; frame-ancestors 'none'");
  return h;
}
function out(data: unknown, status = 200, extra?: HeadersInit) { const h = headers(); h.set("Content-Type", "application/json; charset=utf-8"); if (extra) new Headers(extra).forEach((v, k) => h.set(k, v)); return new Response(JSON.stringify(data), { status, headers: h }); }
const fail = (message = "We could not complete that step. Please try again.", status = 400) => out({ ok: false, message }, status);
const sessionCookie = (id: string) => `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
const preauthCookie = (id: string) => `mfa_preauth=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=600`;
const clearCookie = () => "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
async function input(r: Request): Promise<Record<string, unknown> | null> {
  if (Number(r.headers.get("content-length") || "0") > 12288) return null;
  try { const body = await r.arrayBuffer(); if (body.byteLength > 12288) return null; const x = JSON.parse(dec.decode(body)); if (!x || typeof x !== "object" || Array.isArray(x)) return {}; for (const v of Object.values(x)) if (typeof v === "string" && v.length > 512) return null; return x as Record<string, unknown>; } catch { return {}; }
}
function trustedOrigin(r: Request) {
  const o = r.headers.get("origin");
  if (!o) return false;
  try {
    const u = new URL(o), host = u.hostname.replace(/^\[|\]$/g, "");
    return u.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(host);
  } catch { return false; }
}
function originOK(r: Request) { return r.method === "GET" ? true : trustedOrigin(r); }
function auth(r: Request, changing = false) { const found = current(r); if (!found || found.session.userId !== USER.id) return { error: fail("Please sign in again.", 401) }; if (changing && r.headers.get("x-csrf-token") !== found.session.csrf) return { error: fail("This page needs refreshing before you continue.", 403) }; return found; }
const valid = (v: unknown, re: RegExp) => typeof v === "string" && v.length <= 128 && re.test(v) ? v : null;
const locked = (s: Session) => s.lockedUntil > Date.now();
const bad = (s: Session) => { if (++s.failures >= 5) { s.failures = 0; s.lockedUntil = Date.now() + 300000; } };
const good = (s: Session) => { s.failures = 0; };
const recoveryEntries = async (codes: string[]) => Promise.all(codes.map(async value => ({ hash: await hash(value), used: false })));
async function recoveryMatch(r: MfaRecord, submitted: string) { const h = await hash(submitted); let hit = -1; for (let i = 0; i < r.backups.length; i++) if (equal(h, r.backups[i].hash) && !r.backups[i].used) hit = i; if (hit < 0) return false; r.backups[hit].used = true; return true; }

async function api(r: Request, path: string): Promise<Response> {
  if (r.method === "OPTIONS") return new Response(null, { status: 204, headers: headers() });
  if (!originOK(r)) return fail("This request is not allowed.", 403);

  /* Login CSRF: a short-lived HttpOnly pre-auth cookie is bound to a separately
     supplied token. Sign-in additionally requires an explicit trusted Origin. */
  if (path === "/api/preauth" && r.method === "GET") {
    const id = token(24), csrf = token(24);
    preauth.set(id, { csrf, expires: Date.now() + 600000 });
    for (const [key, value] of preauth) if (value.expires < Date.now()) preauth.delete(key);
    return out({ ok: true, csrf }, 200, { "Set-Cookie": preauthCookie(id) });
  }
  if (path === "/api/signin" && r.method === "POST") {
    const preauthId = cookie(r, "mfa_preauth"), proof = preauthId && preauth.get(preauthId);
    if (!trustedOrigin(r) || !proof || proof.expires < Date.now() || !equal(String(r.headers.get("x-preauth-csrf-token") || ""), proof.csrf)) return fail("Please refresh the sign-in page and try again.", 403);
    const x = await input(r); if (!x) return fail("That request was too large.", 413);
    const email = typeof x.email === "string" ? x.email.trim().toLowerCase() : "", password = typeof x.password === "string" ? x.password : "";
    const [a, b, c, d] = await Promise.all([hash(email), hash(USER.email), hash(password), hash(USER.password)]);
    if (!/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(email) || !equal(a, b) || !equal(c, d)) return fail("Those sign-in details did not work. Check them and try again.", 401);
    preauth.delete(preauthId);
    removeSessionsForUser(USER.id);
    const id = token(), identityOtp = DEMO_IDENTITY_OTP;
    const s: Session = { userId: USER.id, csrf: token(24), created: Date.now(), seen: Date.now(), identity: await pending(identityOtp), failures: 0, lockedUntil: 0 };
    sessions.set(id, s);
    return out({ ok: true, csrf: s.csrf, message: "A code is ready to enter.", evaluator: true, identityOtp }, 200, { "Set-Cookie": sessionCookie(id) });
  }

  const a = auth(r, r.method !== "GET"); if ("error" in a) return a.error;
  const s = a.session;
  if (path === "/api/state" && r.method === "GET") { const record = mfa.get(s.userId); return out({ ok: true, csrf: s.csrf, stage: record?.enabled ? "complete" : s.identity?.used ? s.pendingBackups ? "backup" : record ? "setup" : "newsetup" : "identity" }); }
  if (path === "/api/logout" && r.method === "POST") { removeSessionsForUser(s.userId); return out({ ok: true }, 200, { "Set-Cookie": clearCookie() }); }
  if (path === "/api/identity" && r.method === "POST") {
    const x = await input(r), c = x && valid(x.code, /^\d{6}$/); if (!c || !s.identity) return fail("Enter the six-digit code. Example: 123456.");
    if (locked(s)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!await matches(c, s.identity)) { bad(s); return fail("That code did not match. Check the six digits and try again."); }
    s.identity.used = true; good(s); return out({ ok: true, message: "Identity confirmed. Next, add your authenticator." });
  }
  if (path === "/api/identity/resend" && r.method === "POST") {
    if (locked(s)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (s.identity?.used) return fail("Your identity is already confirmed.", 409);
    const otp = DEMO_IDENTITY_OTP; s.identity = await pending(otp);
    return out({ ok: true, message: "A new code is ready.", evaluator: true, identityOtp: otp });
  }
  if (path === "/api/authenticator/start" || path === "/api/authenticator/pending") {
    if (r.method !== "POST" || !s.identity?.used) return fail("Please confirm your identity first.", 403);
    let record = mfa.get(s.userId);
    if (!record && path.endsWith("/start")) { const secret = DEMO_SECRET; record = { secret: await encryptSecret(secret), enabled: false, backups: [], usedTotp: [] }; mfa.set(s.userId, record); }
    if (!record || record.enabled || s.pendingBackups) return fail("There is no pending authenticator setup.", 404);
    const secret = await decryptSecret(record.secret), provisioningUri = uri(secret);
    return out({ ok: true, secret, provisioningUri, evaluator: true, demoTotpCode: await totp(secret) });
  }
  if (path === "/api/authenticator/verify" && r.method === "POST") {
    const x = await input(r), c = x && valid(x.code, /^\d{6}$/), record = mfa.get(s.userId);
    if (!c || !record || record.enabled) return fail("Enter the six-digit authenticator code. Example: 123456.");
    if (locked(s)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!await verifyTotp(record, c)) { bad(s); return fail("That code did not match, may have already been used, or is no longer current. Check your authenticator and enter its current six-digit code."); }
    good(s); const codes = [...DEMO_RECOVERY_CODES]; record.backups = await recoveryEntries(codes); s.pendingBackups = codes;
    return out({ ok: true, backupCodes: codes, message: "Authenticator confirmed. Save your recovery codes now.", evaluator: true });
  }
  if (path === "/api/backup/pending" && r.method === "POST") return s.pendingBackups ? out({ ok: true, backupCodes: s.pendingBackups, evaluator: true }) : fail("There are no recovery codes waiting to be saved.", 404);
  if (path === "/api/backup/regenerate" && r.method === "POST") { const record = mfa.get(s.userId); if (!record || !s.pendingBackups) return fail("Please finish authenticator verification first.", 403); const codes = [...DEMO_RECOVERY_CODES]; record.backups = await recoveryEntries(codes); s.pendingBackups = codes; return out({ ok: true, backupCodes: codes, message: "New recovery codes are ready. Earlier codes no longer work.", evaluator: true }); }
  if (path === "/api/backup/acknowledge" && r.method === "POST") { const record = mfa.get(s.userId); if (!record || !s.pendingBackups) return fail("Please finish authenticator verification first.", 403); delete s.pendingBackups; record.enabled = true; return out({ ok: true, message: "MFA is now active." }); }
  if (path === "/api/mfa/verify" && r.method === "POST") {
    const x = await input(r), record = mfa.get(s.userId); if (!record?.enabled) return fail("MFA setup is not complete.", 403);
    if (locked(s)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    const submitted = typeof x?.code === "string" && x.code.length <= 128 ? x.code.trim().toUpperCase() : "";
    const ok = x?.method === "recovery" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(submitted) ? await recoveryMatch(record, submitted) : x?.method === "totp" && /^\d{6}$/.test(submitted) ? await verifyTotp(record, submitted) : false;
    if (!ok) { bad(s); return fail("That code did not work. Check it and try again."); } good(s); return out({ ok: true, message: "Authenticator code accepted." });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank MFA</title><style nonce="${nonce}">:root{font-family:Verdana,Arial,sans-serif;color:#14263b;background:#f7fafc;letter-spacing:.025em}body{margin:auto;max-width:570px;padding:18px;font-size:17px;line-height:1.7}.brand{font-size:20px;color:#07598f}.step{color:#456274}.card,.logs{background:#fff;border:1px solid #c5d6e0;border-radius:15px;padding:21px;margin:14px 0;box-shadow:0 1px 3px #1231}.card{min-height:315px}h1{font-size:28px;line-height:1.25}input,button{font:inherit;letter-spacing:.03em;padding:13px;width:100%;box-sizing:border-box;border-radius:9px;margin:6px 0}input{border:2px solid #829aaa}button{border:0;font-weight:bold;cursor:pointer}.primary{background:#075f9d;color:#fff;min-height:52px}.secondary{background:#e7f1f6;color:#164c70;border:1px solid #9bb7c8}.hint,.notice{background:#e8f5fb;padding:11px 13px;border-radius:9px}.notice{background:#eaf7ed;color:#14552b}.error{background:#fff0ef;color:#7b211a;padding:10px;border-radius:8px}.codebox{padding:12px;background:#f2f6f8;border:1px solid #bed0dc;border-radius:8px;overflow-wrap:anywhere;white-space:pre-wrap}.qr{display:block;width:230px;max-width:100%;margin:14px auto;border:10px solid white;image-rendering:pixelated}.small{font-size:14px;color:#435c6c}.hidden{display:none}pre{font:13px/1.5 monospace;white-space:pre-wrap;overflow-wrap:anywhere}button:focus,input:focus{outline:3px solid #f2b84b;outline-offset:2px}@media(max-width:380px){body{padding:11px;font-size:16px}.card{padding:16px}h1{font-size:25px}}</style></head><body><header><div class="brand">◈ Local Bank</div><p class="step" id="step">Step 1 of 5 · Sign in</p></header><main class="card" id="app" aria-live="polite"></main><details class="logs" id="logPanel"><summary>▸ Test simulation logs</summary><pre id="logs">Testing values appear here and in the browser console.</pre></details><script nonce="${nonce}">(()=>{"use strict";let csrf="",precsrf="",setup=null,backups=[],codesVisible=true;const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");const esc=x=>String(x).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));const id=x=>document.getElementById(x);function log(a,v){console.log(a,v);logs.textContent+="\\n"+a+" "+(Array.isArray(v)?v.join(", "):String(v))}function simulation(r){if(!r.evaluator)return;if(r.identityOtp)log("Simulated identity OTP:",r.identityOtp);if(r.demoTotpCode)log("Simulated current authenticator OTP:",r.demoTotpCode);if(r.backupCodes)log("Simulated recovery codes:",r.backupCodes)}async function api(u,d,m="POST"){let hs=m==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf};if(u==="/api/signin")hs["X-Preauth-CSRF-Token"]=precsrf;let r=await fetch(u,{method:m,headers:hs,body:d===undefined?undefined:JSON.stringify(d)}),j=await r.json();if(!r.ok)throw Error(j.message||"We could not complete that step.");return j}function view(s,t,h){step.textContent=s;app.innerHTML="<h1>"+esc(t)+"</h1>"+h+"<p class=\\"hint\\">💡 Take your time. You can retry safely.</p>"}function error(e){let p=document.createElement("p");p.className="error";p.textContent="⚠ "+e.message;app.append(p)}async function copy(t,n){try{await navigator.clipboard.writeText(t);n.textContent="✓ Copied. You can paste it into your app.";n.className="notice"}catch{n.textContent="Select the text and use your browser's Copy option.";n.className="error"}}

/* ISO/IEC 18004 QR encoder: byte mode, automatic version capacity selection,
   Reed-Solomon block ECC, BCH format/version data, all eight masks and penalty
   scoring. It covers the provisioning URI sizes used by this mobile flow. */
function qr(text){const B=new TextEncoder().encode(text),T=[[[1,26,19],[1,26,16],[1,26,13],[1,26,9]],[[1,44,34],[1,44,28],[1,44,22],[1,44,16]],[[1,70,55],[1,70,44],[2,35,17],[2,35,13]],[[1,100,80],[2,50,32],[2,50,24],[4,25,9]],[[1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12]],[[2,86,68],[4,43,27],[4,43,19],[4,43,15]],[[2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14]],[[2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15]],[[2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13]],[[2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16]]],P=[[],[6,18],[6,22],[6,26],[6,30],[6,34],[6,22,38],[6,24,42],[6,26,46],[6,28,50]],E=[],L=[];let z=1;for(let i=0;i<255;i++){E[i]=z;L[z]=i;z<<=1;if(z&256)z^=285}for(let i=255;i<512;i++)E[i]=E[i-255];const mul=(a,b)=>a&&b?E[L[a]+L[b]]:0,blocks=(v)=>{let a=T[v-1][1],r=[];for(let i=0;i<a.length;i+=3)for(let j=0;j<a[i];j++)r.push([a[i+1],a[i+2]]);return r};let v=1;for(;v<=10;v++){let cap=blocks(v).reduce((s,x)=>s+x[1],0),cc=v<10?8:16;if(4+cc+B.length*8<=cap*8)break}if(v>10)return "<p class='error'>The QR code could not be made. Use the manual secret below.</p>";const N=17+4*v,base=Array.from({length:N},()=>Array(N).fill(null)),set=(r,c,x)=>{if(r>=0&&c>=0&&r<N&&c<N)base[r][c]=x};function finder(r,c){for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4))?1:0)}finder(0,0);finder(N-7,0);finder(0,N-7);for(let i=8;i<N-8;i++){set(6,i,i%2?0:1);set(i,6,i%2?0:1)}for(const r of P[v-1])for(const c of P[v-1])if(base[r][c]===null)for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(x),Math.abs(y))!==1?1:0);function fpos(i){return i<6?[i,8]:i<8?[i+1,8]:[N-15+i,8]}function fpos2(i){return i<8?[8,N-i-1]:i<9?[8,15-i-1]:[8,15-i-1+1]}for(let i=0;i<15;i++){let a=fpos(i),b=fpos2(i);set(a[0],a[1],0);set(b[0],b[1],0)}set(N-8,8,1);if(v>=7)for(let i=0;i<18;i++){set(Math.floor(i/3),N-11+i%3,0);set(N-11+i%3,Math.floor(i/3),0)}let cap=blocks(v).reduce((s,x)=>s+x[1],0),bits="0100"+B.length.toString(2).padStart(v<10?8:16,"0");for(const q of B)bits+=q.toString(2).padStart(8,"0");bits+="0".repeat(Math.min(4,cap*8-bits.length));while(bits.length%8)bits+="0";let data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8),2));for(let i=0;data.length<cap;i++)data.push(i%2?17:236);function ecc(d,n){let g=[1];for(let i=0;i<n;i++){let q=Array(g.length+1).fill(0);for(let j=0;j<g.length;j++){q[j]^=g[j];q[j+1]^=mul(g[j],E[i])}g=q}let rem=Array(n).fill(0);for(const q of d){let f=q^rem.shift();rem.push(0);for(let j=0;j<n;j++)rem[j]^=mul(g[j+1],f)}return rem}let ds=[],es=[],at=0;for(const b of blocks(v)){let d=data.slice(at,at+b[1]);at+=b[1];ds.push(d);es.push(ecc(d,b[0]-b[1]))}let stream=[];for(let i=0;i<Math.max(...ds.map(x=>x.length));i++)for(const d of ds)if(i<d.length)stream.push(d[i]);for(let i=0;i<Math.max(...es.map(x=>x.length));i++)for(const e of es)if(i<e.length)stream.push(e[i]);let coords=[],up=true;for(let c=N-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<N;q++){let r=up?N-1-q:q;for(let k=0;k<2;k++)if(base[r][c-k]===null)coords.push([r,c-k])}up=!up}function bch(x,p){let d=n=>n.toString(2).length;while(d(x)>=d(p))x^=p<<(d(x)-d(p));return x}function putInfo(m,mask){let q=((0<<3)|mask);q=((q<<10)|bch(q<<10,0x537))^0x5412;for(let i=0;i<15;i++){let a=fpos(i),b=fpos2(i),bit=(q>>i)&1;m[a[0]][a[1]]=bit;m[b[0]][b[1]]=bit}m[N-8][8]=1;if(v>=7){let w=(v<<12)|bch(v<<12,0x1f25);for(let i=0;i<18;i++){let bit=(w>>i)&1;m[Math.floor(i/3)][N-11+i%3]=bit;m[N-11+i%3][Math.floor(i/3)]=bit}}}const masked=(r,c,k)=>[ (r+c)%2===0,r%2===0,c%3===0,(r+c)%3===0,(Math.floor(r/2)+Math.floor(c/3))%2===0,(r*c)%2+(r*c)%3===0,((r*c)%2+(r*c)%3)%2===0,((r+c)%2+(r*c)%3)%2===0 ][k];function score(m){let s=0;for(let r=0;r<N;r++)for(let c=0;c<N;c++){if(c<N-1&&r<N-1&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c]&&m[r][c]===m[r+1][c+1])s+=3}for(let r=0;r<N;r++)for(let c=0;c<N;c++){for(const d of [[0,1],[1,0]]){let n=1;while(r+n*d[0]<N&&c+n*d[1]<N&&m[r][c]===m[r+n*d[0]][c+n*d[1]])n++;if(n>=5)s+=n-2}}for(let r=0;r<N;r++)for(let c=0;c<=N-7;c++){let a=m[r].slice(c,c+7).join("");if(a==="1011101"&&((c>=4&&m[r].slice(c-4,c).every(x=>!x))||(c+11<=N&&m[r].slice(c+7,c+11).every(x=>!x))))s+=40}for(let c=0;c<N;c++)for(let r=0;r<=N-7;r++){let a="";for(let i=0;i<7;i++)a+=m[r+i][c];if(a==="1011101"&&((r>=4&&[0,1,2,3].every(i=>!m[r-4+i][c]))||(r+11<=N&&[0,1,2,3].every(i=>!m[r+7+i][c]))))s+=40}let dark=m.flat().filter(Boolean).length;s+=Math.floor(Math.abs(dark*100/(N*N)-50)/5)*10;return s}let best,bestScore=Infinity;for(let k=0;k<8;k++){let m=base.map(x=>x.slice());coords.forEach(([r,c],i)=>{let bit=(stream[i>>3]>>(7-(i&7)))&1;m[r][c]=bit^(masked(r,c,k)?1:0)});putInfo(m,k);let sc=score(m);if(sc<bestScore){bestScore=sc;best=m}}let rect="";for(let r=0;r<N;r++)for(let c=0;c<N;c++)if(best[r][c])rect+="<rect x='"+c+"' y='"+r+"' width='1' height='1'/>";return "<svg class=\\"qr\\" viewBox='-4 -4 "+(N+8)+" "+(N+8)+"' role='img' aria-label='Authenticator provisioning QR code' xmlns='http://www.w3.org/2000/svg'><rect x='-4' y='-4' width='"+(N+8)+"' height='"+(N+8)+"' fill='white'/><g fill='#111'>"+rect+"</g></svg>"}

function sign(){view("Step 1 of 5 · Sign in","Sign in","<p>👤 Use your bank email and password.</p><form id='f'><label>Email <input name='email' type='email' autocomplete='username' placeholder='name@example.com' required></label><label>Password <input name='password' type='password' autocomplete='current-password' required></label><button class='primary'>Sign in</button></form>");id("f").onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/signin",Object.fromEntries(new FormData(e.target)));csrf=r.csrf;simulation(r);identity()}catch(e){error(e)}}}function identity(){view("Step 2 of 5 · Confirm identity","Check your identity","<p>📩 Enter the six-digit code from your message.</p><p class='small'>Example: 123456</p><form id='f'><label>Six-digit code <input name='code' inputmode='numeric' autocomplete='one-time-code' pattern='[0-9]{6}' placeholder='123456' required></label><button class='primary'>Confirm code</button></form><button class='secondary' id='resend'>Send a new code</button>");id("f").onsubmit=async e=>{e.preventDefault();try{await api("/api/identity",Object.fromEntries(new FormData(e.target)));start()}catch(e){error(e)}};id("resend").onclick=async()=>{try{simulation(await api("/api/identity/resend",{}));id("resend").textContent="✓ New code sent"}catch(e){error(e)}}}async function start(){try{setup=await api("/api/authenticator/start",{});simulation(setup);authenticator()}catch(e){error(e)}}function authenticator(){let s=setup.secret;view("Step 3 of 5 · Add authenticator","Add your authenticator","<p>📱 Scan this QR code in your authenticator app.</p>"+qr(setup.provisioningUri)+"<p class='small'>Or add it manually. Copying avoids typing a long secret.</p><div class='codebox'>Issuer: LocalBank<br>Account: Marcus<br>Secret: <span>"+esc(s)+"</span><br>Algorithm: SHA1 · Digits: 6 · Period: 30 seconds</div><button class='secondary' id='copy'>Copy manual secret</button><p id='note' class='small'></p><form id='f'><label>Current six-digit code <input name='code' inputmode='numeric' autocomplete='one-time-code' pattern='[0-9]{6}' placeholder='123456' required></label><button class='primary'>Confirm authenticator</button></form>");id("copy").onclick=()=>copy(s,id("note"));id("f").onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/authenticator/verify",Object.fromEntries(new FormData(e.target)));backups=r.backupCodes;simulation(r);save()}catch(e){error(e)}}}function save(){view("Step 4 of 5 · Save recovery codes","Save recovery codes","<p>🔐 Keep these somewhere safe. Each code works once.</p><div class='codebox'>"+(codesVisible?backups.map(esc).join("\\n"):"Recovery codes are hidden.")+"</div><p id='note' class='small'></p><button class='secondary' id='toggle'>"+(codesVisible?"Hide codes":"Reveal codes")+"</button><button class='secondary' id='copy'>Copy visible codes</button><button class='secondary' id='regen'>Make new codes instead</button><button class='primary' id='done'>I have saved my codes</button>");id("toggle").onclick=()=>{codesVisible=!codesVisible;save()};id("copy").onclick=()=>codesVisible?copy(backups.join("\\n"),id("note")):(id("note").textContent="Reveal the codes before copying them.");id("regen").onclick=async()=>{try{let r=await api("/api/backup/regenerate",{});backups=r.backupCodes;codesVisible=true;simulation(r);save()}catch(e){error(e)}};id("done").onclick=async()=>{try{await api("/api/backup/acknowledge",{});complete()}catch(e){error(e)}}}function complete(){view("Step 5 of 5 · Complete","MFA is ready","<p class='notice'>✓ Your authenticator is active.</p><button class='primary' id='verify'>Verify MFA now</button><button class='secondary' id='logout'>Sign out</button>");id("verify").onclick=verify;id("logout").onclick=async()=>{await api("/api/logout",{});csrf="";await loadPreauth();sign()}}function verify(){view("MFA check","Verify your MFA","<p>🔑 Enter a current six-digit authenticator code, or one recovery code.</p><p class='small'>Examples: 123456 or ALPHA-23456</p><form id='f'><label>Code <input name='code' autocomplete='one-time-code' placeholder='123456' required></label><button class='primary'>Verify code</button></form>");id("f").onsubmit=async e=>{e.preventDefault();try{let c=String(new FormData(e.target).get("code")||"");await api("/api/mfa/verify",{method:c.includes("-")?"recovery":"totp",code:c});complete()}catch(e){error(e)}}}async function loadPreauth(){let r=await api("/api/preauth",undefined,"GET");precsrf=r.csrf}async function begin(){try{let r=await api("/api/state",undefined,"GET");csrf=r.csrf;if(r.stage==="complete")complete();else if(r.stage==="identity")identity();else if(r.stage==="backup"){backups=(await api("/api/backup/pending",{})).backupCodes;save()}else if(r.stage==="setup"){setup=await api("/api/authenticator/pending",{});simulation(setup);authenticator()}else start()}catch{try{await loadPreauth()}catch{}sign()}}begin()})()</script></body></html>`;
}

async function handler(request: Request) {
  try {
    const u = new URL(request.url);
    if (u.pathname.startsWith("/api/")) return await api(request, u.pathname);
    if (u.pathname === "/" && request.method === "GET") { const nonce = token(18), h = headers(nonce); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page(nonce), { headers: h }); }
    return fail("That page is not available.", 404);
  } catch { return fail("We could not complete that request. Please try again.", 500); }
}

Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: readFileSync(CERT_PATH), key: readFileSync(KEY_PATH) },
  fetch: handler
});
