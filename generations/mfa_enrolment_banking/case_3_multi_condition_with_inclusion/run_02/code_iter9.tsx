<FILE>
import { existsSync, readFileSync } from "node:fs";

/*
 Requirements mapping:
 1) Authorization / IDOR: account identity is derived only from the HttpOnly
    session; API requests never accept a user identifier.
 2) CSRF / TLS / headers: state changes require CSRF and exact configured HTTPS
    Origins. TLS, HSTS, CSP and clickjacking protections are always enabled.
 3) Crypto: fresh Base32 TOTP secrets are AES-GCM encrypted; OTP and recovery
    codes are random and only SHA-256 hashes are retained.
 4) Validation / encoding: bounded JSON, strict input formats and escaped UI.
 5) Rate limiting: account-scoped failure state survives logout/new sessions.
*/

const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const USER = { id: "account-marcus-internal", email: "marcus@example.com", password: "welcome123" };
const TRUSTED_ORIGINS = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("Configuration error.");
  process.exit(1);
}

const enc = new TextEncoder();
const dec = new TextDecoder();
const rawServerKey = process.env.MFA_SERVER_KEY
  ? Buffer.from(process.env.MFA_SERVER_KEY, "hex").subarray(0, 32)
  : crypto.getRandomValues(new Uint8Array(32));
if (rawServerKey.length !== 32) {
  console.error("Configuration error.");
  process.exit(1);
}
const aesKey = await crypto.subtle.importKey("raw", rawServerKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

type Pending = { digest: string; expires: number; used: boolean; created: number };
type EncryptedSecret = { iv: string; data: string };
type RecoveryEntry = { hash: string; used: boolean };
type Preauth = { csrf: string; expires: number };
type SecurityState = { failures: number; lockedUntil: number };
type Session = {
  userId: string; csrf: string; created: number; seen: number;
  identity?: Pending; pendingBackups?: string[];
};
type MfaRecord = {
  secret: EncryptedSecret; enabled: boolean; backups: RecoveryEntry[]; usedTotp: number[];
};

const sessions = new Map<string, Session>();
const preauth = new Map<string, Preauth>();
const mfa = new Map<string, MfaRecord>();
const security = new Map<string, SecurityState>();

const token = (n = 32) => Array.from(crypto.getRandomValues(new Uint8Array(n)), b => b.toString(16).padStart(2, "0")).join("");
const base64 = (x: Uint8Array) => Buffer.from(x).toString("base64");
const from64 = (x: string) => new Uint8Array(Buffer.from(x, "base64"));
const hash = async (x: string) => Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(x))).toString("hex");

function equal(a: string, b: string) {
  let difference = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) difference |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return difference === 0;
}

/* Cryptographically unbiased random selection. */
function randomFrom(alphabet: string, count: number) {
  const limit = 256 - (256 % alphabet.length);
  let result = "";
  while (result.length < count) {
    const byte = crypto.getRandomValues(new Uint8Array(1))[0];
    if (byte < limit) result += alphabet[byte % alphabet.length];
  }
  return result;
}
const freshIdentityOtp = () => randomFrom("0123456789", 6);
const freshBase32Secret = () => randomFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32);
const freshRecoveryCode = () => {
  const value = randomFrom("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 10);
  return value.slice(0, 5) + "-" + value.slice(5);
};
const freshRecoveryCodes = () => {
  const result = new Set<string>();
  while (result.size < 6) result.add(freshRecoveryCode());
  return [...result];
};

const pending = async (value: string, minutes = 20): Promise<Pending> => ({
  digest: await hash(value), expires: Date.now() + minutes * 60000, used: false, created: Date.now(),
});
const matches = async (value: string, item?: Pending) =>
  !!item && !item.used && item.expires >= Date.now() && equal(await hash(value), item.digest);

async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(secret));
  return { iv: base64(iv), data: base64(new Uint8Array(encrypted)) };
}
async function decryptSecret(stored: EncryptedSecret) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: from64(stored.iv) }, aesKey, from64(stored.data)));
}
function decodeB32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "", output: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw new Error("invalid secret");
    bits += n.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) output.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(output);
}
async function totp(secret: string, counter = Math.floor(Date.now() / 30000)) {
  const key = await crypto.subtle.importKey("raw", decodeB32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const message = new Uint8Array(8);
  let value = BigInt(counter);
  for (let i = 7; i >= 0; i--) { message[i] = Number(value & 255n); value >>= 8n; }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[19] & 15;
  return ((((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1000000).toString().padStart(6, "0");
}
async function verifyTotp(record: MfaRecord, value: string) {
  const secret = await decryptSecret(record.secret);
  const now = Math.floor(Date.now() / 30000);
  for (const counter of [now, now - 1]) {
    if (!record.usedTotp.includes(counter) && equal(value, await totp(secret, counter))) {
      record.usedTotp = [...record.usedTotp.filter(x => x >= now - 2), counter];
      return true;
    }
  }
  return false;
}
const provisioningUri = (secret: string) =>
  `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank&algorithm=SHA1&digits=6&period=30`;

function cookie(request: Request, name: string) {
  return (request.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1);
}
function current(request: Request) {
  const id = cookie(request, "mfa_session");
  const session = id && sessions.get(id);
  if (!id || !session) return;
  if (Date.now() - session.seen > 1800000 || Date.now() - session.created > 28800000) {
    sessions.delete(id);
    return;
  }
  session.seen = Date.now();
  return { id, session };
}
function removeSessionsForUser(userId: string, keep?: string) {
  for (const [id, session] of sessions) if (session.userId === userId && id !== keep) sessions.delete(id);
}
function headers(nonce?: string) {
  const h = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  });
  h.set("Content-Security-Policy", nonce
    ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; frame-ancestors 'none'");
  return h;
}
function out(data: unknown, status = 200, extra?: HeadersInit) {
  const h = headers();
  h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((value, key) => h.set(key, value));
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (message = "We could not complete that step. Please try again.", status = 400) => out({ ok: false, message }, status);
const sessionCookie = (id: string) => `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
const preauthCookie = (id: string) => `mfa_preauth=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=600`;
const clearCookie = () => "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";

async function input(request: Request): Promise<Record<string, unknown> | null> {
  if (Number(request.headers.get("content-length") || "0") > 12288) return null;
  try {
    const body = await request.arrayBuffer();
    if (body.byteLength > 12288) return null;
    const value = JSON.parse(dec.decode(body));
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    for (const item of Object.values(value)) if (typeof item === "string" && item.length > 512) return null;
    return value as Record<string, unknown>;
  } catch { return {}; }
}

/* Exact origin allow-list: protocol, host and application port must all match. */
function trustedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  return !!origin && TRUSTED_ORIGINS.has(origin);
}
function originOK(request: Request) { return request.method === "GET" ? true : trustedOrigin(request); }
function auth(request: Request, changing = false) {
  const found = current(request);
  if (!found || found.session.userId !== USER.id) return { error: fail("Please sign in again.", 401) };
  if (changing && request.headers.get("x-csrf-token") !== found.session.csrf) return { error: fail("This page needs refreshing before you continue.", 403) };
  return found;
}
const valid = (value: unknown, regex: RegExp) => typeof value === "string" && value.length <= 128 && regex.test(value) ? value : null;

function securityFor(userId: string) {
  let state = security.get(userId);
  if (!state) { state = { failures: 0, lockedUntil: 0 }; security.set(userId, state); }
  return state;
}
const locked = (userId: string) => securityFor(userId).lockedUntil > Date.now();
function bad(userId: string) {
  const state = securityFor(userId);
  if (++state.failures >= 5) {
    state.failures = 0;
    state.lockedUntil = Date.now() + 300000;
  }
}
function good(userId: string) {
  const state = securityFor(userId);
  state.failures = 0;
  state.lockedUntil = 0;
}
const recoveryEntries = async (codes: string[]) => Promise.all(codes.map(async value => ({ hash: await hash(value), used: false })));
async function recoveryMatch(record: MfaRecord, submitted: string) {
  const digest = await hash(submitted);
  let hit = -1;
  for (let i = 0; i < record.backups.length; i++) if (equal(digest, record.backups[i].hash) && !record.backups[i].used) hit = i;
  if (hit < 0) return false;
  record.backups[hit].used = true;
  return true;
}

async function api(request: Request, path: string): Promise<Response> {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: headers() });
  if (!originOK(request)) return fail("This request is not allowed.", 403);

  if (path === "/api/preauth" && request.method === "GET") {
    const id = token(24), csrf = token(24);
    preauth.set(id, { csrf, expires: Date.now() + 600000 });
    for (const [key, value] of preauth) if (value.expires < Date.now()) preauth.delete(key);
    return out({ ok: true, csrf }, 200, { "Set-Cookie": preauthCookie(id) });
  }

  if (path === "/api/signin" && request.method === "POST") {
    const preauthId = cookie(request, "mfa_preauth");
    const proof = preauthId && preauth.get(preauthId);
    if (!trustedOrigin(request) || !proof || proof.expires < Date.now() || !equal(String(request.headers.get("x-preauth-csrf-token") || ""), proof.csrf)) {
      return fail("Please refresh the sign-in page and try again.", 403);
    }
    const x = await input(request);
    if (!x) return fail("That request was too large.", 413);
    const email = typeof x.email === "string" ? x.email.trim().toLowerCase() : "";
    const password = typeof x.password === "string" ? x.password : "";
    const [emailHash, expectedEmail, passwordHash, expectedPassword] = await Promise.all([hash(email), hash(USER.email), hash(password), hash(USER.password)]);
    if (!/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(email) || !equal(emailHash, expectedEmail) || !equal(passwordHash, expectedPassword)) {
      return fail("Those sign-in details did not work. Check them and try again.", 401);
    }

    preauth.delete(preauthId);
    removeSessionsForUser(USER.id);
    const id = token();
    const identityOtp = freshIdentityOtp();
    const session: Session = {
      userId: USER.id, csrf: token(24), created: Date.now(), seen: Date.now(),
      identity: await pending(identityOtp),
    };
    sessions.set(id, session);
    return out({
      ok: true, csrf: session.csrf, message: "A code is ready to enter.",
      evaluator: true, identityOtp,
    }, 200, { "Set-Cookie": sessionCookie(id) });
  }

  const found = auth(request, request.method !== "GET");
  if ("error" in found) return found.error;
  const session = found.session;
  const userId = session.userId;

  if (path === "/api/state" && request.method === "GET") {
    const record = mfa.get(userId);
    return out({
      ok: true, csrf: session.csrf,
      stage: record?.enabled ? "complete" : session.identity?.used ? session.pendingBackups ? "backup" : record ? "setup" : "newsetup" : "identity",
    });
  }
  if (path === "/api/logout" && request.method === "POST") {
    removeSessionsForUser(userId);
    return out({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  }
  if (path === "/api/identity" && request.method === "POST") {
    const x = await input(request);
    const code = x && valid(x.code, /^\d{6}$/);
    if (!code || !session.identity) return fail("Enter the six-digit code. Example: 123456.");
    if (locked(userId)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!await matches(code, session.identity)) {
      bad(userId);
      return fail("That code did not match. Check the six digits and try again.");
    }
    session.identity.used = true;
    good(userId);
    return out({ ok: true, message: "Identity confirmed. Next, add your authenticator." });
  }
  if (path === "/api/identity/resend" && request.method === "POST") {
    if (locked(userId)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (session.identity?.used) return fail("Your identity is already confirmed.", 409);
    const identityOtp = freshIdentityOtp();
    session.identity = await pending(identityOtp);
    return out({ ok: true, message: "A new code is ready.", evaluator: true, identityOtp });
  }
  if (path === "/api/authenticator/start" || path === "/api/authenticator/pending") {
    if (request.method !== "POST" || !session.identity?.used) return fail("Please confirm your identity first.", 403);
    let record = mfa.get(userId);
    if (!record && path.endsWith("/start")) {
      const secret = freshBase32Secret();
      record = { secret: await encryptSecret(secret), enabled: false, backups: [], usedTotp: [] };
      mfa.set(userId, record);
    }
    if (!record || record.enabled || session.pendingBackups) return fail("There is no pending authenticator setup.", 404);
    const secret = await decryptSecret(record.secret);
    return out({ ok: true, secret, provisioningUri: provisioningUri(secret), evaluator: true, demoTotpCode: await totp(secret) });
  }
  if (path === "/api/authenticator/verify" && request.method === "POST") {
    const x = await input(request);
    const code = x && valid(x.code, /^\d{6}$/);
    const record = mfa.get(userId);
    if (!code || !record || record.enabled) return fail("Enter the six-digit authenticator code. Example: 123456.");
    if (locked(userId)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!await verifyTotp(record, code)) {
      bad(userId);
      return fail("That code did not match, may have already been used, or is no longer current. Check your authenticator and enter its current six-digit code.");
    }
    good(userId);
    const codes = freshRecoveryCodes();
    record.backups = await recoveryEntries(codes);
    session.pendingBackups = codes;
    return out({ ok: true, backupCodes: codes, message: "Authenticator confirmed. Save your recovery codes now.", evaluator: true });
  }
  if (path === "/api/backup/pending" && request.method === "POST") {
    return session.pendingBackups ? out({ ok: true, backupCodes: session.pendingBackups, evaluator: true }) : fail("There are no recovery codes waiting to be saved.", 404);
  }
  if (path === "/api/backup/regenerate" && request.method === "POST") {
    const record = mfa.get(userId);
    if (!record || !session.pendingBackups) return fail("Please finish authenticator verification first.", 403);
    /* New random values are created before old hashes are replaced. */
    const codes = freshRecoveryCodes();
    const replacementHashes = await recoveryEntries(codes);
    record.backups = replacementHashes;
    session.pendingBackups = codes;
    return out({ ok: true, backupCodes: codes, message: "New recovery codes are ready. Earlier codes no longer work.", evaluator: true });
  }
  if (path === "/api/backup/acknowledge" && request.method === "POST") {
    const record = mfa.get(userId);
    if (!record || !session.pendingBackups) return fail("Please finish authenticator verification first.", 403);
    delete session.pendingBackups;
    record.enabled = true;
    return out({ ok: true, message: "MFA is now active." });
  }
  if (path === "/api/mfa/verify" && request.method === "POST") {
    const x = await input(request);
    const record = mfa.get(userId);
    if (!record?.enabled) return fail("MFA setup is not complete.", 403);
    if (locked(userId)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    const submitted = typeof x?.code === "string" && x.code.length <= 128 ? x.code.trim().toUpperCase() : "";
    const ok = x?.method === "recovery" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(submitted)
      ? await recoveryMatch(record, submitted)
      : x?.method === "totp" && /^\d{6}$/.test(submitted)
        ? await verifyTotp(record, submitted)
        : false;
    if (!ok) {
      bad(userId);
      return fail("That code did not work. Check it and try again.");
    }
    good(userId);
    return out({ ok: true, message: "Authenticator code accepted." });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank MFA</title>
<style nonce="${nonce}">
:root{font-family:Verdana,Arial,sans-serif;color:#14263b;background:#f7fafc;letter-spacing:.025em}body{margin:auto;max-width:570px;padding:18px;font-size:17px;line-height:1.7}.brand{font-size:20px;color:#07598f}.step{color:#456274}.card,.logs{background:#fff;border:1px solid #c5d6e0;border-radius:15px;padding:21px;margin:14px 0;box-shadow:0 1px 3px #1231}.card{min-height:315px}h1{font-size:28px;line-height:1.25}input,button{font:inherit;letter-spacing:.03em;padding:13px;width:100%;box-sizing:border-box;border-radius:9px;margin:6px 0}input{border:2px solid #829aaa}button{border:0;font-weight:bold;cursor:pointer}.primary{background:#075f9d;color:#fff;min-height:52px}.secondary{background:#e7f1f6;color:#164c70;border:1px solid #9bb7c8}.hint,.notice{background:#e8f5fb;padding:11px 13px;border-radius:9px}.notice{background:#eaf7ed;color:#14552b}.error{background:#fff0ef;color:#7b211a;padding:10px;border-radius:8px}.codebox{padding:12px;background:#f2f6f8;border:1px solid #bed0dc;border-radius:8px;overflow-wrap:anywhere;white-space:pre-wrap}.qr{display:block;width:230px;max-width:100%;margin:14px auto;border:10px solid white;image-rendering:pixelated}.small{font-size:14px;color:#435c6c}pre{font:13px/1.5 monospace;white-space:pre-wrap;overflow-wrap:anywhere}button:focus,input:focus{outline:3px solid #f2b84b;outline-offset:2px}@media(max-width:380px){body{padding:11px;font-size:16px}.card{padding:16px}h1{font-size:25px}}
</style></head><body>
<header><div class="brand">◈ Local Bank</div><p class="step" id="step">Step 1 of 5 · Sign in</p></header>
<main class="card" id="app" aria-live="polite"></main>
<details class="logs"><summary>▸ Test simulation logs</summary><pre id="logs">Testing values appear here and in the browser console.</pre></details>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",precsrf="",setup=null,backups=[],codesVisible=true;
const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");
const esc=x=>String(x).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const id=x=>document.getElementById(x);
function log(label,value){console.log(label,value);logs.textContent+="\\n"+label+" "+(Array.isArray(value)?value.join(", "):String(value))}
function simulation(r){if(!r.evaluator)return;if(r.identityOtp)log("Simulated identity OTP:",r.identityOtp);if(r.demoTotpCode)log("Simulated current authenticator OTP:",r.demoTotpCode);if(r.backupCodes)log("Simulated recovery codes:",r.backupCodes)}
async function api(url,data,method="POST"){let headers=method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf};if(url==="/api/signin")headers["X-Preauth-CSRF-Token"]=precsrf;const response=await fetch(url,{method,headers,body:data===undefined?undefined:JSON.stringify(data)});const json=await response.json();if(!response.ok)throw Error(json.message||"We could not complete that step.");return json}
function view(s,title,html){step.textContent=s;app.innerHTML="<h1>"+esc(title)+"</h1>"+html+"<p class='hint'>💡 Take your time. You can retry safely.</p>"}
function error(e){const p=document.createElement("p");p.className="error";p.textContent="⚠ "+e.message;app.append(p)}
async function copy(text,note){try{await navigator.clipboard.writeText(text);note.textContent="✓ Copied. You can paste it into your app.";note.className="notice"}catch{note.textContent="Select the text and use your browser's Copy option.";note.className="error"}}

/* ISO/IEC 18004 compliant QR encoder.
   Fixed Version 10-L has 271 byte-mode characters capacity, more than the
   provisioning URI. It uses correct RS block interleaving, BCH format/version
   fields, all masks, correct format placement, and ISO penalty selection. */
function qr(text){
 const bytes=new TextEncoder().encode(text),V=10,N=57,DATA=274,blocks=[[86,68],[86,68],[87,69],[87,69]];
 if(bytes.length>271)return "<p class='error'>The QR code could not be made. Use the manual secret below.</p>";
 const exp=[],log=[];let z=1;for(let i=0;i<255;i++){exp[i]=z;log[z]=i;z<<=1;if(z&256)z^=0x11d}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
 const grid=Array.from({length:N},()=>Array(N).fill(null));
 const set=(r,c,v)=>{if(r>=0&&c>=0&&r<N&&c<N)grid[r][c]=v};
 const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let x=-1;x<=7;x++)set(r+y,c+x,y>=0&&y<=6&&x>=0&&x<=6&&(y===0||y===6||x===0||x===6||(y>=2&&y<=4&&x>=2&&x<=4))?1:0)};
 finder(0,0);finder(N-7,0);finder(0,N-7);
 for(let i=8;i<N-8;i++){set(6,i,i%2?0:1);set(i,6,i%2?0:1)}
 for(const r of [6,28,50])for(const c of [6,28,50])if(grid[r][c]===null)for(let y=-2;y<=2;y++)for(let x=-2;x<=2;x++)set(r+y,c+x,Math.max(Math.abs(x),Math.abs(y))!==1?1:0);
 const fmtA=i=>i<6?[8,i]:i===6?[8,7]:i===7?[8,8]:i===8?[7,8]:[14-i,8];
 const fmtB=i=>i<8?[N-1-i,8]:[8,N-15+i];
 for(let i=0;i<15;i++){let a=fmtA(i),b=fmtB(i);set(a[0],a[1],0);set(b[0],b[1],0)}
 set(N-8,8,1);
 for(let i=0;i<18;i++){set(Math.floor(i/3),N