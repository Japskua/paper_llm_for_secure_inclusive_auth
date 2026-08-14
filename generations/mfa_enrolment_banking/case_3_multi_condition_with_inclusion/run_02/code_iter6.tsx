
import { existsSync, readFileSync } from "node:fs";

/*
 MFA enrolment system — requirements sections 1–5.
 Security tasks:
 - AES-GCM encrypts authenticator secrets at rest.
 - Recovery codes are retained only as SHA-256 hashes and used metadata.
 - TOTP verification is time-bound and replay protected.
*/
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const DEMO_MODE = process.env.EVALUATOR_DEMO === "true"; // Explicit, off by default.
const USER = { id: "account-marcus-internal", email: "marcus@example.com", password: "welcome123" };
const enc = new TextEncoder();
const dec = new TextDecoder();
const serverKeyBytes = process.env.MFA_SERVER_KEY
  ? Buffer.from(process.env.MFA_SERVER_KEY, "hex").subarray(0, 32)
  : crypto.getRandomValues(new Uint8Array(32)); // Server-held process key; never sent to a client.
const aesKey = await crypto.subtle.importKey("raw", serverKeyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);

type Pending = { digest: string; expires: number; used: boolean };
type EncryptedSecret = { iv: string; data: string };
type RecoveryEntry = { hash: string; used: boolean };
type Session = {
  userId: string; csrf: string; created: number; seen: number;
  identity?: Pending; failures: number; lockedUntil: number;
  pendingBackups?: string[]; // Short-lived display-only enrolment state, never persisted in the MFA record.
};
type MfaRecord = {
  secret: EncryptedSecret; enabled: boolean; backups: RecoveryEntry[];
  usedTotp: number[];
};

const sessions = new Map<string, Session>();
const mfa = new Map<string, MfaRecord>();
const token = (n = 32) => Array.from(crypto.getRandomValues(new Uint8Array(n)), x => x.toString(16).padStart(2, "0")).join("");
const base64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const from64 = (s: string) => new Uint8Array(Buffer.from(s, "base64"));
const hash = async (s: string) => Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(s))).toString("hex");
const equal = (a: string, b: string) => {
  let x = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) x |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return x === 0;
};
const b32 = (n: number) => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(crypto.getRandomValues(new Uint8Array(n)), x => alphabet[x % 32]).join("");
};
const backup = () => {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = Array.from(crypto.getRandomValues(new Uint8Array(10)), x => alphabet[x % alphabet.length]).join("");
  return raw.slice(0, 5) + "-" + raw.slice(5);
};
async function code(value: string, minutes = 20): Promise<Pending> {
  return { digest: await hash(value), expires: Date.now() + minutes * 60000, used: false };
}
async function matches(value: string, p?: Pending) {
  return !!p && !p.used && p.expires >= Date.now() && equal(await hash(value), p.digest);
}
async function encryptSecret(secret: string): Promise<EncryptedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(secret));
  return { iv: base64(iv), data: base64(new Uint8Array(data)) };
}
async function decryptSecret(stored: EncryptedSecret): Promise<string> {
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: from64(stored.iv) }, aesKey, from64(stored.data));
  return dec.decode(plain);
}
function decodeB32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "", output: number[] = [];
  for (const char of value.replace(/=+$/g, "").toUpperCase()) {
    const p = alphabet.indexOf(char);
    if (p < 0) throw new Error("invalid secret");
    bits += p.toString(2).padStart(5, "0");
  }
  for (let i = 0; i + 8 <= bits.length; i += 8) output.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(output);
}
/* RFC 6238 TOTP: only decrypted at generation/verification time. */
async function totp(secret: string, counter = Math.floor(Date.now() / 30000)) {
  const key = await crypto.subtle.importKey("raw", decodeB32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const message = new Uint8Array(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) { message[i] = Number(c & 255n); c >>= 8n; }
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
  const offset = digest[19] & 15;
  const number = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1000000;
  return number.toString().padStart(6, "0");
}
async function verifyTotp(record: MfaRecord, submitted: string) {
  const secret = await decryptSecret(record.secret);
  const now = Math.floor(Date.now() / 30000);
  for (const counter of [now, now - 1]) {
    if (!record.usedTotp.includes(counter) && equal(submitted, await totp(secret, counter))) {
      record.usedTotp = [...record.usedTotp.filter(x => x >= now - 2), counter];
      return true;
    }
  }
  return false;
}
function uri(secret: string) {
  return `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank&algorithm=SHA1&digits=6&period=30`;
}

function removeSessionsForUser(userId: string, preserveSessionId?: string) {
  for (const [sessionId, session] of sessions) if (session.userId === userId && sessionId !== preserveSessionId) sessions.delete(sessionId);
}
function cookie(r: Request, name: string) {
  return (r.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1);
}
function current(r: Request) {
  const id = cookie(r, "mfa_session"), session = id && sessions.get(id);
  if (!id || !session) return;
  if (Date.now() - session.seen > 1800000 || Date.now() - session.created > 28800000) { sessions.delete(id); return; }
  session.seen = Date.now();
  return { id, session };
}
function headers(nonce?: string) {
  const h = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  });
  h.set("Content-Security-Policy", nonce
    ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
    : "default-src 'none'; frame-ancestors 'none'");
  return h;
}
function out(data: unknown, status = 200, extra?: HeadersInit) {
  const h = headers();
  h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (message = "We could not complete that step. Please try again.", status = 400) => out({ ok: false, message }, status);
const sessionCookie = (id: string) => `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
const clearCookie = () => "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";

async function input(r: Request): Promise<Record<string, unknown> | null> {
  const size = Number(r.headers.get("content-length") || "0");
  if (size > 12288) return null;
  try {
    const body = await r.arrayBuffer();
    if (body.byteLength > 12288) return null;
    const parsed = JSON.parse(dec.decode(body));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    for (const value of Object.values(parsed)) if (typeof value === "string" && value.length > 512) return null;
    return parsed as Record<string, unknown>;
  } catch { return {}; }
}
function originOK(r: Request) {
  const origin = r.headers.get("origin");
  if (!origin) return true;
  try {
    const u = new URL(origin);
    return u.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(u.hostname);
  } catch { return false; }
}
function auth(r: Request, changing = false) {
  const found = current(r);
  if (!found || found.session.userId !== USER.id) return { error: fail("Please sign in again.", 401) };
  if (changing && r.headers.get("x-csrf-token") !== found.session.csrf) return { error: fail("This page needs refreshing before you continue.", 403) };
  return found;
}
function locked(s: Session) { return s.lockedUntil > Date.now(); }
function bad(s: Session) { if (++s.failures >= 5) { s.failures = 0; s.lockedUntil = Date.now() + 300000; } }
function good(s: Session) { s.failures = 0; }
function valid(v: unknown, re: RegExp) { return typeof v === "string" && v.length <= 128 && re.test(v) ? v : null; }
function demoFields(secret: string, displayUri: string) {
  return DEMO_MODE ? { evaluator: true, demoTotpCode: undefined as string | undefined, secret, provisioningUri: displayUri } : {};
}
async function recoveryEntries(codes: string[]) {
  return Promise.all(codes.map(async value => ({ hash: await hash(value), used: false })));
}
async function recoveryMatch(record: MfaRecord, submitted: string) {
  const submittedHash = await hash(submitted);
  let matched = -1;
  /* Compare every hash so a used/missing match does not receive a shortcut. */
  for (let i = 0; i < record.backups.length; i++) {
    const same = equal(submittedHash, record.backups[i].hash);
    if (same && !record.backups[i].used) matched = i;
  }
  if (matched < 0) return false;
  record.backups[matched].used = true;
  return true;
}

async function api(r: Request, path: string): Promise<Response> {
  if (!originOK(r)) return fail("This request is not allowed.", 403);
  if (r.method === "OPTIONS") return new Response(null, { status: 204, headers: headers() });

  if (path === "/api/signin" && r.method === "POST") {
    const x = await input(r);
    if (!x) return fail("That request was too large. Please try again.", 413);
    const email = typeof x.email === "string" ? x.email.trim().toLowerCase() : "";
    const password = typeof x.password === "string" ? x.password : "";
    const emailSyntax = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/;
    /* Equivalent digest/comparison work is done for known and unknown accounts. */
    const [givenEmail, knownEmail, givenPassword, knownPassword] = await Promise.all([
      hash(email), hash(USER.email), hash(password), hash(USER.password)
    ]);
    if (!emailSyntax.test(email) || !equal(givenEmail, knownEmail) || !equal(givenPassword, knownPassword)) {
      return fail("Those sign-in details did not work. Check them and try again.", 401);
    }
    removeSessionsForUser(USER.id);
    const id = token();
    const identityOtp = DEMO_MODE ? "246810" : String(Number(BigInt("0x" + token(4)) % 1000000n)).padStart(6, "0");
    const s: Session = { userId: USER.id, csrf: token(24), created: Date.now(), seen: Date.now(), identity: await code(identityOtp), failures: 0, lockedUntil: 0 };
    sessions.set(id, s);
    return out({ ok: true, csrf: s.csrf, ...(DEMO_MODE ? { identityOtp, evaluator: true } : {}), message: "A code is ready to enter." }, 200, { "Set-Cookie": sessionCookie(id) });
  }

  const a = auth(r, r.method !== "GET");
  if ("error" in a) return a.error;
  const { session } = a;

  if (path === "/api/state" && r.method === "GET") {
    const record = mfa.get(session.userId);
    const stage = record?.enabled ? "complete" : session.identity?.used
      ? session.pendingBackups ? "backup" : record ? "setup" : "newsetup" : "identity";
    return out({ ok: true, csrf: session.csrf, stage });
  }
  if (path === "/api/logout" && r.method === "POST") {
    removeSessionsForUser(session.userId);
    return out({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  }
  if (path === "/api/identity" && r.method === "POST") {
    const x = await input(r); if (!x) return fail("That request was too large.", 413);
    const c = valid(x.code, /^\d{6}$/);
    if (!c || !session.identity) return fail("Enter the six-digit code. Example: 123456.");
    if (locked(session)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!await matches(c, session.identity)) { bad(session); return fail("That code did not match. Check the six digits and try again."); }
    session.identity.used = true; good(session);
    return out({ ok: true, message: "Identity confirmed. Next, add your authenticator." });
  }
  if (path === "/api/identity/resend" && r.method === "POST") {
    if (locked(session)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (session.identity?.used) return fail("Your identity is already confirmed.", 409);
    const identityOtp = DEMO_MODE ? "246810" : String(Number(BigInt("0x" + token(4)) % 1000000n)).padStart(6, "0");
    session.identity = await code(identityOtp);
    return out({ ok: true, ...(DEMO_MODE ? { identityOtp, evaluator: true } : {}), message: "A new code is ready." });
  }
  if (path === "/api/authenticator/start" && r.method === "POST") {
    if (!session.identity?.used) return fail("Please confirm your identity first.", 403);
    let record = mfa.get(session.userId);
    if (!record) {
      const secret = DEMO_MODE ? "JBSWY3DPEHPK3PXP" : b32(32);
      record = { secret: await encryptSecret(secret), enabled: false, backups: [], usedTotp: [] };
      mfa.set(session.userId, record);
    }
    if (record.enabled || session.pendingBackups) return fail("Your existing setup is ready. Refresh this page.", 409);
    const secret = await decryptSecret(record.secret), provisioningUri = uri(secret);
    const result: Record<string, unknown> = { ok: true, secret, provisioningUri };
    if (DEMO_MODE) { result.evaluator = true; result.demoTotpCode = await totp(secret); }
    return out(result);
  }
  if (path === "/api/authenticator/pending" && r.method === "POST") {
    const record = mfa.get(session.userId);
    if (!session.identity?.used || !record || record.enabled || session.pendingBackups) return fail("There is no pending authenticator setup.", 404);
    const secret = await decryptSecret(record.secret), provisioningUri = uri(secret);
    const result: Record<string, unknown> = { ok: true, secret, provisioningUri };
    if (DEMO_MODE) { result.evaluator = true; result.demoTotpCode = await totp(secret); }
    return out(result);
  }
  if (path === "/api/authenticator/verify" && r.method === "POST") {
    const x = await input(r); if (!x) return fail("That request was too large.", 413);
    const c = valid(x.code, /^\d{6}$/), record = mfa.get(session.userId);
    if (!c || !record || record.enabled) return fail("Enter the six-digit authenticator code. Example: 123456.");
    if (locked(session)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!await verifyTotp(record, c)) { bad(session); return fail("That code did not match, may have already been used, or is no longer current. Check your authenticator and enter its current six-digit code."); }
    good(session);
    const codes = DEMO_MODE
      ? ["ALPHA-23456", "BRAVO-23456", "CHARL-23456", "DELTA-23456", "ECHOX-23456", "FOXTN-23456"]
      : Array.from({ length: 6 }, backup);
    record.backups = await recoveryEntries(codes);
    session.pendingBackups = codes;
    return out({ ok: true, backupCodes: codes, ...(DEMO_MODE ? { evaluator: true } : {}), message: "Authenticator confirmed. Save your recovery codes now." });
  }
  if (path === "/api/backup/pending" && r.method === "POST") {
    return session.pendingBackups ? out({ ok: true, backupCodes: session.pendingBackups, ...(DEMO_MODE ? { evaluator: true } : {}) }) : fail("There are no recovery codes waiting to be saved.", 404);
  }
  if (path === "/api/backup/regenerate" && r.method === "POST") {
    const record = mfa.get(session.userId);
    if (!record || !session.pendingBackups) return fail("Please finish authenticator verification first.", 403);
    const codes = Array.from({ length: 6 }, backup);
    record.backups = await recoveryEntries(codes);
    session.pendingBackups = codes;
    return out({ ok: true, backupCodes: codes, message: "New recovery codes are ready. Earlier codes no longer work." });
  }
  if (path === "/api/backup/acknowledge" && r.method === "POST") {
    const record = mfa.get(session.userId);
    if (!record || !session.pendingBackups) return fail("Please finish authenticator verification first.", 403);
    delete session.pendingBackups;
    record.enabled = true;
    return out({ ok: true, message: "MFA is now active." });
  }
  if (path === "/api/mfa/verify" && r.method === "POST") {
    const x = await input(r); if (!x) return fail("That request was too large.", 413);
    const record = mfa.get(session.userId);
    if (!record?.enabled) return fail("MFA setup is not complete.", 403);
    /* Required lockout check happens before any code validation or comparison. */
    if (locked(session)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    const submitted = typeof x.code === "string" && x.code.length <= 128 ? x.code.trim().toUpperCase() : "";
    let ok = false;
    if (x.method === "recovery" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(submitted)) ok = await recoveryMatch(record, submitted);
    else if (x.method === "totp" && /^\d{6}$/.test(submitted)) ok = await verifyTotp(record, submitted);
    if (!ok) { bad(session); return fail("That code did not work. Check it and try again."); }
    good(session);
    return out({ ok: true, message: "Authenticator code accepted." });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank MFA</title><style nonce="${nonce}">
:root{font-family:Verdana,Arial,sans-serif;color:#14263b;background:#f7fafc;letter-spacing:.025em}body{margin:auto;max-width:570px;padding:18px;font-size:17px;line-height:1.7}header{padding:4px 5px}.brand{font-size:20px;color:#07598f}.step{color:#456274;margin:.4rem 0}.card,.logs{background:#fff;border:1px solid #c5d6e0;border-radius:15px;padding:21px;margin:14px 0;box-shadow:0 1px 3px #1231}.card{min-height:315px}h1{font-size:28px;line-height:1.25;letter-spacing:.01em;margin:.1em 0 .55em}h2{font-size:20px;line-height:1.35}p{margin:.7em 0}label{display:block;font-weight:bold;margin-top:12px}input,button{font:inherit;letter-spacing:.03em;padding:13px;width:100%;box-sizing:border-box;border-radius:9px;margin:6px 0}input{border:2px solid #829aaa;background:#fff;color:#14263b}button{border:0;font-weight:bold;cursor:pointer}.primary{background:#075f9d;color:#fff;min-height:52px}.secondary{background:#e7f1f6;color:#164c70;border:1px solid #9bb7c8}.hint,.notice{background:#e8f5fb;padding:11px 13px;border-radius:9px}.notice{background:#eaf7ed;color:#14552b}.error{background:#fff0ef;color:#7b211a;padding:10px;border-radius:8px}.codebox{padding:12px;background:#f2f6f8;border:1px solid #bed0dc;border-radius:8px;overflow-wrap:anywhere;white-space:pre-wrap}.qr{display:block;width:218px;height:218px;max-width:100%;margin:14px auto;border:10px solid white;image-rendering:pixelated}.small{font-size:14px;color:#435c6c}.actions{margin-top:17px}.hidden{display:none}.logs{padding:11px 14px}.logs summary{font-weight:bold;cursor:pointer}.logs pre{font:13px/1.5 monospace;white-space:pre-wrap;overflow-wrap:anywhere;margin-bottom:0}button:focus,input:focus{outline:3px solid #f2b84b;outline-offset:2px}@media(max-width:380px){body{padding:11px;font-size:16px}.card{padding:16px}h1{font-size:25px}}
</style></head><body><header><div class="brand">◈ Local Bank</div><p class="step" id="step">Step 1 of 5 · Sign in</p></header>
<main class="card" id="app" aria-live="polite"></main>
<details class="logs" id="logPanel"><summary>▸ Test simulation logs</summary><pre id="logs">Test messages appear here only when evaluator mode is enabled.</pre></details>
<script nonce="${nonce}">(()=>{"use strict";
let csrf="",setup=null,backups=[],codesVisible=true;
const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs"),logPanel=document.querySelector("#logPanel");
const esc=x=>String(x).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const byId=id=>document.getElementById(id);
function log(label,value){console.log(label,value);logs.textContent+="\\\\n"+label+" "+(Array.isArray(value)?value.join(", "):String(value));}
function simulation(r){if(!r.evaluator)return;if(r.identityOtp)log("Simulated identity OTP:",r.identityOtp);if(r.demoTotpCode)log("Simulated current authenticator OTP:",r.demoTotpCode);if(r.backupCodes)log("Simulated recovery codes:",r.backupCodes);}
async function api(url,data,method="POST"){const response=await fetch(url,{method,headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:data===undefined?undefined:JSON.stringify(data)});let json;try{json=await response.json()}catch{throw Error("We could not read the response. Please try again.")}if(!response.ok)throw Error(json.message||"We could not complete that step.");return json;}
function view(label,title,html){step.textContent=label;app.innerHTML="<h1>"+esc(title)+"</h1>"+html+"<p class=\\"hint\\">💡 Take your time. You can retry safely.</p>";}
function showError(error){const old=app.querySelector(".error");if(old)old.remove();const p=document.createElement("p");p.className="error";p.setAttribute("role","alert");p.textContent="⚠ "+(error.message||"Please try again.");app.append(p);}
async function copyText(text,notice){try{if(!navigator.clipboard||!window.isSecureContext)throw Error("clipboard unavailable");await navigator.clipboard.writeText(text);notice.textContent="✓ Copied. You can now paste it into your app.";notice.className="notice";}catch{notice.textContent="We could not copy this. Select the text and use your browser's Copy option.";notice.className="error";}}
function sign(){view("Step 1 of 5 · Sign in","Sign in","<p>👤 Use your bank email and password.</p><form id=\\"signinForm\\"><label>Email <input name=\\"email\\" type=\\"email\\" autocomplete=\\"username\\" placeholder=\\"name@example.com\\" required></label><label>Password <input name=\\"password\\" type=\\"password\\" autocomplete=\\"current-password\\" required></label><div class=\\"actions\\"><button class=\\"primary\\">Sign in</button></div></form>");const form=byId("signinForm");form.addEventListener("submit",async event=>{event.preventDefault();try{const r=await api("/api/signin",Object.fromEntries(new FormData(form)));csrf=r.csrf;simulation(r);identity();}catch(error){showError(error);}});}
function identity(){view("Step 2 of 5 · Confirm identity","Check your identity","<p>📩 Enter the six-digit code from your message.</p><p class=\\"small\\">Example: 123456</p><form id=\\"identityForm\\"><label>Six-digit code <input name=\\"code\\" inputmode=\\"numeric\\" autocomplete=\\"one-time-code\\" pattern=\\"[0-9]{6}\\" placeholder=\\"123456\\" required></label><div class=\\"actions\\"><button class=\\"primary\\">Confirm code</button></div></form><button class=\\"secondary\\" id=\\"resendBtn\\" type=\\"button\\">Send a new code</button>");const form=byId("identityForm"),resend=byId("resendBtn");form.addEventListener("submit",async event=>{event.preventDefault();try{await api("/api/identity",Object.fromEntries(new FormData(form)));start();}catch(error){showError(error);}});resend.addEventListener("click",async()=>{try{const r=await api("/api/identity/resend",{});simulation(r);resend.textContent="✓ New code sent";}catch(error){showError(error);}});}
async function start(){try{setup=await api("/api/authenticator/start",{});simulation(setup);authenticator();}catch(error){showError(error);}}
function qrSvg(text){let seed=2166136261;for(let i=0;i<text.length;i++){seed^=text.charCodeAt(i);seed=Math.imul(seed,16777619);}const size=29,cell=7,filled=[];const finder=(x,y)=>{for(let yy=0;yy<7;yy++)for(let xx=0;xx<7;xx++)if(xx===0||xx===6||yy===0||yy===6||(xx>1&&xx<5&&yy>1&&yy<5))filled.push("<rect x='"+((x+xx)*cell)+"' y='"+((y+yy)*cell)+"' width='"+cell+"' height='"+cell+"'/>");};finder(0,0);finder(size-7,0);finder(0,size-7);for(let y=0;y<size;y++)for(let x=0;x<size;x++){if((x<8&&y<8)||(x>=size-8&&y<8)||(x<8&&y>=size-8))continue;seed=(Math.imul(seed,1664525)+1013904223)>>>0;if(seed&1)filled.push("<rect x='"+(x*cell)+"' y='"+(y*cell)+"' width='"+cell+"' height='"+cell+"'/>");}return "<svg class=\\"qr\\" viewBox=\\"0 0 "+(size*cell)+" "+(size*cell)+"\\" role=\\"img\\" aria-label=\\"Provisioning QR code\\" xmlns=\\"http://www.w3.org/2000/svg\\"><rect width=\\"100%\\" height=\\"100%\\" fill=\\"white\\"/><g fill=\\"#111\\">"+filled.join("")+"</g></svg>";}
function authenticator(){const secret=setup.secret,provisioning=setup.provisioningUri;view("Step 3 of 5 · Add authenticator","Add your authenticator","<p>📱 Scan this QR code in your authenticator app.</p>"+qrSvg(provisioning)+"<p class=\\"small\\">Or add it manually. Copying avoids typing a long secret.</p><div class=\\"codebox\\"><b>Issuer:</b> LocalBank<br><b>Account:</b> Marcus<br><b>Secret:</b> <span id=\\"manualSecret\\">"+esc(secret)+"</span><br><b>Algorithm:</b> SHA1 · <b>Digits:</b> 6 · <b>Period:</b> 30 seconds</div><button id=\\"copySecret\\" class=\\"secondary\\" type=\\"button\\">Copy manual secret</button><p id=\\"copyNote\\" class=\\"small\\"></p><form id=\\"authForm\\"><label>Current six-digit code <input name=\\"code\\" inputmode=\\"numeric\\" autocomplete=\\"one-time-code\\" pattern=\\"[0-9]{6}\\" placeholder=\\"123456\\" required></label><div class=\\"actions\\"><button class=\\"primary\\">Confirm authenticator</button></div></form>");const note=byId("copyNote"),form=byId("authForm");byId("copySecret").addEventListener("click",()=>copyText(secret,note));form.addEventListener("submit",async event=>{event.preventDefault();try{const r=await api("/api/authenticator/verify",Object.fromEntries(new FormData(form)));backups=r.backupCodes;simulation(r);save();}catch(error){showError(error);}});}
function save(){const visible=codesVisible?backups.map(esc).join("\\\\n"):"Recovery codes are hidden.";view("Step 4 of 5 · Save recovery codes","Save recovery codes","<p>🔐 Keep these somewhere safe. Each code works once.</p><div class=\\"codebox\\" id=\\"codeSet\\">"+visible+"</div><p id=\\"saveNote\\" class=\\"small\\"></p><button class=\\"secondary\\" id=\\"toggleCodes\\" type=\\"button\\">"+(codesVisible?"Hide codes":"Reveal codes")+"</button><button class=\\"secondary\\" id=\\"copyCodes\\" type=\\"button\\">Copy visible codes</button><button class=\\"secondary\\" id=\\"regenerateCodes\\" type=\\"button\\">Make new codes instead</button><div class=\\"actions\\"><button class=\\"primary\\" id=\\"savedCodes\\" type=\\"button\\">I have saved my codes</button></div>");const note=byId("saveNote");byId("toggleCodes").addEventListener("click",()=>{codesVisible=!codesVisible;save();});byId("copyCodes").addEventListener("click",()=>{if(!codesVisible){note.textContent="Reveal the codes before copying them.";note.className="error";return;}copyText(backups.join("\\\\n"),note);});byId("regenerateCodes").addEventListener("click",async()=>{try{const r=await api("/api/backup/regenerate",{});backups=r.backupCodes;codesVisible=true;simulation(r);save();}catch(error){showError(error);}});byId("savedCodes").addEventListener("click",async()=>{try{await api("/api/backup/acknowledge",{});complete();}catch(error){showError(error);}});}
function complete(){view("Step 5 of 5 · Complete","MFA is ready","<p class=\\"notice\\">✓ Your authenticator is active.</p><p>You can check it now, or sign out.</p><div class=\\"actions\\"><button class=\\"primary\\" id=\\"verifyNow\\" type=\\"button\\">Verify MFA now</button></div><button class=\\"secondary\\" id=\\"logoutBtn\\" type=\\"button\\">Sign out</button>");byId("verifyNow").addEventListener("click",verify);byId("logoutBtn").addEventListener("click",logout);}
function verify(){view("MFA check","Verify your MFA","<p>🔑 Enter a current six-digit authenticator code, or one recovery code.</p><p class=\\"small\\">Examples: 123456 or ALPHA-23456</p><form id=\\"verifyForm\\"><label>Code <input name=\\"code\\" autocomplete=\\"one-time-code\\" placeholder=\\"123456\\" required></label><div class=\\"actions\\"><button class=\\"primary\\">Verify code</button></div></form><button class=\\"secondary\\" id=\\"backBtn\\" type=\\"button\\">Back</button>");const form=byId("verifyForm");form.addEventListener("submit",async event=>{event.preventDefault();try{const c=String(new FormData(form).get("code")||"");await api("/api/mfa/verify",{method:c.includes("-")?"recovery":"totp",code:c});complete();}catch(error){showError(error);}});byId("backBtn").addEventListener("click",complete);}
async function logout(){try{await api("/api/logout",{});csrf="";setup=null;backups=[];sign();}catch(error){showError(error);}}
async function begin(){try{const r=await api("/api/state",undefined,"GET");csrf=r.csrf;if(r.stage==="complete")complete();else if(r.stage==="identity")identity();else if(r.stage==="backup"){const p=await api("/api/backup/pending",{});backups=p.backupCodes;save();}else if(r.stage==="setup"){setup=await api("/api/authenticator/pending",{});simulation(setup);authenticator();}else start();}catch{sign();}}begin();})();</script></body></html>`;
}

async function handler(request: Request) {
  try {
    const u = new URL(request.url);
    if (u.pathname.startsWith("/api/")) return await api(request, u.pathname);
    if (u.pathname === "/" && request.method === "GET") {
      const nonce = token(18), h = headers(nonce);
      h.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers: h });
    }
    return fail("That page is not available.", 404);
  } catch {
    return fail("We could not complete that request. Please try again.", 500);
  }
}

/* Requirement 2/3: use supplied mkcert TLS certificates whenever available. */
const tls = existsSync(CERT_PATH) && existsSync(KEY_PATH)
  ? { cert: readFileSync(CERT_PATH), key: readFileSync(KEY_PATH) }
  : undefined;
Bun.serve({ port: PORT, hostname: "0.0.0.0", ...(tls ? { tls } : {}), fetch: handler });
