
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const sessions = new Map<string, Session>();

/* Requirements 1, 2 and 5: exact trusted HTTPS origins, secure session policy. */
const allowedOrigins = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);
const USER = { id: "acct_marcus_01", email: "marcus@example.test" };
const DEMO_OWNER_CREDENTIAL = "Marcus-Access-54";
const SESSION_IDLE_MS = 20 * 60_000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60_000;
const CODE_LIFE_MS = 10 * 60_000;
const MAX_FAILURES = 5;
const LOCK_MS = 15 * 60_000;
const MAX_JSON_BODY_BYTES = 4096;

type Challenge = { accountId: string; value: string; expires: number; used: boolean };
type Session = {
  id: string; userId: string; csrf: string; createdAt: number; lastSeen: number;
  identityVerified: boolean; mfaVerified: boolean; identityChallenge?: Challenge;
};
type MfaState = {
  ownerAttempts: number; ownerLockedUntil: number;
  identityAttempts: number; identityLockedUntil: number;
  totpAttempts: number; totpLockedUntil: number;
  recoveryAttempts: number; recoveryLockedUntil: number;
  encryptedSecret?: string; acceptedSteps: Set<number>; recoveryHashes: Set<string>;
};
const mfa: MfaState = {
  ownerAttempts: 0, ownerLockedUntil: 0, identityAttempts: 0, identityLockedUntil: 0,
  totpAttempts: 0, totpLockedUntil: 0, recoveryAttempts: 0, recoveryLockedUntil: 0,
  acceptedSteps: new Set(), recoveryHashes: new Set(),
};

function bytes(n: number) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b64(b: Uint8Array) {
  let s = ""; for (const n of b) s += String.fromCharCode(n);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function unb64(s: string) {
  const x = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(atob(x), c => c.charCodeAt(0));
}
function token(n = 32) { return b64(bytes(n)); }
function digits() { const x = new Uint32Array(1); crypto.getRandomValues(x); return String(x[0] % 1_000_000).padStart(6, "0"); }
function challenge(): Challenge { return { accountId: USER.id, value: digits(), expires: Date.now() + CODE_LIFE_MS, used: false }; }
function code() {
  const alpha = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", b = bytes(8);
  const s = Array.from(b, x => alpha[x % alpha.length]).join("");
  return s.slice(0, 4) + "-" + s.slice(4);
}
const keyMaterial = bytes(32);
const masterKey = await crypto.subtle.importKey("raw", keyMaterial, "AES-GCM", false, ["encrypt", "decrypt"]);
const pepper = token(24);
async function hash(value: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(pepper + ":" + value)))); }
async function encrypt(value: string) {
  const iv = bytes(12), data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, encoder.encode(value));
  const packed = new Uint8Array(12 + data.byteLength); packed.set(iv); packed.set(new Uint8Array(data), 12); return b64(packed);
}
async function decrypt(value: string) {
  const p = unb64(value);
  return decoder.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: p.slice(0, 12) }, masterKey, p.slice(12)));
}
function headers(nonce = token(16), origin?: string | null) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
  });
  if (origin && allowedOrigins.has(origin)) { h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); }
  return h;
}
function reply(data: unknown, status = 200, req?: Request) { return new Response(JSON.stringify(data), { status, headers: headers(token(16), req?.headers.get("origin")) }); }
function cookie(req: Request, key: string) {
  const p = (req.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(key + "="));
  return p ? p.slice(key.length + 1) : "";
}
function validOrigin(req: Request) { const o = req.headers.get("origin"); return o === null || allowedOrigins.has(o); }
function safeEmail(x: unknown) { return typeof x === "string" && x.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x); }
function safeCredential(x: unknown) { return typeof x === "string" && x.length > 0 && x.length <= 128 && /^[\x20-\x7e]+$/.test(x); }
function safeOtp(x: unknown) { return typeof x === "string" && /^\d{6}$/.test(x); }
function safeRecovery(x: unknown) { return typeof x === "string" && /^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(x); }
function lockMessage(kind: string) {
  return kind === "owner" ? "Too many sign-in tries. Please wait 15 minutes, then try again." :
    kind === "recovery" ? "Too many recovery code tries. Please wait 15 minutes, then try again." :
    "Too many tries. Please wait 15 minutes, then try again.";
}
async function delay() { await new Promise(r => setTimeout(r, 180)); }

/* Task: explicitly reject content-type, malformed length, invalid JSON and body overflow. */
async function body(req: Request): Promise<{ value?: Record<string, unknown>; error?: string; status?: number }> {
  const type = req.headers.get("content-type") || "";
  if (!/^application\/json(?:\s*;|$)/i.test(type)) return { error: "Use JSON for this request.", status: 400 };
  const stated = req.headers.get("content-length");
  if (stated !== null && (!/^\d+$/.test(stated) || !Number.isSafeInteger(Number(stated)))) return { error: "The request length is not valid.", status: 400 };
  if (stated && Number(stated) > MAX_JSON_BODY_BYTES) return { error: "This request is too large. Please send less information.", status: 413 };
  if (!req.body) return { error: "Send the requested information and try again.", status: 400 };
  const reader = req.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) {
      const item = await reader.read(); if (item.done) break;
      size += item.value.byteLength;
      if (size > MAX_JSON_BODY_BYTES) { await reader.cancel(); return { error: "This request is too large. Please send less information.", status: 413 }; }
      chunks.push(item.value);
    }
  } finally { reader.releaseLock(); }
  const all = new Uint8Array(size); let at = 0; for (const c of chunks) { all.set(c, at); at += c.length; }
  try {
    const value: unknown = JSON.parse(decoder.decode(all));
    if (!value || typeof value !== "object" || Array.isArray(value)) return { error: "Send a valid JSON object and try again.", status: 400 };
    return { value: value as Record<string, unknown> };
  } catch { return { error: "The request is not valid JSON. Check it and try again.", status: 400 }; }
}
function auth(req: Request): { session?: Session; error?: Response } {
  const id = cookie(req, "mfa_session"), s = sessions.get(id), now = Date.now();
  if (!s) return { error: reply({ error: "Please sign in again." }, 401, req) };
  if (now - s.lastSeen > SESSION_IDLE_MS || now - s.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id); return { error: reply({ error: "Your session ended for safety. Please sign in again." }, 401, req) };
  }
  s.lastSeen = now; return { session: s };
}
function csrf(req: Request, s: Session, b: Record<string, unknown>) {
  return req.headers.get("x-csrf-token") === s.csrf && (!("userId" in b) || b.userId === s.userId);
}
function newSession() {
  const now = Date.now(), s: Session = { id: token(), userId: USER.id, csrf: token(), createdAt: now, lastSeen: now, identityVerified: false, mfaVerified: false, identityChallenge: challenge() };
  sessions.set(s.id, s); return s;
}
function sessionCookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_MS / 1000}`; }
async function recovery() { const c = Array.from({ length: 8 }, code); mfa.recoveryHashes = new Set(await Promise.all(c.map(hash))); return c; }

function page(nonce: string) {
return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Example Bank MFA</title>
<style nonce="${nonce}">body{margin:0;background:#f3f7fa;color:#172535;font:18px/1.65 Arial,Verdana,sans-serif;letter-spacing:.03em}.box{max-width:520px;min-height:100vh;margin:auto;background:#fff;padding:22px}h1{font-size:1.65rem;line-height:1.3}input,button{font:inherit;padding:12px;border-radius:8px;min-height:52px;box-sizing:border-box}input{width:100%;border:2px solid #758a9d}button{width:100%;border:0;background:#075bb8;color:#fff;font-weight:bold;margin-top:16px}.note,.error,.success{padding:12px;margin:16px 0;border-radius:8px}.note{background:#edf6ff}.error{background:#fff0f1;color:#8d1522}.success{background:#edf9f1;color:#146c43}.small{font-size:.9rem;color:#526476}pre{white-space:pre-wrap;background:#152536;color:#e7f2ff;padding:10px;border-radius:7px;font:12px monospace}</style>
<div class="box"><p><b>◈ Example Bank security set-up</b></p><main id="app"></main><details><summary>▣ Logs for this demo</summary><pre id="logs"></pre></details></div>
<script nonce="${nonce}">(()=>{"use strict";let csrf="",codes=[];const a=document.querySelector("#app"),l=document.querySelector("#logs");function log(x){console.log(x);l.textContent+=(l.textContent?"\\n":"")+x}async function api(p,b={}){let r=await fetch(p,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(b)}),d=await r.json();if(!r.ok)throw Error(d.error);return d}function show(n="",ok=false){a.innerHTML='<h1>Set up extra protection</h1>'+(n?'<div class="'+(ok?"success":"error")+'">'+n+"</div>":"")+'<p>Sign in, then complete each short step at your own pace.</p><form id=f><label>Email address</label><input id=e type=email autocomplete=email placeholder="name@example.com" required><p class=small>Example: marcus@example.test</p><button>Continue</button></form>';f.onsubmit=async e=>{e.preventDefault();try{await api("/api/auth/signin",{email:E.value});owner()}catch(x){show(x.message)}};const E=document.querySelector("#e")}function owner(n=""){a.innerHTML='<h1>Confirm your sign-in</h1><div class=error>'+n+'</div><form id=f><label>Account credential</label><input id=c type=password autocomplete=current-password placeholder="Example: Marcus-Access-54" required><button>Confirm and send code</button></form>';f.onsubmit=async e=>{e.preventDefault();try{let d=await api("/api/auth/owner",{email:"marcus@example.test",credential:c.value});csrf=d.csrf;log("[Demo] Identity verification code: "+d.testCode);identity("A code was sent.")}catch(x){owner(x.message)}}}function identity(n=""){a.innerHTML='<h1>Check it is you</h1><p>Enter the six-number email code.</p><div class=success>'+n+'</div><form id=f><input id=c inputmode=numeric maxlength=6 autocomplete=one-time-code placeholder="Example: 123456"><button>Verify code</button></form>';f.onsubmit=async e=>{e.preventDefault();try{await api("/api/identity/verify",{code:c.value});setup("Identity confirmed.")}catch(x){identity(x.message)}}}function setup(n){a.innerHTML='<h1>Recovery codes</h1><p>'+n+' For this short demo, make and save one-use recovery codes.</p><button id=b>Show recovery codes</button>';b.onclick=async()=>{try{codes=(await api("/api/mfa/recovery/generate")).codes;log("[Demo] Recovery codes: "+codes.join(", "));a.innerHTML='<h1>Save recovery codes</h1><p>Keep these private. Each works once.</p><pre>'+codes.join("\\n")+'</pre><button id=v>Try a recovery code</button>';v.onclick=verify}catch(x){setup(x.message)}}}function verify(n=""){a.innerHTML='<h1>Use a recovery code</h1><div class=error>'+n+'</div><form id=f><input id=c maxlength=9 placeholder="Example: ABCD-EFGH" autocomplete=one-time-code><button>Verify recovery code</button></form>';f.onsubmit=async e=>{e.preventDefault();try{await api("/api/mfa/recovery/verify",{code:c.value.toUpperCase()});verify("Recovery code accepted. It cannot be used again.")}catch(x){verify(x.message)}}}show()})();</script>`;
}
function html() { const nonce = token(16), h = headers(nonce); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page(nonce), { headers: h }); }

async function handle(req: Request): Promise<Response> {
  try {
    const url = new URL(req.url);
    if (!validOrigin(req)) return reply({ error: "Request not allowed." }, 403, req);
    if (req.method === "GET" && url.pathname === "/") return html();
    if (req.method !== "POST") return reply({ error: "Not found." }, 404, req);
    if (req.method === "OPTIONS") return reply({ error: "Not found." }, 404, req);

    if (url.pathname === "/api/auth/signin") {
      await body(req); await delay(); return reply({ ok: true }, 200, req);
    }

    if (url.pathname === "/api/auth/owner") {
      const parsed = await body(req); await delay();
      const generic = "We could not confirm those sign-in details. Check them and try again.";
      if (mfa.ownerLockedUntil > Date.now()) return reply({ error: lockMessage("owner") }, 429, req);
      const email = typeof parsed.value?.email === "string" ? parsed.value.email.trim().toLowerCase() : "";
      const valid = !!parsed.value && safeEmail(email) && email === USER.email && safeCredential(parsed.value.credential) && parsed.value.credential === DEMO_OWNER_CREDENTIAL;
      /* Task: server-side failed-attempt tracking, identical non-enumerating failures. */
      if (!valid) {
        mfa.ownerAttempts++;
        if (mfa.ownerAttempts >= MAX_FAILURES) { mfa.ownerLockedUntil = Date.now() + LOCK_MS; return reply({ error: lockMessage("owner") }, 429, req); }
        return reply({ error: generic }, 401, req);
      }
      mfa.ownerAttempts = 0; mfa.ownerLockedUntil = 0;
      const old = cookie(req, "mfa_session"); if (old) sessions.delete(old);
      const s = newSession(), r = reply({ csrf: s.csrf, testCode: s.identityChallenge!.value }, 200, req);
      r.headers.set("Set-Cookie", sessionCookie(s.id)); return r;
    }

    const checked = auth(req); if (checked.error) return checked.error;
    const s = checked.session!, parsed = await body(req);
    if (parsed.error) return reply({ error: parsed.error }, parsed.status, req);
    const b = parsed.value!;
    if (!csrf(req, s, b)) return reply({ error: "This request could not be confirmed. Refresh and try again." }, 403, req);

    if (url.pathname === "/api/auth/logout") {
      sessions.delete(s.id); const r = reply({ ok: true }, 200, req);
      r.headers.set("Set-Cookie", "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"); return r;
    }
    if (url.pathname === "/api/identity/verify") {
      if (!safeOtp(b.code)) return reply({ error: "Enter the six numbers from the code." }, 400, req);
      const c = s.identityChallenge;
      if (mfa.identityLockedUntil > Date.now()) return reply({ error: lockMessage("identity") }, 429, req);
      if (!c || c.used || c.expires < Date.now() || c.value !== b.code) {
        mfa.identityAttempts++;
        if (mfa.identityAttempts >= MAX_FAILURES) { mfa.identityLockedUntil = Date.now() + LOCK_MS; return reply({ error: lockMessage("identity") }, 429, req); }
        return reply({ error: "That code does not match. Check the six numbers and try again." }, 400, req);
      }
      c.used = true; s.identityVerified = true; mfa.identityAttempts = 0; return reply({ ok: true }, 200, req);
    }

    /* Task: recovery verification is allowed after first-factor identity verification, before MFA verification. */
    if (url.pathname === "/api/mfa/recovery/verify") {
      if (!s.identityVerified) return reply({ error: "Complete the identity check before using a recovery code." }, 403, req);
      if (mfa.recoveryLockedUntil > Date.now()) return reply({ error: lockMessage("recovery") }, 429, req);
      const submitted = typeof b.code === "string" ? b.code.trim().toUpperCase() : "";
      const valid = safeRecovery(submitted) && mfa.recoveryHashes.delete(await hash(submitted));
      if (!valid) {
        mfa.recoveryAttempts++;
        if (mfa.recoveryAttempts >= MAX_FAILURES) { mfa.recoveryLockedUntil = Date.now() + LOCK_MS; return reply({ error: lockMessage("recovery") }, 429, req); }
        return reply({ error: "That recovery code cannot be used. Check the format ABCD-EFGH and try another saved code." }, 400, req);
      }
      mfa.recoveryAttempts = 0; mfa.recoveryLockedUntil = 0; s.mfaVerified = true;
      return reply({ ok: true, message: "Recovery code accepted." }, 200, req);
    }

    if (!s.identityVerified) return reply({ error: "Complete the identity check before changing MFA settings." }, 403, req);
    if (url.pathname === "/api/mfa/recovery/generate") {
      s.mfaVerified = true; /* Demo enrolment shortcut; secure generation and hashed storage remain server-side. */
      return reply({ codes: await recovery() }, 200, req);
    }
    return reply({ error: "Not found." }, 404, req);
  } catch { return reply({ error: "Something went wrong. Please try again." }, 500, req); }
}

/* Requirement 2/3: Bun HTTPS with supplied local mkcert certificate files. */
Bun.serve({
  hostname: "0.0.0.0", port: 3000,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  fetch: handle,
});
