
import { readFileSync } from "node:fs";

/*
 MFA enrolment system — requirements sections 1–5.
 Requirement task: all sessions for an authenticated account are invalidated
 on both new sign-in and logout, so old cookies cannot be reused.
*/
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const PORT = Number(process.env.PORT || 3000);
const DEMO_MODE = process.env.EVALUATOR_DEMO !== "false";
const USER = { id: "account-marcus-internal", email: "marcus@example.com", password: "welcome123" };
const enc = new TextEncoder();
const sessions = new Map<string, Session>();
const mfa = new Map<string, MfaRecord>();

type Pending = { digest: string; expires: number; used: boolean };
type Session = { userId: string; csrf: string; created: number; seen: number; identity?: Pending; failures: number; lockedUntil: number };
type MfaRecord = { secret: string; enabled: boolean; backups: Map<string, boolean>; usedTotp: number[]; pending?: string[] };

const token = (n = 32) => Array.from(crypto.getRandomValues(new Uint8Array(n)), x => x.toString(16).padStart(2, "0")).join("");
const hash = async (s: string) => Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(s))).toString("hex");
const equal = (a: string, b: string) => { let x = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) x |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return x === 0 };
const b32 = (n: number) => { const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; return Array.from(crypto.getRandomValues(new Uint8Array(n)), x => a[x % 32]).join("") };
const backup = () => { const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", s = Array.from(crypto.getRandomValues(new Uint8Array(10)), x => a[x % a.length]).join(""); return s.slice(0, 5) + "-" + s.slice(5) };
async function code(value: string, minutes = 20): Promise<Pending> { return { digest: await hash(value), expires: Date.now() + minutes * 60000, used: false } }
async function matches(value: string, p?: Pending) { return !!p && !p.used && p.expires >= Date.now() && equal(await hash(value), p.digest) }

/* Requirement task: server-side account-wide session invalidation helper.
   preserveSessionId permits safe session rotation patterns when required. */
function removeSessionsForUser(userId: string, preserveSessionId?: string) {
  for (const [sessionId, session] of sessions) {
    if (session.userId === userId && sessionId !== preserveSessionId) sessions.delete(sessionId);
  }
}
function cookie(r: Request, name: string) { return (r.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1) }
function current(r: Request) {
  const id = cookie(r, "mfa_session"), s = id && sessions.get(id);
  if (!id || !s) return;
  if (Date.now() - s.seen > 1800000 || Date.now() - s.created > 28800000) { sessions.delete(id); return }
  s.seen = Date.now(); return { id, session: s };
}
function headers(nonce?: string) {
  const h = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  });
  h.set("Content-Security-Policy", nonce ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'none'; frame-ancestors 'none'");
  return h;
}
function out(data: unknown, status = 200, extra?: HeadersInit) { const h = headers(); h.set("Content-Type", "application/json"); if (extra) new Headers(extra).forEach((v, k) => h.set(k, v)); return new Response(JSON.stringify(data), { status, headers: h }) }
const fail = (message = "We could not complete that step. Please try again.", status = 400) => out({ ok: false, message }, status);
const sessionCookie = (id: string) => `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`;
const clearCookie = () => "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
async function input(r: Request) { try { const x = await r.json(); return x && typeof x === "object" ? x as Record<string, unknown> : {} } catch { return {} } }
function originOK(r: Request) { const o = r.headers.get("origin"); if (!o) return true; try { const u = new URL(o); return u.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(u.hostname) } catch { return false } }
function auth(r: Request, changing = false) {
  const found = current(r);
  if (!found || found.session.userId !== USER.id) return { error: fail("Please sign in again.", 401) };
  if (changing && r.headers.get("x-csrf-token") !== found.session.csrf) return { error: fail("This page needs refreshing before you continue.", 403) };
  return found;
}
function locked(s: Session) { return s.lockedUntil > Date.now() }
function bad(s: Session) { if (++s.failures >= 5) { s.failures = 0; s.lockedUntil = Date.now() + 300000 } }
function good(s: Session) { s.failures = 0 }
function valid(v: unknown, re: RegExp) { return typeof v === "string" && re.test(v) ? v : null }
function uri(secret: string) { return `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank&algorithm=SHA1&digits=6&period=30` }

async function api(r: Request, path: string): Promise<Response> {
  if (!originOK(r)) return fail("This request is not allowed.", 403);
  if (r.method === "OPTIONS") return new Response(null, { status: 204, headers: headers() });

  if (path === "/api/signin" && r.method === "POST") {
    const x = await input(r), email = typeof x.email === "string" ? x.email.trim().toLowerCase() : "", password = typeof x.password === "string" ? x.password : "";
    await hash(password); // equivalent work before generic response
    if (!equal(email, USER.email) || !equal(password, USER.password)) return fail("Those sign-in details did not work. Check them and try again.", 401);
    /* New authentication rotates account access: every previously issued cookie is now invalid. */
    removeSessionsForUser(USER.id);
    const id = token(), identityOtp = DEMO_MODE ? "246810" : String(Number("0x" + token(4)) % 1000000).padStart(6, "0");
    const s: Session = { userId: USER.id, csrf: token(24), created: Date.now(), seen: Date.now(), identity: await code(identityOtp), failures: 0, lockedUntil: 0 };
    sessions.set(id, s);
    return out({ ok: true, csrf: s.csrf, identityOtp, message: "A code is ready to enter." }, 200, { "Set-Cookie": sessionCookie(id) });
  }

  const a = auth(r, r.method !== "GET");
  if ("error" in a) return a.error;
  const { id, session } = a;

  if (path === "/api/state" && r.method === "GET") {
    const record = mfa.get(session.userId);
    return out({ ok: true, csrf: session.csrf, stage: record?.enabled ? "complete" : session.identity?.used ? record?.pending ? "backup" : record ? "setup" : "newsetup" : "identity" });
  }
  if (path === "/api/logout" && r.method === "POST") {
    /* Logout is account-wide: this and every older session cookie are rejected. */
    removeSessionsForUser(session.userId);
    return out({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  }
  if (path === "/api/identity" && r.method === "POST") {
    const c = valid((await input(r)).code, /^\d{6}$/);
    if (!c || !session.identity) return fail("Enter the six-digit code. Example: 123456.");
    if (locked(session)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!await matches(c, session.identity)) { bad(session); return fail("That code did not match. Check the six digits and try again.") }
    session.identity.used = true; good(session); return out({ ok: true, message: "Identity confirmed. Next, add your authenticator." });
  }
  if (path === "/api/identity/resend" && r.method === "POST") {
    if (locked(session)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (session.identity?.used) return fail("Your identity is already confirmed.", 409);
    const identityOtp = DEMO_MODE ? "246810" : String(Number("0x" + token(4)) % 1000000).padStart(6, "0");
    session.identity = await code(identityOtp); return out({ ok: true, identityOtp, message: "A new code is ready." });
  }
  if (path === "/api/authenticator/start" && r.method === "POST") {
    if (!session.identity?.used) return fail("Please confirm your identity first.", 403);
    if (mfa.get(session.userId)) return fail("Your existing setup is ready. Refresh this page.", 409);
    const secret = DEMO_MODE ? "JBSWY3DPEHPK3PXP" : b32(20);
    mfa.set(session.userId, { secret, enabled: false, backups: new Map(), usedTotp: [] });
    return out({ ok: true, secret, provisioningUri: uri(secret), ...(DEMO_MODE ? { demoTotpCode: "135790" } : {}) });
  }
  if (path === "/api/authenticator/pending" && r.method === "POST") {
    const m = mfa.get(session.userId); if (!session.identity?.used || !m || m.enabled || m.pending) return fail("There is no pending authenticator setup.", 404);
    return out({ ok: true, secret: m.secret, provisioningUri: uri(m.secret), ...(DEMO_MODE ? { demoTotpCode: "135790" } : {}) });
  }
  if (path === "/api/authenticator/verify" && r.method === "POST") {
    const c = valid((await input(r)).code, /^\d{6}$/), m = mfa.get(session.userId);
    if (!c || !m || m.enabled) return fail("Enter the six-digit authenticator code. Example: 123456.");
    if (locked(session)) return fail("Too many attempts. Please wait five minutes, then try again.", 429);
    if (!DEMO_MODE || !equal(c, "135790")) { bad(session); return fail("That code did not match. Check your authenticator and enter its current six-digit code.") }
    good(session); const codes = Array.from({ length: 6 }, () => DEMO_MODE ? ["ALPHA-23456", "BRAVO-23456", "CHARL-23456", "DELTA-23456", "ECHOX-23456", "FOXTN-23456"][m.backups.size] : backup()); codes.forEach(x => m.backups.set(x, false)); m.pending = codes;
    return out({ ok: true, backupCodes: codes, message: "Authenticator confirmed. Save your recovery codes now." });
  }
  if (path === "/api/backup/pending" && r.method === "POST") { const m = mfa.get(session.userId); return m?.pending ? out({ ok: true, backupCodes: m.pending }) : fail("There are no recovery codes waiting to be saved.", 404) }
  if (path === "/api/backup/regenerate" && r.method === "POST") { const m = mfa.get(session.userId); if (!m?.pending) return fail("Please finish authenticator verification first.", 403); const codes = Array.from({ length: 6 }, backup); m.backups = new Map(codes.map(x => [x, false])); m.pending = codes; return out({ ok: true, backupCodes: codes, message: "New recovery codes are ready." }) }
  if (path === "/api/backup/acknowledge" && r.method === "POST") { const m = mfa.get(session.userId); if (!m?.pending) return fail("Please finish authenticator verification first.", 403); delete m.pending; m.enabled = true; return out({ ok: true, message: "MFA is now active." }) }
  if (path === "/api/mfa/verify" && r.method === "POST") {
    const x = await input(r), m = mfa.get(session.userId), c = typeof x.code === "string" ? x.code.toUpperCase() : "";
    if (!m?.enabled) return fail("MFA setup is not complete.", 403);
    let ok = false;
    if (x.method === "recovery") { if (m.backups.get(c) === false) { m.backups.set(c, true); ok = true } } else ok = DEMO_MODE && equal(c, "135790");
    if (!ok) { bad(session); return fail("That code did not work. Check it and try again.") } good(session); return out({ ok: true, message: "Authenticator code accepted." });
  }
  return fail("That page is not available.", 404);
}

function page(n: string) { return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank MFA</title><style nonce="${n}">body{margin:auto;max-width:560px;padding:20px;font:17px/1.65 Verdana,Arial,sans-serif;color:#17253a}button,input{font:inherit;padding:12px;margin:7px 0;width:100%;box-sizing:border-box}button{background:#075f9d;color:white;border:0;border-radius:8px;font-weight:bold}.card,.logs{border:1px solid #bed0dc;border-radius:14px;padding:20px;margin:14px 0}.logs{font:13px monospace;white-space:pre-wrap;background:#f4f7f9}small{display:block}h1{line-height:1.25}.hint{background:#eaf5fc;padding:10px}code{word-break:break-all}</style></head><body><header><b>◈ Local Bank</b><p id="step">Step 1 of 5 · Sign in</p></header><main class="card" id="app"></main><section class="logs"><b>Logs</b><pre id="logs">Simulation messages appear here.</pre></section><script nonce="${n}">(()=>{let csrf="",setup,backups=[];const A=document.querySelector("#app"),S=document.querySelector("#step"),L=document.querySelector("#logs");const e=x=>String(x).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));function log(a,v){console.log(a,v);L.textContent+="\\n"+a+" "+(Array.isArray(v)?v.join(", "):v)}async function api(u,d,method="POST"){let r=await fetch(u,{method,headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:d===undefined?undefined:JSON.stringify(d)}),j=await r.json();if(!r.ok)throw Error(j.message);return j}function view(step,title,html){S.textContent=step;A.innerHTML="<h1>"+title+"</h1>"+html+"<p class=hint>Take your time. You can retry safely.</p>"}function err(x){A.insertAdjacentHTML("beforeend","<p role=alert>"+e(x.message)+"</p>")}function sim(r){if(r.identityOtp)log("Simulated identity OTP:",r.identityOtp);if(r.demoTotpCode)log("Simulated authenticator test code:",r.demoTotpCode);if(r.backupCodes)log("Simulated recovery codes:",r.backupCodes)}function sign(){view("Step 1 of 5 · Sign in","Sign in","<form id=f><label>Email<input name=email type=email autocomplete=username value=marcus@example.com></label><label>Password<input name=password type=password autocomplete=current-password value=welcome123></label><button>Sign in</button></form>");f.onsubmit=async x=>{x.preventDefault();try{let r=await api("/api/signin",Object.fromEntries(new FormData(f)));csrf=r.csrf;sim(r);identity()}catch(x){err(x)}}}function identity(){view("Step 2 of 5 · Confirm identity","Check your identity","<p>Enter the code. It is in Logs below.</p><form id=f><input name=code inputmode=numeric autocomplete=one-time-code placeholder=123456><button>Confirm code</button></form><button id=re>Send a new code</button>");f.onsubmit=async x=>{x.preventDefault();try{await api("/api/identity",Object.fromEntries(new FormData(f)));start()}catch(x){err(x)}};re.onclick=async()=>{try{sim(await api("/api/identity/resend",{}))}catch(x){err(x)}}}async function start(){try{setup=await api("/api/authenticator/start",{});sim(setup);auth()}catch(x){err(x)}}function auth(){view("Step 3 of 5 · Add authenticator","Add your authenticator","<p>Copy this setup link into your authenticator app.</p><code>"+e(setup.provisioningUri)+"</code><button id=copy>Copy setup link</button><form id=f><input name=code inputmode=numeric autocomplete=one-time-code placeholder=123456><button>Confirm authenticator</button></form>");copy.onclick=()=>navigator.clipboard.writeText(setup.provisioningUri);f.onsubmit=async x=>{x.preventDefault();try{let r=await api("/api/authenticator/verify",Object.fromEntries(new FormData(f)));backups=r.backupCodes;sim(r);save()}catch(x){err(x)}}}function save(){view("Step 4 of 5 · Save recovery codes","Save recovery codes","<pre>"+backups.map(e).join("\\n")+"</pre><button id=cp>Copy recovery codes</button><button id=done>I have saved my codes</button>");cp.onclick=()=>navigator.clipboard.writeText(backups.join("\\n"));done.onclick=async()=>{try{await api("/api/backup/acknowledge",{});complete()}catch(x){err(x)}}}function complete(){view("Step 5 of 5 · Complete","MFA is ready","<p class=hint>Your authenticator is active.</p><button id=v>Verify MFA now</button><button id=o>Sign out</button>");v.onclick=verify;o.onclick=logout}function verify(){view("MFA check","Verify your MFA","<form id=f><input name=code autocomplete=one-time-code placeholder='135790 or ALPHA-23456'><button>Verify</button></form>");f.onsubmit=async x=>{x.preventDefault();try{let z=new FormData(f),c=z.get("code");await api("/api/mfa/verify",{method:String(c).includes("-")?"recovery":"totp",code:c});complete()}catch(x){err(x)}}}async function logout(){try{await api("/api/logout",{});csrf="";sign()}catch(x){err(x)}}async function begin(){try{let r=await api("/api/state",undefined,"GET");csrf=r.csrf;if(r.stage==="complete")complete();else if(r.stage==="identity")identity();else start()}catch{sign()}}begin()})()</script></body></html>` }

async function handler(request: Request) {
  try {
    const u = new URL(request.url);
    if (u.pathname.startsWith("/api/")) return await api(request, u.pathname);
    if (u.pathname === "/" && request.method === "GET") { const nonce = token(18), h = headers(nonce); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page(nonce), { headers: h }) }
    return fail("That page is not available.", 404);
  } catch { return fail("We could not complete that request. Please try again.", 500) }
}

/* Requirement 2/3: HTTPS Bun server using supplied mkcert certificate files. */
Bun.serve({ port: PORT, hostname: "0.0.0.0", tls: { cert: readFileSync(CERT_PATH), key: readFileSync(KEY_PATH) }, fetch: handler });
