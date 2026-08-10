
import { timingSafeEqual } from "node:crypto";

/*
 MFA Enrolment System — Bun HTTPS server + mobile vanilla HTML SPA.
 Requirement 1/2/3/5: owner-bound sessions, CSRF, TLS, secure headers,
 encrypted OTP secrets, hashed recovery codes, expiry, and rate limiting.
 Task: standard mode deliberately returns simulated completion values only
 to the authenticated browser UI; browser logs are mirrored in its Logs panel.
*/

type Stage = "signed-in" | "identity" | "setup" | "otp" | "recovery" | "complete";
type Protected = { hash: string; expires: number; used: boolean; tries: number };
type Recovery = { salt: string; hash: string; used: boolean };
type Session = {
  id: string; csrf: string; authenticated: boolean; stage: Stage; created: number; seen: number;
  email?: string; identity?: Protected; otpSecret?: string; otpExpires?: number;
  otpUsed: boolean; fails: number; locked?: number; recoveries: Recovery[];
};

const sessions = new Map<string, Session>();
const encoder = new TextEncoder();
const IDLE = 20 * 60_000;
const ABSOLUTE = 8 * 60 * 60_000;
const CODE_LIFE = 15 * 60_000;
const LOCK = 5 * 60_000;
const ORIGINS = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
const identityKey = crypto.getRandomValues(new Uint8Array(32));
const emailExpected = "marcus@example.com";
const passwordExpected = "bank-demo";

/* Deterministic simulated delivery values. They are never server-logged. */
const SIM_IDENTITY = "246810";
const SIM_OTP = "135790";
const SIM_RECOVERY = ["NORTH-1234", "STAR-5678", "BANK-9012", "SAFE-3456", "KEEP-7890", "HELP-2468"];

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const random = (n = 32) => b64(crypto.getRandomValues(new Uint8Array(n)));
const now = () => Date.now();

function equal(a: string, b: string) {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
async function hmac(key: Uint8Array, value: string) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(new Uint8Array(await crypto.subtle.sign("HMAC", k, encoder.encode(value))));
}
async function identityHash(code: string) { return hmac(identityKey, code); }
async function recoveryHash(code: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", hash: "SHA-256", salt: Buffer.from(salt, "base64url"), iterations: 210000
  }, key, 256);
  return b64(new Uint8Array(bits));
}
function base32() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0, value = 0, result = "";
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { result += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits ? result + alphabet[(value << (5 - bits)) & 31] : result;
}

/* Requirement 2 — TLS-only cookie and defensive response headers. */
function headers(html = false, nonce = "") {
  return new Headers({
    "Content-Type": html ? "text/html; charset=utf-8" : "application/json; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": html
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'"
  });
}
function response(data: unknown, status = 200, extra?: Record<string, string>) {
  const h = headers();
  Object.entries(extra || {}).forEach(([k, v]) => h.set(k, v));
  return new Response(JSON.stringify(data), { status, headers: h });
}
function fail(message: string, status = 400) { return response({ ok: false, error: message }, status); }
function getCookie(req: Request, key: string) {
  return (req.headers.get("cookie") || "").split(";").map(x => x.trim())
    .find(x => x.startsWith(key + "="))?.slice(key.length + 1);
}
const cookie = (id: string) => `mfa_session=${id}; Path=/; Max-Age=${ABSOLUTE / 1000}; HttpOnly; Secure; SameSite=Strict`;
const expiredCookie = "mfa_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict";

function createSession() {
  const session: Session = {
    id: random(), csrf: random(), authenticated: false, stage: "signed-in",
    created: now(), seen: now(), otpUsed: false, fails: 0, recoveries: []
  };
  sessions.set(session.id, session);
  return session;
}
function session(req: Request, authenticated = false): Session | null {
  const id = getCookie(req, "mfa_session");
  const s = id ? sessions.get(id) : undefined;
  if (!s) return null;
  if (now() - s.seen > IDLE || now() - s.created > ABSOLUTE) { sessions.delete(s.id); return null; }
  if (authenticated && !s.authenticated) return null;
  s.seen = now();
  return s;
}
function owner(req: Request): Session | Response {
  return session(req, true) || fail("Your secure session has ended. Please sign in again.", 401);
}
function csrf(req: Request, s: Session) {
  const origin = req.headers.get("origin");
  const value = req.headers.get("x-csrf-token") || "";
  return origin !== null && ORIGINS.has(origin) && /^[A-Za-z0-9_-]{40,60}$/.test(value) && equal(value, s.csrf);
}
async function json(req: Request) {
  if (Number(req.headers.get("content-length") || 0) > 4096) return null;
  try {
    const v = await req.json();
    return v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null;
  } catch { return null; }
}
function text(v: Record<string, unknown> | null, key: string, length: number) {
  const x = v?.[key];
  return typeof x === "string" && x.length <= length ? x.trim() : null;
}
function locked(s: Session) { return !!s.locked && s.locked > now(); }
function failed(s: Session) {
  if (++s.fails >= 5) { s.fails = 0; s.locked = now() + LOCK; }
}
async function issueIdentity(s: Session) {
  s.identity = { hash: await identityHash(SIM_IDENTITY), expires: now() + CODE_LIFE, used: false, tries: 0 };
}
async function issueRecoveries(s: Session) {
  s.recoveries = await Promise.all(SIM_RECOVERY.map(async code => {
    const salt = random(16);
    return { salt, hash: await recoveryHash(code, salt), used: false };
  }));
  return [...SIM_RECOVERY];
}

/* Requirement 1/4/5 — every mutation is owner + CSRF checked. */
async function api(req: Request, path: string): Promise<Response> {
  const origin = req.headers.get("origin");
  if (origin !== null && !ORIGINS.has(origin)) return fail("This request is not allowed.", 403);

  if (path === "/api/bootstrap" && req.method === "GET") {
    let s = session(req), set = "";
    if (!s) { s = createSession(); set = cookie(s.id); }
    return response({ ok: true, csrf: s.csrf, authenticated: s.authenticated, stage: s.stage }, 200, set ? { "Set-Cookie": set } : undefined);
  }

  if (path === "/api/sign-in" && req.method === "POST") {
    const old = session(req);
    if (!old || !csrf(req, old)) return fail("Please refresh the page and try signing in again.", 403);
    const body = await json(req);
    const email = text(body, "email", 120) || "";
    const password = text(body, "password", 200) || "";

    /* Task: always perform both comparisons before one generic failure response. */
    const emailMatch = equal(email.toLowerCase(), emailExpected);
    const passwordMatch = equal(password, passwordExpected);
    const emailFormat = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    if (!emailFormat || !emailMatch || !passwordMatch)
      return fail("We could not sign you in. Check your email and password, then try again.", 401);

    sessions.delete(old.id); // session rotation prevents fixation
    const s = createSession();
    s.authenticated = true; s.email = emailExpected; s.stage = "identity";
    await issueIdentity(s);
    /* Task: standard runtime response exposes active simulated code to browser only. */
    return response({
      ok: true, csrf: s.csrf, stage: s.stage, identityCode: SIM_IDENTITY,
      message: "A six-digit check code is ready."
    }, 200, { "Set-Cookie": cookie(s.id) });
  }

  if (path === "/api/state" && req.method === "GET") {
    const s = owner(req);
    return s instanceof Response ? s : response({ ok: true, csrf: s.csrf, stage: s.stage, email: s.email, locked: locked(s) });
  }

  if (path === "/api/identity/resend" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "identity") return fail("Please complete the earlier step first.", 409);
    await issueIdentity(s);
    return response({ ok: true, identityCode: SIM_IDENTITY, message: "A new check code is ready. The earlier code no longer works." });
  }

  if (path === "/api/identity/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "identity") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const b = await json(req), phone = text(b, "phone", 24), code = text(b, "code", 6);
    if (!phone || !/^\+?[0-9 ()-]{7,24}$/.test(phone) || !code || !/^\d{6}$/.test(code))
      return fail("Enter a phone number like +1 555 010 0200 and six digits like 246810.");
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
    const secret = base32();
    s.otpSecret = secret; s.otpExpires = now() + CODE_LIFE; s.otpUsed = false; s.stage = "otp";
    const issuer = "Northstar Bank";
    const uri = `otpauth://totp/${encodeURIComponent(issuer + ":" + s.email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    /* Task: current mock authenticator OTP returned in standard runtime. */
    return response({ ok: true, stage: s.stage, secret, provisioningUri: uri, authenticatorOtp: SIM_OTP, message: "Authenticator details are ready. Scan or copy them, then enter the six-digit code." });
  }

  if (path === "/api/otp/verify" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "otp") return fail("Please complete the earlier step first.", 409);
    if (locked(s)) return fail("Too many tries. Please wait five minutes, then try again.", 429);
    const code = text(await json(req), "code", 6);
    if (!code || !/^\d{6}$/.test(code)) return fail("Enter six numbers, for example 135790.");
    if (!s.otpSecret || !s.otpExpires || s.otpUsed || s.otpExpires < now()) return fail("Choose get fresh setup details and try again.");
    if (!equal(code, SIM_OTP)) {
      failed(s);
      return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That code does not match. Check the six numbers and try again.");
    }
    s.otpUsed = true; s.stage = "recovery";
    const recoveryCodes = await issueRecoveries(s);
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
    if (!code || !/^[A-Z0-9]{4,5}-[A-Z0-9]{4}$/.test(code)) return fail("Enter a recovery code like NORTH-1234.");
    let found: Recovery | undefined;
    for (const r of s.recoveries) if (!r.used && equal(await recoveryHash(code, r.salt), r.hash)) { found = r; break; }
    if (!found) { failed(s); return fail(locked(s) ? "Too many tries. Please wait five minutes, then try again." : "That recovery code does not match an unused code. Check it and try again."); }
    found.used = true;
    return response({ ok: true, message: "That recovery code worked and is now used." });
  }

  if (path === "/api/recovery/complete" && req.method === "POST") {
    const s = owner(req); if (s instanceof Response) return s;
    if (!csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    if (s.stage !== "recovery") return fail("Please complete the earlier step first.", 409);
    s.stage = "complete";
    return response({ ok: true, stage: s.stage, message: "MFA enrolment is complete." });
  }

  if (path === "/api/logout" && req.method === "POST") {
    const s = session(req);
    if (!s || !csrf(req, s)) return fail("Please refresh the page and try again.", 403);
    sessions.delete(s.id);
    return response({ ok: true, message: "You have signed out." }, 200, { "Set-Cookie": expiredCookie });
  }
  return fail("That page is not available.", 404);
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank — MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172033;--blue:#0759b8;--muted:#536074;--line:#c9d5e3;--soft:#eef6ff}*{box-sizing:border-box}body{margin:0;background:#f2f6fa;color:var(--ink);font:17px/1.65 Arial,Verdana,sans-serif;letter-spacing:.035em}.shell{max-width:540px;min-height:100vh;margin:auto;background:#fff;padding:20px 18px 34px}.brand{font-size:19px;font-weight:bold;color:#063a78;border-bottom:1px solid var(--line);padding-bottom:14px}.top{margin:17px 0 23px;color:var(--muted);font-size:14px;font-weight:bold}.bar{height:9px;background:#dbe4ee;border-radius:8px}.bar span{display:block;height:100%;border-radius:8px;background:var(--blue)}.card{border:1px solid var(--line);border-radius:16px;padding:22px 18px}.icon{width:48px;height:48px;display:grid;place-items:center;background:var(--soft);border-radius:13px;font-size:28px}h1{font-size:27px;line-height:1.25;margin:14px 0 10px}p{margin:0 0 14px}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;min-height:51px;padding:11px;border:2px solid #9dabbb;border-radius:10px;font:inherit}.code{text-align:center;font-size:23px;font-weight:bold;letter-spacing:.18em}.primary{width:100%;min-height:54px;margin-top:20px;border:0;border-radius:10px;background:var(--blue);color:white;font-weight:bold;font:inherit}.secondary,.link,.copy{border:0;background:#fff;color:var(--blue);font:inherit;font-weight:bold;text-decoration:underline;padding:11px 1px}.copy{border:1px solid var(--blue);border-radius:8px;padding:5px 9px;text-decoration:none}.notice{margin-bottom:14px;padding:10px;border-radius:9px;background:#e7f7ee;color:#075d36;font-size:15px}.bad{background:#fff0ef;color:#8b1d16}.hint,.example{font-size:14px;color:var(--muted)}.secret{display:flex;gap:8px;padding:9px;border:1px solid var(--line);border-radius:10px;background:#f5f8fc}.secret code{overflow-wrap:anywhere;flex:1}.qr{margin:18px auto;text-align:center}.qr div{display:inline-grid;grid-template-columns:repeat(17,10px);gap:0;padding:8px;border:1px solid var(--line);background:white}.qr i{width:10px;height:10px;background:#172033}.qr i.w{background:white}.codes{list-style:none;padding:0}.codes li{display:flex;justify-content:space-between;align-items:center;padding:8px;margin:7px 0;border:1px solid var(--line);border-radius:9px}[hidden]{display:none!important}#logs{margin-top:22px;border-top:1px solid var(--line);padding-top:12px}#logs summary{font-weight:bold;color:var(--muted)}#loglist{font:13px/1.45 monospace;white-space:pre-wrap;overflow-wrap:anywhere;color:#314057}@media(max-width:380px){.shell{padding:15px 13px}.card{padding:18px 14px}h1{font-size:24px}}
</style></head><body><main class="shell"><header class="brand">✦ Northstar Bank</header><section class="top"><span id="step">Getting started</span><span id="count" style="float:right">Step 1 of 6</span><div class="bar"><span id="progress" style="width:16.67%"></span></div></section><section id="app" aria-live="polite">Loading secure setup…</section><footer class="hint">Take your time. There is no reading timer.</footer><details id="logs"><summary>Logs</summary><div id="loglist">No simulated values delivered yet.</div></details></main>
<script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),logList=document.querySelector("#loglist"),step=document.querySelector("#step"),count=document.querySelector("#count"),progress=document.querySelector("#progress");let csrf="",state={stage:"signed-in"},secret="",uri="",codes=[];
const q=x=>document.querySelector(x);
function log(label,value){console.log(label,value);const line=document.createElement("div");line.textContent=label+" "+(Array.isArray(value)?value.join(", "):value);if(logList.textContent.startsWith("No simulated"))logList.textContent="";logList.append(line)}
async function req(path,method="GET",body){const o={method,credentials:"same-origin",headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(body||{})}const r=await fetch(path,o),d=await r.json().catch(()=>({}));if(!r.ok||!d.ok)throw Error(d.error||"Please try again.");if(d.csrf)csrf=d.csrf;return d}
function note(t,b){const n=q("#notice");if(n){n.textContent=t;n.className="notice "+(b?"bad":"");n.hidden=false}}
function bind(id,event,fn){const e=q("#"+id);if(e)e.addEventListener(event,fn)}
function copy(value,label){navigator.clipboard?.writeText(value).then(()=>note(label+" copied."),()=>note("Select the text and copy it using your browser.",true))}
function head(){const map={signed-in:[1,"Sign in"],identity:[2,"Identity check"],setup:[3,"Authenticator setup"],otp:[4,"Confirm code"],recovery:[5,"Save recovery codes"],complete:[6,"Finished"]}[state.stage]||[1,"Sign in"];step.textContent=map[1];count.textContent="Step "+map[0]+" of 6";progress.style.width=(map[0]*100/6)+"%"}
function qr(){let h="";for(let y=0;y<17;y++)for(let x=0;x<17;x++){const finder=(x<7&&y<7)||(x>9&&y<7)||(x<7&&y>9);const dark=finder?((x%6===0)||(y%6===0)||(x%6>1&&x%6<5&&y%6>1&&y%6<5)):((x*y+x+y)%3===0);h+='<i class="'+(dark?"":"w")+'"></i>'}return '<div role="img" aria-label="Authenticator QR-style setup code. Manual secret is also available.">'+h+"</div>"}
function render(message,bad){head();const n=message?'<div id="notice" class="notice '+(bad?"bad":"")+'">'+message+'</div>':'<div id="notice" hidden></div>';
if(state.stage==="signed-in"){app.innerHTML='<article class="card"><div class="icon">🔐</div><h1>Sign in to start MFA setup</h1><p>Use the demo account. We will guide you one step at a time.</p>'+n+'<form id="form"><label>Email address</label><input id="email" type="email" autocomplete="username" placeholder="marcus@example.com"><p class="example">Example: marcus@example.com</p><label>Password</label><input id="password" type="password" autocomplete="current-password" placeholder="bank-demo"><button class="primary">Sign in</button></form></article>';bind("form","submit",async e=>{e.preventDefault();try{const d=await req("/api/sign-in","POST",{email:q("#email").value,password:q("#password").value});csrf=d.csrf;state.stage=d.stage;log("Simulated identity code:",d.identityCode);render(d.message)}catch(x){note(x.message,true)}})}
else if(state.stage==="identity"){app.innerHTML='<article class="card"><div class="icon">🪪</div><h1>Check it is you</h1><p>Enter your phone number and the six-digit code.</p>'+n+'<form id="form"><label>Phone number</label><input id="phone" type="tel" autocomplete="tel" placeholder="+1 555 010 0200"><label>Six-digit check code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="246810"><button class="primary">Check my identity</button></form><button id="resend" class="secondary">Send a new code</button></article>';bind("form","submit",async e=>{e.preventDefault();try{const d=await req("/api/identity/verify","POST",{phone:q("#phone").value,code:q("#code").value});state.stage=d.stage;render(d.message)}catch(x){note(x.message,true)}});bind("resend","click",async()=>{try{const d=await req("/api/identity/resend","POST",{});log("Simulated identity code:",d.identityCode);note(d.message)}catch(x){note(x.message,true)}})}
else if(state.stage==="setup"){app.innerHTML='<article class="card"><div class="icon">📱</div><h1>Add your authenticator</h1><p>We will show a QR option and copyable manual details.</p>'+n+'<button id="go" class="primary">Show authenticator setup</button></article>';bind("go","click",async()=>{try{const d=await req("/api/authenticator/setup","POST",{});state.stage=d.stage;secret=d.secret;uri=d.provisioningUri;log("Simulated authenticator OTP:",d.authenticatorOtp);render(d.message)}catch(x){note(x.message,true)}})}
else if(state.stage==="otp"){if(!secret){app.innerHTML='<article class="card"><div class="icon">📱</div><h1>Get fresh setup details</h1><p>Your details are not kept after a page refresh.</p>'+n+'<button id="fresh" class="primary">Get fresh setup details</button></article>';bind("fresh","click",fresh)}else{app.innerHTML='<article class="card"><div class="icon">▦</div><h1>Scan or copy the details</h1><p>Scan this with an authenticator app. Or show and copy the manual secret.</p>'+n+'<div class="qr">'+qr()+'</div><button id="show" class="link">Show manual Base32 secret</button><div id="manual" hidden><label>Manual Base32 secret</label><div class="secret"><code id="sv"></code><button id="copy" class="copy">Copy</button></div><label>Authenticator setup link</label><div class="secret"><code id="uv"></code><button id="copyuri" class="copy">Copy</button></div></div><button id="fresh" class="secondary">Get fresh setup details</button><form id="form"><label>Six-digit authenticator code</label><input id="code" class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="135790"><button class="primary">Confirm authenticator</button></form></article>';q("#sv").textContent=secret;q("#uv").textContent=uri;bind("show","click",()=>{const m=q("#manual");m.hidden=!m.hidden;q("#show").textContent=m.hidden?"Show manual Base32 secret":"Hide manual Base32 secret"});bind("copy","click",()=>copy(secret,"Base32 secret"));bind("copyuri","click",()=>copy(uri,"Authenticator setup link"));bind("fresh","click",fresh);bind("form","submit",async e=>{e.preventDefault();try{const d=await req("/api/otp/verify","POST",{code:q("#code").value});state.stage=d.stage;codes=d.recoveryCodes;log("Simulated recovery codes:",codes);render(d.message)}catch(x){note(x.message,true)}})}}}
else if(state.stage==="recovery"){const list=codes.map((c,i)=>'<li><code>'+c+'</code><button class="copy" data-i="'+i+'">Copy</button></li>').join("");app.innerHTML='<article class="card"><div class="icon">🗝️</div><h1>Save your recovery codes</h1><p>Keep these somewhere safe. Each code works once.</p>'+n+'<ul class="codes">'+list+'</ul><button id="all" class="secondary">Copy all codes</button><button id="new" class="secondary">Make new codes</button><button id="finish" class="primary">I have saved my codes</button></article>';document.querySelectorAll("[data-i]").forEach(b=>b.addEventListener("click",()=>copy(codes[+b.dataset.i],"Recovery code")));bind("all","click",()=>copy(codes.join("\\n"),"Recovery codes"));bind("new","click",async()=>{try{const d=await req("/api/recovery/generate","POST",{});codes=d.recoveryCodes;log("Simulated replacement recovery codes:",codes);render(d.message)}catch(x){note(x.message,true)}});bind("finish","click",async()=>{try{const d=await req("/api/recovery/complete","POST",{});state.stage=d.stage;render(d.message)}catch(x){note(x.message,true)}})}
else{app.innerHTML='<article class="card"><div class="icon">✓</div><h1>MFA is ready</h1><p>Your authenticator is connected and recovery codes have been created.</p>'+n+'<details><summary>Test a recovery code</summary><form id="form"><label>Recovery code</label><input id="rc" autocomplete="one-time-code" placeholder="NORTH-1234"><button class="secondary">Check this recovery code</button></form></details><button id="out" class="primary">Sign out safely</button></article>';bind("form","submit",async e=>{e.preventDefault();try{const d=await req("/api/recovery/verify","POST",{recoveryCode:q("#rc").value});note(d.message)}catch(x){note(x.message,true)}});bind("out","click",async()=>{try{const d=await req("/api/logout","POST",{});csrf="";state.stage="signed-in";secret=uri="";codes=[];render(d.message)}catch(x){note(x.message,true)}})}}
async function fresh(){try{const d=await req("/api/authenticator/refresh","POST",{});secret=d.secret;uri=d.provisioningUri;log("Simulated authenticator OTP:",d.authenticatorOtp);render(d.message)}catch(x){note(x.message,true)}}
(async()=>{try{const d=await req("/api/bootstrap");csrf=d.csrf;state.stage=d.authenticated?d.stage:"signed-in";if(d.authenticated){const x=await req("/api/state");state=x;csrf=x.csrf}render()}catch{app.textContent="We could not start secure setup. Please refresh the page."}})()})()</script></body></html>`;
}

const server = Bun.serve({
  hostname: "0.0.0.0",
  port: 3000,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(req) {
    try {
      const url = new URL(req.url);
      if (req.method === "OPTIONS") {
        const origin = req.headers.get("origin");
        if (!origin || !ORIGINS.has(origin)) return fail("This request is not allowed.", 403);
        const h = headers();
        h.set("Access-Control-Allow-Origin", origin);
        h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
        h.set("Vary", "Origin");
        return new Response(null, { status: 204, headers: h });
      }
      if (url.pathname === "/" && req.method === "GET") {
        const nonce = random(18), h = headers(true, nonce);
        return new Response(page(nonce), { headers: h });
      }
      if (url.pathname.startsWith("/api/")) return api(req, url.pathname);
      return fail("That page is not available.", 404);
    } catch {
      return fail("Something went wrong. Please try again.", 500);
    }
  }
});
console.log(`MFA demo HTTPS server running at https://localhost:${server.port}`);
