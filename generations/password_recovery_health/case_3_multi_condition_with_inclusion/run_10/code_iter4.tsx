
import { readFileSync } from "node:fs";

/*
 Password Recovery System — single-file Bun HTTPS server + vanilla HTML SPA.
 Security mappings: CSRF/session protection, random short-lived single-use tokens,
 bcrypt password hashes, throttling, CSP/HSTS/secure headers, and no private data output.
*/

type Stage = "start" | "requested" | "verified" | "mfa" | "passwordChanged" | "authenticated" | "privacyAccepted";
type Attempt = { count: number; until: number; last: number };
type Account = { id: string; identifier: string; passwordHash: string };
type Session = {
  id: string; csrf: string; expires: number; stage: Stage; accountId?: string;
  identifier?: string; resetToken?: string; manualCode?: string; resetExpires?: number;
  resetUsed?: boolean; mfaCode?: string; authenticated: boolean; privacyAccepted: boolean;
};

const sessions = new Map<string, Session>();
const attempts = new Map<string, Attempt>();
const RESET_MS = 10 * 60_000;
const SESSION_MS = 30 * 60_000;
const MFA_CODE = "246810";
const sinkId = "recovery-sink";
const hash = await Bun.password.hash("HospitalDemo!2026", { algorithm: "bcrypt" });
const accounts = new Map<string, Account>([
  ["account-helen", { id: "account-helen", identifier: "helena@example.com", passwordHash: hash }],
  [sinkId, { id: sinkId, identifier: "", passwordHash: hash }],
]);

function random(bytes = 32) {
  const a = new Uint8Array(bytes);
  crypto.getRandomValues(a);
  return Buffer.from(a).toString("base64url");
}
function newSession(): Session {
  return { id: random(), csrf: random(), expires: Date.now() + SESSION_MS, stage: "start", authenticated: false, privacyAccepted: false };
}
function cookie(req: Request) {
  return (req.headers.get("cookie") || "").match(/(?:^|;\s*)recovery_session=([A-Za-z0-9_-]{20,})/)?.[1];
}
function sessionFor(req: Request) {
  const id = cookie(req), old = id && sessions.get(id);
  if (old && old.expires > Date.now()) return { session: old, isNew: false };
  if (id) sessions.delete(id);
  const session = newSession(); sessions.set(session.id, session);
  return { session, isNew: true };
}
function headers(nonce: string) {
  return new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`,
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store, private", Pragma: "no-cache",
  });
}
function addCookie(h: Headers, s: Session, fresh: boolean) {
  if (fresh) h.append("Set-Cookie", `recovery_session=${s.id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${Math.max(1, Math.floor((s.expires - Date.now()) / 1000))}`);
}
function reply(body: Record<string, unknown>, s: Session, fresh: boolean, status = 200) {
  const h = headers(random(16)); h.set("Content-Type", "application/json; charset=utf-8"); addCookie(h, s, fresh);
  return new Response(JSON.stringify(body), { status, headers: h });
}
function plain(message: string, status: number) {
  const h = headers(random(16)); h.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(message, { status, headers: h });
}
function safeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
function validId(v: unknown): v is string { return typeof v === "string" && /^[A-Za-z0-9@._+\- ]{3,120}$/.test(v); }
function validCode(v: unknown): v is string { return typeof v === "string" && /^[A-Za-z0-9_-]{4,100}$/.test(v); }
function validPass(v: unknown): v is string { return typeof v === "string" && v.length >= 12 && v.length <= 128; }
function strong(v: string) { return /[a-z]/.test(v) && /[A-Z]/.test(v) && /[0-9]/.test(v) && /[^A-Za-z0-9]/.test(v); }
function find(identifier: string) {
  const id = identifier.trim().toLowerCase();
  for (const a of accounts.values()) if (a.identifier && safeEqual(a.identifier, id)) return a;
}
function ip(req: Request, server: any) {
  try { return String(server.requestIP(req)?.address || "unknown").replace(/[^0-9a-fA-F:.]/g, "").slice(0, 64) || "unknown"; } catch { return "unknown"; }
}
function key(action: string, id: string, source: string) { return action + "\0" + id + "\0" + source; }
function allowed(action: string, id: string, source: string) { return !attempts.get(key(action, id, source)) || attempts.get(key(action, id, source))!.until <= Date.now(); }
function fail(action: string, id: string, source: string) {
  const k = key(action, id, source), old = attempts.get(k) || { count: 0, until: 0, last: 0 };
  old.count++; old.last = Date.now(); old.until = old.last + [0, 1000, 5000, 30000, 60000, 300000][Math.min(5, old.count - 1)]; attempts.set(k, old);
}
function clear(action: string, id: string, source: string) { attempts.delete(key(action, id, source)); }
function state(s: Session) { return { stage: s.stage, csrf: s.csrf, authenticated: s.authenticated, privacyAccepted: s.privacyAccepted }; }
async function body(req: Request) {
  if (Number(req.headers.get("content-length") || 0) > 4096) return null;
  try { const v = await req.json(); return v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null; } catch { return null; }
}
function csrf(req: Request, s: Session, b: Record<string, unknown> | null) {
  const token = req.headers.get("x-csrf-token") || b?.csrf;
  return typeof token === "string" && safeEqual(token, s.csrf);
}
function reset(s: Session) {
  s.stage = "start"; s.accountId = undefined; s.identifier = undefined; s.resetToken = undefined; s.manualCode = undefined;
  s.resetExpires = undefined; s.resetUsed = false; s.mfaCode = undefined; s.authenticated = false; s.privacyAccepted = false;
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>Hospital account recovery</title>
<style nonce="${nonce}">
:root{--ink:#17324d;--blue:#075c9d;--line:#d5e0e8;--soft:#f3f8fb;--muted:#526679}*{box-sizing:border-box}body{margin:0;background:#f5f8fa;color:var(--ink);font:18px/1.5 system-ui,sans-serif}header{background:#fff;border-bottom:1px solid var(--line);padding:1rem}.inner,main{max-width:760px;margin:auto}.brand{font-weight:800}.sub,.small{color:var(--muted);font-size:.92rem}main{padding:1.5rem 1rem 3rem}.progress{display:flex;gap:.35rem;padding:0;margin:0 0 1.5rem;list-style:none}.progress li{flex:1;border-top:5px solid var(--line);padding-top:.3rem;text-align:center;color:var(--muted);font-size:.72rem}.progress .on{border-color:var(--blue);color:var(--blue);font-weight:bold}.card,.help,.logs{background:#fff;border:1px solid var(--line);border-radius:11px;padding:1.25rem;margin-top:1rem}h1{font-size:1.55rem;line-height:1.2;margin:.1rem 0 .7rem}.next{padding:.8rem;background:var(--soft);border-left:4px solid var(--blue)}label{font-weight:bold;display:block;margin:1rem 0 .25rem}input{font:inherit;width:100%;padding:.65rem;border:2px solid #9aabba;border-radius:7px}input:focus{outline:3px solid #82c6ef;border-color:var(--blue)}button{font:inherit;font-weight:bold;background:var(--blue);color:white;border:0;border-radius:7px;padding:.7rem 1rem;margin:1rem .4rem 0 0;cursor:pointer}.secondary{background:white;color:var(--blue);border:1px solid var(--blue)}.notice{padding:.75rem;border-radius:7px;margin:1rem 0}.error{background:#fff1ee;color:#7b250e}.success{background:#edfaf3;color:#176b47}#logList{color:var(--muted);overflow-wrap:anywhere}summary{font-weight:bold;cursor:pointer}
</style></head><body><header><div class="inner"><div class="brand">Hospital account access</div><div class="sub">A calm, guided recovery process</div></div></header><main>
<nav aria-label="Recovery progress"><ol class="progress" id="progress"><li>1. Request</li><li>2. Verify</li><li>3. Confirm</li><li>4. Sign in</li></ol></nav><section id="app" class="card" aria-live="polite">Preparing secure recovery…</section>
<aside class="help"><details><summary>Need help?</summary><p>You may pause and return later. This browser saves only your non-sensitive progress reminder. Recovery codes expire for security, but you can request a fresh code and continue whenever needed.</p><p>Hospital staff will never ask for your password or recovery code by email, phone, or message. Use a verified hospital phone number if you need help.</p></details></aside>
<section class="logs" aria-label="Logs"><strong>Logs</strong><ul id="logList"><li>Secure recovery page ready.</li></ul></section></main>
<script nonce="${nonce}">(()=>{"use strict";let S={stage:"start",csrf:"",authenticated:false,privacyAccepted:false},token="",A=document.querySelector("#app"),P=document.querySelector("#progress"),K="hospital-recovery-progress-v1";
const say=m=>{console.log(m);let x=document.createElement("li");x.textContent=m;document.querySelector("#logList").append(x)}, msg=(p,m,k="error")=>{let x=document.createElement("div");x.className="notice "+k;x.textContent=m;p.prepend(x)};
async function api(path,data={}){let r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":S.csrf},body:JSON.stringify(data)}),j={};try{j=await r.json()}catch{}if(!r.ok)throw Error(j.message||"Please try again.");if(j.csrf)S.csrf=j.csrf;return j}
const save=()=>localStorage.setItem(K,JSON.stringify({step:S.stage}));function shell(title,intro,next){A.replaceChildren();let h=document.createElement("h1"),p=document.createElement("p"),n=document.createElement("p");h.textContent=title;p.textContent=intro;n.className="next";n.textContent="Next step: "+next;A.append(h,p,n);let z=["requested","verified"].includes(S.stage)?2:["mfa","passwordChanged"].includes(S.stage)?3:["authenticated","privacyAccepted"].includes(S.stage)?4:1;P.querySelectorAll("li").forEach((x,i)=>x.classList.toggle("on",i<z))}
function field(f,label,type,name,hint=""){let l=document.createElement("label"),i=document.createElement("input");l.htmlFor=name;l.textContent=label;i.id=i.name=name;i.type=type;i.required=true;i.autocomplete=type==="password"?"new-password":"username";f.append(l,i);if(hint){let p=document.createElement("p");p.className="small";p.textContent=hint;f.append(p)}return i}function btn(text,type="submit"){let b=document.createElement("button");b.type=type;b.textContent=text;return b}
function fresh(){let b=btn("Get a fresh recovery code","button");b.className="secondary";b.onclick=async()=>{try{await api("/api/restart");localStorage.removeItem(K);S.stage="start";token="";say("Recovery restarted. You can request a fresh recovery code.");render()}catch(e){msg(A,e.message)}};return b}
function start(){shell("Reset your password","We will guide you one small step at a time. There is no rush while you use this page. Recovery codes do expire for security; a fresh code is always available.","Enter the account identifier you use for hospital access.");let f=document.createElement("form"),id=field(f,"Account identifier","text","identifier","For example, the email address or identifier you normally use.");f.append(btn("Request recovery code"));f.onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/recovery-request",{identifier:id.value});S.stage=r.stage;save();say("Recovery delivery simulation: server-accepted manual recovery code: "+r.manualRecoveryCode);say("Recovery delivery simulation: verification URL: "+r.verificationUrl);render()}catch(x){msg(f,x.message)}};A.append(f)}
function verify(){shell("Verify your recovery","Enter the server-accepted manual recovery code shown in the delivery simulation log. The code expires after 10 minutes for security. If it expires, choose Get a fresh recovery code; your progress reminder remains available.","Enter your recovery code, then select Verify code.");let f=document.createElement("form"),c=field(f,"Recovery code","text","code","Use the manual recovery code labelled “server-accepted” in the Logs panel.");if(token){let n=document.createElement("p");n.className="notice success";n.textContent="A recovery link was detected. You may verify it instead.";f.append(n);let b=btn("Verify recovery link","button");b.onclick=async()=>{try{let r=await api("/api/verify",{token});S.stage=r.stage;save();say("Recovery link verified.");say("MFA delivery simulation: confirmation code: "+r.testMfaCode);render()}catch(e){msg(f,e.message)}};f.append(b)}f.append(btn("Verify code"),fresh());f.onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/verify",{code:c.value});S.stage=r.stage;save();say("Recovery code verified.");say("MFA delivery simulation: confirmation code: "+r.testMfaCode);render()}catch(x){msg(f,x.message)}};A.append(f)}
function mfa(){shell("Confirm it is you","This extra confirmation helps protect your account.","Enter the six-digit confirmation code delivered after recovery verification.");let f=document.createElement("form"),c=field(f,"Confirmation code","text","mfa","Use the six-digit code shown in Logs.");f.append(btn("Confirm code"),fresh());f.onsubmit=async e=>{e.preventDefault();try{S.stage=(await api("/api/mfa",{code:c.value})).stage;save();say("MFA confirmation completed.");render()}catch(x){msg(f,x.message)}};A.append(f)}
function password(){shell("Choose a new password","Choose a private password. It is not stored in this browser or written to Logs.","Enter the same strong password twice.");let p=document.createElement("p");p.className="small";p.textContent="At least 12 characters, with uppercase, lowercase, a number, and a symbol.";let f=document.createElement("form"),a=field(f,"New password","password","newPassword"),b=field(f,"Repeat new password","password","repeatPassword");f.append(btn("Save new password"),fresh());f.onsubmit=async e=>{e.preventDefault();try{S.stage=(await api("/api/password-change",{password:a.value,repeat:b.value})).stage;save();say("Password changed securely. Password values were not logged.");render()}catch(x){msg(f,x.message)}};A.append(p,f)}
function login(){shell("Sign in with your new password","Your password reset is complete. Sign in to review updated privacy conditions.","Enter your normal account identifier and your new password.");let f=document.createElement("form"),i=field(f,"Account identifier","text","loginId"),p=field(f,"New password","password","loginPassword");p.autocomplete="current-password";f.append(btn("Sign in"));f.onsubmit=async e=>{e.preventDefault();try{let r=await api("/api/login",{identifier:i.value,password:p.value});S.stage=r.stage;S.authenticated=true;localStorage.removeItem(K);say("Secure sign-in completed.");render()}catch(x){msg(f,x.message)}};A.append(f)}
function privacy(){shell("Review privacy conditions","You are signed in. Confirm that you have reviewed the updated privacy conditions so hospital staff can continue appointment support.","Select Confirm privacy conditions when ready.");let p=document.createElement("p");p.textContent="This demonstration does not display patient records or private details.";let b=btn("Confirm privacy conditions","button");b.onclick=async()=>{try{let r=await api("/api/privacy-confirm");S.stage=r.stage;S.privacyAccepted=true;say("Privacy conditions confirmed.");render()}catch(e){msg(A,e.message)}};A.append(p,b)}
function done(){shell("Confirmation complete","The updated privacy conditions have been confirmed.","You may safely close this page.");let p=document.createElement("p");p.className="notice success";p.textContent="Your recovery task is complete.";A.append(p)}
function render(){({start,requested:verify,verified:mfa,mfa:password,passwordChanged:login,authenticated:privacy,privacyAccepted:done}[S.stage]||start)()}async function load(){let r=await fetch("/api/state",{credentials:"same-origin",cache:"no-store"});if(!r.ok)throw Error();S=await r.json();token=new URLSearchParams(location.search).get("token")||"";try{if(JSON.parse(localStorage.getItem(K)||"{}").step&&S.stage==="start")say("A saved recovery reminder is available. You may continue or request a fresh code.")}catch{}render()}load().catch(()=>A.textContent="This secure page could not be prepared. Please refresh and try again.")})();</script></body></html>`;
}

async function api(req: Request, s: Session, fresh: boolean, path: string, source: string): Promise<Response> {
  if (path === "/api/state" && req.method === "GET") return reply(state(s), s, fresh);
  if (req.method !== "POST") return reply({ message: "Request not available." }, s, fresh, 405);
  const b = await body(req);
  if (!b || !csrf(req, s, b)) return reply({ message: "This secure form needs to be refreshed before continuing." }, s, fresh, 403);

  if (path === "/api/restart") { reset(s); return reply(state(s), s, fresh); }

  if (path === "/api/recovery-request") {
    const identifier = validId(b.identifier) ? b.identifier.trim().toLowerCase() : "unknown";
    if (!allowed("recovery", identifier, source)) return reply({ message: "Too many requests. Please pause briefly, then try again." }, s, fresh, 429);
    if (!validId(b.identifier)) { fail("recovery", identifier, source); return reply({ message: "Enter the account identifier using letters, numbers, and standard email characters." }, s, fresh, 400); }
    const account = find(identifier);
    s.accountId = account?.id || sinkId; s.identifier = identifier; s.stage = "requested"; s.resetUsed = false;
    s.resetToken = random(32);
    /*
      Task fix: the endpoint returns manualRecoveryCode and this exact stored value
      is accepted by /api/verify when submitted as { code }.
    */
    s.manualCode = random(18);
    s.resetExpires = Date.now() + RESET_MS; s.mfaCode = undefined; s.authenticated = false; s.privacyAccepted = false;
    clear("recovery", identifier, source);
    return reply({ stage: s.stage, manualRecoveryCode: s.manualCode, verificationUrl: `https://localhost:3000/verify?token=${encodeURIComponent(s.resetToken)}` }, s, fresh);
  }

  if (path === "/api/verify") {
    const id = s.identifier || "unknown";
    if (!allowed("verify", id, source)) return reply({ message: "Too many attempts. Please pause briefly, then try again." }, s, fresh, 429);
    if (s.stage !== "requested" || s.resetUsed || !s.accountId || !s.resetExpires || Date.now() > s.resetExpires) {
      fail("verify", id, source);
      return reply({ message: "This recovery code has expired or is no longer available. Choose Get a fresh recovery code to continue." }, s, fresh, 400);
    }
    const codeOK = validCode(b.code) && safeEqual(b.code, s.manualCode || "");
    const tokenOK = validCode(b.token) && safeEqual(b.token, s.resetToken || "");
    if (!codeOK && !tokenOK) { fail("verify", id, source); return reply({ message: "That code could not be verified. Check the server-accepted code in Logs, or get a fresh code." }, s, fresh, 400); }
    clear("verify", id, source); s.resetUsed = true; s.resetToken = undefined; s.manualCode = undefined; s.stage = "verified"; s.mfaCode = MFA_CODE;
    return reply({ stage: s.stage, testMfaCode: MFA_CODE }, s, fresh);
  }

  if (path === "/api/mfa") {
    const id = s.identifier || "unknown";
    if (!allowed("mfa", id, source)) return reply({ message: "Too many attempts. Please pause briefly, then try again." }, s, fresh, 429);
    if (s.stage !== "verified" || !validCode(b.code) || !safeEqual(b.code, s.mfaCode || "")) { fail("mfa", id, source); return reply({ message: "That confirmation code could not be verified. Please try again." }, s, fresh, 400); }
    clear("mfa", id, source); s.stage = "mfa"; return reply({ stage: s.stage }, s, fresh);
  }

  if (path === "/api/password-change") {
    const id = s.identifier || "unknown", account = s.accountId && accounts.get(s.accountId);
    if (!allowed("password", id, source)) return reply({ message: "Too many attempts. Please pause briefly, then try again." }, s, fresh, 429);
    if (s.stage !== "mfa" || !account || !s.resetExpires || Date.now() > s.resetExpires) { fail("password", id, source); return reply({ message: "This secure reset step has expired. Choose Get a fresh recovery code to continue." }, s, fresh, 400); }
    if (!validPass(b.password) || !validPass(b.repeat) || b.password !== b.repeat || !strong(b.password)) { fail("password", id, source); return reply({ message: "Passwords must match, be 12–128 characters, and include uppercase, lowercase, a number, and a symbol." }, s, fresh, 400); }
    account.passwordHash = await Bun.password.hash(b.password, { algorithm: "bcrypt" }); s.mfaCode = undefined; s.resetExpires = undefined; s.stage = "passwordChanged"; clear("password", id, source);
    return reply({ stage: s.stage }, s, fresh);
  }

  if (path === "/api/login") {
    const id = validId(b.identifier) ? b.identifier.trim().toLowerCase() : "unknown", bound = s.accountId && accounts.get(s.accountId), entered = validId(b.identifier) ? find(b.identifier) : undefined;
    if (!allowed("login", id, source)) return reply({ message: "Too many sign-in attempts. Please pause briefly, then try again." }, s, fresh, 429);
    if (s.stage !== "passwordChanged" || !validPass(b.password) || !bound || !entered || entered.id !== bound.id || bound.id === sinkId || !await Bun.password.verify(b.password, bound.passwordHash)) {
      fail("login", id, source); return reply({ message: "The sign-in details could not be confirmed. Please try again." }, s, fresh, 400);
    }
    clear("login", id, source); s.authenticated = true; s.stage = "authenticated"; return reply(state(s), s, fresh);
  }

  if (path === "/api/privacy-confirm") {
    if (!s.authenticated || s.stage !== "authenticated") return reply({ message: "Please sign in before confirming privacy conditions." }, s, fresh, 403);
    s.privacyAccepted = true; s.stage = "privacyAccepted"; return reply(state(s), s, fresh);
  }
  return reply({ message: "Request not available." }, s, fresh, 404);
}

const cert = readFileSync("certs/cert.pem");
const key = readFileSync("certs/key.pem");

Bun.serve({
  port: 3000, hostname: "0.0.0.0", tls: { cert, key },
  async fetch(req, server) {
    try {
      if (req.headers.get("x-forwarded-proto") === "http") return plain("HTTPS is required.", 400);
      const now = Date.now();
      for (const [id, s] of sessions) if (s.expires <= now) sessions.delete(id);
      for (const [k, a] of attempts) if (a.last + 15 * 60_000 < now && a.until <= now) attempts.delete(k);
      const url = new URL(req.url), { session, isNew } = sessionFor(req);
      if (url.pathname.startsWith("/api/")) return await api(req, session, isNew, url.pathname, ip(req, server));
      if (req.method === "GET" && ["/", "/verify", "/recovery"].includes(url.pathname)) {
        const nonce = random(16), h = headers(nonce); h.set("Content-Type", "text/html; charset=utf-8"); addCookie(h, session, isNew);
        return new Response(page(nonce), { headers: h });
      }
      return plain("Page not found.", 404);
    } catch { return plain("The secure service is temporarily unavailable.", 503); }
  },
});

console.log("Secure recovery service running at https://localhost:3000");
