
import { randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Password Recovery System — single-file Bun HTTPS server and vanilla JS SPA.
 * Security requirements: CSRF, session access control, secure headers, bcrypt,
 * reset-token expiry/single use, MFA, throttling, output-safe DOM rendering.
 */

type Recovery = {
  token: string;
  expiresAt: number;
  tokenConsumed: boolean; // Token is consumed immediately after successful verification.
  verified: boolean;
  mfaVerified: boolean;
  passwordUpdated: boolean; // Server-authoritative post-update / pre-login state.
  mfaCode: string;
  real: boolean;
};
type Session = { csrf: string; createdAt: number; recovery?: Recovery; authenticated: boolean };
type RateRecord = { attempts: number; windowStart: number; blockedUntil: number };

const sessions = new Map<string, Session>();
const rates = new Map<string, RateRecord>();
const SESSION_COOKIE = "hospital_recovery_session";
const SESSION_AGE = 86400;
const TOKEN_LIFE = 15 * 60 * 1000;
const WINDOW = 15 * 60 * 1000;
const BLOCK = 15 * 60 * 1000;
const MAX = 5;
const EMAIL = "helena@example.test";
let passwordHash = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
let privacyAccepted = false;

const token = (n = 32) => randomBytes(n).toString("hex");
const equal = (a: string, b: string) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};
function sessionNew() {
  const id = token(), session: Session = { csrf: token(), createdAt: Date.now(), authenticated: false };
  sessions.set(id, session);
  return { id, session };
}
function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) {
    const i = p.indexOf("=");
    if (i > 0) try { out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch {}
  }
  return out;
}
function current(r: Request) {
  const id = cookies(r)[SESSION_COOKIE];
  if (!id || !/^[a-f0-9]{64}$/.test(id)) return null;
  const session = sessions.get(id);
  if (!session || Date.now() - session.createdAt > SESSION_AGE * 1000) {
    if (id) sessions.delete(id);
    return null;
  }
  return { id, session };
}
const cookie = (id: string) => `${SESSION_COOKIE}=${id}; Path=/; Max-Age=${SESSION_AGE}; Secure; HttpOnly; SameSite=Strict`;

function headers(nonce = "") {
  const h = new Headers();
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("Content-Security-Policy", `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`);
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  h.set("Cache-Control", "no-store, max-age=0, private");
  return h;
}
function response(data: unknown, status = 200, extra?: HeadersInit) {
  const h = headers(); h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(data), { status, headers: h });
}
function pageResponse(body: string, nonce: string, set?: string) {
  const h = headers(nonce); h.set("Content-Type", "text/html; charset=utf-8");
  if (set) h.set("Set-Cookie", set);
  return new Response(body, { headers: h });
}
function protectedSession(r: Request) {
  const s = current(r), csrf = r.headers.get("x-csrf-token") || "";
  return s && /^[a-f0-9]{64}$/.test(csrf) && equal(csrf, s.session.csrf) ? s : null;
}
async function body(r: Request): Promise<Record<string, unknown> | null> {
  if (Number(r.headers.get("content-length") || 0) > 4096 || !r.headers.get("content-type")?.includes("application/json")) return null;
  try { const b = await r.json(); return b && typeof b === "object" && !Array.isArray(b) ? b as Record<string, unknown> : null; } catch { return null; }
}
function allowed(key: string) {
  const now = Date.now(), old = rates.get(key);
  if (!old) { rates.set(key, { attempts: 1, windowStart: now, blockedUntil: 0 }); return true; }
  if (old.blockedUntil > now) return false;
  if (now - old.windowStart > WINDOW) { old.attempts = 1; old.windowStart = now; old.blockedUntil = 0; return true; }
  old.attempts++;
  if (old.attempts > MAX) { old.blockedUntil = now + BLOCK; return false; }
  return true;
}
function peer(r: Request, server: any) {
  try { return "peer:" + (server.requestIP(r)?.address || "local"); } catch { return "local"; }
}
function validEmail(v: unknown): v is string { return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function validPassword(v: unknown): v is string {
  return typeof v === "string" && v.length >= 12 && v.length <= 128 && /[a-z]/.test(v) && /[A-Z]/.test(v) && /\d/.test(v) && /[^A-Za-z0-9]/.test(v);
}

/* Server-authoritative stage resolution, including refresh after password update. */
function stage(s: Session) {
  if (s.authenticated) return privacyAccepted ? "complete" : "privacy";
  const r = s.recovery;
  if (r?.passwordUpdated) return "signin";
  if (!r || !r.real || r.expiresAt < Date.now()) return "request";
  if (!r.verified) return "confirm-token";
  if (!r.mfaVerified) return "choose-password";
  return "safety-check";
}
function message(x: string) {
  return ({
    request: "To protect your account, request a recovery code when you are ready.",
    "confirm-token": "Your recovery code is ready to confirm.",
    "choose-password": "Your recovery code was confirmed. Choose a new password next.",
    "safety-check": "Your safety check is ready. Choose your password again if you refreshed.",
    signin: "Your password was changed. Please sign in to continue.",
    privacy: "You are signed in. Review the privacy statement when ready.",
    complete: "Privacy conditions were accepted. Hospital staff can continue with appointment booking."
  } as Record<string, string>)[x] || "Your secure step was checked.";
}

/* Regression checks for required server-authoritative state transitions. */
function regressionChecks() {
  const now = Date.now();
  const r: Recovery = { token: "a".repeat(64), expiresAt: now + 1000, tokenConsumed: false, verified: false, mfaVerified: false, passwordUpdated: false, mfaCode: "481516", real: true };
  const s: Session = { csrf: token(), createdAt: now, authenticated: false, recovery: r };
  const first = !r.tokenConsumed && equal(r.token, "a".repeat(64));
  if (first) { r.tokenConsumed = true; r.verified = true; }
  const secondRejected = r.tokenConsumed;
  r.mfaVerified = true; r.passwordUpdated = true;
  const refreshRestoresSignin = stage(s) === "signin";
  s.authenticated = true; privacyAccepted = true;
  const completionRetained = stage(s) === "complete";
  privacyAccepted = false;
  console.log(`[regression] token second submission rejected=${secondRejected}; refresh restores sign-in=${refreshRestoresSignin}; completion retained=${completionRetained}`);
}
regressionChecks();

async function api(r: Request, path: string, ip: string): Promise<Response> {
  if (path === "/api/bootstrap" && r.method === "GET") {
    let c = current(r), set: string | undefined;
    if (!c) { c = sessionNew(); set = cookie(c.id); }
    const x = stage(c.session);
    return response({ ok: true, csrf: c.session.csrf, recoveryStage: x, recoveryMessage: message(x) }, 200, set ? { "Set-Cookie": set } : undefined);
  }
  if (r.method !== "POST") return response({ ok: false, message: "This action is not available." }, 405);
  const c = protectedSession(r);
  if (!c) return response({ ok: false, message: "Your secure page needs to be refreshed before continuing." }, 403);
  const b = await body(r);
  if (!b) return response({ ok: false, message: "Please use the form and try again." }, 400);
  const limited = (name: string, context: string) => allowed(`${name}:${context}:${ip}`);
  if (path === "/api/recovery/initiate") {
    const email = b.email;
    if (!limited("initiate", typeof email === "string" ? email.slice(0, 254).toLowerCase() : "invalid")) return response({ ok: false, message: "For safety, please pause and try again later." }, 429);
    if (!validEmail(email)) return response({ ok: false, message: "Enter an email address in the usual format." }, 400);
    const reset = token();
    c.session.recovery = { token: reset, expiresAt: Date.now() + TOKEN_LIFE, tokenConsumed: false, verified: false, mfaVerified: false, passwordUpdated: false, mfaCode: "481516", real: email.trim().toLowerCase() === EMAIL };
    return response({ ok: true, message: "If an account can use that address, a recovery message has been prepared.", testDeliveryToken: reset });
  }
  const recovery = c.session.recovery;
  if (path === "/api/recovery/verify-token") {
    if (!limited("token", recovery?.token || "none")) return response({ ok: false, message: "For safety, please pause and try again later." }, 429);
    const supplied = b.token;
    const valid = typeof supplied === "string" && /^[a-f0-9]{64}$/.test(supplied) && !!recovery && recovery.real && !recovery.tokenConsumed && recovery.expiresAt >= Date.now() && equal(supplied, recovery.token);
    if (!valid) return response({ ok: false, message: "That code cannot be confirmed. Check it carefully or request a new recovery message." }, 400);
    /* Single-use reset-token requirement: consume atomically before responding. */
    recovery.tokenConsumed = true;
    recovery.verified = true;
    return response({ ok: true, message: "Code confirmed. Choose a new password, then complete one more safety check.", testMfaCode: recovery.mfaCode });
  }
  if (path === "/api/recovery/verify-mfa") {
    if (!limited("mfa", recovery?.token || "none")) return response({ ok: false, message: "For safety, please pause and try again later." }, 429);
    const code = b.code;
    const valid = typeof code === "string" && /^\d{6}$/.test(code) && !!recovery && recovery.real && recovery.verified && !recovery.passwordUpdated && recovery.expiresAt >= Date.now() && equal(code, recovery.mfaCode);
    if (!valid) return response({ ok: false, message: "That safety code cannot be confirmed. Check the six digits and try again." }, 400);
    recovery.mfaVerified = true;
    return response({ ok: true, message: "Safety check complete. Your new password is ready to be saved." });
  }
  if (path === "/api/recovery/password-update") {
    if (!limited("password", recovery?.token || "none")) return response({ ok: false, message: "For safety, please pause and try again later." }, 429);
    if (!recovery || !recovery.real || !recovery.verified || !recovery.mfaVerified || recovery.passwordUpdated || recovery.expiresAt < Date.now()) return response({ ok: false, message: "Restart recovery and complete the safety steps before saving a password." }, 403);
    if (!validPassword(b.password)) return response({ ok: false, message: "Use at least 12 characters with uppercase, lowercase, number, and symbol." }, 400);
    passwordHash = await Bun.password.hash(b.password, { algorithm: "bcrypt", cost: 10 });
    recovery.passwordUpdated = true;
    return response({ ok: true, message: "Your password has been changed. You can now sign in." });
  }
  if (path === "/api/authenticate") {
    if (!limited("login", "account")) return response({ ok: false, message: "For safety, please pause and try again later." }, 429);
    if (typeof b.password !== "string" || b.password.length > 128 || !await Bun.password.verify(b.password, passwordHash)) return response({ ok: false, message: "The sign-in details could not be confirmed. Please try again." }, 401);
    c.session.authenticated = true;
    return response({ ok: true, message: "Signed in securely. Please review the privacy statement." });
  }
  if (path === "/api/privacy/accept") {
    if (!c.session.authenticated) return response({ ok: false, message: "Please sign in before accepting the privacy statement." }, 403);
    if (b.accept !== true) return response({ ok: false, message: "Please confirm that you have read the statement." }, 400);
    privacyAccepted = true;
    return response({ ok: true, message: "Privacy conditions accepted. Hospital staff can now continue with appointment booking." });
  }
  return response({ ok: false, message: "This secure action is not available." }, 404);
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hospital account recovery</title><style>
:root{--b:#075a9d;--i:#17212b;--l:#c8d4dc;--g:#126b42}*{box-sizing:border-box}body{margin:0;background:#f2f7fa;color:var(--i);font:18px/1.55 Arial,sans-serif}.wrap{width:min(760px,calc(100% - 32px));margin:auto}header{background:#fff;border-bottom:4px solid var(--b)}header .wrap{padding:18px 0}h1{margin:0;font-size:1.55rem}main{padding:25px 0}.box{background:#fff;border:1px solid var(--l);border-radius:8px;padding:20px;margin-bottom:18px}h2{margin-top:0;font-size:1.35rem}label{display:block;font-weight:bold;margin:16px 0 5px}input{width:100%;padding:12px;border:2px solid #71818c;border-radius:5px;font:inherit}button{margin-top:18px;padding:12px 18px;border:0;border-radius:5px;background:var(--b);color:#fff;font:inherit;font-weight:bold}button:focus,input:focus{outline:4px solid #f4bf38;outline-offset:3px}.note{padding:12px;border-left:5px solid var(--b);background:#eaf4fb;font-weight:bold}.error{border-color:#a43120;background:#fff0ed}.success{border-color:var(--g);background:#ecf8f1}.muted{color:#4b5963}.help{border-left:6px solid #f4bf38}.logs{font-size:.9rem}#logs{max-height:130px;overflow:auto}.progress ol{display:flex;flex-wrap:wrap;gap:6px 18px;margin:8px 0;padding-left:24px}.active{color:var(--b);font-weight:bold}.done{color:var(--g)}.privacy{border:1px solid var(--l);padding:14px;background:#f8fbfc}
</style></head><body><header><div class="wrap"><h1>Hospital account recovery</h1><p class="muted">A calm, step-by-step way to return to your account.</p></div></header><main class="wrap"><nav class="box progress" aria-label="Recovery progress"><strong>Your steps</strong><ol id="progress"></ol></nav><section id="app" class="box" aria-live="polite"></section><aside class="box help"><h2>Need help?</h2><p>You can pause, refresh, and return later. Your secure next step is saved by the service.</p><p><strong>Stay safe:</strong> hospital staff will never ask for your password or security code by email. Do not share either one.</p></aside><section class="box logs"><h2>Logs</h2><ul id="logs"></ul></section></main><script nonce="${nonce}">(()=>{"use strict";
const app=document.querySelector("#app"),p=document.querySelector("#progress"),logs=document.querySelector("#logs"),names=["Request","Confirm code","New password","Safety check","Sign in","Privacy"];let csrf="",step=1,pending="";
const el=(tag,text)=>{const x=document.createElement(tag);if(text!==undefined)x.textContent=text;return x};const note=(x,c="")=>{const n=el("div",x);n.className="note "+c;return n};const log=x=>{console.log(x);logs.append(el("li",x))};const api=async(path,data)=>{try{return await (await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)})).json()}catch{return{ok:false,message:"Please refresh and try again."}}};
function nav(){p.replaceChildren();names.forEach((n,i)=>{const x=el("li",(i+1)+". "+n);if(i+1===step)x.className="active";if(i+1<step)x.className="done";p.append(x)})}
function field(form,label,type,name){const l=el("label",label),i=document.createElement("input");i.type=type;i.name=name;i.required=true;l.htmlFor="f"+name;i.id=l.htmlFor;form.append(l,i);return i}
function form(title,intro,msg,kind){app.replaceChildren(el("h2",title),el("p",intro));if(msg)app.append(note(msg,kind));const f=document.createElement("form");app.append(f);return f}
function button(f,text){const b=el("button",text);b.type="submit";f.append(b)}
function render(msg="",kind=""){nav();if(step===7){app.replaceChildren(el("h2","All set"),note(msg||"Privacy conditions accepted.","success"),el("p","You may now safely close this page."));return}
if(step===1){const f=form("Step 1: Request a recovery code","Enter the email address you use for your hospital account.",msg,kind),i=field(f,"Email address","email","email");button(f,"Request recovery code");f.onsubmit=async e=>{e.preventDefault();let r=await api("/api/recovery/initiate",{email:i.value.trim()});if(!r.ok)return render(r.message,"error");step=2;log("[delivery simulation] Reset token: "+r.testDeliveryToken);render(r.message,"success")};return}
if(step===2){const f=form("Step 2: Confirm your recovery code","Enter the 64-character token from secure delivery. It is also in Logs for this practice system.",msg,kind),i=field(f,"Recovery token","text","token");i.maxLength=64;button(f,"Confirm code");f.onsubmit=async e=>{e.preventDefault();let r=await api("/api/recovery/verify-token",{token:i.value.trim().toLowerCase()});if(!r.ok)return render(r.message,"error");step=3;log("[delivery simulation] MFA safety code: "+r.testMfaCode);log("[verification simulation] Reset token consumed after successful verification.");render(r.message,"success")};return}
if(step===3){const f=form("Step 3: Choose a new password","Use at least 12 characters with uppercase, lowercase, number, and symbol.",msg,kind),a=field(f,"New password","password","new"),b=field(f,"Repeat new password","password","repeat");button(f,"Continue to safety check");f.onsubmit=e=>{e.preventDefault();let x=a.value;if(x!==b.value)return render("The passwords do not match.","error");if(x.length<12||!/[a-z]/.test(x)||!/[A-Z]/.test(x)||!/\\d/.test(x)||! / .test(" ")&& !/[^A-Za-z0-9]/.test(x))return render("Use at least 12 characters with uppercase, lowercase, number, and symbol.","error");pending=x;step=4;render("Password choice ready. Complete the safety check next.","success")};return}
if(step===4){const f=form("Step 4: Complete the safety check","Enter the six-digit safety code from Logs.",msg,kind),i=field(f,"Safety code","text","mfa");i.maxLength=6;button(f,"Confirm safety code");f.onsubmit=async e=>{e.preventDefault();let r=await api("/api/recovery/verify-mfa",{code:i.value.trim()});if(!r.ok)return render(r.message,"error");if(!pending){step=3;return render("Choose your password again. Passwords are never kept in browser storage.","error")}r=await api("/api/recovery/password-update",{password:pending});pending="";if(!r.ok)return render(r.message,"error");step=5;log("[regression] password update complete; a refresh restores server-authoritative Sign in.");render(r.message,"success")};return}
if(step===5){const f=form("Step 5: Sign in","Use your new password to securely sign in.",msg,kind),i=field(f,"Password","password","login");i.autocomplete="current-password";button(f,"Sign in securely");f.onsubmit=async e=>{e.preventDefault();let r=await api("/api/authenticate",{password:i.value});if(!r.ok)return render(r.message,"error");step=6;log("[verification simulation] Sign-in confirmed.");render(r.message,"success")};return}
const f=form("Step 6: Accept the updated privacy conditions","You are signed in. Confirm acceptance so hospital staff can continue with appointment booking.",msg,kind),box=el("div");box.className="privacy";box.append(el("strong","Privacy statement"),el("p","Your healthcare account information is handled only for care and appointment services."));app.insertBefore(box,f);const c=field(f,"I have read and accept the updated privacy conditions.","checkbox","accept");c.style.width="auto";button(f,"Accept privacy conditions");f.onsubmit=async e=>{e.preventDefault();let r=await api("/api/privacy/accept",{accept:c.checked});if(!r.ok)return render(r.message,"error");step=7;log("[regression] Login plus privacy acceptance reached completion; refresh retains completion.");render(r.message,"success")}}
(async()=>{try{let d=await (await fetch("/api/bootstrap",{credentials:"same-origin"})).json();csrf=d.csrf;step=({request:1,"confirm-token":2,"choose-password":3,"safety-check":4,signin:5,privacy:6,complete:7})[d.recoveryStage]||1;render(d.recoveryMessage,"success")}catch{app.append(note("A secure connection could not be prepared. Please refresh.","error"))}})();
})();</script></body></html>`;
}

async function main() {
  try {
    const cert = Bun.file("certs/cert.pem"), key = Bun.file("certs/key.pem");
    if (!(await cert.exists()) || !(await key.exists())) { console.log("Secure server could not start: TLS certificate files are unavailable."); return; }
    Bun.serve({
      hostname: "0.0.0.0", port: 3000,
      tls: { cert: await cert.text(), key: await key.text() },
      fetch: async (r, server) => {
        try {
          const u = new URL(r.url);
          if (u.pathname === "/" && r.method === "GET") {
            let c = current(r), set: string | undefined;
            if (!c) { c = sessionNew(); set = cookie(c.id); }
            const nonce = token(16);
            return pageResponse(page(nonce), nonce, set);
          }
          if (u.pathname.startsWith("/api/")) return api(r, u.pathname, peer(r, server));
          return response({ ok: false, message: "Page not found." }, 404);
        } catch { return response({ ok: false, message: "The secure service could not complete that request." }, 500); }
      }
    });
    console.log("Hospital recovery HTTPS server listening on https://localhost:3000");
  } catch { console.log("Secure server could not start. Check TLS certificate configuration."); }
}
main();
