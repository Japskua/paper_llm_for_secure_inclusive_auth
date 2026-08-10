
import { readFileSync } from "node:fs";

/*
 MFA Enrolment System — Bun HTTPS server and mobile SPA.
 Security requirements:
 - Account ownership is always derived from the HttpOnly session, never client IDs.
 - State changes require SameSite session, trusted Origin, and CSRF token.
 - Demo values are deterministic only for this academic mock; stored values remain
   encrypted (authenticator secret) or salted PBKDF2 hashes (password/recovery codes).
*/

const PORT = 3000;
const cert = readFileSync("certs/cert.pem", "utf8");
const key = readFileSync("certs/key.pem", "utf8");

const ACCOUNT_ID = "acct_marcus_001";
const ACCOUNT_EMAIL = "marcus@example.com";
const ACCOUNT_PHONE = "+15551234567";

/*
 Academic-demo values, intentionally documented and deterministic:
 Password: MarcusDemo!42
 Identity OTP: 482913
 Authenticator secret: JBSWY3DPEHPK3PXP
 Authenticator verification OTP: 654321
 Recovery codes: A1B2-C3D4 through Q1W2-E3R4
 They are never written to server logs or the visible Logs panel.
*/
const DEMO_PASSWORD = "MarcusDemo!42";
const DEMO_IDENTITY_OTP = "482913";
const DEMO_AUTH_SECRET = "JBSWY3DPEHPK3PXP";
const DEMO_AUTH_OTP = "654321";
const DEMO_RECOVERY_CODES = [
  "A1B2-C3D4", "E5F6-G7H8", "J9K2-L3M4", "N5P6-Q7R8",
  "S9T2-U3V4", "W5X6-Y7Z8", "B2C3-D4E5", "Q1W2-E3R4",
];

const encKey = await crypto.subtle.generateKey(
  { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
);

type RecoveryValue = { salt: string; value: string };
type Account = {
  id: string;
  email: string;
  normalizedPhone: string;
  passwordSalt: string;
  passwordValue: string;
  mfaSecretEncrypted?: string;
  mfaEnabled: boolean;
  backupCodeValues: RecoveryValue[];
};
type Session = {
  token: string;
  csrf: string;
  userId: string | null;
  stage: "preauth" | "signedin" | "verified";
  createdAt: number;
  lastSeen: number;
  expiresAt: number;
  invalidated?: boolean;
  identityCode?: string;
  identityCodeUsed?: boolean;
  identityCodeExpires?: number;
  identityFailures: number;
  identityLockedUntil?: number;
  otpFailures: number;
  otpLockedUntil?: number;
  otpUsed?: boolean;
  recoveryFailures: number;
  recoveryLockedUntil?: number;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const absoluteMs = 8 * 60 * 60 * 1000;
const idleMs = 20 * 60 * 1000;
const codeMs = 10 * 60 * 1000;
const lockMs = 10 * 60 * 1000;
const trusted = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

function bytes(n: number) {
  const value = new Uint8Array(n);
  crypto.getRandomValues(value);
  return value;
}
function b64(value: Uint8Array) {
  let text = "";
  for (const byte of value) text += String.fromCharCode(byte);
  return btoa(text);
}
function token(n = 32) {
  return b64(bytes(n)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function constantEqual(a: string, b: string) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let different = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    different |= (x[i] || 0) ^ (y[i] || 0);
  }
  return different === 0;
}
async function encrypt(value: string) {
  const iv = bytes(12);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, encKey, new TextEncoder().encode(value),
  );
  return b64(iv) + "." + b64(new Uint8Array(encrypted));
}
async function credentialValue(value: string, salt: string) {
  const material = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(value), "PBKDF2", false, ["deriveBits"],
  );
  const output = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    hash: "SHA-256",
    salt: new TextEncoder().encode(salt),
    iterations: 210000,
  }, material, 256);
  return b64(new Uint8Array(output));
}
async function recoveryValue(code: string, salt: string) {
  return credentialValue(code, salt);
}
async function demoRecoveryValues() {
  const values: RecoveryValue[] = [];
  for (let i = 0; i < DEMO_RECOVERY_CODES.length; i++) {
    const salt = `academic-demo-recovery-salt-${i}`;
    values.push({ salt, value: await recoveryValue(DEMO_RECOVERY_CODES[i], salt) });
  }
  return values;
}

const passwordSalt = "academic-demo-password-salt-v1";
accounts.set(ACCOUNT_ID, {
  id: ACCOUNT_ID,
  email: ACCOUNT_EMAIL,
  normalizedPhone: ACCOUNT_PHONE,
  passwordSalt,
  passwordValue: await credentialValue(DEMO_PASSWORD, passwordSalt),
  mfaEnabled: false,
  backupCodeValues: [],
});

function normalizePhone(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 32) return null;
  const trimmed = value.trim();
  if (!/^\+?[0-9 ()-]{7,24}$/.test(trimmed)) return null;
  const digits = trimmed.replace(/\D/g, "");
  if (digits.length < 8 || digits.length > 15) return null;
  return "+" + digits;
}
function validEmail(value: unknown): value is string {
  return typeof value === "string" &&
    /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$/.test(value);
}
function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function validManualSecret(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-7]{16,64}$/.test(value);
}
function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(value);
}

function cookies(request: Request) {
  const all: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0) all[part.slice(0, at).trim()] = part.slice(at + 1).trim();
  }
  return all;
}
function sessionCookie(value: string, active = true) {
  return `__Host-mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; ${
    active ? `Max-Age=${absoluteMs / 1000}` : "Max-Age=0"
  }`;
}
function makeSession(stage: Session["stage"], userId: string | null) {
  const now = Date.now();
  const session: Session = {
    token: token(),
    csrf: token(24),
    userId,
    stage,
    createdAt: now,
    lastSeen: now,
    expiresAt: now + absoluteMs,
    identityFailures: 0,
    otpFailures: 0,
    recoveryFailures: 0,
  };
  sessions.set(session.token, session);
  return session;
}
function current(request: Request) {
  const id = cookies(request).__Host-mfa_session;
  const session = id ? sessions.get(id) : undefined;
  const now = Date.now();
  if (!session || session.invalidated || session.expiresAt < now || session.lastSeen + idleMs < now) {
    if (id) sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function originOK(request: Request) {
  const origin = request.headers.get("origin");
  return !origin || trusted.has(origin);
}
function headers(request: Request, nonce = token(18)) {
  const result = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
  });
  const origin = request.headers.get("origin");
  if (origin && trusted.has(origin)) {
    result.set("Access-Control-Allow-Origin", origin);
    result.set("Access-Control-Allow-Credentials", "true");
    result.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    result.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    result.set("Vary", "Origin");
  }
  return result;
}
function reply(request: Request, data: unknown, status = 200, extra?: HeadersInit) {
  const result = headers(request);
  result.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => result.set(k, v));
  return new Response(JSON.stringify(data), { status, headers: result });
}
function fail(request: Request, status: number, message: string) {
  return reply(request, { ok: false, message }, status);
}
function csrf(request: Request, session: Session) {
  return constantEqual(request.headers.get("x-csrf-token") || "", session.csrf);
}
function isResponse(value: unknown): value is Response {
  return value instanceof Response;
}
/* Broken access control protection: user identity always comes only from the session. */
function owner(request: Request, needed: Session["stage"] = "verified"):
  { session: Session; account: Account } | Response {
  if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
  const session = current(request);
  if (!session || session.stage !== needed || !session.userId) {
    return fail(request, 401, "Please sign in again.");
  }
  if (!csrf(request, session)) return fail(request, 403, "Please refresh the page and try again.");
  const account = accounts.get(session.userId);
  return account ? { session, account } : fail(request, 401, "Please sign in again.");
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#14263a;--blue:#075d9f;--line:#c6d5df;--pale:#edf6fb;--bad:#8d1f25;--good:#176c48}*{box-sizing:border-box}body{margin:0;background:#eaf1f5;color:var(--ink);font:17px/1.7 Verdana,Arial,sans-serif;letter-spacing:.035em}.shell{min-height:100vh;max-width:560px;margin:auto;padding:20px 18px 34px;background:#fffdf9}header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:21px}.brand{font-weight:bold;color:#034778}.step,.small,.example{color:#526174;font-size:.9rem}h1{font-size:1.55rem;line-height:1.3;margin:0 0 13px}h2{font-size:1.12rem}p{margin:0 0 15px}.lead{font-size:1.04rem}.card,.note{border:1px solid var(--line);border-radius:12px;padding:17px;margin:16px 0;background:#fff}.note{background:var(--pale);border-left:5px solid var(--blue)}.error{background:#fff0f0;border-left-color:var(--bad);color:#70141a}.success{background:#edf8f1;border-left-color:var(--good)}label{display:block;font-weight:bold;margin:18px 0 5px}input,textarea{width:100%;padding:13px;border:2px solid #8496a7;border-radius:8px;font:inherit;letter-spacing:.04em}.primary,.secondary,.link{font:inherit;font-weight:bold;cursor:pointer}.primary{width:100%;padding:14px;border:0;border-radius:9px;background:var(--blue);color:#fff;margin-top:22px}.secondary{padding:10px;border:2px solid var(--blue);border-radius:8px;background:#fff;color:#034778;margin:8px 6px 0 0}.link{border:0;background:none;color:var(--blue);text-decoration:underline;padding:12px 0}.secret,.codes li{font-family:monospace;letter-spacing:.11em;word-break:break-all}.secret{background:#f0f5f7;padding:12px;border-radius:7px;user-select:all}.codes{list-style:none;padding:0}.codes li{border-bottom:1px solid var(--line);padding:7px;font-weight:bold;user-select:all}.qr{display:grid;grid-template-columns:repeat(17,10px);gap:1px;width:max-content;padding:9px;margin:16px auto;border:2px solid var(--ink);background:#fff}.qr i{width:10px;height:10px;background:#fff}.qr i.on{background:#14263a}.logs{border-top:2px solid var(--line);margin-top:28px;padding-top:14px}.logbox{background:#162636;color:#e8f4fb;border-radius:8px;padding:10px;min-height:65px;font:12px/1.45 monospace;max-height:145px;overflow:auto}details{margin-top:20px}@media print{header,.primary,.secondary,.link,details,.logs{display:none}.shell{max-width:none}}
</style>
</head>
<body>
<main class="shell">
<header><div class="brand">🛡️ Harbour Bank</div><div class="step" id="step">Security setup</div></header>
<section id="app" aria-live="polite"></section>
<section class="logs"><h2>🧾 Logs</h2><p class="small">Safe status messages. Private codes are only in the browser console for this demo.</p><div class="logbox" id="logs"></div></section>
</main>
<script nonce="${nonce}">
(()=>{"use strict";
let csrf="",screen="signin",secret="",uri="",codes=[],visible=true,identityPhone="";
const app=document.querySelector("#app"),step=document.querySelector("#step"),logs=document.querySelector("#logs");
function log(text){console.log(text);const line=document.createElement("div");line.textContent=text;logs.append(line);logs.scrollTop=logs.scrollHeight}
function testValue(label,value){console.log("[ACADEMIC DEMO TEST VALUE] "+label+":",value)}
async function api(path,data,method="POST"){const response=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:method==="GET"?undefined:JSON.stringify(data||{})});const result=await response.json().catch(()=>({message:"Something went wrong. Please try again."}));if(!response.ok)throw Error(result.message);return result}
function base(title,progress){app.replaceChildren();step.textContent=progress;const h=document.createElement("h1");h.textContent=title;app.append(h)}
function note(text,type="error"){const n=document.createElement("div");n.className="note "+type;n.textContent=text;app.prepend(n)}
function field(label,id,type,example,autocomplete){const wrap=document.createElement("div"),l=document.createElement("label"),i=document.createElement("input"),p=document.createElement("p");l.htmlFor=id;l.textContent=label;i.id=id;i.type=type;i.autocomplete=autocomplete||"off";p.className="example";p.textContent=example;wrap.append(l,i,p);return wrap}
function button(text,kind="primary"){const b=document.createElement("button");b.type="button";b.className=kind;b.textContent=text;return b}
function help(){const d=document.createElement("details");const s=document.createElement("summary");s.textContent="Need help?";const p=document.createElement("p");p.textContent="Take your time. Nothing disappears while you read. You can safely retry.";d.append(s,p);app.append(d)}
async function copy(value,label,parent){try{await navigator.clipboard.writeText(value);note(label+" copied. Paste it into your authenticator app or a private note.","success")}catch(_){const t=document.createElement("textarea");t.readOnly=true;t.value=value;t.setAttribute("aria-label","Selectable "+label);parent.append(t);t.focus();t.select();note("Select the "+label+" below and copy it manually.")}}
function fakeQr(value){const d=document.createElement("div");d.className="qr";d.setAttribute("role","img");d.setAttribute("aria-label","Authenticator setup QR-style reference code. You can use the setup key below instead.");let seed=0;for(const c of value)seed=(seed*31+c.charCodeAt(0))>>>0;for(let i=0;i<289;i++){seed=(seed*1664525+1013904223)>>>0;const q=document.createElement("i");if((seed>>>29)&1)q.className="on";d.append(q)}return d}
function render(){({signin,identity,provision,backup,saved,settings})[screen]()}
function signin(){base("Sign in","Step 1 of 4 · Sign in");const lead=document.createElement("p");lead.className="lead";lead.textContent="Sign in to start your security setup.";const hint=document.createElement("p");hint.className="note";hint.textContent="Academic demo sign-in: marcus@example.com and MarcusDemo!42.";const f=document.createElement("form");f.append(field("Email address","email","email","Example: marcus@example.com","email"),field("Password","password","password","Use your saved password","current-password"));const b=button("Sign in");b.type="submit";f.append(b);f.onsubmit=async e=>{e.preventDefault();try{const result=await api("/api/signin",{email:document.querySelector("#email").value,password:document.querySelector("#password").value});csrf=result.csrf;screen="identity";log("Sign-in accepted. Next: confirm identity.");render()}catch(error){note(error.message)}};app.append(lead,hint,f);help()}
function identity(){base("Confirm it is you","Step 2 of 4 · Confirm identity");const lead=document.createElement("p");lead.className="lead";lead.textContent="We will send a short code to your account phone.";const f=document.createElement("form");f.append(lead,field("Mobile number","phone","tel","Example: +1 555 123 4567","tel"));const b=button("Send my code");b.type="submit";f.append(b);f.onsubmit=async e=>{e.preventDefault();identityPhone=document.querySelector("#phone").value;try{const result=await api("/api/identity/request",{phone:identityPhone});testValue("Simulated identity delivery code",result.testingCode);log("Mock identity code delivered. Find the test value in the browser console.");identityCode()}catch(error){note(error.message)}};app.append(f);help()}
function identityCode(){const f=document.createElement("form");f.append(field("Enter the 6-digit code","code","text","Example: 482913","one-time-code"));const confirm=button("Confirm code");confirm.type="submit";const resend=button("Send a new code","link");resend.onclick=async()=>{try{const result=await api("/api/identity/request",{phone:identityPhone});testValue("Replacement simulated identity delivery code",result.testingCode);log("Replacement mock identity code delivered.")}catch(error){note(error.message)}};f.append(confirm,resend);f.onsubmit=async e=>{e.preventDefault();try{const result=await api("/api/identity/verify",{code:document.querySelector("#code").value.trim()});csrf=result.csrf;screen="provision";log("Identity confirmed. Next: set up your authenticator.");render()}catch(error){note(error.message)}};app.querySelector("form").replaceWith(f)}
function provision(){base("Set up your authenticator","Step 3 of 4 · Authenticator");const lead=document.createElement("p");lead.className="lead";lead.textContent="Scan the reference code with your authenticator app, or copy the setup key.";app.append(lead);api("/api/mfa/provision",{}).then(result=>{secret=result.secret;uri=result.provisioningUri;testValue("Simulated authenticator testing code",result.testingCode);log("Authenticator setup created. The test code is in the browser console.");const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="📷 QR setup option";const text=document.createElement("p");text.textContent="If scanning is difficult, use the setup key below instead.";const key=document.createElement("div");key.className="secret";key.textContent=secret;const cp=button("Copy setup key","secondary");cp.onclick=()=>copy(secret,"Setup key",card);card.append(h,fakeQr(uri),text,key,cp);app.append(card);const f=document.createElement("form");f.append(field("Optional: paste setup key to check it","manual","text","Example: JBSWY3DPEHPK3PXP"),field("Enter the 6-digit code from your app","code","text","Example: 654321","one-time-code"));const verify=button("Verify authenticator");verify.type="submit";f.append(verify);f.onsubmit=async e=>{e.preventDefault();try{const done=await api("/api/mfa/verify",{code:document.querySelector("#code").value.trim(),manualSecret:document.querySelector("#manual").value.trim()||undefined});codes=done.codes;visible=true;testValue("Simulated recovery-code testing values",codes);log("Authenticator verified. Recovery codes are ready.");screen="backup";render()}catch(error){note(error.message)}};app.append(f);help()}).catch(error=>note(error.message))}
function backup(){base("Save your recovery codes","Step 4 of 4 · Recovery codes");const lead=document.createElement("p");lead.className="lead";lead.textContent="These one-use codes help if you lose your phone. Keep them private.";const card=document.createElement("section");card.className="card";const toggle=button(visible?"Hide codes":"Reveal codes","secondary");toggle.onclick=()=>{visible=!visible;render()};card.append(toggle);if(visible){const list=document.createElement("ul");list.className="codes";codes.forEach(code=>{const li=document.createElement("li");li.textContent=code;list.append(li)});const cp=button("Copy codes","secondary");cp.onclick=()=>copy(codes.join("\\n"),"Recovery codes",card);const print=button("Print or save as PDF","secondary");print.onclick=()=>window.print();card.append(list,cp,print)}else{const p=document.createElement("p");p.className="note";p.textContent="Your recovery codes are hidden. Select Reveal codes whenever you are ready.";card.append(p)}const done=button("I saved my codes");done.onclick=()=>{screen="saved";render()};app.append(lead,card,done);help()}
function saved(){base("MFA is ready","Complete · Security setup");note("✓ Your authenticator and recovery codes are ready.","success");const b=button("Go to MFA settings");b.onclick=()=>{screen="settings";render()};app.append(b);help()}
function settings(){base("MFA settings","Security settings");const lead=document.createElement("p");lead.className="lead";lead.textContent="🛡️ Your authenticator app is active.";const card=document.createElement("section");card.className="card";const h=document.createElement("h2");h.textContent="Use a recovery code";card.append(h,field("Recovery code","recovery","text","Example: A1B2-C3D4","one-time-code"));const use=button("Use recovery code");use.onclick=async()=>{try{await api("/api/recovery/verify",{code:document.querySelector("#recovery").value.trim().toUpperCase()});note("Recovery code accepted and used. It cannot be used again.","success");document.querySelector("#recovery").value=""}catch(error){note(error.message)}};card.append(use);const regenerate=button("Create new recovery codes","secondary");regenerate.onclick=async()=>{try{const result=await api("/api/recovery/regenerate",{});codes=result.codes;visible=true;testValue("Replacement simulated recovery-code testing values",codes);log("New recovery codes created.");screen="backup";render()}catch(error){note(error.message)}};const logout=button("Log out","link");logout.onclick=async()=>{try{await api("/api/logout",{});csrf="";screen="signin";log("Signed out. Secure session invalidated.");render()}catch(error){note(error.message)}};app.append(lead,card,regenerate,logout);help()}
api("/api/bootstrap",null,"GET").then(result=>{csrf=result.csrf;screen=result.stage==="verified"?"settings":result.stage==="signedin"?"identity":"signin";render()}).catch(()=>note("Unable to start securely. Please refresh the page."));
})();
</script>
</body>
</html>`;
}

Bun.serve({
  port: PORT,
  tls: { cert, key },
  async fetch(request) {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") {
        return originOK(request)
          ? new Response(null, { status: 204, headers: headers(request) })
          : fail(request, 403, "This request was not accepted.");
      }

      if (url.pathname === "/" && request.method === "GET") {
        const nonce = token(18);
        const result = headers(request, nonce);
        result.set("Content-Type", "text/html; charset=utf-8");
        return new Response(page(nonce), { headers: result });
      }

      if (url.pathname === "/api/bootstrap" && request.method === "GET") {
        if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
        let session = current(request);
        let setCookie = "";
        if (!session) {
          session = makeSession("preauth", null);
          setCookie = sessionCookie(session.token);
        }
        return reply(request, { ok: true, csrf: session.csrf, stage: session.stage }, 200,
          setCookie ? { "Set-Cookie": setCookie } : undefined);
      }

      /* Identification/authentication: generic failures and constant-time credential check. */
      if (url.pathname === "/api/signin" && request.method === "POST") {
        if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
        const old = current(request);
        const data = await body(request);
        if (!old || old.stage !== "preauth" || !csrf(request, old)) {
          return fail(request, 403, "Please refresh the page and try again.");
        }

        const submittedEmail = validEmail(data?.email) ? data.email.toLowerCase() : "";
        const submittedPassword = typeof data?.password === "string" &&
          data.password.length > 0 && data.password.length <= 200 ? data.password : "";
        const account = submittedEmail === ACCOUNT_EMAIL ? accounts.get(ACCOUNT_ID) : undefined;
        /* Always perform the same PBKDF2 work, including for unknown accounts. */
        const comparisonSalt = account?.passwordSalt || passwordSalt;
        const submittedValue = await credentialValue(submittedPassword, comparisonSalt);
        const storedValue = account?.passwordValue || accounts.get(ACCOUNT_ID)!.passwordValue;
        const accepted = !!account && constantEqual(submittedValue, storedValue);

        if (!accepted) {
          return fail(request, 401, "Check your email and password, then try again.");
        }

        sessions.delete(old.token); // session rotation prevents fixation
        const session = makeSession("signedin", account.id);
        return reply(request, { ok: true, csrf: session.csrf }, 200, {
          "Set-Cookie": sessionCookie(session.token),
        });
      }

      /*
       Identity delivery is available only after successful credentials and only for
       the authenticated account's normalized phone. No user/account ID is accepted.
      */
      if (url.pathname === "/api/identity/request" && request.method === "POST") {
        const owned = owner(request, "signedin");
        if (isResponse(owned)) return owned;
        const now = Date.now();
        if (owned.session.identityLockedUntil && owned.session.identityLockedUntil > now) {
          return fail(request, 429, "Too many attempts. Wait 10 minutes, then request a new code.");
        }
        const data = await body(request);
        const submittedPhone = normalizePhone(data?.phone);
        if (!submittedPhone) {
          return fail(request, 400, "Enter a phone number such as +1 555 123 4567.");
        }
        if (!constantEqual(submittedPhone, owned.account.normalizedPhone)) {
          return fail(request, 403, "Use the mobile number saved on this account.");
        }
        if (owned.session.identityLockedUntil && owned.session.identityLockedUntil <= now) {
          owned.session.identityLockedUntil = undefined;
          owned.session.identityFailures = 0;
        }

        owned.session.identityCode = DEMO_IDENTITY_OTP;
        owned.session.identityCodeUsed = false;
        owned.session.identityCodeExpires = now + codeMs;
        owned.session.identityFailures = 0;
        /*
         Only the authenticated, credential-approved browser receives this academic
         test value. It is not logged, placed in a URL, or exposed to other sessions.
        */
        return reply(request, { ok: true, testingCode: DEMO_IDENTITY_OTP });
      }

      if (url.pathname === "/api/identity/verify" && request.method === "POST") {
        const owned = owner(request, "signedin");
        if (isResponse(owned)) return owned;
        const now = Date.now();
        const data = await body(request);
        if (owned.session.identityLockedUntil && owned.session.identityLockedUntil > now) {
          return fail(request, 429, "Too many attempts. Wait 10 minutes, then request a new code.");
        }
        const codeMatches = validOtp(data?.code) &&
          !!owned.session.identityCode &&
          constantEqual(data.code, owned.session.identityCode);
        if (owned.session.identityCodeUsed || !owned.session.identityCodeExpires ||
          owned.session.identityCodeExpires < now || !codeMatches) {
          if (++owned.session.identityFailures >= 5) owned.session.identityLockedUntil = now + lockMs;
          return fail(request, 400, "That code did not work. Check the 6 digits or send a new code.");
        }
        owned.session.identityCodeUsed = true;
        owned.session.identityCode = undefined;
        owned.session.stage = "verified";
        owned.session.csrf = token(24);
        return reply(request, { ok: true, csrf: owned.session.csrf });
      }

      if (url.pathname === "/api/mfa/provision" && request.method === "POST") {
        const owned = owner(request);
        if (isResponse(owned)) return owned;
        owned.account.mfaSecretEncrypted = await encrypt(DEMO_AUTH_SECRET);
        owned.session.otpUsed = false;
        owned.session.otpFailures = 0;
        owned.session.otpLockedUntil = undefined;
        const provisioningUri = `otpauth://totp/Harbour%3Amarcus?secret=${DEMO_AUTH_SECRET}&issuer=Harbour&algorithm=SHA1&digits=6&period=30`;
        return reply(request, {
          ok: true,
          secret: DEMO_AUTH_SECRET,
          provisioningUri,
          testingCode: DEMO_AUTH_OTP,
        });
      }

      if (url.pathname === "/api/mfa/verify" && request.method === "POST") {
        const owned = owner(request);
        if (isResponse(owned)) return owned;
        const now = Date.now();
        const data = await body(request);
        if (owned.session.otpLockedUntil && owned.session.otpLockedUntil > now) {
          return fail(request, 429, "Too many attempts. Wait 10 minutes, then try again.");
        }

        let secretMatches = !!owned.account.mfaSecretEncrypted;
        if (data?.manualSecret !== undefined) {
          secretMatches = secretMatches && validManualSecret(data.manualSecret) &&
            constantEqual(data.manualSecret, DEMO_AUTH_SECRET);
        }
        const codeMatches = validOtp(data?.code) && constantEqual(data.code, DEMO_AUTH_OTP);
        if (!secretMatches || !codeMatches || owned.session.otpUsed) {
          if (++owned.session.otpFailures >= 5) owned.session.otpLockedUntil = now + lockMs;
          return fail(request, 400, !secretMatches
            ? "That setup key does not match this authenticator setup. Copy the setup key again, then retry."
            : "That code did not work. Check the 6 digits and try again.");
        }

        owned.session.otpUsed = true;
        owned.session.otpFailures = 0;
        owned.session.otpLockedUntil = undefined;
        owned.account.mfaEnabled = true;
        owned.account.backupCodeValues = await demoRecoveryValues();
        return reply(request, { ok: true, codes: [...DEMO_RECOVERY_CODES] });
      }

      if (url.pathname === "/api/recovery/verify" && request.method === "POST") {
        const owned = owner(request);
        if (isResponse(owned)) return owned;
        const now = Date.now();
        const data = await body(request);
        if (owned.session.recoveryLockedUntil && owned.session.recoveryLockedUntil > now) {
          return fail(request, 429, "Too many recovery-code attempts. Wait 10 minutes, then try again.");
        }
        if (!validRecovery(data?.code)) {
          return fail(request, 400, "Enter one recovery code in the format A1B2-C3D4.");
        }
        let found = -1;
        for (let i = 0; i < owned.account.backupCodeValues.length; i++) {
          const stored = owned.account.backupCodeValues[i];
          const candidate = await recoveryValue(data.code, stored.salt);
          if (constantEqual(candidate, stored.value)) found = i;
        }
        if (found < 0) {
          if (++owned.session.recoveryFailures >= 5) owned.session.recoveryLockedUntil = now + lockMs;
          return fail(request, 400, "That recovery code is not available. Check the code or create a new set.");
        }
        owned.account.backupCodeValues.splice(found, 1); // single-use
        owned.session.recoveryFailures = 0;
        owned.session.recoveryLockedUntil = undefined;
        return reply(request, { ok: true });
      }

      if (url.pathname === "/api/recovery/regenerate" && request.method === "POST") {
        const owned = owner(request);
        if (isResponse(owned)) return owned;
        if (!owned.account.mfaEnabled) {
          return fail(request, 400, "Set up your authenticator before creating recovery codes.");
        }
        owned.account.backupCodeValues = await demoRecoveryValues();
        return reply(request, { ok: true, codes: [...DEMO_RECOVERY_CODES] });
      }

      if (url.pathname === "/api/logout" && request.method === "POST") {
        if (!originOK(request)) return fail(request, 403, "This request was not accepted.");
        const session = current(request);
        if (!session || !csrf(request, session)) {
          return fail(request, 403, "Please refresh the page and try again.");
        }
        session.invalidated = true;
        sessions.delete(session.token);
        return reply(request, { ok: true }, 200, { "Set-Cookie": sessionCookie("", false) });
      }

      return fail(request, 404, "Page not found.");
    } catch {
      return fail(request, 500, "Something went wrong. Please try again.");
    }
  },
});
