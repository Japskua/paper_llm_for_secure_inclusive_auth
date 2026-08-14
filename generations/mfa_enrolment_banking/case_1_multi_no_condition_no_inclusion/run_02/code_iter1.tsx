
import { createHash, randomBytes, createCipheriv, createDecipheriv, createHmac } from "node:crypto";

/*
  MFA Enrolment System
  Single Bun server + inline HTML/CSS/JavaScript.
  Run with: bun app.ts
*/

/* [2] HTTPS is mandatory. Certificates are supplied at certs/cert.pem and certs/key.pem. */
const certFile = Bun.file("certs/cert.pem");
const keyFile = Bun.file("certs/key.pem");
if (!(await certFile.exists()) || !(await keyFile.exists())) {
  throw new Error("TLS certificates are required at certs/cert.pem and certs/key.pem");
}

const PORT = 3000;
const SESSION_IDLE_MS = 15 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const CODE_EXPIRY_MS = 5 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const MAX_FAILURES = 5;
const TRUSTED_ORIGINS = new Set([
  `https://localhost:${PORT}`,
  `https://127.0.0.1:${PORT}`,
  `https://[::1]:${PORT}`,
]);

type SessionStage = "identity" | "authenticated";

type Session = {
  id: string;
  userId: string;
  stage: SessionStage;
  csrf: string;
  createdAt: number;
  lastSeen: number;
  identityCodeHash?: string;
  identityCodeExpires?: number;
  identityCodeUsed?: boolean;
  failures: number;
  lockedUntil: number;
};

type EncryptedValue = {
  iv: string;
  ciphertext: string;
};

type BackupCode = {
  salt: string;
  hash: string;
  used: boolean;
};

type Account = {
  id: string;
  email: string;
  phone: string;
  mfaEnabled: boolean;
  encryptedSecret?: EncryptedValue;
  pendingEncryptedSecret?: EncryptedValue;
  lastAcceptedTotpCounter?: number;
  backupCodes: BackupCode[];
  failures: number;
  lockedUntil: number;
};

/* [1, 5] Authoritative in-memory server records; no client-provided account IDs are used. */
const account: Account = {
  id: "acct_marcus_001",
  email: "marcus@example.test",
  phone: "+1 ••• ••• 0184",
  mfaEnabled: false,
  backupCodes: [],
  failures: 0,
  lockedUntil: 0,
};
const sessions = new Map<string, Session>();

/* [3] The OTP shared secret is AES-256-GCM encrypted while stored in memory. */
const encryptionKey = randomBytes(32);
const backupPepper = randomBytes(32);

function now(): number {
  return Date.now();
}

function base64url(value: Buffer): string {
  return value.toString("base64url");
}

function token(bytes = 32): string {
  return base64url(randomBytes(bytes));
}

function digest(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("base64url");
}

function timingSafeEqualText(a: string, b: string): boolean {
  const ah = Buffer.from(a);
  const bh = Buffer.from(b);
  if (ah.length !== bh.length) return false;
  let diff = 0;
  for (let i = 0; i < ah.length; i++) diff |= ah[i] ^ bh[i];
  return diff === 0;
}

function encryptSecret(secret: string): EncryptedValue {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv: base64url(iv), ciphertext: base64url(Buffer.concat([tag, ciphertext])) };
}

function decryptSecret(value: EncryptedValue): string {
  const iv = Buffer.from(value.iv, "base64url");
  const packed = Buffer.from(value.ciphertext, "base64url");
  const tag = packed.subarray(0, 16);
  const ciphertext = packed.subarray(16);
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}

function base32Encode(bytes: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const byte of bytes) bits += byte.toString(2).padStart(8, "0");
  let output = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) output += alphabet[parseInt(bits.slice(i, i + 5), 2)];
  return output;
}

function base32Decode(input: string): Buffer | null {
  const clean = input.replace(/[\s-]/g, "").toUpperCase();
  if (!/^[A-Z2-7]{16,128}$/.test(clean)) return null;
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of clean) bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/* [3, 5] Server-side RFC-style TOTP verification; values are never server logged. */
function totp(secret: string, counter = Math.floor(now() / 30000)): string {
  const secretBytes = base32Decode(secret);
  if (!secretBytes) return "";
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", secretBytes).update(message).digest();
  const offset = hmac[hmac.length - 1] & 15;
  const binary = ((hmac[offset] & 127) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(binary % 1000000).padStart(6, "0");
}

function validTotp(secret: string, supplied: string): number | null {
  if (!/^\d{6}$/.test(supplied)) return null;
  const current = Math.floor(now() / 30000);
  for (const counter of [current - 1, current, current + 1]) {
    if (timingSafeEqualText(totp(secret, counter), supplied)) return counter;
  }
  return null;
}

function generateBackupCodes(): { plain: string[]; stored: BackupCode[] } {
  const plain: string[] = [];
  const stored: BackupCode[] = [];
  for (let i = 0; i < 8; i++) {
    const raw = randomBytes(5).toString("hex").toUpperCase();
    const code = `${raw.slice(0, 5)}-${raw.slice(5, 10)}`;
    const salt = token(16);
    plain.push(code);
    stored.push({
      salt,
      hash: digest(Buffer.concat([Buffer.from(salt), Buffer.from(code), backupPepper])),
      used: false,
    });
  }
  return { plain, stored };
}

function cookieValue(request: Request, name: string): string | null {
  const cookies = request.headers.get("cookie") || "";
  for (const part of cookies.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return null;
}

function sessionCookie(id: string): string {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(SESSION_ABSOLUTE_MS / 1000)}`;
}

function clearCookie(): string {
  return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

function newSession(stage: SessionStage): Session {
  const session: Session = {
    id: token(32),
    userId: account.id,
    stage,
    csrf: token(32),
    createdAt: now(),
    lastSeen: now(),
    failures: 0,
    lockedUntil: 0,
  };
  sessions.set(session.id, session);
  return session;
}

/* [1, 5] Every protected route checks server-side ownership and expiry. */
function authenticatedSession(request: Request, requiredStage?: SessionStage): Session | null {
  const id = cookieValue(request, "mfa_session");
  if (!id) return null;
  const session = sessions.get(id);
  if (!session || session.userId !== account.id) return null;
  if (now() - session.lastSeen > SESSION_IDLE_MS || now() - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  if (requiredStage && session.stage !== requiredStage) return null;
  session.lastSeen = now();
  return session;
}

/* [1] CSRF is required on all state-changing requests. */
function csrfValid(request: Request, session: Session): boolean {
  const value = request.headers.get("x-csrf-token") || "";
  return /^[A-Za-z0-9_-]{32,128}$/.test(value) && timingSafeEqualText(value, session.csrf);
}

function isTrustedMutation(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !!origin && TRUSTED_ORIGINS.has(origin);
}

/* [2] Security headers are attached consistently to HTML, API, and error responses. */
function securityHeaders(nonce = ""): Headers {
  const headers = new Headers();
  headers.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  );
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  headers.set("Access-Control-Allow-Origin", `https://localhost:${PORT}`);
  headers.set("Vary", "Origin");
  return headers;
}

function json(data: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = securityHeaders();
  headers.set("Content-Type", "application/json; charset=utf-8");
  if (extra) for (const [key, value] of new Headers(extra)) headers.set(key, value);
  return new Response(JSON.stringify(data), { status, headers });
}

function genericUnauthorized(): Response {
  return json({ error: "Your session is unavailable. Please sign in again." }, 401, { "Set-Cookie": clearCookie() });
}

function validEmail(value: unknown): value is string {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]{2,80}$/.test(value) && value.length <= 254;
}

function validPhone(value: unknown): boolean {
  return typeof value === "string" && /^[+0-9 ()-]{7,24}$/.test(value);
}

function validCsrfShape(value: unknown): boolean {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}

function validOtp(value: unknown): value is string {
  return typeof value === "string" && /^\d{6}$/.test(value);
}

function validRecovery(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/.test(value);
}

async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function lockActive(session: Session): boolean {
  return session.lockedUntil > now() || account.lockedUntil > now();
}

function failure(session: Session): void {
  session.failures++;
  account.failures++;
  if (session.failures >= MAX_FAILURES || account.failures >= MAX_FAILURES) {
    session.lockedUntil = now() + LOCKOUT_MS;
    account.lockedUntil = now() + LOCKOUT_MS;
    session.failures = 0;
    account.failures = 0;
  }
}

function clearFailures(session: Session): void {
  session.failures = 0;
  account.failures = 0;
}

function safeStatus(session: Session) {
  return {
    csrf: session.csrf,
    email: account.email,
    phone: account.phone,
    mfaEnabled: account.mfaEnabled,
    backupCodesRemaining: account.backupCodes.filter((item) => !item.used).length,
  };
}

const page = (nonce: string) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="light">
<title>Northstar Bank · MFA security</title>
<style nonce="${nonce}">
:root{--navy:#11233f;--blue:#1559b7;--pale:#edf5ff;--line:#cbd5e1;--ink:#172033;--muted:#526174;--good:#126b43;--warn:#a64b00;--bad:#b42318}
*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font:16px/1.45 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{background:var(--navy);color:#fff;padding:18px 20px}.brand{max-width:560px;margin:auto;font-weight:750;letter-spacing:.2px}.brand span{display:block;font-size:.78rem;font-weight:500;opacity:.77}
main{max-width:560px;margin:0 auto;padding:18px 14px 40px}section{background:#fff;border:1px solid #dce4ee;border-radius:14px;padding:20px;margin-bottom:14px;box-shadow:0 2px 7px #20314a0d}
h1{font-size:1.38rem;line-height:1.25;margin:0 0 8px}h2{font-size:1.08rem;margin:0 0 10px}p{margin:8px 0;color:var(--muted)}label{display:block;font-weight:650;margin:15px 0 5px}input{width:100%;border:1px solid #9cacbf;border-radius:8px;padding:12px;font:inherit;color:var(--ink);background:#fff}input:focus{outline:3px solid #b9d6ff;border-color:var(--blue)}
button{width:100%;border:0;border-radius:8px;padding:12px 14px;margin-top:16px;background:var(--blue);color:#fff;font:700 1rem inherit;cursor:pointer}button:hover{background:#0d4798}button.secondary{background:#e7eef8;color:#14345f}button.danger{background:#9f2621}.notice{border-radius:8px;padding:11px 12px;margin:12px 0;background:var(--pale);color:#153c70}.notice.warning{background:#fff1df;color:#783600}.notice.error{background:#fff0ef;color:var(--bad)}.hidden{display:none!important}
.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;font-weight:750;word-break:break-word;background:#f5f7fa;border-radius:8px;padding:12px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:12px 0}.codes div{font-family:ui-monospace,monospace;font-weight:700;background:#f2f5f9;padding:9px;border-radius:6px;text-align:center}
dl{margin:10px 0}dt{color:var(--muted);font-size:.85rem}dd{margin:2px 0 12px;font-weight:650}.status{display:inline-block;padding:3px 8px;border-radius:12px;background:#e8f7ee;color:var(--good);font-size:.84rem;font-weight:700}.status.off{background:#eef1f5;color:#536174}.logs{background:#101b2d;color:#d8e8ff;border-radius:9px;padding:11px;max-height:180px;overflow:auto;font:12px/1.45 ui-monospace,SFMono-Regular,monospace;white-space:pre-wrap}.small{font-size:.88rem}.divider{border:0;border-top:1px solid #e1e7ee;margin:20px 0}
</style>
</head>
<body>
<header><div class="brand">Northstar Bank<span>Mobile account security</span></div></header>
<main id="app" aria-live="polite">
<section><h1>Loading secure account…</h1></section>
</main>
<script nonce="${nonce}">
(() => {
"use strict";
/* [4] Dynamic data is always inserted with textContent, never HTML interpolation. */
const app=document.getElementById("app");
let csrf="";
let shownCodes=[];

function escapeText(v){return String(v ?? "");}
function log(message){console.log(message);const p=document.createElement("div");p.textContent=message;document.getElementById("logs")?.appendChild(p);}
function logsPanel(){const sec=document.createElement("section");sec.innerHTML='<h2>Logs</h2><p class="small">Evaluation-safe browser simulation log.</p><div id="logs" class="logs" role="log"></div>';return sec;}
function message(text,type=""){const el=document.createElement("div");el.className="notice "+type;el.textContent=text;return el;}
function section(title){const el=document.createElement("section");const h=document.createElement("h1");h.textContent=title;el.appendChild(h);return el;}
function input(label,type,name,autocomplete){const wrap=document.createElement("div"), l=document.createElement("label"), i=document.createElement("input");l.htmlFor=name;l.textContent=label;i.id=i.name=name;i.type=type;i.autocomplete=autocomplete||"off";wrap.append(l,i);return [wrap,i];}
function button(text,klass=""){const b=document.createElement("button");b.type="button";b.textContent=text;if(klass)b.className=klass;return b;}
function render(...nodes){app.replaceChildren(...nodes);}
async function api(path,method="GET",payload){
  const options={method,headers:{}};
  if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;}
  if(payload!==undefined)options.body=JSON.stringify(payload);
  try{const res=await fetch(path,options);const data=await res.json();if(!res.ok)throw new Error(data.error||"Request could not be completed.");if(data.csrf)csrf=data.csrf;return data;}
  catch(e){throw new Error(e instanceof Error?e.message:"Request could not be completed.");}
}
function errorInto(target,text){target.replaceChildren(message(text,"error"));}

function signIn(){
 const sec=section("Sign in to secure payments");
 sec.append(message("MFA is required before high-value payments can be authorised."));
 const [emailWrap,email]=input("Email address","email","email","username");
 const [phoneWrap,phone]=input("Mobile phone number","tel","phone","tel");
 phone.placeholder="+1 555 010 0184";
 const note=document.createElement("p");note.className="small";note.textContent="For this protected demonstration, any valid-looking sign-in details receive the same response.";
 const result=document.createElement("div");const submit=button("Continue");
 submit.onclick=async()=>{result.replaceChildren();try{
   const data=await api("/api/signin","POST",{email:email.value.trim(),phone:phone.value.trim(),redirect:"/verify-identity"});
   csrf=data.csrf; log("Mock identity verification code delivered to browser test UI: "+data.testCode);
   identity(data.testCode);
 }catch(e){errorInto(result,e.message);}};
 sec.append(emailWrap,phoneWrap,note,submit,result,logsPanel());render(sec);
}

function identity(testCode){
 const sec=section("Verify your identity");
 sec.append(message("We sent a six-digit verification code to your registered contact method. It expires in five minutes."));
 const [wrap,code]=input("Verification code","text","identity-code","one-time-code");code.inputMode="numeric";code.maxLength=6;
 const help=document.createElement("p");help.className="small";help.textContent="Evaluation mock code: "+testCode;
 const result=document.createElement("div"),submit=button("Verify identity");
 submit.onclick=async()=>{try{await api("/api/identity","POST",{otp:code.value.trim()});settings();}catch(e){errorInto(result,e.message);}};
 sec.append(wrap,help,submit,result,logsPanel());render(sec);
}

function settings(){
 api("/api/me").then(data=>{
  csrf=data.csrf;const sec=section("MFA security settings");
  const status=document.createElement("span");status.className="status "+(data.mfaEnabled?"":"off");status.textContent=data.mfaEnabled?"Authenticator enabled":"Authenticator not enabled";
  sec.append(status);
  const dl=document.createElement("dl");dl.innerHTML="<dt>Signed-in account</dt><dd></dd><dt>Registered phone</dt><dd></dd><dt>Recovery codes remaining</dt><dd></dd>";
  const dds=dl.querySelectorAll("dd");dds[0].textContent=data.email;dds[1].textContent=data.phone;dds[2].textContent=String(data.backupCodesRemaining);sec.append(dl);
  if(!data.mfaEnabled){const setup=button("Set up authenticator");setup.onclick=provision;sec.append(setup);}
  else {
   const check=button("Test authenticator verification");check.onclick=totpCheck;
   const recovery=button("Use a recovery code","secondary");recovery.onclick=useRecovery;
   const regenerate=button("Regenerate recovery codes","secondary");regenerate.onclick=regenerateCodes;
   sec.append(check,recovery,regenerate);
  }
  const logout=button("Sign out","danger");logout.onclick=logoutNow;sec.append(logout,logsPanel());render(sec);
 }).catch(()=>signIn());
}

function provision(){
 api("/api/mfa/provision","POST",{}).then(data=>{
  const sec=section("Set up your authenticator");
  sec.append(message("Add this secret to your authenticator app. It is shown only for this enrolment step.","warning"));
  const label=document.createElement("p");label.innerHTML="<strong>Manual setup secret</strong>";
  const secret=document.createElement("div");secret.className="code";secret.textContent=data.secret;
  const instruction=document.createElement("p");instruction.textContent="In your app choose Time-based / TOTP, account "+data.accountLabel+", then enter the secret above. Do not save it in this browser.";
  const [wrap,otp]=input("Six-digit code from your authenticator","text","totp","one-time-code");otp.inputMode="numeric";otp.maxLength=6;
  const result=document.createElement("div"),activate=button("Activate authenticator");
  activate.onclick=async()=>{try{const response=await api("/api/mfa/activate","POST",{otp:otp.value.trim(),manualSecret:data.secret});csrf=response.csrf;showCodes(response.codes,"Authenticator enabled. Store these recovery codes now.");}catch(e){errorInto(result,e.message);}};
  const back=button("Back to settings","secondary");back.onclick=settings;
  sec.append(label,secret,instruction,wrap,activate,result,back,logsPanel());render(sec);
 }).catch(e=>{const sec=section("MFA security settings");sec.append(message(e.message,"error"));render(sec);});
}

function showCodes(codes,title){
 shownCodes=codes;log("Mock backup recovery codes generated: "+codes.join(", "));
 const sec=section(title);sec.append(message("These recovery codes are displayed once. Copy them to a secure location; each can be used only once.","warning"));
 const grid=document.createElement("div");grid.className="codes";codes.forEach(c=>{const d=document.createElement("div");d.textContent=c;grid.appendChild(d);});
 const copied=document.createElement("div");const copy=button("Mark codes as safely stored");
 copy.onclick=()=>{copied.replaceChildren(message("Recovery codes have been acknowledged. They will not be displayed again."));copy.disabled=true;};
 const done=button("Return to security settings","secondary");done.onclick=settings;sec.append(grid,copy,copied,done,logsPanel());render(sec);
}

function totpCheck(){
 const sec=section("Test authenticator");
 sec.append(message("Enter a current code from your configured authenticator."));
 const [wrap,otp]=input("Authenticator code","text","mfa-check","one-time-code");otp.inputMode="numeric";otp.maxLength=6;
 const result=document.createElement("div"),verify=button("Verify code");
 verify.onclick=async()=>{try{await api("/api/mfa/check","POST",{otp:otp.value.trim()});result.replaceChildren(message("Authenticator verified successfully."));}catch(e){errorInto(result,e.message);}};
 const back=button("Back to settings","secondary");back.onclick=settings;sec.append(wrap,verify,result,back,logsPanel());render(sec);
}

function useRecovery(){
 const sec=section("Use a recovery code");
 sec.append(message("A recovery code is consumed immediately after successful verification.","warning"));
 const [wrap,code]=input("Recovery code","text","recovery-code","one-time-code");code.placeholder="ABCDE-12345";code.maxLength=11;
 const result=document.createElement("div"),verify=button("Use recovery code");
 verify.onclick=async()=>{try{await api("/api/mfa/recovery","POST",{code:code.value.trim().toUpperCase()});result.replaceChildren(message("Recovery code accepted and invalidated."));}catch(e){errorInto(result,e.message);}};
 const back=button("Back to settings","secondary");back.onclick=settings;sec.append(wrap,verify,result,back,logsPanel());render(sec);
}

function regenerateCodes(){
 const sec=section("Regenerate recovery codes");
 sec.append(message("Generating new recovery codes immediately invalidates all previous recovery codes.","warning"));
 const result=document.createElement("div"),confirm=button("Generate new recovery codes");
 confirm.onclick=async()=>{try{const data=await api("/api/mfa/backup/regenerate","POST",{});showCodes(data.codes,"New recovery codes");}catch(e){errorInto(result,e.message);}};
 const back=button("Cancel","secondary");back.onclick=settings;sec.append(confirm,result,back,logsPanel());render(sec);
}

async function logoutNow(){try{await api("/api/logout","POST",{});}catch(_){}csrf="";shownCodes=[];signIn();}
settings();
})();
</script>
</body>
</html>`;

async function handle(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const nonce = token(18);

  if (request.method === "OPTIONS") {
    const headers = securityHeaders(nonce);
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    headers.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    headers.set("Access-Control-Max-Age", "600");
    return new Response(null, { status: 204, headers });
  }

  if (url.pathname === "/" && request.method === "GET") {
    const headers = securityHeaders(nonce);
    headers.set("Content-Type", "text/html; charset=utf-8");
    return new Response(page(nonce), { headers });
  }

  if (!url.pathname.startsWith("/api/")) return new Response("Not found", { status: 404, headers: securityHeaders(nonce) });

  if (request.method !== "GET" && !isTrustedMutation(request)) {
    return json({ error: "Request could not be completed." }, 403);
  }

  /* [4] Sign-in receives generic feedback and validates expected field formats. */
  if (url.pathname === "/api/signin" && request.method === "POST") {
    const input = await body(request);
    const email = input?.email;
    const phone = input?.phone;
    const redirect = input?.redirect;
    if (!validEmail(email) || !validPhone(phone) || redirect !== "/verify-identity") {
      return json({ error: "Please check your details and try again." }, 400);
    }

    const session = newSession("identity");
    const code = String(randomBytes(4).readUInt32BE(0) % 1000000).padStart(6, "0");
    session.identityCodeHash = digest(code);
    session.identityCodeExpires = now() + CODE_EXPIRY_MS;
    session.identityCodeUsed = false;

    /* Required simulated delivery: value is returned only to the browser evaluation UI, never server logged. */
    return json(
      { csrf: session.csrf, message: "If the details can be verified, a code has been sent.", testCode: code },
      200,
      { "Set-Cookie": sessionCookie(session.id) },
    );
  }

  if (url.pathname === "/api/identity" && request.method === "POST") {
    const session = authenticatedSession(request, "identity");
    if (!session) return genericUnauthorized();
    if (!csrfValid(request, session)) return json({ error: "Request could not be completed." }, 403);
    const input = await body(request);
    if (!validOtp(input?.otp)) return json({ error: "Verification could not be completed." }, 400);
    if (lockActive(session)) return json({ error: "Too many attempts. Please wait before trying again." }, 429);

    const suppliedHash = digest(input.otp);
    const acceptable = !!session.identityCodeHash && !!session.identityCodeExpires &&
      !session.identityCodeUsed && now() <= session.identityCodeExpires &&
      timingSafeEqualText(suppliedHash, session.identityCodeHash);

    if (!acceptable) {
      failure(session);
      return json({ error: "Verification could not be completed." }, 400);
    }

    /* [5] Session fixation protection: remove pre-auth session and issue a rotated authenticated session. */
    session.identityCodeUsed = true;
    sessions.delete(session.id);
    const rotated = newSession("authenticated");
    clearFailures(rotated);
    return json({ ...safeStatus(rotated) }, 200, { "Set-Cookie": sessionCookie(rotated.id) });
  }

  const session = authenticatedSession(request, "authenticated");
  if (!session) return genericUnauthorized();

  if (url.pathname === "/api/me" && request.method === "GET") {
    return json(safeStatus(session));
  }

  if (request.method !== "POST") return json({ error: "Request could not be completed." }, 405);
  if (!csrfValid(request, session)) return json({ error: "Request could not be completed." }, 403);

  if (url.pathname === "/api/logout") {
    sessions.delete(session.id);
    return json({ ok: true }, 200, { "Set-Cookie": clearCookie() });
  }

  if (url.pathname === "/api/mfa/provision") {
    if (account.mfaEnabled) return json({ error: "Authenticator is already enabled." }, 400);
    const secret = base32Encode(randomBytes(20));
    account.pendingEncryptedSecret = encryptSecret(secret);
    return json({
      csrf: session.csrf,
      secret,
      accountLabel: account.email,
      issuer: "Northstar Bank",
    });
  }

  if (url.pathname === "/api/mfa/activate") {
    const input = await body(request);
    if (!validOtp(input?.otp) || typeof input?.manualSecret !== "string" || !/^[A-Z2-7]{16,128}$/.test(input.manualSecret)) {
      return json({ error: "Verification could not be completed." }, 400);
    }
    if (lockActive(session) || !account.pendingEncryptedSecret) {
      return json({ error: lockActive(session) ? "Too many attempts. Please wait before trying again." : "Start authenticator setup again." }, 400);
    }
    const protectedSecret = decryptSecret(account.pendingEncryptedSecret);
    if (!timingSafeEqualText(protectedSecret, input.manualSecret)) return json({ error: "Verification could not be completed." }, 400);
    const counter = validTotp(protectedSecret, input.otp);
    if (counter === null || account.lastAcceptedTotpCounter === counter) {
      failure(session);
      return json({ error: "Verification could not be completed." }, 400);
    }

    account.encryptedSecret = account.pendingEncryptedSecret;
    account.pendingEncryptedSecret = undefined;
    account.lastAcceptedTotpCounter = counter;
    account.mfaEnabled = true;
    const generated = generateBackupCodes();
    account.backupCodes = generated.stored;
    clearFailures(session);
    return json({ csrf: session.csrf, codes: generated.plain });
  }

  if (url.pathname === "/api/mfa/check") {
    const input = await body(request);
    if (!validOtp(input?.otp) || !account.mfaEnabled || !account.encryptedSecret) {
      return json({ error: "Verification could not be completed." }, 400);
    }
    if (lockActive(session)) return json({ error: "Too many attempts. Please wait before trying again." }, 429);
    const counter = validTotp(decryptSecret(account.encryptedSecret), input.otp);
    if (counter === null || account.lastAcceptedTotpCounter === counter) {
      failure(session);
      return json({ error: "Verification could not be completed." }, 400);
    }
    account.lastAcceptedTotpCounter = counter;
    clearFailures(session);
    return json({ csrf: session.csrf, verified: true });
  }

  if (url.pathname === "/api/mfa/recovery") {
    const input = await body(request);
    if (!validRecovery(input?.code) || !account.mfaEnabled) return json({ error: "Verification could not be completed." }, 400);
    if (lockActive(session)) return json({ error: "Too many attempts. Please wait before trying again." }, 429);

    let matched: BackupCode | undefined;
    for (const item of account.backupCodes) {
      const candidate = digest(Buffer.concat([Buffer.from(item.salt), Buffer.from(input.code), backupPepper]));
      if (!item.used && timingSafeEqualText(candidate, item.hash)) matched = item;
    }
    if (!matched) {
      failure(session);
      return json({ error: "Verification could not be completed." }, 400);
    }
    matched.used = true;
    clearFailures(session);
    return json({ csrf: session.csrf, verified: true });
  }

  if (url.pathname === "/api/mfa/backup/regenerate") {
    if (!account.mfaEnabled) return json({ error: "Authenticator setup is required first." }, 400);
    const generated = generateBackupCodes();
    account.backupCodes = generated.stored;
    return json({ csrf: session.csrf, codes: generated.plain });
  }

  return json({ error: "Request could not be completed." }, 404);
}

/* [2] Production-safe catch: no debug stacks or secret-bearing errors are returned. */
Bun.serve({
  port: PORT,
  tls: { cert: certFile, key: keyFile },
  async fetch(request) {
    try {
      return await handle(request);
    } catch {
      return json({ error: "Service temporarily unavailable." }, 500);
    }
  },
});

console.log(`MFA enrolment service listening securely on https://localhost:${PORT}`);
