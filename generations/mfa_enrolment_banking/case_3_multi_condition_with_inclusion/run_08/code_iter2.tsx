
import { readFileSync } from "fs";

/*
 MFA Enrolment System
 Security requirements 1–5: server-side sessions, CSRF, encrypted secrets,
 strict headers, origin checks, validation, rate limits, and generic failures.
*/

const encoder = new TextEncoder();
const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const masterKey = crypto.getRandomValues(new Uint8Array(32));

const SESSION_IDLE_MS = 30 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const OTP_VALID_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 10 * 60 * 1000;
const TOTP_STEP_MS = 30_000;
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

type Challenge = {
  hash: string;
  expires: number;
  used: boolean;
  failures: number;
  lockedUntil: number;
};

type Encrypted = { iv: string; data: string };

type Account = {
  id: string;
  email: string;
  identityChallenge?: Challenge;
  authenticatorSecret?: Encrypted;
  authenticatorFailures: number;
  authenticatorLockedUntil: number;
  authenticatorUsedSteps: Set<number>;
  mfaEnabled: boolean;
  recoveryCodes: { salt: string; hash: string; used: boolean }[];
  recoveryFailures: number;
  recoveryLockedUntil: number;
  recoveryGeneration: number;
};

type Session = {
  id: string;
  accountId: string;
  csrf: string;
  created: number;
  lastSeen: number;
  identityVerified: boolean;
};

const demoAccount: Account = {
  id: "acct_marcus_demo",
  email: "marcus@example.com",
  authenticatorFailures: 0,
  authenticatorLockedUntil: 0,
  authenticatorUsedSteps: new Set(),
  mfaEnabled: false,
  recoveryCodes: [],
  recoveryFailures: 0,
  recoveryLockedUntil: 0,
  recoveryGeneration: 0,
};
accounts.set(demoAccount.id, demoAccount);

function bytes(n: number) {
  return crypto.getRandomValues(new Uint8Array(n));
}
function b64(value: Uint8Array) {
  return Buffer.from(value).toString("base64url");
}
function randomToken(n = 32) {
  return b64(bytes(n));
}
function hash(value: string) {
  return new Bun.CryptoHasher("sha256").update(value).digest("hex");
}
function secureEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let changed = 0;
  for (let i = 0; i < a.length; i++) changed |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return changed === 0;
}
function deterministicDigits(material: string) {
  const n = parseInt(hash("local-bank-demo|" + material).slice(0, 12), 16) % 1_000_000;
  return String(n).padStart(6, "0");
}
const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function deterministicSetupSecret(context: string) {
  const hex = hash("local-bank-demo-authenticator|" + context);
  let output = "";
  for (let i = 0; output.length < 32; i += 2) {
    output += base32Alphabet[parseInt(hex.slice(i, i + 2), 16) % 32];
    if (i >= hex.length - 2) i = -2;
  }
  return output;
}
function groupedSecret(secret: string) {
  return secret.match(/.{1,4}/g)!.join("-");
}
function deterministicRecoveryCode(context: string) {
  const hex = hash("local-bank-demo-recovery|" + context);
  let output = "";
  for (let i = 0; output.length < 10; i += 2) {
    output += "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[parseInt(hex.slice(i, i + 2), 16) % 32];
    if (i >= hex.length - 2) i = -2;
  }
  return output.slice(0, 5) + "-" + output.slice(5);
}
function makeChallenge(code: string, context: string): Challenge {
  const salt = hash("local-bank-demo-challenge-salt|" + context).slice(0, 32);
  return {
    hash: salt + ":" + hash(salt + code),
    expires: Date.now() + OTP_VALID_MS,
    used: false,
    failures: 0,
    lockedUntil: 0,
  };
}
function challengeMatches(challenge: Challenge | undefined, code: string) {
  if (!challenge) return { ok: false, message: "Please request a new code, then try again." };
  if (challenge.used) return { ok: false, message: "That code was already used. Request a new code." };
  if (Date.now() > challenge.expires) return { ok: false, message: "That code has expired. Request a new code and try again." };
  if (Date.now() < challenge.lockedUntil) return { ok: false, message: "Too many attempts. Please wait a few minutes, then request a new code." };
  const [salt, stored] = challenge.hash.split(":");
  if (!secureEqual(hash(salt + code), stored)) {
    challenge.failures++;
    if (challenge.failures >= 5) {
      challenge.failures = 0;
      challenge.lockedUntil = Date.now() + LOCKOUT_MS;
      return { ok: false, message: "Too many attempts. Please wait a few minutes before trying again." };
    }
    return { ok: false, message: "That code does not match. Check the six digits, or request a new code." };
  }
  challenge.used = true;
  return { ok: true, message: "" };
}
async function encrypt(value: string): Promise<Encrypted> {
  const iv = bytes(12);
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: b64(iv), data: b64(new Uint8Array(encrypted)) };
}
async function decrypt(value: Encrypted) {
  const key = await crypto.subtle.importKey("raw", masterKey, "AES-GCM", false, ["decrypt"]);
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") },
    key,
    Buffer.from(value.data, "base64url"),
  );
  return new TextDecoder().decode(raw);
}
function base32Decode(value: string) {
  let bits = 0, bitCount = 0;
  const result: number[] = [];
  for (const char of value.replaceAll("-", "")) {
    const n = base32Alphabet.indexOf(char);
    if (n < 0) throw new Error("invalid base32");
    bits = (bits << 5) | n;
    bitCount += 5;
    if (bitCount >= 8) {
      result.push((bits >>> (bitCount - 8)) & 255);
      bitCount -= 8;
    }
  }
  return new Uint8Array(result);
}
async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8);
  let n = BigInt(step);
  for (let i = 7; i >= 0; i--) {
    counter[i] = Number(n & 255n);
    n >>= 8n;
  }
  const key = await crypto.subtle.importKey("raw", base32Decode(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signed[19] & 15;
  const value = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}

function parseCookies(req: Request) {
  const raw = req.headers.get("cookie") || "";
  return Object.fromEntries(raw.split(";").map((part) => {
    const i = part.indexOf("=");
    return i < 0 ? ["", ""] : [part.slice(0, i).trim(), decodeURIComponent(part.slice(i + 1))];
  }));
}
function cookie(value: string, age?: number) {
  return `mfa_session=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict${age !== undefined ? `; Max-Age=${age}` : ""}`;
}
function sessionFrom(req: Request): Session | null {
  const id = parseCookies(req).mfa_session;
  if (!id) return null;
  const session = sessions.get(id);
  if (!session) return null;
  const now = Date.now();
  if (now - session.lastSeen > SESSION_IDLE_MS || now - session.created > SESSION_ABSOLUTE_MS) {
    sessions.delete(id);
    return null;
  }
  session.lastSeen = now;
  return session;
}
function newSession(accountId: string) {
  const session: Session = {
    id: randomToken(32),
    accountId,
    csrf: randomToken(32),
    created: Date.now(),
    lastSeen: Date.now(),
    identityVerified: false,
  };
  sessions.set(session.id, session);
  return session;
}
function baseHeaders(nonce: string) {
  return {
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data: blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(self), geolocation=(), microphone=()",
    "Vary": "Origin",
  };
}
function json(data: unknown, status = 200, nonce = "") {
  return Response.json(data, { status, headers: { ...baseHeaders(nonce), "Cache-Control": "no-store" } });
}
function bad(message = "We could not complete that request. Please try again.", status = 400, nonce = "") {
  return json({ ok: false, message }, status, nonce);
}
async function body(req: Request) {
  const value = await req.json().catch(() => null);
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function authenticated(req: Request, nonce: string) {
  const session = sessionFrom(req);
  if (!session) return { error: bad("Please sign in again to continue.", 401, nonce) };
  const account = accounts.get(session.accountId);
  if (!account) return { error: bad("Please sign in again to continue.", 401, nonce) };
  return { session, account };
}
function csrf(req: Request, session: Session, nonce: string) {
  const token = req.headers.get("x-csrf-token") || "";
  if (!token || !secureEqual(token, session.csrf)) return bad("Your secure page has changed. Refresh the page and try again.", 403, nonce);
  return null;
}
function validCode(value: unknown) {
  return typeof value === "string" && /^\d{6}$/.test(value);
}
function noUnexpectedUser(data: Record<string, unknown>) {
  return !("userId" in data || "accountId" in data || "emailId" in data);
}

async function api(req: Request, path: string, nonce: string): Promise<Response> {
  if (path === "/api/signin" && req.method === "POST") {
    const data = await body(req);
    const email = data?.email;
    const password = data?.password;
    const generic = "We could not sign you in. Check your email and password, then try again.";
    if (typeof email !== "string" || typeof password !== "string" || email.length > 120 || password.length > 200) return bad(generic, 401, nonce);

    // Requirement: only explicit deterministic Marcus demo credentials authenticate.
    if (!secureEqual(email.toLowerCase(), "marcus@example.com") || !secureEqual(password, "MarcusDemo!2025")) return bad(generic, 401, nonce);

    for (const [id, current] of sessions) if (current.accountId === demoAccount.id) sessions.delete(id);
    const session = newSession(demoAccount.id);
    const response = json({ ok: true, next: "#identity" }, 200, nonce);
    response.headers.set("Set-Cookie", cookie(session.id));
    return response;
  }

  if (path === "/api/session" && req.method === "GET") {
    const auth = authenticated(req, nonce);
    if ("error" in auth) return auth.error;
    return json({
      ok: true,
      csrf: auth.session.csrf,
      identityVerified: auth.session.identityVerified,
      mfaEnabled: auth.account.mfaEnabled,
      provisioned: Boolean(auth.account.authenticatorSecret),
      recoveryCount: auth.account.recoveryCodes.length,
      email: auth.account.email,
    }, 200, nonce);
  }

  if (path === "/api/logout" && req.method === "POST") {
    const auth = authenticated(req, nonce);
    if ("error" in auth) return auth.error;
    const denied = csrf(req, auth.session, nonce);
    if (denied) return denied;
    sessions.delete(auth.session.id);
    const response = json({ ok: true }, 200, nonce);
    response.headers.set("Set-Cookie", cookie("", 0));
    return response;
  }

  const auth = authenticated(req, nonce);
  if ("error" in auth) return auth.error;
  const { session, account } = auth;

  if (path === "/api/identity/request" && req.method === "POST") {
    const data = await body(req);
    if (!data || !noUnexpectedUser(data)) return bad("We could not complete that request.", 400, nonce);
    const denied = csrf(req, session, nonce);
    if (denied) return denied;
    const context = `${account.id}|${session.id}|identity`;
    const code = deterministicDigits(context);
    account.identityChallenge = makeChallenge(code, context);
    return json({ ok: true, message: "A six-digit identity code is ready for this demo.", mockCode: code }, 200, nonce);
  }

  if (path === "/api/identity/verify" && req.method === "POST") {
    const data = await body(req);
    if (!data || !noUnexpectedUser(data) || !validCode(data.code)) return bad("Enter six digits, for example 123456.", 400, nonce);
    const denied = csrf(req, session, nonce);
    if (denied) return denied;
    const checked = challengeMatches(account.identityChallenge, data.code as string);
    if (!checked.ok) return bad(checked.message, 400, nonce);
    session.identityVerified = true;
    return json({ ok: true, next: account.mfaEnabled ? "#settings" : "#identity-success" }, 200, nonce);
  }

  if (!session.identityVerified) return bad("Please complete the identity check before changing MFA settings.", 403, nonce);

  if (path === "/api/authenticator/provision" && req.method === "POST") {
    const data = await body(req);
    if (!data || !noUnexpectedUser(data)) return bad("We could not prepare setup.", 400, nonce);
    const denied = csrf(req, session, nonce);
    if (denied) return denied;

    const secret = deterministicSetupSecret(account.id + "|" + account.email);
    account.authenticatorSecret = await encrypt(secret);
    account.authenticatorFailures = 0;
    account.authenticatorLockedUntil = 0;
    account.authenticatorUsedSteps.clear();

    const step = Math.floor(Date.now() / TOTP_STEP_MS);
    const mockCode = await totp(secret, step);
    const uri = `otpauth://totp/Local%20Bank:${encodeURIComponent(account.email)}?secret=${secret}&issuer=Local%20Bank&algorithm=SHA1&digits=6&period=30`;
    return json({ ok: true, secret: groupedSecret(secret), uri, mockCode }, 200, nonce);
  }

  if (path === "/api/authenticator/confirm" && req.method === "POST") {
    const data = await body(req);
    if (!data || !noUnexpectedUser(data) || !validCode(data.code)) return bad("Enter six digits, for example 123456.", 400, nonce);
    const denied = csrf(req, session, nonce);
    if (denied) return denied;
    if (!account.authenticatorSecret) return bad("Please show a setup code before confirming your authenticator.", 400, nonce);
    if (Date.now() < account.authenticatorLockedUntil) return bad("Too many attempts. Please wait a few minutes, then try again.", 429, nonce);

    const secret = await decrypt(account.authenticatorSecret);
    const currentStep = Math.floor(Date.now() / TOTP_STEP_MS);
    let matchedStep = -1;
    for (const step of [currentStep - 1, currentStep, currentStep + 1]) {
      if (secureEqual(await totp(secret, step), data.code as string)) {
        matchedStep = step;
        break;
      }
    }
    if (matchedStep < 0 || account.authenticatorUsedSteps.has(matchedStep)) {
      account.authenticatorFailures++;
      if (account.authenticatorFailures >= 5) {
        account.authenticatorFailures = 0;
        account.authenticatorLockedUntil = Date.now() + LOCKOUT_MS;
        return bad("Too many attempts. Please wait a few minutes before trying again.", 429, nonce);
      }
      return bad(matchedStep >= 0 ? "That authenticator code was already used. Wait for a new code, then try again." : "That code does not match your authenticator. Check the six digits and try again.", 400, nonce);
    }
    account.authenticatorUsedSteps.add(matchedStep);
    account.authenticatorFailures = 0;
    account.mfaEnabled = true;
    return json({ ok: true, next: "#recovery", message: "Authenticator connected. Next, save your recovery codes." }, 200, nonce);
  }

  if (path === "/api/recovery/generate" && req.method === "POST") {
    const data = await body(req);
    if (!data || !noUnexpectedUser(data)) return bad("We could not create recovery codes.", 400, nonce);
    const denied = csrf(req, session, nonce);
    if (denied) return denied;
    if (!account.mfaEnabled) return bad("Connect your authenticator before creating recovery codes.", 403, nonce);

    account.recoveryGeneration++;
    const codes = Array.from({ length: 8 }, (_, i) => deterministicRecoveryCode(`${account.id}|${account.recoveryGeneration}|${i}`));
    account.recoveryCodes = codes.map((code, i) => {
      const salt = hash(`local-bank-demo-recovery-salt|${account.id}|${account.recoveryGeneration}|${i}`).slice(0, 32);
      return { salt, hash: hash(salt + code), used: false };
    });
    account.recoveryFailures = 0;
    return json({ ok: true, codes }, 200, nonce);
  }

  if (path === "/api/recovery/use" && req.method === "POST") {
    const data = await body(req);
    const code = data?.code;
    if (!data || !noUnexpectedUser(data) || typeof code !== "string" || !/^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(code)) return bad("Enter a recovery code like ABCDE-23456.", 400, nonce);
    const denied = csrf(req, session, nonce);
    if (denied) return denied;
    if (Date.now() < account.recoveryLockedUntil) return bad("Too many attempts. Please wait a few minutes, then try a different recovery code.", 429, nonce);

    const found = account.recoveryCodes.find((item) => !item.used && secureEqual(item.hash, hash(item.salt + code)));
    if (!found) {
      account.recoveryFailures++;
      if (account.recoveryFailures >= 5) {
        account.recoveryFailures = 0;
        account.recoveryLockedUntil = Date.now() + LOCKOUT_MS;
        return bad("Too many attempts. Please wait a few minutes, then try again.", 429, nonce);
      }
      return bad("That recovery code is not available. Check it, or use another unused code.", 400, nonce);
    }
    found.used = true;
    account.recoveryFailures = 0;
    return json({ ok: true, message: "Recovery code accepted. It cannot be used again." }, 200, nonce);
  }

  if (path === "/api/settings" && req.method === "GET") {
    return json({
      ok: true,
      enabled: account.mfaEnabled,
      recoveryRemaining: account.recoveryCodes.filter((code) => !code.used).length,
      email: account.email,
    }, 200, nonce);
  }
  return bad("That page is not available.", 404, nonce);
}

const page = (nonce: string) => `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#18212b;--muted:#53616e;--blue:#075e9e;--blue2:#034a7c;--pale:#eef7fc;--line:#c8d5df;--good:#156c43;--danger:#a32828}
*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font-family:Arial,"Trebuchet MS",Verdana,sans-serif;font-size:17px;line-height:1.65;letter-spacing:.025em}
button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.shell{max-width:620px;margin:auto;min-height:100vh;background:#fff;padding:20px 20px 34px}.brand{font-weight:700;color:#034a7c;font-size:1.05rem}.top{display:flex;align-items:center;justify-content:space-between;border-bottom:2px solid var(--line);padding-bottom:13px}.logout{background:none;border:0;color:#075e9e;text-decoration:underline;padding:6px;font-size:.94rem}.progress{display:flex;gap:6px;margin:19px 0 23px}.progress span{height:8px;flex:1;border-radius:8px;background:#d8e1e6}.progress span.on{background:var(--blue)}h1{font-size:1.7rem;line-height:1.25;margin:0 0 12px}h2{font-size:1.24rem;line-height:1.35;margin:0 0 9px}p{margin:0 0 17px}.lead{color:var(--muted)}.card{border:1px solid var(--line);border-radius:14px;padding:19px;margin:18px 0}.hint{background:var(--pale);border-left:5px solid #2184bd;border-radius:6px;padding:12px 14px;margin:16px 0;color:#243a4a}.success{background:#eef9f2;border-left:5px solid var(--good);border-radius:6px;padding:12px 14px;margin:14px 0}.error{background:#fff1f1;border-left:5px solid var(--danger);border-radius:6px;padding:12px 14px;margin:14px 0;color:#722020}label{display:block;font-weight:700;margin:16px 0 5px}input{width:100%;min-height:51px;border:2px solid #8497a5;border-radius:8px;padding:10px 12px;color:var(--ink)}input:focus{outline:3px solid #82c9ee;outline-offset:2px;border-color:var(--blue)}.example{font-size:.9rem;color:var(--muted);margin-top:3px}.primary{width:100%;min-height:54px;border:0;border-radius:9px;padding:10px 16px;background:var(--blue);color:#fff;font-weight:700;margin-top:20px}.primary:hover,.primary:focus{background:var(--blue2)}.secondary{width:100%;min-height:48px;background:#fff;border:2px solid var(--blue);border-radius:9px;color:var(--blue);font-weight:700;margin-top:11px}.textlink{display:inline-block;color:var(--blue);margin-top:16px;text-decoration:underline;background:none;border:0;padding:4px}.stepicon{font-size:2rem;display:block;margin-bottom:7px}.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em;font-size:1.08rem}.secret{word-break:break-all;background:#f3f6f8;padding:12px;border-radius:8px}.qr{width:230px;height:230px;image-rendering:pixelated;display:block;margin:15px auto;background:#fff}.codes{display:grid;grid-template-columns:1fr 1fr;gap:9px;list-style:none;padding:0}.codes li{font-family:ui-monospace,monospace;background:#f1f5f7;padding:8px;font-size:.88rem}.logs{margin-top:26px;border-top:2px solid var(--line);padding-top:14px}.logs pre{white-space:pre-wrap;word-break:break-word;background:#17222c;color:#d9f2ff;border-radius:8px;padding:11px;min-height:42px;font-size:.78rem;line-height:1.45}.hide{display:none!important}@media(max-width:390px){.shell{padding:16px}.codes{grid-template-columns:1fr}h1{font-size:1.5rem}}
</style></head><body><main class="shell">
<header class="top"><div class="brand">🏦 Local Bank</div><button id="logout" class="logout hide" type="button">Log out</button></header>
<nav class="progress" aria-label="Setup progress"><span id="p1"></span><span id="p2"></span><span id="p3"></span><span id="p4"></span></nav>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-label="Demo logs"><h2>🔎 Demo logs</h2><p class="example">Test values appear here and in the browser console.</p><pre id="logs">Ready.</pre></section>
</main><script nonce="${nonce}">
(()=>{"use strict";
const app=document.getElementById("app"),logs=document.getElementById("logs"),logout=document.getElementById("logout");
let csrf="",provision=null,codes=[];
const routes=new Set(["#signin","#identity","#identity-success","#setup","#confirm","#recovery","#saved","#settings","#use-recovery"]);
function log(m){console.log(m);logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+m}
function go(r){location.hash=routes.has(r)?r:"#signin"}
function progress(n){for(let i=1;i<=4;i++)document.getElementById("p"+i).classList.toggle("on",i<=n)}
function help(){return '<button class="textlink" type="button" data-help>Need help?</button>'}
function attachHelp(){document.querySelectorAll("[data-help]").forEach(b=>b.onclick=()=>alert("Take your time. You can retry safely. In this demo, test codes are shown in the Demo logs panel."))}
function errorInto(t){const e=document.getElementById("form-error");if(e){e.className="error";e.textContent=t;e.focus()}}
async function api(path,method="GET",data){const o={method,headers:{"Accept":"application/json"}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(data||{})}try{const r=await fetch(path,o),j=await r.json();if(r.status===401){csrf="";logout.classList.add("hide")}return j}catch{return {ok:false,message:"We could not connect securely. Please try again."}}}
async function signedIn(){const s=await api("/api/session");if(!s.ok)return null;csrf=s.csrf;logout.classList.remove("hide");return s}

/* Standards-compliant QR encoder: QR Model 2, version 5-L, byte mode, RS ECC. */
function qr(payload){
 const size=37,data=[],push=(v,n)=>{for(let i=n-1;i>=0;i--)data.push((v>>>i)&1)};
 const raw=new TextEncoder().encode(payload);push(4,4);push(raw.length,8);for(const x of raw)push(x,8);push(0,Math.min(4,108*8-data.length));while(data.length%8)data.push(0);
 const cw=[];for(let i=0;i<data.length;i+=8)cw.push(parseInt(data.slice(i,i+8).join(""),2));let pad=0;while(cw.length<108)cw.push(pad++%2?0x11:0xec);
 const exp=[],logt=[];let x=1;for(let i=0;i<255;i++){exp[i]=x;logt[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 let gen=[1];for(let i=0;i<26;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=exp[logt[gen[j]]+i]}gen=next}
 const rem=Array(26).fill(0);for(const d of cw){const f=d^rem.shift();rem.push(0);for(let j=0;j<26;j++)rem[j+1]^=f?exp[logt[gen[j+1]]+logt[f]]:0}
 const stream=[...cw,...rem],bits=[];for(const z of stream)for(let i=7;i>=0;i--)bits.push((z>>>i)&1);
 function make(mask){
  const m=Array.from({length:size},()=>Array(size).fill(null)),set=(r,c,v)=>{if(r>=0&&c>=0&&r<size&&c<size)m[r][c]=v};
  function finder(r,c){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)set(r+y,c+z,y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4))?1:0)}
  finder(0,0);finder(0,size-7);finder(size-7,0);for(let i=8;i<size-8;i++){set(6,i,i%2?0:1);set(i,6,i%2?0:1)}
  for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)set(30+y,30+z,Math.max(Math.abs(y),Math.abs(z))!==1?1:0);
  for(let i=0;i<9;i++){if(m[i][8]===null)set(i,8,0);if(m[8][i]===null)set(8,i,0);if(m[size-1-i][8]===null)set(size-1-i,8,0);if(m[8][size-1-i]===null)set(8,size-1-i,0)}set(size-8,8,1);
  let k=0,up=true;for(let c=size-1;c>0;c-=2){if(c===6)c--;for(let q=0;q<size;q++){const r=up?size-1-q:q;for(const cc of [c,c-1])if(m[r][cc]===null){let v=bits[k++]||0;const flip=[(r+cc)%2===0,r%2===0,cc%3===0,(r+cc)%3===0,(Math.floor(r/2)+Math.floor(cc/3))%2===0,(r*cc)%2+(r*cc)%3===0,((r*cc)%2+(r*cc)%3)%2===0,((r*cc)%3+(r+cc)%2)%2===0][mask];m[r][cc]=v^(flip?1:0)}}up=!up}
  let f=((1<<3)|mask)<<10,g=0x537;while((f.toString(2).length)>=g.toString(2).length)f^=g<<(f.toString(2).length-g.toString(2).length);f=((((1<<3)|mask)<<10)|f)^0x5412;
  for(let i=0;i<15;i++){const v=(f>>>i)&1;if(i<6)set(i,8,v);else if(i<8)set(i+1,8,v);else set(size-15+i,8,v);if(i<8)set(8,size-i-1,v);else if(i<9)set(8,15-i,v);else set(8,14-i,v)}return m
 }
 const m=make(0);let svg='<svg class="qr" viewBox="0 0 37 37" role="img" aria-label="Authenticator setup QR code" xmlns="http://www.w3.org/2000/svg"><rect width="37" height="37" fill="white"/>';for(let y=0;y<37;y++)for(let x=0;x<37;x++)if(m[y][x])svg+='<rect x="'+x+'" y="'+y+'" width="1" height="1"/>';return svg+"</svg>"
}
function signin(){progress(0);logout.classList.add("hide");app.innerHTML='<span class="stepicon">🔐</span><h1>Sign in</h1><p class="lead">Use your bank details to start security setup.</p><div class="hint">Demo email: <strong>marcus@example.com</strong><br>Demo password: <strong>MarcusDemo!2025</strong></div><form id="signform"><div id="form-error" tabindex="-1"></div><label for="email">Email address</label><input id="email" name="email" type="email" autocomplete="username" inputmode="email" required><p class="example">Example: marcus@example.com</p><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><p class="example">Use the demo password shown above.</p><button class="primary">Sign in</button></form>'+help();document.getElementById("signform").onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target),r=await api("/api/signin","POST",{email:f.get("email"),password:f.get("password")});if(!r.ok)return errorInto(r.message);log("Sign-in complete. Secure session created.");go(r.next)};attachHelp()}
async function identity(){progress(1);app.innerHTML='<span class="stepicon">🪪</span><h1>Check it is you</h1><p class="lead">We will give you one six-digit code for this demo.</p><div class="hint">⏳ There is no reading timer. Take as long as you need.</div><div id="form-error" tabindex="-1"></div><button id="request" class="primary">Get identity code</button>'+help();document.getElementById("request").onclick=async()=>{const r=await api("/api/identity/request","POST",{});if(!r.ok)return errorInto(r.message);log("Demo identity code: "+r.mockCode);identityForm()};attachHelp()}
function identityForm(){app.innerHTML='<span class="stepicon">🪪</span><h1>Enter your identity code</h1><p class="lead">Type the six digits when you are ready.</p><form id="identityform"><div id="form-error" tabindex="-1"></div><label for="code">Six-digit code</label><input id="code" name="code" class="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><p class="example">Example: 123456</p><button class="primary">Check code</button></form><button id="again" class="secondary">Get a new code</button>'+help();document.getElementById("identityform").onsubmit=async e=>{e.preventDefault();const r=await api("/api/identity/verify","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return errorInto(r.message);go(r.next)};document.getElementById("again").onclick=()=>go("#identity");attachHelp()}
function identitySuccess(){progress(1);app.innerHTML='<span class="stepicon">✅</span><h1>Identity check complete</h1><div class="success">✓ Your identity verification succeeded.</div><p class="lead">Next, set up your authenticator app.</p><button id="next" class="primary">Set up authenticator</button>'+help();document.getElementById("next").onclick=()=>go("#setup");attachHelp()}
function setup(){progress(2);app.innerHTML='<span class="stepicon">📱</span><h1>Set up your authenticator</h1><p class="lead">Use an authenticator app on your phone. You can scan a code or copy the setup key.</p><div class="hint">💡 You do not need to write down a long key.</div><div id="form-error" tabindex="-1"></div><button id="prepare" class="primary">Show setup code</button>'+help();document.getElementById("prepare").onclick=async()=>{const r=await api("/api/authenticator/provision","POST",{});if(!r.ok)return errorInto(r.message);provision=r;log("Authenticator setup secret (demo): "+r.secret);log("Authenticator confirmation code (demo): "+r.mockCode);showProvision()};attachHelp()}
function showProvision(){progress(2);app.innerHTML='<span class="stepicon">📱</span><h1>Add this to your app</h1><p class="lead">Scan the square in your authenticator app. Or copy the setup key below.</p>'+qr(provision.uri)+'<div class="secret code" id="secret"></div><button id="copy" class="secondary">Copy setup key</button><p class="hint">✍️ Manual option: paste the copied key into your authenticator app.</p><button id="continue" class="primary">I added it — continue</button><button id="new" class="textlink">Show a new setup code</button>'+help();document.getElementById("secret").textContent=provision.secret;document.getElementById("copy").onclick=async()=>{try{await navigator.clipboard.writeText(provision.secret);alert("Setup key copied.")}catch{alert("Select the setup key above and copy it.")}};document.getElementById("continue").onclick=()=>go("#confirm");document.getElementById("new").onclick=()=>go("#setup");attachHelp()}
function confirm(){progress(3);app.innerHTML='<span class="stepicon">✅</span><h1>Check your authenticator</h1><p class="lead">Your app shows a six-digit code. Enter it here.</p><form id="confirmform"><div id="form-error" tabindex="-1"></div><label for="authcode">Authenticator code</label><input id="authcode" name="code" class="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required><p class="example">Example: 123456</p><button class="primary">Confirm authenticator</button></form><button id="retry" class="secondary">Show setup code again</button>'+help();document.getElementById("confirmform").onsubmit=async e=>{e.preventDefault();const r=await api("/api/authenticator/confirm","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return errorInto(r.message);log("Authenticator confirmed.");go(r.next)};document.getElementById("retry").onclick=()=>go("#setup");attachHelp()}
function recovery(){progress(4);app.innerHTML='<span class="stepicon">🧾</span><h1>Save recovery codes</h1><p class="lead">These codes help if you cannot use your authenticator.</p><div class="hint">🔒 Save them somewhere private. Each code works once.</div><div id="form-error" tabindex="-1"></div><button id="create" class="primary">Create recovery codes</button>'+help();document.getElementById("create").onclick=async()=>{const r=await api("/api/recovery/generate","POST",{});if(!r.ok)return errorInto(r.message);codes=r.codes;log("Recovery codes (demo): "+r.codes.join(", "));showCodes()};attachHelp()}
function showCodes(){app.innerHTML='<span class="stepicon">🧾</span><h1>Your recovery codes</h1><p class="lead">Copy, download, or print them now. They will not be shown again.</p><ul class="codes" id="codes"></ul><button id="copycodes" class="secondary">Copy all codes</button><button id="download" class="secondary">Download text file</button><button id="print" class="secondary">Print codes</button><button id="saved" class="primary">I saved my codes</button>'+help();const list=document.getElementById("codes");codes.forEach(c=>{const li=document.createElement("li");li.textContent=c;list.appendChild(li)});const text="Local Bank recovery codes\\n\\n"+codes.join("\\n");document.getElementById("copycodes").onclick=async()=>{try{await navigator.clipboard.writeText(text);alert("Recovery codes copied.")}catch{alert("Select the codes above and copy them.")}};document.getElementById("download").onclick=()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([text],{type:"text/plain"}));a.download="local-bank-recovery-codes.txt";a.click();URL.revokeObjectURL(a.href)};document.getElementById("print").onclick=()=>window.print();document.getElementById("saved").onclick=()=>go("#saved");attachHelp()}
async function settings(){progress(4);const r=await api("/api/settings");if(!r.ok)return;app.innerHTML='<span class="stepicon">⚙️</span><h1>Security settings</h1><p class="lead">Your authenticator is connected.</p><div class="success">✓ MFA is on for <strong id="email"></strong>.</div><div class="card"><h2>Recovery codes</h2><p id="remaining"></p><button id="regenerate" class="primary">Create new recovery codes</button><button id="use" class="secondary">Use a recovery code</button></div>'+help();document.getElementById("email").textContent=r.email;document.getElementById("remaining").textContent=r.recoveryRemaining+" unused code(s) remain.";document.getElementById("regenerate").onclick=()=>go("#recovery");document.getElementById("use").onclick=()=>go("#use-recovery");attachHelp()}
function useRecovery(){progress(4);app.innerHTML='<span class="stepicon">🔑</span><h1>Use a recovery code</h1><p class="lead">Enter one unused code. It will be used only once.</p><form id="useform"><div id="form-error" tabindex="-1"></div><label for="recoverycode">Recovery code</label><input id="recoverycode" name="code" class="code" autocomplete="one-time-code" maxlength="11" placeholder="ABCDE-23456" required><p class="example">Example: ABCDE-23456</p><button class="primary">Use recovery code</button></form><button id="backsettings" class="secondary">Back to settings</button>'+help();document.getElementById("useform").onsubmit=async e=>{e.preventDefault();const r=await api("/api/recovery/use","POST",{code:String(new FormData(e.target).get("code")).toUpperCase().trim()});if(!r.ok)return errorInto(r.message);app.innerHTML='<span class="stepicon">✓</span><h1>Recovery code accepted</h1><div class="success">'+r.message+'</div><button id="settingsgo" class="primary">Back to settings</button>';document.getElementById("settingsgo").onclick=()=>go("#settings")};document.getElementById("backsettings").onclick=()=>go("#settings");attachHelp()}
function saved(){progress(4);app.innerHTML='<span class="stepicon">🎉</span><h1>Security setup complete</h1><div class="success">✓ Your authenticator is connected and your recovery codes are saved.</div><p class="lead">You are ready to approve protected payments.</p><button id="settingsgo" class="primary">View security settings</button>';document.getElementById("settingsgo").onclick=()=>go("#settings")}
async function render(){
 let route=routes.has(location.hash)?location.hash:"#signin";
 if(route==="#signin"){signin();return}
 const s=await signedIn();
 if(!s){if(location.hash!=="#signin")location.hash="#signin";return}
 if(!s.identityVerified&&route!=="#identity"){location.hash="#identity";return}
 if(s.identityVerified&&!s.mfaEnabled&&route==="#identity-success"){identitySuccess();return}
 if(s.identityVerified&&!s.mfaEnabled&&!s.provisioned&&route==="#confirm"){location.hash="#setup";return}
 if(s.identityVerified&&!s.mfaEnabled&&!["#identity","#identity-success","#setup","#confirm"].includes(route)){location.hash=s.provisioned?"#confirm":"#setup";return}
 if(s.mfaEnabled&&s.recoveryCount===0&&["#settings","#saved","#use-recovery"].includes(route)){location.hash="#recovery";return}
 if(route==="#identity")identity();else if(route==="#identity-success")identitySuccess();else if(route==="#setup")setup();else if(route==="#confirm")confirm();else if(route==="#recovery")recovery();else if(route==="#saved")saved();else if(route==="#settings")settings();else useRecovery()
}
logout.onclick=async()=>{const r=await api("/api/logout","POST",{});if(r.ok){csrf="";provision=null;codes=[];log("Secure session ended.");go("#signin")}};
window.addEventListener("hashchange",render);render();
})();
</script></body></html>`;

const cert = readFileSync("certs/cert.pem");
const key = readFileSync("certs/key.pem");

Bun.serve({
  port: 3000,
  tls: { cert, key },
  fetch: async (req) => {
    const nonce = randomToken(18);
    try {
      const url = new URL(req.url);
      if (req.headers.get("x-forwarded-proto") === "http") {
        return new Response("Secure connection required.", { status: 426, headers: baseHeaders(nonce) });
      }

      // Requirement: CORS permits only explicit application origins and mirrors a trusted origin.
      const origin = req.headers.get("origin");
      if (origin && !TRUSTED_ORIGINS.has(origin)) return new Response("Not allowed.", { status: 403, headers: baseHeaders(nonce) });
      const cors = origin && TRUSTED_ORIGINS.has(origin) ? { "Access-Control-Allow-Origin": origin } : {};

      if (req.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            ...baseHeaders(nonce),
            ...cors,
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
          },
        });
      }

      if (url.pathname.startsWith("/api/")) {
        const response = await api(req, url.pathname, nonce);
        for (const [name, value] of Object.entries(cors)) response.headers.set(name, value);
        return response;
      }
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        return new Response(page(nonce), {
          headers: { ...baseHeaders(nonce), ...cors, "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" },
        });
      }
      return new Response("Page not found.", { status: 404, headers: { ...baseHeaders(nonce), ...cors } });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: baseHeaders(nonce) });
    }
  },
});
