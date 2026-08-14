
import { readFileSync } from "fs";

/* Requirements 1–5: deterministic in-memory demo state, owner-bound sessions,
   CSRF protection, encrypted TOTP secret storage, hashed recovery codes. */
const accounts = new Map<string, Account>();
const sessions = new Map<string, Session>();
const bootstrapTokens = new Map<string, number>();
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RECOVERY_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);
const STEP = 30_000;
const IDLE_TIMEOUT = 30 * 60_000;
const ABSOLUTE_TIMEOUT = 8 * 60 * 60_000;
const CODE_LIFETIME = 15 * 60_000;
const LOCKOUT = 10 * 60_000;

type Challenge = {
  salt: string;
  hash: string;
  expires: number;
  used: boolean;
  failures: number;
  lockedUntil: number;
};
type Secret = { iv: string; data: string };
type Recovery = { salt: string; hash: string; used: boolean };
type Account = {
  id: string;
  email: string;
  mfa: boolean;
  secret?: Secret;
  identity?: Challenge;
  authFailures: number;
  authLockedUntil: number;
  usedSteps: Set<number>;
  recoveries: Recovery[];
};
type Session = {
  id: string;
  accountId: string;
  csrf: string;
  created: number;
  seen: number;
  identityVerified: boolean;
};

const marcus: Account = {
  id: "acct_marcus_demo",
  email: "marcus@example.com",
  mfa: false,
  authFailures: 0,
  authLockedUntil: 0,
  usedSteps: new Set(),
  recoveries: [],
};
accounts.set(marcus.id, marcus);

const random = (length = 32) =>
  Buffer.from(crypto.getRandomValues(new Uint8Array(length))).toString("base64url");
const digest = (value: string) =>
  new Bun.CryptoHasher("sha256").update(value).digest("hex");
function equal(a: string, b: string) {
  if (a.length !== b.length) return false;
  let different = 0;
  for (let i = 0; i < a.length; i++) different |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return different === 0;
}
function validObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return !["id", "userId", "accountId", "redirect", "next"].some((key) =>
    key in (value as Record<string, unknown>)
  );
}
const validEmail = (v: unknown) =>
  typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const validPassword = (v: unknown) => typeof v === "string" && v.length > 0 && v.length <= 128;
const validOtp = (v: unknown) => typeof v === "string" && /^\d{6}$/.test(v);
const validRecovery = (v: unknown) =>
  typeof v === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(v);

function seed() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map((v) => BASE32[v & 31]).join("");
}
function groupedSeed(value: string) {
  return value.match(/.{1,4}/g)!.join("-");
}
function recoveryCode() {
  const value = [...crypto.getRandomValues(new Uint8Array(10))]
    .map((v) => RECOVERY_CHARS[v & 31])
    .join("");
  return value.slice(0, 5) + "-" + value.slice(5);
}
function identityCode(sessionId: string) {
  return String(parseInt(digest("identity-demo|" + sessionId).slice(0, 12), 16) % 1_000_000).padStart(6, "0");
}
function challenge(code: string): Challenge {
  const salt = random(24);
  return {
    salt,
    hash: digest(salt + code),
    expires: Date.now() + CODE_LIFETIME,
    used: false,
    failures: 0,
    lockedUntil: 0,
  };
}
function checkChallenge(value: Challenge | undefined, code: string) {
  if (!value) return "Request a new code, then try again.";
  if (value.used) return "That code was already used. Request a new code.";
  if (Date.now() > value.expires) return "That code has expired. Request a new code.";
  if (Date.now() < value.lockedUntil) return "Too many attempts. Please wait a few minutes, then request a new code.";
  if (!equal(digest(value.salt + code), value.hash)) {
    value.failures++;
    if (value.failures >= 5) {
      value.failures = 0;
      value.lockedUntil = Date.now() + LOCKOUT;
      return "Too many attempts. Please wait a few minutes before trying again.";
    }
    return "That code does not match. Check the six digits, or request a new code.";
  }
  value.used = true;
  return "";
}
async function encryptSecret(value: string): Promise<Secret> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textEncoder.encode(value));
  return {
    iv: Buffer.from(iv).toString("base64url"),
    data: Buffer.from(data).toString("base64url"),
  };
}
async function decryptSecret(value: Secret) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const data = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") },
    key,
    Buffer.from(value.data, "base64url")
  );
  return textDecoder.decode(data);
}
function base32Bytes(value: string) {
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const letter of value) {
    buffer = (buffer << 5) | BASE32.indexOf(letter);
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}
async function totp(secret: string, counterValue: number) {
  const counter = new Uint8Array(8);
  let count = BigInt(counterValue);
  for (let i = 7; i >= 0; i--) {
    counter[i] = Number(count & 255n);
    count >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    base32Bytes(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signed[19] & 15;
  const number =
    ((signed[offset] & 127) << 24) |
    (signed[offset + 1] << 16) |
    (signed[offset + 2] << 8) |
    signed[offset + 3];
  return String(number % 1_000_000).padStart(6, "0");
}

/* Requirement 2: strict security headers and no cache for sensitive views. */
function headers(nonce: string) {
  return {
    "Content-Security-Policy":
      "default-src 'self'; script-src 'nonce-" +
      nonce +
      "'; style-src 'nonce-" +
      nonce +
      "'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    Vary: "Origin",
  };
}
function response(data: unknown, status = 200, nonce = "") {
  return Response.json(data, { status, headers: headers(nonce) });
}
function fail(message = "We could not complete that request. Please try again.", status = 400, nonce = "") {
  return response({ ok: false, message }, status, nonce);
}
function cookieMap(request: Request) {
  return Object.fromEntries(
    (request.headers.get("cookie") || "").split(";").map((part) => {
      const at = part.indexOf("=");
      return at < 0 ? ["", ""] : [part.slice(0, at).trim(), decodeURIComponent(part.slice(at + 1))];
    })
  );
}
function sessionCookie(value: string, age?: number) {
  return (
    "mfa_session=" +
    encodeURIComponent(value) +
    "; Path=/; HttpOnly; Secure; SameSite=Strict" +
    (age === undefined ? "" : "; Max-Age=" + age)
  );
}
function bootstrapCookie(value: string) {
  return "signin_csrf=" + encodeURIComponent(value) + "; Path=/; Secure; SameSite=Strict; Max-Age=600";
}
function getSession(request: Request) {
  const session = sessions.get(cookieMap(request).mfa_session || "");
  if (!session) return null;
  if (Date.now() - session.seen > IDLE_TIMEOUT || Date.now() - session.created > ABSOLUTE_TIMEOUT) {
    sessions.delete(session.id);
    return null;
  }
  session.seen = Date.now();
  return session;
}
function owner(request: Request, nonce: string) {
  const session = getSession(request);
  const account = session && accounts.get(session.accountId);
  return session && account ? { session, account } : { error: fail("Please sign in again to continue.", 401, nonce) };
}
function csrf(request: Request, session: Session, nonce: string) {
  return equal(request.headers.get("x-csrf-token") || "", session.csrf)
    ? null
    : fail("Your secure page has changed. Refresh the page and try again.", 403, nonce);
}
async function body(request: Request) {
  const data = await request.json().catch(() => null);
  return validObject(data) ? data : null;
}

async function api(request: Request, path: string, nonce: string): Promise<Response> {
  if (path === "/api/csrf-bootstrap" && request.method === "GET") {
    const token = random();
    bootstrapTokens.set(token, Date.now() + 600_000);
    const out = response({ ok: true, csrf: token }, 200, nonce);
    out.headers.set("Set-Cookie", bootstrapCookie(token));
    return out;
  }

  if (path === "/api/signin" && request.method === "POST") {
    const data = await body(request);
    const token = request.headers.get("x-login-csrf") || "";
    const expires = bootstrapTokens.get(token);
    bootstrapTokens.delete(token);
    if (
      !ORIGINS.has(request.headers.get("origin") || "") ||
      !expires ||
      expires < Date.now() ||
      !equal(token, cookieMap(request).signin_csrf || "")
    ) return fail("Please refresh the sign-in page and try again.", 403, nonce);
    if (!data || !validEmail(data.email) || !validPassword(data.password))
      return fail("Enter a valid email address and password.", 400, nonce);
    if (!equal(String(data.email).toLowerCase(), marcus.email) || !equal(String(data.password), "MarcusDemo!2025"))
      return fail("We could not sign you in. Check your email and password, then try again.", 401, nonce);

    for (const [id, session] of sessions) if (session.accountId === marcus.id) sessions.delete(id);
    const session: Session = {
      id: random(),
      accountId: marcus.id,
      csrf: random(),
      created: Date.now(),
      seen: Date.now(),
      identityVerified: false,
    };
    sessions.set(session.id, session);
    const out = response({ ok: true, next: "#identity" }, 200, nonce);
    out.headers.set("Set-Cookie", sessionCookie(session.id));
    return out;
  }

  const current = owner(request, nonce);
  if ("error" in current) return current.error;
  const { session, account } = current;

  if (path === "/api/session" && request.method === "GET")
    return response(
      {
        ok: true,
        csrf: session.csrf,
        identityVerified: session.identityVerified,
        mfa: account.mfa,
        provisioned: !!account.secret,
        recoveryCount: account.recoveries.length,
      },
      200,
      nonce
    );

  if (request.method !== "POST") return fail("That page is not available.", 404, nonce);
  const data = await body(request);
  if (!data) return fail(undefined, 400, nonce);
  const csrfError = csrf(request, session, nonce);
  if (csrfError) return csrfError;

  if (path === "/api/logout") {
    sessions.delete(session.id);
    const out = response({ ok: true }, 200, nonce);
    out.headers.set("Set-Cookie", sessionCookie("", 0));
    return out;
  }
  if (path === "/api/identity/request") {
    const code = identityCode(session.id);
    account.identity = challenge(code);
    return response({ ok: true, simulatedCode: code }, 200, nonce);
  }
  if (path === "/api/identity/verify") {
    if (!validOtp(data.code)) return fail("Enter exactly six digits, for example 123456.", 400, nonce);
    const error = checkChallenge(account.identity, String(data.code));
    if (error) return fail(error, 400, nonce);
    session.identityVerified = true;
    return response({ ok: true, next: account.mfa ? "#saved" : "#setup" }, 200, nonce);
  }
  if (!session.identityVerified)
    return fail("Please complete the identity check before changing MFA settings.", 403, nonce);

  if (path === "/api/authenticator/provision") {
    const value = seed();
    account.secret = await encryptSecret(value);
    account.authFailures = 0;
    account.authLockedUntil = 0;
    account.usedSteps.clear();
    const issuer = "Local Bank";
    const label = issuer + ":" + account.email;
    const uri =
      "otpauth://totp/" +
      encodeURIComponent(label) +
      "?secret=" +
      encodeURIComponent(value) +
      "&issuer=" +
      encodeURIComponent(issuer) +
      "&algorithm=SHA1&digits=6&period=30";
    return response(
      {
        ok: true,
        secret: groupedSeed(value),
        provisioningUri: uri,
        simulatedOtp: await totp(value, Math.floor(Date.now() / STEP)),
      },
      200,
      nonce
    );
  }
  if (path === "/api/authenticator/confirm") {
    if (!validOtp(data.code)) return fail("Enter exactly six digits, for example 123456.", 400, nonce);
    if (!account.secret) return fail("Show a setup key before confirming your authenticator.", 400, nonce);
    if (Date.now() < account.authLockedUntil)
      return fail("Too many attempts. Please wait a few minutes, then try again.", 429, nonce);

    const value = await decryptSecret(account.secret);
    const now = Math.floor(Date.now() / STEP);
    let match = -1;
    for (const step of [now - 1, now, now + 1]) {
      if (equal(await totp(value, step), String(data.code))) {
        match = step;
        break;
      }
    }
    if (match < 0 || account.usedSteps.has(match)) {
      account.authFailures++;
      if (account.authFailures >= 5) {
        account.authFailures = 0;
        account.authLockedUntil = Date.now() + LOCKOUT;
        return fail("Too many attempts. Please wait a few minutes before trying again.", 429, nonce);
      }
      return fail(
        match >= 0
          ? "That authenticator code was already used. Show a new code and try again."
          : "That code does not match your authenticator. Check the six digits and try again.",
        400,
        nonce
      );
    }
    account.usedSteps.add(match);
    account.authFailures = 0;
    account.mfa = true;
    return response({ ok: true, next: "#recovery" }, 200, nonce);
  }
  if (path === "/api/recovery/generate") {
    if (!account.mfa) return fail("Connect your authenticator before creating recovery codes.", 403, nonce);
    const codes = Array.from({ length: 8 }, recoveryCode);
    account.recoveries = codes.map((code) => {
      const salt = random(24);
      return { salt, hash: digest(salt + code), used: false };
    });
    return response({ ok: true, codes }, 200, nonce);
  }
  return fail("That page is not available.", 404, nonce);
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Local Bank security setup</title>
<style nonce="${nonce}">
:root{--blue:#075e9e;--ink:#17212c;--muted:#53616e;--line:#c8d5df;--soft:#eef7fc}*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font:18px/1.7 Atkinson Hyperlegible,"OpenDyslexic","Segoe UI",Verdana,Arial,sans-serif;letter-spacing:.035em}.shell{max-width:620px;min-height:100vh;margin:auto;padding:20px;background:#fff}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--line);padding-bottom:12px}.brand{font-weight:800;color:#034a7c}button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.link{border:0;background:none;color:var(--blue);text-decoration:underline;padding:6px}.hide{display:none!important}.progress{display:flex;gap:6px;margin:19px 0}.progress i{height:8px;flex:1;background:#d8e1e6;border-radius:9px}.progress .on{background:var(--blue)}h1{font-size:1.7rem;line-height:1.3;margin:18px 0 8px}h2{font-size:1.15rem}.lead,.example{color:var(--muted)}.hint,.success,.error{padding:13px 14px;margin:16px 0;border-radius:8px;background:var(--soft);border-left:5px solid #2184bd}.success{background:#eef9f2;border-color:#156c43}.error{background:#fff1f1;border-color:#8d2424;color:#702020}label{display:block;font-weight:800;margin-top:16px}input{width:100%;min-height:53px;border:2px solid #8497a5;border-radius:8px;padding:10px;font-size:1.08rem}input:focus{outline:3px solid #82c9ee;outline-offset:2px}.primary,.secondary{width:100%;min-height:54px;border-radius:9px;padding:9px;margin-top:18px;font-weight:800}.primary{border:0;background:var(--blue);color:#fff}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue)}.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em}.secret{padding:14px;background:#f3f6f8;overflow-wrap:anywhere;min-height:56px}.qr-wrap{text-align:center;margin:17px 0;padding:16px;background:#f4f8fa;border-radius:10px}.qr-wrap canvas{width:min(100%,320px);height:auto;image-rendering:pixelated;background:#fff}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0;list-style:none}.codes li{padding:9px;background:#f1f5f7;font-family:ui-monospace,Consolas,monospace}.logs{margin-top:28px;border-top:2px solid var(--line)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#17222c;color:#d9f2ff;padding:12px;border-radius:8px;font:14px/1.55 ui-monospace,Consolas,monospace}@media(max-width:390px){.shell{padding:16px}.codes{grid-template-columns:1fr}body{font-size:17px}}
</style></head><body><main class="shell">
<header class="top"><span class="brand">🏦 Local Bank</span><button class="link hide" id="logout">Log out</button></header>
<nav class="progress" aria-label="Setup progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></nav>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-label="Activity logs"><h2>🔎 Activity logs</h2><p class="example">Demo delivery and verification messages appear here.</p><pre id="logs">Ready.</pre></section>
</main><script nonce="${nonce}">
(function(){"use strict";
var app=document.querySelector("#app"),logs=document.querySelector("#logs"),logout=document.querySelector("#logout"),csrf="",loginCsrf="",provision=null,recoveryCodes=[],notice="";
var routes=new Set(["#signin","#identity","#setup","#confirm","#recovery","#saved"]);
function esc(v){var e=document.createElement("span");e.textContent=String(v);return e.innerHTML}
function log(message){console.log(message);logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+message}
function go(route){location.hash=routes.has(route)?route:"#signin"}
function progress(step){for(var i=1;i<5;i++)document.querySelector("#p"+i).classList.toggle("on",i<=step)}
function help(){return '<p><button class="link" data-help>Need help?</button></p>'}
function attachHelp(){document.querySelectorAll("[data-help]").forEach(function(b){b.onclick=function(){alert("Take your time. You can retry safely. Use the example beside each box.")}})}
function error(message){var el=document.querySelector("#form-error");if(el){el.className="error";el.textContent=message;el.focus()}}
function takeNotice(){var value=notice;notice="";return value?'<div class="success">'+esc(value)+"</div>":""}
async function api(path,method,data){method=method||"GET";var o={method:method,headers:{Accept:"application/json"}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrf;o.body=JSON.stringify(data||{})}try{return await (await fetch(path,o)).json()}catch(e){return {ok:false,message:"We could not connect securely. Please try again."}}}
async function bootstrap(){var r=await api("/api/csrf-bootstrap");if(r.ok)loginCsrf=r.csrf;return r}
async function session(){var r=await api("/api/session");if(r.ok){csrf=r.csrf;logout.classList.remove("hide");return r}return null}

/* Task: standards-compliant QR encoder for the fixed Version 8, level-L
   provisioning URI. Every mask begins with a deep copy of immutable base.
   Format and version BCH values use generator-polynomial long division. */
function qr(uri,canvas){
  var version=8,size=49,DATA=194,ECC=24,rawBytes=new TextEncoder().encode(uri);
  if(rawBytes.length>192)throw new Error("Setup address is too long");
  var exp=Array(512).fill(0),log=Array(256).fill(0),v=1,i;
  for(i=0;i<255;i++){exp[i]=v;log[v]=i;v<<=1;if(v&256)v^=0x11d}
  for(i=255;i<512;i++)exp[i]=exp[i-255];
  function clone(a){return a.map(function(r){return r.slice()})}
  function polyRem(value,generator){
    var degree=0,t=generator;while(t>1){degree++;t>>>=1}
    while(value){
      var d=0,u=value;while(u>1){d++;u>>>=1}
      if(d<degree)break;
      value^=generator<<(d-degree);
    }
    return value;
  }
  function matrix(){return Array.from({length:size},function(){return Array(size)})}
  function set(m,x,y,value){if(x>=0&&y>=0&&x<size&&y<size)m[y][x]=value}
  function finder(m,x,y){for(var dy=-1;dy<=7;dy++)for(var dx=-1;dx<=7;dx++)set(m,x+dx,y+dy,dx>=0&&dx<=6&&dy>=0&&dy<=6&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4)))}
  function alignment(m,x,y){for(var dy=-2;dy<=2;dy++)for(var dx=-2;dx<=2;dx++)set(m,x+dx,y+dy,Math.abs(dx)===2||Math.abs(dy)===2||(dx===0&&dy===0))}
  function format(m,mask){
    var bits=((1<<3)|mask)<<10;
    bits=(bits|polyRem(bits,0x537))^0x5412;
    function bit(n){return ((bits>>>n)&1)!==0}
    for(var k=0;k<=5;k++)set(m,8,k,bit(k));
    set(m,8,7,bit(6));set(m,8,8,bit(7));set(m,7,8,bit(8));
    for(k=9;k<15;k++)set(m,14-k,8,bit(k));
    for(k=0;k<8;k++)set(m,size-1-k,8,bit(k));
    for(k=8;k<15;k++)set(m,8,size-15+k,bit(k));
  }
  function versionInfo(m){
    var bits=(version<<12)|polyRem(version<<12,0x1f25);
    for(var k=0;k<18;k++){
      var b=((bits>>>k)&1)!==0,x=size-11+(k%3),y=Math.floor(k/3);
      set(m,x,y,b);set(m,y,x,b);
    }
  }
  function masked(mask,row,col){
    if(mask===0)return (row+col)%2===0;
    if(mask===1)return row%2===0;
    if(mask===2)return col%3===0;
    if(mask===3)return (row+col)%3===0;
    if(mask===4)return (Math.floor(row/2)+Math.floor(col/3))%2===0;
    if(mask===5)return ((row*col)%2+(row*col)%3)===0;
    if(mask===6)return (((row*col)%2+(row*col)%3)%2)===0;
    return (((row+col)%2+(row*col)%3)%2)===0;
  }
  function rs(block){
    var gen=[1],a,b;
    for(a=0;a<ECC;a++){
      var next=Array(gen.length+1).fill(0);
      for(b=0;b<gen.length;b++){next[b]^=gen[b];next[b+1]^=exp[(log[gen[b]]+a)%255]}
      gen=next;
    }
    var rem=Array(ECC).fill(0);
    block.forEach(function(byte){
      var factor=byte^rem.shift();rem.push(0);
      if(factor)for(var j=0;j<ECC;j++)rem[j]^=exp[(log[gen[j+1]]+log[factor])%255];
    });
    return rem;
  }
  var base=matrix();
  finder(base,0,0);finder(base,size-7,0);finder(base,0,size-7);
  var centers=[6,24,42];
  centers.forEach(function(y){centers.forEach(function(x){if(base[y][x]===undefined)alignment(base,x,y)})});
  for(i=8;i<size-8;i++){if(base[i][6]===undefined)set(base,6,i,i%2===0);if(base[6][i]===undefined)set(base,i,6,i%2===0)}
  set(base,8,size-8,true);versionInfo(base);

  var bits=[0,1,0,0];
  for(i=7;i>=0;i--)bits.push((rawBytes.length>>>i)&1);
  rawBytes.forEach(function(byte){for(var j=7;j>=0;j--)bits.push((byte>>>j)&1)});
  for(i=0;i<4&&bits.length<DATA*8;i++)bits.push(0);
  while(bits.length%8)bits.push(0);
  var data=[];
  for(i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));
  for(i=0;data.length<DATA;i++)data.push(i%2?0x11:0xec);
  var blocks=[data.slice(0,97),data.slice(97,194)],ecc=[rs(data.slice(0,97)),rs(data.slice(97,194))],stream=[];
  for(i=0;i<97;i++)stream.push(blocks[0][i],blocks[1][i]);
  for(i=0;i<ECC;i++)stream.push(ecc[0][i],ecc[1][i]);
  var payload=[];stream.forEach(function(byte){for(var j=7;j>=0;j--)payload.push((byte>>>j)&1)});

  function penalty(m){
    var score=0,r,c;
    for(r=0;r<size;r++)for(c=0;c<size;c++){
      var run=1,colour=m[r][c];
      while(c+run<size&&m[r][c+run]===colour)run++;
      if(run>=5)score+=run-2;
      run=1;while(r+run<size&&m[r+run][c]===colour)run++;
      if(run>=5)score+=run-2;
    }
    for(r=0;r<size-1;r++)for(c=0;c<size-1;c++)if(m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c]&&m[r][c]===m[r+1][c+1])score+=3;
    var dark=0;for(r=0;r<size;r++)for(c=0;c<size;c++)if(m[r][c])dark++;
    score+=Math.floor(Math.abs(dark*20-size*size*10)/(size*size))*10;
    return score;
  }
  var best=null,bestScore=Infinity;
  for(var mask=0;mask<8;mask++){
    var current=clone(base); /* immutable base copy for every mask candidate */
    format(current,mask);
    var index=0,up=true;
    for(var x=size-1;x>0;x-=2){
      if(x===6)x--;
      for(var n=0;n<size;n++){
        var y=up?size-1-n:n;
        for(var dx=0;dx<2;dx++){
          var col=x-dx;
          if(current[y][col]===undefined){
            var value=payload[index++]===1;
            if(masked(mask,y,col))value=!value;
            current[y][col]=value;
          }
        }
      }
      up=!up;
    }
    var score=penalty(current);
    if(score<bestScore){bestScore=score;best=current}
  }
  var quiet=4,scale=6,total=(size+quiet*2)*scale;
  canvas.width=canvas.height=total;
  var ctx=canvas.getContext("2d");ctx.fillStyle="#fff";ctx.fillRect(0,0,total,total);ctx.fillStyle="#000";
  for(i=0;i<size;i++)for(var j=0;j<size;j++)if(best[i][j])ctx.fillRect((j+quiet)*scale,(i+quiet)*scale,scale,scale);
}
function signin(){
  progress(0);
  app.innerHTML='<h1>🔐 Sign in</h1><p class="lead">Start your security setup.</p><div class="hint">Demo email: <b>marcus@example.com</b><br>Demo password: <b>MarcusDemo!2025</b></div><form id="form"><div id="form-error" tabindex="-1"></div><label>Email address</label><input name="email" type="email" autocomplete="username" placeholder="name@example.com" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button class="primary">Sign in</button></form>'+help();
  document.querySelector("#form").onsubmit=async function(e){e.preventDefault();if(!loginCsrf){var b=await bootstrap();if(!b.ok){error(b.message);return}}var f=new FormData(e.target);try{var r=await (await fetch("/api/signin",{method:"POST",headers:{Accept:"application/json","Content-Type":"application/json","X-Login-CSRF":loginCsrf},body:JSON.stringify({email:f.get("email"),password:f.get("password")})})).json();if(!r.ok){error(r.message);return}log("Sign-in complete. Secure session created.");notice="Signed in successfully. Next: get your identity code.";go(r.next)}catch(x){error("We could not connect securely. Please try again.")}};
  attachHelp();
}
function identity(){
  progress(1);app.innerHTML='<h1>🪪 Check it is you</h1>'+takeNotice()+'<p class="lead">Get a six-digit identity code for this demo.</p><div class="hint">There is no reading timer. Take as long as you need.</div><div id="form-error" tabindex="-1"></div><button id="get" class="primary">Get identity code</button>'+help();
  var request=async function(){var r=await api("/api/identity/request","POST",{});if(!r.ok){error(r.message);return}log("Simulated identity code: "+r.simulatedCode);entry()};
  document.querySelector("#get").onclick=request;attachHelp();
  function entry(){app.innerHTML='<h1>🪪 Enter your identity code</h1><div class="success">Your identity code was requested. Next: enter the six digits.</div><form id="form"><div id="form-error" tabindex="-1"></div><label>Six-digit code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><button class="primary">Check code</button></form><button id="again" class="secondary">Re-request identity code</button>'+help();document.querySelector("#form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/identity/verify","POST",{code:new FormData(e.target).get("code")});if(!r.ok){error(r.message);return}notice="Identity check complete. Next: set up your authenticator.";go(r.next)};document.querySelector("#again").onclick=request;attachHelp()}
}
async function createProvision(){var r=await api("/api/authenticator/provision","POST",{});if(!r.ok){error(r.message);return}provision=r;log("Simulated authenticator verification OTP: "+r.simulatedOtp);showProvision()}
function setup(){progress(2);app.innerHTML='<h1>📱 Set up your authenticator</h1>'+takeNotice()+'<p class="lead">Use a QR code or copy a setup key. You do not need to write anything down.</p><div class="hint">Your authenticator app will give you a six-digit code.</div><div id="form-error" tabindex="-1"></div><button id="show" class="primary">Show setup options</button>'+help();document.querySelector("#show").onclick=createProvision;attachHelp()}
function showProvision(){
  progress(2);app.innerHTML='<h1>📱 Add this to your app</h1><div class="success">Setup created. Choose one simple way to add it.</div><p class="lead"><b>Option 1:</b> Scan this QR code with your authenticator app.</p><div class="qr-wrap"><canvas id="qr" aria-label="QR code for Local Bank authenticator setup"></canvas></div><p class="lead"><b>Option 2:</b> Copy the setup key and paste it into your app.</p><div id="private"></div><button id="toggle" class="secondary">Hide setup key</button><button id="copy" class="secondary">Copy setup key</button><button id="next" class="primary">I added it — continue</button><button id="new" class="link">Show a new setup key</button>'+help();
  qr(provision.provisioningUri,document.querySelector("#qr"));
  var shown=true,box=document.querySelector("#private");
  function draw(){box.innerHTML=shown?'<div class="secret code"></div>':'<div class="hint">Setup key is hidden. Select reveal when you are ready.</div>';if(shown)box.firstChild.textContent=provision.secret;document.querySelector("#toggle").textContent=shown?"Hide setup key":"Reveal setup key"}
  draw();document.querySelector("#toggle").onclick=function(){shown=!shown;draw()};document.querySelector("#copy").onclick=function(){navigator.clipboard.writeText(provision.secret).then(function(){alert("Setup key copied.")}).catch(function(){alert("Select the setup key and copy it.")})};document.querySelector("#next").onclick=function(){go("#confirm")};document.querySelector("#new").onclick=createProvision;attachHelp();
}
function confirm(){
  progress(3);app.innerHTML='<h1>✅ Check your authenticator</h1><p class="lead">Enter the six digits from your app.</p><div class="hint">Take your time. If needed, show a new setup option and try again.</div><form id="form"><div id="form-error" tabindex="-1"></div><label>Authenticator code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><button class="primary">Confirm authenticator</button></form><button id="retry" class="secondary">Show setup options again</button>'+help();
  document.querySelector("#form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/authenticator/confirm","POST",{code:new FormData(e.target).get("code")});if(!r.ok){error(r.message);return}log("Authenticator confirmed.");notice="Authenticator confirmed. Next: create your recovery codes.";go(r.next)};
  document.querySelector("#retry").onclick=function(){provision?showProvision():go("#setup")};attachHelp();
}
function recovery(){
  progress(4);app.innerHTML='<h1>🧾 Save recovery codes</h1>'+takeNotice()+'<p class="lead">These help if you cannot use your authenticator.</p><div class="hint">Save them somewhere private. Each code works once.</div><div id="form-error" tabindex="-1"></div><button id="create" class="primary">Create recovery codes</button>'+help();
  document.querySelector("#create").onclick=async function(){var r=await api("/api/recovery/generate","POST",{});if(!r.ok){error(r.message);return}recoveryCodes=r.codes;log("Simulated recovery-code set: "+recoveryCodes.join(", "));showCodes()};attachHelp();
}
function showCodes(){
  app.innerHTML='<h1>🧾 Your recovery codes</h1><div class="success">Recovery codes created. Next: copy or save them privately.</div><div id="private"></div><button id="toggle" class="secondary">Hide recovery codes</button><button id="copy" class="secondary">Copy all codes</button><button id="done" class="primary">I saved my codes</button>'+help();
  var shown=true,box=document.querySelector("#private");
  function draw(){box.innerHTML=shown?'<ul class="codes"></ul>':'<div class="hint">Recovery codes are hidden. Select reveal when you are ready.</div>';if(shown)recoveryCodes.forEach(function(code){var li=document.createElement("li");li.textContent=code;box.firstChild.appendChild(li)});document.querySelector("#toggle").textContent=shown?"Hide recovery codes":"Reveal recovery codes"}
  draw();document.querySelector("#toggle").onclick=function(){shown=!shown;draw()};document.querySelector("#copy").onclick=function(){navigator.clipboard.writeText(recoveryCodes.join("\\n")).then(function(){alert("Recovery codes copied.")}).catch(function(){alert("Select the codes and copy them.")})};document.querySelector("#done").onclick=function(){go("#saved")};attachHelp();
}
function saved(){progress(4);app.innerHTML='<h1>🎉 Security setup complete</h1><div class="success">Your authenticator is connected and your recovery codes are saved.</div><button id="start" class="primary">Finish</button>'+help();document.querySelector("#start").onclick=function(){alert("Security setup is complete.")};attachHelp()}
async function render(){
  var route=routes.has(location.hash)?location.hash:"#signin";
  if(route==="#signin"){await bootstrap();signin();return}
  var state=await session();if(!state){go("#signin");return}
  if(!state.identityVerified&&route!=="#identity"){go("#identity");return}
  if(!state.mfa&&["#recovery","#saved"].includes(route)){go(state.provisioned?"#confirm":"#setup");return}
  if(state.mfa&&state.recoveryCount===0&&route==="#saved"){go("#recovery");return}
  ({"#identity":identity,"#setup":setup,"#confirm":confirm,"#recovery":recovery,"#saved":saved})[route]();
}
logout.onclick=async function(){var r=await api("/api/logout","POST",{});if(r.ok){csrf="";provision=null;recoveryCodes=[];log("Secure session ended.");go("#signin")}};
addEventListener("hashchange",render);render();
})();</script></body></html>`;
}

const certificate = readFileSync("certs/cert.pem");
const privateKey = readFileSync("certs/key.pem");

/* Requirement 3: TLS-only Bun server using supplied localhost certificates. */
Bun.serve({
  port: 3000,
  tls: { cert: certificate, key: privateKey },
  fetch: async (request) => {
    const nonce = random(18);
    try {
      const url = new URL(request.url);
      const origin = request.headers.get("origin");
      if (request.headers.get("x-forwarded-proto") === "http")
        return new Response("Secure connection required.", { status: 426, headers: headers(nonce) });
      if (origin && !ORIGINS.has(origin))
        return new Response("Not allowed.", { status: 403, headers: headers(nonce) });
      const cors = origin ? { "Access-Control-Allow-Origin": origin } : {};
      if (request.method === "OPTIONS")
        return new Response(null, {
          status: 204,
          headers: {
            ...headers(nonce),
            ...cors,
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token, X-Login-CSRF",
          },
        });
      if (url.pathname.startsWith("/api/")) {
        const out = await api(request, url.pathname, nonce);
        for (const [key, value] of Object.entries(cors)) out.headers.set(key, value);
        return out;
      }
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html"))
        return new Response(page(nonce), {
          headers: { ...headers(nonce), ...cors, "Content-Type": "text/html; charset=utf-8" },
        });
      return new Response("Page not found.", { status: 404, headers: headers(nonce) });
    } catch {
      return new Response("We could not complete that request. Please try again.", {
        status: 500,
        headers: headers(nonce),
      });
    }
  },
});
