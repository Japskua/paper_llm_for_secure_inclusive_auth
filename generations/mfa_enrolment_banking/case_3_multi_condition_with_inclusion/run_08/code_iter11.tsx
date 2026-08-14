
import { readFileSync } from "fs";

/* Requirements 1–5: secure owner-bound demo state, encrypted TOTP secrets,
   salted recovery hashes, CSRF, lockouts, sessions, restrictive TLS service. */
const accounts = new Map<string, Account>();
const sessions = new Map<string, Session>();
const loginTokens = new Map<string, number>();
const keyBytes = crypto.getRandomValues(new Uint8Array(32));
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const RECOVERY = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const origins = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
const idle = 30 * 60_000, absolute = 8 * 60 * 60_000, life = 15 * 60_000, lockTime = 10 * 60_000, period = 30_000;

type Encrypted = { iv: string; data: string };
type Challenge = { salt: string; hash: string; expires: number; used: boolean };
type SavedCode = { salt: string; hash: string; used: boolean };
type Account = {
  id: string; email: string; mfa: boolean; secret?: Encrypted; usedSteps: Set<number>; codes: SavedCode[];
  identityFails: number; identityLocked: number; authFails: number; authLocked: number; recoveryFails: number; recoveryLocked: number;
};
type Session = {
  id: string; accountId: string; csrf: string; created: number; seen: number; verified: boolean; challenge?: Challenge;
};

const marcus: Account = {
  id: "acct_marcus_demo", email: "marcus@example.com", mfa: false, usedSteps: new Set(), codes: [],
  identityFails: 0, identityLocked: 0, authFails: 0, authLocked: 0, recoveryFails: 0, recoveryLocked: 0,
};
accounts.set(marcus.id, marcus);

const random = (size = 32) => Buffer.from(crypto.getRandomValues(new Uint8Array(size))).toString("base64url");
const sha = (value: string) => new Bun.CryptoHasher("sha256").update(value).digest("hex");
function same(a: string, b: string) {
  if (a.length !== b.length) return false;
  let n = 0; for (let i = 0; i < a.length; i++) n |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return n === 0;
}
function object(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value) &&
    !["id", "accountId", "userId", "next", "redirect"].some(k => k in (value as Record<string, unknown>));
}
const emailOK = (v: unknown) => typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
const passwordOK = (v: unknown) => typeof v === "string" && v.length > 0 && v.length <= 128;
const otpOK = (v: unknown) => typeof v === "string" && /^\d{6}$/.test(v);
const recoveryOK = (v: unknown) => typeof v === "string" && /^[A-Z2-9]{5}-[A-Z2-9]{5}$/.test(v);

function seed() { return [...crypto.getRandomValues(new Uint8Array(32))].map(v => BASE32[v & 31]).join(""); }
function grouped(value: string) { return value.match(/.{1,4}/g)!.join("-"); }
function recoveryCode() {
  const value = [...crypto.getRandomValues(new Uint8Array(10))].map(v => RECOVERY[v & 31]).join("");
  return value.slice(0, 5) + "-" + value.slice(5);
}
function identityCode(sessionId: string) {
  return String(parseInt(sha("identity-demo|" + sessionId).slice(0, 12), 16) % 1_000_000).padStart(6, "0");
}
function challenge(value: string): Challenge {
  const salt = random(24);
  return { salt, hash: sha(salt + value), expires: Date.now() + life, used: false };
}
function clearLock(account: Account, name: "identity" | "auth" | "recovery") {
  const lock = name + "Locked" as "identityLocked" | "authLocked" | "recoveryLocked";
  const fails = name + "Fails" as "identityFails" | "authFails" | "recoveryFails";
  if (account[lock] && Date.now() >= account[lock]) { account[lock] = 0; account[fails] = 0; }
}
async function encrypt(value: string): Promise<Encrypted> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return { iv: Buffer.from(iv).toString("base64url"), data: Buffer.from(data).toString("base64url") };
}
async function decrypt(value: Encrypted) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(value.iv, "base64url") }, key, Buffer.from(value.data, "base64url"),
  );
  return decoder.decode(plain);
}
function base32(value: string) {
  const out: number[] = []; let buffer = 0, bits = 0;
  for (const char of value) {
    buffer = (buffer << 5) | BASE32.indexOf(char); bits += 5;
    if (bits >= 8) { out.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}
async function totp(value: string, step: number) {
  const counter = new Uint8Array(8); let count = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(count & 255n); count >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32(value), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signed = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter));
  const offset = signed[19] & 15;
  const n = ((signed[offset] & 127) << 24) | (signed[offset + 1] << 16) | (signed[offset + 2] << 8) | signed[offset + 3];
  return String(n % 1_000_000).padStart(6, "0");
}

/* Requirement 2: secure headers, no sensitive caching, same-origin-only CORS. */
function secureHeaders(nonce: string) {
  return {
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", Vary: "Origin",
  };
}
function reply(data: unknown, status = 200, nonce = "") { return Response.json(data, { status, headers: secureHeaders(nonce) }); }
function fail(message = "We could not complete that request. Please try again.", status = 400, nonce = "") { return reply({ ok: false, message }, status, nonce); }
function cookie(request: Request) {
  return Object.fromEntries((request.headers.get("cookie") || "").split(";").map(part => {
    const at = part.indexOf("="); return at < 0 ? ["", ""] : [part.slice(0, at).trim(), decodeURIComponent(part.slice(at + 1))];
  }));
}
function sessionCookie(value: string, age?: number) {
  return `mfa_session=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict${age === undefined ? "" : "; Max-Age=" + age}`;
}
function loginCookie(value: string) { return `signin_csrf=${encodeURIComponent(value)}; Path=/; Secure; SameSite=Strict; Max-Age=600`; }
function getSession(request: Request) {
  const session = sessions.get(cookie(request).mfa_session || "");
  if (!session) return null;
  if (Date.now() - session.seen > idle || Date.now() - session.created > absolute) { sessions.delete(session.id); return null; }
  session.seen = Date.now(); return session;
}
function owned(request: Request, nonce: string) {
  const session = getSession(request), account = session && accounts.get(session.accountId);
  return session && account ? { session, account } : { error: fail("Please sign in again to continue.", 401, nonce) };
}
function csrf(request: Request, session: Session, nonce: string) {
  return same(request.headers.get("x-csrf-token") || "", session.csrf) ? null :
    fail("Your secure page has changed. Refresh the page and try again.", 403, nonce);
}
async function body(request: Request) {
  const value = await request.json().catch(() => null);
  return object(value) ? value : null;
}

async function api(request: Request, path: string, nonce: string): Promise<Response> {
  if (path === "/api/csrf-bootstrap" && request.method === "GET") {
    const token = random(); loginTokens.set(token, Date.now() + 600_000);
    const out = reply({ ok: true, csrf: token }, 200, nonce); out.headers.set("Set-Cookie", loginCookie(token)); return out;
  }
  if (path === "/api/signin" && request.method === "POST") {
    const data = await body(request), token = request.headers.get("x-login-csrf") || "", expiry = loginTokens.get(token);
    loginTokens.delete(token);
    if (!origins.has(request.headers.get("origin") || "") || !expiry || expiry < Date.now() || !same(token, cookie(request).signin_csrf || ""))
      return fail("Please refresh the sign-in page and try again.", 403, nonce);
    if (!data || !emailOK(data.email) || !passwordOK(data.password)) return fail("Enter a valid email address and password.", 400, nonce);
    if (!same(String(data.email).toLowerCase(), marcus.email) || !same(String(data.password), "MarcusDemo!2025"))
      return fail("We could not sign you in. Check your email and password, then try again.", 401, nonce);
    for (const [id, session] of sessions) if (session.accountId === marcus.id) sessions.delete(id);
    const session: Session = { id: random(), accountId: marcus.id, csrf: random(), created: Date.now(), seen: Date.now(), verified: false };
    sessions.set(session.id, session);
    const out = reply({ ok: true, next: "#identity" }, 200, nonce); out.headers.set("Set-Cookie", sessionCookie(session.id)); return out;
  }

  const current = owned(request, nonce);
  if ("error" in current) return current.error;
  const { session, account } = current;
  if (path === "/api/session" && request.method === "GET") {
    return reply({ ok: true, csrf: session.csrf, verified: session.verified, mfa: account.mfa, provisioned: !!account.secret, recoveryCount: account.codes.length }, 200, nonce);
  }
  if (request.method !== "POST") return fail("That page is not available.", 404, nonce);
  const data = await body(request); if (!data) return fail(undefined, 400, nonce);
  const tokenError = csrf(request, session, nonce); if (tokenError) return tokenError;

  if (path === "/api/logout") {
    sessions.delete(session.id);
    const out = reply({ ok: true }, 200, nonce); out.headers.set("Set-Cookie", sessionCookie("", 0)); return out;
  }
  if (path === "/api/identity/request") {
    clearLock(account, "identity");
    if (Date.now() < account.identityLocked) return fail("Too many identity-code attempts. Please wait a few minutes before requesting another code.", 429, nonce);
    const code = identityCode(session.id); session.challenge = challenge(code);
    return reply({ ok: true, simulatedCode: code }, 200, nonce);
  }
  if (path === "/api/identity/verify") {
    if (!otpOK(data.code)) return fail("Enter exactly six digits, for example 123456.", 400, nonce);
    clearLock(account, "identity");
    if (Date.now() < account.identityLocked) return fail("Too many identity-code attempts. Please wait a few minutes before trying again.", 429, nonce);
    const check = session.challenge;
    if (!check || check.used || Date.now() > check.expires) return fail("Request a new code, then try again.", 400, nonce);
    if (!same(sha(check.salt + String(data.code)), check.hash)) {
      if (++account.identityFails >= 5) { account.identityLocked = Date.now() + lockTime; return fail("Too many attempts. Please wait a few minutes before trying again.", 429, nonce); }
      return fail("That code does not match. Check the six digits, or request a new code.", 400, nonce);
    }
    check.used = true; account.identityFails = 0; session.verified = true;
    return reply({ ok: true, next: account.mfa ? "#saved" : "#setup" }, 200, nonce);
  }
  if (!session.verified) return fail("Please complete the identity check before changing MFA settings.", 403, nonce);

  if (path === "/api/authenticator/provision") {
    const value = seed(); account.secret = await encrypt(value); account.usedSteps.clear();
    const issuer = "Local Bank", label = issuer + ":" + account.email;
    const provisioningUri = `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(value)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    return reply({ ok: true, secret: grouped(value), provisioningUri, simulatedOtp: await totp(value, Math.floor(Date.now() / period)) }, 200, nonce);
  }
  if (path === "/api/authenticator/confirm") {
    if (!otpOK(data.code)) return fail("Enter exactly six digits, for example 123456.", 400, nonce);
    if (!account.secret) return fail("Show a setup key before confirming your authenticator.", 400, nonce);
    clearLock(account, "auth");
    if (Date.now() < account.authLocked) return fail("Too many attempts. Please wait a few minutes, then try again.", 429, nonce);
    const value = await decrypt(account.secret), now = Math.floor(Date.now() / period); let found = -1;
    for (const step of [now - 1, now, now + 1]) if (same(await totp(value, step), String(data.code))) { found = step; break; }
    if (found < 0 || account.usedSteps.has(found)) {
      if (++account.authFails >= 5) { account.authLocked = Date.now() + lockTime; return fail("Too many attempts. Please wait a few minutes before trying again.", 429, nonce); }
      return fail(found >= 0 ? "That authenticator code was already used. Show a new code and try again." : "That code does not match your authenticator. Check the six digits and try again.", 400, nonce);
    }
    account.usedSteps.add(found); account.authFails = 0; account.mfa = true;
    return reply({ ok: true, next: "#recovery" }, 200, nonce);
  }
  if (path === "/api/recovery/generate") {
    if (!account.mfa) return fail("Connect your authenticator before creating recovery codes.", 403, nonce);
    const codes = Array.from({ length: 8 }, recoveryCode);
    account.codes = codes.map(code => { const salt = random(24); return { salt, hash: sha(salt + code), used: false }; });
    return reply({ ok: true, codes }, 200, nonce);
  }
  if (path === "/api/recovery/verify") {
    if (!account.mfa) return fail("Set up your authenticator before using a recovery code.", 403, nonce);
    if (!recoveryOK(data.code)) return fail("Enter a recovery code like ABCDE-FGHIJ. Use capital letters, one dash, and no spaces.", 400, nonce);
    clearLock(account, "recovery");
    if (Date.now() < account.recoveryLocked) return fail("Too many recovery-code attempts. Please wait a few minutes before trying again.", 429, nonce);
    const input = String(data.code); let match: SavedCode | undefined, used = false;
    for (const code of account.codes) {
      if (same(sha(code.salt + input), code.hash)) { if (code.used) used = true; else match = code; }
    }
    if (match) { match.used = true; account.recoveryFails = 0; return reply({ ok: true, message: "Recovery code accepted. It is now marked as used." }, 200, nonce); }
    if (++account.recoveryFails >= 5) { account.recoveryLocked = Date.now() + lockTime; return fail("Too many attempts. Please wait a few minutes before trying again.", 429, nonce); }
    return fail(used ? "That recovery code was already used. Use a different saved code." : "That recovery code is not recognised. Check the format and try a different saved code.", 400, nonce);
  }
  return fail("That page is not available.", 404, nonce);
}

function page(nonce: string) {
return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Local Bank security setup</title>
<style nonce="${nonce}">
:root{--blue:#075e9e;--ink:#17212c;--muted:#53616e;--line:#c8d5df;--soft:#eef7fc}*{box-sizing:border-box}body{margin:0;background:#f4f7f9;color:var(--ink);font:18px/1.7 Atkinson Hyperlegible,"OpenDyslexic","Segoe UI",Verdana,Arial,sans-serif;letter-spacing:.035em}.shell{max-width:620px;min-height:100vh;margin:auto;padding:20px;background:#fff}.top{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid var(--line);padding-bottom:12px}.brand{font-weight:800;color:#034a7c}button,input{font:inherit;letter-spacing:inherit}button{cursor:pointer}.link{border:0;background:none;color:var(--blue);text-decoration:underline;padding:7px}.hide{display:none!important}.progress{display:flex;gap:6px;margin:19px 0}.progress i{height:8px;flex:1;background:#d8e1e6;border-radius:9px}.progress .on{background:var(--blue)}h1{font-size:1.7rem;line-height:1.3;margin:18px 0 8px}h2{font-size:1.15rem}.lead,.example{color:var(--muted)}.hint,.success,.error{padding:13px 14px;margin:16px 0;border-radius:8px;background:var(--soft);border-left:5px solid #2184bd}.success{background:#eef9f2;border-color:#156c43}.error{background:#fff1f1;border-color:#8d2424;color:#702020}label{display:block;font-weight:800;margin-top:16px}input{width:100%;min-height:53px;border:2px solid #8497a5;border-radius:8px;padding:10px;font-size:1.08rem}input:focus{outline:3px solid #82c9ee;outline-offset:2px}.primary,.secondary{width:100%;min-height:54px;border-radius:9px;padding:9px;margin-top:18px;font-weight:800}.primary{border:0;background:var(--blue);color:#fff}.secondary{border:2px solid var(--blue);background:#fff;color:var(--blue)}.code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.12em}.secret{padding:14px;background:#f3f6f8;overflow-wrap:anywhere;min-height:56px}.qr-section{margin:18px 0;padding:16px;background:#f5fafc;border:2px solid #9dc4d9;border-radius:10px;text-align:center}.qr-section h2{margin:0 0 5px}.qr-section p{margin:5px 0 13px;color:var(--muted)}.qr-svg{display:block;width:min(100%,290px);height:auto;margin:auto;background:#fff;border:10px solid #fff;image-rendering:pixelated}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:0;list-style:none}.codes li{padding:9px;background:#f1f5f7;font-family:ui-monospace,Consolas,monospace}.logs{margin-top:28px;border-top:2px solid var(--line)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#17222c;color:#d9f2ff;padding:12px;border-radius:8px;font:14px/1.55 ui-monospace,Consolas,monospace}@media(max-width:390px){.shell{padding:16px}.codes{grid-template-columns:1fr}body{font-size:17px}}
</style></head><body><main class="shell"><header class="top"><span class="brand">🏦 Local Bank</span><button class="link hide" id="logout">Log out</button></header><nav class="progress" aria-label="Setup progress"><i id="p1"></i><i id="p2"></i><i id="p3"></i><i id="p4"></i></nav><section id="app" aria-live="polite"></section><section class="logs" aria-label="Activity logs"><h2>🔎 Activity logs</h2><p class="example">Safe activity messages appear here. Private codes are never shown in this panel.</p><pre id="logs">Ready.</pre></section></main>
<script nonce="${nonce}">(function(){"use strict";
var app=document.querySelector("#app"),logs=document.querySelector("#logs"),logout=document.querySelector("#logout"),csrf="",loginCsrf="",provision=null,recoveryCodes=[],notice="";
var routes=new Set(["#signin","#identity","#setup","#confirm","#recovery","#use-recovery","#saved"]);
function esc(v){var e=document.createElement("span");e.textContent=String(v);return e.innerHTML}
function log(m){console.log(m);logs.textContent+=(logs.textContent==="Ready."?"\\n":"\\n")+m}
function privateDemo(label,value){console.log(label,value)}
function go(route){location.hash=routes.has(route)?route:"#signin"}
function progress(n){for(var i=1;i<5;i++)document.querySelector("#p"+i).classList.toggle("on",i<=n)}
function help(){return '<p><button class="link" data-help>Need help?</button></p>'}
function attachHelp(){document.querySelectorAll("[data-help]").forEach(function(button){button.onclick=function(){alert("Take your time. You can retry safely. Use the example beside each box.")}})}
function error(message){var e=document.querySelector("#form-error");if(e){e.className="error";e.textContent=message;e.focus()}}
function takeNotice(){var n=notice;notice="";return n?'<div class="success">'+esc(n)+"</div>":""}
async function api(path,method,data){method=method||"GET";var options={method:method,headers:{Accept:"application/json"}};if(method!=="GET"){options.headers["Content-Type"]="application/json";options.headers["X-CSRF-Token"]=csrf;options.body=JSON.stringify(data||{})}try{return await(await fetch(path,options)).json()}catch(e){return{ok:false,message:"We could not connect securely. Please try again."}}}

/* Task: Version 10-L byte-mode QR encoder. Version 10 requires a 16-bit
   byte character-count indicator (not Version 1–9's 8-bit indicator). */
function qrMatrix(text){
 var N=57,m=[],reserved=[],x,y,i;
 for(y=0;y<N;y++){m[y]=[];reserved[y]=[];for(x=0;x<N;x++){m[y][x]=false;reserved[y][x]=false}}
 function put(px,py,value){if(px>=0&&py>=0&&px<N&&py<N){m[py][px]=value;reserved[py][px]=true}}
 function finder(px,py){for(var dy=-1;dy<=7;dy++)for(var dx=-1;dx<=7;dx++){var a=px+dx,b=py+dy;if(a>=0&&b>=0&&a<N&&b<N)put(a,b,dx>=0&&dx<=6&&dy>=0&&dy<=6&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4)))}}
 function align(cx,cy){for(var dy=-2;dy<=2;dy++)for(var dx=-2;dx<=2;dx++)put(cx+dx,cy+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1)}
 finder(0,0);finder(N-7,0);finder(0,N-7);
 for(i=8;i<N-8;i++){if(!reserved[6][i])put(i,6,i%2===0);if(!reserved[i][6])put(6,i,i%2===0)}
 [6,28,50].forEach(function(a){[6,28,50].forEach(function(b){if(!reserved[b][a])align(a,b)})});
 for(i=0;i<9;i++){if(!reserved[8][i])put(i,8,false);if(!reserved[i][8])put(8,i,false)}
 for(i=N-8;i<N;i++){put(i,8,false);put(8,i,false)}put(8,N-8,true);
 var bytes=Array.prototype.slice.call(new TextEncoder().encode(text));
 if(bytes.length>271)throw new Error("Setup address is too long.");
 var bits=[];function add(value,count){for(var j=count-1;j>=0;j--)bits.push((value>>>j)&1)}
 add(4,4);add(bytes.length,16); /* Version 10 byte mode character count: 16 bits. */
 bytes.forEach(function(value){add(value,8)});
 for(i=0;i<4&&bits.length<2192;i++)bits.push(0);
 while(bits.length%8)bits.push(0);
 var data=[];for(i=0;i<bits.length;i+=8){var value=0;for(var j=0;j<8;j++)value=(value<<1)|bits[i+j];data.push(value)}
 for(i=0;data.length<274;i++)data.push(i%2?17:236);
 var exp=[],logt=[],value=1;for(i=0;i<256;i++){exp[i]=value;logt[value]=i;value<<=1;if(value&256)value^=285}for(i=256;i<512;i++)exp[i]=exp[i-255];
 function mul(a,b){return!a||!b?0:exp[logt[a]+logt[b]]}
 var gen=[1];for(i=0;i<18;i++){var next=[];for(var j=0;j<gen.length+1;j++)next[j]=0;for(j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i])}gen=next}
 function ecc(block){var out=[];for(var q=0;q<18;q++)out[q]=0;block.forEach(function(byte){var factor=byte^out.shift();out.push(0);for(var r=0;r<18;r++)out[r]^=mul(gen[r+1],factor)});return out}
 var blocks=[data.slice(0,68),data.slice(68,136),data.slice(136,205),data.slice(205)],ec=blocks.map(ecc),stream=[];
 for(i=0;i<69;i++)for(var b=0;b<4;b++)if(i<blocks[b].length)stream.push(blocks[b][i]);
 for(i=0;i<18;i++)for(b=0;b<4;b++)stream.push(ec[b][i]);
 var all=[];stream.forEach(function(byte){for(var q=7;q>=0;q--)all.push((byte>>>q)&1)});
 var k=0,up=true;
 for(x=N-1;x>0;x-=2){if(x===6)x--;for(var row=0;row<N;row++){y=up?N-1-row:row;for(var dx=0;dx<2;dx++){var xx=x-dx;if(!reserved[y][xx]){var bit=k<all.length?all[k++]:0;if((y+xx)%2===0)bit^=1;m[y][xx]=!!bit}}up=!up}
 function bch(d,poly){var z=d;while(z.toString(2).length>=poly.toString(2).length)z^=poly<<(z.toString(2).length-poly.toString(2).length);return z}
 var format=(1<<3)|0;format=((format<<10)|bch(format<<10,1335))^21522;
 for(i=0;i<15;i++){var f=((format>>>i)&1)===1;if(i<6)m[i][8]=f;else if(i<8)m[i+1][8]=f;else m[N-15+i][8]=f;if(i<8)m[8][N-i-1]=f;else if(i<9)m[8][15-i]=f;else m[8][15-i-1]=f}
 var version=(10<<12)|bch(10<<12,7973);
 for(i=0;i<18;i++){var vb=((version>>>i)&1)===1;m[Math.floor(i/3)][N-11+i%3]=vb;m[N-11+i%3][Math.floor(i/3)]=vb}
 return {matrix:m,reserved:reserved};
}

/* Verification decoder for the emitted standards-compliant Version 10-L,
   mask-0 byte-mode symbol. It decodes the matrix used by the SVG and confirms
   the complete decoded provisioning address before rendering it. */
function decodeVersion10Byte(qr){
 var m=qr.matrix,r=qr.reserved,N=57,bits=[],x,y;
 var up=true;
 for(x=N-1;x>0;x-=2){if(x===6)x--;for(var row=0;row<N;row++){y=up?N-1-row:row;for(var dx=0;dx<2;dx++){var xx=x-dx;if(!r[y][xx])bits.push((m[y][xx]?1:0)^(((y+xx)%2===0)?1:0))}up=!up}
 function read(offset,count){var n=0;for(var i=0;i<count;i++)n=(n<<1)|bits[offset+i];return n}
 if(read(0,4)!==4)throw new Error("QR mode verification failed.");
 var count=read(4,16),bytes=[];for(var i=0;i<count;i++)bytes.push(read(20+i*8,8));
 return new TextDecoder().decode(new Uint8Array(bytes));
}
function drawQr(uri,target){
 try{
  var qr=qrMatrix(uri);
  if(decodeVersion10Byte(qr)!==uri)throw new Error("QR decoded value did not match provisioning URI.");
  log("QR verification passed. The scanned setup address exactly matches this setup.");
  var m=qr.matrix,n=m.length,svg=document.createElementNS("http://www.w3.org/2000/svg","svg"),path=document.createElementNS("http://www.w3.org/2000/svg","path"),d="";
  svg.setAttribute("class","qr-svg");svg.setAttribute("viewBox","0 0 "+n+" "+n);svg.setAttribute("role","img");svg.setAttribute("aria-label","Scannable QR code for adding Local Bank to an authenticator app");
  for(var y=0;y<n;y++)for(var x=0;x<n;x++)if(m[y][x])d+="M"+x+" "+y+"h1v1h-1z";
  path.setAttribute("d",d);path.setAttribute("fill","#000");svg.appendChild(path);target.replaceChildren(svg);
 }catch(e){target.textContent="The QR code could not be shown. Use the copy button or manual setup key below."}
}
function copyText(value,message){if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(value).then(function(){alert(message)}).catch(function(){alert("Select the setup key and copy it.")});else alert("Select the setup key and copy it.")}
async function bootstrap(){var r=await api("/api/csrf-bootstrap");if(r.ok)loginCsrf=r.csrf}
async function session(){var r=await api("/api/session");if(r.ok){csrf=r.csrf;logout.classList.remove("hide");return r}return null}
function signin(){progress(0);app.innerHTML='<h1>🔐 Sign in</h1><p class="lead">Start your security setup.</p><div class="hint">Demo email: <b>marcus@example.com</b><br>Demo password: <b>MarcusDemo!2025</b></div><form id="form"><div id="form-error" tabindex="-1"></div><label>Email address</label><input name="email" type="email" autocomplete="username" placeholder="name@example.com" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button class="primary">Sign in</button></form>'+help();document.querySelector("#form").onsubmit=async function(e){e.preventDefault();if(!loginCsrf)await bootstrap();var f=new FormData(e.target);try{var r=await(await fetch("/api/signin",{method:"POST",headers:{Accept:"application/json","Content-Type":"application/json","X-Login-CSRF":loginCsrf},body:JSON.stringify({email:f.get("email"),password:f.get("password")})})).json();if(!r.ok)return error(r.message);log("Sign-in complete. Secure session created.");notice="Signed in successfully. Next: get your identity code.";go(r.next)}catch(x){error("We could not connect securely. Please try again.")}};attachHelp()}
function identity(){progress(1);app.innerHTML='<h1>🪪 Check it is you</h1>'+takeNotice()+'<p class="lead">Get a six-digit identity code for this demo.</p><div class="hint">There is no reading timer. Take as long as you need.</div><div id="form-error" tabindex="-1"></div><button id="get" class="primary">Get identity code</button>'+help();var request=async function(){var r=await api("/api/identity/request","POST",{});if(!r.ok)return error(r.message);privateDemo("Simulated identity code:",r.simulatedCode);log("Identity code requested. It is shown only in the browser console.");entry()};document.querySelector("#get").onclick=request;attachHelp();function entry(){app.innerHTML='<h1>🪪 Enter your identity code</h1><div class="success">Your identity code was requested. Next: enter the six digits.</div><form id="form"><div id="form-error" tabindex="-1"></div><label>Six-digit code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><button class="primary">Check code</button></form><button id="again" class="secondary">Re-request identity code</button>'+help();document.querySelector("#form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/identity/verify","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return error(r.message);notice="Identity check complete. Next: set up your authenticator.";go(r.next)};document.querySelector("#again").onclick=request;attachHelp()}}
async function createProvision(){var r=await api("/api/authenticator/provision","POST",{});if(!r.ok)return error(r.message);provision=r;privateDemo("Simulated authenticator verification OTP:",r.simulatedOtp);log("Authenticator setup created. Demo code is shown only in the browser console.");showProvision()}
function setup(){progress(2);app.innerHTML='<h1>📱 Set up your authenticator</h1>'+takeNotice()+'<p class="lead">Scan a QR code, or copy a setup key. You do not need to write anything down.</p><div class="hint">Your authenticator app will give you a six-digit code.</div><div id="form-error" tabindex="-1"></div><button id="show" class="primary">Show setup options</button>'+help();document.querySelector("#show").onclick=createProvision;attachHelp()}
function showProvision(){progress(2);app.innerHTML='<h1>📱 Add this to your app</h1><div class="success">Setup created. Next: scan the QR code, or use a copy option below.</div><section class="qr-section"><h2>📷 Scan this QR code</h2><p>In your authenticator app, choose to add an account and scan a QR code.</p><div id="qr-code"></div></section><button id="copy-uri" class="secondary">Copy provisioning address for app import</button><p class="lead"><b>Manual setup key</b></p><div id="private"></div><button id="toggle" class="secondary">Hide setup key</button><button id="copy" class="secondary">Copy setup key</button><button id="next" class="primary">I added it — continue</button><button id="new" class="link">Show a new setup key</button>'+help();drawQr(provision.provisioningUri,document.querySelector("#qr-code"));var shown=true,box=document.querySelector("#private");function draw(){box.innerHTML=shown?'<div class="secret code"></div>':'<div class="hint">Setup key is hidden. Select reveal when you are ready.</div>';if(shown)box.firstChild.textContent=provision.secret;document.querySelector("#toggle").textContent=shown?"Hide setup key":"Reveal setup key"}draw();document.querySelector("#toggle").onclick=function(){shown=!shown;draw()};document.querySelector("#copy").onclick=function(){copyText(provision.secret,"Setup key copied.")};document.querySelector("#copy-uri").onclick=function(){copyText(provision.provisioningUri,"Provisioning address copied.")};document.querySelector("#next").onclick=function(){go("#confirm")};document.querySelector("#new").onclick=createProvision;attachHelp()}
function confirm(){progress(3);app.innerHTML='<h1>✅ Check your authenticator</h1><p class="lead">Enter the six digits from your app.</p><div class="hint">Take your time. If needed, show setup options again and try again.</div><form id="form"><div id="form-error" tabindex="-1"></div><label>Authenticator code</label><input class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" required><button class="primary">Confirm authenticator</button></form><button id="retry" class="secondary">Show setup options again</button>'+help();document.querySelector("#form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/authenticator/confirm","POST",{code:new FormData(e.target).get("code")});if(!r.ok)return error(r.message);log("Authenticator confirmed.");notice="Authenticator confirmed. Next: create your recovery codes.";go(r.next)};document.querySelector("#retry").onclick=function(){provision?showProvision():go("#setup")};attachHelp()}
function recovery(){progress(4);app.innerHTML='<h1>🧾 Save recovery codes</h1>'+takeNotice()+'<p class="lead">These help if you cannot use your authenticator.</p><div class="hint">Save them somewhere private. Each code works once.</div><div id="form-error" tabindex="-1"></div><button id="create" class="primary">Create recovery codes</button><button id="test" class="link">Use a recovery code instead</button>'+help();document.querySelector("#create").onclick=async function(){var r=await api("/api/recovery/generate","POST",{});if(!r.ok)return error(r.message);recoveryCodes=r.codes;privateDemo("Simulated recovery-code set:",recoveryCodes);log("Recovery codes created. They are shown only on this protected screen and in the browser console.");showCodes()};document.querySelector("#test").onclick=function(){go("#use-recovery")};attachHelp()}
function showCodes(){app.innerHTML='<h1>🧾 Your recovery codes</h1><div class="success">Recovery codes created. Next: copy or save them privately.</div><div id="private"></div><button id="toggle" class="secondary">Hide recovery codes</button><button id="copy" class="secondary">Copy all codes</button><button id="done" class="primary">I saved my codes</button><button id="test" class="link">Test a recovery code</button>'+help();var shown=true,box=document.querySelector("#private");function draw(){box.innerHTML=shown?'<ul class="codes"></ul>':'<div class="hint">Recovery codes are hidden. Select reveal when ready.</div>';if(shown)recoveryCodes.forEach(function(c){var li=document.createElement("li");li.textContent=c;box.firstChild.appendChild(li)});document.querySelector("#toggle").textContent=shown?"Hide recovery codes":"Reveal recovery codes"}draw();document.querySelector("#toggle").onclick=function(){shown=!shown;draw()};document.querySelector("#copy").onclick=function(){copyText(recoveryCodes.join("\\n"),"Recovery codes copied.")};document.querySelector("#done").onclick=function(){go("#saved")};document.querySelector("#test").onclick=function(){go("#use-recovery")};attachHelp()}
function useRecovery(){progress(4);app.innerHTML='<h1>🔑 Use a recovery code</h1><p class="lead">Use one saved code if you cannot use your authenticator.</p><div class="hint">Example: <b>ABCDE-FGHIJ</b><br>Each code works once. Take your time.</div><form id="form"><div id="form-error" tabindex="-1"></div><label>Recovery code</label><input class="code" name="code" autocomplete="one-time-code" autocapitalize="characters" maxlength="11" placeholder="ABCDE-FGHIJ" required><button class="primary">Check recovery code</button></form><button id="back" class="secondary">Back to recovery codes</button>'+help();document.querySelector("#form").onsubmit=async function(e){e.preventDefault();var r=await api("/api/recovery/verify","POST",{code:String(new FormData(e.target).get("code")||"").toUpperCase()});if(!r.ok)return error(r.message);notice=r.message+" Next: finish setup.";log("A recovery code was accepted and marked used.");go("#saved")};document.querySelector("#back").onclick=function(){go("#recovery")};attachHelp()}
function saved(){progress(4);app.innerHTML='<h1>🎉 Security setup complete</h1>'+takeNotice()+'<div class="success">Your authenticator is connected and your recovery codes are saved.</div><button id="use" class="secondary">Use a recovery code</button><button id="start" class="primary">Finish</button>'+help();document.querySelector("#start").onclick=function(){alert("Security setup is complete.")};document.querySelector("#use").onclick=function(){go("#use-recovery")};attachHelp()}
async function render(){var route=routes.has(location.hash)?location.hash:"#signin";if(route==="#signin"){await bootstrap();signin();return}var state=await session();if(!state){go("#signin");return}if(!state.verified&&route!=="#identity"){go("#identity");return}if(!state.mfa&&["#recovery","#use-recovery","#saved"].includes(route)){go(state.provisioned?"#confirm":"#setup");return}if(state.mfa&&state.recoveryCount===0&&["#saved","#use-recovery"].includes(route)){go("#recovery");return}({"#identity":identity,"#setup":setup,"#confirm":confirm,"#recovery":recovery,"#use-recovery":useRecovery,"#saved":saved})[route]()}
logout.onclick=async function(){var r=await api("/api/logout","POST",{});if(r.ok){csrf="";provision=null;recoveryCodes=[];log("Secure session ended.");go("#signin")}};addEventListener("hashchange",render);render()})();</script></body></html>`;
}

const certificate = readFileSync("certs/cert.pem");
const privateKey = readFileSync("certs/key.pem");

/* Requirement 3: TLS-only Bun server using supplied localhost certificates. */
Bun.serve({
  port: 3000,
  tls: { cert: certificate, key: privateKey },
  fetch: async request => {
    const nonce = random(18);
    try {
      const url = new URL(request.url), origin = request.headers.get("origin");
      if (request.headers.get("x-forwarded-proto") === "http") return new Response("Secure connection required.", { status: 426, headers: secureHeaders(nonce) });
      if (origin && !origins.has(origin)) return new Response("Not allowed.", { status: 403, headers: secureHeaders(nonce) });
      const cors = origin ? { "Access-Control-Allow-Origin": origin } : {};
      if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: { ...secureHeaders(nonce), ...cors, "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token, X-Login-CSRF" } });
      if (url.pathname.startsWith("/api/")) {
        const out = await api(request, url.pathname, nonce);
        for (const [key, value] of Object.entries(cors)) out.headers.set(key, value);
        return out;
      }
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html"))
        return new Response(page(nonce), { headers: { ...secureHeaders(nonce), ...cors, "Content-Type": "text/html; charset=utf-8" } });
      return new Response("Page not found.", { status: 404, headers: secureHeaders(nonce) });
    } catch {
      return new Response("We could not complete that request. Please try again.", { status: 500, headers: secureHeaders(nonce) });
    }
  },
});
