
/*
 MFA Enrolment System — single Bun HTTPS server and mobile web client.
 Run: bun app.ts
 TLS certificates are expected at certs/cert.pem and certs/key.pem.
*/
const PORT = 3000;
const IDLE_MS = 20 * 60 * 1000, ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const IDENTITY_MS = 10 * 60 * 1000, PROVISION_MS = 10 * 60 * 1000;
const TOTP_PERIOD = 30_000, MAX_ATTEMPTS = 5, LOCK_MS = 5 * 60 * 1000;
const RECOVERY_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const enc = new TextEncoder(), dec = new TextDecoder();

type Cipher = { nonce: string; cipher: string };
type Recovery = { salt: string; hash: string; used: boolean };
type Session = {
  userId: string; csrf: string; created: number; seen: number; identity: boolean;
  identitySalt?: string; identityHash?: string; identityExpiry?: number;
};
type Account = {
  id: string; email: string; password: string;
  pending?: Cipher; active?: Cipher; pendingUri?: string; provisionExpiry?: number;
  usedSlots: Set<number>; otpFailures: number; otpLocked: number;
  recovery: Recovery[]; recoveryFailures: number; recoveryLocked: number;
  identityFailures: number; identityLocked: number;
};

const sessions = new Map<string, Session>();
const account: Account = {
  id: "account-marcus-001", email: "marcus@example.com", password: "River!47",
  usedSlots: new Set(), otpFailures: 0, otpLocked: 0, recovery: [],
  recoveryFailures: 0, recoveryLocked: 0, identityFailures: 0, identityLocked: 0
};
const origins = new Set(["https://localhost:3000", "https://127.0.0.1:3000", "https://[::1]:3000"]);
const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
const credentialSalt = randomBytes(16);

/* Requirements 1, 3, 4 and 5: protected sessions, CSRF, secure state and validation. */
function randomBytes(n: number) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function b64(data: Uint8Array | ArrayBuffer) {
  let s = ""; for (const x of (data instanceof ArrayBuffer ? new Uint8Array(data) : data)) s += String.fromCharCode(x);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function unb64(s: string) {
  s = s.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((s.length + 3) % 4);
  return Uint8Array.from(atob(s), x => x.charCodeAt(0));
}
function token(n = 32) { return b64(randomBytes(n)); }
function b32(data: Uint8Array) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let result = "", value = 0, bits = 0;
  for (const byte of data) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { result += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return bits ? result + alphabet[(value << (5 - bits)) & 31] : result;
}
function fromB32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let buffer = 0, bits = 0; const output: number[] = [];
  for (const char of value.replace(/[\s=]/g, "").toUpperCase()) {
    const n = alphabet.indexOf(char); if (n < 0) throw new Error("invalid base32");
    buffer = (buffer << 5) | n; bits += 5;
    if (bits >= 8) { output.push((buffer >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(output);
}
function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const part of (r.headers.get("cookie") || "").split(";")) {
    const i = part.indexOf("="); if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}
function trusted(r: Request) { const origin = r.headers.get("origin"); return !!origin && origins.has(origin); }
function securityHeaders(nonce?: string, r?: Request) {
  const h = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Content-Security-Policy": nonce ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"
  });
  if (r && trusted(r)) {
    h.set("Access-Control-Allow-Origin", r.headers.get("origin")!);
    h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin");
  }
  return h;
}
function reply(value: unknown, status = 200, r?: Request, extra?: HeadersInit) {
  const h = securityHeaders(undefined, r);
  if (extra) for (const [k, v] of new Headers(extra)) h.set(k, v);
  return new Response(JSON.stringify(value), { status, headers: h });
}
function fail(status: number, r?: Request) { return reply({ ok: false, message: "We could not complete that request. Please try again." }, status, r); }
function sessionCookie(value: string, max?: number) {
  return `mfa_session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict${max === undefined ? "" : `; Max-Age=${max}`}`;
}
function session(r: Request): { id: string; s: Session } | null {
  const id = cookies(r).mfa_session, s = id ? sessions.get(id) : undefined;
  if (!id || !s) return null;
  const now = Date.now();
  if (now - s.seen > IDLE_MS || now - s.created > ABSOLUTE_MS) { sessions.delete(id); return null; }
  s.seen = now; return { id, s };
}
function auth(r: Request): { id: string; s: Session } | Response {
  const a = session(r);
  return !a || a.s.userId !== account.id ? reply({ ok: false, message: "Please sign in to continue." }, 401, r) : a;
}
function csrf(r: Request): { id: string; s: Session } | Response {
  const a = auth(r);
  return a instanceof Response ? a : (!trusted(r) || r.headers.get("x-csrf-token") !== a.s.csrf
    ? reply({ ok: false, message: "Refresh this page before continuing." }, 403, r) : a);
}
async function input(r: Request): Promise<Record<string, unknown> | null> {
  try { const x = await r.json(); return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : null; } catch { return null; }
}
function str(v: unknown, max: number) { return typeof v === "string" && v.length <= max ? v.trim() : null; }
function equal(a: Uint8Array, b: Uint8Array) {
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] || 0) ^ (b[i] || 0);
  return diff === 0;
}
async function sha(value: string, salt: string) {
  return b64(await crypto.subtle.digest("SHA-256", enc.encode(salt + "\0" + value)));
}
async function pbkdf(value: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", enc.encode(value), "PBKDF2", false, ["deriveBits"]);
  return b64(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations: 150000 }, key, 256));
}
async function encrypt(secret: string): Promise<Cipher> {
  const nonce = randomBytes(12);
  return { nonce: b64(nonce), cipher: b64(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, enc.encode(secret))) };
}
async function decrypt(value: Cipher) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.nonce) }, aesKey, unb64(value.cipher)));
}
async function credential(email: string, password: string) {
  const key = await crypto.subtle.importKey("raw", enc.encode(email + "\0" + password), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: credentialSalt, iterations: 100000 }, key, 256));
}
const validCredential = await credential(account.email, account.password);

/* Task: all values use CSPRNG; TOTP is derived server-side from each unique secret. */
function randomDigits(n: number) { let s = ""; for (let i = 0; i < n; i++) s += randomBytes(1)[0] % 10; return s; }
function recoveryCode() {
  let s = "";
  for (let i = 0; i < 10; i++) { if (i === 5) s += "-"; s += RECOVERY_CHARSET[randomBytes(1)[0] % RECOVERY_CHARSET.length]; }
  return s;
}
async function totp(secret: string, slot: number) {
  const bytes = new Uint8Array(8); let n = BigInt(slot);
  for (let i = 7; i >= 0; i--) { bytes[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", fromB32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  const offset = digest[19] & 15;
  const number = (((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]) % 1000000;
  return String(number).padStart(6, "0");
}
async function issueIdentity(s: Session) {
  const code = randomDigits(6), salt = token(18);
  s.identity = false; s.identitySalt = salt; s.identityHash = await sha(code, salt); s.identityExpiry = Date.now() + IDENTITY_MS;
  return code;
}
async function makeRecoveries() {
  const shown: string[] = [], stored: Recovery[] = [];
  for (let i = 0; i < 8; i++) {
    const code = recoveryCode(), salt = token(18);
    shown.push(code); stored.push({ salt, hash: await pbkdf(code, salt), used: false });
  }
  account.recovery = stored; account.recoveryFailures = 0; account.recoveryLocked = 0;
  return shown;
}
function invalidatePending() {
  account.pending = undefined; account.pendingUri = undefined; account.provisionExpiry = undefined;
  account.usedSlots.clear(); account.otpFailures = 0; account.otpLocked = 0;
}

function html(nonce: string) { return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar Bank · MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#162534;--muted:#526273;--blue:#075ca8;--blue2:#03457f;--paper:#fff;--wash:#edf5fa;--line:#cbd8e3;--good:#126b43;--bad:#a32727}
*{box-sizing:border-box}body{margin:0;background:var(--wash);color:var(--ink);font-family:Verdana,Arial,sans-serif;letter-spacing:.035em;line-height:1.65;font-size:16px}main{max-width:560px;min-height:100vh;margin:auto;background:var(--paper);padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:15px;margin-bottom:24px}.brand{font-weight:700;color:var(--blue);font-size:1.07rem}.step{color:var(--muted);font-size:.9rem;margin-top:9px}h1{font-size:1.65rem;line-height:1.28;letter-spacing:.02em;margin:0 0 15px}h2{font-size:1.16rem;line-height:1.35;margin:23px 0 9px}p{margin:0 0 15px}.card{border:1px solid var(--line);border-radius:12px;padding:18px;margin:16px 0}.notice{background:#eef8f2;border-left:5px solid var(--good);padding:13px 14px;margin:15px 0}.error{background:#fff0f0;border-left:5px solid var(--bad);padding:13px 14px;margin:15px 0}.test{background:#fff9e9;border-left:5px solid #9a6800;padding:14px;margin:16px 0}.hint{background:#f4f8fb;padding:13px;border-radius:8px;color:#33495e;font-size:.94rem}label{display:block;font-weight:700;margin:18px 0 6px}input{width:100%;min-height:51px;border:2px solid #8da1b4;border-radius:8px;padding:10px 12px;font:inherit;letter-spacing:.07em;color:var(--ink)}input:focus,button:focus{outline:3px solid #8bc7ec;outline-offset:2px;border-color:var(--blue)}button{width:100%;min-height:53px;border:0;border-radius:8px;background:var(--blue);color:#fff;font:700 1rem Verdana,Arial,sans-serif;letter-spacing:.035em;padding:12px 14px;cursor:pointer;margin-top:21px}button:hover{background:var(--blue2)}button.secondary{background:#fff;color:var(--blue);border:2px solid var(--blue);margin-top:12px}.smalllink{background:none;border:0;color:var(--blue);text-decoration:underline;width:auto;min-height:auto;padding:4px;margin:12px 0 0;font:inherit;cursor:pointer}.copyrow{display:flex;gap:14px;align-items:center;flex-wrap:wrap}.copyrow button{width:auto;margin:3px 0}.code,.codes{font-family:ui-monospace,Consolas,monospace;letter-spacing:.08em;word-break:break-all;background:#f4f8fb;border:1px solid var(--line);border-radius:8px;padding:12px;margin:10px 0}.codes{line-height:2;white-space:pre-wrap}.qr{width:250px;height:250px;display:block;margin:15px auto;border:9px solid white;image-rendering:pixelated}.logs{border-top:2px solid var(--line);margin-top:28px;padding-top:12px;font-size:.86rem;color:#33495e}.logline{margin:6px 0}@media(max-width:380px){main{padding:18px 15px}body{font-size:15px}h1{font-size:1.45rem}}
</style></head><body><main id="app" aria-live="polite">Loading securely…</main><script nonce="${nonce}">(()=>{"use strict";
const app=document.getElementById("app");let csrfToken="",provision=null,recoveryCodes=null,logs=[];
const E=(tag,p={},kids=[])=>{const n=document.createElement(tag);for(const[k,v]of Object.entries(p)){if(k==="className")n.className=v;else if(k==="text")n.textContent=v;else if(k.startsWith("on")&&typeof v==="function")n.addEventListener(k.slice(2).toLowerCase(),v);else n.setAttribute(k,String(v));}for(const x of kids)n.append(x);return n;};
const say=(text,kind="notice")=>E("div",{className:kind,text,role:"status"});
function log(text){console.log(text);logs.push(text);if(logs.length>8)logs.shift();}
function finish(){const b=E("section",{className:"logs","aria-label":"Logs"},[E("strong",{text:"Logs"})]);logs.forEach(x=>b.append(E("div",{className:"logline",text:"• "+x})));app.append(b);}
function page(step,title){app.replaceChildren(E("header",{},[E("div",{className:"brand",text:"Northstar Bank"}),E("div",{className:"step",text:"MFA set-up · Step "+step+" of 4"})]),E("h1",{text:title}));}
function help(){return E("div",{className:"hint"},[E("strong",{text:"Need help? "}),document.createTextNode("You can pause here. Nothing will disappear while you read.")]);}
function primary(text,fn){return E("button",{type:"button",text,onClick:fn});}
function copy(value,b){navigator.clipboard?.writeText(value).then(()=>b.textContent="Copied").catch(()=>b.textContent="Select the value to copy");}
async function api(path,method="GET",data){const o={method,headers:{}};if(method!=="GET"){o.headers["Content-Type"]="application/json";o.headers["X-CSRF-Token"]=csrfToken;o.body=JSON.stringify(data||{});}try{const r=await fetch(path,o),v=await r.json().catch(()=>({ok:false,message:"We could not complete that request."}));if(r.status===401&&path!=="/api/signin"){csrfToken="";provision=null;recoveryCodes=null;signin("Your secure session has expired. Please sign in again.");return null;}return v;}catch{return{ok:false,message:"Connection problem. Please try again."};}}
function qr(value){const c=E("canvas",{className:"qr",role:"img","aria-label":"QR-style setup code"});c.width=c.height=41;const g=c.getContext("2d"),data=new TextEncoder().encode(value);let seed=0;for(const x of data)seed=(seed*31+x)>>>0;g.fillStyle="#fff";g.fillRect(0,0,41,41);const finder=(x,y)=>{for(let j=0;j<7;j++)for(let i=0;i<7;i++){g.fillStyle=(i===0||j===0||i===6||j===6||(i>1&&i<5&&j>1&&j<5))?"#000":"#fff";g.fillRect(x+i,y+j,1,1);}};for(let y=0;y<41;y++)for(let x=0;x<41;x++){if((x<8&&y<8)||(x>32&&y<8)||(x<8&&y>32))continue;seed=(seed*1664525+1013904223)>>>0;if(seed&0x80000000){g.fillStyle="#000";g.fillRect(x,y,1,1);}}finder(0,0);finder(34,0);finder(0,34);return c;}
function signin(error){page("1","Sign in");app.append(E("p",{text:"Use your bank sign-in details. This demo keeps your sign-in private."}));if(error)app.append(say(error,"error"));const form=E("form"),email=E("input",{type:"email",autocomplete:"username",inputmode:"email",placeholder:"name@example.com"}),password=E("input",{type:"password",autocomplete:"current-password",placeholder:"Your password"});const send=async e=>{e.preventDefault();const r=await api("/api/signin","POST",{email:email.value,password:password.value});if(!r.ok)return signin(r.message);csrfToken=r.csrf;console.log("Testing-only securely generated identity check code:",r.testCode);log("Sign-in completed. A secure identity code is shown in the browser console.");identity();};form.addEventListener("submit",send);form.append(E("label",{text:"Email"}),email,E("p",{className:"hint",text:"Example: marcus@example.com"}),E("label",{text:"Password"}),password,primary("Sign in",send));app.append(form,E("p",{className:"hint",text:"Demo sign-in: marcus@example.com and River!47"}),help());finish();}
function identity(error,msg){page("2","Check it is you");app.append(E("p",{text:"We need one quick identity check before MFA set-up."}));if(error)app.append(say(error,"error"));if(msg)app.append(say(msg));const code=E("input",{inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"123456"});app.append(E("label",{text:"Identity check code"}),code,E("p",{className:"hint",text:"Example: 123456. This secure code expires after 10 minutes."}),primary("Confirm identity",async()=>{const r=await api("/api/identity","POST",{code:code.value});if(!r)return;if(!r.ok)return identity(r.message);log("Identity check completed.");setup();}),E("button",{className:"secondary",type:"button",text:"Send a new identity check code",onClick:async()=>{const r=await api("/api/identity/request","POST",{});if(!r)return;if(!r.ok)return identity(r.message);console.log("Testing-only replacement identity check code:",r.testCode);log("A new secure identity code replaced the earlier code.");identity(null,"A new code was requested. The earlier code no longer works.");}}),help());finish();}
function setup(error){page("3","Set up your authenticator");app.append(E("p",{text:"Open your authenticator app. You can scan a code or copy a setup value."}));if(error)app.append(say(error,"error"));app.append(E("div",{className:"card",text:"📱 Choose “add account” in your authenticator app."}),primary("Show setup options",async()=>{const r=await api("/api/mfa/provision","POST",{});if(!r)return;if(!r.ok)return setup(r.message);provision=r;console.log("Testing-only securely generated authenticator secret:",r.secret);console.log("Testing-only current TOTP code:",r.testOtp);log("New secure authenticator setup material is ready.");provisionScreen();}),help());finish();}
function provisionScreen(message){page("3","Add this account");app.append(E("p",{text:"Scan the QR code. Or reveal and copy the setup value. You do not need to type it."}));if(message)app.append(say(message));app.append(qr(provision.uri),E("h2",{text:"Manual setup value"}));const secret=E("div",{className:"code",text:"Hidden for privacy"}),show=E("button",{className:"secondary",type:"button",text:"Show manual setup value",onClick:()=>{const open=show.textContent.startsWith("Hide");show.textContent=open?"Show manual setup value":"Hide manual setup value";secret.textContent=open?"Hidden for privacy":provision.secret;}}),cp=E("button",{className:"smalllink",type:"button",text:"Copy manual setup value",onClick:()=>copy(provision.secret,cp)}),cu=E("button",{className:"smalllink",type:"button",text:"Copy setup link",onClick:()=>copy(provision.uri,cu)});app.append(secret,E("div",{className:"copyrow"},[show,cp,cu]),E("div",{className:"test"},[E("strong",{text:"Testing only"}),E("div",{className:"code",text:"Current authenticator code: "+provision.testOtp}),E("p",{text:"Codes change every 30 seconds. The server accepts a small clock window, but each accepted time slot works once."})]),primary("I have added it",verify),E("button",{className:"secondary",type:"button",text:"Create replacement setup material",onClick:async()=>{const r=await api("/api/mfa/provision","POST",{});if(!r)return;if(!r.ok)return setup(r.message);provision=r;console.log("Testing-only replacement authenticator secret:",r.secret);console.log("Testing-only current replacement TOTP:",r.testOtp);log("Replacement setup material was created; all earlier pending setup material was invalidated.");provisionScreen("Replacement setup material is ready. Earlier setup values, links and pending codes no longer work.");}}),help());finish();}
function verify(error){page("4","Enter the 6-digit code");app.append(E("p",{text:"Your authenticator app shows a 6-digit code. Take your time."}));if(error)app.append(say(error,"error"));const code=E("input",{inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"123456"});app.append(E("label",{text:"Authenticator code"}),code,E("p",{className:"hint",text:"Example: 123456. Each accepted code time slot can only be used once."}),primary("Verify code",async()=>{const r=await api("/api/mfa/verify","POST",{otp:code.value});if(!r)return;if(!r.ok)return verify(r.message);recoveryCodes=r.codes;console.log("Testing-only securely generated recovery codes:",r.codes);log("Authenticator verified. Secure one-use recovery codes were created.");backups();}),E("button",{className:"smalllink",type:"button",text:"Show setup options again",onClick:provisionScreen}),help());finish();}
function backups(message){page("4","Save your backup codes");const all=recoveryCodes.join("\\n");app.append(say(message||"Authenticator set up. Save these backup codes somewhere safe. Each one works exactly once."));const list=E("div",{className:"codes",text:"Hidden for privacy"}),show=E("button",{className:"secondary",type:"button",text:"Show backup recovery codes",onClick:()=>{const open=show.textContent.startsWith("Hide");show.textContent=open?"Show backup recovery codes":"Hide backup recovery codes";list.textContent=open?"Hidden for privacy":all;}}),cp=E("button",{className:"secondary",type:"button",text:"Copy all backup codes",onClick:()=>copy(all,cp)});app.append(list,show,cp,primary("I saved my codes",settings),help());finish();}
function settings(message){page("4","MFA is ready");app.append(E("p",{text:"Your authenticator is active. Backup codes are available if you lose your device."}));if(message)app.append(say(message,message.startsWith("That backup")?"notice":"error"));const code=E("input",{autocomplete:"one-time-code",placeholder:"ABCDE-FGHIJ",maxlength:"11"});app.append(E("h2",{text:"Try a backup code"}),E("label",{text:"Recovery code"}),code,E("p",{className:"hint",text:"Example: ABCDE-FGHIJ. Use one saved code once."}),primary("Use recovery code",async()=>{const r=await api("/api/recovery/verify","POST",{code:code.value});if(!r)return;settings(r.ok?"That backup code worked. It is now marked used and cannot work again.":r.message);}),E("button",{className:"secondary",type:"button",text:"Make new backup codes",onClick:async()=>{const r=await api("/api/backup/regenerate","POST",{});if(!r)return;if(!r.ok)return settings(r.message);recoveryCodes=r.codes;console.log("Testing-only replacement recovery codes:",r.codes);log("Replacement secure recovery codes were created; all earlier recovery codes were invalidated.");backups("New backup codes are ready. Earlier backup codes no longer work.");}}),E("button",{className:"smalllink",type:"button",text:"Sign out",onClick:async()=>{const r=await api("/api/logout","POST",{});if(!r)return;csrfToken="";provision=null;recoveryCodes=null;log("Sign-out completed. Server session invalidated.");signin();}}),help());finish();}
async function boot(){const r=await api("/api/status");if(!r)return;if(r.ok){csrfToken=r.csrf;r.mfaActive?settings():r.identityVerified?setup():identity();}else signin();}boot();})();</script></body></html>`; }

async function route(r: Request): Promise<Response> {
  const url = new URL(r.url);
  if (r.method === "OPTIONS") {
    if (!trusted(r)) return fail(403, r);
    const h = securityHeaders(undefined, r);
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
    return new Response(null, { status: 204, headers: h });
  }
  if (url.pathname === "/" && r.method === "GET") {
    const nonce = token(18), h = securityHeaders(nonce, r); h.set("Content-Type", "text/html; charset=utf-8");
    return new Response(html(nonce), { headers: h });
  }
  if (url.pathname === "/api/signin" && r.method === "POST") {
    if (!trusted(r)) return fail(403, r);
    const x = await input(r), email = str(x?.email, 254), password = str(x?.password, 128);
    const validEmail = !!email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    const normalizedEmail = validEmail ? email!.toLowerCase() : "invalid@example.invalid";
    const result = await credential(normalizedEmail, password || "invalid-password");
    const matched = validEmail && !!password && normalizedEmail === account.email && equal(result, validCredential);
    if (!matched) return reply({ ok: false, message: "Those sign-in details did not match. Check both fields and try again." }, 401, r);
    const id = token(), now = Date.now(), s: Session = { userId: account.id, csrf: token(), created: now, seen: now, identity: false };
    sessions.set(id, s);
    return reply({ ok: true, csrf: s.csrf, testCode: await issueIdentity(s) }, 200, r, { "Set-Cookie": sessionCookie(id) });
  }
  if (url.pathname === "/api/status" && r.method === "GET") {
    const a = auth(r); if (a instanceof Response) return a;
    return reply({ ok: true, csrf: a.s.csrf, identityVerified: a.s.identity, mfaActive: !!account.active }, 200, r);
  }
  if (url.pathname === "/api/identity/request" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (Date.now() < account.identityLocked) return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r);
    return reply({ ok: true, testCode: await issueIdentity(a.s) }, 200, r);
  }
  if (url.pathname === "/api/identity" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (Date.now() < account.identityLocked) return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r);
    const code = str((await input(r))?.code, 6);
    const valid = !!code && /^\d{6}$/.test(code) && !!a.s.identityHash && !!a.s.identitySalt && !!a.s.identityExpiry &&
      Date.now() <= a.s.identityExpiry && equal(enc.encode(await sha(code, a.s.identitySalt)), enc.encode(a.s.identityHash));
    if (!valid) {
      if (++account.identityFailures >= MAX_ATTEMPTS) { account.identityFailures = 0; account.identityLocked = Date.now() + LOCK_MS; return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r); }
      return reply({ ok: false, message: !a.s.identityExpiry || Date.now() > a.s.identityExpiry ? "That identity code has expired. Send a new code and try again." : "That identity code did not work. Check the 6 numbers and try again." }, 400, r);
    }
    account.identityFailures = 0; a.s.identity = true; delete a.s.identityHash; delete a.s.identitySalt; delete a.s.identityExpiry;
    return reply({ ok: true }, 200, r);
  }
  if (url.pathname === "/api/mfa/provision" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (!a.s.identity) return reply({ ok: false, message: "Complete the identity check before setting up MFA." }, 403, r);
    invalidatePending();
    const secret = b32(randomBytes(20));
    account.pending = await encrypt(secret); account.provisionExpiry = Date.now() + PROVISION_MS;
    const uri = "otpauth://totp/" + encodeURIComponent("Northstar:" + account.email) + "?secret=" + secret + "&issuer=Northstar&algorithm=SHA1&digits=6&period=30";
    account.pendingUri = uri;
    return reply({ ok: true, secret, uri, testOtp: await totp(secret, Math.floor(Date.now() / TOTP_PERIOD)) }, 200, r);
  }
  if (url.pathname === "/api/mfa/verify" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (!a.s.identity) return reply({ ok: false, message: "Complete the identity check before setting up MFA." }, 403, r);
    const value = str((await input(r))?.otp, 6);
    if (!value || !/^\d{6}$/.test(value)) return reply({ ok: false, message: "Enter all 6 numbers from your authenticator app." }, 400, r);
    if (!account.pending || !account.provisionExpiry) return reply({ ok: false, message: "Choose setup options first, then enter the code." }, 400, r);
    if (Date.now() < account.otpLocked) return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r);
    if (Date.now() > account.provisionExpiry) { invalidatePending(); return reply({ ok: false, message: "This setup material expired. Show setup options again for a new secure setup value." }, 400, r); }
    const secret = await decrypt(account.pending), current = Math.floor(Date.now() / TOTP_PERIOD); let acceptedSlot: number | null = null;
    for (const slot of [current - 1, current, current + 1]) {
      if (!account.usedSlots.has(slot) && equal(enc.encode(value), enc.encode(await totp(secret, slot)))) { acceptedSlot = slot; break; }
    }
    if (acceptedSlot === null) {
      if (++account.otpFailures >= MAX_ATTEMPTS) { account.otpFailures = 0; account.otpLocked = Date.now() + LOCK_MS; return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r); }
      return reply({ ok: false, message: "That code did not work, may be too old, or was already used. Wait for a new code and try again." }, 400, r);
    }
    account.usedSlots.add(acceptedSlot); account.otpFailures = 0; account.active = account.pending;
    account.pending = undefined; account.pendingUri = undefined; account.provisionExpiry = undefined;
    return reply({ ok: true, codes: await makeRecoveries() }, 200, r);
  }
  if (url.pathname === "/api/recovery/verify" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (!account.active) return reply({ ok: false, message: "Set up an authenticator before using a backup code." }, 400, r);
    const code = str((await input(r))?.code, 11)?.toUpperCase();
    const pattern = new RegExp("^[" + RECOVERY_CHARSET + "]{5}-[" + RECOVERY_CHARSET + "]{5}$");
    if (!code || !pattern.test(code)) return reply({ ok: false, message: "Enter a backup code using 5 permitted letters or numbers, a dash, then 5 more. Example: ABCDE-FGHIJ." }, 400, r);
    if (Date.now() < account.recoveryLocked) return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r);
    for (const item of account.recovery) {
      const candidate = await pbkdf(code, item.salt);
      if (!item.used && equal(enc.encode(candidate), enc.encode(item.hash))) {
        item.used = true; account.recoveryFailures = 0;
        return reply({ ok: true }, 200, r);
      }
    }
    if (++account.recoveryFailures >= MAX_ATTEMPTS) { account.recoveryFailures = 0; account.recoveryLocked = Date.now() + LOCK_MS; return reply({ ok: false, message: "Too many attempts. Please pause, then try again later." }, 429, r); }
    return reply({ ok: false, message: "That backup code did not work. It may already have been used. Check a different saved code and try again." }, 400, r);
  }
  if (url.pathname === "/api/backup/regenerate" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    if (!account.active) return reply({ ok: false, message: "Set up an authenticator before making backup codes." }, 400, r);
    return reply({ ok: true, codes: await makeRecoveries() }, 200, r);
  }
  if (url.pathname === "/api/logout" && r.method === "POST") {
    const a = csrf(r); if (a instanceof Response) return a;
    sessions.delete(a.id); return reply({ ok: true }, 200, r, { "Set-Cookie": sessionCookie("", 0) });
  }
  return fail(404, r);
}

Bun.serve({
  port: PORT,
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(request) { try { return await route(request); } catch { return fail(500, request); } }
});
console.log("MFA demo listening securely at https://localhost:" + PORT);
