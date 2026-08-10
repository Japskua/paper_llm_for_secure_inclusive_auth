
/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Run with: bun app.ts
 TLS certificates: certs/cert.pem and certs/key.pem
*/
const encoder = new TextEncoder();
const sessions = new Map<string, { userId: string; csrf: string; createdAt: number; lastSeenAt: number }>();
const accounts = new Map<string, any>();
const SESSION_IDLE = 30 * 60_000, SESSION_ABSOLUTE = 8 * 60 * 60_000, MAX_FAILURES = 5, LOCKOUT = 5 * 60_000;
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const recoveryKey = crypto.getRandomValues(new Uint8Array(32));

function sha256(v: string) { return Bun.CryptoHasher.hash("sha256", v, "hex"); }
function token(n = 32) { return Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url"); }
function same(a: string, b: string) {
  const x = encoder.encode(a), y = encoder.encode(b); let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}
async function hmac(v: string, key: Uint8Array) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Buffer.from(await crypto.subtle.sign("HMAC", k, encoder.encode(v))).toString("hex");
}
async function encrypt(v: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  const c = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, k, encoder.encode(v));
  return { iv: Buffer.from(iv).toString("base64url"), ciphertext: Buffer.from(c).toString("base64url") };
}
async function decrypt(v: any) {
  const k = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  const p = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(v.iv, "base64url") }, k, Buffer.from(v.ciphertext, "base64url"));
  return new TextDecoder().decode(p);
}
function secret() {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let s = "";
  while (s.length < 32) for (const b of crypto.getRandomValues(new Uint8Array(32))) if (b < 248) { s += a[b % 32]; if (s.length === 32) return s; }
  return s;
}
function recovery() {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", set = new Set<string>();
  while (set.size < 10) {
    let s = ""; while (s.length < 10) for (const b of crypto.getRandomValues(new Uint8Array(32))) if (b < 252) { s += a[b % 36]; if (s.length === 10) break; }
    set.add(s.slice(0, 5) + "-" + s.slice(5));
  }
  return [...set];
}
function base32(s: string) {
  const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, count = 0; const out: number[] = [];
  for (const c of s.replace(/=|\s/g, "").toUpperCase()) {
    const n = a.indexOf(c); if (n < 0) throw new Error("invalid");
    bits = (bits << 5) | n; count += 5;
    while (count >= 8) { count -= 8; out.push((bits >>> count) & 255); }
  }
  return new Uint8Array(out);
}
async function totp(s: string, count = Math.floor(Date.now() / 30_000)) {
  const data = new Uint8Array(8); let n = BigInt(count);
  for (let i = 7; i >= 0; i--) { data[i] = Number(n & 255n); n >>= 8n; }
  const k = await crypto.subtle.importKey("raw", base32(s), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const d = new Uint8Array(await crypto.subtle.sign("HMAC", k, data)), o = d[19] & 15;
  const v = ((d[o] & 127) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
  return String(v % 1_000_000).padStart(6, "0");
}
accounts.set("marcus-account-001", {
  id: "marcus-account-001", email: "marcus@example.com", passwordHash: sha256("BankDemo!42"),
  mfaEnabled: false, pending: null, active: null, pendingUsed: [], used: [], backup: [],
  otpFailures: 0, otpLocked: 0, recoveryFailures: 0, recoveryLocked: 0, replacing: false
});
const dummy = sha256("not-a-real-account-password");

function cookies(r: Request) {
  const o: Record<string, string> = {};
  for (const c of (r.headers.get("cookie") || "").split(";")) { const i = c.indexOf("="); if (i > 0) o[c.slice(0, i).trim()] = c.slice(i + 1).trim(); }
  return o;
}
function trusted(h: string) { return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]"; }
function originOK(r: Request) { const u = new URL(r.url); return u.protocol === "https:" && trusted(u.hostname) && r.headers.get("origin") === u.origin; }
function headers(r: Request, nonce = "") {
  const h = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains", "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store"
  });
  if (originOK(r)) { h.set("Access-Control-Allow-Origin", new URL(r.url).origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); }
  return h;
}
function json(r: Request, body: any, status = 200, extra?: HeadersInit) {
  const h = headers(r); h.set("Content-Type", "application/json; charset=utf-8");
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(JSON.stringify(body), { status, headers: h });
}
async function body(r: Request) { try { const x = await r.json(); return x && typeof x === "object" && !Array.isArray(x) ? x as any : null; } catch { return null; } }
function owner(r: Request): any {
  const id = cookies(r).mfa_session, s = id && sessions.get(id), now = Date.now();
  if (!s || now - s.lastSeenAt > SESSION_IDLE || now - s.createdAt > SESSION_ABSOLUTE) { if (id) sessions.delete(id); return null; }
  const a = accounts.get(s.userId); if (!a) return null; s.lastSeenAt = now; return { id, s, a };
}
function csrf(r: Request, s: any) { return originOK(r) && r.headers.get("x-csrf-token") === s.csrf; }
function validOtp(v: any) { return typeof v === "string" && /^\d{6}$/.test(v); }
function validCode(v: any) { return typeof v === "string" && /^[A-Z0-9]{5}-[A-Z0-9]{5}$/i.test(v); }
function cookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE / 1000}`; }

/* Requirements: Version 10-L QR encoder, byte mode, RS ECC level L.
   The Version 10-L block layout is 68, 68, 69, 69 data codewords, then 18 ECC each. */
function page(nonce: string) { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank · Security setup</title><style nonce="${nonce}">
:root{--ink:#172331;--blue:#1259b5;--line:#cbd8e6;--soft:#edf5ff;--bad:#8b2424}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font:16px/1.65 Verdana,Arial,sans-serif;letter-spacing:.025em}main{max-width:620px;min-height:100vh;margin:auto;padding:18px 16px}header{display:flex;gap:10px;align-items:center}.mark{background:var(--blue);color:white;border-radius:12px;padding:8px 14px;font-size:22px}h1{font-size:1.35rem}h2{line-height:1.3}.steps{display:flex;gap:4px;margin:18px 0}.steps span{flex:1;border-bottom:4px solid var(--line);font-size:.72rem;text-align:center}.steps .on{border-color:var(--blue);color:#073c83;font-weight:bold}.card{background:white;border:1px solid var(--line);border-radius:16px;padding:20px}.notice{padding:11px;border-radius:9px;background:var(--soft);margin:12px 0}.bad{background:#fff0f0;color:var(--bad)}label{display:block;font-weight:bold;margin:15px 0 5px}input,button{width:100%;min-height:52px;border-radius:10px;font:inherit}input{border:2px solid #9eafc0;padding:10px}button{border:0;padding:10px;margin-top:12px;font-weight:bold;cursor:pointer}.primary{background:var(--blue);color:white}.secondary{background:white;color:#073c83;border:2px solid var(--blue)}button:focus,input:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}.qr{width:250px;height:250px;padding:8px;margin:15px auto;border:1px solid var(--line)}.secret,.code{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere;background:#f4f8fc;padding:10px;border-radius:8px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.row{display:flex;gap:8px}.row button{flex:1}.hint{color:#526273;font-size:.88rem}.log{margin-top:18px;border-top:1px solid var(--line);padding-top:10px}.logs{white-space:pre-wrap;font:12px/1.5 ui-monospace,monospace;background:#101923;color:#dbefff;padding:10px;border-radius:8px;min-height:45px}@media(max-width:390px){.codes{grid-template-columns:1fr}}
</style></head><body><main><header><div class="mark">✦</div><div><h1>Northstar Bank</h1><div class="hint">Security setup</div></div></header><nav class="steps"><span data-s="1">1. Confirm</span><span data-s="2">2. App</span><span data-s="3">3. Check</span><span data-s="4">4. Save</span></nav><section id="app" class="card" aria-live="polite"></section><section class="log"><strong>Logs</strong><div id="logs" class="logs">Ready.</div></section><p class="hint">Take your time. There is no reading timer.</p></main><script nonce="${nonce}">
"use strict";const app=document.querySelector("#app"),logs=document.querySelector("#logs");let csrf="",sec="",uri="",codes=[];
function log(m,v){console.log(m,v||"");logs.textContent+=(logs.textContent==="Ready."?"":"\\n")+m+(v?" "+JSON.stringify(v):"")}
function esc(v){const e=document.createElement("span");e.textContent=String(v);return e.innerHTML}
function step(n){document.querySelectorAll("[data-s]").forEach(x=>x.classList.toggle("on",+x.dataset.s===n))}
function note(x,b=""){return '<div class="notice '+b+'">'+esc(x)+"</div>"}function help(){return "<details><summary>Help with this step</summary><p>Pause or retry at any time. There is no reading timer.</p></details>"}
async function api(path,data={}){let r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)}),d=await r.json().catch(()=>({message:"Please try again."}));if(r.status===401){csrf="";signin("Your session ended. Please sign in again.")}return {r,d}}
async function copy(v,name){try{await navigator.clipboard.writeText(v);document.querySelector("#msg").textContent=name+" copied."}catch{document.querySelector("#msg").textContent="Copy did not work. You can select the text instead."}}
/* QR implementation. Correct Version 10-L partition: [68,68,69,69]. */
function qr(u){const v=10,n=57,d=[],b=[...new TextEncoder().encode(u)];function bit(x,c){for(let i=c-1;i>=0;i--)d.push(x>>>i&1)}bit(4,4);bit(b.length,16);b.forEach(x=>bit(x,8));for(let i=0;i<Math.min(4,2192-d.length);i++)d.push(0);while(d.length%8)d.push(0);let raw=[];for(let i=0;i<d.length;i+=8)raw.push(d.slice(i,i+8).reduce((a,x)=>a*2+x,0));for(let i=0;raw.length<274;i++)raw.push(i%2?17:236);const ex=[1],lg=Array(256).fill(0);for(let i=1,x=1;i<256;i++){ex[i]=x;lg[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)ex[i]=ex[i-255];const mul=(a,b)=>a&&b?ex[lg[a]+lg[b]]:0;let g=[1];for(let i=0;i<18;i++){let z=Array(g.length+1).fill(0);g.forEach((x,j)=>{z[j]^=x;z[j+1]^=mul(x,ex[i])});g=z}function ecc(q){let r=Array(18).fill(0);q.forEach(x=>{let f=x^r.shift();r.push(0);g.slice(1).forEach((z,i)=>r[i]^=mul(z,f))});return r}
const bl=[raw.slice(0,68),raw.slice(68,136),raw.slice(136,205),raw.slice(205,274)],ec=bl.map(ecc),st=[];for(let i=0;i<69;i++)bl.forEach(q=>i<q.length&&st.push(q[i]));for(let i=0;i<18;i++)ec.forEach(q=>st.push(q[i]));const m=Array.from({length:n},()=>Array(n).fill(0)),used=Array.from({length:n},()=>Array(n).fill(false)),put=(x,y,z)=>{m[y][x]=z;used[y][x]=true};function find(x,y){for(let j=-1;j<=7;j++)for(let i=-1;i<=7;i++)if(x+i>=0&&y+j>=0&&x+i<n&&y+j<n)put(x+i,y+j,i>=0&&i<=6&&j>=0&&j<=6&&(i===0||i===6||j===0||j===6||(i>=2&&i<=4&&j>=2&&j<=4))?1:0)}find(0,0);find(50,0);find(0,50);for(let i=8;i<n-8;i++){if(!used[6][i])put(i,6,i%2===0);if(!used[i][6])put(6,i,i%2===0)}[6,28,50].forEach(y=>[6,28,50].forEach(x=>{if(used[y][x])return;for(let j=-2;j<=2;j++)for(let i=-2;i<=2;i++)put(x+i,y+j,Math.max(Math.abs(i),Math.abs(j))!==1?1:0)}));put(8,49,1);for(let i=0;i<9;i++){if(!used[8][i])put(i,8,0);if(!used[i][8])put(8,i,0)}for(let i=0;i<8;i++){put(56-i,8,0);put(8,56-i,0)}for(let i=0;i<6;i++)for(let j=0;j<3;j++){put(46+j,i,0);put(i,46+j,0)}let rem=v<<12;for(let i=17;i>=12;i--)if(rem&(1<<i))rem^=0x1f25;let ver=v<<12|rem;for(let i=0;i<18;i++){let z=ver>>>i&1,a=46+i%3,b=Math.floor(i/3);put(a,b,z);put(b,a,z)}let bi=0,up=true;for(let x=56;x>0;x-=2){if(x===6)x--;for(let q=0;q<n;q++){let y=up?56-q:q;for(let dx=0;dx<2;dx++)if(!used[y][x-dx]){let z=bi<st.length?st[bi>>>3]>>>(7-(bi&7))&1:0;bi++;if((x-dx+y)%2===0)z^=1;put(x-dx,y,z)}}up=!up}let f=8;for(let i=0;i<10;i++)if(f&(1<<i))f^=0x537;f=(8|f)^0x5412;for(let i=0;i<=5;i++)put(8,i,f>>>i&1);put(8,7,f>>>6&1);put(8,8,f>>>7&1);put(7,8,f>>>8&1);for(let i=9;i<15;i++)put(14-i,8,f>>>i&1);for(let i=0;i<8;i++)put(56-i,8,f>>>i&1);for(let i=8;i<15;i++)put(8,42+i,f>>>i&1);let p="";for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(m[y][x])p+="M"+x+" "+y+"h1v1h-1z";document.querySelector("#qr").innerHTML='<svg viewBox="0 0 57 57" role="img" aria-label="Authenticator QR code"><rect width="100%" height="100%" fill="white"/><path d="'+p+'" fill="black"/></svg>'}
function signin(info=""){step(1);app.innerHTML="<h2>Confirm your account</h2><p>Use your bank email and password.</p>"+note("Demo: marcus@example.com · password: BankDemo!42")+(info?note(info):"")+"<label>Email address</label><input id=e type=email autocomplete=email placeholder='marcus@example.com'><label>Password</label><input id=p type=password autocomplete=current-password><button class=primary id=go>Continue</button>"+help();go.onclick=async()=>{let r=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:e.value,password:p.value})}),d=await r.json();if(!r.ok)return app.insertAdjacentHTML("afterbegin",note(d.message,"bad"));csrf=d.csrf;d.mfaEnabled?account("Your authenticator is active."):setup("Your identity is confirmed. Next, add your authenticator app.")}}
function setup(x){step(2);app.innerHTML="<h2>Add your authenticator app</h2>"+note(x)+"<p>Open your authenticator app. You can scan a setup image or copy a secret.</p><button class=primary id=show>Show secure setup</button>"+help();show.onclick=provision}
async function provision(){let a=await api("/api/provision");if(!a.r.ok)return app.insertAdjacentHTML("afterbegin",note(a.d.message,"bad"));sec=a.d.secret;uri=a.d.uri;log("Mock TOTP test value:",a.d.verificationCode);step(2);app.innerHTML="<h2>Your setup is ready</h2>"+note(a.d.message)+"<p>Scan this QR code. If scanning is difficult, copy the secret below.</p><div id=qr class=qr></div><div class=secret>"+esc(sec)+"</div><div class=row><button class=secondary id=cp>Copy secret</button><button class=secondary id=next>I added it to my app</button></div><details><summary>Show full setup link</summary><div class=secret>"+esc(uri)+"</div></details><div id=msg class=hint></div>"+help();qr(uri);cp.onclick=()=>copy(sec,"Authenticator secret");next.onclick=verify}
function verify(){step(3);app.innerHTML="<h2>Check your app</h2><p>Enter the six numbers shown in your authenticator app.</p><label>Six-digit code</label><input id=o inputmode=numeric autocomplete=one-time-code maxlength=6 placeholder=123456><p class=hint>Example: 123456. You have plenty of time.</p><button class=primary id=v>Verify code</button>"+help();v.onclick=async()=>{let a=await api("/api/verify-otp",{otp:o.value.trim()});if(!a.r.ok)return app.insertAdjacentHTML("afterbegin",note(a.d.message,"bad"));codes=a.d.codes;log("Mock recovery codes:",codes);save("Your authenticator is now connected.")}}
function save(x){step(4);app.innerHTML="<h2>Save your recovery codes</h2>"+note(x)+"<p>Store these somewhere safe. Each code works once.</p><div class=codes>"+codes.map(c=>"<div class=code>"+esc(c)+"</div>").join("")+"</div><button class=primary id=f>I saved my codes</button>"+help();f.onclick=()=>account("Your recovery codes are saved.")}
function account(x){step(4);app.innerHTML="<h2>Security setup</h2>"+note(x)+"<p>Your authenticator is active.</p><button class=primary id=r>Replace authenticator</button><button class=secondary id=g>Generate new recovery codes</button><button class=secondary id=l>Sign out</button>"+help();r.onclick=async()=>{let a=await api("/api/begin-reenrolment");a.r.ok?setup("Replacement started. Your current authenticator remains active until checked."):alert(a.d.message)};g.onclick=async()=>{let a=await api("/api/regenerate-backup-codes");if(a.r.ok){codes=a.d.codes;log("Mock recovery codes:",codes);save("New recovery codes replaced the old ones.")}};l.onclick=async()=>{await api("/api/logout");csrf="";signin("You have signed out safely.")}}
signin();
</script></body></html>`; }

async function handle(r: Request): Promise<Response> {
  const u = new URL(r.url);
  if (u.protocol !== "https:" || !trusted(u.hostname)) return new Response("Not found", { status: 404, headers: headers(r) });
  if (r.method === "GET" && u.pathname === "/") { const n = token(18), h = headers(r, n); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page(n), { headers: h }); }
  if (r.method === "POST" && u.pathname === "/api/signin") {
    if (!originOK(r)) return json(r, { ok: false, message: "Please use the secure sign-in page." }, 403);
    const d = await body(r), email = typeof d?.email === "string" ? d.email.toLowerCase().trim() : "", p = d?.password;
    const a = [...accounts.values()].find(x => x.email === email), match = same(sha256(typeof p === "string" ? p : ""), a ? a.passwordHash : dummy);
    if (!a || !match || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof p !== "string" || p.length < 8) return json(r, { ok: false, message: "Sign-in could not be completed. Check your email and password, then try again." }, 401);
    for (const [id, s] of sessions) if (s.userId === a.id) sessions.delete(id);
    const id = token(), s = { userId: a.id, csrf: token(24), createdAt: Date.now(), lastSeenAt: Date.now() }; sessions.set(id, s);
    return json(r, { ok: true, csrf: s.csrf, mfaEnabled: a.mfaEnabled }, 200, { "Set-Cookie": cookie(id) });
  }
  const o = owner(r); if (!o) return json(r, { ok: false, message: "Please sign in again to continue." }, 401);
  if (r.method !== "POST" || !csrf(r, o.s)) return json(r, { ok: false, message: "Please refresh the secure page and try again." }, 403);
  const a = o.a;
  if (u.pathname === "/api/logout") { sessions.delete(o.id); return json(r, { ok: true }, 200, { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" }); }
  if (u.pathname === "/api/begin-reenrolment") { if (!a.mfaEnabled) return json(r, { ok: false, message: "Finish setup first." }, 400); a.replacing = true; return json(r, { ok: true }); }
  if (u.pathname === "/api/provision") {
    if (a.mfaEnabled && !a.replacing) return json(r, { ok: false, message: "Choose Replace authenticator first." }, 400);
    const s = secret(); a.pending = await encrypt(s); a.pendingUsed = [];
    const uri = "otpauth://totp/" + encodeURIComponent("Northstar Bank:" + a.email) + "?secret=" + s + "&issuer=Northstar%20Bank&algorithm=SHA1&digits=6&period=30";
    return json(r, { ok: true, secret: s, uri, verificationCode: await totp(s), message: "Authenticator setup is ready." });
  }
  if (u.pathname === "/api/verify-otp") {
    const d = await body(r), now = Date.now(); if (!validOtp(d?.otp)) return json(r, { ok: false, message: "Enter exactly six numbers, for example 123456." }, 400);
    if (a.otpLocked > now) return json(r, { ok: false, message: "Too many attempts. Please wait a few minutes." }, 429);
    if (!a.pending) return json(r, { ok: false, message: "Request a new setup and try again." }, 400);
    const s = await decrypt(a.pending), base = Math.floor(now / 30_000); let hit = -1;
    for (let c = base - 1; c <= base + 1; c++) if (c >= 0 && !a.pendingUsed.includes(c) && same(await totp(s, c), d.otp)) { hit = c; break; }
    if (hit < 0) { if (++a.otpFailures >= MAX_FAILURES) a.otpLocked = now + LOCKOUT; return json(r, { ok: false, message: "That code did not match, was used, or is no longer current. Try again." }, 400); }
    a.pendingUsed.push(hit); a.active = a.pending; a.pending = null; a.mfaEnabled = true; a.replacing = false; a.otpFailures = 0;
    const c = recovery(); a.backup = await Promise.all(c.map(x => hmac(x, recoveryKey))); return json(r, { ok: true, codes: c });
  }
  if (u.pathname === "/api/regenerate-backup-codes") {
    if (!a.mfaEnabled) return json(r, { ok: false, message: "Finish setup first." }, 400);
    const c = recovery(); a.backup = await Promise.all(c.map(x => hmac(x, recoveryKey))); return json(r, { ok: true, codes: c });
  }
  return new Response("Not found", { status: 404, headers: headers(r) });
}
Bun.serve({
  hostname: "localhost", port: Number(Bun.env.PORT || 3000),
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(r) { try { return await handle(r); } catch { return new Response("Something went wrong. Please try again.", { status: 500, headers: headers(r) }); } }
});
console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
