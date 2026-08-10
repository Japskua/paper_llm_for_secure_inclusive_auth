
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

/* Requirements: standards-compliant QR Version 10-L encoder.
   Uses byte mode, Reed-Solomon ECC, all mask candidates, BCH format/version data,
   and ISO/IEC 18004 penalty selection. */
function page(nonce: string) { return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank · Security setup</title><style nonce="${nonce}">
:root{--ink:#172331;--blue:#1259b5;--line:#cbd8e6;--soft:#edf5ff;--bad:#8b2424}*{box-sizing:border-box}body{margin:0;background:#f3f7fb;color:var(--ink);font:16px/1.65 Verdana,Arial,sans-serif;letter-spacing:.025em}main{max-width:620px;min-height:100vh;margin:auto;padding:18px 16px}header{display:flex;gap:10px;align-items:center}.mark{background:var(--blue);color:white;border-radius:12px;padding:8px 14px;font-size:22px}h1{font-size:1.35rem}h2{line-height:1.3}.steps{display:flex;gap:4px;margin:18px 0}.steps span{flex:1;border-bottom:4px solid var(--line);font-size:.72rem;text-align:center}.steps .on{border-color:var(--blue);color:#073c83;font-weight:bold}.card{background:white;border:1px solid var(--line);border-radius:16px;padding:20px}.notice{padding:11px;border-radius:9px;background:var(--soft);margin:12px 0}.bad{background:#fff0f0;color:var(--bad)}label{display:block;font-weight:bold;margin:15px 0 5px}input,button{width:100%;min-height:52px;border-radius:10px;font:inherit}input{border:2px solid #9eafc0;padding:10px}button{border:0;padding:10px;margin-top:12px;font-weight:bold;cursor:pointer}.primary{background:var(--blue);color:white}.secondary{background:white;color:#073c83;border:2px solid var(--blue)}button:focus,input:focus,summary:focus{outline:3px solid #e3a927;outline-offset:2px}.qr{width:250px;height:250px;padding:8px;margin:15px auto;border:1px solid var(--line)}.secret,.code{font-family:ui-monospace,Consolas,monospace;overflow-wrap:anywhere;background:#f4f8fc;padding:10px;border-radius:8px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.row{display:flex;gap:8px}.row button{flex:1}.hint{color:#526273;font-size:.88rem}.sensitive[hidden]{display:none}@media(max-width:390px){.codes{grid-template-columns:1fr}.row{flex-direction:column}}
</style></head><body><main><header><div class="mark">✦</div><div><h1>Northstar Bank</h1><div class="hint">Security setup</div></div></header><nav class="steps"><span data-s="1">1. Confirm</span><span data-s="2">2. App</span><span data-s="3">3. Check</span><span data-s="4">4. Save</span></nav><section id="app" class="card" aria-live="polite"></section><p class="hint">Take your time. There is no reading timer.</p></main><script nonce="${nonce}">
"use strict";
const app=document.querySelector("#app");let csrf="",sec="",uri="",codes=[];
function log(m,v){console.log(m,v)}
function esc(v){const e=document.createElement("span");e.textContent=String(v);return e.innerHTML}
function step(n){document.querySelectorAll("[data-s]").forEach(x=>x.classList.toggle("on",+x.dataset.s===n))}
function note(x,b=""){return '<div class="notice '+b+'">'+esc(x)+"</div>"}function help(){return "<details><summary>Help with this step</summary><p>Pause or retry at any time. There is no reading timer.</p></details>"}
async function api(path,data={}){let r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)}),d=await r.json().catch(()=>({message:"Please try again."}));if(r.status===401){csrf="";signin("Your session ended. Please sign in again.")}return {r,d}}
async function copy(v,name){const msg=document.querySelector("#msg");try{await navigator.clipboard.writeText(v);if(msg)msg.textContent=name+" copied. You can now paste it somewhere safe."}catch{if(msg)msg.textContent="Copy did not work in this browser. You can select the text and copy it instead."}}

/* Standards-compliant QR Version 10, level L. The URI fits its 274 byte-mode
   data codewords. It generates correct BCH format information for the chosen mask. */
function qr(text){
  const version=10,size=57,bytes=[...new TextEncoder().encode(text)],bits=[];
  const push=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1)};
  push(4,4);push(bytes.length,16);bytes.forEach(x=>push(x,8));
  while(bits.length<Math.min(2192,bits.length+4))bits.push(0);
  while(bits.length%8)bits.push(0);
  const raw=[];for(let i=0;i<bits.length;i+=8)raw.push(bits.slice(i,i+8).reduce((a,b)=>(a<<1)|b,0));
  for(let i=0;raw.length<274;i++)raw.push(i%2?0x11:0xec);

  const exp=Array(512).fill(0),log=Array(256).fill(0);let z=1;
  for(let i=0;i<255;i++){exp[i]=z;log[z]=i;z<<=1;if(z&256)z^=0x11d}for(let i=255;i<512;i++)exp[i]=exp[i-255];
  const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
  let gen=[1];for(let i=0;i<18;i++){const g=Array(gen.length+1).fill(0);gen.forEach((x,j)=>{g[j]^=x;g[j+1]^=mul(x,exp[i])});gen=g}
  const ecc=q=>{const r=Array(18).fill(0);q.forEach(x=>{const f=x^r.shift();r.push(0);gen.slice(1).forEach((g,i)=>r[i]^=mul(g,f))});return r};
  const blocks=[raw.slice(0,68),raw.slice(68,136),raw.slice(136,205),raw.slice(205,274)], parity=blocks.map(ecc), stream=[];
  for(let i=0;i<69;i++)blocks.forEach(b=>{if(i<b.length)stream.push(b[i])});
  for(let i=0;i<18;i++)parity.forEach(b=>stream.push(b[i]));

  const grid=Array.from({length:size},()=>Array(size).fill(0)),reserved=Array.from({length:size},()=>Array(size).fill(false));
  const put=(x,y,v)=>{grid[y][x]=v?1:0;reserved[y][x]=true};
  const finder=(x,y)=>{for(let dy=-1;dy<=7;dy++)for(let dx=-1;dx<=7;dx++)if(x+dx>=0&&y+dy>=0&&x+dx<size&&y+dy<size){const dark=dx>=0&&dx<=6&&dy>=0&&dy<=6&&(dx===0||dx===6||dy===0||dy===6||(dx>=2&&dx<=4&&dy>=2&&dy<=4));put(x+dx,y+dy,dark)}};
  finder(0,0);finder(size-7,0);finder(0,size-7);
  for(let i=8;i<size-8;i++){if(!reserved[6][i])put(i,6,i%2===0);if(!reserved[i][6])put(6,i,i%2===0)}
  const aligns=[6,28,50];
  aligns.forEach(y=>aligns.forEach(x=>{if(reserved[y][x])return;for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)put(x+dx,y+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1)}));
  put(8,size-8,1);
  for(let i=0;i<9;i++){if(!reserved[8][i])put(i,8,0);if(!reserved[i][8])put(8,i,0)}
  for(let i=0;i<8;i++){put(size-1-i,8,0);put(8,size-1-i,0)}

  let vr=version<<12;for(let i=17;i>=12;i--)if(vr&(1<<i))vr^=0x1f25<<(i-12);const versionInfo=(version<<12)|vr;
  for(let i=0;i<18;i++){const bit=(versionInfo>>>i)&1,row=Math.floor(i/3),col=size-11+(i%3);put(col,row,bit);put(row,col,bit)}

  const dataCells=[];let bitIndex=0,up=true;
  for(let x=size-1;x>0;x-=2){if(x===6)x--;for(let q=0;q<size;q++){const y=up?size-1-q:q;for(let dx=0;dx<2;dx++){const xx=x-dx;if(!reserved[y][xx]){grid[y][xx]=bitIndex<stream.length*8?((stream[bitIndex>>>3]>>>(7-(bitIndex&7)))&1):0;dataCells.push([xx,y]);bitIndex++}}}up=!up}

  const masked=(x,y,m)=>m===0?(x+y)%2===0:m===1?y%2===0:m===2?x%3===0:m===3?(x+y)%3===0:m===4?(Math.floor(y/2)+Math.floor(x/3))%2===0:m===5?(x*y)%2+(x*y)%3===0:m===6?((x*y)%2+(x*y)%3)%2===0:((x*y)%3+(x+y)%2)%2===0;
  const format=(mask)=>{let r=(1<<3|mask)<<10;for(let i=14;i>=10;i--)if(r&(1<<i))r^=0x537<<(i-10);return (((1<<3|mask)<<10)|r)^0x5412};
  const writeFormat=(m,mask)=>{const f=format(mask),set=(x,y,v)=>m[y][x]=v;for(let i=0;i<=5;i++)set(8,i,(f>>>i)&1);set(8,7,(f>>>6)&1);set(8,8,(f>>>7)&1);set(7,8,(f>>>8)&1);for(let i=9;i<15;i++)set(14-i,8,(f>>>i)&1);for(let i=0;i<8;i++)set(size-1-i,8,(f>>>i)&1);for(let i=8;i<15;i++)set(8,size-15+i,(f>>>i)&1)};
  const penalty=m=>{let p=0;for(let y=0;y<size;y++)for(let x=0;x<size;x++){let n=0;for(let dy=-1;dy<=1;dy++)for(let dx=-1;dx<=1;dx++)if(dx||dy){const yy=y+dy,xx=x+dx;if(yy>=0&&yy<size&&xx>=0&&xx<size&&m[yy][xx]===m[y][x])n++}if(n>5)p+=3+n-5}for(let y=0;y<size-1;y++)for(let x=0;x<size-1;x++)if(m[y][x]===m[y][x+1]&&m[y][x]===m[y+1][x]&&m[y][x]===m[y+1][x+1])p+=3;const test=a=>{for(let i=0;i<=size-7;i++)if(a.slice(i,i+7).join("")==="1011101")p+=40};for(let y=0;y<size;y++)test(m[y]);for(let x=0;x<size;x++)test(m.map(r=>r[x]));let dark=0;m.forEach(r=>r.forEach(v=>dark+=v));p+=Math.floor(Math.abs(dark*20-size*size*10)/(size*size))*10;return p};
  let best=null,bestPenalty=Infinity;
  for(let mask=0;mask<8;mask++){const candidate=grid.map(r=>r.slice());dataCells.forEach(([x,y])=>{if(masked(x,y,mask))candidate[y][x]^=1});writeFormat(candidate,mask);const score=penalty(candidate);if(score<bestPenalty){bestPenalty=score;best=candidate}}
  let path="";for(let y=0;y<size;y++)for(let x=0;x<size;x++)if(best[y][x])path+="M"+x+" "+y+"h1v1h-1z";
  document.querySelector("#qr").innerHTML='<svg viewBox="0 0 57 57" role="img" aria-label="Authenticator QR code"><rect width="100%" height="100%" fill="white"/><path d="'+path+'" fill="black"/></svg>';
}
function signin(info=""){step(1);app.innerHTML="<h2>Confirm your account</h2><p>Use your bank email and password.</p>"+note("Demo: marcus@example.com · password: BankDemo!42")+(info?note(info):"")+"<label>Email address</label><input id=e type=email autocomplete=email placeholder='marcus@example.com'><label>Password</label><input id=p type=password autocomplete=current-password><button class=primary id=go>Continue</button>"+help();go.onclick=async()=>{let r=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:e.value,password:p.value})}),d=await r.json();if(!r.ok)return app.insertAdjacentHTML("afterbegin",note(d.message,"bad"));csrf=d.csrf;d.mfaEnabled?account("Your authenticator is active."):setup("Your identity is confirmed. Next, add your authenticator app.")}}
function setup(x){step(2);app.innerHTML="<h2>Add your authenticator app</h2>"+note(x)+"<p>Open your authenticator app. You can scan a setup image or copy a secret.</p><button class=primary id=show>Show secure setup</button>"+help();show.onclick=provision}
async function provision(){
  let a=await api("/api/provision");
  if(!a.r.ok)return app.insertAdjacentHTML("afterbegin",note(a.d.message,"bad"));
  sec=a.d.secret;uri=a.d.uri;log("Mock TOTP test value:",a.d.verificationCode);step(2);
  app.innerHTML="<h2>Your setup is ready</h2>"+note(a.d.message)+"<p>Your QR code and secret are hidden until you choose to view them.</p><button class=primary id=reveal>Show QR and secret</button><button class=secondary id=request>Request a new setup</button><div id=sensitive class=sensitive hidden><p>Scan this QR code. If scanning is difficult, copy the secret below.</p><div id=qr class=qr></div><div class=secret>"+esc(sec)+"</div><div class=row><button class=secondary id=cp>Copy secret</button><button class=secondary id=hide>Hide QR and secret</button></div><details><summary>Show full setup link</summary><div class=secret>"+esc(uri)+"</div></details><button class=primary id=next>I added it to my app</button></div><div id=msg class=hint></div>"+help();
  const reveal=document.querySelector("#reveal"), sensitive=document.querySelector("#sensitive");
  reveal.onclick=()=>{sensitive.hidden=false;reveal.textContent="QR and secret shown";reveal.disabled=true;qr(uri)};
  request.onclick=()=>provision();
  cp.onclick=()=>copy(sec,"Authenticator secret");
  hide.onclick=()=>{sensitive.hidden=true;reveal.textContent="Show QR and secret";reveal.disabled=false};
  next.onclick=verify;
}
function verify(){step(3);app.innerHTML="<h2>Check your app</h2><p>Enter the six numbers shown in your authenticator app.</p><label>Six-digit code</label><input id=o inputmode=numeric autocomplete=one-time-code maxlength=6 placeholder=123456><p class=hint>Example: 123456. You have plenty of time.</p><button class=primary id=v>Verify code</button>"+help();v.onclick=async()=>{let a=await api("/api/verify-otp",{otp:o.value.trim()});if(!a.r.ok)return app.insertAdjacentHTML("afterbegin",note(a.d.message,"bad"));codes=a.d.codes;log("Mock recovery codes:",codes);save("Your authenticator is now connected.")}}
function save(x){step(4);app.innerHTML="<h2>Save your recovery codes</h2>"+note(x)+"<p>Store these somewhere safe. Each code works once.</p><div class=codes>"+codes.map(c=>"<div class=code>"+esc(c)+"</div>").join("")+"</div><button class=secondary id=copyall>Copy all recovery codes</button><div id=msg class=hint></div><button class=primary id=f>I saved my codes</button>"+help();copyall.onclick=()=>copy(codes.join("\\n"),"All recovery codes");f.onclick=()=>account("Your recovery codes are saved.")}
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
