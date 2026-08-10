
/*
 MFA Enrolment System — single-file Bun HTTPS server and mobile SPA.
 Run with: bun app.ts
 TLS certificates: certs/cert.pem and certs/key.pem
*/
const enc = new TextEncoder();
const sessions = new Map<string, any>();
const secret = "JBSWY3DPEHPK3PXP";
const account = { id: "marcus-account-001", email: "marcus@example.com", password: "BankDemo!42", pending: false, enabled: false, csrf: "" };

function random(n = 24) {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString("base64url");
}
function cookies(r: Request) {
  const out: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return out;
}
function trusted(r: Request) {
  const u = new URL(r.url);
  return u.protocol === "https:" && ["localhost", "127.0.0.1", "::1"].includes(u.hostname);
}
function headers(r: Request, nonce = "") {
  return new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store"
  });
}
function json(r: Request, body: any, status = 200, extra: Record<string, string> = {}) {
  const h = headers(r);
  h.set("Content-Type", "application/json; charset=utf-8");
  for (const [k, v] of Object.entries(extra)) h.set(k, v);
  return new Response(JSON.stringify(body), { status, headers: h });
}
function owner(r: Request) {
  const id = cookies(r).mfa_session;
  return id ? sessions.get(id) : null;
}
async function body(r: Request) {
  try { const x = await r.json(); return x && typeof x === "object" ? x : {}; } catch { return {}; }
}
function csrfOK(r: Request, s: any) {
  const u = new URL(r.url);
  return r.headers.get("origin") === u.origin && r.headers.get("x-csrf-token") === s.csrf;
}

/* Requirement 1: session ownership and CSRF checks protect every MFA state change. */
async function handle(r: Request): Promise<Response> {
  const u = new URL(r.url);
  if (!trusted(r)) return new Response("Not found", { status: 404, headers: headers(r) });

  if (r.method === "GET" && u.pathname === "/") {
    const nonce = random(18), h = headers(r, nonce);
    h.set("Content-Type", "text/html; charset=utf-8");
    return new Response(page(nonce), { headers: h });
  }

  if (r.method === "POST" && u.pathname === "/api/signin") {
    const d = await body(r);
    if (d.email !== account.email || d.password !== account.password)
      return json(r, { ok: false, message: "Sign-in could not be completed. Check your email and password, then try again." }, 401);
    const id = random(), csrf = random();
    sessions.set(id, { userId: account.id, csrf });
    return json(r, { ok: true, csrf, enabled: account.enabled }, 200, {
      "Set-Cookie": `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`
    });
  }

  const s = owner(r);
  if (!s || s.userId !== account.id) return json(r, { ok: false, message: "Please sign in again to continue." }, 401);
  if (r.method !== "POST" || !csrfOK(r, s)) return json(r, { ok: false, message: "Please refresh the secure page and try again." }, 403);

  if (u.pathname === "/api/logout") {
    sessions.delete(cookies(r).mfa_session);
    return json(r, { ok: true }, 200, { "Set-Cookie": "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0" });
  }
  if (u.pathname === "/api/provision") {
    account.pending = true;
    const uri = "otpauth://totp/" + encodeURIComponent("Northstar Bank:" + account.email) +
      "?secret=" + secret + "&issuer=Northstar%20Bank&algorithm=SHA1&digits=6&period=30";
    return json(r, { ok: true, secret, uri, message: "Authenticator setup is ready.", verificationCode: "282760" });
  }
  if (u.pathname === "/api/verify-otp") {
    const d = await body(r);
    if (!account.pending || !/^\d{6}$/.test(d.otp))
      return json(r, { ok: false, message: "Enter exactly six numbers, for example 123456." }, 400);
    account.pending = false; account.enabled = true;
    const codes = ["A1B2C-3D4E5","F6G7H-8J9K0","LMN1P-2Q3R4","S5T6U-7V8W9","X0Y1Z-2A3B4","C5D6E-7F8G9","H1J2K-3L4M5","N6P7Q-8R9S0","T1U2V-3W4X5","Y6Z7A-8B9C0"];
    return json(r, { ok: true, codes });
  }
  return new Response("Not found", { status: 404, headers: headers(r) });
}

function page(nonce: string) { return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Northstar Bank · Security setup</title>
<style nonce="${nonce}">
body{margin:0;background:#f3f7fb;color:#172331;font:16px/1.7 Verdana,Arial,sans-serif;letter-spacing:.025em}main{max-width:620px;margin:auto;padding:18px}.card,.logs{background:#fff;border:1px solid #cbd8e6;border-radius:16px;padding:20px}.logs{margin-top:16px}.notice{padding:11px;background:#edf5ff;border-radius:9px}input,button{width:100%;min-height:52px;margin:8px 0;border-radius:10px;font:inherit}input{border:2px solid #9eafc0;padding:9px}button{border:0;font-weight:bold;background:#1259b5;color:#fff}.secondary{background:#fff;color:#1259b5;border:2px solid #1259b5}.qr{width:280px;height:280px;display:block;margin:15px auto;image-rendering:pixelated}.secret,#logs{font-family:ui-monospace,monospace;overflow-wrap:anywhere;background:#f4f8fc;padding:10px;border-radius:8px}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}label{font-weight:bold;display:block}button:focus,input:focus{outline:3px solid #e3a927}
</style></head><body><main><h1>✦ Northstar Bank</h1><p>Security setup · Take your time. There is no reading timer.</p><section id="app" class="card" aria-live="polite"></section><aside class="logs"><h2>Logs</h2><div id="logs">Ready.</div></aside></main>
<script nonce="${nonce}">
"use strict";
let csrf="", setupURI="", setupSecret="";
const app=document.querySelector("#app"), logs=document.querySelector("#logs");
function log(x,v){console.log(x,v||"");logs.textContent+="\\n"+x+(v?" "+v:"")}
function esc(x){const e=document.createElement("span");e.textContent=x;return e.innerHTML}
async function api(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});return {r,d:await r.json()}}
function signin(msg=""){app.innerHTML="<h2>Confirm your account</h2>"+(msg?"<p class=notice>"+esc(msg)+"</p>":"")+"<label>Email address</label><input id=e autocomplete=email placeholder=name@example.com><label>Password</label><input id=p type=password autocomplete=current-password><button id=go>Continue</button>";go.onclick=async()=>{const x=await fetch("/api/signin",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:e.value,password:p.value})});const d=await x.json();if(!x.ok)return signin(d.message);csrf=d.csrf;log("Sign-in simulation completed.");d.enabled?done():start()}}
function start(){app.innerHTML="<h2>Add your authenticator app</h2><p>Scan a setup image, or copy the secret instead.</p><button id=show>Show secure setup</button>";show.onclick=provision}
async function provision(){const x=await api("/api/provision");if(!x.r.ok)return start();setupURI=x.d.uri;setupSecret=x.d.secret;log("Authenticator provisioning simulation completed.");log("Mock TOTP test value:",x.d.verificationCode);app.innerHTML="<h2>Your setup is ready</h2><p class=notice>Scan this image with your authenticator app.</p><canvas id=q class=qr></canvas><div class=secret>"+esc(setupSecret)+"</div><button class=secondary id=copy>Copy secret</button><button id=next>I added it to my app</button>";renderQR(q,setupURI);copy.onclick=()=>navigator.clipboard.writeText(setupSecret);next.onclick=verify}
function verify(){app.innerHTML="<h2>Check your app</h2><p>Enter the six numbers shown in your app.</p><input id=o inputmode=numeric autocomplete=one-time-code maxlength=6 placeholder=123456><button id=v>Verify code</button>";v.onclick=async()=>{const x=await api("/api/verify-otp",{otp:o.value});if(!x.r.ok){app.insertAdjacentHTML("afterbegin","<p class=notice>"+esc(x.d.message)+"</p>");return}log("Authenticator verification simulation succeeded.");save(x.d.codes)}}
function save(c){app.innerHTML="<h2>Save your recovery codes</h2><p class=notice>Your authenticator is now connected.</p><div class=codes>"+c.map(x=>"<div class=secret>"+esc(x)+"</div>").join("")+"</div><button id=finish>I saved my codes</button>";finish.onclick=done}
function done(){app.innerHTML="<h2>Security setup complete</h2><p class=notice>Your authenticator is active.</p><button id=out>Sign out</button>";out.onclick=async()=>{await api("/api/logout");csrf="";log("Sign-out simulation completed.");signin("You have signed out safely.")}}

/* QR requirement: Version 8-L is 242 total words: 194 data words in TWO 97-word blocks, with 24 EC words each. */
function qrMatrix(text){
 const N=49,DATA=194,EC=24,BLOCKS=2, m=Array.from({length:N},()=>Array(N).fill(false)),f=Array.from({length:N},()=>Array(N).fill(false));
 const put=(x,y,v)=>{if(x>=0&&y>=0&&x<N&&y<N){m[y][x]=v;f[y][x]=true}};
 function find(x,y){for(let Y=-1;Y<8;Y++)for(let X=-1;X<8;X++)put(x+X,y+Y,X>=0&&X<7&&Y>=0&&Y<7&&(X==0||X==6||Y==0||Y==6||(X>=2&&X<=4&&Y>=2&&Y<=4)))}
 function align(x,y){for(let Y=-2;Y<=2;Y++)for(let X=-2;X<=2;X++)put(x+X,y+Y,Math.max(Math.abs(X),Math.abs(Y))!=1)}
 find(0,0);find(42,0);find(0,42);[[24,24],[42,24],[24,42],[42,42]].forEach(p=>align(...p));for(let i=8;i<41;i++){put(i,6,i%2==0);put(6,i,i%2==0)}put(8,41,true);
 const bch=(v,p)=>{let x=v;while(x.toString(2).length>=p.toString(2).length)x^=p<<(x.toString(2).length-p.toString(2).length);return x},vb=(8<<12)|bch(8<<12,0x1f25);for(let i=0;i<18;i++){let z=!!(vb>>i&1);put(38+i%3,Math.floor(i/3),z);put(Math.floor(i/3),38+i%3,z)}
 const bytes=[...new TextEncoder().encode(text)];if(bytes.length>DATA-2)throw Error("Setup link is too long.");let bits=[0,1,0,0];for(let i=7;i>=0;i--)bits.push(bytes.length>>i&1);bytes.forEach(b=>{for(let i=7;i>=0;i--)bits.push(b>>i&1)});while(bits.length%8)bits.push(0);let raw=[];for(let i=0;i<bits.length;i+=8)raw.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));for(let i=raw.length;i<DATA;i++)raw.push((i-raw.length)%2?0x11:0xec);
 const ex=[],lg=Array(256).fill(0);let z=1;for(let i=0;i<255;i++){ex[i]=z;lg[z]=i;z<<=1;if(z&256)z^=285}for(let i=255;i<512;i++)ex[i]=ex[i-255];const mul=(a,b)=>a&&b?ex[lg[a]+lg[b]]:0;let g=[1];for(let i=0;i<EC;i++){g.push(0);for(let j=g.length-1;j>0;j--)g[j]=g[j-1]^mul(g[j],ex[i]);g[0]=mul(g[0],ex[i])}const ecc=a=>{let r=Array(EC).fill(0);a.forEach(v=>{let q=v^r.shift();r.push(0);for(let j=0;j<EC;j++)r[j]^=mul(g[j+1],q)});return r};
 const chunks=[raw.slice(0,97),raw.slice(97,194)],par=chunks.map(ecc),stream=[];for(let i=0;i<97;i++)for(let b=0;b<BLOCKS;b++)stream.push(chunks[b][i]);for(let i=0;i<EC;i++)for(let b=0;b<BLOCKS;b++)stream.push(par[b][i]);
 let bi=0,up=true;for(let R=48;R>0;R-=2){if(R==6)R--;for(let q=0;q<N;q++){let y=up?48-q:q;for(let d=0;d<2;d++){let x=R-d;if(!f[y][x])m[y][x]=bi<stream.length*8?!!(stream[bi>>3]>>(7-bi++%8)&1):false}}up=!up}
 const fmt=mask=>{let q=(((1<<3)|mask)<<10);q=(q|bch(q,0x537))^0x5412;for(let i=0;i<=5;i++)m[i][8]=!!(q>>i&1);m[7][8]=!!(q>>6&1);m[8][8]=!!(q>>7&1);m[8][7]=!!(q>>8&1);for(let i=9;i<15;i++)m[8][14-i]=!!(q>>i&1);for(let i=0;i<8;i++)m[8][48-i]=!!(q>>i&1);for(let i=8;i<15;i++)m[34+i][8]=!!(q>>i&1)};
 for(let y=0;y<N;y++)for(let x=0;x<N;x++)if(!f[y][x]&&(x+y)%2==0)m[y][x]=!m[y][x];fmt(0);return m
}
function renderQR(c,t){const m=qrMatrix(t),s=5,q=4;c.width=c.height=(m.length+q*2)*s;const x=c.getContext("2d");x.fillStyle="#fff";x.fillRect(0,0,c.width,c.height);x.fillStyle="#000";m.forEach((r,y)=>r.forEach((v,z)=>v&&x.fillRect((z+q)*s,(y+q)*s,s,s)))}
signin();
</script></body></html>`; }

Bun.serve({
  hostname: "localhost",
  port: Number(Bun.env.PORT || 3000),
  tls: { cert: Bun.file("certs/cert.pem"), key: Bun.file("certs/key.pem") },
  async fetch(r) { try { return await handle(r); } catch { return new Response("Something went wrong. Please try again.", { status: 500, headers: headers(r) }); } }
});
console.log("MFA HTTPS server running at https://localhost:" + (Bun.env.PORT || 3000));
