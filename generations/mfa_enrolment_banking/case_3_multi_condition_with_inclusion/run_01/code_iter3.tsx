
import { existsSync, readFileSync } from "node:fs";
import { createCipheriv, createDecipheriv, createHmac, pbkdf2Sync, randomBytes, randomInt, timingSafeEqual } from "node:crypto";

/* Requirements §§1–5: server-side in-memory academic MFA demonstration. */
const PORT = Number(process.env.PORT || 3000);
const SESSION = "mfa_session";
const IDLE = 30 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CHALLENGE = 10 * 60_000, LOCK = 10 * 60_000;
const PERIOD = 30_000, RECOVERY_EXPIRY = 365 * 24 * 60 * 60_000;
const key = randomBytes(32), pepper = randomBytes(32);

type Protected = { iv: Buffer; tag: Buffer; data: Buffer };
type Backup = { salt: Buffer; hash: Buffer; used: boolean; expires: number };
type Account = { id: string; email: string; mfa: boolean; secret?: Protected; backups: Backup[]; failures: number; locked?: number };
type Enrollment = { secret: Protected; failures: number; locked?: number; used: Set<number> };
type Session = {
  id: string; csrf: string; created: number; seen: number; phase: "preauth" | "auth"; user?: string;
  email?: string; code?: string; codeExpires?: number; codeUsed?: boolean; failures: number; locked?: number; enrollment?: Enrollment;
};

const sessions = new Map<string, Session>(), accounts = new Map<string, Account>(), accountIds = new Map<string, Account>();
const token = (n = 32) => randomBytes(n).toString("base64url");
const enc = (value: string): Protected => {
  const iv = randomBytes(12), c = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([c.update(value, "utf8"), c.final()]);
  return { iv, data, tag: c.getAuthTag() };
};
const dec = (v: Protected) => {
  const c = createDecipheriv("aes-256-gcm", key, v.iv); c.setAuthTag(v.tag);
  return Buffer.concat([c.update(v.data), c.final()]).toString("utf8");
};
const hash = (v: string, salt = randomBytes(16)) => ({ salt, hash: pbkdf2Sync(v, Buffer.concat([salt, pepper]), 210000, 32, "sha256") });
const matches = (v: string, salt: Buffer, expected: Buffer) => {
  const got = pbkdf2Sync(v, Buffer.concat([salt, pepper]), 210000, 32, "sha256");
  return got.length === expected.length && timingSafeEqual(got, expected);
};
function cookies(r: Request) {
  const result: Record<string, string> = {};
  for (const p of (r.headers.get("cookie") || "").split(";")) {
    const i = p.indexOf("="); if (i > 0) result[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return result;
}
function newSession(phase: "preauth" | "auth" = "preauth", user?: string) {
  const now = Date.now(), s: Session = { id: token(), csrf: token(), created: now, seen: now, phase, user, failures: 0 };
  sessions.set(s.id, s); return s;
}
function session(r: Request) {
  const s = sessions.get(cookies(r)[SESSION]); if (!s) return;
  const now = Date.now();
  if (now - s.seen > IDLE || now - s.created > ABSOLUTE) { sessions.delete(s.id); return; }
  s.seen = now; return s;
}
function sessionCookie(s: Session) {
  return `${SESSION}=${s.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`;
}
const clearCookie = () => `${SESSION}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
function trusted(r: Request) {
  const origin = r.headers.get("origin"); if (!origin) return true;
  try { const u = new URL(origin); return u.protocol === "https:" && u.port === String(PORT) && ["localhost", "127.0.0.1", "::1"].includes(u.hostname); } catch { return false; }
}
function headers(r: Request, nonce?: string) {
  const h = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store",
    "Content-Security-Policy": nonce ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  });
  const origin = r.headers.get("origin");
  if (origin && trusted(r)) { h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); }
  return h;
}
function reply(r: Request, data: unknown, status = 200, cookie?: string) {
  const h = headers(r); h.set("Content-Type", "application/json; charset=utf-8"); if (cookie) h.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (r: Request, status: number, message: string) => reply(r, { ok: false, message }, status);
async function body(r: Request): Promise<Record<string, unknown> | undefined> {
  if (Number(r.headers.get("content-length") || 0) > 4096) return;
  try { const x = await r.json(); return x && typeof x === "object" && !Array.isArray(x) ? x as Record<string, unknown> : undefined; } catch { return; }
}
function csrf(r: Request, s: Session) {
  const v = r.headers.get("x-csrf-token");
  return trusted(r) && !!v && v.length === s.csrf.length && timingSafeEqual(Buffer.from(v), Buffer.from(s.csrf));
}
function owner(r: Request) {
  const s = session(r); if (!s || s.phase !== "auth" || !s.user) return;
  const a = accountIds.get(s.user); return a ? { s, a } : undefined;
}
function account(email: string) {
  let a = accounts.get(email);
  if (!a) { a = { id: token(18), email, mfa: false, backups: [], failures: 0 }; accounts.set(email, a); accountIds.set(a.id, a); }
  return a;
}
const identityCode = () => String(randomInt(1_000_000)).padStart(6, "0");
function secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, value = 0, out = "";
  for (const b of randomBytes(20)) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  return bits ? out + alphabet[(value << (5 - bits)) & 31] : out;
}
function decode32(s: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, value = 0; const out: number[] = [];
  for (const c of s.replace(/[=\s]/g, "")) { const x = alphabet.indexOf(c); if (x < 0) throw Error("bad secret"); value = (value << 5) | x; bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function otp(secretValue: string, step = Math.floor(Date.now() / PERIOD)) {
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step));
  const d = createHmac("sha1", decode32(secretValue)).update(counter).digest(), o = d[19] & 15;
  return String((((d[o] & 127) << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) % 1_000_000).padStart(6, "0");
}
function backup() {
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; let v = "";
  for (const b of randomBytes(12)) v += a[b % a.length];
  return `${v.slice(0, 4)}-${v.slice(4, 8)}-${v.slice(8)}`;
}
function newBackups(a: Account) {
  const plain = Array.from({ length: 8 }, backup);
  a.backups = plain.map(x => ({ ...hash(x), used: false, expires: Date.now() + RECOVERY_EXPIRY })); return plain;
}

function page(nonce: string) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Harbour Bank · MFA</title>
<style nonce="${nonce}">
:root{--ink:#17263c;--blue:#075cc7;--pale:#edf6ff;--line:#d5dfeb;--muted:#526278}*{box-sizing:border-box}body{margin:0;background:#f5f8fc;color:var(--ink);font:16px/1.65 Verdana,Arial,sans-serif;letter-spacing:.035em}main{max-width:560px;min-height:100vh;margin:auto;padding:22px 18px 32px;background:#fff}.brand{font-weight:bold;color:#064b9f}.steps{display:flex;gap:5px;margin:18px 0 24px}.steps i{height:8px;flex:1;border-radius:8px;background:#dbe3ed}.steps i.on{background:var(--blue)}h1{font-size:1.58rem;line-height:1.3}h2{font-size:1.16rem}p{color:var(--muted)}.hint,.notice,.error{padding:12px;border-radius:8px;margin:14px 0}.hint{background:var(--pale);border-left:4px solid var(--blue)}.notice{background:#eaf8f0;color:#105537}.error{background:#fff0e8;color:#843900}label{display:block;font-weight:bold;margin:15px 0 5px}input{width:100%;padding:13px;border:2px solid #9aaabd;border-radius:9px;font:inherit;letter-spacing:.09em}input:focus{outline:3px solid #a9d0ff;border-color:var(--blue)}button{border:0;border-radius:9px;padding:13px 16px;font:inherit;font-weight:bold;cursor:pointer;letter-spacing:.025em}.primary{display:block;width:100%;margin-top:18px;background:var(--blue);color:white}.secondary{margin:8px 6px 0 0;background:#e8f0fa;color:#17436d}.link{padding:8px 0;background:transparent;color:var(--blue);text-decoration:underline}.secret,.codes{font-family:ui-monospace,Consolas,monospace;letter-spacing:.09em;background:#f4f7fa;padding:12px;border-radius:8px;overflow-wrap:anywhere}.codes{list-style:none}.codes li{padding:7px;border-bottom:1px solid var(--line)}.qr{display:block;width:min(390px,100%);height:auto;margin:16px auto;image-rendering:pixelated}@media(max-width:370px){body{font-size:15px}main{padding:17px 14px}}
</style></head><body><main id="app" aria-live="polite">Loading…</main><script nonce="${nonce}">
(()=>{"use strict";const app=document.querySelector("#app"),S={csrf:"",view:"signin",email:"",code:"",mfa:false,secret:"",uri:"",otp:"",codes:[],notice:"",error:"",showQR:false,logs:[]};
const E=(tag,p={},...kids)=>{let n=document.createElement(tag);for(const[k,v]of Object.entries(p)){if(k==="text")n.textContent=v;else if(k==="class")n.className=v;else if(k.startsWith("on"))n.addEventListener(k.slice(2),v);else n.setAttribute(k,v)}kids.forEach(x=>n.append(x instanceof Node?x:document.createTextNode(x)));return n};
function log(x){console.log(x);S.logs.push(x)}async function api(path,method="GET",data){try{let r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":S.csrf},body:method==="GET"?undefined:JSON.stringify(data||{})}),j=await r.json();if(r.status===401)S.view="signin";return j}catch{return{ok:false,message:"Connection problem. Please try again."}}}
function head(r,n){r.append(E("div",{class:"brand",text:"⚓ Harbour Bank"}));let x=E("div",{class:"steps","aria-label":"Setup progress"});for(let i=1;i<5;i++)x.append(E("i",{class:i<=n?"on":""}));r.append(x)}
function status(r){if(S.error)r.append(E("div",{class:"error",role:"alert",text:S.error}));if(S.notice)r.append(E("div",{class:"notice",text:S.notice}))}
function help(r){r.append(E("button",{class:"link",type:"button",onClick:()=>{S.notice="Help: Take as long as you need. You can retry without penalty.";S.error="";render()},text:"? Need a little help"}))}
function field(r,label,attrs){let id="x"+Math.random().toString(36).slice(2),i=E("input",{id,...attrs});r.append(E("label",{for:id,text:label}),i);return i}
function primary(r,text,fn){r.append(E("button",{class:"primary",type:"button",onClick:fn,text}))}
function logs(r){if(S.logs.length)r.append(E("h2",{text:"Logs"}),E("div",{class:"hint",text:S.logs.join("\\n")}))}
function render(){app.replaceChildren();let r=E("div");app.append(r);({signin,identity,home,enrol,codes,recovery}[S.view]||signin)(r)}
function signin(r){head(r,1);r.append(E("h1",{text:"Sign in to set up MFA"}),E("p",{text:"We will send one short identity code. This demo does not use a real email."}));status(r);let i=field(r,"Email address",{type:"email",autocomplete:"email",inputmode:"email",placeholder:"marcus@example.com"});i.value=S.email;r.append(E("div",{class:"hint",text:"Example: marcus@example.com"}));primary(r,"Send identity code",async()=>{let email=i.value.trim();if(!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)){S.error="Enter an email in this format: name@example.com.";return render()}let x=await api("/api/signin/request","POST",{email});if(!x.ok){S.error=x.message;return render()}S.email=email;S.code=x.mockCode;log("Mock identity code delivered: "+x.mockCode);S.notice="A six-digit code is ready for this demo.";S.error="";S.view="identity";render()});help(r);logs(r)}
function identity(r){head(r,1);r.append(E("h1",{text:"Check your identity"}),E("p",{text:"Enter the six-digit code we sent."}));status(r);if(S.code)r.append(E("div",{class:"hint",text:"Demo test code: "+S.code}));let i=field(r,"Identity code",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});primary(r,"Check code",async()=>{let code=i.value.replace(/\\s/g,"");if(!/^\\d{6}$/.test(code)){S.error="Enter all 6 numbers, for example 123456.";return render()}let x=await api("/api/signin/verify","POST",{code});if(!x.ok){S.error=x.message;return render()}S.csrf=x.csrf;S.mfa=x.mfa;S.code="";S.notice="Identity checked. Next, set up your authenticator.";S.error="";S.view="home";render()});r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.view="signin";S.notice="You can request a new code.";render()},text:"Request another code"}));help(r);logs(r)}
function home(r){head(r,S.mfa?4:2);r.append(E("h1",{text:S.mfa?"MFA is set up":"Set up your authenticator"}),E("p",{text:S.mfa?"Your account has an extra sign-in check. Keep recovery codes somewhere safe.":"Use an authenticator app to get a short code when needed."}));status(r);if(!S.mfa){r.append(E("div",{class:"hint",text:"You can scan a QR code, or copy the setup secret instead."}));primary(r,"Set up authenticator",async()=>{let x=await api("/api/mfa/enroll","POST",{});if(!x.ok){S.error=x.message;return render()}S.secret=x.secret;S.uri=x.provisioningUri;S.otp=x.mockOtp;log("Mock authenticator setup secret: "+x.secret);log("Mock authenticator OTP for verification: "+x.mockOtp);S.notice="Setup secret ready. Choose the method that feels easiest.";S.error="";S.view="enrol";render()})}else{r.append(E("div",{class:"notice",text:"Authenticator confirmed. Your next step is to save recovery codes."}));primary(r,"View recovery codes",()=>{S.view="codes";S.notice="";render()});r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.view="recovery";render()},text:"Test a recovery code"}))}r.append(E("button",{class:"link",type:"button",onClick:logout,text:"Sign out"}));help(r);logs(r)}

/* QR requirement: standards-compliant Version 40-L byte QR. Its 2,956 byte capacity covers every permitted encoded email URI. */
const mul=(a,b)=>{let p=0;while(b){if(b&1)p^=a;a=a&128?(a<<1)^285:a<<1;b>>=1}return p};
function rs(data,n){let g=[1];for(let i=0;i<n;i++){let q=Array(g.length+1).fill(0),a=1;for(let z=0;z<i;z++)a=mul(a,2);g.forEach((v,j)=>{q[j]^=v;q[j+1]^=mul(v,a)});g=q}let out=Array(n).fill(0);data.forEach(d=>{let f=d^out.shift();out.push(0);for(let i=0;i<n;i++)out[i]^=mul(g[i+1],f)});return out}
function bch(v,g){let x=v;while(x.toString(2).length>=g.toString(2).length)x^=g<<(x.toString(2).length-g.toString(2).length);return x}
function matrix(text){const N=177,m=Array.from({length:N},()=>Array(N).fill(null)),put=(y,x,v)=>{if(y>=0&&x>=0&&y<N&&x<N)m[y][x]=v},finder=(y,x)=>{for(let j=-1;j<8;j++)for(let i=-1;i<8;i++)put(y+j,x+i,j>=0&&j<7&&i>=0&&i<7&&(j===0||j===6||i===0||i===6||(j>=2&&j<=4&&i>=2&&i<=4)))},align=(y,x)=>{for(let j=-2;j<=2;j++)for(let i=-2;i<=2;i++)put(y+j,x+i,Math.max(Math.abs(i),Math.abs(j))!==1)};
finder(0,0);finder(N-7,0);finder(0,N-7);let pos=[6,30,58,86,114,142,170];for(let y of pos)for(let x of pos)if(!((y===6&&x===6)||(y===6&&x===170)||(y===170&&x===6)))align(y,x);for(let i=8;i<N-8;i++){put(6,i,i%2===0);put(i,6,i%2===0)}put(N-8,8,true);
for(let i=0;i<9;i++){if(m[i][8]===null)put(i,8,false);if(m[8][i]===null)put(8,i,false);if(m[N-1-i][8]===null)put(N-1-i,8,false);if(m[8][N-1-i]===null)put(8,N-1-i,false)}
for(let i=0;i<6;i++)for(let j=0;j<3;j++){put(i,N-11+j,false);put(N-11+j,i,false)}
let raw=[...new TextEncoder().encode(text)],bits=[0,1,0,0];for(let i=15;i>=0;i--)bits.push((raw.length>>i)&1);raw.forEach(v=>{for(let i=7;i>=0;i--)bits.push((v>>i)&1)});for(let i=0;i<4&&bits.length<23648;i++)bits.push(0);while(bits.length%8)bits.push(0);let data=[];for(let i=0;i<bits.length;i+=8)data.push(parseInt(bits.slice(i,i+8).join(""),2));for(let p=0;data.length<2956;p++)data.push(p%2?17:236);
let blocks=[],at=0;for(let i=0;i<25;i++){let n=i<19?118:119,b=data.slice(at,at+n);at+=n;blocks.push([b,rs(b,30)])}let stream=[];for(let i=0;i<119;i++)blocks.forEach(b=>{if(i<b[0].length)stream.push(b[0][i])});for(let i=0;i<30;i++)blocks.forEach(b=>stream.push(b[1][i]));let sb=[];stream.forEach(v=>{for(let i=7;i>=0;i--)sb.push((v>>i)&1)});
function paint(mask){let a=m.map(x=>x.slice()),bit=0,up=true;for(let x=N-1;x>0;x-=2){if(x===6)x--;for(let z=0;z<N;z++){let y=up?N-1-z:z;for(let dx=0;dx<2;dx++)if(a[y][x-dx]===null){let k=[(y+x)%2===0,y%2===0,(x-dx)%3===0,(y+x)%3===0,(Math.floor(y/2)+Math.floor((x-dx)/3))%2===0,(y*(x-dx))%2+(y*(x-dx))%3===0,((y*(x-dx))%2+(y*(x-dx))%3)%2===0,((y+x)%2+(y*(x-dx))%3)%2===0][mask];a[y][x-dx]=!!((sb[bit++]||0)^(k?1:0))}}up=!up}let f=(((1<<3)|mask)<<10)|bch(((1<<3)|mask)<<10,0x537);f^=0x5412;for(let i=0;i<15;i++){let v=!!((f>>i)&1);if(i<6)a[i][8]=v;else if(i<8)a[i+1][8]=v;else a[N-15+i][8]=v;if(i<8)a[8][N-i-1]=v;else if(i<9)a[8][15-i]=v;else a[8][14-i]=v}let ver=(40<<12)|bch(40<<12,0x1f25);for(let i=0;i<18;i++){let v=!!((ver>>i)&1);a[Math.floor(i/3)][N-11+i%3]=v;a[N-11+i%3][Math.floor(i/3)]=v}return a}
function score(a){let p=0;for(let y=0;y<N;y++)for(let x=0;x<N;x++){let n=0;for(let j=-1;j<2;j++)for(let i=-1;i<2;i++)if((i||j)&&a[y+j]?.[x+i]===a[y][x])n++;if(n>5)p+=n-2}return p}let best=paint(0),s=score(best);for(let i=1;i<8;i++){let q=paint(i),z=score(q);if(z<s){best=q;s=z}}return best}
function qr(uri){let a=matrix(uri),ns="http://www.w3.org/2000/svg",s=document.createElementNS(ns,"svg");s.setAttribute("class","qr");s.setAttribute("viewBox","0 0 177 177");s.setAttribute("role","img");s.setAttribute("aria-label","QR code for authenticator setup");let bg=document.createElementNS(ns,"rect");bg.setAttribute("width","177");bg.setAttribute("height","177");bg.setAttribute("fill","white");s.append(bg);a.forEach((r,y)=>r.forEach((v,x)=>{if(v){let q=document.createElementNS(ns,"rect");q.setAttribute("x",x);q.setAttribute("y",y);q.setAttribute("width","1");q.setAttribute("height","1");s.append(q)}}));return s}
function enrol(r){head(r,2);r.append(E("h1",{text:"Add the authenticator"}),E("p",{text:"In your authenticator app, add an account. Scan the QR code or use the copied secret."}));status(r);r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.showQR=!S.showQR;render()},text:S.showQR?"Hide QR code":"Show QR code"}));if(S.showQR)r.append(qr(S.uri));r.append(E("h2",{text:"Manual setup secret"}),E("div",{class:"secret",text:S.secret}),E("button",{class:"secondary",type:"button",onClick:()=>copy(S.secret,"The setup secret was copied."),text:"Copy setup secret"}),E("div",{class:"hint",text:"Demo test code: "+S.otp}));let i=field(r,"Authenticator code",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});primary(r,"Confirm authenticator",async()=>{let otp=i.value.replace(/\\s/g,""),x=await api("/api/mfa/confirm","POST",{otp});if(!x.ok){S.error=x.message;return render()}S.mfa=true;S.secret=S.uri=S.otp="";S.notice="Authenticator confirmed. Now save your recovery codes.";S.error="";S.view="codes";render()});r.append(E("button",{class:"link",type:"button",onClick:()=>{S.view="home";render()},text:"Back"}));help(r);logs(r)}
function codes(r){head(r,4);r.append(E("h1",{text:"Save recovery codes"}),E("p",{text:"Each code works once if you cannot use your authenticator. Save them somewhere private."}));status(r);if(S.codes.length){let l=E("ul",{class:"codes"});S.codes.forEach(x=>l.append(E("li",{text:x})));r.append(l,E("button",{class:"secondary",type:"button",onClick:()=>copy(S.codes.join("\\n"),"Recovery codes copied."),text:"Copy all codes"}));primary(r,"I saved my codes",()=>{S.codes=[];S.notice="Recovery codes are ready when you need them.";S.view="home";render()})}else primary(r,"Create recovery codes",async()=>{let x=await api("/api/mfa/backup/regenerate","POST",{});if(!x.ok){S.error=x.message;return render()}S.codes=x.codes;log("Mock backup recovery codes: "+x.codes.join(", "));S.notice="New recovery codes created. Save them now.";render()});r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.view="recovery";render()},text:"Use a recovery code"}));help(r);logs(r)}
function recovery(r){head(r,4);r.append(E("h1",{text:"Use a recovery code"}),E("p",{text:"Enter one unused recovery code. It will be used up after it works."}));status(r);let i=field(r,"Recovery code",{type:"text",autocomplete:"one-time-code",placeholder:"Example: ABCD-EFGH-JKLM"});primary(r,"Check recovery code",async()=>{let x=await api("/api/mfa/recovery/verify","POST",{code:i.value.trim().toUpperCase()});if(!x.ok){S.error=x.message;return render()}S.notice="Recovery code accepted and used. Your MFA remains active.";S.error="";S.view="home";render()});r.append(E("button",{class:"link",type:"button",onClick:()=>{S.view="home";render()},text:"Back"}));help(r);logs(r)}
async function copy(v,msg){try{await navigator.clipboard.writeText(v);S.notice=msg}catch{S.notice="Select the code and copy it using your browser controls."}S.error="";render()}async function logout(){await api("/api/logout","POST",{});Object.assign(S,{csrf:"",view:"signin",mfa:false,secret:"",codes:[],notice:"Signed out.",error:""});render()}(async()=>{let x=await api("/api/session");if(x.ok){S.csrf=x.csrf;S.mfa=x.mfa;S.view=x.auth?"home":"signin"}render()})()})();
</script></body></html>`;
}

async function handler(r: Request): Promise<Response> {
  try {
    const u = new URL(r.url);
    if (r.method === "OPTIONS") { if (!trusted(r)) return fail(r, 403, "This request is not allowed."); const h = headers(r); h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token"); return new Response(null, { status: 204, headers: h }); }
    if (u.pathname === "/" && r.method === "GET") { const nonce = token(18), h = headers(r, nonce); h.set("Content-Type", "text/html; charset=utf-8"); return new Response(page(nonce), { headers: h }); }
    if (!u.pathname.startsWith("/api/")) return fail(r, 404, "Page not found.");
    if (u.pathname === "/api/session" && r.method === "GET") { let s = session(r), c: string | undefined; if (!s) { s = newSession(); c = sessionCookie(s); } const a = s.user && accountIds.get(s.user); return reply(r, { ok: true, csrf: s.csrf, auth: !!a && s.phase === "auth", mfa: !!a?.mfa }, 200, c); }
    if (u.pathname === "/api/signin/request" && r.method === "POST") {
      let s = session(r), c: string | undefined; if (!s) { s = newSession(); c = sessionCookie(s); } if (!csrf(r, s)) return fail(r, 403, "Your page check expired. Refresh the page and try again.");
      const d = await body(r), email = typeof d?.email === "string" ? d.email.trim().toLowerCase() : "";
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email) || email.length > 120) return fail(r, 400, "Enter an email in this format: name@example.com.");
      s.email = email; s.code = identityCode(); s.codeExpires = Date.now() + CHALLENGE; s.codeUsed = false; s.failures = 0; s.locked = undefined;
      return reply(r, { ok: true, mockCode: s.code }, 200, c);
    }
    if (u.pathname === "/api/signin/verify" && r.method === "POST") {
      const s = session(r); if (!s || !csrf(r, s)) return fail(r, 403, "Your page check expired. Refresh the page and try again.");
      /* Task: parse JSON exactly once, then validate data.code from that object. */
      const data = await body(r);
      const code = typeof data?.code === "string" ? data.code : "";
      const now = Date.now();
      if (s.locked && now < s.locked) return fail(r, 429, "Too many incorrect codes. Wait a few minutes, then request a new code.");
      if (!/^\d{6}$/.test(code)) return fail(r, 400, "Enter all 6 numbers from the code.");
      if (!s.email || !s.code || s.codeUsed || !s.codeExpires || now > s.codeExpires) return fail(r, 400, "That code is no longer available. Request a new code and try again.");
      if (!timingSafeEqual(Buffer.from(code), Buffer.from(s.code))) { if (++s.failures >= 5) s.locked = now + LOCK; return fail(r, 400, "That code did not match. Check the 6 numbers or request another code."); }
      const a = account(s.email); s.codeUsed = true; sessions.delete(s.id); const auth = newSession("auth", a.id);
      return reply(r, { ok: true, csrf: auth.csrf, mfa: a.mfa }, 200, sessionCookie(auth));
    }
    if (u.pathname === "/api/logout" && r.method === "POST") { const s = session(r); if (!s || !csrf(r, s)) return fail(r, 403, "Your page check expired. Refresh the page and try again."); sessions.delete(s.id); return reply(r, { ok: true }, 200, clearCookie()); }
    const o = owner(r); if (!o) return fail(r, 401, "Please sign in again to continue."); if (!csrf(r, o.s)) return fail(r, 403, "Your page check expired. Refresh the page and try again.");
    if (u.pathname === "/api/mfa/enroll" && r.method === "POST") { const x = secret(); o.s.enrollment = { secret: enc(x), failures: 0, used: new Set() }; const label = encodeURIComponent(`Harbour Bank:${o.a.email}`); return reply(r, { ok: true, secret: x, provisioningUri: `otpauth://totp/${label}?secret=${x}&issuer=Harbour%20Bank&algorithm=SHA1&digits=6&period=30`, mockOtp: otp(x) }); }
    if (u.pathname === "/api/mfa/confirm" && r.method === "POST") {
      const d = await body(r), v = typeof d?.otp === "string" ? d.otp : "", e = o.s.enrollment, now = Date.now(); if (!e) return fail(r, 400, "Start authenticator setup first, then enter its code."); if (e.locked && now < e.locked) return fail(r, 429, "Too many incorrect codes. Wait a few minutes, then start setup again.");
      const sec = dec(e.secret), step = Math.floor(now / PERIOD); let hit: number | undefined; for (const n of [step - 1, step, step + 1]) if (/^\d{6}$/.test(v) && otp(sec, n) === v && !e.used.has(n)) { hit = n; break; }
      if (hit === undefined) { if (++e.failures >= 5) e.locked = now + LOCK; return fail(r, 400, "That authenticator code is expired, already used, or does not match. Get a new code in your app and try again."); }
      e.used.add(hit); o.a.secret = e.secret; o.a.mfa = true; o.s.enrollment = undefined; return reply(r, { ok: true });
    }
    if (u.pathname === "/api/mfa/backup/regenerate" && r.method === "POST") { if (!o.a.mfa) return fail(r, 400, "Confirm your authenticator before creating recovery codes."); return reply(r, { ok: true, codes: newBackups(o.a) }); }
    if (u.pathname === "/api/mfa/recovery/verify" && r.method === "POST") {
      const d = await body(r), v = typeof d?.code === "string" ? d.code.trim().toUpperCase() : "", now = Date.now(); if (o.a.locked && now < o.a.locked) return fail(r, 429, "Too many incorrect codes. Wait a few minutes, then try a saved code.");
      const b = /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(v) && o.a.backups.find(x => !x.used && x.expires > now && matches(v, x.salt, x.hash)); if (!b) { if (++o.a.failures >= 5) o.a.locked = now + LOCK; return fail(r, 400, "That recovery code is unavailable. Try another saved, unused code or create new codes."); } b.used = true; o.a.failures = 0; return reply(r, { ok: true });
    }
    return fail(r, 404, "Page not found.");
  } catch { return fail(r, 500, "We could not complete that step. Please try again."); }
}
if (!existsSync("certs/cert.pem") || !existsSync("certs/key.pem")) throw Error("TLS certificates are required at certs/cert.pem and certs/key.pem.");
Bun.serve({ port: PORT, tls: { cert: readFileSync("certs/cert.pem"), key: readFileSync("certs/key.pem") }, fetch: handler });
