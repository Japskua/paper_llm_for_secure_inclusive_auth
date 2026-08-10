
import { existsSync, readFileSync } from "node:fs";
import { createCipheriv, createDecipheriv, createHmac, pbkdf2Sync, randomBytes, randomInt, timingSafeEqual, createHash } from "node:crypto";

/* Requirements 1–5: TLS-only, secure in-memory academic MFA demonstration. */
const PORT = Number(process.env.PORT || 3000);
const SESSION = "mfa_session";
const IDLE = 30 * 60_000, ABSOLUTE = 8 * 60 * 60_000;
const CHALLENGE = 10 * 60_000, LOCK = 10 * 60_000, COOLDOWN = 30_000;
const PERIOD = 30_000, RECOVERY_EXPIRY = 365 * 24 * 60 * 60_000;
const key = randomBytes(32), pepper = randomBytes(32);

type Protected = { iv: Buffer; tag: Buffer; data: Buffer };
type Backup = { salt: Buffer; hash: Buffer; used: boolean; expires: number };
type Account = {
  id: string; email: string; mfa: boolean; secret?: Protected; backups: Backup[];
  failures: number; locked?: number; usedTotp: Set<number>;
};
type Enrollment = { secret: Protected; failures: number; locked?: number; used: Set<number> };
type Session = {
  id: string; csrf: string; created: number; seen: number; phase: "preauth" | "pending-mfa" | "auth";
  user?: string; emailHash?: string; enrollment?: Enrollment;
};
type IdentityLimit = {
  requested?: number; codeHash?: { salt: Buffer; hash: Buffer }; expires?: number; used?: boolean;
  failures: number; locked?: number; supported: boolean;
};

const sessions = new Map<string, Session>();
const accounts = new Map<string, Account>();
const accountIds = new Map<string, Account>();
const identityLimits = new Map<string, IdentityLimit>();
const sourceLimits = new Map<string, { requested?: number; failures: number; locked?: number }>();

/* Only this explicit deterministic demo identity can complete identity verification. */
const DEMO_EMAIL = "marcus@example.com";
const demoIdentity = new Map([[DEMO_EMAIL, { id: "demo-marcus-001", email: DEMO_EMAIL }]]);
const token = (n = 32) => randomBytes(n).toString("base64url");
const privacyHash = (value: string) => createHash("sha256").update(pepper).update(value).digest("base64url");

function enc(value: string): Protected {
  const iv = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return { iv, tag: cipher.getAuthTag(), data };
}
function dec(value: Protected) {
  const cipher = createDecipheriv("aes-256-gcm", key, value.iv);
  cipher.setAuthTag(value.tag);
  return Buffer.concat([cipher.update(value.data), cipher.final()]).toString("utf8");
}
function hash(value: string, salt = randomBytes(16)) {
  return { salt, hash: pbkdf2Sync(value, Buffer.concat([salt, pepper]), 210000, 32, "sha256") };
}
function matches(value: string, salt: Buffer, expected: Buffer) {
  const got = pbkdf2Sync(value, Buffer.concat([salt, pepper]), 210000, 32, "sha256");
  return got.length === expected.length && timingSafeEqual(got, expected);
}
function cookieValues(request: Request) {
  const out: Record<string, string> = {};
  for (const item of (request.headers.get("cookie") || "").split(";")) {
    const i = item.indexOf("=");
    if (i > 0) out[item.slice(0, i).trim()] = item.slice(i + 1).trim();
  }
  return out;
}
function sourceKey(request: Request) {
  const forwarded = request.headers.get("x-forwarded-for") || "";
  const source = forwarded.split(",")[0].trim() || request.headers.get("user-agent") || "unknown";
  return privacyHash(source.slice(0, 300));
}
function normalEmail(value: unknown) {
  if (typeof value !== "string") return "";
  const email = value.trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email) && email.length <= 120 ? email : "";
}
function newSession(phase: Session["phase"] = "preauth", user?: string) {
  const now = Date.now();
  const s: Session = { id: token(), csrf: token(), created: now, seen: now, phase, user };
  sessions.set(s.id, s);
  return s;
}
function getSession(request: Request) {
  const s = sessions.get(cookieValues(request)[SESSION]);
  if (!s) return;
  const now = Date.now();
  if (now - s.seen > IDLE || now - s.created > ABSOLUTE) {
    sessions.delete(s.id);
    return;
  }
  s.seen = now;
  return s;
}
function sessionCookie(s: Session) {
  return `${SESSION}=${s.id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(ABSOLUTE / 1000)}`;
}
const clearCookie = () => `${SESSION}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

function trusted(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try {
    const u = new URL(origin);
    const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return u.protocol === "https:" && u.port === String(PORT) && ["localhost", "127.0.0.1", "::1"].includes(host);
  } catch { return false; }
}
/* Requirements 1 and 2: CSRF, secure headers, restrictive CORS and clickjacking prevention. */
function headers(request: Request, nonce?: string) {
  const h = new Headers({
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "Content-Security-Policy": nonce
      ? `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
      : "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
  });
  const origin = request.headers.get("origin");
  if (origin && trusted(request)) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Vary", "Origin");
  }
  return h;
}
function reply(request: Request, data: unknown, status = 200, cookie?: string) {
  const h = headers(request);
  h.set("Content-Type", "application/json; charset=utf-8");
  if (cookie) h.append("Set-Cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers: h });
}
const fail = (request: Request, status: number, message: string) => reply(request, { ok: false, message }, status);

async function body(request: Request): Promise<Record<string, unknown> | undefined> {
  if (Number(request.headers.get("content-length") || 0) > 4096) return;
  try {
    const data = await request.json();
    return data && typeof data === "object" && !Array.isArray(data) ? data as Record<string, unknown> : undefined;
  } catch { return; }
}
function csrf(request: Request, s: Session) {
  const value = request.headers.get("x-csrf-token");
  return trusted(request) && !!value && value.length === s.csrf.length &&
    timingSafeEqual(Buffer.from(value), Buffer.from(s.csrf));
}
function owner(request: Request) {
  const s = getSession(request);
  if (!s || s.phase !== "auth" || !s.user) return;
  const a = accountIds.get(s.user);
  return a ? { s, a } : undefined;
}
function pendingOwner(request: Request) {
  const s = getSession(request);
  if (!s || s.phase !== "pending-mfa" || !s.user) return;
  const a = accountIds.get(s.user);
  return a?.mfa ? { s, a } : undefined;
}
function demoAccount(email: string) {
  const mapped = demoIdentity.get(email);
  if (!mapped) return;
  let a = accountIds.get(mapped.id);
  if (!a) {
    a = { id: mapped.id, email: mapped.email, mfa: false, backups: [], failures: 0, usedTotp: new Set() };
    accounts.set(mapped.email, a);
    accountIds.set(a.id, a);
  }
  return a;
}

const identityCode = () => String(randomInt(1_000_000)).padStart(6, "0");
function base32Secret() {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "", bits = 0, value = 0;
  for (const byte of randomBytes(20)) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out;
}
function decode32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, current = 0; const out: number[] = [];
  for (const char of value.replace(/[=\s]/g, "")) {
    const n = alphabet.indexOf(char);
    if (n < 0) throw Error("bad base32");
    current = (current << 5) | n; bits += 5;
    if (bits >= 8) { out.push((current >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
function otp(value: string, step = Math.floor(Date.now() / PERIOD)) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac("sha1", decode32(value)).update(counter).digest();
  const offset = digest[19] & 15;
  return String((((digest[offset] & 127) << 24) | (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) | digest[offset + 3]) % 1_000_000).padStart(6, "0");
}
function backupCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  for (const byte of randomBytes(12)) code += alphabet[byte % alphabet.length];
  return `${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8)}`;
}
function newBackups(a: Account) {
  const plain = Array.from({ length: 8 }, backupCode);
  a.backups = plain.map(code => ({ ...hash(code), used: false, expires: Date.now() + RECOVERY_EXPIRY }));
  return plain;
}
function lockMessage() { return "Too many incorrect codes. Wait a few minutes, then try again."; }
function checkLimit(limit: { locked?: number }, now: number) { return !!limit.locked && now < limit.locked; }
function recordFailure(limit: { failures: number; locked?: number }, now: number) {
  if (++limit.failures >= 5) limit.locked = now + LOCK;
}

/* Requirements: mobile, plain-language, no moving content, browser console mock logs only. */
function page(nonce: string) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Harbour Bank MFA</title>
<style nonce="${nonce}">
:root{--ink:#17263c;--blue:#075cc7;--pale:#edf6ff;--line:#d5dfeb;--muted:#526278;--good:#105537;--bad:#843900}
*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font:16px/1.72 Verdana,Arial,sans-serif;letter-spacing:.035em}
main{max-width:560px;min-height:100vh;margin:auto;padding:22px 18px 34px;background:white}.brand{font-weight:bold;color:#064b9f}.steps{display:flex;gap:5px;margin:18px 0 24px}.steps i{height:8px;flex:1;border-radius:9px;background:#dbe3ed}.steps i.on{background:var(--blue)}
h1{font-size:1.55rem;line-height:1.32;margin:0 0 9px}h2{font-size:1.12rem;line-height:1.35;margin:20px 0 7px}p{color:var(--muted);margin:8px 0 16px}
.hint,.notice,.error{padding:12px 13px;border-radius:9px;margin:14px 0;white-space:pre-line}.hint{background:var(--pale);border-left:4px solid var(--blue)}.notice{background:#eaf8f0;color:var(--good)}.error{background:#fff0e8;color:var(--bad)}
label{display:block;font-weight:bold;margin:16px 0 5px}input{width:100%;padding:13px;border:2px solid #9aaabd;border-radius:9px;font:inherit;letter-spacing:.09em}input:focus,button:focus{outline:3px solid #a9d0ff;outline-offset:2px;border-color:var(--blue)}
button{border:0;border-radius:9px;padding:13px 16px;font:inherit;font-weight:bold;cursor:pointer;letter-spacing:.02em}.primary{display:block;width:100%;margin-top:18px;background:var(--blue);color:white}.secondary{margin:8px 6px 0 0;background:#e8f0fa;color:#17436d}.link{padding:9px 0;background:transparent;color:var(--blue);text-decoration:underline}
.secret,.codes{font-family:ui-monospace,Consolas,monospace;letter-spacing:.08em;background:#f4f7fa;padding:12px;border-radius:9px;overflow-wrap:anywhere}.codes{list-style:none}.codes li{padding:7px;border-bottom:1px solid var(--line)}
/* QR layout is nonce-authorized CSS. 20px is over four 4.5px modules: a reliable white quiet zone. */
.qr{width:280px;height:280px;margin:16px auto;background:#fff;border:20px solid #fff;display:grid;image-rendering:pixelated}
.qr53{grid-template-columns:repeat(53,1fr);grid-template-rows:repeat(53,1fr)}
.q{background:#111}[hidden]{display:none!important}
@media(max-width:370px){body{font-size:15px}main{padding:17px 14px}.qr{width:272px;height:272px;border-width:20px}}
</style>
</head><body><main id="app" aria-live="polite">Loading…</main>
<script nonce="${nonce}">
(()=>{"use strict";
const app=document.querySelector("#app");
const S={csrf:"",view:"signin",mfa:false,recoveryExists:false,code:"",otp:"",secret:"",uri:"",codes:[],notice:"",error:"",showSecret:false,showQr:false,showCodes:false};
function log(message){console.log(message)}
const E=(tag,p={},...kids)=>{const n=document.createElement(tag);for(const[k,v]of Object.entries(p)){if(k==="text")n.textContent=v;else if(k==="class")n.className=v;else if(k==="hidden")n.hidden=!!v;else if(k.startsWith("on"))n.addEventListener(k.slice(2).toLowerCase(),v);else n.setAttribute(k,String(v))}kids.forEach(x=>n.append(x instanceof Node?x:document.createTextNode(String(x))));return n};
async function api(path,method="GET",data){try{const r=await fetch(path,{method,credentials:"same-origin",headers:method==="GET"?{}:{"Content-Type":"application/json","X-CSRF-Token":S.csrf},body:method==="GET"?undefined:JSON.stringify(data||{})});const j=await r.json();if(r.status===401)S.view="signin";return j}catch{return{ok:false,message:"Connection problem. Please try again."}}}
function head(r,n){r.append(E("div",{class:"brand",text:"⚓ Harbour Bank"}));const x=E("div",{class:"steps","aria-label":"Progress"});for(let i=1;i<5;i++)x.append(E("i",{class:i<=n?"on":""}));r.append(x)}
function status(r){if(S.error)r.append(E("div",{class:"error",role:"alert",text:S.error}));if(S.notice)r.append(E("div",{class:"notice",text:S.notice}))}
function help(r){r.append(E("button",{class:"link",type:"button",onClick:()=>{S.notice="Help: Take as long as you need. You can try again without penalty.";S.error="";render()},text:"? Need a little help"}))}
function field(r,label,attrs){const id="f"+Math.random().toString(36).slice(2);const i=E("input",{id,...attrs});r.append(E("label",{for:id,text:label}),i);return i}
function primary(r,text,fn){r.append(E("button",{class:"primary",type:"button",onClick:fn,text}))}
function render(){app.replaceChildren();const r=E("div");app.append(r);({signin,identity,challenge,home,enrol,codes,recovery}[S.view]||signin)(r)}

function signin(r){
 head(r,1);r.append(E("h1",{text:"Sign in to set up MFA"}),E("p",{text:"We will send one short identity code. This is a safe demo, not a real email."}));status(r);
 const email=field(r,"Email address",{type:"email",autocomplete:"email",inputmode:"email",placeholder:"marcus@example.com"});
 r.append(E("div",{class:"hint",text:"Demo identity: marcus@example.com"}));
 primary(r,"Send identity code",async()=>{const x=await api("/api/signin/request","POST",{email:email.value});if(!x.ok){S.error=x.message;return render()}S.code=x.mockCode||"";if(S.code)log("Mock identity verification code: "+S.code);S.notice="If this identity can be checked, a six-digit demo code is ready.";S.error="";S.view="identity";render()});help(r);
}
function identity(r){
 head(r,1);r.append(E("h1",{text:"Check your identity"}),E("p",{text:"Enter the six-digit code."}));status(r);if(S.code)r.append(E("div",{class:"hint",text:"Demo test code: "+S.code}));
 const code=field(r,"Identity code",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});
 primary(r,"Check code",async()=>{const x=await api("/api/signin/verify","POST",{code:code.value.replace(/\\s/g,"")});if(!x.ok){S.error=x.message;return render()}S.csrf=x.csrf;S.mfa=!!x.mfa;S.recoveryExists=!!x.recoveryExists;S.code="";S.error="";if(x.challenge){S.notice="Identity checked. One more short MFA check is needed.";S.view="challenge"}else{S.notice="Identity checked. Next, set up your authenticator.";S.view="home"}render()});
 r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.code="";S.view="signin";S.notice="You can request another code.";S.error="";render()},text:"Request another code"}));help(r);
}
function challenge(r){
 head(r,2);r.append(E("h1",{text:"Complete your MFA check"}),E("p",{text:"Use a current authenticator code or one saved recovery code. You are not signed in until this works."}));status(r);
 const code=field(r,"Authenticator or recovery code",{type:"text",autocomplete:"one-time-code",placeholder:"Example: 123456 or ABCD-EFGH-JKLM"});
 primary(r,"Complete sign in",async()=>{const x=await api("/api/signin/mfa/verify","POST",{code:code.value.trim().toUpperCase()});if(!x.ok){S.error=x.message;return render()}S.csrf=x.csrf;S.mfa=true;S.recoveryExists=!!x.recoveryExists;S.notice="MFA check complete. You are now signed in.";S.error="";S.view="home";render()});help(r);
}
function home(r){
 head(r,S.mfa?4:2);r.append(E("h1",{text:S.mfa?"MFA is set up":"Set up your authenticator"}),E("p",{text:S.mfa?"Your account has an extra sign-in check.":"Use an authenticator app to get a short code when needed."}));status(r);
 if(!S.mfa){r.append(E("div",{class:"hint",text:"You can show a QR setup pattern, or reveal and copy a manual setup secret."}));primary(r,"Set up authenticator",async()=>{const x=await api("/api/mfa/enroll","POST",{});if(!x.ok){S.error=x.message;return render()}S.secret=x.secret;S.uri=x.provisioningUri;S.otp=x.mockOtp;log("Mock authenticator OTP for verification: "+x.mockOtp);S.notice="Setup secret ready. Choose the method that feels easiest.";S.error="";S.view="enrol";render()})}
 else{r.append(E("div",{class:"notice",text:"Authenticator confirmed. Save recovery codes somewhere private."}));primary(r,"View recovery codes",()=>{S.view="codes";S.notice="";render()});r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.view="recovery";render()},text:"Test a recovery code"}))}
 r.append(E("button",{class:"link",type:"button",onClick:logout,text:"Sign out"}));help(r);
}

/* Standards-compliant QR Code Model 2 encoder: Version 9, error correction M, byte mode.
   It locally encodes the complete otpauth URI; no image service, asset, or network request is used. */
function qr(value){
 const version=9,size=53,dataWords=182,blocks=[[58,36],[58,36],[58,36],[59,37],[59,37]];
 const bytes=new TextEncoder().encode(value);if(bytes.length>dataWords-3)throw new Error("Setup pattern is too long.");
 const bits=[];const put=(v,n)=>{for(let i=n-1;i>=0;i--)bits.push((v>>>i)&1)};
 put(4,4);put(bytes.length,8);for(const b of bytes)put(b,8);put(0,Math.min(4,dataWords*8-bits.length));while(bits.length%8)bits.push(0);
 const raw=[];for(let i=0;i<bits.length;i+=8)raw.push(bits.slice(i,i+8).reduce((a,b)=>a*2+b,0));
 for(let pad=0;raw.length<dataWords;pad++)raw.push(pad%2?0x11:0xec);
 const exp=[0],log=[0];let x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=0x11d}for(let i=255;i<512;i++)exp[i]=exp[i-255];
 const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;
 const poly=n=>{let p=[1];for(let i=0;i<n;i++){const q=exp[i];const next=Array(p.length+1).fill(0);for(let j=0;j<p.length;j++){next[j]^=p[j];next[j+1]^=mul(p[j],q)}p=next}return p};
 const dc=[],ec=[];let offset=0;
 for(const [total,count] of blocks){const d=raw.slice(offset,offset+count);offset+=count;const g=poly(total-count), rem=d.concat(Array(total-count).fill(0));for(let i=0;i<d.length;i++){const f=rem[i];if(f)for(let j=0;j<g.length;j++)rem[i+j]^=mul(g[j],f)}dc.push(d);ec.push(rem.slice(d.length))}
 const stream=[];for(let i=0;i<Math.max(...dc.map(a=>a.length));i++)for(const a of dc)if(i<a.length)stream.push(a[i]);for(let i=0;i<Math.max(...ec.map(a=>a.length));i++)for(const a of ec)if(i<a.length)stream.push(a[i]);
 const bch=(v,poly)=>{let d=v;while((d.toString(2).length)>=poly.toString(2).length)d^=poly<<(d.toString(2).length-poly.toString(2).length);return d};
 const versionBits=(version<<12)|bch(version<<12,0x1f25);
 const make=mask=>{const m=Array.from({length:size},()=>Array(size).fill(null));
  const finder=(r,c)=>{for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)if(r+y>=0&&r+y<size&&c+z>=0&&c+z<size)m[r+y][c+z]=y>=0&&y<=6&&z>=0&&z<=6&&(y===0||y===6||z===0||z===6||(y>=2&&y<=4&&z>=2&&z<=4))};
  finder(0,0);finder(size-7,0);finder(0,size-7);
  for(const r of [6,26,46])for(const c of [6,26,46])if(m[r][c]===null)for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)m[r+y][c+z]=Math.max(Math.abs(y),Math.abs(z))!==1;
  for(let i=8;i<size-8;i++){if(m[i][6]===null)m[i][6]=i%2===0;if(m[6][i]===null)m[6][i]=i%2===0}
  for(let i=0;i<18;i++){const bit=((versionBits>>>i)&1)===1;m[Math.floor(i/3)][size-11+i%3]=bit;m[size-11+i%3][Math.floor(i/3)]=bit}
  const type=(bch(mask<<10,0x537)^(mask<<10)^0x5412);
  for(let i=0;i<15;i++){const bit=((type>>>i)&1)===1;m[i<6?i:i<8?i+1:size-15+i][8]=bit;m[8][i<8?size-i-1:i<9?15-i:size-i]=bit}m[size-8][8]=true;
  let bit=0,row=size-1,dir=-1;const masked=(r,c)=>[ (r+c)%2===0,r%2===0,c%3===0,(r+c)%3===0,(Math.floor(r/2)+Math.floor(c/3))%2===0,(r*c)%2+(r*c)%3===0,((r*c)%2+(r*c)%3)%2===0,((r*c)%3+(r+c)%2)%2===0 ][mask];
  for(let col=size-1;col>0;col-=2){if(col===6)col--;while(true){for(let j=0;j<2;j++){const c=col-j;if(m[row][c]===null){const v=bit<stream.length*8?((stream[Math.floor(bit/8)]>>>(7-bit%8))&1):0;m[row][c]=Boolean(v^Number(masked(row,c)));bit++}}row+=dir;if(row<0||row===size){row-=dir;dir=-dir;break}}}return m};
 const penalty=m=>{let p=0;for(let r=0;r<size;r++)for(let c=0;c<size;c++){let same=0;for(let y=-1;y<=1;y++)for(let z=-1;z<=1;z++)if(y||z){const a=r+y,b=c+z;if(a>=0&&a<size&&b>=0&&b<size&&m[a][b]===m[r][c])same++}if(same>5)p+=3+same-5}for(let r=0;r<size-1;r++)for(let c=0;c<size-1;c++)if(m[r][c]===m[r+1][c]&&m[r][c]===m[r][c+1]&&m[r][c]===m[r+1][c+1])p+=3;for(const line of [...m,...Array.from({length:size},(_,c)=>m.map(r=>r[c]))])for(let i=0;i<=size-7;i++)if(line.slice(i,i+7).map(Number).join("")==="1011101")p+=40;const dark=m.flat().filter(Boolean).length;p+=Math.floor(Math.abs(100*dark/(size*size)-50)/5)*10;return p};
 let best=make(0),score=penalty(best);for(let i=1;i<8;i++){const next=make(i),n=penalty(next);if(n<score){best=next;score=n}}
 /* The 53×53 grid is defined by the nonce-authorized .qr53 stylesheet rule. */
 const q=E("div",{class:"qr qr53",role:"img","aria-label":"QR code containing authenticator setup information"});for(const row of best)for(const cell of row)q.append(E("span",{class:cell?"q":""}));return q;
}
function enrol(r){
 head(r,2);r.append(E("h1",{text:"Add the authenticator"}),E("p",{text:"In your authenticator app, add an account. Scan the setup pattern or copy the setup secret."}));status(r);
 r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.showQr=!S.showQr;render()},text:S.showQr?"Hide QR setup pattern":"Show QR setup pattern"}));if(S.showQr&&S.uri)r.append(qr(S.uri),E("div",{class:"hint",text:"If scanning is difficult, use the manual setup secret below."}));
 r.append(E("h2",{text:"Manual setup secret"}),E("button",{class:"secondary",type:"button",onClick:()=>{S.showSecret=!S.showSecret;render()},text:S.showSecret?"Hide setup secret":"Show setup secret"}));if(S.showSecret)r.append(E("div",{class:"secret",text:S.secret}),E("button",{class:"secondary",type:"button",onClick:()=>copy(S.secret,"The setup secret was copied."),text:"Copy setup secret"}));
 r.append(E("div",{class:"hint",text:"Demo test code: "+S.otp}));const code=field(r,"Authenticator code",{type:"text",inputmode:"numeric",autocomplete:"one-time-code",maxlength:"6",placeholder:"Example: 123456"});
 primary(r,"Confirm authenticator",async()=>{const x=await api("/api/mfa/confirm","POST",{otp:code.value.replace(/\\s/g,"")});if(!x.ok){S.error=x.message;return render()}S.mfa=true;S.secret=S.uri=S.otp="";S.showQr=S.showSecret=false;S.notice="Authenticator confirmed. Now save your recovery codes.";S.error="";S.view="codes";render()});help(r);
}
function codes(r){
 head(r,4);r.append(E("h1",{text:"Save recovery codes"}),E("p",{text:"Each code works once if you cannot use your authenticator. Save them somewhere private."}));status(r);
 if(S.codes.length){r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.showCodes=!S.showCodes;render()},text:S.showCodes?"Hide recovery codes":"Show recovery codes"}));if(S.showCodes){const list=E("ul",{class:"codes"});S.codes.forEach(x=>list.append(E("li",{text:x})));r.append(list)}r.append(E("button",{class:"secondary",type:"button",onClick:()=>copy(S.codes.join("\\n"),"Recovery codes copied."),text:"Copy all codes"}));primary(r,"I saved my codes",()=>{S.codes=[];S.showCodes=false;S.notice="Recovery codes are ready when you need them.";S.view="home";render()})}
 else if(S.recoveryExists){r.append(E("div",{class:"hint",text:"Recovery codes already exist. Creating new ones will stop old unused codes."}));primary(r,"Create new recovery codes",()=>createCodes(true))}
 else primary(r,"Create recovery codes",()=>createCodes(false));
 r.append(E("button",{class:"secondary",type:"button",onClick:()=>{S.view="recovery";render()},text:"Use a recovery code"}));help(r);
}
async function createCodes(confirm){const x=await api("/api/mfa/backup/regenerate","POST",{confirm});if(!x.ok){S.error=x.message;return render()}S.codes=x.codes;S.recoveryExists=true;S.showCodes=false;log("Mock backup recovery codes: "+x.codes.join(", "));S.notice="New recovery codes created. Save them now.";S.error="";render()}
function recovery(r){
 head(r,4);r.append(E("h1",{text:"Use a recovery code"}),E("p",{text:"Enter one unused recovery code. It will be used after it works."}));status(r);const code=field(r,"Recovery code",{type:"text",autocomplete:"one-time-code",placeholder:"Example: ABCD-EFGH-JKLM"});
 primary(r,"Check recovery code",async()=>{const x=await api("/api/mfa/recovery/verify","POST",{code:code.value.trim().toUpperCase()});if(!x.ok){S.error=x.message;return render()}S.notice="Recovery code accepted and used. Your MFA remains active.";S.error="";S.view="home";render()});r.append(E("button",{class:"link",type:"button",onClick:()=>{S.view="home";render()},text:"Back"}));help(r);
}
async function copy(value,message){try{await navigator.clipboard.writeText(value);S.notice=message}catch{S.notice="Select the code and copy it using your browser controls."}S.error="";render()}
async function logout(){await api("/api/logout","POST",{});Object.assign(S,{csrf:"",view:"signin",mfa:false,recoveryExists:false,code:"",otp:"",secret:"",uri:"",codes:[],notice:"Signed out.",error:"",showSecret:false,showQr:false,showCodes:false});render()}
(async()=>{const x=await api("/api/session");if(x.ok){S.csrf=x.csrf;if(x.auth){S.mfa=!!x.mfa;S.recoveryExists=!!x.recoveryExists;S.view="home"}else if(x.challenge){S.mfa=true;S.view="challenge"}}render()})();
})();
</script></body></html>`;
}

async function handler(request: Request): Promise<Response> {
  try {
    const u = new URL(request.url);
    if (request.method === "OPTIONS") {
      if (!trusted(request)) return fail(request, 403, "This request is not allowed.");
      const h = headers(request);
      h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      h.set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token");
      return new Response(null, { status: 204, headers: h });
    }
    if (u.pathname === "/" && request.method === "GET") {
      const nonce = token(18), h = headers(request, nonce);
      h.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(nonce), { headers: h });
    }
    if (!u.pathname.startsWith("/api/")) return fail(request, 404, "Page not found.");

    if (u.pathname === "/api/session" && request.method === "GET") {
      let s = getSession(request), cookie: string | undefined;
      if (!s) { s = newSession(); cookie = sessionCookie(s); }
      const a = s.user ? accountIds.get(s.user) : undefined;
      return reply(request, {
        ok: true, csrf: s.csrf, auth: s.phase === "auth" && !!a,
        challenge: s.phase === "pending-mfa" && !!a,
        mfa: !!a?.mfa, recoveryExists: !!a?.backups.length
      }, 200, cookie);
    }

    if (u.pathname === "/api/signin/request" && request.method === "POST") {
      let s = getSession(request), cookie: string | undefined;
      if (!s) { s = newSession(); cookie = sessionCookie(s); }
      if (!csrf(request, s)) return fail(request, 403, "Your page check expired. Refresh the page and try again.");
      const d = await body(request), email = normalEmail(d?.email);
      if (!email) return fail(request, 400, "Enter an email in this format: name@example.com.");
      const now = Date.now(), eHash = privacyHash(email), src = sourceKey(request);
      let limit = identityLimits.get(eHash);
      if (!limit) { limit = { failures: 0, supported: demoIdentity.has(email) }; identityLimits.set(eHash, limit); }
      let source = sourceLimits.get(src);
      if (!source) { source = { failures: 0 }; sourceLimits.set(src, source); }
      if (checkLimit(limit, now) || checkLimit(source, now)) return fail(request, 429, lockMessage());
      if ((limit.requested && now - limit.requested < COOLDOWN) || (source.requested && now - source.requested < COOLDOWN)) {
        return fail(request, 429, "Please wait a short time before requesting another code.");
      }
      const code = identityCode();
      limit.codeHash = hash(code); limit.expires = now + CHALLENGE; limit.used = false; limit.requested = now;
      source.requested = now; s.emailHash = eHash;
      return reply(request, { ok: true, mockCode: code }, 200, cookie);
    }

    if (u.pathname === "/api/signin/verify" && request.method === "POST") {
      const s = getSession(request);
      if (!s || !csrf(request, s)) return fail(request, 403, "Your page check expired. Refresh the page and try again.");
      const d = await body(request), code = typeof d?.code === "string" ? d.code.trim() : "";
      const now = Date.now(), limit = s.emailHash ? identityLimits.get(s.emailHash) : undefined;
      const src = sourceLimits.get(sourceKey(request));
      if (!limit || !src || checkLimit(limit, now) || checkLimit(src, now)) return fail(request, 429, lockMessage());
      if (!/^\d{6}$/.test(code) || !limit.codeHash || limit.used || !limit.expires || now > limit.expires) {
        return fail(request, 400, "That code is unavailable. Request a new code and try again.");
      }
      const valid = matches(code, limit.codeHash.salt, limit.codeHash.hash) && limit.supported;
      if (!valid) {
        recordFailure(limit, now); recordFailure(src, now);
        return fail(request, 400, "That code did not match. Check the 6 numbers or request another code.");
      }
      const identity = [...demoIdentity.entries()].find(([email]) => privacyHash(email) === s.emailHash);
      const a = identity && demoAccount(identity[0]);
      if (!a) return fail(request, 400, "That code did not match. Check the 6 numbers or request another code.");
      limit.used = true; limit.failures = 0; src.failures = 0;
      sessions.delete(s.id);
      const next = newSession(a.mfa ? "pending-mfa" : "auth", a.id);
      return reply(request, {
        ok: true, csrf: next.csrf, mfa: a.mfa, challenge: a.mfa,
        recoveryExists: a.backups.length > 0
      }, 200, sessionCookie(next));
    }

    if (u.pathname === "/api/signin/mfa/verify" && request.method === "POST") {
      const p = pendingOwner(request);
      if (!p || !csrf(request, p.s)) return fail(request, 401, "Please sign in again to continue.");
      const d = await body(request), value = typeof d?.code === "string" ? d.code.trim().toUpperCase() : "";
      const now = Date.now();
      if (checkLimit(p.a, now)) return fail(request, 429, lockMessage());
      let valid = false;
      if (/^\d{6}$/.test(value) && p.a.secret) {
        const sec = dec(p.a.secret), step = Math.floor(now / PERIOD);
        for (const n of [step - 1, step, step + 1]) {
          if (otp(sec, n) === value && !p.a.usedTotp.has(n)) { p.a.usedTotp.add(n); valid = true; break; }
        }
      } else if (/^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value)) {
        const found = p.a.backups.find(x => !x.used && x.expires > now && matches(value, x.salt, x.hash));
        if (found) { found.used = true; valid = true; }
      }
      if (!valid) {
        recordFailure(p.a, now);
        return fail(request, 400, "That authenticator or recovery code is unavailable. Check it and try again.");
      }
      p.a.failures = 0; sessions.delete(p.s.id);
      const auth = newSession("auth", p.a.id);
      return reply(request, { ok: true, csrf: auth.csrf, recoveryExists: p.a.backups.length > 0 }, 200, sessionCookie(auth));
    }

    if (u.pathname === "/api/logout" && request.method === "POST") {
      const s = getSession(request);
      if (!s || !csrf(request, s)) return fail(request, 403, "Your page check expired. Refresh the page and try again.");
      sessions.delete(s.id);
      return reply(request, { ok: true }, 200, clearCookie());
    }

    const o = owner(request);
    if (!o) return fail(request, 401, "Please sign in again to continue.");
    if (!csrf(request, o.s)) return fail(request, 403, "Your page check expired. Refresh the page and try again.");

    if (u.pathname === "/api/mfa/enroll" && request.method === "POST") {
      if (o.a.mfa) return fail(request, 400, "Your authenticator is already confirmed.");
      let existing = true;
      if (!o.s.enrollment) { o.s.enrollment = { secret: enc(base32Secret()), failures: 0, used: new Set() }; existing = false; }
      const value = dec(o.s.enrollment.secret), label = encodeURIComponent(`Harbour Bank:${o.a.email}`);
      return reply(request, {
        ok: true, existing, secret: value,
        provisioningUri: `otpauth://totp/${label}?secret=${value}&issuer=Harbour%20Bank&algorithm=SHA1&digits=6&period=30`,
        mockOtp: otp(value)
      });
    }
    if (u.pathname === "/api/mfa/confirm" && request.method === "POST") {
      const d = await body(request), value = typeof d?.otp === "string" ? d.otp.trim() : "";
      const e = o.s.enrollment, now = Date.now();
      if (!e) return fail(request, 400, "Start authenticator setup first, then enter its code.");
      if (checkLimit(e, now)) return fail(request, 429, lockMessage());
      if (!/^\d{6}$/.test(value)) return fail(request, 400, "Enter all 6 numbers from your authenticator.");
      const sec = dec(e.secret), step = Math.floor(now / PERIOD); let hit: number | undefined;
      for (const n of [step - 1, step, step + 1]) if (otp(sec, n) === value && !e.used.has(n)) { hit = n; break; }
      if (hit === undefined) { recordFailure(e, now); return fail(request, 400, "That authenticator code is expired, already used, or does not match. Get a new code and try again."); }
      e.used.add(hit); o.a.secret = e.secret; o.a.mfa = true; o.a.usedTotp = new Set(); o.s.enrollment = undefined;
      return reply(request, { ok: true });
    }
    if (u.pathname === "/api/mfa/backup/regenerate" && request.method === "POST") {
      if (!o.a.mfa) return fail(request, 400, "Confirm your authenticator before creating recovery codes.");
      const d = await body(request), confirm = d?.confirm === true;
      if (o.a.backups.length && !confirm) return fail(request, 400, "Confirm that all prior unused recovery codes should stop working.");
      return reply(request, { ok: true, codes: newBackups(o.a) });
    }
    if (u.pathname === "/api/mfa/recovery/verify" && request.method === "POST") {
      const d = await body(request), value = typeof d?.code === "string" ? d.code.trim().toUpperCase() : "", now = Date.now();
      if (checkLimit(o.a, now)) return fail(request, 429, lockMessage());
      const found = /^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(value) &&
        o.a.backups.find(x => !x.used && x.expires > now && matches(value, x.salt, x.hash));
      if (!found) { recordFailure(o.a, now); return fail(request, 400, "That recovery code is unavailable. Try another saved unused code or create new codes."); }
      found.used = true; o.a.failures = 0;
      return reply(request, { ok: true });
    }
    return fail(request, 404, "Page not found.");
  } catch {
    return fail(request, 500, "We could not complete that step. Please try again.");
  }
}

if (!existsSync("certs/cert.pem") || !existsSync("certs/key.pem")) {
  throw Error("TLS certificates are required at certs/cert.pem and certs/key.pem.");
}
Bun.serve({
  port: PORT,
  tls: { cert: readFileSync("certs/cert.pem"), key: readFileSync("certs/key.pem") },
  fetch: handler
});
