
import {
  createCipheriv, createDecipheriv, createHmac, randomBytes, scryptSync,
  timingSafeEqual,
} from "node:crypto";

/**
 * MFA Enrolment System
 * Requirements 1–5: owner-only sessions, CSRF, TLS/security headers,
 * encrypted OTP seeds, hashed recovery codes, rate limiting, and inclusive UI.
 */
const PORT = 3000;
const ACCOUNT_ID = "account-marcus-001";
const ACCOUNT_EMAIL = "marcus@example.com";
const ACCOUNT_PHONE_SUFFIX = "4821";

/* Test-only authentication is isolated and must be explicitly enabled. */
const TEST_MODE = process.env.MFA_TEST_MODE === "1";
const DEMO_TEST_ENABLED = TEST_MODE && process.env.MFA_DEMO_MODE === "1";
const TRUSTED_ASSERTION_KEY = process.env.MFA_TRUSTED_ASSERTION_KEY || "";

const ACADEMIC_FIXTURE_CODE = "MARCUS-ACADEMIC";
const ACADEMIC_IDENTITY_CODE = "246810";
const ACADEMIC_TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const ACADEMIC_RECOVERY_CODES = [
  "A1B2-C3D4-E5F6-7890", "B2C3-D4E5-F607-8A9B",
  "C3D4-E5F6-0718-9ABC", "D4E5-F607-1829-ABCD",
  "E5F6-0718-293A-BCDE", "F607-1829-3ABC-DEF0",
  "0718-293A-BCDE-F012", "1829-3ABC-DEF0-1234",
];

const SESSION_IDLE_MS = 20 * 60 * 1000;
const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const VERIFY_EXPIRY_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILURES = 5;
const TOTP_STEP_SECONDS = 30;
const TRUSTED_ORIGINS = new Set([
  "https://localhost:3000",
  "https://127.0.0.1:3000",
  "https://[::1]:3000",
]);

type Session = {
  id: string; csrf: string; accountId: string; identityVerified: boolean;
  fixture: boolean; createdAt: number; lastSeenAt: number;
};
type ProtectedValue = {
  hash: string; expiresAt: number; used: boolean; accountId: string;
};
type RecoveryHash = { salt: string; hash: string };
type AccountMfa = {
  encryptedSecret?: string; secretIv?: string; secretTag?: string;
  identityCode?: ProtectedValue;
  recoveryHashes: RecoveryHash[];
  mfaEnabled: boolean;
  otpVerified: boolean;
  otpVerifiedEnrolment?: string;
  recoveryGeneratedEnrolment?: string;
  enrolmentId?: string;
  failures: number;
  lockedUntil: number;
  lastAcceptedTotpCounter?: number;
};

const now = () => Date.now();
const token = (bytes = 32) => randomBytes(bytes).toString("base64url");
const encryptionKey = randomBytes(32);
const sessions = new Map<string, Session>();

/* Requirement 1: MFA records are strictly keyed by authenticated account ID. */
const accountMfaRecords = new Map<string, AccountMfa>();
function accountRecord(accountId: string): AccountMfa {
  let item = accountMfaRecords.get(accountId);
  if (!item) {
    item = {
      recoveryHashes: [], mfaEnabled: false, otpVerified: false,
      failures: 0, lockedUntil: 0,
    };
    accountMfaRecords.set(accountId, item);
  }
  return item;
}

function equal(a: string, b: string) {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function createAuthenticatedSession(identityVerified = false, fixture = false) {
  const session: Session = {
    id: token(), csrf: token(), accountId: ACCOUNT_ID, identityVerified, fixture,
    createdAt: now(), lastSeenAt: now(),
  };
  sessions.set(session.id, session);
  return session;
}
function sessionCookie(id: string, expiry = false) {
  return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict${expiry ? "; Max-Age=0" : ""}`;
}
function headers(nonce = "", extra: Record<string, string> = {}) {
  const scripts = nonce ? `'nonce-${nonce}'` : "'none'";
  return {
    "Content-Security-Policy": `default-src 'self'; script-src ${scripts}; style-src ${scripts}; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
    "Cache-Control": "no-store",
    ...extra,
  };
}
function json(data: unknown, status = 200, extra: Record<string, string> = {}) {
  return Response.json(data, { status, headers: headers("", extra) });
}
function genericError(status = 400) {
  return json({ ok: false, message: "We could not complete that step. Please check the information and try again." }, status);
}
function parseCookies(request: Request) {
  const result: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const [key, ...values] = part.trim().split("=");
    if (key && values.length) result[key] = values.join("=");
  }
  return result;
}
function getLiveSession(request: Request) {
  const id = parseCookies(request).mfa_session;
  const session = id ? sessions.get(id) : undefined;
  if (!session) return null;
  if (now() - session.lastSeenAt > SESSION_IDLE_MS || now() - session.createdAt > SESSION_ABSOLUTE_MS) {
    sessions.delete(session.id);
    return null;
  }
  session.lastSeenAt = now();
  return session;
}
function requireOwner(request: Request): Session | Response {
  const session = getLiveSession(request);
  if (!session || session.accountId !== ACCOUNT_ID) {
    return json({ ok: false, message: "Please sign in to your secure setup page." }, 401);
  }
  return session;
}
function trustedSameOrigin(request: Request) {
  return TRUSTED_ORIGINS.has(request.headers.get("origin") || "");
}
function csrfOkay(request: Request, session: Session) {
  return trustedSameOrigin(request) && equal(request.headers.get("x-csrf-token") || "", session.csrf);
}
async function body(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/* Production authentication boundary: only a signed upstream assertion can create a production session. */
function trustedOwnerAssertion(request: Request) {
  if (!TRUSTED_ASSERTION_KEY) return false;
  const identity = request.headers.get("x-preauthenticated-identity") || "";
  const stamp = request.headers.get("x-preauthenticated-timestamp") || "";
  const signature = request.headers.get("x-preauthenticated-signature") || "";
  if (identity !== ACCOUNT_ID || !/^\d{13}$/.test(stamp) || Math.abs(now() - Number(stamp)) > 60_000) return false;
  const expected = createHmac("sha256", TRUSTED_ASSERTION_KEY).update(`${identity}.${stamp}`).digest("base64url");
  return equal(signature, expected);
}
function protectedCode(code: string, accountId: string): ProtectedValue {
  return {
    hash: createHmac("sha256", encryptionKey).update(code).digest("hex"),
    expiresAt: now() + VERIFY_EXPIRY_MS, used: false, accountId,
  };
}
function codeHash(code: string) {
  return createHmac("sha256", encryptionKey).update(code).digest("hex");
}
function encrypt(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return {
    encryptedSecret: encrypted.toString("base64"),
    secretIv: iv.toString("base64"),
    secretTag: cipher.getAuthTag().toString("base64"),
  };
}
function decrypt(item: AccountMfa) {
  if (!item.encryptedSecret || !item.secretIv || !item.secretTag) return "";
  try {
    const decipher = createDecipheriv("aes-256-gcm", encryptionKey, Buffer.from(item.secretIv, "base64"));
    decipher.setAuthTag(Buffer.from(item.secretTag, "base64"));
    return Buffer.concat([
      decipher.update(Buffer.from(item.encryptedSecret, "base64")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return "";
  }
}

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Secret() {
  const raw = randomBytes(20);
  let bits = 0, value = 0, output = "";
  for (const byte of raw) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return bits ? output + BASE32[(value << (5 - bits)) & 31] : output;
}
function decodeBase32(value: string) {
  let bits = 0, buffer = 0;
  const output: number[] = [];
  for (const char of value.replace(/=|\s/g, "").toUpperCase()) {
    const item = BASE32.indexOf(char);
    if (item < 0) return Buffer.alloc(0);
    buffer = (buffer << 5) | item;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}
function totp(secret: string, counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS)) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", decodeBase32(secret)).update(message).digest();
  const offset = mac[19] & 15;
  const value = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
function matchingTotpCounter(secret: string, code: string) {
  const current = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  for (const offset of [-1, 0, 1]) {
    if (equal(totp(secret, current + offset), code)) return current + offset;
  }
  return null;
}
function provisioningUri(secret: string) {
  const issuer = "SafeBank";
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${ACCOUNT_EMAIL}`)}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}
function lockMessage(record: AccountMfa) {
  return record.lockedUntil > now() ? "Too many attempts were made. Please wait a few minutes, then try again." : "";
}
function failure(record: AccountMfa) {
  record.failures++;
  if (record.failures >= MAX_FAILURES) {
    record.failures = 0;
    record.lockedUntil = now() + LOCKOUT_MS;
  }
}
function clearFailures(record: AccountMfa) {
  record.failures = 0;
}
const validPhone = (value: unknown) => typeof value === "string" && /^\d{4}$/.test(value);
const validOtp = (value: unknown) => typeof value === "string" && /^\d{6}$/.test(value);
function normalRecovery(value: unknown) {
  if (typeof value !== "string") return "";
  const text = value.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return /^[A-F0-9]{16}$/.test(text)
    ? `${text.slice(0, 4)}-${text.slice(4, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}`
    : "";
}
function recoveryHash(code: string, salt: Buffer) {
  return { salt: salt.toString("base64"), hash: scryptSync(code, salt, 32).toString("base64") };
}

function page(nonce: string) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeBank MFA setup</title>
<style nonce="${nonce}">
:root{--ink:#172033;--muted:#536074;--blue:#075cc6;--soft:#edf5ff;--line:#cbd5e1;--good:#087443;--bad:#992020}*{box-sizing:border-box}body{margin:0;background:#f4f7fb;color:var(--ink);font-family:Arial,Verdana,Tahoma,sans-serif;font-size:17px;letter-spacing:.035em;line-height:1.65}main{width:min(100%,560px);min-height:100vh;margin:auto;background:#fff;padding:22px 20px 38px}header{border-bottom:2px solid var(--line);padding-bottom:16px;margin-bottom:22px}.brand{font-size:1.25rem;font-weight:800}.step{color:var(--muted);font-size:.92rem;margin:5px 0 0}h1{font-size:1.7rem;line-height:1.25;margin:0 0 12px}p{max-width:48ch}.card{border:1px solid var(--line);border-radius:14px;padding:18px;margin:18px 0}.notice{background:var(--soft);border-left:5px solid var(--blue)}.success{background:#effbf4;border-left:5px solid var(--good)}.error{background:#fff2f2;border-left:5px solid var(--bad);color:#721c1c}.test{background:#fff8df;border-left:5px solid #b77900}label{display:block;font-weight:700;margin:16px 0 5px}input{width:100%;min-height:51px;border:2px solid #9aa8ba;border-radius:9px;padding:10px 12px;font:inherit;letter-spacing:.08em}input:focus,button:focus,summary:focus{outline:3px solid #f5aa2d;outline-offset:3px}.hint{color:var(--muted);margin:3px 0 14px;font-size:.92rem}button{display:block;width:100%;min-height:53px;border:0;border-radius:9px;padding:12px 15px;font:inherit;font-weight:800;cursor:pointer;margin:15px 0 0}.primary{background:var(--blue);color:#fff}.secondary{color:#044a9e;background:#e7f0fd}.textbutton{color:#044a9e;background:transparent;text-decoration:underline;min-height:40px}.icon{font-size:1.6rem;margin-right:8px}.code{font-family:monospace;font-size:1.03rem;letter-spacing:.1em;overflow-wrap:anywhere;background:#f5f7fa;padding:11px;border-radius:8px;white-space:pre-wrap}.qr{display:block;width:270px;max-width:100%;margin:18px auto;background:#fff;image-rendering:pixelated}.small{font-size:.9rem;color:var(--muted)}details{margin-top:20px;border-top:1px solid var(--line);padding-top:14px}summary{font-weight:800;cursor:pointer;color:#044a9e}.hidden{display:none}.logs{margin-top:24px;border-top:2px solid var(--line);padding-top:14px}.logs h2{font-size:1.05rem;margin:0 0 7px}.logbox{max-height:190px;overflow:auto;background:#172033;color:#f7fbff;border-radius:9px;padding:12px;font-family:monospace;font-size:.78rem;letter-spacing:0;white-space:pre-wrap}@media(max-width:360px){main{padding:18px 15px}body{font-size:16px}h1{font-size:1.48rem}}
</style></head><body><main>
<header><div class="brand">🔐 SafeBank</div><p class="step" id="step">MFA setup</p></header>
<section id="app" aria-live="polite"></section>
<section class="logs" aria-labelledby="logsTitle"><h2 id="logsTitle">Logs</h2><p class="small">Simulated delivery and test messages appear here.</p><div id="logs" class="logbox" role="log" aria-live="polite">Ready.</div></section>
</main><script nonce="${nonce}">(()=>{"use strict";
let csrf="",testMode=false,demoEnabled=false,backupCodes=[];
const app=document.getElementById("app"),step=document.getElementById("step"),logs=document.getElementById("logs"),by=id=>document.getElementById(id);
const esc=v=>{const d=document.createElement("div");d.textContent=String(v);return d.innerHTML};
function log(message,value){if(arguments.length>1)console.log(message,value);else console.log(message);const shown=arguments.length>1?message+" "+(Array.isArray(value)?value.join("\\n"):String(value)):message;logs.textContent+=(logs.textContent==="Ready."?"":"\\n")+shown;logs.scrollTop=logs.scrollHeight}
function set(label,html){step.textContent=label;app.innerHTML=html}
async function api(path,data={}){const r=await fetch(path,{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":csrf},body:JSON.stringify(data)});const x=await r.json().catch(()=>({ok:false,message:"Please try again."}));if(r.status===401){csrf="";signedOut(x.message||"Your secure setup session ended.")}return x}
function testOutput(label,value){if(!testMode||value===undefined)return "";log("[ACADEMIC TEST MODE] "+label+":",value);return '<div class="card test"><strong>Academic test value</strong><div class="code">'+esc(Array.isArray(value)?value.join("\\n"):value)+'</div></div>'}
function help(){return '<details><summary>Need help?</summary><p>You can take your time. There is no reading time limit. You can retry any step.</p><button class="textbutton" data-start type="button">Start this setup again</button></details>'}
function signIn(message=""){const demo=demoEnabled?'<div class="card test"><p><strong>Explicit test-only demo sign-in</strong></p><button class="primary" id="demoLogin">Open test demo setup</button></div>':"";const fixture=testMode?'<div class="card test"><p><strong>Academic test mode</strong></p><label for="fixture">Academic fixture phrase</label><p class="hint">Example: MARCUS-ACADEMIC</p><input id="fixture" autocomplete="off"><button class="secondary" id="fixtureLogin">Open secure test setup</button></div>':"";set("Secure setup sign-in",'<h1><span class="icon">🔒</span>Secure setup</h1><div class="card notice"><p>'+esc(message||"Sign in through SafeBank before opening MFA setup.")+'</p></div>'+demo+fixture);const d=by("demoLogin");if(d)d.onclick=async()=>{const r=await api("/api/demo/login");if(r.ok){log("Test-only demo sign-in completed.");location.reload()}else signIn(r.message)};const f=by("fixtureLogin");if(f)f.onclick=async()=>{const r=await api("/api/test/login",{fixture:by("fixture").value});if(r.ok){log("Academic test sign-in completed.");location.reload()}else signIn(r.message)}}
function identity(message=""){set("Step 1 of 4 · identity check",'<h1><span class="icon">🪪</span>Check it is you</h1><p>We will send a six-digit code to your phone ending in 4821.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div id="sentConfirmation"></div><form id="identityForm"><label for="phone">Last 4 digits of phone</label><p class="hint">Example: 4821</p><input id="phone" inputmode="numeric" autocomplete="tel" maxlength="4" required><label for="identityCode">Code</label><p class="hint">Example: 123456</p><input id="identityCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary">Check code</button></form><button class="secondary" id="send">Send or re-send code</button>'+help());by("send").onclick=async()=>{const r=await api("/api/identity/send",{phone:by("phone").value});if(!r.ok)return identity(r.message);by("sentConfirmation").innerHTML='<div class="card success"><strong>Code sent.</strong><p>Enter it when you are ready.</p></div>'+testOutput("Identity code",r.testCode);log("Simulated identity code delivery sent.");by("identityCode").focus()};by("identityForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/identity/verify",{code:by("identityCode").value});if(r.ok){csrf=r.csrf||"";log("Identity check completed. Secure session refreshed.");provision()}else identity(r.message)}}

/* Standards-compliant QR Model 2 encoder: Version 10, error correction L.
   It encodes the exact otpauth URI as byte data and produces a scannable SVG. */
function qr(text){const ver=10,n=57,bytes=[...new TextEncoder().encode(text)],data=[];const put=(v,b)=>{for(let i=b-1;i>=0;i--)data.push((v>>i)&1)};put(4,4);put(bytes.length,8);bytes.forEach(x=>put(x,8));for(let i=0;i<4&&data.length<274*8;i++)data.push(0);while(data.length%8)data.push(0);let pad=0;while(data.length<274*8){put(pad++%2?17:236,8)}const words=[];for(let i=0;i<data.length;i+=8)words.push(data.slice(i,i+8).reduce((a,b)=>a*2+b,0));const exp=[],logg=Array(256);let x=1;for(let i=0;i<255;i++){exp[i]=x;logg[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>!a||!b?0:exp[logg[a]+logg[b]];let gen=[1];for(let i=0;i<18;i++){const next=Array(gen.length+1).fill(0);for(let j=0;j<gen.length;j++){next[j]^=gen[j];next[j+1]^=mul(gen[j],exp[i])}gen=next}const rs=d=>{const r=Array(18).fill(0);for(const q of d){const f=q^r.shift();r.push(0);for(let j=0;j<18;j++)r[j]^=mul(gen[j+1],f)}return r};const blocks=[words.slice(0,68),words.slice(68,136),words.slice(136,205),words.slice(205,274)],ec=blocks.map(rs),all=[];for(let i=0;i<69;i++)blocks.forEach(b=>{if(i<b.length)all.push(b[i])});for(let i=0;i<18;i++)ec.forEach(b=>all.push(b[i]));const raw=[];all.forEach(q=>{for(let i=7;i>=0;i--)raw.push((q>>i)&1)});function matrix(){return Array.from({length:n},()=>Array(n).fill(null))}function setFinder(m,a,b){for(let y=-1;y<=7;y++)for(let z=-1;z<=7;z++)if(a+z>=0&&b+y>=0&&a+z<n&&b+y<n)m[b+y][a+z]=(z>=0&&z<=6&&y>=0&&y<=6&&(z===0||z===6||y===0||y===6||(z>=2&&z<=4&&y>=2&&y<=4)))?1:0}function bch(v,p){let d=0,t=p;while(t){d++;t>>=1}v<<=d-1;while(v.toString(2).length>=d){let s=v.toString(2).length-d;v^=p<<s}return v}function build(mask){const m=matrix();setFinder(m,0,0);setFinder(m,n-7,0);setFinder(m,0,n-7);for(const yy of [6,28,50])for(const xx of [6,28,50])if(m[yy][xx]===null)for(let y=-2;y<=2;y++)for(let z=-2;z<=2;z++)m[yy+y][xx+z]=(Math.max(Math.abs(y),Math.abs(z))===2||(!y&&!z))?1:0;for(let i=8;i<n-8;i++){if(m[6][i]===null)m[6][i]=i%2?0:1;if(m[i][6]===null)m[i][6]=i%2?0:1}const fmt=((8|mask)<<10|bch(8|mask,0x537))^0x5412;for(let i=0;i<15;i++){const v=(fmt>>i)&1;m[i<6?i:i<8?i+1:n-15+i][8]=v;m[8][i<8?n-i-1:i<9?15-i:14-i]=v}m[n-8][8]=1;const vb=(ver<<12)|bch(ver,0x1f25);for(let i=0;i<18;i++){const v=(vb>>i)&1;m[Math.floor(i/3)][n-11+i%3]=v;m[n-11+i%3][Math.floor(i/3)]=v}let k=0,up=true;for(let col=n-1;col>0;col-=2){if(col===6)col--;for(let q=0;q<n;q++){let row=up?n-1-q:q;for(let c=0;c<2;c++){let xx=col-c;if(m[row][xx]===null){let bit=raw[k++]||0;const invert=[(r,z)=>(r+z)%2===0,(r,z)=>r%2===0,(r,z)=>z%3===0,(r,z)=>(r+z)%3===0,(r,z)=>(Math.floor(r/2)+Math.floor(z/3))%2===0,(r,z)=>(r*z)%2+(r*z)%3===0,(r,z)=>((r*z)%2+(r*z)%3)%2===0,(r,z)=>((r+z)%2+(r*z)%3)%2===0][mask];m[row][xx]=invert(row,xx)?bit^1:bit}}up=!up}return m}function score(m){let s=0;for(let y=0;y<n;y++)for(let x=0;x<n;x++){let same=0,v=m[y][x];for(const[a,b]of[[1,0],[-1,0],[0,1],[0,-1]])if(m[y+a]?.[x+b]===v)same++;if(same>2)s+=3+same-2}for(let y=0;y<n-1;y++)for(let x=0;x<n-1;x++)if(m[y][x]===m[y+1][x]&&m[y][x]===m[y][x+1]&&m[y][x]===m[y+1][x+1])s+=3;let dark=m.flat().filter(Boolean).length;s+=Math.abs(100*dark/(n*n)-50)/5*10;return s}let best=build(0),bs=score(best);for(let i=1;i<8;i++){let q=build(i),z=score(q);if(z<bs){best=q;bs=z}}let cells="";for(let y=0;y<n;y++)for(let x=0;x<n;x++)if(best[y][x])cells+='<rect x="'+(x+4)+'" y="'+(y+4)+'" width="1" height="1"/>';return '<svg class="qr" viewBox="0 0 '+(n+8)+' '+(n+8)+'" role="img" aria-label="Authenticator setup QR code"><rect width="100%" height="100%" fill="white"/>'+cells+'</svg>'}
function provision(message=""){set("Step 2 of 4 · authenticator",'<h1><span class="icon">📱</span>Add your authenticator</h1><p>Scan the QR code with your authenticator app. Or copy the setup key instead.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice" id="setupBox"><p class="small">Select “Make setup key” first.</p></div><button class="primary" id="make">Make setup key</button>'+help());by("make").onclick=makeProvision}
async function makeProvision(){const r=await api("/api/provision");if(!r.ok)return provision(r.message);by("setupBox").innerHTML=qr(r.uri)+'<label for="secret">Setup key</label><p class="hint">You can reveal it only if you need it.</p><div id="secret" class="code hidden">'+esc(r.secret)+'</div><button class="secondary" id="toggleSecret">Show setup key</button><button class="secondary" id="copy">Copy setup key</button>';by("toggleSecret").onclick=()=>{const h=by("secret").classList.toggle("hidden");by("toggleSecret").textContent=h?"Show setup key":"Hide setup key"};by("copy").onclick=async()=>{try{await navigator.clipboard.writeText(r.secret);log("Authenticator setup key copied.")}catch{alert("Copy was not available. Show the setup key instead.")}};log("Simulated authenticator provisioning created.");testOutput("Authenticator setup key",r.testSecret);testOutput("Authenticator code",r.testOtp);by("make").textContent="Continue to check code";by("make").onclick=otp}
function otp(message=""){set("Step 3 of 4 · check authenticator",'<h1><span class="icon">✅</span>Check your authenticator</h1><p>Enter the six digits from your authenticator app.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<form id="otpForm"><label for="otpCode">Authenticator code</label><p class="hint">Example: 123456</p><input id="otpCode" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required><button class="primary">Check code</button></form><button class="secondary" id="newCode">Get a new test code</button>'+help());by("newCode").onclick=async()=>{const r=await api("/api/totp/test");if(!r.ok)return otp(r.message);testOutput("Current authenticator code",r.testOtp)};by("otpForm").onsubmit=async e=>{e.preventDefault();const r=await api("/api/otp/verify",{code:by("otpCode").value});if(r.ok){log("Authenticator code checked.");backups()}else otp(r.message)}}
function backups(message=""){backupCodes=[];set("Step 4 of 4 · backup codes",'<h1><span class="icon">🧾</span>Save backup codes</h1><p>These codes help if you lose your phone. Keep them somewhere private.</p>'+(message?'<div class="card error">'+esc(message)+'</div>':'')+'<div class="card notice"><p id="codesHelp" class="small">No codes made yet.</p><div id="codes" class="code hidden"></div><button class="secondary hidden" id="toggleCodes">Show backup codes</button><button class="secondary" id="copyCodes">Copy backup codes</button></div><button class="primary" id="makeCodes">Make backup codes</button><button class="secondary hidden" id="finish">I saved my codes</button>'+help());by("makeCodes").onclick=async()=>{const r=await api("/api/backups/generate");if(!r.ok)return backups(r.message);backupCodes=r.codes;by("codes").textContent=backupCodes.join("\\n");by("codesHelp").textContent="Your new backup codes are hidden. Show them when you are ready to save them.";by("toggleCodes").classList.remove("hidden");by("finish").classList.remove("hidden");by("makeCodes").textContent="Make new backup codes";log("Simulated backup recovery codes created.");if(testMode)log("[ACADEMIC TEST MODE] Backup recovery codes:",backupCodes)};by("toggleCodes").onclick=()=>{const h=by("codes").classList.toggle("hidden");by("toggleCodes").textContent=h?"Show backup codes":"Hide backup codes"};by("copyCodes").onclick=async()=>{if(!backupCodes.length)return alert("Make backup codes first.");try{await navigator.clipboard.writeText(backupCodes.join("\\n"));log("Backup codes copied.")}catch{alert("Copy was not available. Show the backup codes instead.")}};by("finish").onclick=async()=>{const r=await api("/api/complete");if(r.ok)success();else backups(r.message)}}
function success(){set("MFA setup complete",'<h1><span class="icon">🎉</span>You are all set</h1><div class="card success"><p><strong>Your authenticator and backup codes are ready.</strong></p></div><button class="primary" id="logout">Log out safely</button>');by("logout").onclick=async()=>{await api("/api/logout");csrf="";log("Secure session logged out.");signedOut("You are logged out.")}}
function signedOut(message){set("Secure setup",'<h1><span class="icon">🔒</span>Setup closed</h1><div class="card notice"><p>'+esc(message)+'</p></div><button class="primary" id="open">Open secure setup</button>');by("open").onclick=()=>location.reload()}
document.addEventListener("click",e=>{const t=e.target;if(t instanceof HTMLElement&&t.dataset.start)identity()});
fetch("/api/bootstrap",{credentials:"same-origin"}).then(async r=>{const x=await r.json();testMode=!!x.testMode;demoEnabled=!!x.demoEnabled;if(!x.ok)return signIn(x.message);csrf=x.csrf;identity()}).catch(()=>signedOut("Please refresh the page and try again."));
})();</script></body></html>`;
}

async function handleApi(request: Request, pathname: string): Promise<Response> {
  if (pathname === "/api/bootstrap" && request.method === "GET") {
    const owner = requireOwner(request);
    if (owner instanceof Response) {
      return json({ ok: false, message: "Sign in is required before MFA setup.", testMode: TEST_MODE, demoEnabled: DEMO_TEST_ENABLED }, 401);
    }
    return json({ ok: true, csrf: owner.csrf, testMode: TEST_MODE && owner.fixture, demoEnabled: DEMO_TEST_ENABLED });
  }

  /* Disabled by default; only explicit MFA_TEST_MODE=1 and MFA_DEMO_MODE=1 enables this endpoint. */
  if (pathname === "/api/demo/login" && request.method === "POST") {
    if (!DEMO_TEST_ENABLED || !trustedSameOrigin(request)) {
      return json({ ok: false, message: "The test demo sign-in is not enabled." }, 403);
    }
    const session = createAuthenticatedSession(false, true);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(session.id) });
  }

  if (pathname === "/api/test/login" && request.method === "POST") {
    if (!trustedSameOrigin(request)) return json({ ok: false, message: "The academic fixture sign-in could not be completed." }, 403);
    const data = await body(request);
    if (!TEST_MODE || !data || typeof data.fixture !== "string" || !equal(data.fixture, ACADEMIC_FIXTURE_CODE)) {
      return json({ ok: false, message: "The academic fixture sign-in could not be completed." }, 403);
    }
    const session = createAuthenticatedSession(false, true);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(session.id) });
  }

  if (request.method !== "POST") return genericError(405);
  const owner = requireOwner(request);
  if (owner instanceof Response) return owner;
  if (!csrfOkay(request, owner)) return genericError(403);
  const data = await body(request);
  if (!data) return genericError();

  if (pathname === "/api/logout") {
    sessions.delete(owner.id);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", true) });
  }

  const record = accountRecord(owner.accountId);
  const locked = lockMessage(record);
  if (locked) return json({ ok: false, message: locked }, 429);

  if (pathname === "/api/identity/send") {
    if (!validPhone(data.phone) || !equal(String(data.phone), ACCOUNT_PHONE_SUFFIX)) {
      failure(record);
      return json({ ok: false, message: "Those phone digits did not match. Enter the last four digits, for example 4821." }, 400);
    }
    const code = TEST_MODE && owner.fixture ? ACADEMIC_IDENTITY_CODE : String(randomBytes(4).readUInt32BE(0) % 1_000_000).padStart(6, "0");
    record.identityCode = protectedCode(code, owner.accountId);
    return json(TEST_MODE && owner.fixture ? { ok: true, testCode: code } : { ok: true });
  }

  if (pathname === "/api/identity/verify") {
    if (!validOtp(data.code)) {
      failure(record);
      return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    }
    const value = record.identityCode;
    if (!value || value.accountId !== owner.accountId || value.used || value.expiresAt < now() || !equal(value.hash, codeHash(String(data.code)))) {
      failure(record);
      return json({ ok: false, message: "That code did not work. Check the six numbers or ask for a new code." }, 400);
    }
    value.used = true;
    clearFailures(record);
    sessions.delete(owner.id);
    const replacement = createAuthenticatedSession(true, owner.fixture);
    return json({ ok: true, csrf: replacement.csrf }, 200, { "Set-Cookie": sessionCookie(replacement.id) });
  }

  if (!owner.identityVerified) return json({ ok: false, message: "Please complete the identity check first." }, 403);

  if (pathname === "/api/provision") {
    const secret = TEST_MODE && owner.fixture ? ACADEMIC_TOTP_SECRET : base32Secret();
    /* New enrolment invalidates all old recovery codes and completion state for this owner only. */
    record.enrolmentId = token(18);
    record.recoveryHashes = [];
    record.recoveryGeneratedEnrolment = undefined;
    record.otpVerified = false;
    record.otpVerifiedEnrolment = undefined;
    record.lastAcceptedTotpCounter = undefined;
    record.mfaEnabled = false;
    Object.assign(record, encrypt(secret));
    const result: Record<string, unknown> = { ok: true, secret, uri: provisioningUri(secret) };
    if (TEST_MODE && owner.fixture) {
      result.testSecret = secret;
      result.testOtp = totp(secret);
    }
    return json(result);
  }

  if (pathname === "/api/totp/test") {
    const secret = decrypt(record);
    if (!secret || !record.enrolmentId) return json({ ok: false, message: "Make a setup key first." }, 400);
    return json(TEST_MODE && owner.fixture ? { ok: true, testOtp: totp(secret) } : { ok: true });
  }

  if (pathname === "/api/otp/verify") {
    if (!validOtp(data.code)) {
      failure(record);
      return json({ ok: false, message: "Enter six numbers, for example 123456." }, 400);
    }
    const secret = decrypt(record);
    const counter = secret ? matchingTotpCounter(secret, String(data.code)) : null;
    if (!record.enrolmentId || counter === null || record.lastAcceptedTotpCounter === counter) {
      failure(record);
      return json({ ok: false, message: counter !== null ? "That code was already used. Wait for a new code, then try again." : "That code did not work. Check the six numbers or get a new code." }, 400);
    }
    record.lastAcceptedTotpCounter = counter;
    record.otpVerified = true;
    record.otpVerifiedEnrolment = record.enrolmentId;
    clearFailures(record);
    return json({ ok: true });
  }

  if (pathname === "/api/backups/generate") {
    if (!record.enrolmentId || !record.otpVerified || record.otpVerifiedEnrolment !== record.enrolmentId) {
      return json({ ok: false, message: "Please check your authenticator code first." }, 403);
    }
    const codes: string[] = TEST_MODE && owner.fixture ? [...ACADEMIC_RECOVERY_CODES] : [];
    while (codes.length < 8) {
      const raw = randomBytes(8).toString("hex").toUpperCase();
      codes.push(`${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`);
    }
    record.recoveryHashes = codes.map((code, i) => recoveryHash(code, TEST_MODE && owner.fixture ? Buffer.alloc(16, i + 1) : randomBytes(16)));
    record.recoveryGeneratedEnrolment = record.enrolmentId;
    return json({ ok: true, codes });
  }

  if (pathname === "/api/complete") {
    if (!record.enrolmentId || !record.otpVerified || record.otpVerifiedEnrolment !== record.enrolmentId) {
      return json({ ok: false, message: "Please check your authenticator code before continuing." }, 400);
    }
    if (!record.recoveryHashes.length || record.recoveryGeneratedEnrolment !== record.enrolmentId) {
      return json({ ok: false, message: "Make new backup codes for this setup before continuing." }, 400);
    }
    record.mfaEnabled = true;
    return json({ ok: true });
  }

  if (pathname === "/api/recovery/verify") {
    if (!record.mfaEnabled) return json({ ok: false, message: "MFA setup must be completed first." }, 403);
    const code = normalRecovery(data.code);
    if (!code) {
      failure(record);
      return json({ ok: false, message: "Enter a backup code in this format: A1B2-C3D4-E5F6-7890." }, 400);
    }
    let matched = -1;
    for (let i = 0; i < record.recoveryHashes.length; i++) {
      const item = record.recoveryHashes[i];
      const attempt = scryptSync(code, Buffer.from(item.salt, "base64"), 32).toString("base64");
      if (equal(attempt, item.hash)) matched = i;
    }
    if (matched < 0) {
      failure(record);
      return json({ ok: false, message: "That backup code did not work. Check it and try again." }, 400);
    }
    record.recoveryHashes.splice(matched, 1);
    clearFailures(record);
    return json({ ok: true });
  }

  return genericError(404);
}

const server = Bun.serve({
  port: PORT,
  hostname: "0.0.0.0",
  tls: { cert: "certs/cert.pem", key: "certs/key.pem" },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === "OPTIONS") {
        const origin = request.headers.get("origin") || "";
        if (!TRUSTED_ORIGINS.has(origin)) return new Response(null, { status: 403, headers: headers() });
        return new Response(null, { status: 204, headers: headers("", {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        }) });
      }
      if (url.pathname === "/" && request.method === "GET") {
        const nonce = randomBytes(24).toString("base64");
        const live = getLiveSession(request);
        if (!live && trustedOwnerAssertion(request)) {
          const session = createAuthenticatedSession(false, false);
          return new Response(page(nonce), { headers: headers(nonce, { "Content-Type": "text/html; charset=utf-8", "Set-Cookie": sessionCookie(session.id) }) });
        }
        return new Response(page(nonce), { headers: headers(nonce, { "Content-Type": "text/html; charset=utf-8" }) });
      }
      if (url.pathname.startsWith("/api/")) return await handleApi(request, url.pathname);
      return new Response("Not found", { status: 404, headers: headers("", { "Content-Type": "text/plain; charset=utf-8" }) });
    } catch {
      return new Response("Something went wrong. Please try again.", { status: 500, headers: headers("", { "Content-Type": "text/plain; charset=utf-8" }) });
    }
  },
});

console.log(`MFA enrolment server listening on https://localhost:${server.port}`);
