
import { readFileSync } from "node:fs";

/*
 MFA enrolment system.
 Requirement 1: account-owned MFA records, session ownership, and CSRF.
 Requirement 2: restrictive headers, secure cookies, CORS, TLS, generic errors.
 Requirement 3: encrypted OTP seeds and PBKDF2-hashed recovery codes.
 Requirement 4: validated inputs and output encoding.
 Requirement 5: expiring/single-use verification values and rate limits.

 IMPORTANT TEST FIXTURE POLICY:
 MFA_NON_PRODUCTION_TEST_MODE=enabled is the only opt-in for deterministic fixtures.
 Fixture logging is prohibited in deployed/security-evaluated production mode.
*/
const PORT = Number(Bun.env.PORT || 3000);
const TEST_ONLY = Bun.env.MFA_NON_PRODUCTION_TEST_MODE === "enabled" && Bun.env.NODE_ENV !== "production";
const COOKIE = "__Host_mfa_session";
const IDLE = 30 * 60_000, ABSOLUTE = 8 * 60 * 60_000, CODE_LIFE = 15 * 60_000;
const LOCK = 10 * 60_000, MAX_ATTEMPTS = 5;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ISSUER = "Harbor Bank";
const encoder = new TextEncoder();

const origins = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);
const DEMO_ACCOUNT = { id: "account-marcus-demo", email: "marcus@example.com", password: "MarcusDemo!54" };
const TEST_SECRETS = ["JBSWY3DPEHPK3PXPJBSWY", "KRUGS4ZANFZSAYJAON2X"];

type Protected = { cipher: string; iv: string };
type RecoveryHash = { salt: string; hash: string };
type OneCode = { hash: string; expires: number; used: boolean; attempts: number; lockedUntil: number };
type Session = {
  id: string; csrf: string; created: number; seen: number; account?: string; email?: string;
  identity?: OneCode; resends: number; resendStarted: number; setupCount: number;
};
type MfaRecord = {
  accountId: string; enabled: boolean; otpSecret?: Protected; recoveryHashes: RecoveryHash[];
  provisioned: boolean; testOtp?: OneCode; recoveryRound: number; otpAttempts: number;
  otpLockedUntil: number; recoveryAttempts: number; recoveryLockedUntil: number; usedTotpSteps: Set<number>;
};

const mfaRecords = new Map<string, MfaRecord>();
const sessions = new Map<string, Session>();
const loginLimits = new Map<string, { attempts: number; lockedUntil: number }>();
const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
const rateKey = crypto.getRandomValues(new Uint8Array(32));

function b64(bytes: Uint8Array) { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); }
function unb64(v: string) { return Uint8Array.from(atob(v), x => x.charCodeAt(0)); }
function token(n = 32) { return b64(crypto.getRandomValues(new Uint8Array(n))).replace(/[+/=]/g, x => x === "+" ? "-" : x === "/" ? "_" : ""); }
function secureText(chars: string, length: number) {
  const out: string[] = [], limit = 256 - 256 % chars.length;
  while (out.length < length) for (const n of crypto.getRandomValues(new Uint8Array(length - out.length))) if (n < limit) out.push(chars[n % chars.length]);
  return out.join("");
}
async function digest(v: string) { return b64(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(v)))); }
function equal(a: string, b: string) { if (a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; }
async function rateId(email: string) { return digest(`${b64(rateKey)}:${email}`); }
function identityCode() { return TEST_ONLY ? "123456" : secureText("0123456789", 6); }
function testBase32(n: number, len = 5) { let s = ""; while (s.length < len) { s = B32[n % 32] + s; n = Math.floor(n / 32); } return s; }
function recoveryCodes(round: number) {
  if (TEST_ONLY) return Array.from({ length: 8 }, (_, i) => `${testBase32(round * 16 + i + 1)}-${testBase32(round * 16 + i + 129)}`);
  const values = new Set<string>(); while (values.size < 8) values.add(`${secureText(B32, 5)}-${secureText(B32, 5)}`); return [...values];
}
/* Requirement 3: AES-GCM protects the shared secret at rest. */
async function encrypt(v: string): Promise<Protected> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["encrypt"]);
  return { iv: b64(iv), cipher: b64(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(v)))) };
}
async function decrypt(v: Protected) {
  const key = await crypto.subtle.importKey("raw", encryptionKey, "AES-GCM", false, ["decrypt"]);
  return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(v.iv) }, key, unb64(v.cipher)));
}
async function recoveryKdf(code: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(code), "PBKDF2", false, ["deriveBits"]);
  return b64(new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations: 210000 }, key, 256)));
}
async function hashRecovery(code: string): Promise<RecoveryHash> { const salt = b64(crypto.getRandomValues(new Uint8Array(16))); return { salt, hash: await recoveryKdf(code, salt) }; }
async function recoveryMatches(v: RecoveryHash, code: string) { return equal(v.hash, await recoveryKdf(code, v.salt)); }
function base32Bytes(v: string) {
  let bits = "";
  for (const c of v.replace(/=/g, "").toUpperCase()) { const i = B32.indexOf(c); if (i < 0) throw Error("invalid base32"); bits += i.toString(2).padStart(5, "0"); }
  const out: number[] = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return new Uint8Array(out);
}
async function totp(secret: string, step: number) {
  const counter = new Uint8Array(8); let n = BigInt(step);
  for (let i = 7; i >= 0; i--) { counter[i] = Number(n & 255n); n >>= 8n; }
  const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, counter)), offset = mac[19] & 15;
  const value = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(value % 1_000_000).padStart(6, "0");
}
function uri(email: string, secret: string) { return `otpauth://totp/${encodeURIComponent(ISSUER)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(ISSUER)}&algorithm=SHA1&digits=6&period=30`; }
function newRecord(accountId: string): MfaRecord { return { accountId, enabled: false, recoveryHashes: [], provisioned: false, recoveryRound: 0, otpAttempts: 0, otpLockedUntil: 0, recoveryAttempts: 0, recoveryLockedUntil: 0, usedTotpSteps: new Set() }; }
function ownedRecord(session: Session) {
  if (session.account !== DEMO_ACCOUNT.id || session.email !== DEMO_ACCOUNT.email) return;
  let record = mfaRecords.get(session.account); if (!record) { record = newRecord(session.account); mfaRecords.set(session.account, record); } return record;
}
function newSession(account?: string, email?: string) {
  const now = Date.now(), s: Session = { id: token(), csrf: token(), created: now, seen: now, account, email, resends: 0, resendStarted: now, setupCount: 0 };
  sessions.set(s.id, s); return s;
}
function cookieValues(request: Request) {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get("cookie") || "").split(";")) { const i = part.indexOf("="); if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); }
  return out;
}
function sessionFor(request: Request) {
  const s = sessions.get(cookieValues(request)[COOKIE]);
  if (!s || Date.now() - s.seen > IDLE || Date.now() - s.created > ABSOLUTE) { if (s) sessions.delete(s.id); return; }
  s.seen = Date.now(); return s;
}
function sessionCookie(s: Session) { return `${COOKIE}=${encodeURIComponent(s.id)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${ABSOLUTE / 1000}`; }
function standardHeaders(origin?: string | null, nonce?: string) {
  const h = new Headers({
    "Content-Security-Policy": `default-src 'self'; script-src 'self' 'nonce-${nonce || "none"}'; style-src 'self' 'nonce-${nonce || "none"}'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Cache-Control": "no-store"
  });
  if (origin && origins.has(origin)) { h.set("Access-Control-Allow-Origin", origin); h.set("Access-Control-Allow-Credentials", "true"); h.set("Vary", "Origin"); }
  return h;
}
function json(body: unknown, status = 200, req?: Request, extra?: Record<string, string>) {
  const h = standardHeaders(req?.headers.get("origin")); h.set("Content-Type", "application/json; charset=utf-8");
  for (const [k, v] of Object.entries(extra || {})) h.set(k, v); return new Response(JSON.stringify(body), { status, headers: h });
}
function fail(message: string, status: number, req: Request) { return json({ ok: false, message }, status, req); }
function allowedOrigin(req: Request) { const o = req.headers.get("origin"); return !o || origins.has(o); }
async function bodyOf(req: Request): Promise<Record<string, unknown> | undefined> {
  if (Number(req.headers.get("content-length") || 0) > 10_000) return;
  try { const b = await req.json(); if (!b || typeof b !== "object" || Array.isArray(b) || "userId" in b || "accountId" in b || "redirect" in b) return; return b as Record<string, unknown>; } catch { return; }
}
function csrf(s: Session, b: Record<string, unknown>) { return typeof b.csrf === "string" && b.csrf.length > 30 && equal(s.csrf, b.csrf); }
function waitMessage(until: number) { return `Too many tries were made. Please wait until ${new Date(until).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}, then try again.`; }
async function sendIdentity(s: Session) { const code = identityCode(); s.identity = { hash: await digest(code), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, lockedUntil: 0 }; return code; }
/* Sensitive fixture values are returned only with the unmistakable non-production flag. */
function fixture(values: Record<string, string | string[]>) { return TEST_ONLY ? { testMode: true, testValues: values } : { testMode: false }; }

/*
 Standards-compliant QR Model 2 encoder: Version 8, error correction level L.
 Version 8-L holds 194 byte-mode data codewords, enough for this otpauth URI.
 It uses ISO/IEC 18004 byte mode, Reed-Solomon ECC, format/version information,
 all eight masks, and penalty selection. No assets, package, or network call.
*/
const QR_SIZE = 49, QR_DATA = 194, QR_ECC = 24;
const gfExp = new Uint8Array(512), gfLog = new Uint8Array(256);
(() => { let x = 1; for (let i = 0; i < 255; i++) { gfExp[i] = x; gfLog[x] = i; x <<= 1; if (x & 256) x ^= 0x11d; } for (let i = 255; i < 512; i++) gfExp[i] = gfExp[i - 255]; })();
function qrMul(a: number, b: number) { return !a || !b ? 0 : gfExp[gfLog[a] + gfLog[b]]; }
function qrEcc(data: number[]) {
  const gen = [1];
  for (let i = 0; i < QR_ECC; i++) { const next = Array(gen.length + 1).fill(0); for (let j = 0; j < gen.length; j++) { next[j] ^= gen[j]; next[j + 1] ^= qrMul(gen[j], gfExp[i]); } gen.splice(0, gen.length, ...next); }
  const rem = Array(QR_ECC).fill(0);
  for (const value of data) { const lead = value ^ rem.shift()!; rem.push(0); for (let i = 0; i < QR_ECC; i++) rem[i] ^= qrMul(gen[i + 1], lead); }
  return rem;
}
function qrBch(value: number, poly: number) { let d = value; const p = Math.floor(Math.log2(poly)); while (Math.floor(Math.log2(d)) >= p) d ^= poly << (Math.floor(Math.log2(d)) - p); return d; }
function qrMask(mask: number, r: number, c: number) {
  if (mask === 0) return (r + c) % 2 === 0;
  if (mask === 1) return r % 2 === 0;
  if (mask === 2) return c % 3 === 0;
  if (mask === 3) return (r + c) % 3 === 0;
  if (mask === 4) return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
  if (mask === 5) return (r * c) % 2 + (r * c) % 3 === 0;
  if (mask === 6) return ((r * c) % 2 + (r * c) % 3) % 2 === 0;
  return ((r * c) % 3 + (r + c) % 2) % 2 === 0;
}
function qrMatrix(text: string) {
  const bytes = [...encoder.encode(text)];
  if (bytes.length > 190) throw Error("setup data is too long");
  const bits: number[] = [];
  const put = (n: number, len: number) => { for (let i = len - 1; i >= 0; i--) bits.push((n >>> i) & 1); };
  put(4, 4); put(bytes.length, 8); for (const b of bytes) put(b, 8);
  for (let i = 0; i < 4 && bits.length < QR_DATA * 8; i++) bits.push(0);
  while (bits.length % 8) bits.push(0);
  const stream: number[] = []; for (let i = 0; i < bits.length; i += 8) stream.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  for (let pad = 0; stream.length < QR_DATA; pad ^= 1) stream.push(pad ? 0x11 : 0xec);
  const blocks = [stream.slice(0, 97), stream.slice(97, 194)], ecc = blocks.map(qrEcc), codewords: number[] = [];
  for (let i = 0; i < 97; i++) for (const b of blocks) codewords.push(b[i]);
  for (let i = 0; i < QR_ECC; i++) for (const b of ecc) codewords.push(b[i]);
  const dataBits: number[] = []; for (const b of codewords) putTo(dataBits, b, 8);
  let best: boolean[][] = [], score = Infinity;
  for (let mask = 0; mask < 8; mask++) { const m = qrBuild(dataBits, mask); const p = qrPenalty(m); if (p < score) { score = p; best = m; } }
  return best;
}
function putTo(a: number[], n: number, len: number) { for (let i = len - 1; i >= 0; i--) a.push((n >>> i) & 1); }
function qrBuild(bits: number[], mask: number) {
  const m: (boolean | null)[][] = Array.from({ length: QR_SIZE }, () => Array(QR_SIZE).fill(null));
  const set = (r: number, c: number, v: boolean) => { if (r >= 0 && r < QR_SIZE && c >= 0 && c < QR_SIZE) m[r][c] = v; };
  const finder = (r: number, c: number) => { for (let y = -1; y <= 7; y++) for (let x = -1; x <= 7; x++) set(r + y, c + x, y >= 0 && y <= 6 && x >= 0 && x <= 6 && (y === 0 || y === 6 || x === 0 || x === 6 || (y >= 2 && y <= 4 && x >= 2 && x <= 4))); };
  finder(0, 0); finder(0, 42); finder(42, 0);
  for (const r of [6, 24, 42]) for (const c of [6, 24, 42]) if (!((r === 6 && c === 6) || (r === 6 && c === 42) || (r === 42 && c === 6))) for (let y = -2; y <= 2; y++) for (let x = -2; x <= 2; x++) set(r + y, c + x, Math.max(Math.abs(x), Math.abs(y)) !== 1);
  for (let i = 8; i < QR_SIZE - 8; i++) { if (m[6][i] === null) set(6, i, i % 2 === 0); if (m[i][6] === null) set(i, 6, i % 2 === 0); }
  for (let i = 0; i < 9; i++) { if (m[8][i] === null) set(8, i, false); if (m[i][8] === null) set(i, 8, false); }
  for (let i = 0; i < 8; i++) { set(8, QR_SIZE - 1 - i, false); set(QR_SIZE - 1 - i, 8, false); }
  for (let i = 0; i < 6; i++) { set(i, QR_SIZE - 11, false); set(QR_SIZE - 11, i, false); }
  set(QR_SIZE - 8, 8, true);
  let bit = 0, upward = true;
  for (let col = QR_SIZE - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (let i = 0; i < QR_SIZE; i++) { const r = upward ? QR_SIZE - 1 - i : i; for (let c = col; c >= col - 1; c--) if (m[r][c] === null) { let v = bit < bits.length ? !!bits[bit++] : false; if (qrMask(mask, r, c)) v = !v; m[r][c] = v; } }
    upward = !upward;
  }
  const format = ((1 << 3) | mask) << 10, fmt = (format | qrBch(format, 0x537)) ^ 0x5412;
  for (let i = 0; i < 15; i++) { const v = ((fmt >>> i) & 1) === 1; if (i < 6) set(i, 8, v); else if (i < 8) set(i + 1, 8, v); else set(QR_SIZE - 15 + i, 8, v); if (i < 8) set(8, QR_SIZE - i - 1, v); else if (i < 9) set(8, 15 - i, v); else set(8, 15 - i - 1, v); }
  const verBase = 8 << 12, version = verBase | qrBch(verBase, 0x1f25);
  for (let i = 0; i < 18; i++) { const v = ((version >>> i) & 1) === 1; set(Math.floor(i / 3), QR_SIZE - 11 + i % 3, v); set(QR_SIZE - 11 + i % 3, Math.floor(i / 3), v); }
  return m.map(row => row.map(Boolean));
}
function qrPenalty(m: boolean[][]) {
  let p = 0, n = QR_SIZE;
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) {
    const v = m[r][c]; let same = 0; for (let y = -1; y <= 1; y++) for (let x = -1; x <= 1; x++) if ((x || y) && r + y >= 0 && r + y < n && c + x >= 0 && c + x < n && m[r + y][c + x] === v) same++; if (same > 5) p += 3 + same - 5;
  }
  for (let r = 0; r < n - 1; r++) for (let c = 0; c < n - 1; c++) if (m[r][c] === m[r + 1][c] && m[r][c] === m[r][c + 1] && m[r][c] === m[r + 1][c + 1]) p += 3;
  for (const row of [...m, ...Array.from({ length: n }, (_, c) => m.map(row => row[c]))]) for (let i = 0; i <= n - 7; i++) if (row.slice(i, i + 7).map(Number).join("") === "1011101") p += 40;
  let dark = 0; for (const row of m) for (const v of row) if (v) dark++; p += Math.floor(Math.abs(100 * dark / (n * n) - 50) / 5) * 10; return p;
}

const page = (nonce: string) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Harbor Bank · Security setup</title>
<style nonce="${nonce}">
:root{--ink:#162631;--muted:#50616c;--blue:#075d9f;--pale:#eef7fc;--line:#bdd0db;--good:#166f46;--bad:#a52e27}*{box-sizing:border-box}body{margin:0;background:#edf3f5;color:var(--ink);font:17px/1.65 Arial,Verdana,Tahoma,sans-serif;letter-spacing:.035em;word-spacing:.07em}.shell{max-width:560px;min-height:100vh;margin:auto;background:#fff;padding:20px 18px 38px}header{padding-bottom:14px;border-bottom:2px solid var(--line);margin-bottom:20px}.brand{font-weight:700;color:#034a80}.step{margin-top:7px;color:var(--muted);font-size:.92rem}h1{font-size:1.52rem;line-height:1.3;margin:0 0 12px}h2{font-size:1.15rem}.icon{display:block;font-size:2rem;margin-bottom:8px}p{margin:0 0 16px}label{display:block;font-weight:700;margin:18px 0 5px}.hint,.small{display:block;color:var(--muted);font-size:.9rem;margin-bottom:6px}input{width:100%;min-height:52px;border:2px solid #8297a4;border-radius:9px;padding:9px 12px;font:inherit;letter-spacing:inherit}input:focus{outline:3px solid #76b9e8;outline-offset:2px;border-color:var(--blue)}button{font:inherit;letter-spacing:inherit;cursor:pointer}.primary{width:100%;min-height:55px;border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:700;margin:21px 0 10px}.secondary{min-height:44px;border:2px solid var(--blue);border-radius:8px;background:#fff;color:#034a80;padding:6px 11px;margin:4px 5px 4px 0;font-weight:700}.text{border:0;background:none;color:#034a80;padding:8px 0;text-decoration:underline;font-weight:700}.card{background:var(--pale);border:1px solid var(--line);border-radius:12px;padding:16px;margin:17px 0}.notice,.error{padding:11px 13px;margin:15px 0;border-left:5px solid var(--good);background:#edf9f1}.error{border-left-color:var(--bad);background:#fff0ef}.status{min-height:1.8em}.test{border-left-color:#8a6400;background:#fff9e8}.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px}.recovery{font:15px monospace;letter-spacing:.07em;text-align:center;padding:9px 3px;border:1px solid var(--line);background:#fff;border-radius:6px}.qrwrap{text-align:center}.qr{display:grid;grid-template-columns:repeat(49,4px);width:212px;line-height:0;padding:8px;margin:auto;background:#fff;border:1px solid var(--line)}.qr i{height:4px;background:#fff}.qr i.b{background:#111}details{border-top:1px solid var(--line);padding-top:12px;margin-top:20px}summary{color:#034a80;font-weight:700;cursor:pointer}.logs{margin-top:25px;padding-top:14px;border-top:2px solid var(--line)}#logBox{min-height:76px;max-height:200px;overflow:auto;white-space:pre-wrap;border-radius:8px;padding:11px;background:#10232d;color:#e9f7ff;font:13px/1.55 monospace;letter-spacing:0}
</style></head><body><div class="shell"><header><div class="brand">◈ Harbor Bank</div><div id="step" class="step">Security setup</div></header><main id="app" aria-live="polite"></main><section class="logs"><h2>Logs</h2><p class="small">Private codes are not logged in normal operation.</p><div id="logBox">Ready. Nothing has been stored in this browser.</div></section></div>
<script nonce="${nonce}">(()=>{
const app=document.querySelector('#app'),step=document.querySelector('#step'),logBox=document.querySelector('#logBox');let csrf='',screen='signin',secret='',setupUri='',codes=[],shownSecret=true,shownCodes=true,test={},remaining=0;const logs=[];
const esc=x=>String(x).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
/* Normal operation logs only redacted event names. Test fixture logging is explicit opt-in. */
const say=(x,sensitive=false)=>{if(sensitive&&!test.testMode)return;logs.push(x);console.log(x);logBox.textContent=logs.join('\\n');logBox.scrollTop=logBox.scrollHeight};
const api=async(path,data,method='POST')=>{const r=await fetch(path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json'},body:method==='GET'?undefined:JSON.stringify(data||{})});const v=await r.json().catch(()=>({message:'We could not complete that step. Please try again.'}));if(!r.ok)throw Error(v.message);return v};
const help=()=>'<details><summary>Need help?</summary><p>Take your time. Nothing disappears while you read. You can retry safely.</p></details>';
const note=(v,label)=>v?'<div class="notice test"><strong>Non-production test value:</strong> '+esc(label)+': <strong>'+esc(Array.isArray(v)?v.join(', '):v)+'</strong></div>':'';
const status=(t,b=false)=>{const e=document.querySelector('#status');if(e){e.textContent=t;e.className=(b?'error':'notice')+' status'}};
function event(r,label){test={testMode:!!r.testMode,...(r.testValues||{})};if(test.testMode){const values=Object.entries(r.testValues||{}).map(([k,v])=>k+'='+(Array.isArray(v)?v.join(', '):v)).join(' | ');say('[NON-PRODUCTION TEST FIXTURE] '+label+' '+values,true)}else say('['+label+'] Completed securely. Private values are redacted.')}
function render(){
const v={
signin:()=>{step.textContent='Step 1 of 5 · Sign in';return '<span class="icon">🔐</span><h1>Sign in to start security setup</h1><p>Use your bank email and password. We will send one short identity code.</p><label for="email">Email address</label><span class="hint">Example: marcus@example.com</span><input id="email" type="email" autocomplete="email" placeholder="name@example.com"><label for="password">Password</label><span class="hint">Your password manager can fill this.</span><input id="password" type="password" autocomplete="current-password"><div id="status" class="status"></div><button class="primary" id="signin">Sign in</button><details><summary>Demo account details</summary><p>Email: marcus@example.com<br>Password: MarcusDemo!54</p></details>'+help()},
identity:()=>{step.textContent='Step 2 of 5 · Check it is you';return '<span class="icon">✉️</span><h1>Enter your identity code</h1><p>We sent a 6-digit code to your email.</p>'+note(test.identityCode,'Identity code')+'<label for="identity">6-digit code</label><span class="hint">Example: 123456</span><input id="identity" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="identityCheck">Check code</button><button class="text" id="resend">Send a new code</button>'+help()},
setup:()=>{step.textContent='Step 3 of 5 · Add your authenticator';return '<span class="icon">📱</span><h1>Add Harbor Bank to your authenticator app</h1><p>Scan this QR code. Or copy and paste the setup secret.</p><div class="card qrwrap"><div class="qr" id="qr" role="img" aria-label="Authenticator setup QR code"></div><p class="small">Use the manual secret below if scanning is difficult.</p></div><button class="secondary" id="copySecret">Copy setup secret</button><button class="secondary" id="copyUri">Copy setup link</button><button class="secondary" id="hideSecret">'+(shownSecret?'Hide secret':'Show secret')+'</button><label for="manual">Manual setup secret</label><span class="hint">Copy and paste this into your authenticator app.</span><input id="manual" type="'+(shownSecret?'text':'password')+'" spellcheck="false" value="'+esc(secret)+'"><div id="status" class="status"></div><button class="primary" id="appAdded">I added it to my app</button><button class="text" id="newSetup">Get a new setup code</button>'+help()},
otp:()=>{step.textContent='Step 4 of 5 · Check your authenticator';return '<span class="icon">🔢</span><h1>Enter the code from your authenticator app</h1><p>Use the current 6-digit code. Take your time.</p>'+note(test.authenticatorOtp,'Authenticator code')+'<label for="otp">Authenticator code</label><span class="hint">Example: 123456</span><input id="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456"><div id="status" class="status"></div><button class="primary" id="otpCheck">Check authenticator</button><button class="text" id="back">Go back to setup</button>'+help()},
backup:()=>{step.textContent='Step 5 of 5 · Save backup codes';const list=shownCodes?codes.map(x=>'<div class="recovery">'+esc(x)+'</div>').join(''):'<div class="recovery">•••••-•••••</div>'.repeat(8);return '<span class="icon">🧾</span><h1>Save your backup codes</h1><p>Keep these somewhere safe. Each code works once if you cannot use your authenticator.</p><div class="card"><div class="codes">'+list+'</div></div><button class="secondary" id="copyCodes">Copy all codes</button><button class="secondary" id="hideCodes">'+(shownCodes?'Hide codes':'Show codes')+'</button><label for="confirm">Paste one saved code</label><span class="hint">Example: ABCDE-23456. This check does not use up your code.</span><input id="confirm" autocomplete="one-time-code" placeholder="ABCDE-23456"><div id="status" class="status"></div><button class="primary" id="saveCheck">Check saved code</button>'+help()},
done:()=>{step.textContent='Complete · MFA is ready';return '<span class="icon">✓</span><h1>Your security setup is complete</h1><div class="notice">MFA is enabled. Your authenticator is ready. You have '+remaining+' backup codes available.</div><label for="useCode">Use a backup code</label><span class="hint">Example: ABCDE-23456. A used code cannot be used again.</span><input id="useCode" autocomplete="one-time-code" placeholder="ABCDE-23456"><div id="status" class="status"></div><button class="secondary" id="useRecovery">Use backup code</button><button class="secondary" id="regenerate">Replace backup codes</button><button class="primary" id="logout">Sign out</button>'+help()}};
app.innerHTML=v[screen]();if(screen==='setup')drawQr(setupUri);bind()}
function drawQr(text){const el=document.querySelector('#qr');if(!el)return;const matrix=qr(text);const f=document.createDocumentFragment();for(const row of matrix)for(const dark of row){const i=document.createElement('i');if(dark)i.className='b';f.append(i)}el.replaceChildren(f)}
const copy=async(v,msg)=>{try{await navigator.clipboard.writeText(v);status(msg)}catch{status('Copy did not work here. Select the text and copy it instead.',true)}};
function bind(){const on=(id,fn)=>{const e=document.querySelector('#'+id);if(e)e.onclick=fn};
on('signin',async()=>{try{const r=await api('/api/signin',{csrf,email:document.querySelector('#email').value,password:document.querySelector('#password').value});csrf=r.csrf;event(r,'IDENTITY DELIVERY');screen='identity';render()}catch(e){status(e.message,true)}});
on('resend',async()=>{try{const r=await api('/api/identity/resend',{csrf});event(r,'IDENTITY DELIVERY');status('A new code was sent. Use the new code.')}catch(e){status(e.message,true)}});
on('identityCheck',async()=>{try{const r=await api('/api/identity/verify',{csrf,code:document.querySelector('#identity').value});if(r.enabled){remaining=r.remaining;test={};screen='done';render()}else{const p=await api('/api/provision',{csrf});secret=p.secret;setupUri=p.uri;event(p,'AUTHENTICATOR PROVISIONING');screen='setup';render()}}catch(e){status(e.message,true)}});
on('copySecret',()=>copy(secret,'Setup secret copied. Paste it into your authenticator app.'));on('copyUri',()=>copy(setupUri,'Setup link copied.'));on('hideSecret',()=>{shownSecret=!shownSecret;render()});
on('newSetup',async()=>{try{const r=await api('/api/provision',{csrf});secret=r.secret;setupUri=r.uri;event(r,'AUTHENTICATOR PROVISIONING');render();status('A new setup secret is ready. Add this one instead.')}catch(e){status(e.message,true)}});
on('appAdded',async()=>{try{const r=await api('/api/provision/manual',{csrf,secret:document.querySelector('#manual').value});event(r,'AUTHENTICATOR READY');screen='otp';render()}catch(e){status(e.message,true)}});
on('back',()=>{screen='setup';render()});on('otpCheck',async()=>{try{const r=await api('/api/otp/verify',{csrf,code:document.querySelector('#otp').value});codes=r.recoveryCodes;event(r,'RECOVERY CODES');screen='backup';render()}catch(e){status(e.message,true)}});
on('copyCodes',()=>copy(codes.join('\\n'),'Backup codes copied. Store them in a safe place.'));on('hideCodes',()=>{shownCodes=!shownCodes;render()});
on('saveCheck',async()=>{try{const r=await api('/api/recovery/confirm',{csrf,code:document.querySelector('#confirm').value});remaining=r.remaining;codes=[];test={};screen='done';render()}catch(e){status(e.message,true)}});
on('useRecovery',async()=>{try{const r=await api('/api/recovery/use',{csrf,code:document.querySelector('#useCode').value});remaining=r.remaining;status(r.message)}catch(e){status(e.message,true)}});
on('regenerate',async()=>{try{const r=await api('/api/recovery/regenerate',{csrf});codes=r.recoveryCodes;event(r,'RECOVERY CODES');shownCodes=true;screen='backup';render();status('New backup codes are ready. The older codes no longer work.')}catch(e){status(e.message,true)}});
on('logout',async()=>{try{await api('/api/logout',{csrf});csrf='';secret='';setupUri='';codes=[];test={};say('[SESSION] Signed out. MFA settings remain on the account.');screen='signin';render()}catch(e){status(e.message,true)}});
}
(async()=>{try{const r=await api('/api/csrf',null,'GET');csrf=r.csrf;render()}catch{app.textContent='Secure setup is unavailable. Please refresh the page.'}})();
})();</script></body></html>`;

async function api(request: Request, path: string): Promise<Response> {
  if (!allowedOrigin(request)) return fail("This request is not allowed.", 403, request);
  if (request.method === "OPTIONS") {
    const h = standardHeaders(request.headers.get("origin")); h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS"); h.set("Access-Control-Allow-Headers", "Content-Type");
    return new Response(null, { status: 204, headers: h });
  }
  if (path === "/api/csrf" && request.method === "GET") {
    let s = sessionFor(request); if (!s) s = newSession();
    return json({ ok: true, csrf: s.csrf }, 200, request, { "Set-Cookie": sessionCookie(s) });
  }
  if (request.method !== "POST") return fail("That page is not available.", 404, request);
  const body = await bodyOf(request); if (!body) return fail("Please check the information and try again.", 400, request);

  if (path === "/api/signin") {
    const old = sessionFor(request); if (!old || !csrf(old, body)) return fail("Please refresh the page and try signing in again.", 403, request);
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "", password = typeof body.password === "string" ? body.password : "";
    const key = await rateId(email || "invalid"), limit = loginLimits.get(key), now = Date.now();
    if (limit && limit.lockedUntil > now) return fail("Sign-in is temporarily unavailable. Please wait a few minutes, then try again.", 429, request);
    const submitted = await digest(`${email}\0${password}`), expected = await digest(`${DEMO_ACCOUNT.email}\0${DEMO_ACCOUNT.password}`);
    const valid = /^[^\s@]+@[^\s@]+\.[^\s@]{2,100}$/.test(email) && password.length > 0 && password.length <= 200 && equal(submitted, expected);
    if (!valid) {
      const next = { attempts: (limit?.lockedUntil || 0) <= now ? (limit?.attempts || 0) + 1 : 1, lockedUntil: 0 }; if (next.attempts >= MAX_ATTEMPTS) next.lockedUntil = now + LOCK; loginLimits.set(key, next);
      return fail(next.lockedUntil ? "Sign-in is temporarily unavailable. Please wait a few minutes, then try again." : "Check your email and password, then try again.", next.lockedUntil ? 429 : 401, request);
    }
    loginLimits.delete(key); sessions.delete(old.id);
    const s = newSession(DEMO_ACCOUNT.id, DEMO_ACCOUNT.email), code = await sendIdentity(s);
    return json({ ok: true, csrf: s.csrf, ...fixture({ identityCode: code }) }, 200, request, { "Set-Cookie": sessionCookie(s) });
  }

  const session = sessionFor(request), record = session ? ownedRecord(session) : undefined;
  if (!session || !record) return fail("Your secure session has ended. Please sign in again.", 401, request);
  if (!csrf(session, body)) return fail("Please refresh the page before trying again.", 403, request);

  if (path === "/api/identity/resend") {
    if (!session.identity || session.identity.used) return fail("Please sign in again before requesting a code.", 403, request);
    if (session.identity.lockedUntil > Date.now()) return fail(waitMessage(session.identity.lockedUntil), 429, request);
    if (Date.now() - session.resendStarted > 600_000) { session.resendStarted = Date.now(); session.resends = 0; }
    if (++session.resends > 3) return fail("Too many new codes were requested. Please wait a few minutes, then try again.", 429, request);
    const code = await sendIdentity(session); return json({ ok: true, ...fixture({ identityCode: code }) }, 200, request);
  }
  if (path === "/api/identity/verify") {
    const code = typeof body.code === "string" ? body.code.trim() : "";
    if (!/^\d{6}$/.test(code)) return fail("Enter the 6-digit code, for example 123456.", 400, request);
    const identity = session.identity; if (!identity) return fail("Please request a new identity code.", 400, request);
    if (identity.lockedUntil > Date.now()) return fail(waitMessage(identity.lockedUntil), 429, request);
    if (identity.used || identity.expires < Date.now() || !equal(await digest(code), identity.hash)) { if (++identity.attempts >= MAX_ATTEMPTS) identity.lockedUntil = Date.now() + LOCK; return fail(identity.lockedUntil ? waitMessage(identity.lockedUntil) : "That code is not right or has been used. Check it, or request a new code.", identity.lockedUntil ? 429 : 400, request); }
    identity.used = true; return json({ ok: true, enabled: record.enabled, remaining: record.recoveryHashes.length }, 200, request);
  }
  if (path === "/api/provision") {
    if (!session.identity?.used) return fail("Check your identity code before setting up an authenticator.", 403, request);
    if (record.enabled) return fail("MFA is already enabled for this account.", 400, request);
    const secret = TEST_ONLY ? TEST_SECRETS[session.setupCount++ % TEST_SECRETS.length] : secureText(B32, 20);
    record.otpSecret = await encrypt(secret); record.provisioned = false; record.usedTotpSteps = new Set(); record.recoveryHashes = [];
    record.testOtp = TEST_ONLY ? { hash: await digest("654321"), expires: Date.now() + CODE_LIFE, used: false, attempts: 0, lockedUntil: 0 } : undefined;
    /* The setup secret/URI is intentionally displayed only on this authenticated setup screen, never logged or placed in a URL. */
    return json({ ok: true, secret, uri: uri(session.email!, secret), ...fixture({ authenticatorOtp: "654321" }) }, 200, request);
  }
  if (path === "/api/provision/manual") {
    const supplied = typeof body.secret === "string" ? body.secret.trim().toUpperCase().replaceAll(" ", "") : "";
    if (!session.identity?.used || !record.otpSecret || !/^[A-Z2-7]{16,64}$/.test(supplied)) return fail("Paste the full setup secret, then try again.", 400, request);
    if (!equal(supplied, await decrypt(record.otpSecret))) return fail("That setup secret does not match this account. Get a new setup code and try again.", 400, request);
    record.provisioned = true; return json({ ok: true, ...fixture({ authenticatorOtp: "654321" }) }, 200, request);
  }
  if (path === "/api/otp/verify") {
    const code = typeof body.code === "string" ? body.code.trim() : "", now = Date.now();
    if (!/^\d{6}$/.test(code)) return fail("Enter the 6-digit authenticator code, for example 123456.", 400, request);
    if (!record.provisioned || !record.otpSecret) return fail("Set up your authenticator before checking its code.", 403, request);
    if (record.otpLockedUntil > now) return fail(waitMessage(record.otpLockedUntil), 429, request);
    let used: number | undefined;
    if (TEST_ONLY) { const t = record.testOtp; if (t && !t.used && t.expires >= now && equal(await digest(code), t.hash)) { t.used = true; used = -1; } }
    else { const secret = await decrypt(record.otpSecret), step = Math.floor(now / 30_000); for (const c of [step - 1, step, step + 1]) if (!record.usedTotpSteps.has(c) && equal(code, await totp(secret, c))) { used = c; break; } }
    if (used === undefined) { if (++record.otpAttempts >= MAX_ATTEMPTS) record.otpLockedUntil = now + LOCK; return fail(record.otpLockedUntil ? waitMessage(record.otpLockedUntil) : `That authenticator code is not right, has expired, or has already been used. You have ${MAX_ATTEMPTS - record.otpAttempts} tries before a short wait.`, record.otpLockedUntil ? 429 : 400, request); }
    record.usedTotpSteps.add(used); record.otpAttempts = 0; record.enabled = true;
    const generated = recoveryCodes(++record.recoveryRound); record.recoveryHashes = await Promise.all(generated.map(hashRecovery));
    return json({ ok: true, recoveryCodes: generated, ...fixture({ recoveryCodes: generated }) }, 200, request);
  }
  if (path === "/api/recovery/regenerate") {
    if (!record.enabled || !session.identity?.used) return fail("Check your identity before replacing backup codes.", 403, request);
    const generated = recoveryCodes(++record.recoveryRound); record.recoveryHashes = await Promise.all(generated.map(hashRecovery)); record.recoveryAttempts = 0;
    return json({ ok: true, recoveryCodes: generated, ...fixture({ recoveryCodes: generated }) }, 200, request);
  }
  if (path === "/api/recovery/confirm" || path === "/api/recovery/use") {
    const code = typeof body.code === "string" ? body.code.trim().toUpperCase() : "", now = Date.now();
    if (!record.enabled || !/^[A-Z2-7]{5}-[A-Z2-7]{5}$/.test(code)) return fail("Paste one saved backup code in the format ABCDE-23456.", 400, request);
    if (record.recoveryLockedUntil > now) return fail(waitMessage(record.recoveryLockedUntil), 429, request);
    const matches = await Promise.all(record.recoveryHashes.map(v => recoveryMatches(v, code))), index = matches.findIndex(Boolean);
    if (index < 0) { if (++record.recoveryAttempts >= MAX_ATTEMPTS) record.recoveryLockedUntil = now + LOCK; return fail(record.recoveryLockedUntil ? waitMessage(record.recoveryLockedUntil) : "That backup code was not found. Paste one of the codes you saved.", record.recoveryLockedUntil ? 429 : 400, request); }
    record.recoveryAttempts = 0;
    if (path === "/api/recovery/use") { record.recoveryHashes.splice(index, 1); return json({ ok: true, message: "Your backup code was accepted and is now used.", remaining: record.recoveryHashes.length }, 200, request); }
    return json({ ok: true, message: "Your saved code was checked. It was not used up.", remaining: record.recoveryHashes.length }, 200, request);
  }
  if (path === "/api/logout") { sessions.delete(session.id); return json({ ok: true }, 200, request, { "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0` }); }
  return fail("That page is not available.", 404, request);
}

/* Requirement 2/3: Bun serves HTTPS using supplied localhost TLS certificates. */
Bun.serve({
  port: PORT,
  tls: { cert: readFileSync("certs/cert.pem", "utf8"), key: readFileSync("certs/key.pem", "utf8") },
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:") return new Response(null, { status: 301, headers: { Location: `https://${url.host}${url.pathname}` } });
      if (url.pathname.startsWith("/api/")) return api(request, url.pathname);
      if (url.pathname === "/" && request.method === "GET") { const nonce = token(18), headers = standardHeaders(request.headers.get("origin"), nonce); headers.set("Content-Type", "text/html; charset=utf-8"); return new Response(page(nonce), { headers }); }
      return new Response("Page not found.", { status: 404, headers: standardHeaders(request.headers.get("origin")) });
    } catch { return new Response("We could not complete that request. Please try again.", { status: 500, headers: standardHeaders() }); }
  }
});

console.log(`MFA enrolment server ready at https://localhost:${PORT}`);
