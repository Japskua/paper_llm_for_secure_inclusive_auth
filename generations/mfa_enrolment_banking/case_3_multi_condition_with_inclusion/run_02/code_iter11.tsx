<FILE>
import { existsSync, readFileSync } from "node:fs";

/*
 MFA Enrolment System
 Requirements 1–5: server-side session ownership, CSRF, TLS, restrictive
 headers, encrypted TOTP secrets, hashed recovery codes, validation and limits.
 Accessibility: short, predictable mobile screens with no reading timer.
*/

const PORT = Number(process.env.PORT || 3000);
const CERT_PATH = "certs/cert.pem";
const KEY_PATH = "certs/key.pem";
const TEST_MODE = process.env.MFA_TEST_MODE === "1";

if (!existsSync(CERT_PATH) || !existsSync(KEY_PATH)) {
  console.error("Configuration error.");
  process.exit(1);
}

const USER = { id: "account-marcus-internal", email: "marcus@example.com", password: "welcome123" };
const FIXTURES = {
  identityCode: "246810",
  authenticatorSecret: "JBSWY3DPEHPK3PXP",
  recoveryCodes: ["MANGO-23456", "RIVER-789AB", "CEDAR-45DEF", "TIGER-678JK", "MAPLE-9LMNP", "SUNNY-2QRST"],
};
const enc = new TextEncoder(), dec = new TextDecoder();
const SERVER_KEY = process.env.MFA_SERVER_KEY
  ? Buffer.from(process.env.MFA_SERVER_KEY, "hex").subarray(0, 32)
  : crypto.getRandomValues(new Uint8Array(32));
if (SERVER_KEY.length !== 32) { console.error("Configuration error."); process.exit(1); }
const aesKey = await crypto.subtle.importKey("raw", SERVER_KEY, "AES-GCM", false, ["encrypt", "decrypt"]);

type Pending = { digest: string; expires: number; used: boolean };
type Encrypted = { iv: string; data: string };
type Backup = { salt: string; verifier: string; used: boolean };
type RecordMfa = { secret: Encrypted; enabled: boolean; backups: Backup[]; usedCounters: number[] };
type Session = { userId: string; csrf: string; created: number; seen: number; identity?: Pending; pendingBackups?: string[] };
type Preauth = { csrf: string; expires: number };
type State = { failures: number; lockedUntil: number };

const sessions = new Map<string, Session>();
const preauths = new Map<string, Preauth>();
const records = new Map<string, RecordMfa>();
const security = new Map<string, State>();
const TRUSTED = new Set([`https://localhost:${PORT}`, `https://127.0.0.1:${PORT}`, `https://[::1]:${PORT}`]);

const IDENTITY_MS = 20 * 60_000, IDLE_MS = 30 * 60_000, ABSOLUTE_MS = 8 * 60 * 60_000, LOCK_MS = 5 * 60_000;

function token(bytes = 32) { return Buffer.from(crypto.getRandomValues(new Uint8Array(bytes))).toString("hex"); }
function b64(bytes: Uint8Array) { return Buffer.from(bytes).toString("base64"); }
function unb64(value: string) { return new Uint8Array(Buffer.from(value, "base64")); }
async function hash(value: string) { return Buffer.from(await crypto.subtle.digest("SHA-256", enc.encode(value))).toString("hex"); }
function equal(a: string, b: string) {
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}
function randomFrom(chars: string, count: number) {
  let out = "", cutoff = 256 - (256 % chars.length);
  while (out.length < count) { const n = crypto.getRandomValues(new Uint8Array(1))[0]; if (n < cutoff) out += chars[n % chars.length]; }
  return out;
}
function newIdentityCode() { return TEST_MODE ? FIXTURES.identityCode : randomFrom("0123456789", 6); }
function newSecret() { return TEST_MODE ? FIXTURES.authenticatorSecret : randomFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 32); }
function newBackups() {
  if (TEST_MODE) return [...FIXTURES.recoveryCodes];
  const set = new Set<string>();
  while (set.size < 6) { const x = randomFrom("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 10); set.add(x.slice(0, 5) + "-" + x.slice(5)); }
  return [...set];
}
async function pending(value: string): Promise<Pending> { return { digest: await hash(value), expires: Date.now() + IDENTITY_MS, used: false }; }
async function matches(value: string, item?: Pending) { return !!item && !item.used && item.expires >= Date.now() && equal(await hash(value), item.digest); }

async function encrypt(secret: string): Promise<Encrypted> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, enc.encode(secret));
  return { iv: b64(iv), data: b64(new Uint8Array(data)) };
}
async function decrypt(value: Encrypted) {
  return dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(value.iv) }, aesKey, unb64(value.data)));
}
async function backupHash(code: string, salt: string) {
  const key = await crypto.subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
  return Buffer.from(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 120000 }, key, 256)).toString("hex");
}
async function makeBackups(codes: string[]) {
  const out: Backup[] = [];
  for (const code of codes) { const salt = token(16); out.push({ salt, verifier: await backupHash(code, salt), used: false }); }
  return out;
}
async function useBackup(record: RecordMfa, code: string) {
  for (const item of record.backups) if (!item.used && equal(await backupHash(code, item.salt), item.verifier)) { item.used = true; return true; }
  return false;
}
function base32(value: string) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = "", out: number[] = [];
  for (const ch of value) { const n = alphabet.indexOf(ch); if (n < 0) throw new Error("Invalid secret"); bits += n.toString(2).padStart(5, "0"); }
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(out);
}
async function totp(secret: string, counter = Math.floor(Date.now() / 30000)) {
  const key = await crypto.subtle.importKey("raw", base32(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const msg = new Uint8Array(8); let n = BigInt(counter);
  for (let i = 7; i >= 0; i--) { msg[i] = Number(n & 255n); n >>= 8n; }
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg)), off = sig[19] & 15;
  return String((((sig[off] & 127) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3]) % 1_000_000).padStart(6, "0");
}
async function verifyTotp(record: RecordMfa, code: string) {
  const secret = await decrypt(record.secret), now = Math.floor(Date.now() / 30000);
  for (const counter of [now, now - 1]) if (!record.usedCounters.includes(counter) && equal(code, await totp(secret, counter))) {
    record.usedCounters = [...record.usedCounters.filter(x => x >= now - 2), counter]; return true;
  }
  return false;
}
function uri(secret: string) { return `otpauth://totp/LocalBank:Marcus?secret=${secret}&issuer=LocalBank&algorithm=SHA1&digits=6&period=30`; }

function cookie(request: Request, name: string) {
  return (request.headers.get("cookie") || "").split(";").map(x => x.trim()).find(x => x.startsWith(name + "="))?.slice(name.length + 1);
}
function sessionCookie(id: string) { return `mfa_session=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`; }
function preCookie(id: string) { return `mfa_preauth=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=600`; }
function clearPreCookie() { return "mfa_preauth=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }
function clearSessionCookie() { return "mfa_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"; }

function headers(nonce?: string, origin?: string | null) {
  const h