'use strict';
/*
 * Crypto helpers of the password manager: key from the master password (scrypt), AES-256-GCM, TOTP (RFC 6238), password
 * generator and rating, "Have I Been Pwned" check with k-anonymity (only the first 5 characters of the SHA-1 hash leave
 * the PC).
 */
const crypto = require('crypto');
const { T } = require('./i18n');

// Old vaults (v1) use N=2^15; new ones and those upgraded on unlock N=2^17 (~128 MB, about 0.4 s per unlock)
const SCRYPT_V1 = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const SCRYPT = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 };

function deriveKey(password, salt, params = SCRYPT) {
  return crypto.scryptSync(Buffer.from(String(password), 'utf8'), salt, 32, { N: params.N, r: params.r, p: params.p, maxmem: params.maxmem || Math.max(64 * 1024 * 1024, 256 * params.N * params.r) });
}
/** Like deriveKey, but in the thread pool: does not block Hostwerk (scrypt with N=2^17 takes ~0.4 s). */
function deriveKeyAsync(password, salt, params = SCRYPT) {
  return new Promise((ok, fail) => crypto.scrypt(Buffer.from(String(password), 'utf8'), salt, 32, { N: params.N, r: params.r, p: params.p, maxmem: params.maxmem || Math.max(64 * 1024 * 1024, 256 * params.N * params.r) }, (e, k) => (e ? fail(e) : ok(k))));
}
function encrypt(key, plaintext, aad = null) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (aad) c.setAAD(Buffer.from(aad, 'utf8'));
  const enc = Buffer.concat([c.update(Buffer.from(plaintext, 'utf8')), c.final()]);
  return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), data: enc.toString('base64') };
}
function decrypt(key, { iv, tag, data }, aad = null) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  if (aad) d.setAAD(Buffer.from(aad, 'utf8'));
  d.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(data, 'base64')), d.final()]).toString('utf8');
}

/* ---------- TOTP ---------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(s) {
  const clean = String(s || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0; let value = 0; const out = [];
  for (const ch of clean) { value = (value << 5) | B32.indexOf(ch); bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; } }
  return Buffer.from(out);
}
function base32Encode(buf) {
  let bits = 0; let value = 0; let out = '';
  for (const b of buf) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
/** otpauth:// address or a plain secret → { secret, digits, period, algorithm, issuer, account } */
function parseOtp(input) {
  const s = String(input || '').trim();
  if (/^otpauth:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      const label = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
      const [issuerFromLabel, account] = label.includes(':') ? label.split(':', 2) : [null, label];
      return { secret: u.searchParams.get('secret') || '', digits: Number(u.searchParams.get('digits')) || 6, period: Number(u.searchParams.get('period')) || 30, algorithm: (u.searchParams.get('algorithm') || 'SHA1').toUpperCase(), issuer: u.searchParams.get('issuer') || issuerFromLabel || '', account: account || '' };
    } catch { /* below */ }
  }
  return { secret: s.replace(/\s+/g, ''), digits: 6, period: 30, algorithm: 'SHA1', issuer: '', account: '' };
}
function totp(input, at = Date.now()) {
  const o = parseOtp(input);
  if (!o.secret) return null;
  const counter = Math.floor(at / 1000 / o.period);
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const algo = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' }[o.algorithm] || 'sha1';
  const h = crypto.createHmac(algo, base32Decode(o.secret)).update(msg).digest();
  const off = h[h.length - 1] & 0xf;
  const code = ((h.readUInt32BE(off) & 0x7fffffff) % 10 ** o.digits).toString().padStart(o.digits, '0');
  return { code, period: o.period, remaining: o.period - (Math.floor(at / 1000) % o.period), issuer: o.issuer, account: o.account };
}

/* ---------- passwords ---------- */
const SETS = { lower: 'abcdefghijkmnopqrstuvwxyz', upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ', digits: '23456789', symbols: '!@#$%&*+-=?_~' };
function generate({ length = 20, lower = true, upper = true, digits = true, symbols = true, ambiguous = false, words = 0, separator = '-' } = {}) {
  if (words > 0) return passphrase(words, separator);
  let pool = ''; const must = [];
  for (const [k, on] of Object.entries({ lower, upper, digits, symbols })) if (on) { let s = SETS[k]; if (ambiguous) s += { lower: 'l', upper: 'IO', digits: '01', symbols: '' }[k]; pool += s; must.push(s); }
  if (!pool) pool = SETS.lower + SETS.digits;
  const n = Math.max(6, Math.min(128, Number(length) || 20));
  for (let tries = 0; tries < 50; tries++) {
    const out = Array.from({ length: n }, () => pool[crypto.randomInt(pool.length)]).join('');
    if (must.every((s) => [...out].some((ch) => s.includes(ch)))) return out;
  }
  return Array.from({ length: n }, () => pool[crypto.randomInt(pool.length)]).join('');
}
// Word list of the passphrase generator (German words – the list is data, not interface text)
const WORDS = 'apfel baum berg blume brot buch dach eule fisch fluss garten gold haus hund insel jahr kerze kind koffer lampe licht luft mond nacht nebel ozean pferd regen rose sand schiff schnee sonne stern stuhl tiger tisch turm vogel wald wasser wolke zebra zimmer zucker anker bogen drache falke feder flamme funke glanz hafen honig kette klang kompass krone kugel laterne linse magnet nadel perle quelle rad ritter saite schild segel spiegel strom traum welle wind wurzel'.split(' ');
function passphrase(words = 4, sep = '-') { const n = Math.max(3, Math.min(10, words)); return Array.from({ length: n }, () => { const w = WORDS[crypto.randomInt(WORDS.length)]; return w[0].toUpperCase() + w.slice(1); }).join(sep) + crypto.randomInt(10, 99); }

const LABELS = ['very weak', 'weak', 'medium', 'strong', 'very strong'];
/** Strength 0–4 with reasons (length, variety, patterns, well-known words). */
function strength(pw) {
  const s = String(pw || '');
  if (!s) return { score: 0, label: T('empty'), bits: 0, hints: [T('No password')] };
  let pool = 0; if (/[a-z]/.test(s)) pool += 26; if (/[A-Z]/.test(s)) pool += 26; if (/\d/.test(s)) pool += 10; if (/[^A-Za-z0-9]/.test(s)) pool += 33;
  let bits = s.length * Math.log2(pool || 1);
  const hints = [];
  if (s.length < 8) hints.push(T('too short (under 8 characters)'));
  if (/^(.)\1+$/.test(s) || /^(..)\1+$/.test(s)) { bits /= 3; hints.push(T('repetitions')); }
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf|yxcv|qwertz)/i.test(s)) { bits -= 12; hints.push(T('keyboard or number sequence')); }
  if (/(passwor|password|geheim|secret|admin|welcome|willkommen|hallo|letmein|iloveyou|123456|111111)/i.test(s)) { bits -= 20; hints.push(T('well-known word')); }
  if (/^[A-Za-z]+\d{1,4}[!.?]?$/.test(s)) { bits -= 8; hints.push(T('word + number – a common pattern')); }
  bits = Math.max(0, Math.round(bits));
  const score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  return { score, label: T(LABELS[score]), bits, hints };
}

/** Have I Been Pwned (k-anonymity): how often does the password show up in data leaks? */
async function pwned(pw) {
  const h = crypto.createHash('sha1').update(String(pw), 'utf8').digest('hex').toUpperCase();
  const r = await fetch(`https://api.pwnedpasswords.com/range/${h.slice(0, 5)}`, { headers: { 'Add-Padding': 'true', 'User-Agent': 'Hostwerk' }, signal: AbortSignal.timeout(10000) });
  if (!r.ok) throw new Error(T('HIBP answers with {status}', { status: r.status }));
  const text = await r.text();
  const line = text.split(/\r?\n/).find((l) => l.startsWith(h.slice(5)));
  return line ? Number(line.split(':')[1]) || 0 : 0;
}

module.exports = { deriveKeyAsync, SCRYPT_V1, SCRYPT, deriveKey, encrypt, decrypt, totp, parseOtp, base32Decode, base32Encode, generate, passphrase, strength, pwned };
