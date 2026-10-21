'use strict';
/*
 * Own Hostwerk vault (built-in password manager): one encrypted file per vault under data/passwoerter/<id>.hwvault.
 *
 * Format 3 (since 2.0): a random 256-bit vault key encrypts the content (AES-256-GCM); the vault key itself is wrapped
 * with a key from the master password (Argon2id 64 MiB/3/1, without hash-wasm scrypt). Header (salt + derivation
 * parameters) goes into both encryptions as AAD – whoever changes it gets nothing decrypted. A new master password only
 * wraps the vault key again; attachments (<id>.files/, also encrypted with the vault key) stay untouched.
 * Older files (format 1/2: scrypt, key straight from the password) still open and are lifted to format 3 quietly on the
 * first unlock. Every write is atomic (temporary file + rename) – a crash leaves the old or the new file, never half.
 *
 * Unlocked, the content only lives in memory and is locked again automatically after being idle (autoLockMin).
 * Items: login (with passkeys), note, card, identity, ssh – with folders, tags, favourites, extra fields, attachments,
 * a history of old passwords and a trash.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { SCRYPT_V1, deriveKeyAsync, deriveKdf, bestKdf, kdfText, kdfWeaker, encrypt, decrypt, decryptRaw, strength } = require('./crypto');
const { T } = require('./i18n');
const host = require('./host');

const FORMAT = 3;
// Format 2: AAD over salt + scrypt parameters; format 3: salt + any derivation (kdfText)
const aadV2 = (salt, kdf) => `hostwerk-vault:v2:${salt}:${kdf.N}:${kdf.r}:${kdf.p}`;
const aadV3 = (salt, kdf) => `hostwerk-vault:v3:${salt}:${kdfText(kdf)}`;
/** Write atomically through Hostwerk (temporary file + rename); without a host (unit tests) through an own temp file. */
const writeFileSafe = (file, data, opts) => {
  let sw = null; try { sw = host.core('safewrite'); } catch { sw = null; }
  if (sw && sw.writeFileSafe) return sw.writeFileSafe(file, data, opts);
  const tmp = `${file}.${process.pid}.tmp`; fs.writeFileSync(tmp, data, opts); fs.renameSync(tmp, file); return undefined;
};

const TYPES = ['login', 'note', 'card', 'identity', 'ssh'];
const MAX_HISTORY = 10;
const MAX_FILE = 5 * 1024 * 1024;   // one attachment
const MAX_FILES = 50 * 1024 * 1024; // all attachments of a vault
const PASSKEY_KEYS = ['credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'rpName', 'userHandle', 'userName', 'userDisplayName', 'counter', 'discoverable', 'creationDate'];
const hostOf = (u) => { try { return new URL(/^[a-z][\w+.-]*:\/\//i.test(u) ? u : `https://${u}`).hostname.toLowerCase(); } catch { return ''; } };

class VaultStore {
  constructor(file, { autoLockMin = 15 } = {}) {
    this.file = file;
    this.key = null; this.data = null; this.head = null; this.timer = null; this.autoLockMin = autoLockMin; this.lastUse = 0;
  }
  get filesDir() { return this.file.replace(/\.hwvault$/, '') + '.files'; }
  exists() { return fs.existsSync(this.file); }
  locked() { return !this.key; }
  header() { try { const j = JSON.parse(fs.readFileSync(this.file, 'utf8')); return { v: j.v, created: j.created, updated: j.updated, kdf: j.kdf ? { ...j.kdf } : { alg: 'scrypt', ...SCRYPT_V1 } }; } catch { return null; } }

  /** Open a file with the master password → { key (vault key, null for old formats), text } or throw 401. */
  async open(password, j) {
    const salt = Buffer.from(j.salt, 'base64');
    try {
      if (j.v >= 3) {
        const kek = await deriveKdf(password, salt, j.kdf);
        let key;
        try { key = decryptRaw(kek, j.key, aadV3(j.salt, j.kdf)); } finally { kek.fill(0); }
        return { key, text: decrypt(key, j, aadV3(j.salt, j.kdf)) };
      }
      const kdf = j.kdf || SCRYPT_V1;
      const old = await deriveKeyAsync(password, salt, kdf);
      try { return { key: null, text: decrypt(old, j, j.v >= 2 ? aadV2(j.salt, kdf) : null) }; } finally { old.fill(0); }
    } catch (e) {
      if (/Argon2 is not available|out of range/.test(e.message)) throw e;
      throw Object.assign(new Error(T('Wrong master password.')), { status: 401 });
    }
  }
  /** Check the master password without opening the vault (e.g. before deleting it). */
  async verify(password) {
    try { const j = JSON.parse(fs.readFileSync(this.file, 'utf8')); const r = await this.open(password, j); if (r.key) r.key.fill(0); return true; } catch { return false; }
  }
  /** Wrap the vault key with a fresh salt and the best derivation available today. */
  async wrap(password) {
    const salt = crypto.randomBytes(16).toString('base64');
    const kdf = bestKdf();
    const kek = await deriveKdf(password, Buffer.from(salt, 'base64'), kdf);
    try { this.head = { salt, kdf, key: encrypt(kek, this.key, aadV3(salt, kdf)) }; } finally { kek.fill(0); }
  }

  async create(password) {
    if (this.exists()) throw new Error(T('This vault already exists.'));
    if (String(password || '').length < 8) throw new Error(T('The master password needs at least 8 characters.'));
    this.key = crypto.randomBytes(32);
    await this.wrap(password);
    this.data = { items: [], folders: [], created: Date.now() };
    this.save();
    this.touch();
    return this.summary();
  }
  async unlock(password) {
    const j = JSON.parse(await fs.promises.readFile(this.file, 'utf8'));
    const { key, text } = await this.open(password, j);
    this.data = JSON.parse(text);
    if (!Array.isArray(this.data.items)) this.data.items = [];
    // Older/weaker vaults are lifted quietly to the current format (own vault key, Argon2id, new salt)
    if (!key || j.v < FORMAT || kdfWeaker(j.kdf)) { this.key = key || crypto.randomBytes(32); await this.wrap(password); this.save(); } else { this.key = key; this.head = { salt: j.salt, kdf: j.kdf, key: j.key }; }
    this.touch();
    return this.summary();
  }
  lock() { if (this.key) this.key.fill(0); this.key = null; this.data = null; this.head = null; clearTimeout(this.timer); this.timer = null; }
  touch() {
    this.lastUse = Date.now();
    clearTimeout(this.timer);
    if (this.autoLockMin > 0) { this.timer = setTimeout(() => this.lock(), this.autoLockMin * 60000); if (this.timer.unref) this.timer.unref(); }
  }
  need() { if (!this.key) throw Object.assign(new Error(T('The vault is locked – please enter the master password.')), { status: 423 }); this.touch(); return this.data; }
  save() {
    const { salt, kdf, key } = this.head;
    const enc = encrypt(this.key, JSON.stringify(this.data), aadV3(salt, kdf));
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    writeFileSafe(this.file, JSON.stringify({ v: FORMAT, hostwerkVault: 1, salt, kdf, key, created: this.data.created, updated: Date.now(), ...enc }), { mode: 0o600 });
  }
  async changePassword(oldPw, newPw) {
    await this.unlock(oldPw);
    if (String(newPw || '').length < 8) throw new Error(T('The new master password needs at least 8 characters.'));
    await this.wrap(newPw);
    this.save();
    return { ok: true };
  }

  /* ---------- items ---------- */
  summary() {
    const d = this.need();
    const live = d.items.filter((i) => !i.trashed);
    return { items: live.length, trashed: d.items.length - live.length, folders: d.folders, created: d.created };
  }
  /** List without secrets (password, TOTP, card number, note content, keys). */
  list({ q = '', folder = null, type = null, trashed = false, tag = null, fav = null, has = null } = {}) {
    const d = this.need();
    const n = String(q || '').toLowerCase();
    // the address bar sends "0"/"1" as text – "0" must not count as true (otherwise only the trash shows)
    const yes = (x) => x === true || x === 1 || x === '1' || x === 'true';
    const tr = yes(trashed);
    return d.items.filter((i) => !!i.trashed === tr && (!folder || i.folder === folder || String(i.folder || '').startsWith(`${folder}/`)) && (!type || i.type === type) && (!tag || (i.tags || []).includes(tag))
      && (!yes(fav) || i.favorite) && (!has || (has === 'passkey' ? (i.passkeys || []).length > 0 : has === 'files' ? (i.attachments || []).length > 0 : has === 'totp' ? !!i.totp : true))
      && (!n || `${i.name} ${i.username || ''} ${(i.urls || []).join(' ')} ${(i.tags || []).join(' ')} ${i.notesPreview || ''} ${i.folder || ''}`.toLowerCase().includes(n)))
      .map((i) => this.pub(i)).sort((a, b) => (b.favorite - a.favorite) || a.name.localeCompare(b.name, 'de'));
  }
  /** Numbers for the navigation (all, favourites, per type, passkeys, files, trash). */
  stats() {
    const d = this.need();
    const live = d.items.filter((i) => !i.trashed);
    const by = Object.fromEntries(TYPES.map((x) => [x, live.filter((i) => i.type === x).length]));
    return { all: live.length, fav: live.filter((i) => i.favorite).length, ...by, passkey: live.filter((i) => (i.passkeys || []).length).length, files: live.filter((i) => (i.attachments || []).length).length, trash: d.items.length - live.length, tags: this.tags(), folders: this.folders() };
  }
  pub(i) {
    const { password, totp, fields, notes, card, identity, history, ssh, passkeys, attachments, ...rest } = i; // eslint-disable-line no-unused-vars
    return { ...rest, hasPassword: !!password, hasTotp: !!totp, hasNotes: !!notes, fieldCount: (fields || []).length, historyCount: (history || []).length, cardLast4: card && card.number ? String(card.number).slice(-4) : null, passkeyCount: (passkeys || []).length, attachmentCount: (attachments || []).length, sshType: ssh ? ssh.keyType || null : null, pwScore: password ? strength(password).score : null, host: hostOf((i.urls || [])[0] || '') || null };
  }
  get(id) { const i = this.need().items.find((x) => x.id === id); if (!i) throw Object.assign(new Error(T('Item not found')), { status: 404 }); return i; }
  normalize(b, old = null) {
    const type = TYPES.includes(b.type) ? b.type : (old && old.type) || 'login';
    const urls = Array.isArray(b.urls) ? b.urls.map((u) => String(u).trim()).filter(Boolean).slice(0, 20) : typeof b.url === 'string' && b.url ? [b.url.trim()] : (old && old.urls) || [];
    const sub = (k) => (b[k] && typeof b[k] === 'object' ? b[k] : null) || (old && old[k]) || {};
    const item = {
      id: old ? old.id : crypto.randomBytes(8).toString('hex'), type, name: String(b.name ?? (old && old.name) ?? '').trim().slice(0, 200) || T('Untitled'),
      username: String(b.username ?? (old && old.username) ?? '').slice(0, 300), password: String(b.password ?? (old && old.password) ?? ''), urls,
      totp: String(b.totp ?? (old && old.totp) ?? '').trim(), notes: String(b.notes ?? (old && old.notes) ?? '').slice(0, 20000),
      fields: Array.isArray(b.fields) ? b.fields.filter((f) => f && f.name).map((f) => ({ name: String(f.name).slice(0, 100), value: String(f.value ?? '').slice(0, 2000), hidden: !!f.hidden })).slice(0, 50) : (old && old.fields) || [],
      folder: typeof b.folder === 'string' ? b.folder.trim().replace(/\/+$/, '').slice(0, 100) : (old && old.folder) || '', tags: Array.isArray(b.tags) ? [...new Set(b.tags.map((t) => String(t).trim().slice(0, 40)).filter(Boolean))].slice(0, 20) : (old && old.tags) || [],
      favorite: typeof b.favorite === 'boolean' ? b.favorite : !!(old && old.favorite),
      card: type === 'card' ? Object.fromEntries(['holder', 'number', 'expiry', 'cvv', 'brand', 'pin'].map((k) => [k, String(sub('card')[k] ?? '').slice(0, 100)])) : null,
      identity: type === 'identity' ? Object.fromEntries(['title', 'firstName', 'lastName', 'company', 'email', 'phone', 'address', 'zip', 'city', 'state', 'country', 'birthday', 'passport', 'license', 'taxId'].map((k) => [k, String(sub('identity')[k] ?? '').slice(0, 300)])) : null,
      ssh: type === 'ssh' ? Object.fromEntries(['privateKey', 'publicKey', 'fingerprint', 'keyType'].map((k) => [k, String(sub('ssh')[k] ?? '').slice(0, 20000)])) : null,
      // Passkeys come only by import (Bitwarden JSON) – kept and exported again, never changed here
      passkeys: (old ? old.passkeys || [] : Array.isArray(b.passkeys) ? b.passkeys : []).filter((p) => p && typeof p === 'object').slice(0, 20).map((p) => Object.fromEntries(PASSKEY_KEYS.filter((k) => p[k] != null).map((k) => [k, String(p[k]).slice(0, 4000)]))),
      attachments: (old && old.attachments) || [],
      created: old ? old.created : Number(b.created) || Date.now(), updated: Date.now(), passwordChanged: old ? old.passwordChanged : Number(b.passwordChanged) || Date.now(),
      history: old ? old.history || [] : (Array.isArray(b.history) ? b.history.filter((h) => h && h.password).slice(0, MAX_HISTORY).map((h) => ({ password: String(h.password), until: Number(h.until) || null })) : []),
      trashed: old ? old.trashed || false : false, source: b.source || (old && old.source) || null,
    };
    item.notesPreview = item.notes && type !== 'note' ? item.notes.slice(0, 80).replace(/\s+/g, ' ') : '';
    if (old && old.password && old.password !== item.password) { item.history = [{ password: old.password, until: Date.now() }, ...(old.history || [])].slice(0, MAX_HISTORY); item.passwordChanged = Date.now(); }
    return item;
  }
  add(b) { const d = this.need(); const i = this.normalize(b); d.items.push(i); this.save(); return i; }
  addMany(list) { const d = this.need(); const out = []; for (const b of list) { const i = this.normalize(b); d.items.push(i); out.push(i); } this.save(); return out; }
  update(id, b) { const d = this.need(); const idx = d.items.findIndex((x) => x.id === id); if (idx < 0) throw Object.assign(new Error(T('Item not found')), { status: 404 }); d.items[idx] = this.normalize(b, d.items[idx]); this.save(); return d.items[idx]; }
  trash(id, on = true) { const i = this.get(id); i.trashed = on; i.updated = Date.now(); this.save(); return this.pub(i); }
  remove(id) { const d = this.need(); const gone = d.items.filter((x) => x.id === id); d.items = d.items.filter((x) => x.id !== id); this.save(); for (const i of gone) this.dropFiles(i); }
  emptyTrash() { const d = this.need(); const gone = d.items.filter((x) => x.trashed); d.items = d.items.filter((x) => !x.trashed); this.save(); for (const i of gone) this.dropFiles(i); return gone.length; }
  folders() { const d = this.need(); const used = new Map(); for (const i of d.items) if (!i.trashed && i.folder) used.set(i.folder, (used.get(i.folder) || 0) + 1); return [...new Set([...(d.folders || []), ...used.keys()])].sort((a, b) => a.localeCompare(b, 'de')).map((f) => ({ name: f, count: used.get(f) || 0 })); }
  setFolders(list) { const d = this.need(); d.folders = [...new Set((list || []).map((f) => String(f).trim().slice(0, 100)).filter(Boolean))]; this.save(); return this.folders(); }
  tags() { const d = this.need(); const c = new Map(); for (const i of d.items) if (!i.trashed) for (const t of i.tags || []) c.set(t, (c.get(t) || 0) + 1); return [...c.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count); }
  /** Every item with secrets (export, security check, provider sync). */
  all() { return this.need().items.filter((i) => !i.trashed); }

  /* ---------- attachments (encrypted with the vault key, one file each) ---------- */
  attFile(attId) { if (!/^[a-f0-9]{16}$/.test(attId)) throw Object.assign(new Error(T('Attachment not found')), { status: 404 }); return path.join(this.filesDir, `${attId}.bin`); }
  addAttachment(itemId, { name, mime, data }) {
    const it = this.get(itemId);
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data || ''), 'base64');
    if (!buf.length) throw Object.assign(new Error(T('The file is empty.')), { status: 400 });
    if (buf.length > MAX_FILE) throw Object.assign(new Error(T('Attachments can be at most {mb} MB.', { mb: MAX_FILE / 1048576 })), { status: 413 });
    const total = this.need().items.reduce((s, i) => s + (i.attachments || []).reduce((a, x) => a + (x.size || 0), 0), 0);
    if (total + buf.length > MAX_FILES) throw Object.assign(new Error(T('All attachments of a vault together can be at most {mb} MB.', { mb: MAX_FILES / 1048576 })), { status: 413 });
    const id = crypto.randomBytes(8).toString('hex');
    fs.mkdirSync(this.filesDir, { recursive: true });
    writeFileSafe(this.attFile(id), JSON.stringify(encrypt(this.key, buf, `hostwerk-att:${id}`)), { mode: 0o600 });
    const meta = { id, name: String(name || 'file').replace(/[\\/:*?"<>|]+/g, '_').slice(0, 120), mime: String(mime || 'application/octet-stream').slice(0, 100), size: buf.length, added: Date.now() };
    it.attachments = [...(it.attachments || []), meta].slice(0, 20);
    it.updated = Date.now();
    this.save();
    return meta;
  }
  attachment(itemId, attId) {
    const it = this.get(itemId);
    const meta = (it.attachments || []).find((a) => a.id === attId);
    if (!meta) throw Object.assign(new Error(T('Attachment not found')), { status: 404 });
    const box = JSON.parse(fs.readFileSync(this.attFile(attId), 'utf8'));
    return { ...meta, data: decryptRaw(this.key, box, `hostwerk-att:${attId}`) };
  }
  removeAttachment(itemId, attId) {
    const it = this.get(itemId);
    it.attachments = (it.attachments || []).filter((a) => a.id !== attId);
    it.updated = Date.now();
    this.save();
    fs.rmSync(this.attFile(attId), { force: true });
  }
  removePasskey(itemId, credentialId) { const it = this.get(itemId); it.passkeys = (it.passkeys || []).filter((p) => p.credentialId !== credentialId); it.updated = Date.now(); this.save(); return this.pub(it); }
  dropFiles(i) { for (const a of i.attachments || []) { try { fs.rmSync(this.attFile(a.id), { force: true }); } catch { /* weg */ } } }

  /** Items for a web address (browser extension): host match, subdomains count. */
  matches(url) {
    let h0 = ''; try { h0 = new URL(url).hostname.toLowerCase(); } catch { h0 = String(url || '').toLowerCase(); }
    if (!h0) return [];
    const base = h0.split('.').slice(-2).join('.');
    return this.all().filter((i) => i.type === 'login' && (i.urls || []).some((u) => { const h = hostOf(u) || u.toLowerCase(); return h === h0 || h.endsWith('.' + h0) || h0.endsWith('.' + h) || (h.split('.').slice(-2).join('.') === base); })).map((i) => this.pub(i));
  }
}

module.exports = { VaultStore, TYPES, MAX_FILE, MAX_FILES, hostOf };
