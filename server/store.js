'use strict';
/*
 * Own Hostwerk vault (built-in password manager): one encrypted file per vault under data/passwoerter/<id>.hwvault –
 * AES-256-GCM, key through scrypt from the master password. Unlocked, the content only lives in memory and is locked
 * again automatically after being idle (autoLockMin).
 * Items: login, note, card, identity – with folders, tags, favourites, a history of old passwords and a trash.
 * Every change is saved right away (the whole file is encrypted again).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { SCRYPT, SCRYPT_V1, deriveKeyAsync, encrypt, decrypt } = require('./crypto');
const { T } = require('./i18n');
const host = require('./host');
// The header (salt + derivation parameters) is bound to the content through AAD: whoever changes it gets nothing decrypted
const aadFor = (salt, kdf) => `hostwerk-vault:v2:${salt}:${kdf.N}:${kdf.r}:${kdf.p}`;
const weaker = (k) => !k || k.N < SCRYPT.N || k.r < SCRYPT.r;
/** Write atomically through Hostwerk (temporary file + rename); plain write without a host (unit tests). */
const writeFileSafe = (file, data, opts) => { try { return host.core('safewrite').writeFileSafe(file, data, opts); } catch (e) { if (!/host not bound/.test(e.message)) throw e; fs.writeFileSync(file, data, opts); return undefined; } };

const TYPES = ['login', 'note', 'card', 'identity'];
const MAX_HISTORY = 10;

class VaultStore {
  constructor(file, { autoLockMin = 15 } = {}) {
    this.file = file;
    this.key = null; this.data = null; this.timer = null; this.autoLockMin = autoLockMin; this.lastUse = 0;
  }
  exists() { return fs.existsSync(this.file); }
  locked() { return !this.key; }
  header() { try { const j = JSON.parse(fs.readFileSync(this.file, 'utf8')); return { v: j.v, created: j.created, updated: j.updated, items: null }; } catch { return null; } }
  /** Check the master password without opening the vault (e.g. before deleting it). */
  async verify(password) {
    try { const j = JSON.parse(fs.readFileSync(this.file, 'utf8')); const kdf = j.kdf || SCRYPT_V1; const key = await deriveKeyAsync(password, Buffer.from(j.salt, 'base64'), kdf); decrypt(key, j, j.v >= 2 ? aadFor(j.salt, kdf) : null); key.fill(0); return true; } catch { return false; }
  }

  async create(password) {
    if (this.exists()) throw new Error(T('This vault already exists.'));
    if (String(password || '').length < 8) throw new Error(T('The master password needs at least 8 characters.'));
    const salt = crypto.randomBytes(16);
    this.key = await deriveKeyAsync(password, salt);
    this.salt = salt;
    this.data = { items: [], folders: [], created: Date.now() };
    this.save();
    this.touch();
    return this.summary();
  }
  async unlock(password) {
    const j = JSON.parse(await fs.promises.readFile(this.file, 'utf8'));
    const salt = Buffer.from(j.salt, 'base64');
    const kdf = j.kdf || SCRYPT_V1;
    const key = await deriveKeyAsync(password, salt, kdf);
    let text;
    try { text = decrypt(key, j, j.v >= 2 ? aadFor(j.salt, kdf) : null); } catch { key.fill(0); throw Object.assign(new Error(T('Wrong master password.')), { status: 401 }); }
    this.key = key; this.salt = salt; this.data = JSON.parse(text);
    // Lift older/weaker vaults quietly to the current format on the first unlock (new salt, stronger derivation)
    if (j.v < 2 || weaker(j.kdf)) { this.salt = crypto.randomBytes(16); const old = this.key; this.key = await deriveKeyAsync(password, this.salt); old.fill(0); this.save(); }
    this.touch();
    return this.summary();
  }
  lock() { if (this.key) this.key.fill(0); this.key = null; this.data = null; clearTimeout(this.timer); this.timer = null; }
  touch() {
    this.lastUse = Date.now();
    clearTimeout(this.timer);
    if (this.autoLockMin > 0) { this.timer = setTimeout(() => this.lock(), this.autoLockMin * 60000); if (this.timer.unref) this.timer.unref(); }
  }
  need() { if (!this.key) throw Object.assign(new Error(T('The vault is locked – please enter the master password.')), { status: 423 }); this.touch(); return this.data; }
  save() {
    const text = JSON.stringify(this.data);
    const kdf = { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p };
    const salt = this.salt.toString('base64');
    const enc = encrypt(this.key, text, aadFor(salt, kdf));
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    writeFileSafe(this.file, JSON.stringify({ v: 2, hostwerkVault: 1, salt, kdf, created: this.data.created, updated: Date.now(), ...enc }), { mode: 0o600 });
  }
  async changePassword(oldPw, newPw) {
    await this.unlock(oldPw);
    if (String(newPw || '').length < 8) throw new Error(T('The new master password needs at least 8 characters.'));
    this.salt = crypto.randomBytes(16);
    const old = this.key;
    this.key = await deriveKeyAsync(newPw, this.salt);
    old.fill(0);
    this.save();
    return { ok: true };
  }

  /* ---------- items ---------- */
  summary() {
    const d = this.need();
    const live = d.items.filter((i) => !i.trashed);
    return { items: live.length, trashed: d.items.length - live.length, folders: d.folders, created: d.created };
  }
  /** List without secrets (password, TOTP, card number, note content). */
  list({ q = '', folder = null, type = null, trashed = false, tag = null } = {}) {
    const d = this.need();
    const n = String(q || '').toLowerCase();
    // the address bar sends "0"/"1" as text – "0" must not count as true (otherwise only the trash shows)
    const tr = trashed === true || trashed === 1 || trashed === '1' || trashed === 'true';
    return d.items.filter((i) => !!i.trashed === tr && (!folder || i.folder === folder) && (!type || i.type === type) && (!tag || (i.tags || []).includes(tag))
      && (!n || `${i.name} ${i.username || ''} ${(i.urls || []).join(' ')} ${(i.tags || []).join(' ')} ${i.notesPreview || ''}`.toLowerCase().includes(n)))
      .map((i) => this.pub(i)).sort((a, b) => (b.favorite - a.favorite) || a.name.localeCompare(b.name, 'de'));
  }
  pub(i) {
    const { password, totp, fields, notes, card, identity, history, ...rest } = i; // eslint-disable-line no-unused-vars
    return { ...rest, hasPassword: !!password, hasTotp: !!totp, hasNotes: !!notes, fieldCount: (fields || []).length, historyCount: (history || []).length, cardLast4: card && card.number ? String(card.number).slice(-4) : null };
  }
  get(id) { const i = this.need().items.find((x) => x.id === id); if (!i) throw Object.assign(new Error(T('Item not found')), { status: 404 }); return i; }
  normalize(b, old = null) {
    const type = TYPES.includes(b.type) ? b.type : (old && old.type) || 'login';
    const urls = Array.isArray(b.urls) ? b.urls.map((u) => String(u).trim()).filter(Boolean).slice(0, 20) : typeof b.url === 'string' && b.url ? [b.url.trim()] : (old && old.urls) || [];
    const item = {
      id: old ? old.id : crypto.randomBytes(8).toString('hex'), type, name: String(b.name ?? (old && old.name) ?? '').trim().slice(0, 200) || T('Untitled'),
      username: String(b.username ?? (old && old.username) ?? '').slice(0, 300), password: String(b.password ?? (old && old.password) ?? ''), urls,
      totp: String(b.totp ?? (old && old.totp) ?? '').trim(), notes: String(b.notes ?? (old && old.notes) ?? '').slice(0, 20000),
      fields: Array.isArray(b.fields) ? b.fields.filter((f) => f && f.name).map((f) => ({ name: String(f.name).slice(0, 100), value: String(f.value ?? '').slice(0, 2000), hidden: !!f.hidden })).slice(0, 50) : (old && old.fields) || [],
      folder: typeof b.folder === 'string' ? b.folder.slice(0, 100) : (old && old.folder) || '', tags: Array.isArray(b.tags) ? [...new Set(b.tags.map((t) => String(t).trim().slice(0, 40)).filter(Boolean))].slice(0, 20) : (old && old.tags) || [],
      favorite: typeof b.favorite === 'boolean' ? b.favorite : !!(old && old.favorite),
      card: type === 'card' ? { holder: String((b.card || {}).holder ?? (old && old.card && old.card.holder) ?? ''), number: String((b.card || {}).number ?? (old && old.card && old.card.number) ?? '').replace(/\s+/g, ''), expiry: String((b.card || {}).expiry ?? (old && old.card && old.card.expiry) ?? ''), cvv: String((b.card || {}).cvv ?? (old && old.card && old.card.cvv) ?? ''), brand: String((b.card || {}).brand ?? (old && old.card && old.card.brand) ?? '') } : null,
      identity: type === 'identity' ? Object.fromEntries(['firstName', 'lastName', 'company', 'email', 'phone', 'address', 'zip', 'city', 'country', 'birthday'].map((k) => [k, String((b.identity || {})[k] ?? (old && old.identity && old.identity[k]) ?? '').slice(0, 300)])) : null,
      created: old ? old.created : Date.now(), updated: Date.now(), passwordChanged: old ? old.passwordChanged : Date.now(), history: old ? old.history || [] : [], trashed: old ? old.trashed || false : false, source: b.source || (old && old.source) || null,
    };
    item.notesPreview = item.notes ? item.notes.slice(0, 80).replace(/\s+/g, ' ') : '';
    if (old && old.password && old.password !== item.password) { item.history = [{ password: old.password, until: Date.now() }, ...(old.history || [])].slice(0, MAX_HISTORY); item.passwordChanged = Date.now(); }
    return item;
  }
  add(b) { const d = this.need(); const i = this.normalize(b); d.items.push(i); this.save(); return i; }
  addMany(list) { const d = this.need(); const out = []; for (const b of list) { const i = this.normalize(b); d.items.push(i); out.push(i); } this.save(); return out; }
  update(id, b) { const d = this.need(); const idx = d.items.findIndex((x) => x.id === id); if (idx < 0) throw Object.assign(new Error(T('Item not found')), { status: 404 }); d.items[idx] = this.normalize(b, d.items[idx]); this.save(); return d.items[idx]; }
  trash(id, on = true) { const i = this.get(id); i.trashed = on; i.updated = Date.now(); this.save(); return this.pub(i); }
  remove(id) { const d = this.need(); d.items = d.items.filter((x) => x.id !== id); this.save(); }
  emptyTrash() { const d = this.need(); const n = d.items.filter((x) => x.trashed).length; d.items = d.items.filter((x) => !x.trashed); this.save(); return n; }
  folders() { const d = this.need(); const used = new Map(); for (const i of d.items) if (!i.trashed && i.folder) used.set(i.folder, (used.get(i.folder) || 0) + 1); return [...new Set([...(d.folders || []), ...used.keys()])].sort((a, b) => a.localeCompare(b, 'de')).map((f) => ({ name: f, count: used.get(f) || 0 })); }
  setFolders(list) { const d = this.need(); d.folders = [...new Set((list || []).map((f) => String(f).trim().slice(0, 100)).filter(Boolean))]; this.save(); return this.folders(); }
  tags() { const d = this.need(); const c = new Map(); for (const i of d.items) if (!i.trashed) for (const t of i.tags || []) c.set(t, (c.get(t) || 0) + 1); return [...c.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count); }
  /** Every item with secrets (export, security check, provider sync). */
  all() { return this.need().items.filter((i) => !i.trashed); }
  /** Items for a web address (browser extension): host match, subdomains count. */
  matches(url) {
    let h0 = ''; try { h0 = new URL(url).hostname.toLowerCase(); } catch { h0 = String(url || '').toLowerCase(); }
    if (!h0) return [];
    const base = h0.split('.').slice(-2).join('.');
    return this.all().filter((i) => i.type === 'login' && (i.urls || []).some((u) => { let h = ''; try { h = new URL(/^https?:\/\//i.test(u) ? u : `https://${u}`).hostname.toLowerCase(); } catch { h = u.toLowerCase(); } return h === h0 || h.endsWith('.' + h0) || h0.endsWith('.' + h) || (h.split('.').slice(-2).join('.') === base); })).map((i) => this.pub(i));
  }
}

module.exports = { VaultStore, TYPES };
