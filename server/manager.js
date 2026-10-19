'use strict';
/*
 * Password manager as a Hostwerk service: any number of "vaults" – the built-in Hostwerk vault (store.js) or connected
 * services (providers.js: Bitwarden/Vaultwarden, 1Password, KeePass, pass, LastPass) – plus import/export for all the
 * others (Google, Apple, Proton, Dashlane, NordPass, …, see formats.js and the catalogue).
 *
 *   - Security check: weak, reused, old and leaked passwords (HIBP, k-anonymity), missing 2FA
 *   - TOTP codes, password generator, history, trash, folders/tags
 *   - Browser extension: pairing by code, an own key per browser (settings.passwords.ext), matches per page, filling in,
 *     saving new logins; the extension is only downloaded from Hostwerk (/api/pw/extension.zip)
 *   - Self-maintenance: CLIs (bw, op) with version check and test run, kdbxweb version, HIBP reachability,
 *     online catalogue pw-catalog.json (new formats/providers without a release)
 *   - AI: tools never see passwords (only names/users/addresses/check results)
 * Secrets of the provider configuration are sealed in the settings (core/secrets). Data stays where it always was:
 * settings.passwords and data/passwoerter.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { VaultStore, TYPES } = require('./store');
const { PROVIDERS, runCli, IS_WIN } = require('./providers');
const formats = require('./formats');
const pwc = require('./crypto');
const host = require('./host');
const { T } = require('./i18n');

const DAY = 86400000;
const EXT_TTL = 365 * DAY;
const DATA = path.join(__dirname, '..', 'data');
const KIND = () => T('Passwords'); // category in Hostwerk's change log
const secrets = { open: (x) => host.core('secrets').open(x), seal: (x) => host.core('secrets').seal(x) };
const broadcast = (m) => host.broadcast(m);
const execFile2 = (...a) => host.core('util').exec(...a);

/** Source folder of the browser extension: inside this package, otherwise Hostwerk's own copy. */
function extSource() {
  const own = path.join(__dirname, '..', 'browser-extension');
  if (fs.existsSync(path.join(own, 'manifest.json'))) return own;
  return path.join(host.appRoot() || '', 'extension');
}
/** Mirror the files from src to target without deleting the folder itself. null if a file is locked. */
function syncDir(src, target) {
  try {
    fs.mkdirSync(target, { recursive: true });
    const want = new Set(fs.readdirSync(src));
    for (const f of want) fs.copyFileSync(path.join(src, f), path.join(target, f));
    for (const f of fs.readdirSync(target)) if (!want.has(f) && f !== 'hostwerk-pairing.json') { try { fs.rmSync(path.join(target, f), { recursive: true, force: true }); } catch { /* ignore */ } }
    return target;
  } catch { return null; }
}
const readJson = (file, fallback) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } };

class PasswordManager {
  constructor(ctx) {
    this.ctx = ctx;
    this.timers = [];
    // Time-limited shares also end on time without any access (hourly check)
    if (!process.env.HW_TEST) this.timers.push(setInterval(() => { try { this.expireShares(); } catch { /* ignore */ } }, 3600e3));
    this.dir = path.join(ctx.paths.data, 'passwoerter');
    fs.mkdirSync(this.dir, { recursive: true });
    this.stores = new Map();   // id -> VaultStore | provider
    this.pairings = new Map(); // code -> { at }
    this.audits = new Map();   // id -> last check result (without secrets)
    this.catalog = null;
    this.loadCatalog().catch(() => {});
    if (!process.env.HW_TEST) this.timers.push(setInterval(() => this.loadCatalog({ online: true }).catch(() => {}), 24 * 3600000));
    for (const t of this.timers) if (t.unref) t.unref();
  }
  /** Password generator and rating for Hostwerk (e.g. the AI tool pw_generate) – never touches a vault. */
  generate(opts = {}) { return pwc.generate(opts); }
  strength(pw) { return pwc.strength(pw); }
  stop() { for (const t of this.timers) clearInterval(t); this.timers = []; for (const s of this.stores.values()) { try { s.lock(); } catch { /* ignore */ } } }
  get cfg() { const s = this.ctx.settings.get(); if (!s.passwords) s.passwords = { instances: [], ext: [], autoLockMin: 15, audit: { hibp: true } }; if (!s.passwords.ext) s.passwords.ext = []; if (!s.passwords.instances) s.passwords.instances = []; if (!s.passwords.audit) s.passwords.audit = { hibp: true }; return s.passwords; }
  list() { return this.cfg.instances; }
  get(id) { const i = this.list().find((x) => x.id === id); if (!i) throw Object.assign(new Error(T('Vault not found')), { status: 404 }); return i; }
  save() { this.ctx.settings.save(); }
  record(target, action) { if (this.ctx.audit) this.ctx.audit.record({ kind: KIND(), target, action }); }
  note(key, ok, label, text) { if (this.ctx.keeper) this.ctx.keeper.note(key, { ok, label, text }); }

  /* ---------- catalogue (bundled + online) ---------- */
  async loadCatalog({ online = false } = {}) {
    let cat = readJson(path.join(DATA, 'pw-catalog.json'), null) || readJson(path.join(host.appRoot() || '', 'catalog', 'pw-catalog.json'), { providers: [], formats: [], clis: {} });
    if (online) {
      const label = T('Password manager: catalogue');
      try { const remote = await host.core('github').contentJson('catalog/pw-catalog.json'); if (remote && Array.isArray(remote.providers)) { cat = remote; this.note('pw-katalog', true, label, T('Online catalogue loaded ({n} providers, {f} extra formats).', { n: remote.providers.length, f: (remote.formats || []).length })); } } catch (e) { this.note('pw-katalog', true, label, T('Built-in catalogue (online not reachable: {msg})', { msg: e.message })); }
    }
    this.catalog = cat;
    formats.setExtraFormats(cat.formats || []);
    return cat;
  }

  /* ---------- vaults ---------- */
  info(i) {
    const s = this.stores.get(i.id);
    const prov = PROVIDERS[i.type];
    return { id: i.id, name: i.name, type: i.type, label: i.type === 'hostwerk' ? T('Hostwerk vault') : (prov && prov.label) || i.type, native: i.type === 'hostwerk' || !!(prov && prov.native), readonly: !!(prov && prov.readonly), locked: !s || s.locked(), exists: i.type === 'hostwerk' ? fs.existsSync(this.file(i.id)) : true, cfg: this.pubCfg(i), createdAt: i.createdAt, audit: this.audits.get(i.id) || null, default: this.cfg.defaultId === i.id, color: i.color || null };
  }
  pubCfg(i) { const out = {}; for (const [k, v] of Object.entries(i.cfg || {})) out[k] = typeof v === 'string' && v.startsWith('enc:') ? '••••' : v; return out; }
  file(id) { return path.join(this.dir, `${id}.hwvault`); }
  store(id) {
    const i = this.get(id);
    let s = this.stores.get(id);
    if (!s) {
      if (i.type === 'hostwerk') s = new VaultStore(this.file(id), { autoLockMin: this.cfg.autoLockMin ?? 15 });
      else { const P = PROVIDERS[i.type]; if (!P) throw new Error(T('Unknown provider “{type}”', { type: i.type })); s = new P.cls(this.ctx, i); }
      this.stores.set(id, s);
    }
    return s;
  }
  async create(b) {
    const type = b.type === 'hostwerk' || PROVIDERS[b.type] ? b.type : null;
    if (!type) throw new Error(T('Unknown kind of vault'));
    if (PROVIDERS[type] && PROVIDERS[type].linux && IS_WIN) throw new Error(T('{label} only exists on Linux/macOS.', { label: PROVIDERS[type].label }));
    const id = `${type}-${crypto.randomBytes(3).toString('hex')}`;
    const inst = { id, name: String(b.name || (type === 'hostwerk' ? T('My vault') : PROVIDERS[type].label)).slice(0, 60), type, cfg: {}, createdAt: Date.now(), color: b.color || null };
    this.applyCfg(inst, b.cfg || {});
    this.list().push(inst);
    if (!this.cfg.defaultId) this.cfg.defaultId = id;
    this.save();
    if (type === 'hostwerk') { if (!b.password) throw new Error(T('The master password is missing.')); await this.store(id).create(b.password); }
    broadcast({ type: 'passwords' });
    return this.info(inst);
  }
  applyCfg(inst, cfg) {
    const P = PROVIDERS[inst.type];
    if (!P) return;
    for (const [k, , kind] of P.fields) {
      if (cfg[k] === undefined) continue;
      const v = String(cfg[k] || '').trim();
      if (kind === 'password') { if (v && v !== '••••') inst.cfg[k] = secrets.seal(v); if (v === '') delete inst.cfg[k]; } else inst.cfg[k] = v.slice(0, 500);
    }
  }
  update(id, b) { const i = this.get(id); if (typeof b.name === 'string') i.name = b.name.slice(0, 60); if (b.cfg) { this.applyCfg(i, b.cfg); const s = this.stores.get(id); if (s && s.lock) s.lock(); } if (b.color !== undefined) i.color = b.color || null; if (b.default) this.cfg.defaultId = id; this.save(); broadcast({ type: 'passwords' }); return this.info(i); }
  /**
   * Remove a vault – only with a password: Hostwerk vault = master password; provider with a stored password = that
   * password; otherwise the name as confirmation. Wrong entries are logged.
   */
  async remove(id, { deleteFile = false, password = '', confirm = '' } = {}) {
    const i = this.get(id);
    if (i.type === 'hostwerk' && this.store(id).exists()) {
      if (!password || !(await this.store(id).verify(password))) { this.record(i.name, T('Delete refused (wrong master password)')); throw Object.assign(new Error(T('Wrong master password – the vault was not removed.')), { status: 401 }); }
    } else {
      const stored = i.cfg && i.cfg.password ? secrets.open(i.cfg.password) : '';
      if (stored ? password !== stored : String(confirm).trim().replace(/\s+/g, ' ').toLowerCase() !== String(i.name).trim().replace(/\s+/g, ' ').toLowerCase()) throw Object.assign(new Error(stored ? T('Wrong password – the connection was not removed.') : T('To remove it, please type the name “{name}”.', { name: i.name })), { status: 401 });
    }
    return this.removeNow(id, { deleteFile });
  }
  async removeNow(id, { deleteFile = false } = {}) { const i = this.get(id); const s = this.stores.get(id); if (s && s.lock) s.lock(); this.stores.delete(id); this.cfg.instances = this.list().filter((x) => x.id !== id); if (this.cfg.defaultId === id) this.cfg.defaultId = (this.list()[0] || {}).id || null; this.save(); if (deleteFile && i.type === 'hostwerk') fs.rmSync(this.file(id), { force: true }); broadcast({ type: 'passwords' }); }

  async unlock(id, password) { const i = this.get(id); const s = this.store(id); const r = i.type === 'hostwerk' ? await s.unlock(password) : await s.connect({ password }); broadcast({ type: 'passwords' }); return { ok: true, ...(r || {}) }; }
  lock(id) { const s = this.stores.get(id); if (s) s.lock(); broadcast({ type: 'passwords' }); }
  lockAll() { for (const s of this.stores.values()) s.lock(); broadcast({ type: 'passwords' }); }

  /** One list without secrets (vault: store.list, providers: all() filtered). */
  async items(id, q = {}) {
    const i = this.get(id); const s = this.store(id);
    if (i.type === 'hostwerk') return s.list(q);
    if (s.locked()) throw Object.assign(new Error(T('{name} is not connected – please unlock.', { name: i.name })), { status: 423 });
    const all = await s.all();
    const n = String(q.q || '').toLowerCase();
    return all.filter((x) => !x.trashed && (!q.folder || x.folder === q.folder) && (!q.type || x.type === q.type) && (!n || `${x.name} ${x.username || ''} ${(x.urls || []).join(' ')}`.toLowerCase().includes(n))).map(({ password, totp, notes, fields, ...rest }) => ({ ...rest, hasPassword: !!password, hasTotp: !!totp, hasNotes: !!notes, fieldCount: (fields || []).length })).sort((a, b) => a.name.localeCompare(b.name, 'de'));
  }
  async item(id, itemId) { const i = this.get(id); const s = this.store(id); if (i.type !== 'hostwerk' && s.locked()) throw Object.assign(new Error(T('Not connected')), { status: 423 }); const it = await s.get(itemId); this.record(`${i.name}: ${it.name}`, T('Item viewed (secret retrieved)')); return it; }
  async addItem(id, b) { const i = this.get(id); const s = this.store(id); if (PROVIDERS[i.type] && PROVIDERS[i.type].readonly) throw new Error(T('This provider is read-only.')); const it = await s.add(b); broadcast({ type: 'passwords', id }); return i.type === 'hostwerk' ? s.pub(it) : it; }
  async updateItem(id, itemId, b) { const i = this.get(id); const s = this.store(id); if (PROVIDERS[i.type] && PROVIDERS[i.type].readonly) throw new Error(T('This provider is read-only.')); const it = await s.update(itemId, b); broadcast({ type: 'passwords', id }); return i.type === 'hostwerk' ? s.pub(it) : it; }
  async removeItem(id, itemId, { hard = false } = {}) { const i = this.get(id); const s = this.store(id); if (i.type === 'hostwerk' && !hard) s.trash(itemId, true); else await s.remove(itemId); broadcast({ type: 'passwords', id }); }
  async allWithSecrets(id) { const i = this.get(id); const s = this.store(id); if (i.type === 'hostwerk') return s.all(); if (s.locked()) throw Object.assign(new Error(T('Not connected')), { status: 423 }); return (await s.all()).filter((x) => !x.trashed); }

  /* ---------- security check ---------- */
  async audit(id, { hibp = null } = {}) {
    const items = await this.allWithSecrets(id);
    const useHibp = hibp === null ? this.cfg.audit.hibp !== false : !!hibp;
    const byPw = new Map();
    for (const it of items) if (it.password) (byPw.get(it.password) || byPw.set(it.password, []).get(it.password)).push(it);
    const findings = [];
    const F = (it, kind, text, level = 'warn') => findings.push({ itemId: it.id, name: it.name, username: it.username || '', kind, text, level });
    let leaked = 0; const checked = new Map();
    for (const it of items) {
      if (it.type !== 'login' && !it.password) continue;
      if (!it.password) { if (it.type === 'login') F(it, 'empty', T('No password saved'), 'info'); continue; }
      const st = pwc.strength(it.password);
      if (st.score <= 1) F(it, 'weak', st.hints.length ? T('Weak password ({label}: {hints})', { label: st.label, hints: st.hints.join(', ') }) : T('Weak password ({label})', { label: st.label }), 'err');
      if ((byPw.get(it.password) || []).length > 1) F(it, 'reused', T('Same password in {n} items', { n: byPw.get(it.password).length }), 'err');
      const changed = it.passwordChanged || it.updated || it.created;
      if (changed && Date.now() - changed > 365 * DAY) F(it, 'old', T('Not changed for {n} months', { n: Math.round((Date.now() - changed) / DAY / 30) }), 'info');
      if (it.type === 'login' && !it.totp && (it.urls || []).some((u) => /(google|microsoft|apple|amazon|paypal|github|facebook|instagram|twitter|x\.com|bank|sparkasse|dkb|ing|comdirect|steam|discord|dropbox|cloudflare|hetzner|ionos|strato)/i.test(u))) F(it, 'no2fa', T('Important service without a saved 2FA (TOTP)'), 'warn');
      if (useHibp) {
        try { let n = checked.get(it.password); if (n === undefined) { n = await pwc.pwned(it.password); checked.set(it.password, n); } if (n > 0) { leaked++; F(it, 'leaked', T('Showed up in {n} data leaks – change it now', { n: n.toLocaleString() }), 'err'); } } catch (e) { if (!findings.some((f) => f.kind === 'hibp-error')) findings.push({ kind: 'hibp-error', level: 'info', text: T('Leak check not possible: {msg}', { msg: e.message }), name: '', itemId: null }); break; }
      }
    }
    const counts = { items: items.length, weak: findings.filter((f) => f.kind === 'weak').length, reused: findings.filter((f) => f.kind === 'reused').length, old: findings.filter((f) => f.kind === 'old').length, leaked, no2fa: findings.filter((f) => f.kind === 'no2fa').length };
    const score = Math.max(0, 100 - counts.weak * 8 - counts.reused * 6 - counts.leaked * 15 - counts.no2fa * 3 - counts.old * 1);
    const rank = { err: 0, warn: 1, info: 2 };
    const result = { at: Date.now(), score, counts, findings: findings.sort((a, b) => rank[a.level] - rank[b.level]), hibp: useHibp };
    this.audits.set(id, result);
    return result;
  }

  /* ---------- import / export ---------- */
  async importText(id, text, { folder = '', skipDuplicates = true } = {}) {
    const parsed = formats.detectAndParse(text);
    const i = this.get(id); const s = this.store(id);
    const existing = await this.allWithSecrets(id);
    const key = (x) => `${(x.name || '').toLowerCase()}|${(x.username || '').toLowerCase()}|${((x.urls || [])[0] || '').toLowerCase()}`;
    const have = new Set(existing.map(key));
    const fresh = parsed.items.filter((x) => !skipDuplicates || !have.has(key(x))).map((x) => ({ ...x, folder: folder || x.folder }));
    let added = 0;
    if (i.type === 'hostwerk') { s.addMany(fresh); added = fresh.length; } else { for (const x of fresh) { await s.add(x); added++; } }
    broadcast({ type: 'passwords', id });
    this.record(i.name, T('{n} items imported ({label})', { n: added, label: parsed.label }));
    return { format: parsed.format, label: parsed.label, found: parsed.items.length, added, skipped: parsed.items.length - fresh.length };
  }
  async exportText(id, kind = 'bitwarden-json') {
    const i = this.get(id);
    const items = await this.allWithSecrets(id);
    this.record(i.name, T('Export ({kind}, {n} items)', { kind, n: items.length }));
    if (kind === 'bitwarden-json') return { text: formats.exportBitwardenJson(items, [...new Set(items.map((x) => x.folder).filter(Boolean))]), name: `${i.name}.json`, mime: 'application/json' };
    return { text: formats.exportCsv(items, kind.replace('-csv', '')), name: `${i.name}-${kind}.csv`, mime: 'text/csv' };
  }
  /** Copy items between vaults (e.g. Bitwarden → Hostwerk vault). */
  async transfer(from, to, { ids = null } = {}) {
    const items = (await this.allWithSecrets(from)).filter((x) => !ids || ids.includes(x.id));
    const s = this.store(to); const t = this.get(to);
    let n = 0;
    if (t.type === 'hostwerk') { s.addMany(items.map(({ id, ...x }) => ({ ...x, source: from }))); n = items.length; } else for (const { id, ...x } of items) { await s.add(x); n++; } // eslint-disable-line no-unused-vars
    broadcast({ type: 'passwords', id: to });
    return { copied: n };
  }

  /** Fill-in options of the browser extension (default: suggestions in the field + offer to save on, filling in on load off). */
  autofillCfg() { if (!this.cfg.autofill) this.cfg.autofill = { inline: true, onLoad: false, suggest: true, offerSave: true }; return this.cfg.autofill; }

  /* ---------- browser extension ---------- */
  pairCode() { const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0'); this.pairings.set(code, { at: Date.now() }); setTimeout(() => this.pairings.delete(code), 10 * 60000).unref(); return { code, port: this.ctx.uiPort(), expiresIn: 600 }; }
  /** "Install" clicked → for 15 minutes an extension may sign in without a code (only from an extension origin, once). */
  openPairWindow(browser) { this.pairWindow = { until: Date.now() + 15 * 60000, browser }; }
  autoPair(req) {
    const origin = String(req.headers.origin || '');
    const m = origin.match(/^(chrome|moz)-extension:\/\/([a-z0-9-]+)$/i);
    if (!m) throw Object.assign(new Error(T('Only for the browser extension.')), { status: 403 });
    const w = this.pairWindow;
    if (!w || Date.now() > w.until) throw Object.assign(new Error(T('Pairing not allowed – click “Install” in Hostwerk under Passwords → Browser.')), { status: 403 });
    // Store version: only the real extension id
    const ids = Object.values((this.storeInfo || {}).ids || {}).filter(Boolean);
    if (m[1] === 'chrome' && ids.length && !ids.includes(m[2]) && !this.devExt) throw Object.assign(new Error(T('Unknown extension.')), { status: 403 });
    this.pairWindow = null;
    const ticket = this.pairTicket();
    const name = { chrome: 'Chrome', edge: 'Edge', brave: 'Brave', opera: 'Opera', vivaldi: 'Vivaldi', firefox: 'Firefox' }[w.browser] || 'Browser';
    return this.pair(ticket, { name, browser: String((req.body || {}).browser || '') });
  }

  /** Store versions (ids, signed Firefox file) – from the online catalogue, so they arrive without an app update. */
  async storeCatalog() {
    if (this.storeInfo && Date.now() - this.storeInfo.t < 6 * 3600000) return this.storeInfo;
    let data = null;
    try { const r = await host.core('github').contentJson('catalog/browser-extension.json'); data = r && r.data; } catch { /* offline */ }
    if (!data) data = readJson(path.join(DATA, 'browser-extension.json'), null) || readJson(path.join(host.appRoot() || '', 'catalog', 'browser-extension.json'), {});
    this.storeInfo = { t: Date.now(), ids: { chrome: data.chromeId || null, edge: data.edgeId || null }, firefoxXpi: data.firefoxXpi || null, version: data.version || null };
    return this.storeInfo;
  }

  /** Store way: the browser is told about the extension as an "external extension" (the official way, no change to profiles)
   *  and the store page opens – one click on "Add" there. */
  async storeInstall(browser) {
    const s = await this.storeCatalog();
    const fam = browser === 'edge' ? 'edge' : browser === 'firefox' ? 'firefox' : 'chrome';
    if (fam === 'firefox') {
      if (!s.firefoxXpi) return null;
      const dest = path.join(this.ctx.paths.base, 'browser-erweiterung', 'hostwerk-passwoerter-signiert.xpi');
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      const r = await fetch(s.firefoxXpi, { redirect: 'follow', signal: AbortSignal.timeout(60000) });
      if (!r.ok) return null;
      fs.writeFileSync(dest, Buffer.from(await r.arrayBuffer()));
      return { mode: 'signed', file: dest };
    }
    const id = s.ids[fam];
    if (!id) return null;
    const update = fam === 'edge' ? 'https://edge.microsoft.com/extensionwebstorebase/v1/crx' : 'https://clients2.google.com/service/update2/crx';
    const page = fam === 'edge' ? `https://microsoftedge.microsoft.com/addons/detail/${id}` : `https://chromewebstore.google.com/detail/${id}`;
    const keys = { chrome: 'Software\\Google\\Chrome\\Extensions', edge: 'Software\\Microsoft\\Edge\\Extensions', brave: 'Software\\BraveSoftware\\Brave-Browser\\Extensions', vivaldi: 'Software\\Vivaldi\\Extensions', opera: null };
    let registered = false;
    if (IS_WIN && keys[browser] && !process.env.HW_TEST) {
      const r = await execFile2('reg.exe', ['add', `HKCU\\${keys[browser]}\\${id}`, '/v', 'update_url', '/t', 'REG_SZ', '/d', update, '/f'], { timeout: 15000 }).catch(() => ({ code: 1 }));
      registered = r.code === 0;
    } else if (!IS_WIN && !process.env.HW_TEST) {
      const dirs = { chrome: '.config/google-chrome', brave: '.config/BraveSoftware/Brave-Browser', vivaldi: '.config/vivaldi', edge: '.config/microsoft-edge' };
      if (dirs[browser]) { try { const d = path.join(require('os').homedir(), dirs[browser], 'External Extensions'); fs.mkdirSync(d, { recursive: true }); fs.writeFileSync(path.join(d, `${id}.json`), JSON.stringify({ external_update_url: update })); registered = true; } catch { /* ignore */ } }
    }
    return { mode: 'store', id, page, registered };
  }

  /** One-time ticket for automatic pairing: lies as hostwerk-pairing.json in the extension folder (valid for 30 min). */
  pairTicket() { const ticket = crypto.randomBytes(24).toString('hex'); this.pairings.set(ticket, { at: Date.now(), auto: true }); setTimeout(() => this.pairings.delete(ticket), 30 * 60000).unref(); return ticket; }
  pair(code, { name = 'Browser', browser = '' } = {}) {
    const p = this.pairings.get(String(code || ''));
    if (!p) throw Object.assign(new Error(T('Pairing code invalid or expired – show a new one in Hostwerk under Passwords → Browser.')), { status: 401 });
    this.pairings.delete(String(code));
    const token = crypto.randomBytes(32).toString('hex');
    const e = { id: crypto.randomBytes(4).toString('hex'), name: String(name).slice(0, 60), browser: String(browser).slice(0, 40), hash: crypto.createHash('sha256').update(token).digest('hex'), created: Date.now(), lastUse: null, until: Date.now() + EXT_TTL };
    this.cfg.ext.push(e); this.save(); broadcast({ type: 'passwords' });
    this.record(e.name, T('Browser extension paired'));
    return { token, id: e.id, port: this.ctx.uiPort(), name: e.name };
  }
  extAuth(req) {
    const t = req.headers['x-hostwerk-ext'];
    if (!t || typeof t !== 'string') return null;
    const h = crypto.createHash('sha256').update(t).digest('hex');
    const e = this.cfg.ext.find((x) => x.hash === h);
    if (!e || e.until < Date.now()) return null;
    e.lastUse = Date.now();
    return e;
  }
  /* ---------- sharing with members ----------
   * Share single items with members (users with their own sign-in) – "view & copy" or "copy only". The share lives outside
   * the encrypted vault (ids only); the member only gets the content while the vault is unlocked here. Every access ends up
   * in the change log. Members come from the "Team & users" extension (settings.users).
   */
  get shares() { if (!this.cfg.shares) this.cfg.shares = {}; return this.cfg.shares; }
  shareKey(vault, item) { return `${vault}:${item}`; }
  getShare(vault, item) { this.expireShares(); const sh = this.shares[this.shareKey(vault, item)] || { users: {} }; return sh.users; }
  getShareUntil(vault, item) { const sh = this.shares[this.shareKey(vault, item)]; return (sh && sh.until) || {}; }
  members() { return (this.ctx.settings.get().users) || []; }
  /**
   * Set a share. until = { memberId: point in time (ms) } – without an entry the share has no end. Hostwerk ends expired
   * shares itself (on the next access and hourly) and notes that in the change log.
   */
  setShare(vault, item, users, until = {}) {
    this.get(vault);
    const known = new Set(this.members().filter((u) => u.role !== 'admin').map((u) => u.id));
    const clean = {}; const ends = {};
    for (const [uid, mode] of Object.entries(users || {})) {
      if (!known.has(uid) || !['read', 'copy'].includes(mode)) continue;
      clean[uid] = mode;
      const t = Number((until || {})[uid]);
      if (t) { if (t <= Date.now()) throw new Error(T('The end date is in the past.')); ends[uid] = Math.min(t, Date.now() + 366 * 864e5); }
    }
    const k = this.shareKey(vault, item);
    if (Object.keys(clean).length) this.shares[k] = { users: clean, ...(Object.keys(ends).length ? { until: ends } : {}), at: Date.now() }; else delete this.shares[k];
    this.save();
    const limited = Object.keys(ends).length;
    const n = Object.keys(clean).length;
    this.record(item, n ? (limited ? T('Shared with {n} member(s), {m} of them time-limited', { n, m: limited }) : T('Shared with {n} member(s)', { n })) : T('Sharing ended'));
    return { users: clean, until: ends };
  }
  /** End expired shares (per member). */
  expireShares() {
    const now = Date.now(); let changed = false;
    for (const [k, sh] of Object.entries(this.shares)) {
      for (const [uid, t] of Object.entries(sh.until || {})) {
        if (t > now) continue;
        delete sh.users[uid]; delete sh.until[uid]; changed = true;
        const name = (this.members().find((u) => u.id === uid) || {}).name || T('Member');
        this.record(k.split(':')[1], T('Share for {name} expired', { name }));
      }
      if (!Object.keys(sh.users || {}).length) { delete this.shares[k]; changed = true; }
    }
    if (changed) this.save();
    return changed;
  }
  /** What is shared with this member? (Without passwords) */
  async sharedWith(userId) {
    this.expireShares();
    const out = [];
    for (const [k, sh] of Object.entries(this.shares)) {
      const mode = sh.users && sh.users[userId]; if (!mode) continue;
      const until = (sh.until || {})[userId] || null;
      const [vault, item] = k.split(':');
      let inst; try { inst = this.get(vault); } catch { continue; }
      const st = this.stores.get(vault);
      if (!st || st.locked()) { out.push({ key: k, vaultName: inst.name, locked: true, mode, until }); continue; }
      try { const it = await st.get(item); if (!it || it.trashed) continue; out.push({ key: k, vaultName: inst.name, name: it.name, username: it.username || '', urls: it.urls || [], hasTotp: !!it.totp, mode, until, locked: false }); } catch { /* deleted */ }
    }
    return out;
  }
  async revealShared(userId, key, userName) {
    this.expireShares();
    const sh = this.shares[key];
    const mode = sh && sh.users && sh.users[userId];
    if (!mode) throw Object.assign(new Error(T('Not shared with you.')), { status: 403 });
    const [vault, item] = key.split(':');
    const st = this.stores.get(vault);
    if (!st || st.locked()) throw Object.assign(new Error(T('The vault is locked right now – please try again later.')), { status: 423 });
    const it = await st.get(item);
    this.record(it.name, mode === 'read' ? T('Shared login viewed ({name})', { name: userName || T('Member') }) : T('Shared login copied ({name})', { name: userName || T('Member') }));
    return { username: it.username || '', password: it.password || '', totp: it.totp ? pwc.totp(it.totp) : null, mode };
  }

  revokeExt(id, by = 'Hostwerk') { const e = this.cfg.ext.find((x) => x.id === id); this.cfg.ext = this.cfg.ext.filter((x) => x.id !== id); this.save(); if (e) this.record(e.name, by === 'browser' ? T('Pairing removed in the browser') : T('Pairing removed')); broadcast({ type: 'passwords' }); }
  extensionZip() {
    const dir = extSource();
    const out = path.join(this.ctx.paths.cache, 'hostwerk-browser-erweiterung.zip');
    const stamp = fs.readdirSync(dir).map((f) => fs.statSync(path.join(dir, f)).mtimeMs).reduce((a, b) => Math.max(a, b), 0);
    if (fs.existsSync(out) && fs.statSync(out).mtimeMs >= stamp) return out;
    return host.core('util').zipDir(dir, out).then(() => out);
  }

  /** Build the extension for the browser: Chromium (service_worker) or Firefox (background.scripts, Gecko id). */
  async extensionFor(browser) {
    const fx = browser === 'firefox';
    if (!['chrome', 'edge', 'brave', 'opera', 'vivaldi', 'firefox'].includes(browser)) throw new Error(T('Unknown browser'));
    const src = extSource();
    const dir = path.join(this.ctx.paths.cache, fx ? 'ext-firefox' : 'ext-chromium');
    const zip = dir + '.zip';
    const out = fx ? dir + '.xpi' : zip;
    const stamp = fs.readdirSync(src).map((f) => fs.statSync(path.join(src, f)).mtimeMs).reduce((a, b) => Math.max(a, b), 0);
    if (fs.existsSync(out) && fs.statSync(out).mtimeMs >= stamp && fs.existsSync(path.join(dir, 'manifest.json'))) return { file: out, dir };
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* locked – files are overwritten */ }
    fs.mkdirSync(dir, { recursive: true });
    for (const f of fs.readdirSync(src)) if (fs.statSync(path.join(src, f)).isFile()) fs.copyFileSync(path.join(src, f), path.join(dir, f));
    const m = JSON.parse(fs.readFileSync(path.join(src, 'manifest.json'), 'utf8'));
    if (fx) m.background = { scripts: fs.existsSync(path.join(src, 'i18n.js')) ? ['i18n.js', 'background.js'] : ['background.js'] }; else { m.background = { service_worker: 'background.js' }; delete m.browser_specific_settings; }
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(m, null, 2));
    await host.core('util').zipDir(dir, zip);
    if (fx) fs.copyFileSync(zip, out); // bsdtar picks the format by the extension – so .zip first, then copy
    return { file: out, dir };
  }

  /** "Install directly": put the extension into the Hostwerk folder and open the browser's extension page (or the .xpi in
   *  Firefox). Browsers do not allow a silent install of unpacked extensions – the last clicks (developer mode, choose the
   *  folder) stay with the user. */
  async extensionInstall(browser) {
    const fx = browser === 'firefox';
    this.openPairWindow(browser);
    const exeWin = { chrome: 'chrome', edge: 'msedge', brave: 'brave', opera: 'opera', vivaldi: 'vivaldi', firefox: 'firefox' }[browser];
    const exeNix = { chrome: 'google-chrome', edge: 'microsoft-edge', brave: 'brave-browser', opera: 'opera', vivaldi: 'vivaldi', firefox: 'firefox' }[browser];
    const open = async (arg) => { try { const r = IS_WIN ? await execFile2('cmd.exe', ['/c', 'start', '', exeWin, arg], { timeout: 15000 }) : await execFile2(exeNix, [arg], { timeout: 15000 }); return r.code === 0; } catch { return false; } };
    const store = await this.storeInstall(browser).catch(() => null);
    if (store) {
      const opened = process.env.HW_TEST ? false : await open(store.mode === 'signed' ? store.file : store.page);
      return { ok: true, browser, opened, since: Date.now(), autoPair: true, mode: store.mode, page: store.page || null, file: store.file || null, registered: !!store.registered };
    }
    this.devExt = true; // developer mode: the extension id depends on the folder
    const { file, dir } = await this.extensionFor(browser);
    const home = path.join(this.ctx.paths.base, 'browser-erweiterung');
    fs.mkdirSync(home, { recursive: true });
    let target;
    if (fx) { target = path.join(home, 'hostwerk-passwoerter.xpi'); try { fs.copyFileSync(file, target); } catch { target = path.join(home, `hostwerk-passwoerter-${Date.now().toString(36)}.xpi`); fs.copyFileSync(file, target); } } else {
      target = path.join(home, 'hostwerk-passwoerter');
      // Do not delete and recreate: a browser that already loaded the extension keeps the folder open (EPERM).
      // Overwrite the files in place instead; if that fails, a fresh folder next to it.
      target = syncDir(dir, target) || syncDir(dir, path.join(home, `hostwerk-passwoerter-${Date.now().toString(36)}`));
      if (!target) throw new Error(T('The folder of the browser extension is locked. Please close the browser and try again.'));
      // Automatic pairing: the extension reads this file on its first start and pairs itself
      fs.writeFileSync(path.join(target, 'hostwerk-pairing.json'), JSON.stringify({ port: this.ctx.uiPort(), ticket: this.pairTicket(), name: { chrome: 'Chrome', edge: 'Edge', brave: 'Brave', opera: 'Opera', vivaldi: 'Vivaldi' }[browser] || 'Browser' }));
    }
    const url = { chrome: 'chrome://extensions/', edge: 'edge://extensions/', brave: 'brave://extensions/', opera: 'opera://extensions/', vivaldi: 'vivaldi://extensions/' }[browser];
    // Tests never open the user's real browser
    const opened = process.env.HW_TEST ? false : await open(fx ? target : url);
    return { ok: true, browser, mode: 'dev', opened, since: Date.now(), autoPair: true, dir: fx ? null : target, file: fx ? target : null, url: url || null };
  }

  /* ---------- self-maintenance: CLIs and packages ---------- */
  cliDir(name) { return path.join(this.ctx.paths.bin, `pw-${name}`); }
  cliPath(name) { const d = this.cliDir(name); const exe = path.join(d, IS_WIN ? `${name}.exe` : name); if (fs.existsSync(exe)) return exe; return this.cliFound && this.cliFound[name] ? this.cliFound[name] : null; }
  kdbxwebVersion() { try { return readJson(path.join(host.appRoot() || '', 'node_modules', 'kdbxweb', 'package.json'), {}).version || null; } catch { return null; } }
  async cliStatus() {
    this.cliFound = this.cliFound || {};
    const out = {};
    for (const name of ['bw', 'op']) {
      if (!this.cliFound[name]) this.cliFound[name] = await host.core('platform').which(name);
      const exe = this.cliPath(name);
      let version = null;
      if (exe) { const r = await runCli(exe, ['--version'], { timeout: 15000 }); version = (r.out || r.err).trim().split('\n')[0].replace(/^v/, '') || null; }
      out[name] = { installed: !!exe, path: exe, version, latest: null };
    }
    const kv = this.kdbxwebVersion();
    out.kdbxweb = kv ? { installed: true, version: kv } : { installed: false };
    return out;
  }
  async latestCli(name) {
    const { fetchJson, cached } = host.core('download');
    const cat = (this.catalog && this.catalog.clis) || {};
    if (name === 'bw') {
      const rels = await cached('pw-bw-rel', 3600e3, () => fetchJson('https://api.github.com/repos/bitwarden/clients/releases?per_page=30'));
      const rel = rels.find((r) => /^cli-v/.test(r.tag_name) && !r.prerelease);
      if (!rel) throw new Error(T('No CLI version found'));
      const version = rel.tag_name.replace(/^cli-v/, '');
      const asset = rel.assets.find((a) => new RegExp(`^bw-(oss-)?${IS_WIN ? 'windows' : 'linux'}-${version.replace(/\./g, '\\.')}\\.zip$`).test(a.name)) || rel.assets.find((a) => a.name.includes(IS_WIN ? 'windows' : 'linux') && a.name.endsWith('.zip'));
      return { version, url: asset && asset.browser_download_url, page: rel.html_url };
    }
    if (name === 'op') {
      const j = await cached('pw-op-rel', 3600e3, () => fetchJson(cat.opCheck || 'https://app-updates.agilebits.com/check/1/0/CLI2/en/2.0.0/N'));
      const version = String(j.version || '').replace(/^v/, '');
      const base = cat.opBase || 'https://cache.agilebits.com/dist/1P/op2/pkg';
      return { version, url: `${base}/v${version}/op_${IS_WIN ? 'windows' : 'linux'}_amd64_v${version}.zip`, page: 'https://developer.1password.com/docs/cli/' };
    }
    throw new Error(T('Unknown CLI'));
  }
  installCli(name) {
    const label = name === 'bw' ? 'Bitwarden CLI' : '1Password CLI';
    return host.core('jobs').runJob(T('Download {label}', { label }), async (job) => {
      const l = await this.latestCli(name);
      if (!l.url) throw new Error(T('No download found for this system: {page}', { page: l.page || '' }));
      const dir = this.cliDir(name);
      const dl = host.core('download');
      const r = await this.ctx.keeper.attempt(`pw-cli-${name}`, {
        label: T('Password manager: {label}', { label }), version: l.version, present: () => !!this.cliPath(name),
        install: async () => { const tmp = dir + '.neu'; fs.rmSync(tmp, { recursive: true, force: true }); fs.mkdirSync(tmp, { recursive: true }); const zip = path.join(this.ctx.paths.cache, `${name}-${l.version}.zip`); await dl.downloadFile(l.url, zip, { onProgress: (a, b) => job.progress(b ? (a / b) * 80 : 40, T('Downloading {name} {version}', { name, version: l.version })) }); await dl.extractZip(zip, tmp); fs.rmSync(zip, { force: true }); const exe = path.join(tmp, IS_WIN ? `${name}.exe` : name); if (!fs.existsSync(exe)) { const found = fs.readdirSync(tmp).find((f) => f === name || f === `${name}.exe`); if (!found) throw new Error(T('Program not found in the archive')); } if (!IS_WIN) fs.chmodSync(exe, 0o755); return { tmp, exe }; },
        probe: async ({ exe }) => { const t = await host.core('sac').probe(exe, ['--version']); if (!t.ok) throw new Error(t.blocked ? T('Smart App Control blocks the program.') : T('Does not start: {out}', { out: t.output.slice(0, 200) })); if (!t.output.includes(l.version.split('.')[0])) job.log(T('Version according to the program: {v}', { v: t.output.trim() })); },
        activate: async ({ tmp }) => { fs.rmSync(dir, { recursive: true, force: true }); fs.renameSync(tmp, dir); for (const s of this.stores.values()) if (s.lock) s.lock(); },
        discard: async (x) => { if (x && x.tmp) fs.rmSync(x.tmp, { recursive: true, force: true }); },
      });
      if (!r.ok) throw new Error(r.error || T('Test run failed'));
      return { version: l.version, path: this.cliPath(name) };
    }, { key: 'pw-cli-' + name });
  }
  /** Keeper check: new CLI versions (with auto-update when installed), kdbxweb on npm, HIBP, catalogue. */
  async check() {
    const { fetchJson, cached, cmpVersion } = host.core('download');
    const st = await this.cliStatus();
    const out = { clis: {}, kdbxweb: st.kdbxweb };
    for (const name of ['bw', 'op']) {
      const label = T('Password manager: {name} CLI', { name });
      try {
        const l = await this.latestCli(name); out.clis[name] = { ...st[name], latest: l.version };
        if (st[name].installed && st[name].version && l.version && cmpVersion(l.version, st[name].version) > 0 && this.cliPath(name).startsWith(this.cliDir(name))) await this.installCli(name).promise.catch(() => {});
        this.note(`pw-cli-${name}-check`, true, label, st[name].installed ? T('installed {v}, current {latest}', { v: st[name].version, latest: l.version }) : T('not installed (current {latest})', { latest: l.version }));
      } catch (e) { out.clis[name] = { ...st[name], error: e.message }; this.note(`pw-cli-${name}-check`, false, label, T('Version check failed: {msg}', { msg: e.message })); }
    }
    try { const npm = await cached('pw-kdbxweb-npm', 3600e3, () => fetchJson('https://registry.npmjs.org/kdbxweb/latest')); out.kdbxweb.latest = npm.version; this.note('pw-kdbxweb', true, T('Password manager: KeePass library (kdbxweb)'), cmpVersion(npm.version, st.kdbxweb.version) > 0 ? T('built in {v}, on npm {npm} – the newer version comes with the next Hostwerk update (Dependabot)', { v: st.kdbxweb.version, npm: npm.version }) : T('built in {v}, on npm {npm}', { v: st.kdbxweb.version, npm: npm.version })); } catch (e) { out.kdbxweb.error = e.message; }
    const hibpLabel = T('Password manager: leak check (HIBP)');
    try { await pwc.pwned('Hostwerk-Probe'); this.note('pw-hibp', true, hibpLabel, T('reachable')); } catch (e) { this.note('pw-hibp', false, hibpLabel, e.message); }
    await this.loadCatalog({ online: true }).catch(() => {});
    return out;
  }

  /* ---------- routes ---------- */
  routes(r) {
    const J = (fn) => async (req, res) => res.json(await fn(req, res));
    // Members: only what is shared with them (before /pw/:id, so "shared" is no vault id)
    const me = (req) => { const s = this.ctx.remote && this.ctx.remote.session ? this.ctx.remote.session(req) : null; return s && s.userId ? this.members().find((x) => x.id === s.userId) : null; };
    r.get('/pw/shared/mine', J(async (req) => { const u = me(req); return { member: !!u, name: u ? u.name : null, items: u ? await this.sharedWith(u.id) : [] }; }));
    r.post('/pw/shared/mine/reveal', J(async (req) => { const u = me(req); if (!u) throw Object.assign(new Error(T('Only for members.')), { status: 403 }); return this.revealShared(u.id, String((req.body || {}).key || ''), u.name); }));
    r.get('/pw/:id/items/:item/share', J(async (req) => ({ users: this.getShare(req.params.id, req.params.item), until: this.getShareUntil(req.params.id, req.params.item), members: this.members().filter((u) => u.role !== 'admin' && u.enabled !== false).map((u) => ({ id: u.id, name: u.name })) })));
    r.put('/pw/:id/items/:item/share', J(async (req) => this.setShare(req.params.id, req.params.item, (req.body || {}).users, (req.body || {}).until)));
    r.get('/pw/browsers', J(async () => host.core('browsers').detectBrowsers()));
    r.get('/pw', J(async () => ({ autoLogin: this.cfg.autoLogin === true, autofill: this.autofillCfg(), instances: this.list().map((i) => this.info(i)), providers: Object.entries(PROVIDERS).filter(([, p]) => !(p.linux && IS_WIN)).map(([id, p]) => ({ id, label: p.label, fields: p.fields, hint: p.hint, cli: p.cli || null, readonly: !!p.readonly })), catalog: this.catalog, formats: formats.allFormats().map((f) => ({ id: f.id, label: f.label })), ext: this.cfg.ext.map(({ hash, ...e }) => e), autoLockMin: this.cfg.autoLockMin ?? 15, hibp: this.cfg.audit.hibp !== false, defaultId: this.cfg.defaultId || null, types: TYPES, members: this.members().length > 0 }))); // eslint-disable-line no-unused-vars
    r.put('/pw', (req, res) => { const b = req.body || {}; if (Number.isFinite(Number(b.autoLockMin))) { this.cfg.autoLockMin = Math.max(0, Math.min(240, Number(b.autoLockMin))); for (const s of this.stores.values()) if (s.autoLockMin !== undefined) s.autoLockMin = this.cfg.autoLockMin; } if (typeof b.hibp === 'boolean') this.cfg.audit.hibp = b.hibp; if (typeof b.autoLogin === 'boolean') this.cfg.autoLogin = b.autoLogin; if (b.autofill && typeof b.autofill === 'object') { const a = this.autofillCfg(); for (const k of ['inline', 'onLoad', 'suggest', 'offerSave']) if (typeof b.autofill[k] === 'boolean') a[k] = b.autofill[k]; } if (b.defaultId) this.cfg.defaultId = b.defaultId; this.save(); res.json({ ok: true }); });
    r.post('/pw', J((req) => this.create(req.body || {})));
    r.get('/pw/cli', J(async () => { const st = await this.cliStatus(); for (const n of ['bw', 'op']) { try { st[n].latest = (await this.latestCli(n)).version; } catch { /* offline */ } } return st; }));
    r.post('/pw/cli/:name/install', (req, res) => { if (!['bw', 'op'].includes(req.params.name)) throw new Error(T('Unknown CLI')); res.json({ job: this.installCli(req.params.name).id }); });
    r.post('/pw/generate', (req, res) => { const pw = pwc.generate(req.body || {}); res.json({ password: pw, strength: pwc.strength(pw) }); });
    r.post('/pw/strength', (req, res) => res.json(pwc.strength((req.body || {}).password)));
    r.post('/pw/pwned', J(async (req) => ({ count: await pwc.pwned((req.body || {}).password || '') })));
    r.post('/pw/totp', (req, res) => res.json(pwc.totp((req.body || {}).secret || '') || { error: T('No valid secret') }));
    r.post('/pw/lock-all', (req, res) => { this.lockAll(); res.json({ ok: true }); });
    r.get('/pw/ext/pair-code', (req, res) => res.json(this.pairCode()));
    // For the install display: has a browser paired since the click?
    r.get('/pw/ext/paired-since', (req, res) => { const t = Number(req.query.t) || 0; const e = this.cfg.ext.filter((x) => x.created >= t).pop(); res.json({ paired: !!e, name: e ? e.name : null }); });
    r.delete('/pw/ext/:id', (req, res) => { this.revokeExt(req.params.id); res.json({ ok: true }); });
    r.get('/pw/extension.zip', async (req, res) => { const f = await this.extensionZip(); res.download(f, 'hostwerk-browser-erweiterung.zip'); });
    // Per browser: the Chromium family as a ZIP to unpack, Firefox as .xpi (own manifest without a service worker)
    r.get('/pw/extension/:browser', async (req, res) => { try { const { file } = await this.extensionFor(req.params.browser); res.download(file, req.params.browser === 'firefox' ? 'hostwerk-passwoerter.xpi' : `hostwerk-passwoerter-${req.params.browser}.zip`); } catch (e) { res.status(400).json({ error: e.message }); } });
    r.post('/pw/extension/install', J((req) => this.extensionInstall(String((req.body || {}).browser || 'chrome'))));
    r.get('/pw/:id', J((req) => this.info(this.get(req.params.id))));
    r.put('/pw/:id', J((req) => this.update(req.params.id, req.body || {})));
    r.delete('/pw/:id', J(async (req) => { const b = req.body || {}; await this.remove(req.params.id, { deleteFile: req.query.file === '1' || b.deleteFile === true, password: String(b.password || ''), confirm: String(b.confirm || '') }); this.record(req.params.id, T('Vault removed')); return { ok: true }; }));
    r.post('/pw/:id/unlock', J((req) => this.unlock(req.params.id, (req.body || {}).password)));
    r.post('/pw/:id/lock', (req, res) => { this.lock(req.params.id); res.json({ ok: true }); });
    r.post('/pw/:id/password', J((req) => { const i = this.get(req.params.id); if (i.type !== 'hostwerk') throw new Error(T('Only for the Hostwerk vault.')); return this.store(i.id).changePassword((req.body || {}).oldPassword, (req.body || {}).newPassword); }));
    r.get('/pw/:id/items', J((req) => this.items(req.params.id, req.query)));
    r.post('/pw/:id/items', J((req) => this.addItem(req.params.id, req.body || {})));
    r.get('/pw/:id/items/:item', J((req) => this.item(req.params.id, req.params.item)));
    r.put('/pw/:id/items/:item', J((req) => this.updateItem(req.params.id, req.params.item, req.body || {})));
    r.delete('/pw/:id/items/:item', J(async (req) => { await this.removeItem(req.params.id, req.params.item, { hard: req.query.hard === '1' }); return { ok: true }; }));
    r.post('/pw/:id/items/:item/restore', J((req) => { const s = this.store(req.params.id); return s.trash(req.params.item, false); }));
    r.get('/pw/:id/items/:item/totp', J(async (req) => { const it = await this.store(req.params.id).get(req.params.item); return pwc.totp(it.totp) || { error: T('No TOTP saved') }; }));
    r.get('/pw/:id/folders', J((req) => { const s = this.store(req.params.id); return s.folders ? s.folders() : []; }));
    r.put('/pw/:id/folders', J((req) => this.store(req.params.id).setFolders((req.body || {}).folders)));
    r.get('/pw/:id/tags', J((req) => { const s = this.store(req.params.id); return s.tags ? s.tags() : []; }));
    r.post('/pw/:id/trash/empty', J((req) => ({ removed: this.store(req.params.id).emptyTrash() })));
    r.post('/pw/:id/audit', J((req) => this.audit(req.params.id, req.body || {})));
    r.post('/pw/:id/import', J((req) => this.importText(req.params.id, String((req.body || {}).text || ''), req.body || {})));
    r.post('/pw/:id/import-preview', (req, res) => { const p = formats.detectAndParse(String((req.body || {}).text || '')); res.json({ format: p.format, label: p.label, count: p.items.length, sample: p.items.slice(0, 5).map(({ password, totp, ...x }) => ({ ...x, hasPassword: !!password })) }); }); // eslint-disable-line no-unused-vars
    r.post('/pw/:id/export', async (req, res) => { const e = await this.exportText(req.params.id, (req.body || {}).kind); res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(e.name)}"`); res.type(e.mime); res.send(e.text); });
    r.post('/pw/:id/transfer', J((req) => this.transfer(req.params.id, (req.body || {}).to, req.body || {})));
    r.post('/pw/:id/sync', J(async (req) => { const s = this.store(req.params.id); if (s.sync) await s.sync(); return { ok: true }; }));
  }

  /** Routes for the browser extension (pairing without the Hostwerk token; everything else with the extension key). */
  extRoutes(r) {
    r.post('/pw/ext/pair', (req, res) => { try { res.json(this.pair((req.body || {}).code, req.body || {})); } catch (e) { res.status(e.status || 400).json({ error: e.message }); } });
    r.post('/pw/ext/autopair', (req, res) => { try { res.json(this.autoPair(req)); } catch (e) { res.status(e.status || 400).json({ error: e.message }); } });
    const E = (fn) => async (req, res) => { const e = this.extAuth(req); if (!e) return res.status(401).json({ error: T('Extension not paired') }); try { return res.json(await fn(req, e)); } catch (err) { return res.status(err.status || 400).json({ error: err.message }); } };
    r.get('/pw/ext/status', E(async (req, e) => ({ ok: true, name: e.name, autoLogin: this.cfg.autoLogin === true, autofill: this.autofillCfg(), vaults: this.list().map((i) => ({ id: i.id, name: i.name, locked: this.info(i).locked, default: this.cfg.defaultId === i.id })) })));
    r.post('/pw/ext/unlock', E(async (req) => this.unlock((req.body || {}).id || this.cfg.defaultId, (req.body || {}).password)));
    r.get('/pw/ext/match', E(async (req) => {
      const url = String(req.query.url || ''); const out = [];
      for (const i of this.list()) {
        const s = this.stores.get(i.id); if (!s || s.locked()) continue;
        if (i.type === 'hostwerk') for (const m of s.matches(url)) out.push({ ...m, vault: i.id, vaultName: i.name });
        else { let h = ''; try { h = new URL(url).hostname; } catch { /* ignore */ } const all = await s.all().catch(() => []); for (const it of all) if (!it.trashed && (it.urls || []).some((u) => u.includes(h))) { const { password, totp, notes, fields, ...rest } = it; out.push({ ...rest, hasTotp: !!totp, vault: i.id, vaultName: i.name }); } } // eslint-disable-line no-unused-vars
      }
      return { items: out, locked: this.list().filter((i) => this.info(i).locked).map((i) => ({ id: i.id, name: i.name })) };
    }));
    r.get('/pw/ext/fill', E(async (req, e) => { const it = await this.store(String(req.query.vault)).get(String(req.query.item)); this.record(it.name, T('Filled in in the browser ({name})', { name: e.name })); return { username: it.username, password: it.password, totp: it.totp ? pwc.totp(it.totp) : null, fields: (it.fields || []).filter((f) => !f.hidden) }; }));
    r.post('/pw/ext/save', E(async (req, e) => { const b = req.body || {}; const id = b.vault || this.cfg.defaultId; if (!id) throw new Error(T('No vault')); const it = await this.addItem(id, { type: 'login', name: b.name || b.host || T('New'), username: b.username, password: b.password, urls: [b.url].filter(Boolean), source: 'browser' }); this.record(it.name, T('Saved from the browser ({name})', { name: e.name })); return it; }));
    r.get('/pw/ext/search', E(async (req) => {
      const q = String(req.query.q || '').trim().toLowerCase();
      if (q.length < 1) return { items: [] };
      const out = [];
      for (const i of this.list()) {
        const st = this.stores.get(i.id); if (!st || st.locked()) continue;
        const all = await st.all().catch(() => []);
        for (const it of all) {
          if (it.trashed) continue;
          const hay = [it.name, it.username, ...(it.urls || [])].join(' ').toLowerCase();
          if (!hay.includes(q)) continue;
          const { password, totp, notes, fields, ...rest } = it; // eslint-disable-line no-unused-vars
          out.push({ ...rest, hasTotp: !!totp, vault: i.id, vaultName: i.name });
          if (out.length >= 50) break;
        }
      }
      return { items: out, locked: this.list().filter((i) => this.info(i).locked).map((i) => ({ id: i.id, name: i.name })) };
    }));
    // Pairing removed in the extension → also removed in Hostwerk (the "paired browsers" list is current right away)
    r.delete('/pw/ext/self', E(async (req, e) => { this.revokeExt(e.id, 'browser'); return { ok: true }; }));
    r.post('/pw/ext/generate', E(async (req) => ({ password: pwc.generate(req.body || {}) })));
    r.post('/pw/ext/lock', E(async () => { this.lockAll(); return { ok: true }; }));
  }
}

module.exports = { PasswordManager };
