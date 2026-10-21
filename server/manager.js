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
 *   - Self-maintenance: provider programs (bw, op, clis.js) only for set-up providers – loaded when connecting, version
 *     check and test run, Smart App Control recognised; kdbxweb version, HIBP reachability, online catalogue
 *   - Import/export of every common format (io.js, formats.js), attachments, SSH keys, passkeys, website icons (cached
 *     locally), generator rules per site, encrypted daily backups in Hostwerk's backup centre
 *   - AI: tools never see passwords (only names/users/addresses/check results)
 * Secrets of the provider configuration are sealed in the settings (core/secrets). Data stays where it always was:
 * settings.passwords and data/passwoerter.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { VaultStore, TYPES, hostOf } = require('./store');
const { PROVIDERS, NO_ICONS, IS_WIN } = require('./providers');
const { imageMime, MAX_ICON } = require('./store');
const { Clis } = require('./clis');
const formats = require('./formats');
const io = require('./io');
const sshkey = require('./sshkey');
const pwc = require('./crypto');
const host = require('./host');
const { T, N } = require('./i18n');

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
    this.clis = new Clis(this);
    this.loadCatalog().catch(() => {});
    // Verschlüsselte Sicherung der Hostwerk-Tresore: täglich, nur wenn sich die Datei geändert hat (14 Stände je Tresor)
    if (!process.env.HW_TEST) this.timers.push(setInterval(() => { try { this.backupAll(); } catch { /* nächster Tag */ } }, 6 * 3600e3));
    if (!process.env.HW_TEST) this.timers.push(setInterval(() => this.loadCatalog({ online: true }).catch(() => {}), 24 * 3600000));
    for (const t of this.timers) if (t.unref) t.unref();
  }
  /** Password generator and rating for Hostwerk (e.g. the AI tool pw_generate) – never touches a vault. */
  generate(opts = {}) { return pwc.generate(opts); }
  strength(pw) { return pwc.strength(pw); }
  stop() { for (const t of this.timers) clearInterval(t); this.timers = []; for (const s of this.stores.values()) { try { s.lock(); } catch { /* ignore */ } } }
  get cfg() { const s = this.ctx.settings.get(); if (!s.passwords) s.passwords = { instances: [], ext: [], autoLockMin: 15, audit: { hibp: true }, clipboardSec: 30, icons: true }; if (!s.passwords.ext) s.passwords.ext = []; if (!s.passwords.instances) s.passwords.instances = []; if (!s.passwords.audit) s.passwords.audit = { hibp: true }; return s.passwords; }
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
    return { id: i.id, name: i.name, type: i.type, label: i.type === 'hostwerk' ? T('Hostwerk vault') : (prov && prov.label) || i.type, native: i.type === 'hostwerk' || !!(prov && prov.native), readonly: !!(prov && prov.readonly), cli: (prov && prov.cli) || null, locked: !s || s.locked(), exists: i.type === 'hostwerk' ? fs.existsSync(this.file(i.id)) : true, cfg: this.pubCfg(i), createdAt: i.createdAt, audit: this.audits.get(i.id) || null, default: this.cfg.defaultId === i.id, color: i.color || null };
  }
  pubCfg(i) { const out = {}; for (const [k, v] of Object.entries(i.cfg || {})) out[k] = typeof v === 'string' && v.startsWith('enc:') ? '••••' : v; return out; }
  file(id) { return path.join(this.dir, `${id}.hwvault`); }
  store(id) {
    const i = this.get(id);
    let s = this.stores.get(id);
    if (!s) {
      if (i.type === 'hostwerk') s = new VaultStore(this.file(id), { autoLockMin: this.cfg.autoLockMin ?? 15 });
      else { const P = PROVIDERS[i.type]; if (!P) throw new Error(T('Unknown provider “{type}”', { type: i.type })); s = new P.cls(this.ctx, i, this); }
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
    const out = this.info(inst);
    // Anbieter mit eigenem Programm: gleich beim Einrichten laden (Fortschritt als Auftrag) – bis zum Verbinden ist es da
    const P = PROVIDERS[type];
    if (P && P.cli && !(await this.clis.lookup(P.cli)) && !(this.clis.state[P.cli] || {}).installing) { try { out.cliJob = this.clis.install(P.cli).id; } catch { /* Verbinden bietet es erneut an */ } }
    return out;
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
  async removeNow(id, { deleteFile = false } = {}) { const i = this.get(id); const s = this.stores.get(id); if (s && s.lock) s.lock(); this.stores.delete(id); this.cfg.instances = this.list().filter((x) => x.id !== id); if (this.cfg.defaultId === id) this.cfg.defaultId = (this.list()[0] || {}).id || null; this.save(); if (deleteFile && i.type === 'hostwerk') { fs.rmSync(this.file(id), { force: true }); fs.rmSync(path.join(this.dir, `${id}.files`), { recursive: true, force: true }); fs.rmSync(this.backupDir(id), { recursive: true, force: true }); } broadcast({ type: 'passwords' }); }
  /** Nach einem neuen Anbieter-Programm: offene Verbindungen dieser Anbieter schließen (nächster Zugriff verbindet neu). */
  relock(types) { for (const i of this.list()) if (types.includes(i.type)) { const s = this.stores.get(i.id); if (s && s.lock) s.lock(); } broadcast({ type: 'passwords' }); }

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
    const yes = (x) => x === true || x === '1' || x === 'true';
    if (yes(q.trashed)) return [];
    return all.filter((x) => !x.trashed && (!q.folder || x.folder === q.folder || String(x.folder || '').startsWith(`${q.folder}/`)) && (!q.type || x.type === q.type) && (!q.tag || (x.tags || []).includes(q.tag)) && (!yes(q.fav) || x.favorite) && (!q.has || (q.has === 'totp' ? !!x.totp : q.has === 'passkey' ? (x.passkeys || []).length > 0 : q.has === 'files' ? false : true)) && (!n || `${x.name} ${x.username || ''} ${(x.urls || []).join(' ')}`.toLowerCase().includes(n)))
      .map(({ password, totp, notes, fields, passkeys, ...rest }) => ({ ...rest, hasPassword: !!password, hasTotp: !!totp, hasNotes: !!notes, fieldCount: (fields || []).length, passkeyCount: (passkeys || []).length, pwScore: password ? pwc.strength(password).score : null, host: hostOf((rest.urls || [])[0] || '') || null })).sort((a, b) => (b.favorite - a.favorite) || a.name.localeCompare(b.name, 'de'));
  }
  /** Zahlen für die Navigation (Alle, Favoriten, je Art, Passkeys, Anhänge, Papierkorb, Ordner, Schlagwörter). */
  async stats(id) {
    const i = this.get(id); const s = this.store(id);
    if (i.type === 'hostwerk') return s.stats();
    if (s.locked()) throw Object.assign(new Error(T('{name} is not connected – please unlock.', { name: i.name })), { status: 423 });
    const live = (await s.all()).filter((x) => !x.trashed);
    const count = (fn) => live.filter(fn).length;
    const folders = new Map(); const tags = new Map();
    for (const x of live) { if (x.folder) folders.set(x.folder, (folders.get(x.folder) || 0) + 1); for (const t of x.tags || []) tags.set(t, (tags.get(t) || 0) + 1); }
    return { all: live.length, fav: count((x) => x.favorite), ...Object.fromEntries(TYPES.map((t) => [t, count((x) => x.type === t)])), passkey: count((x) => (x.passkeys || []).length), files: 0, trash: 0, folders: [...folders].map(([name, n]) => ({ name, count: n })).sort((a, b) => a.name.localeCompare(b.name, 'de')), tags: [...tags].map(([name, n]) => ({ name, count: n })).sort((a, b) => b.count - a.count) };
  }
  /** Ein Eintrag mit Geheimnissen – private Schlüssel der Passkeys bleiben im Tresor (nur für Export/Übertragen). */
  async item(id, itemId) { const i = this.get(id); const s = this.store(id); if (i.type !== 'hostwerk' && s.locked()) throw Object.assign(new Error(T('Not connected')), { status: 423 }); const it = await s.get(itemId); this.record(`${i.name}: ${it.name}`, T('Item viewed (secret retrieved)')); return { ...it, icon: undefined, hasIcon: !!(it.icon && it.icon.data) || !!it.hasIcon, iconV: (it.icon && it.icon.v) || it.iconV || null, passkeys: (it.passkeys || []).map(({ keyValue, ...p }) => ({ ...p, hasKey: !!keyValue })), pwStrength: it.password ? pwc.strength(it.password) : null }; }
  /** SSH-Einträge: öffentlichen Teil und Fingerabdruck aus dem privaten Schlüssel ableiten. */
  prepItem(b) { if (b && b.type === 'ssh' && b.ssh && (b.ssh.privateKey || b.ssh.publicKey)) return { ...b, ssh: sshkey.describe(b.ssh) }; return b; }
  async addItem(id, b) { const i = this.get(id); const s = this.store(id); if (PROVIDERS[i.type] && PROVIDERS[i.type].readonly) throw new Error(T('This provider is read-only.')); const it = await s.add(this.prepItem(b)); broadcast({ type: 'passwords', id }); return i.type === 'hostwerk' ? s.pub(it) : it; }
  async updateItem(id, itemId, b) { const i = this.get(id); const s = this.store(id); if (PROVIDERS[i.type] && PROVIDERS[i.type].readonly) throw new Error(T('This provider is read-only.')); const it = await s.update(itemId, this.prepItem(b)); broadcast({ type: 'passwords', id }); return i.type === 'hostwerk' ? s.pub(it) : it; }
  /** Kann dieser Tresor eigene Bilder speichern? → { ok, why } (why = Grund in Englisch, die Oberfläche übersetzt) */
  iconSupport(type) { return type === 'hostwerk' || type === 'keepass' ? { ok: true, why: null } : { ok: false, why: NO_ICONS[type] || 'This provider cannot store own images.' }; }
  /** Own image of an item: data: address / Base64 (null = remove). Hostwerk vault encrypted, KeePass as custom icon. */
  async setItemIcon(id, itemId, data) {
    const i = this.get(id); const s = this.store(id);
    const sup = this.iconSupport(i.type);
    if (!sup.ok) throw Object.assign(new Error(T(sup.why)), { status: 400 });
    let buf = null;
    if (data) {
      const m = String(data).match(/^data:[^;,]*;base64,(.*)$/);
      buf = Buffer.from(m ? m[1] : String(data), 'base64');
      if (buf.length > MAX_ICON || !imageMime(buf)) throw Object.assign(new Error(T('Only PNG, JPEG, WebP or GIF images up to {kb} KB.', { kb: MAX_ICON / 1024 })), { status: 400 });
    }
    if (i.type !== 'hostwerk' && s.locked()) throw Object.assign(new Error(T('Not connected')), { status: 423 });
    const r = i.type === 'hostwerk' ? s.setIcon(itemId, buf) : await s.setIcon(itemId, buf);
    broadcast({ type: 'passwords', id });
    return { ok: true, hasIcon: !!r.hasIcon, iconV: r.iconV || null };
  }
  async itemIcon(id, itemId) {
    const i = this.get(id); const s = this.store(id);
    if (i.type === 'hostwerk') return s.icon(itemId);
    if (s.getIcon && !s.locked()) { const b = await s.getIcon(itemId); return b ? { mime: imageMime(b) || 'image/png', data: b } : null; }
    return null;
  }
  /** Nur Hostwerk-Tresore: Anhänge, Passkeys entfernen */
  own(id) { const i = this.get(id); if (i.type !== 'hostwerk') throw Object.assign(new Error(T('Only for the Hostwerk vault.')), { status: 400 }); return this.store(id); }
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
      if (it.type === 'login' && !it.totp && !(it.passkeys || []).length && (it.urls || []).some((u) => /(google|microsoft|apple|amazon|paypal|github|facebook|instagram|twitter|x\.com|bank|sparkasse|dkb|ing|comdirect|steam|discord|dropbox|cloudflare|hetzner|ionos|strato)/i.test(u))) F(it, 'no2fa', T('Important service without a saved 2FA (TOTP)'), 'warn');
      if (useHibp) {
        try { let n = checked.get(it.password); if (n === undefined) { n = await pwc.pwned(it.password); checked.set(it.password, n); } if (n > 0) { leaked++; F(it, 'leaked', T('Showed up in {n} data leaks – change it now', { n: N(n) }), 'err'); } } catch (e) { if (!findings.some((f) => f.kind === 'hibp-error')) findings.push({ kind: 'hibp-error', level: 'info', text: T('Leak check not possible: {msg}', { msg: e.message }), name: '', itemId: null }); break; }
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
  dupKey(x) { return `${(x.name || '').toLowerCase()}|${(x.username || '').toLowerCase()}|${((x.urls || [])[0] || '').toLowerCase()}`; }
  /**
   * Preview of an import file (any format, see io.parseInput): format, count, first items without secrets, how many are
   * already in the vault (duplicates) and – for a general CSV – the columns with the guessed assignment.
   */
  async importPreview(id, payload = {}) {
    let parsed;
    try { parsed = await io.parseInput(payload); } catch (e) {
      if (e.needsPassword) return { needsPassword: true, message: e.message };
      if (e.needsMapping) return { needsMapping: true, head: e.head, mapping: formats.guessMapping(e.head), fields: formats.MAP_FIELDS, message: e.message };
      throw e;
    }
    let duplicates = null;
    try { const have = new Set((await this.allWithSecrets(id)).map((x) => this.dupKey(x))); duplicates = parsed.items.filter((x) => have.has(this.dupKey(x))).length; } catch { /* gesperrt */ }
    const counts = {}; for (const x of parsed.items) counts[x.type] = (counts[x.type] || 0) + 1;
    return { format: parsed.format, label: parsed.label, count: parsed.items.length, counts, duplicates, head: parsed.head || null, mapping: parsed.mapping || null, fields: formats.MAP_FIELDS,
      sample: parsed.items.slice(0, 8).map((x) => ({ name: x.name, username: x.username || '', type: x.type, url: (x.urls || [])[0] || '', folder: x.folder || '', hasPassword: !!x.password, hasTotp: !!x.totp, passkeys: (x.passkeys || []).length })) };
  }
  /** Take over an import file – duplicates (name + user + address) are skipped unless wanted. */
  async importFile(id, payload = {}, { folder = '', skipDuplicates = true } = {}) {
    const parsed = await io.parseInput(payload);
    const i = this.get(id); const s = this.store(id);
    const have = new Set((await this.allWithSecrets(id)).map((x) => this.dupKey(x)));
    const fresh = parsed.items.filter((x) => !skipDuplicates || !have.has(this.dupKey(x))).map((x) => this.prepImport({ ...x, folder: folder || x.folder }));
    let added = 0;
    if (i.type === 'hostwerk') { s.addMany(fresh); added = fresh.length; } else { for (const x of fresh) { await s.add(x); added++; } }
    broadcast({ type: 'passwords', id });
    this.record(i.name, T('{n} items imported ({label})', { n: added, label: parsed.label }));
    return { format: parsed.format, label: parsed.label, found: parsed.items.length, added, skipped: parsed.items.length - fresh.length };
  }
  /** SSH-Schlüssel aus Importen ergänzen (öffentlicher Teil, Fingerabdruck) – unlesbare bleiben, wie sie sind. */
  prepImport(x) { if (x.type === 'ssh' && x.ssh && x.ssh.privateKey && !x.ssh.publicKey) { try { return { ...x, ssh: sshkey.describe(x.ssh) }; } catch { return x; } } return x; }
  /** Compatibility: plain text (CSV/JSON) as before. */
  importText(id, text, opts = {}) { return this.importFile(id, { text }, opts); }

  /**
   * Export. Encrypted: "kdbx" (KeePass, own password) and "bitwarden-encrypted" (Bitwarden JSON with password).
   * Unencrypted (bitwarden-json, *-csv) only with plain: true – the interface asks with a clear warning first.
   */
  async exportFile(id, { kind = 'bitwarden-json', password = '', plain = false } = {}) {
    const i = this.get(id);
    const items = (await this.allWithSecrets(id)).filter((x) => !x.trashed);
    const enc = kind === 'kdbx' || kind === 'bitwarden-encrypted';
    if (enc && (typeof password !== 'string' || password.length < 8)) throw Object.assign(new Error(T('The password for the export file needs at least 8 characters.')), { status: 400 });
    if (!enc && plain !== true) throw Object.assign(new Error(T('Unencrypted exports contain every password in plain text – please confirm first.')), { status: 428 });
    this.record(i.name, T(enc ? 'Encrypted export ({kind}, {n} items)' : 'Export ({kind}, {n} items)', { kind, n: items.length }));
    if (kind === 'kdbx') return { data: await io.writeKdbx(items, password, i.name), name: `${i.name}.kdbx`, mime: 'application/octet-stream' };
    if (kind === 'bitwarden-encrypted') return { data: Buffer.from(await io.bitwardenEncrypted(items, password)), name: `${i.name}-bitwarden-encrypted.json`, mime: 'application/json' };
    if (kind === 'bitwarden-json') return { data: Buffer.from(formats.exportBitwardenJson(items, [...new Set(items.map((x) => x.folder).filter(Boolean))])), name: `${i.name}.json`, mime: 'application/json' };
    if (!/^(bitwarden|chrome|keepass|generic)-csv$/.test(kind)) throw Object.assign(new Error(T('Unknown export format')), { status: 400 });
    return { data: Buffer.from(formats.exportCsv(items, kind.replace('-csv', ''))), name: `${i.name}-${kind}.csv`, mime: 'text/csv' };
  }
  /** Compatibility (1.x): text export / KeePass file. */
  async exportText(id, kind = 'bitwarden-json') { const r = await this.exportFile(id, { kind, plain: true }); return { text: r.data.toString('utf8'), name: r.name, mime: r.mime }; }
  exportKdbx(id, password) { return this.exportFile(id, { kind: 'kdbx', password }); }

  /* ---------- encrypted backups (backup centre) ---------- */
  backupDir(id) { return path.join(this.dir, 'sicherungen', id); }
  /** Copy of the (already encrypted) vault file + attachments, when it changed since the last copy. 14 stay. */
  backupVault(id, { force = false } = {}) {
    const f = this.file(id);
    if (!fs.existsSync(f)) return null;
    const dir = this.backupDir(id);
    fs.mkdirSync(dir, { recursive: true });
    const mtime = fs.statSync(f).mtimeMs;
    const have = fs.readdirSync(dir).filter((x) => /^\d+\.hwvault$/.test(x)).sort();
    if (!force && have.length && Number(have[have.length - 1].split('.')[0]) >= mtime) return null;
    const t = Date.now();
    fs.copyFileSync(f, path.join(dir, `${t}.hwvault`));
    const files = path.join(this.dir, `${id}.files`);
    if (fs.existsSync(files)) fs.cpSync(files, path.join(dir, `${t}.files`), { recursive: true });
    for (const old of fs.readdirSync(dir).filter((x) => /^\d+\.hwvault$/.test(x)).sort().slice(0, -14)) { const n = old.split('.')[0]; fs.rmSync(path.join(dir, old), { force: true }); fs.rmSync(path.join(dir, `${n}.files`), { recursive: true, force: true }); }
    return t;
  }
  backupAll() { for (const i of this.list()) if (i.type === 'hostwerk') this.backupVault(i.id); }
  /** Source for Hostwerk's backup centre (SDK 2.10, host.backups.register) – list, restore, remove, external backup. */
  backupSource() {
    const parse = (itemId) => { const m = String(itemId).match(/^([a-z]+-[0-9a-f]{6})~(\d+)$/); if (!m) throw Object.assign(new Error(T('Backup not found')), { status: 404 }); const f = path.join(this.backupDir(m[1]), `${m[2]}.hwvault`); if (!fs.existsSync(f)) throw Object.assign(new Error(T('Backup not found')), { status: 404 }); return { id: m[1], t: Number(m[2]), f }; };
    return {
      label: { de: 'Passwort-Tresore', en: 'Password vaults' },
      list: () => this.list().filter((i) => i.type === 'hostwerk').flatMap((i) => { const dir = this.backupDir(i.id); if (!fs.existsSync(dir)) return []; return fs.readdirSync(dir).filter((x) => /^\d+\.hwvault$/.test(x)).map((x) => { const t = Number(x.split('.')[0]); return { id: `${i.id}~${t}`, label: T('{name} (encrypted)', { name: i.name }), t, size: fs.statSync(path.join(dir, x)).size, auto: true, svc: i.id, svcName: i.name, href: `#/ext/passwords/${i.id}` }; }); }),
      restore: async (itemId) => {
        const b = parse(itemId);
        this.backupVault(b.id, { force: true }); // aktuellen Stand vorher sichern – wie alle Wege der Sicherungs-Zentrale
        const s = this.stores.get(b.id); if (s) s.lock();
        const target = this.file(b.id);
        fs.copyFileSync(b.f, target + '.zurueck'); fs.renameSync(target + '.zurueck', target);
        const files = path.join(this.dir, `${b.id}.files`); const saved = path.join(this.backupDir(b.id), `${b.t}.files`);
        fs.rmSync(files, { recursive: true, force: true }); if (fs.existsSync(saved)) fs.cpSync(saved, files, { recursive: true });
        this.record(this.get(b.id).name, T('Vault restored from the backup of {date}', { date: new Date(b.t).toLocaleString('de-DE') }));
        broadcast({ type: 'passwords' });
        return { ok: true };
      },
      remove: (itemId) => { const b = parse(itemId); fs.rmSync(b.f, { force: true }); fs.rmSync(path.join(this.backupDir(b.id), `${b.t}.files`), { recursive: true, force: true }); },
      // Externe Sicherung: jeweils der neueste Stand je Tresor (bleibt verschlüsselt – ohne Master-Passwort nutzlos)
      offsite: ({ dir }) => { const out = []; for (const i of this.list()) if (i.type === 'hostwerk' && fs.existsSync(this.file(i.id))) { const d = path.join(dir, `passwoerter-${i.id}.hwvault`); fs.copyFileSync(this.file(i.id), d); out.push(d); } return out; },
    };
  }

  /* ---------- website icons (cached locally) ---------- */
  iconDir() { return path.join(this.dir, 'symbole'); }
  /**
   * Icon of a website for the list: page → <link rel="icon">, otherwise /favicon.ico. Cached for 30 days (misses 7 days),
   * only public host names (no IP addresses, no local names), at most 200 KB, only real image formats.
   */
  async siteIcon(h) {
    const hostName = String(h || '').toLowerCase();
    if (this.cfg.icons === false) return null;
    if (!/^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/.test(hostName) || /\.(local|lan|home|internal|localhost|test|arpa)$/.test(hostName)) return null;
    const dir = this.iconDir(); fs.mkdirSync(dir, { recursive: true });
    const base = path.join(dir, hostName);
    for (const ext of ['png', 'ico', 'svg', 'jpg', 'gif', 'webp']) { const f = `${base}.${ext}`; if (fs.existsSync(f) && Date.now() - fs.statSync(f).mtimeMs < 30 * 864e5) return f; }
    if (fs.existsSync(`${base}.none`) && Date.now() - fs.statSync(`${base}.none`).mtimeMs < 7 * 864e5) return null;
    // Nur öffentliche Adressen (auch nach Weiterleitungen und DNS) – kein Zugriff aufs Heimnetz über einen Namen
    const isPrivate = (ip) => /^(127\.|10\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(ip) || /^(::1?$|f[cd]|fe80:|::ffff:(127|10|192\.168)\.)/i.test(ip);
    const safeHost = async (h2) => { try { const all = await require('dns').promises.lookup(h2, { all: true }); return all.length > 0 && !all.some((a) => isPrivate(a.address)); } catch { return false; } };
    const get = async (url, max) => {
      let u = url;
      for (let hop = 0; hop < 4; hop++) {
        const p = new URL(u);
        if (p.protocol !== 'https:' || !(await safeHost(p.hostname))) return null;
        const r = await fetch(u, { redirect: 'manual', signal: AbortSignal.timeout(6000), headers: { 'User-Agent': 'Mozilla/5.0 Hostwerk' } });
        if (r.status >= 300 && r.status < 400 && r.headers.get('location')) { u = new URL(r.headers.get('location'), u).href; continue; }
        if (!r.ok) return null;
        const buf = Buffer.from(await r.arrayBuffer());
        return buf.length <= max ? buf : null;
      }
      return null;
    };
    const kind = (b) => (!b || b.length < 8 ? null : b[0] === 0x89 && b[1] === 0x50 ? 'png' : b[0] === 0 && b[1] === 0 && b[2] === 1 ? 'ico' : b[0] === 0xff && b[1] === 0xd8 ? 'jpg' : b.subarray(0, 3).toString() === 'GIF' ? 'gif' : b.subarray(8, 12).toString() === 'WEBP' ? 'webp' : /<svg[\s>]/i.test(b.subarray(0, 600).toString('utf8')) ? 'svg' : null);
    const cands = [];
    try {
      const html = (await get(`https://${hostName}/`, 600 * 1024) || Buffer.alloc(0)).toString('utf8');
      for (const m of html.matchAll(/<link\b[^>]*>/gi)) { const tag = m[0]; if (!/rel\s*=\s*["']?[^"'>]*\bicon\b/i.test(tag)) continue; const href = (tag.match(/href\s*=\s*["']([^"']+)["']/i) || [])[1]; if (href) { try { cands.push(new URL(href, `https://${hostName}/`).href); } catch { /* ungültig */ } } }
    } catch { /* Seite nicht erreichbar */ }
    cands.push(`https://${hostName}/favicon.ico`);
    for (const u of cands.slice(0, 5)) {
      if (!/^https:\/\//.test(u)) continue;
      try { const b = await get(u, 200 * 1024); const k = kind(b); if (k) { const f = `${base}.${k}`; fs.writeFileSync(f, b); return f; } } catch { /* nächste */ }
    }
    fs.writeFileSync(`${base}.none`, '');
    return null;
  }

  /* ---------- generator rules per site ---------- */
  get genRules() { if (!this.cfg.genRules || typeof this.cfg.genRules !== 'object') this.cfg.genRules = {}; return this.cfg.genRules; }
  setGenRule(site, opts) {
    const h = hostOf(String(site || '')).replace(/^www\./, '');
    if (!h) throw Object.assign(new Error(T('Please enter a website address.')), { status: 400 });
    if (opts === null) { delete this.genRules[h]; this.save(); return this.genRules; }
    const o = opts || {};
    this.genRules[h] = { length: Math.max(6, Math.min(128, Number(o.length) || 20)), lower: o.lower !== false, upper: o.upper !== false, digits: o.digits !== false, symbols: !!o.symbols, words: Math.max(0, Math.min(10, Number(o.words) || 0)) };
    this.save();
    return this.genRules;
  }
  /** Generator options for an address: the rule of the site (also for subdomains), otherwise the given ones. */
  genFor(url, fallback = {}) { const h = hostOf(String(url || '')).replace(/^www\./, ''); const key = h && Object.keys(this.genRules).find((k) => h === k || h.endsWith(`.${k}`)); return key ? { ...this.genRules[key], site: key } : fallback; }

  /**
   * Tresor als Dienst für andere Erweiterungen (host.use('passwordVault')): Dateifreigabe, Mailserver, Router,
   * Cloud-Sicherung … legen Zugangsdaten mit einem Aufruf im Standard-Tresor ab. Lesen geht nur über die eigene
   * Kennung (source) – fremde Einträge sieht eine Erweiterung nie.
   */
  vaultService() {
    const pick = () => {
      const id = this.cfg.defaultId && this.list().some((x) => x.id === this.cfg.defaultId) ? this.cfg.defaultId : (this.list()[0] || {}).id;
      return id ? this.get(id) : null;
    };
    const state = () => { const v = pick(); return v ? { available: true, vault: { id: v.id, name: v.name }, locked: !!this.info(v).locked, readonly: !!(PROVIDERS[v.type] && PROVIDERS[v.type].readonly) } : { available: false, vault: null, locked: false, readonly: false }; };
    const need = () => {
      const s = state();
      if (!s.available) throw Object.assign(new Error(T('No vault yet – create one under Passwords first.')), { status: 409 });
      if (s.readonly) throw Object.assign(new Error(T('This provider is read-only.')), { status: 409 });
      if (s.locked) throw Object.assign(new Error(T('The vault “{name}” is locked – unlock it under Passwords first.', { name: s.vault.name })), { status: 423 });
      return s.vault;
    };
    const mine = async (vault, source, key) => (await this.allWithSecrets(vault.id)).find((x) => !x.trashed && x.source === source && (x.fields || []).some((f) => f.name === 'hostwerk-key' && f.value === key));
    return {
      status: state,
      /**
       * Zugang ablegen oder aktualisieren. item = { key, source, name, username, password, url, notes, folder }
       * key + source machen ihn eindeutig (z. B. source 'file-share', key 'sftp:alex') – erneutes Speichern ersetzt das
       * Passwort (das alte bleibt im Verlauf). → { id, vault, updated }
       */
      save: async (item = {}) => {
        const source = String(item.source || '').slice(0, 40); const key = String(item.key || item.name || '').slice(0, 120);
        if (!/^[a-z0-9][a-z0-9-]{1,39}$/.test(source)) throw Object.assign(new Error('save: "source" is the id of the calling extension'), { status: 400 });
        if (!key || !item.password) throw Object.assign(new Error('save: "key" and "password" are needed'), { status: 400 });
        const vault = need();
        const old = await mine(vault, source, key);
        // Beim Aktualisieren bleibt, was der Aufrufer nicht mitschickt (Adresse, Notizen, Benutzer)
        const body = { type: 'login', name: String(item.name || (old && old.name) || key).slice(0, 120), username: String(item.username ?? (old && old.username) ?? ''), password: String(item.password), urls: item.url ? [String(item.url)] : (old && old.urls) || [], notes: String(item.notes ?? (old && old.notes) ?? ''), folder: String(item.folder || 'Hostwerk'), source, fields: [{ name: 'hostwerk-key', value: key, hidden: false }] };
        const it = old ? await this.updateItem(vault.id, old.id, body) : await this.addItem(vault.id, body);
        this.record(`${vault.name}: ${body.name}`, T(old ? 'Access updated by the extension {ext}' : 'Access saved by the extension {ext}', { ext: source }));
        return { id: it.id, vault: vault.id, updated: !!old };
      },
      /** Gibt es den Zugang schon? Ohne Passwort. → { id, name, username, url } oder null */
      find: async ({ source, key } = {}) => { const vault = need(); const it = await mine(vault, String(source || ''), String(key || '')); return it ? { id: it.id, name: it.name, username: it.username || '', url: (it.urls || [])[0] || '' } : null; },
      /** Den eigenen Zugang wieder herausgeben (z. B. um sich anzumelden) – nur für die eigene source, wird protokolliert. */
      reveal: async ({ source, key } = {}) => { const vault = need(); const it = await mine(vault, String(source || ''), String(key || '')); if (!it) return null; this.record(`${vault.name}: ${it.name}`, T('Access read by the extension {ext}', { ext: source })); return { username: it.username || '', password: it.password || '' }; },
    };
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
    if (!w || Date.now() > w.until) throw this.pairFail('window', T('Pairing not allowed – click “Install” in Hostwerk under Passwords → Browser.'), 403);
    // Store version: only the real extension id
    const ids = Object.values((this.storeInfo || {}).ids || {}).filter(Boolean);
    if (m[1] === 'chrome' && ids.length && !ids.includes(m[2]) && !this.devExt) throw this.pairFail('unknown', T('Unknown extension.'), 403);
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

  /** One-time ticket (in memory, 30 min) – for automatic pairing right after "Install" without the folder. */
  pairTicket() { const ticket = crypto.randomBytes(24).toString('hex'); this.pairings.set(ticket, { at: Date.now(), auto: true }); setTimeout(() => this.pairings.delete(ticket), 30 * 60000).unref(); return ticket; }
  /**
   * Ticket for the extension folder (hostwerk-pairing.json): stored as a hash in the settings, valid for 90 days and
   * reusable – so the extension pairs itself again after a Hostwerk restart, a lost key or an update, without a code.
   * Whoever can read the folder is the user of this PC anyway (same trust as the settings file).
   */
  get extTickets() { if (!Array.isArray(this.cfg.extTickets)) this.cfg.extTickets = []; this.cfg.extTickets = this.cfg.extTickets.filter((x) => x && x.until > Date.now()); return this.cfg.extTickets; }
  folderTicket(existing = null) {
    const sha = (x) => crypto.createHash('sha256').update(String(x)).digest('hex');
    if (existing && this.extTickets.some((x) => x.hash === sha(existing) && x.until - Date.now() > 30 * DAY)) return existing;
    const ticket = crypto.randomBytes(24).toString('hex');
    this.cfg.extTickets = [...this.extTickets, { hash: sha(ticket), created: Date.now(), until: Date.now() + 90 * DAY }].slice(-5);
    this.save();
    return ticket;
  }
  /** Remember why pairing failed (the extension card in Hostwerk shows it with the fix). */
  pairFail(reason, message, status = 401) { this.extPairError = { at: Date.now(), reason, message }; return Object.assign(new Error(message), { status, reason }); }
  pair(code, { name = 'Browser', browser = '', version = '' } = {}) {
    const c = String(code || '');
    const sha = crypto.createHash('sha256').update(c).digest('hex');
    const p = this.pairings.get(c);
    const folder = !p && c.length === 48 && this.extTickets.find((x) => x.hash === sha);
    if (!p && !folder) throw this.pairFail(c.length === 48 ? 'ticket' : 'code', c.length === 48 ? T('The pairing file of the extension is out of date – click “Install” in Hostwerk under Passwords → Browser once more.') : T('Pairing code invalid or expired – show a new one in Hostwerk under Passwords → Browser.'));
    if (p) this.pairings.delete(c);
    // Erneute Kopplung desselben Browsers über die Ordner-Datei ersetzt den alten Eintrag (keine Doppelten in der Liste)
    if (folder) this.cfg.ext = this.cfg.ext.filter((x) => !(x.via === sha && x.browser === String(browser).slice(0, 40)));
    const token = crypto.randomBytes(32).toString('hex');
    const e = { id: crypto.randomBytes(4).toString('hex'), name: String(name).slice(0, 60), browser: String(browser).slice(0, 40), hash: crypto.createHash('sha256').update(token).digest('hex'), created: Date.now(), lastUse: null, until: Date.now() + EXT_TTL, version: String(version || '').slice(0, 20) || null, ...(folder ? { via: sha } : {}) };
    this.cfg.ext.push(e); this.save(); broadcast({ type: 'passwords' });
    this.extPairError = null;
    this.pairWindow = null; // gekoppelt (egal auf welchem Weg) → das Fenster für Kopplung ohne Datei schließt sich
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
    const v = String(req.headers['x-hostwerk-ext-version'] || '');
    if (/^\d+\.\d+\.\d+$/.test(v) && e.version !== v) { e.version = v; this.save(); }
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

  /** Version of the extension Hostwerk brings along (browser-extension/manifest.json). */
  extVersion() { return readJson(path.join(extSource(), 'manifest.json'), {}).version || null; }
  /** Pairing file in the extension folder: current port + folder ticket (an existing valid one is kept). */
  writePairingFile(dir, name) {
    const file = path.join(dir, 'hostwerk-pairing.json');
    const old = readJson(file, {});
    fs.writeFileSync(file, JSON.stringify({ port: this.ctx.uiPort(), ticket: this.folderTicket(old.ticket || null), name: name || old.name || 'Browser', version: this.extVersion() }));
  }
  /**
   * On every start: the unpacked extension folder (if the user installed it) gets the current files and a pairing file
   * with today's port – a browser restart or "reload" picks up updates, and pairing works again after port changes.
   */
  refreshExtensionFolder() {
    const target = path.join(this.ctx.paths.base, 'browser-erweiterung', 'hostwerk-passwoerter');
    if (!fs.existsSync(path.join(target, 'manifest.json'))) return null;
    const run = async () => {
      const { dir } = await this.extensionFor('chrome');
      syncDir(dir, target);
      this.writePairingFile(target);
      return target;
    };
    return run().catch(() => null);
  }
  /** The extension says hello on start/after errors (no key needed): version, paired or not, what went wrong. */
  extHello(req) {
    const origin = String(req.headers.origin || '');
    if (!/^(chrome|moz)-extension:\/\/[a-z0-9-]+$/i.test(origin)) throw Object.assign(new Error(T('Only for the browser extension.')), { status: 403 });
    const b = req.body || {};
    this.lastHello = { at: Date.now(), origin, version: /^\d+\.\d+\.\d+$/.test(String(b.version || '')) ? String(b.version) : null, paired: !!b.paired, browser: String(b.browser || '').slice(0, 40), reason: String(b.reason || '').slice(0, 30) || null };
    broadcast({ type: 'passwords-ext' });
    return { ok: true, latest: this.extVersion(), port: this.ctx.uiPort() };
  }
  /** State for the extension card in Hostwerk: paired browsers (version, last seen), waiting, last error. */
  extState() {
    const latest = this.extVersion();
    const older = (v) => { if (!v || !latest) return false; const a = v.split('.').map(Number); const b = latest.split('.').map(Number); for (let i = 0; i < 3; i++) if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) < (b[i] || 0); return false; };
    const folder = path.join(this.ctx.paths.base, 'browser-erweiterung', 'hostwerk-passwoerter');
    return {
      latest,
      folder: fs.existsSync(path.join(folder, 'manifest.json')) ? folder : null,
      ext: this.cfg.ext.map(({ hash, via, ...e }) => ({ ...e, outdated: older(e.version), expired: e.until < Date.now() })), // eslint-disable-line no-unused-vars
      waiting: !!(this.pairWindow && Date.now() < this.pairWindow.until),
      hello: this.lastHello ? { ...this.lastHello, outdated: older(this.lastHello.version) } : null,
      error: this.extPairError && Date.now() - this.extPairError.at < 3600e3 ? this.extPairError : null,
    };
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
      this.writePairingFile(target, { chrome: 'Chrome', edge: 'Edge', brave: 'Brave', opera: 'Opera', vivaldi: 'Vivaldi' }[browser] || 'Browser');
    }
    const url = { chrome: 'chrome://extensions/', edge: 'edge://extensions/', brave: 'brave://extensions/', opera: 'opera://extensions/', vivaldi: 'vivaldi://extensions/' }[browser];
    // Tests never open the user's real browser
    const opened = process.env.HW_TEST ? false : await open(fx ? target : url);
    return { ok: true, browser, mode: 'dev', opened, since: Date.now(), autoPair: true, dir: fx ? null : target, file: fx ? target : null, url: url || null };
  }

  /* ---------- self-maintenance: provider programs (clis.js) and packages ---------- */
  /** Compatibility (1.x): path of a provider program or null. */
  cliPath(name) { return this.clis.path(name); }
  kdbxwebVersion() { try { return readJson(path.join(host.appRoot() || '', 'node_modules', 'kdbxweb', 'package.json'), {}).version || null; } catch { return null; } }
  async cliStatus() {
    const out = {};
    for (const name of ['bw', 'op']) out[name] = await this.clis.status(name);
    const kv = this.kdbxwebVersion();
    out.kdbxweb = kv ? { installed: true, version: kv } : { installed: false };
    return out;
  }
  installCli(name, opts) { return this.clis.install(name, opts); }
  /**
   * Keeper check (daily): provider programs only for set-up providers (clis.check), kdbxweb on npm and the leak check
   * only when there is a vault at all, the catalogue always.
   */
  async check() {
    const { fetchJson, cached, cmpVersion } = host.core('download');
    const out = { clis: await this.clis.check() };
    if (this.list().length) {
      const kv = this.kdbxwebVersion();
      out.kdbxweb = kv ? { installed: true, version: kv } : { installed: false };
      try { const npm = await cached('pw-kdbxweb-npm', 3600e3, () => fetchJson('https://registry.npmjs.org/kdbxweb/latest')); out.kdbxweb.latest = npm.version; this.note('pw-kdbxweb', true, T('Password manager: KeePass library (kdbxweb)'), cmpVersion(npm.version, kv) > 0 ? T('built in {v}, on npm {npm} – the newer version comes with the next Hostwerk update (Dependabot)', { v: kv, npm: npm.version }) : T('built in {v}, on npm {npm}', { v: kv, npm: npm.version })); } catch (e) { out.kdbxweb.error = e.message; }
      if (this.cfg.audit.hibp !== false) { const hibpLabel = T('Password manager: leak check (HIBP)'); try { await pwc.pwned('Hostwerk-Probe'); this.note('pw-hibp', true, hibpLabel, T('reachable')); } catch (e) { this.note('pw-hibp', false, hibpLabel, e.message); } }
    }
    await this.loadCatalog({ online: true }).catch(() => {});
    return out;
  }

  /**
   * SSH-Schlüssel aus dem Tresor an Hostwerks SSH-Schlüssel übergeben (Ordner ~/.ssh): Datei + .pub, nur für den
   * Benutzer lesbar, vorhandene Dateien werden nie überschrieben. Danach steht er unter Hostwerk → SSH-Schlüssel.
   */
  async sshInstall(id, itemId, name) {
    const it = await this.store(id).get(itemId);
    if (it.type !== 'ssh' || !it.ssh || !it.ssh.privateKey) throw Object.assign(new Error(T('This item has no SSH private key.')), { status: 400 });
    const dir = (this.ctx.sshKeys && this.ctx.sshKeys.dir) || path.join(require('os').homedir(), '.ssh');
    const slug = String(it.name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 30) || 'hostwerk';
    const n = String(name || '').trim() || `id_${String(it.ssh.keyType || 'key').replace(/^ssh-/, '').replace(/[^\w]/g, '')}_${slug}`;
    if (!/^[\w.-]{1,60}$/.test(n) || n.endsWith('.pub')) throw Object.assign(new Error(T('Please use a simple file name (letters, digits, . _ -).')), { status: 400 });
    const file = path.join(dir, n);
    if (fs.existsSync(file) || fs.existsSync(file + '.pub')) throw Object.assign(new Error(T('A key “{name}” already exists – please choose another name.', { name: n })), { status: 409 });
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, it.ssh.privateKey.endsWith('\n') ? it.ssh.privateKey : it.ssh.privateKey + '\n', { mode: 0o600, flag: 'wx' });
    if (it.ssh.publicKey) fs.writeFileSync(file + '.pub', it.ssh.publicKey.trim() + '\n', { mode: 0o644, flag: 'wx' });
    this.record(`${this.get(id).name}: ${it.name}`, T('SSH key handed to Hostwerk ({file})', { file: n }));
    return { ok: true, name: n, path: file };
  }

  /* ---------- routes ---------- */
  routes(r) {
    // Fehler mit Handlungs-Code (Programm laden, Smart App Control, Passwort nötig) gehen samt Erklärung an die Oberfläche
    const J = (fn) => async (req, res, next) => {
      try { res.json(await fn(req, res)); } catch (e) {
        if (e && (e.pwCode || e.needsPassword) && !res.headersSent) return res.status(e.status || 409).json({ error: e.message, code: e.pwCode || 'PW_NEEDS_PASSWORD', hint: e.hint || undefined });
        return next(e);
      }
      return undefined;
    };
    const send = (res, f) => { res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(f.name)}"`); res.setHeader('Cache-Control', 'no-store'); res.type(f.mime); res.send(f.data); };
    // Members: only what is shared with them (before /pw/:id, so "shared" is no vault id)
    const me = (req) => { const s = this.ctx.remote && this.ctx.remote.session ? this.ctx.remote.session(req) : null; return s && s.userId ? this.members().find((x) => x.id === s.userId) : null; };
    r.get('/pw/shared/mine', J(async (req) => { const u = me(req); return { member: !!u, name: u ? u.name : null, items: u ? await this.sharedWith(u.id) : [] }; }));
    r.post('/pw/shared/mine/reveal', J(async (req) => { const u = me(req); if (!u) throw Object.assign(new Error(T('Only for members.')), { status: 403 }); return this.revealShared(u.id, String((req.body || {}).key || ''), u.name); }));
    r.get('/pw/:id/items/:item/share', J(async (req) => ({ users: this.getShare(req.params.id, req.params.item), until: this.getShareUntil(req.params.id, req.params.item), members: this.members().filter((u) => u.role !== 'admin' && u.enabled !== false).map((u) => ({ id: u.id, name: u.name })) })));
    r.put('/pw/:id/items/:item/share', J(async (req) => this.setShare(req.params.id, req.params.item, (req.body || {}).users, (req.body || {}).until)));
    r.get('/pw/browsers', J(async () => host.core('browsers').detectBrowsers()));
    r.get('/pw', J(async () => ({ autoLogin: this.cfg.autoLogin === true, autofill: this.autofillCfg(), instances: this.list().map((i) => this.info(i)), providers: Object.entries(PROVIDERS).filter(([, p]) => !(p.linux && IS_WIN)).map(([id, p]) => ({ id, label: p.label, fields: p.fields, hint: p.hint, cli: p.cli || null, readonly: !!p.readonly, icons: this.iconSupport(id).ok, iconsWhy: this.iconSupport(id).why })), catalog: this.catalog, formats: formats.allFormats().map((f) => ({ id: f.id, label: f.label })), ext: this.cfg.ext.map(({ hash, ...e }) => e), autoLockMin: this.cfg.autoLockMin ?? 15, hibp: this.cfg.audit.hibp !== false, defaultId: this.cfg.defaultId || null, types: TYPES, members: this.members().length > 0, cli: { bw: this.clis.quick('bw'), op: this.clis.quick('op') }, clipboardSec: this.cfg.clipboardSec ?? 30, icons: this.cfg.icons !== false, sshDir: (this.ctx.sshKeys && this.ctx.sshKeys.dir) || null }))); // eslint-disable-line no-unused-vars
    r.put('/pw', (req, res) => { const b = req.body || {}; if (Number.isFinite(Number(b.autoLockMin))) { this.cfg.autoLockMin = Math.max(0, Math.min(240, Number(b.autoLockMin))); for (const s of this.stores.values()) if (s.autoLockMin !== undefined) s.autoLockMin = this.cfg.autoLockMin; } if (Number.isFinite(Number(b.clipboardSec))) this.cfg.clipboardSec = Math.max(0, Math.min(600, Number(b.clipboardSec))); if (typeof b.icons === 'boolean') this.cfg.icons = b.icons; if (typeof b.hibp === 'boolean') this.cfg.audit.hibp = b.hibp; if (typeof b.autoLogin === 'boolean') this.cfg.autoLogin = b.autoLogin; if (b.autofill && typeof b.autofill === 'object') { const a = this.autofillCfg(); for (const k of ['inline', 'onLoad', 'suggest', 'offerSave']) if (typeof b.autofill[k] === 'boolean') a[k] = b.autofill[k]; } if (b.defaultId) this.cfg.defaultId = b.defaultId; this.save(); res.json({ ok: true }); });
    r.post('/pw', J((req) => this.create(req.body || {})));
    // Anbieter-Programme: Zustand (mit Version), aktuelle Version beim Hersteller nur für benötigte
    r.get('/pw/cli', J(async () => { const st = await this.cliStatus(); for (const n of ['bw', 'op']) { if (!st[n].needed) continue; try { st[n].latest = (await this.clis.latest(n)).version; } catch { /* offline */ } } return st; }));
    r.post('/pw/cli/:name/install', J(async (req) => { if (!['bw', 'op'].includes(req.params.name)) throw new Error(T('Unknown CLI')); return { job: this.installCli(req.params.name, { manual: true }).id }; }));
    r.post('/pw/generate', (req, res) => { const b = req.body || {}; const opts = b.url ? this.genFor(b.url, b) : b; const pw = pwc.generate(opts); res.json({ password: pw, strength: pwc.strength(pw), rule: opts.site || null }); });
    r.get('/pw/gen-rules', (req, res) => res.json(this.genRules));
    r.put('/pw/gen-rules', J(async (req) => this.setGenRule((req.body || {}).site, (req.body || {}).opts === undefined ? {} : (req.body || {}).opts)));
    r.post('/pw/strength', (req, res) => res.json(pwc.strength((req.body || {}).password)));
    r.post('/pw/pwned', J(async (req) => ({ count: await pwc.pwned((req.body || {}).password || '') })));
    r.post('/pw/totp', (req, res) => res.json(pwc.totp((req.body || {}).secret || '') || { error: T('No valid secret') }));
    r.post('/pw/ssh/generate', J(async (req) => sshkey.generate((req.body || {}).comment)));
    r.post('/pw/ssh/describe', J(async (req) => sshkey.describe(req.body || {})));
    // Symbol einer Webseite (lokal zwischengespeichert) – fehlt es, zeigt die Liste den Anfangsbuchstaben
    r.get('/pw/icon/:host', async (req, res) => {
      const f = await this.siteIcon(req.params.host).catch(() => null);
      if (!f) return res.status(404).end();
      res.setHeader('Cache-Control', 'private, max-age=604800');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox");
      return res.sendFile(f);
    });
    r.post('/pw/lock-all', (req, res) => { this.lockAll(); res.json({ ok: true }); });
    r.get('/pw/ext/pair-code', (req, res) => res.json(this.pairCode()));
    r.get('/pw/ext/state', (req, res) => res.json(this.extState()));
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
    r.get('/pw/:id/stats', J((req) => this.stats(req.params.id)));
    r.get('/pw/:id/items', J((req) => this.items(req.params.id, req.query)));
    r.post('/pw/:id/items', J((req) => this.addItem(req.params.id, req.body || {})));
    r.get('/pw/:id/items/:item', J((req) => this.item(req.params.id, req.params.item)));
    r.put('/pw/:id/items/:item', J((req) => this.updateItem(req.params.id, req.params.item, req.body || {})));
    r.delete('/pw/:id/items/:item', J(async (req) => { await this.removeItem(req.params.id, req.params.item, { hard: req.query.hard === '1' }); return { ok: true }; }));
    r.post('/pw/:id/items/:item/restore', J((req) => { const s = this.store(req.params.id); return s.trash(req.params.item, false); }));
    r.get('/pw/:id/items/:item/totp', J(async (req) => { const it = await this.store(req.params.id).get(req.params.item); return pwc.totp(it.totp) || { error: T('No TOTP saved') }; }));
    // Anhänge (nur Hostwerk-Tresor): verschlüsselt mit dem Tresor-Schlüssel, je Datei höchstens 5 MB
    // Eigenes Bild eines Eintrags (Hostwerk-Tresor verschlüsselt, KeePass als Custom Icon)
    r.put('/pw/:id/items/:item/icon', J(async (req) => this.setItemIcon(req.params.id, req.params.item, (req.body || {}).data || null)));
    r.get('/pw/:id/items/:item/icon', async (req, res, next) => { try { const ic = await this.itemIcon(req.params.id, req.params.item); if (!ic) return res.status(404).end(); res.setHeader('Content-Type', ic.mime); res.setHeader('Cache-Control', 'private, max-age=86400'); res.setHeader('X-Content-Type-Options', 'nosniff'); return res.send(ic.data); } catch (e) { return next(e); } });
    r.post('/pw/:id/items/:item/files', J(async (req) => { const b = req.body || {}; const meta = this.own(req.params.id).addAttachment(req.params.item, { name: b.name, mime: b.mime, data: b.data }); broadcast({ type: 'passwords', id: req.params.id }); this.record(`${this.get(req.params.id).name}: ${meta.name}`, T('Attachment added')); return meta; }));
    r.get('/pw/:id/items/:item/files/:att', (req, res, next) => { try { const a = this.own(req.params.id).attachment(req.params.item, req.params.att); this.record(`${this.get(req.params.id).name}: ${a.name}`, T('Attachment opened')); send(res, { name: a.name, mime: 'application/octet-stream', data: a.data }); } catch (e) { next(e); } });
    r.delete('/pw/:id/items/:item/files/:att', J(async (req) => { this.own(req.params.id).removeAttachment(req.params.item, req.params.att); broadcast({ type: 'passwords', id: req.params.id }); return { ok: true }; }));
    r.delete('/pw/:id/items/:item/passkeys', J(async (req) => { const r2 = this.own(req.params.id).removePasskey(req.params.item, String((req.body || {}).credentialId || '')); broadcast({ type: 'passwords', id: req.params.id }); return r2; }));
    // SSH-Schlüssel an Hostwerks SSH-Schlüssel (~/.ssh) übergeben – nie überschreiben
    r.post('/pw/:id/items/:item/ssh-install', J(async (req) => this.sshInstall(req.params.id, req.params.item, String((req.body || {}).name || ''))));
    r.get('/pw/:id/folders', J((req) => { const s = this.store(req.params.id); return s.folders ? s.folders() : []; }));
    r.put('/pw/:id/folders', J((req) => this.store(req.params.id).setFolders((req.body || {}).folders)));
    r.get('/pw/:id/tags', J((req) => { const s = this.store(req.params.id); return s.tags ? s.tags() : []; }));
    r.post('/pw/:id/trash/empty', J((req) => ({ removed: this.store(req.params.id).emptyTrash() })));
    r.post('/pw/:id/audit', J((req) => this.audit(req.params.id, req.body || {})));
    r.get('/pw/:id/audit', J(async (req) => { const v = this.get(req.params.id); return { vault: { id: v.id, name: v.name, locked: !!this.info(v).locked }, last: this.audits.get(v.id) || null }; }));
    // Import: { text } für Textdateien, { data (Base64), name } für .kdbx/.1pux, password für verschlüsselte, mapping für CSV
    const payload = (b) => ({ text: b.text != null ? String(b.text) : null, data: b.data || null, name: String(b.name || ''), password: String(b.password || ''), mapping: b.mapping || null });
    r.post('/pw/:id/import', J((req) => this.importFile(req.params.id, payload(req.body || {}), { folder: String((req.body || {}).folder || ''), skipDuplicates: (req.body || {}).skipDuplicates !== false })));
    r.post('/pw/:id/import-preview', J((req) => this.importPreview(req.params.id, payload(req.body || {}))));
    r.post('/pw/:id/export', async (req, res, next) => { try { send(res, await this.exportFile(req.params.id, req.body || {})); } catch (e) { next(e); } });
    r.post('/pw/:id/backup', J(async (req) => ({ t: this.backupVault(this.own(req.params.id) && req.params.id, { force: true }) })));
    r.post('/pw/:id/transfer', J((req) => this.transfer(req.params.id, (req.body || {}).to, req.body || {})));
    r.post('/pw/:id/sync', J(async (req) => { const s = this.store(req.params.id); if (s.sync) await s.sync(); return { ok: true }; }));
  }

  /** Routes for the browser extension (pairing without the Hostwerk token; everything else with the extension key). */
  extRoutes(r) {
    r.post('/pw/ext/pair', (req, res) => { try { res.json(this.pair((req.body || {}).code, req.body || {})); } catch (e) { res.status(e.status || 400).json({ error: e.message, reason: e.reason || null }); } });
    r.post('/pw/ext/autopair', (req, res) => { try { res.json(this.autoPair(req)); } catch (e) { res.status(e.status || 400).json({ error: e.message, reason: e.reason || null }); } });
    // Ist hier ein Hostwerk? (nur für Erweiterungen – Webseiten erfahren nichts) und „Hallo“ mit Version/Zustand
    r.get('/pw/ext/ping', (req, res) => { if (!/^(chrome|moz)-extension:\/\//i.test(String(req.headers.origin || ''))) return res.status(403).json({ error: T('Only for the browser extension.') }); return res.json({ hostwerk: true, latest: this.extVersion() }); });
    r.post('/pw/ext/hello', (req, res) => { try { res.json(this.extHello(req)); } catch (e) { res.status(e.status || 400).json({ error: e.message }); } });
    const E = (fn) => async (req, res) => { const e = this.extAuth(req); if (!e) return res.status(401).json({ error: T('Extension not paired') }); try { return res.json(await fn(req, e)); } catch (err) { return res.status(err.status || 400).json({ error: err.message }); } };
    r.get('/pw/ext/status', E(async (req, e) => ({ ok: true, latest: this.extVersion(), name: e.name, autoLogin: this.cfg.autoLogin === true, autofill: this.autofillCfg(), vaults: this.list().map((i) => ({ id: i.id, name: i.name, locked: this.info(i).locked, default: this.cfg.defaultId === i.id })) })));
    r.post('/pw/ext/unlock', E(async (req) => this.unlock((req.body || {}).id || this.cfg.defaultId, (req.body || {}).password)));
    r.get('/pw/ext/match', E(async (req) => {
      const url = String(req.query.url || ''); const out = [];
      for (const i of this.list()) {
        const s = this.stores.get(i.id); if (!s || s.locked()) continue;
        if (i.type === 'hostwerk') for (const m of s.matches(url)) out.push({ ...m, vault: i.id, vaultName: i.name });
        else { let h = ''; try { h = new URL(url).hostname; } catch { /* ignore */ } const all = await s.all().catch(() => []); for (const it of all) if (!it.trashed && (it.urls || []).some((u) => u.includes(h))) { const { password, totp, notes, fields, icon, attachments, passkeys, ssh, history, ...rest } = it; out.push({ ...rest, hasTotp: !!totp, hasIcon: !!(icon && icon.data) || !!rest.hasIcon, vault: i.id, vaultName: i.name }); } } // eslint-disable-line no-unused-vars
      }
      return { items: out, locked: this.list().filter((i) => this.info(i).locked).map((i) => ({ id: i.id, name: i.name })) };
    }));
    // Eigenes Bild für die Liste im Popup (als data:-Adresse – das Popup schickt keinen Schlüssel mit)
    r.get('/pw/ext/icon', E(async (req) => { const ic = await this.itemIcon(String(req.query.vault), String(req.query.item)).catch(() => null); return { data: ic ? `data:${ic.mime};base64,${ic.data.toString('base64')}` : null }; }));
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
          const { password, totp, notes, fields, icon, attachments, passkeys, ssh, history, ...rest } = it; // eslint-disable-line no-unused-vars
          out.push({ ...rest, hasTotp: !!totp, hasIcon: !!(icon && icon.data) || !!rest.hasIcon, vault: i.id, vaultName: i.name });
          if (out.length >= 50) break;
        }
      }
      return { items: out, locked: this.list().filter((i) => this.info(i).locked).map((i) => ({ id: i.id, name: i.name })) };
    }));
    // Pairing removed in the extension → also removed in Hostwerk (the "paired browsers" list is current right away)
    r.delete('/pw/ext/self', E(async (req, e) => { this.revokeExt(e.id, 'browser'); return { ok: true }; }));
    // Regel der Seite (Länge, Zeichen) gilt, wenn die Erweiterung die Adresse mitschickt
    r.post('/pw/ext/generate', E(async (req) => { const b = req.body || {}; return { password: pwc.generate(b.url ? this.genFor(b.url, b) : b) }; }));
    r.post('/pw/ext/lock', E(async () => { this.lockAll(); return { ok: true }; }));
  }
}

module.exports = { PasswordManager };
