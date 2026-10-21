'use strict';
/*
 * Provider adapters: connect existing password managers to Hostwerk – each through the maker's official way:
 *   bitwarden   Bitwarden account or own Vaultwarden – official CLI "bw" (Hostwerk loads it itself when connecting, clis.js)
 *   onepassword 1Password – official CLI "op" with a service account token (no prompts, also loaded by clis.js)
 *   keepass     KeePass/KeePassXC – reads and writes the .kdbx file directly (kdbxweb, KDBX 3/4, Argon2)
 *   pass        Unix password store "pass" (GPG + Git), lastpass: lastpass-cli "lpass" – Linux/macOS, from the package manager
 * All of them return the same shape as the Hostwerk vault (list/get/add/update/remove), secrets only on request.
 * Services without an interface (Google, Apple, Proton, Dashlane, NordPass, Enpass, …) are connected through
 * import/export – see the catalogue (pw-catalog.json) and formats.js.
 */
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const host = require('./host');
const { T } = require('./i18n');

const IS_WIN = process.platform === 'win32';
const which = async (name) => { if (process.env.HW_TEST === '1' && process.env.HW_PW_FAKE_CLI) return `fake-${name}`; try { return await host.core('platform').which(name); } catch { return null; } };
// 0xC0E90002 – Smart App Control / WDAC hat den Start verweigert (wie core/sac.js)
const BLOCKED_EXIT = new Set([3236495362, -1058471934]);
const secrets = { open: (x) => host.core('secrets').open(x), seal: (x) => host.core('secrets').seal(x) };

function runCli(exe, args, { env = {}, input = null, timeout = 60000, cwd } = {}) {
  return new Promise((resolve) => {
    let out = ''; let err = '';
    let p;
    // Tests: "fake-bw", "fake-op", "fake-lpass" run as a Node script (imitation of the real programs)
    const fake = process.env.HW_TEST === '1' && process.env.HW_PW_FAKE_CLI;
    if (fake && /^fake-(bw|op|lpass)$/.test(path.basename(String(exe)))) { args = [fake, path.basename(String(exe)).slice(5), ...args]; exe = process.execPath; }
    const blockedErr = (e) => e && (e.code === 'UNKNOWN' || e.errno === -4094 || (e.code === 'EACCES' && process.platform === 'win32'));
    try { p = spawn(exe, args, { windowsHide: true, env: { ...process.env, ...env }, cwd }); } catch (e) { return resolve({ code: -1, out: '', err: e.message, blocked: blockedErr(e), missing: e.code === 'ENOENT' }); }
    const t = setTimeout(() => { try { p.kill(); } catch { /* ignore */ } }, timeout);
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('error', (e) => { clearTimeout(t); resolve({ code: -1, out, err: e.message, blocked: blockedErr(e), missing: e.code === 'ENOENT' }); });
    p.on('close', (code) => { clearTimeout(t); resolve({ code, out, err, blocked: BLOCKED_EXIT.has(code) }); });
    if (input != null) { try { p.stdin.end(input); } catch { /* ignore */ } } else { try { p.stdin.end(); } catch { /* ignore */ } }
    return undefined;
  });
}
const j = (s) => { try { return JSON.parse(s); } catch { return null; } };
const last = (r) => (r.err || r.out).trim().split('\n').pop();

/* ================================================================ Bitwarden / Vaultwarden (bw) */
class Bitwarden {
  constructor(ctx, inst, pm) { this.ctx = ctx; this.inst = inst; this.pm = pm; this.session = null; }
  env() { return { BITWARDENCLI_APPDATA_DIR: path.join(this.ctx.paths.data, 'passwoerter', 'bw', this.inst.id), BW_SESSION: this.session || '', NODE_OPTIONS: '' }; }
  /** bw starten – fehlt das Programm, sagt die Meldung, was zu tun ist (Bitwarden verbinden = Programm laden). */
  async bw(args, opts = {}) { const exe = await this.pm.clis.ensure('bw'); const r = await runCli(exe, [...args, '--nointeraction'], { env: this.env(), ...opts }); if (r.blocked) { this.pm.clis.markBlocked('bw'); throw this.pm.clis.blockedError('bw'); } return r; }
  async connect({ password } = {}) {
    const c = this.inst.cfg;
    fs.mkdirSync(this.env().BITWARDENCLI_APPDATA_DIR, { recursive: true });
    if (c.server) await this.bw(['config', 'server', c.server]);
    const st = j((await this.bw(['status'])).out) || {};
    if (st.status === 'unauthenticated') {
      const pw = password || secrets.open(c.password);
      if (!c.email || !pw) throw Object.assign(new Error(T('E-mail and master password of the Bitwarden account are missing.')), { status: 401 });
      const args = c.clientId ? ['login', '--apikey', '--raw'] : ['login', c.email, '--passwordenv', 'BW_PASSWORD', '--raw', ...(c.otp ? ['--code', c.otp] : [])];
      const r = await this.bw(args, { env: { BW_PASSWORD: pw, BW_CLIENTID: c.clientId ? secrets.open(c.clientId) : '', BW_CLIENTSECRET: c.clientSecret ? secrets.open(c.clientSecret) : '' } });
      if (r.code !== 0) throw Object.assign(new Error(T('Bitwarden sign-in failed: {msg}', { msg: last(r) })), { status: 401 });
      if (!c.clientId) this.session = r.out.trim();
    }
    if (!this.session) {
      const pw = password || secrets.open(c.password);
      const r = await this.bw(['unlock', '--passwordenv', 'BW_PASSWORD', '--raw'], { env: { BW_PASSWORD: pw } });
      if (r.code !== 0) throw Object.assign(new Error(T('The vault cannot be unlocked: {msg}', { msg: last(r) })), { status: 401 });
      this.session = r.out.trim();
    }
    await this.bw(['sync']).catch(() => {});
    return { ok: true };
  }
  locked() { return !this.session; }
  lock() { this.session = null; }
  conv(i) {
    return { id: i.id, type: ({ 1: 'login', 2: 'note', 3: 'card', 4: 'identity' })[i.type] || 'login', name: i.name, username: (i.login || {}).username || '', password: (i.login || {}).password || '', urls: ((i.login || {}).uris || []).map((u) => u.uri).filter(Boolean), totp: (i.login || {}).totp || '', notes: i.notes || '', folder: i.folderName || '', tags: [], favorite: !!i.favorite, fields: (i.fields || []).map((f) => ({ name: f.name, value: f.value || '', hidden: f.type === 1 })), updated: i.revisionDate ? Date.parse(i.revisionDate) : null, created: i.creationDate ? Date.parse(i.creationDate) : null, passwordChanged: i.login && i.login.passwordRevisionDate ? Date.parse(i.login.passwordRevisionDate) : null, trashed: !!i.deletedDate };
  }
  async all() {
    const [items, folders] = await Promise.all([this.bw(['list', 'items']), this.bw(['list', 'folders'])]);
    if (items.code !== 0) throw new Error('Bitwarden: ' + last(items));
    const fmap = new Map((j(folders.out) || []).map((f) => [f.id, f.name]));
    return (j(items.out) || []).map((i) => this.conv({ ...i, folderName: fmap.get(i.folderId) || '' }));
  }
  async get(id) { const r = await this.bw(['get', 'item', id]); if (r.code !== 0) throw new Error('Bitwarden: ' + (r.err || r.out).trim()); return this.conv(j(r.out)); }
  toBw(it) { const TYPE = { login: 1, note: 2, card: 3, identity: 4 }; return { type: TYPE[it.type] || 1, name: it.name, notes: it.notes || null, favorite: !!it.favorite, login: it.type === 'login' ? { username: it.username || null, password: it.password || null, totp: it.totp || null, uris: (it.urls || []).map((u) => ({ uri: u })) } : null, secureNote: it.type === 'note' ? { type: 0 } : null, fields: (it.fields || []).map((f) => ({ name: f.name, value: f.value, type: f.hidden ? 1 : 0 })) }; }
  async add(it) { const r = await this.bw(['create', 'item'], { input: Buffer.from(JSON.stringify(this.toBw(it))).toString('base64') }); if (r.code !== 0) throw new Error('Bitwarden: ' + (r.err || r.out).trim()); return this.conv(j(r.out)); }
  async update(id, it) { const cur = j((await this.bw(['get', 'item', id])).out); const r = await this.bw(['edit', 'item', id], { input: Buffer.from(JSON.stringify({ ...cur, ...this.toBw(it) })).toString('base64') }); if (r.code !== 0) throw new Error('Bitwarden: ' + (r.err || r.out).trim()); return this.conv(j(r.out)); }
  async remove(id) { const r = await this.bw(['delete', 'item', id]); if (r.code !== 0) throw new Error('Bitwarden: ' + (r.err || r.out).trim()); }
  async sync() { await this.bw(['sync']); }
}

/* ================================================================ 1Password (op) */
class OnePassword {
  constructor(ctx, inst, pm) { this.ctx = ctx; this.inst = inst; this.pm = pm; this.ready = false; }
  env() { return { OP_SERVICE_ACCOUNT_TOKEN: secrets.open(this.inst.cfg.token), OP_FORMAT: 'json', OP_CONFIG_DIR: path.join(this.ctx.paths.data, 'passwoerter', 'op', this.inst.id) }; }
  async op(args, opts = {}) { const exe = await this.pm.clis.ensure('op'); const r = await runCli(exe, args, { env: this.env(), ...opts }); if (r.blocked) { this.pm.clis.markBlocked('op'); throw this.pm.clis.blockedError('op'); } return r; }
  async connect() { if (!this.inst.cfg.token) throw Object.assign(new Error(T('Service account token is missing (1Password → Developer → Service accounts).')), { status: 401 }); fs.mkdirSync(this.env().OP_CONFIG_DIR, { recursive: true }); const r = await this.op(['whoami']); if (r.code !== 0) throw Object.assign(new Error('1Password: ' + last(r)), { status: 401 }); this.ready = true; return { ok: true }; }
  locked() { return !this.ready; }
  lock() { this.ready = false; }
  conv(i, full = null) {
    const f = (full && full.fields) || [];
    const get = (id, purpose) => { const x = f.find((y) => y.id === id || y.purpose === purpose); return x ? x.value || '' : ''; };
    return { id: i.id, type: /SECURE_NOTE/.test(i.category) ? 'note' : /CREDIT_CARD/.test(i.category) ? 'card' : /IDENTITY/.test(i.category) ? 'identity' : 'login', name: i.title, username: get('username', 'USERNAME'), password: get('password', 'PASSWORD'), urls: (i.urls || []).map((u) => u.href), totp: (f.find((y) => y.type === 'OTP') || {}).value || '', notes: get('notesPlain', 'NOTES'), folder: (i.vault || {}).name || '', tags: i.tags || [], favorite: !!i.favorite, fields: f.filter((y) => !['username', 'password', 'notesPlain'].includes(y.id) && y.value && y.type !== 'OTP').map((y) => ({ name: y.label || y.id, value: String(y.value), hidden: y.type === 'CONCEALED' })), updated: i.updated_at ? Date.parse(i.updated_at) : null, created: i.created_at ? Date.parse(i.created_at) : null };
  }
  async all() { const r = await this.op(['item', 'list', ...(this.inst.cfg.vault ? ['--vault', this.inst.cfg.vault] : [])]); if (r.code !== 0) throw new Error('1Password: ' + (r.err || r.out).trim()); return (j(r.out) || []).map((i) => this.conv(i)); }
  async get(id) { const r = await this.op(['item', 'get', id]); if (r.code !== 0) throw new Error('1Password: ' + (r.err || r.out).trim()); const x = j(r.out); return this.conv(x, x); }
  /** Template in the 1Password format (secrets go through standard input, never as an argument into the process list). */
  template(it, base = null) {
    const fields = (base && base.fields ? base.fields.filter((f) => !['username', 'password', 'notesPlain'].includes(f.id)) : []);
    if (it.username !== undefined || base) fields.push({ id: 'username', type: 'STRING', purpose: 'USERNAME', label: 'username', value: it.username ?? (base ? (base.fields || []).find((f) => f.id === 'username')?.value : '') ?? '' });
    if (it.password || base) fields.push({ id: 'password', type: 'CONCEALED', purpose: 'PASSWORD', label: 'password', value: it.password || (base ? (base.fields || []).find((f) => f.id === 'password')?.value : '') || '' });
    if (it.notes !== undefined || base) fields.push({ id: 'notesPlain', type: 'STRING', purpose: 'NOTES', label: 'notesPlain', value: it.notes ?? (base ? (base.fields || []).find((f) => f.id === 'notesPlain')?.value : '') ?? '' });
    return JSON.stringify({ title: it.name || (base && base.title) || '', category: it.type === 'note' ? 'SECURE_NOTE' : (base && base.category) || 'LOGIN', ...(it.urls && it.urls[0] ? { urls: [{ href: it.urls[0], primary: true }] } : base && base.urls ? { urls: base.urls } : {}), fields });
  }
  async add(it) { const args = ['item', 'create', ...(this.inst.cfg.vault ? ['--vault', this.inst.cfg.vault] : []), '-']; const r = await this.op(args, { input: this.template(it) }); if (r.code !== 0) throw new Error('1Password: ' + (r.err || r.out).trim()); const x = j(r.out); return this.conv(x, x); }
  async update(id, it) { const cur = j((await this.op(['item', 'get', id])).out); if (!cur) throw new Error(T('1Password: item not found')); const tf = path.join(this.env().OP_CONFIG_DIR, `edit-${process.pid}-${Date.now()}.json`); fs.mkdirSync(path.dirname(tf), { recursive: true }); fs.writeFileSync(tf, this.template(it, cur), { mode: 0o600 }); let r; try { r = await this.op(['item', 'edit', id, '--template', tf]); } finally { fs.rmSync(tf, { force: true }); } if (r.code !== 0) throw new Error('1Password: ' + (r.err || r.out).trim()); const x = j(r.out); return this.conv(x, x); }
  async remove(id) { const r = await this.op(['item', 'delete', id, '--archive']); if (r.code !== 0) throw new Error('1Password: ' + (r.err || r.out).trim()); }
  async sync() { /* op always reads live */ }
}

/* ================================================================ KeePass (.kdbx) */
/* kdbxweb mit Argon2 (hash-wasm) kommt aus io.js */
const ensureArgon = () => require('./io').kdbxLib();

const kid = (e) => Buffer.from(String(e.uuid.id), 'base64').toString('hex'); // id usable in addresses (UUID as hex)
class KeePass {
  constructor(ctx, inst) { this.ctx = ctx; this.inst = inst; this.db = null; this.creds = null; }
  locked() { return !this.db; }
  lock() { this.db = null; this.creds = null; }
  async connect({ password } = {}) {
    const kdbx = ensureArgon();
    const c = this.inst.cfg;
    if (!c.file) throw new Error(T('No .kdbx file set – enter the path to the file under “Access”.'));
    if (!fs.existsSync(c.file)) throw new Error(T('The .kdbx file was not found: {file}', { file: c.file }));
    const pw = password || secrets.open(c.password);
    const key = c.keyFile && fs.existsSync(c.keyFile) ? new Uint8Array(fs.readFileSync(c.keyFile)).buffer : null;
    const creds = new kdbx.Credentials(pw ? kdbx.ProtectedValue.fromString(pw) : null, key);
    try { this.db = await kdbx.Kdbx.load(new Uint8Array(fs.readFileSync(c.file)).buffer, creds); } catch (e) { throw Object.assign(new Error(T('The KeePass file cannot be opened (password/key file?): {msg}', { msg: e.message })), { status: 401 }); }
    this.creds = creds;
    return { ok: true };
  }
  async save() { const buf = await this.db.save(); const tmp = this.inst.cfg.file + '.neu'; fs.writeFileSync(tmp, Buffer.from(buf)); fs.copyFileSync(this.inst.cfg.file, this.inst.cfg.file + '.bak'); fs.renameSync(tmp, this.inst.cfg.file); }
  val(e, k) { const v = e.fields.get(k); if (!v) return ''; return typeof v === 'string' ? v : v.getText(); }
  conv(e, groupName) {
    const url = this.val(e, 'URL'); const otp = this.val(e, 'otp') || this.val(e, 'TOTP Seed') || this.val(e, 'TimeOtp-Secret-Base32');
    const std = new Set(['Title', 'UserName', 'Password', 'URL', 'Notes', 'otp', 'TOTP Seed', 'TimeOtp-Secret-Base32']);
    const ic = e.customIcon && this.db.meta.customIcons.get(e.customIcon.id);
    return { hasIcon: !!ic, iconV: ic ? (ic.lastModified ? ic.lastModified.getTime() : 1) : null, id: kid(e), type: 'login', name: this.val(e, 'Title') || T('(untitled)'), username: this.val(e, 'UserName'), password: this.val(e, 'Password'), urls: url ? [url] : [], totp: otp, notes: this.val(e, 'Notes'), folder: groupName, tags: e.tags || [], favorite: false, fields: [...e.fields.keys()].filter((k) => !std.has(k)).map((k) => ({ name: k, value: this.val(e, k), hidden: typeof e.fields.get(k) !== 'string' })), updated: e.times.lastModTime ? e.times.lastModTime.getTime() : null, created: e.times.creationTime ? e.times.creationTime.getTime() : null, trashed: this.db.meta.recycleBinUuid && e.parentGroup && e.parentGroup.uuid.id === this.db.meta.recycleBinUuid.id };
  }
  need() { if (!this.db) throw Object.assign(new Error(T('The KeePass file is locked.')), { status: 423 }); }
  walk() { this.need(); const out = []; const rec = (g, name) => { for (const e of g.entries) out.push([e, name]); for (const s of g.groups) rec(s, name ? `${name}/${s.name}` : s.name); }; rec(this.db.getDefaultGroup(), ''); return out; }
  async all() { return this.walk().map(([e, g]) => this.conv(e, g)).filter((i) => !i.trashed); }
  async get(id) { const hit = this.walk().find(([e]) => kid(e) === id); if (!hit) throw Object.assign(new Error(T('Item not found')), { status: 404 }); return this.conv(hit[0], hit[1]); }
  fill(e, it) { const kdbx = ensureArgon(); const P = (s) => kdbx.ProtectedValue.fromString(String(s || '')); e.fields.set('Title', it.name || ''); e.fields.set('UserName', it.username || ''); e.fields.set('Password', P(it.password)); e.fields.set('URL', (it.urls || [])[0] || ''); e.fields.set('Notes', it.notes || ''); if (it.totp) e.fields.set('otp', P(it.totp)); for (const f of it.fields || []) e.fields.set(f.name, f.hidden ? P(f.value) : String(f.value || '')); e.tags = it.tags || []; e.times.update(); }
  async add(it) { this.need(); let group = this.db.getDefaultGroup(); if (it.folder) { const parts = it.folder.split('/'); for (const p of parts) { let s = group.groups.find((g) => g.name === p); if (!s) s = this.db.createGroup(group, p); group = s; } } const e = this.db.createEntry(group); this.fill(e, it); await this.save(); return this.conv(e, it.folder || ''); }
  async update(id, it) { const hit = this.walk().find(([e]) => kid(e) === id); if (!hit) throw Object.assign(new Error(T('Item not found')), { status: 404 }); hit[0].pushHistory(); this.fill(hit[0], { ...this.conv(hit[0], hit[1]), ...it }); await this.save(); return this.conv(hit[0], hit[1]); }
  async remove(id) { const hit = this.walk().find(([e]) => kid(e) === id); if (!hit) return; this.db.remove(hit[0]); await this.save(); }
  async sync() { await this.connect(); }
  /** Own image: KeePass keeps it as a "custom icon" in the file – KeePass, KeePassXC and KeePassDX show it too. */
  async setIcon(id, buf) {
    const kdbx = ensureArgon();
    const hit = this.walk().find(([e]) => kid(e) === id); if (!hit) throw Object.assign(new Error(T('Item not found')), { status: 404 });
    const e = hit[0];
    if (buf) { const u = kdbx.KdbxUuid.random(); this.db.meta.customIcons.set(u.id, { data: new Uint8Array(buf).buffer, name: this.val(e, 'Title') || 'Hostwerk', lastModified: new Date() }); e.customIcon = u; } else e.customIcon = undefined;
    e.times.update();
    await this.save();
    return this.conv(e, hit[1]);
  }
  async getIcon(id) {
    const hit = this.walk().find(([e]) => kid(e) === id); if (!hit) throw Object.assign(new Error(T('Item not found')), { status: 404 });
    const ic = hit[0].customIcon && this.db.meta.customIcons.get(hit[0].customIcon.id);
    return ic ? Buffer.from(ic.data) : null;
  }
}

/* ================================================================ pass (Unix) and lastpass-cli */
class PassCli {
  constructor(ctx, inst) { this.ctx = ctx; this.inst = inst; this.ready = false; }
  async bin() { return which('pass'); }
  locked() { return !this.ready; }
  lock() { this.ready = false; }
  env() { return this.inst.cfg.store ? { PASSWORD_STORE_DIR: this.inst.cfg.store } : {}; }
  async connect() { if (!(await this.bin())) throw Object.assign(new Error(T('“pass” is not installed yet – install it with your package manager (e.g. sudo apt install pass), then connect again.')), { status: 409, pwCode: 'PW_SYSTEM_MISSING' }); const r = await runCli(await this.bin(), ['ls'], { env: this.env() }); if (r.code !== 0) throw new Error('pass: ' + (r.err || r.out).trim()); this.ready = true; return { ok: true }; }
  async all() {
    const r = await runCli(await this.bin(), ['ls'], { env: this.env() });
    const out = []; const stack = [];
    for (const line of r.out.split('\n')) { const m = line.match(/^((?:[│ ]{4})*)[├└]── (.+?)(\.gpg)?$/); if (!m) continue; const depth = m[1].length / 4; stack.splice(depth); const name = m[2].replace(/\x1b\[[0-9;]*m/g, ''); if (/\/$/.test(name) || !line.includes('.gpg') && !m[3]) { stack[depth] = name; continue; } const p = [...stack.slice(0, depth), name].join('/'); out.push({ id: p, type: 'login', name, username: '', password: '', urls: [], folder: stack.slice(0, depth).join('/'), tags: [], favorite: false, fields: [], hasPassword: true }); }
    return out;
  }
  async get(id) { const r = await runCli(await this.bin(), ['show', id], { env: this.env() }); if (r.code !== 0) throw new Error('pass: ' + (r.err || r.out).trim()); const lines = r.out.split('\n'); const rest = lines.slice(1); const kv = (k) => (rest.find((l) => new RegExp(`^${k}:`, 'i').test(l)) || '').split(':').slice(1).join(':').trim(); return { id, type: 'login', name: id.split('/').pop(), username: kv('user(name)?|login'), password: lines[0] || '', urls: [kv('url')].filter(Boolean), totp: kv('otpauth|totp'), notes: rest.filter((l) => !/^(user(name)?|login|url|otpauth|totp):/i.test(l)).join('\n').trim(), folder: id.split('/').slice(0, -1).join('/'), tags: [], favorite: false, fields: [] }; }
  async add(it) { const id = [it.folder, it.name].filter(Boolean).join('/').replace(/[^\w./ -]/g, '_'); const body = [it.password || '', ...(it.username ? [`username: ${it.username}`] : []), ...((it.urls || [])[0] ? [`url: ${it.urls[0]}`] : []), ...(it.totp ? [`otpauth: ${it.totp}`] : []), ...(it.notes ? [it.notes] : [])].join('\n') + '\n'; const r = await runCli(await this.bin(), ['insert', '-m', '-f', id], { env: this.env(), input: body }); if (r.code !== 0) throw new Error('pass: ' + (r.err || r.out).trim()); return this.get(id); }
  async update(id, it) { const cur = await this.get(id); return this.add({ ...cur, ...it, folder: cur.folder, name: cur.name }); }
  async remove(id) { const r = await runCli(await this.bin(), ['rm', '-f', id], { env: this.env() }); if (r.code !== 0) throw new Error('pass: ' + (r.err || r.out).trim()); }
  async sync() { await runCli(await this.bin(), ['git', 'pull'], { env: this.env() }).catch(() => {}); }
}
class LastPassCli {
  constructor(ctx, inst) { this.ctx = ctx; this.inst = inst; this.ready = false; }
  async bin() { return which('lpass'); }
  locked() { return !this.ready; }
  lock() { const was = this.ready; this.ready = false; if (was) this.bin().then((b) => b && runCli(b, ['logout', '-f'])).catch(() => {}); }
  async connect({ password } = {}) { const b = await this.bin(); if (!b) throw Object.assign(new Error(T('lastpass-cli is not installed yet – install it with your package manager (e.g. sudo apt install lastpass-cli), or export from LastPass and import the CSV file.')), { status: 409, pwCode: 'PW_SYSTEM_MISSING' }); const pw = password || secrets.open(this.inst.cfg.password); const r = await runCli(b, ['login', '--trust', this.inst.cfg.email], { env: { LPASS_DISABLE_PINENTRY: '1' }, input: pw + '\n' }); if (r.code !== 0) throw Object.assign(new Error('LastPass: ' + last(r)), { status: 401 }); this.ready = true; return { ok: true }; }
  async all() { const r = await runCli(await this.bin(), ['export', '--sync=now'], { env: { LPASS_DISABLE_PINENTRY: '1' } }); if (r.code !== 0) throw new Error('LastPass: ' + (r.err || r.out).trim()); const { detectAndParse } = require('./formats'); return detectAndParse(r.out).items.map((i, n) => ({ ...i, id: String(n) })); }
  async get(id) { return (await this.all())[Number(id)]; }
  async add() { throw new Error(T('LastPass through the CLI: read and export only – to write, take it over into the Hostwerk vault.')); }
  async update() { return this.add(); }
  async remove() { return this.add(); }
  async sync() { /* export sync=now */ }
}

// Eigene Bilder je Eintrag: wo das Format sie kennt (KeePass „Custom Icons“), sonst bleibt es ehrlich beim Webseiten-Symbol
const NO_ICONS = {
  bitwarden: 'Bitwarden only shows website icons from its own icon service – own images cannot be stored there. Hostwerk shows the website icon.',
  onepassword: '1Password does not let programs set item images. Hostwerk shows the website icon.',
  pass: 'pass only stores text files – there is no place for an image. Hostwerk shows the website icon.',
  lastpass: 'LastPass through the CLI is read-only. Hostwerk shows the website icon.',
};
// Field labels and hints in English – the interface translates them (locales/de.json)
const PROVIDERS = {
  bitwarden: { label: 'Bitwarden / Vaultwarden', cls: Bitwarden, native: true, cli: 'bw', fields: [['server', 'Server (empty = bitwarden.com, otherwise e.g. https://vault.example.com)', 'text'], ['email', 'E-mail', 'text'], ['password', 'Master password', 'password'], ['clientId', 'API client ID (optional, instead of a password sign-in)', 'password'], ['clientSecret', 'API client secret (optional)', 'password']], hint: 'Official program “bw” – Hostwerk loads it by itself when connecting. Works with Bitwarden accounts and self-hosted Vaultwarden (also in Hostwerk’s Docker).' },
  onepassword: { label: '1Password', cls: OnePassword, native: true, cli: 'op', fields: [['token', 'Service account token', 'password'], ['vault', 'Vault (optional)', 'text']], hint: 'Official program “op” with a service account (1Password → Developer tools) – Hostwerk loads it by itself when connecting. Personal accounts: export as .1pux and import.' },
  keepass: { label: 'KeePass / KeePassXC (.kdbx)', cls: KeePass, native: true, fields: [['file', 'Path to the .kdbx file', 'path'], ['password', 'Master password', 'password'], ['keyFile', 'Key file (optional)', 'path']], hint: 'Reads and writes the file directly (KDBX 3/4, Argon2). Before every write a .bak copy is made.' },
  pass: { label: 'pass (Unix password store)', cls: PassCli, native: true, linux: true, fields: [['store', 'Folder of the store (empty = ~/.password-store)', 'path']], hint: 'GPG + Git. Linux/macOS only.' },
  lastpass: { label: 'LastPass (lastpass-cli)', cls: LastPassCli, native: true, readonly: true, linux: true, fields: [['email', 'E-mail', 'text'], ['password', 'Master password', 'password']], hint: 'Through lastpass-cli (Linux/macOS) – read/export only. To manage it, take it over into the Hostwerk vault. On Windows: export from LastPass and import the CSV file.' },
};

module.exports = { PROVIDERS, NO_ICONS, runCli, IS_WIN, ensureArgon };
