'use strict';
/*
 * Mehr Abdeckung: jedes eingebaute Importformat, Export → Import ohne Verlust, Übertragen zwischen Tresoren, KeePass-
 * Export (.kdbx, wieder geöffnet mit kdbxweb), Tresor als Dienst für andere Erweiterungen, Teilen (Rechte ändern,
 * zurücknehmen) und die Browser-Kopplung (automatisch, abgelaufene Schlüssel, Routen der Erweiterung).
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const host = require('../server/host');

// Bibliotheken, die Hostwerk mitbringt (kdbxweb, hash-wasm) – im Erweiterungs-Repo nur, wenn Hostwerk daneben liegt
const HW = path.join(__dirname, '..', '..', '..', 'hostwerk');
const lib = (n) => require(require.resolve(n, { paths: [HW, __dirname] }));
const hasLib = (n) => { try { lib(n); return true; } catch { return false; } };
host.bind({
  t: (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? v[k] : m)) : s),
  lang: () => 'en',
  core: (n) => ({ secrets: { seal: (x) => `enc:${x}`, open: (x) => String(x || '').replace(/^enc:/, '') }, safewrite: { writeFileSafe: (f, d, o) => fs.writeFileSync(f, d, o) } }[n]),
  lib,
  broadcast: () => {},
});
process.env.HW_TEST = '1';
const formats = require('../server/formats');
const { PasswordManager } = require('../server/manager');

const recorded = [];
function manager() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hw-pw2-'));
  const S = { general: { language: 'en' }, users: [{ id: 'm1', name: 'Helper', role: 'mitglied' }, { id: 'm2', name: 'Kim', role: 'mitglied' }, { id: 'a', name: 'Admin', role: 'admin' }] };
  const ctx = { settings: { get: () => S, save: () => {} }, paths: { data: dir, base: dir, cache: dir, bin: dir }, audit: { record: (x) => recorded.push(x) }, uiPort: () => 7000 };
  return { pm: new PasswordManager(ctx), S, dir };
}

/** Eine kleine Beispieldatei je Format: Kopfzeile wie das Original, eine Zeile Daten. */
const SAMPLES = {
  'bitwarden-csv': ['folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp', 'Work,1,login,GitHub,n,,0,https://github.com,alex,pw-1,'],
  chrome: ['name,url,username,password,note', 'GitHub,https://github.com,alex,pw-1,'],
  firefox: ['url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged', 'https://github.com,alex,pw-1,,,{x},1,1,1'],
  apple: ['Title,URL,Username,Password,Notes,OTPAuth', 'GitHub,https://github.com,alex,pw-1,,'],
  '1password-csv': ['Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes', 'GitHub,https://github.com,alex,pw-1,,false,false,,'],
  apple2: ['Title,URL,Username,Password,Notes,OTPAuth', 'GitHub,https://github.com,alex,pw-1,,'],
  lastpass: ['url,username,password,totp,extra,name,grouping,fav', 'https://github.com,alex,pw-1,,,GitHub,Work,0'],
  dashlane: ['username,username2,username3,title,password,note,url,category,otpSecret', 'alex,,,GitHub,pw-1,,https://github.com,,'],
  nordpass: ['name,url,username,password,note,cardholdername,folder', 'GitHub,https://github.com,alex,pw-1,,,Work'],
  protonpass: ['type,name,url,email,username,password,note,totp,createTime,modifyTime,vault', 'login,GitHub,https://github.com,,alex,pw-1,,,1,1,Personal'],
  'keepass-csv': ['Group,Title,Username,Password,URL,Notes,TOTP', 'Root/Work,GitHub,alex,pw-1,https://github.com,,'],
  keeper: ['Folder,Title,Login,Password,Website Address,Notes', 'Work,GitHub,alex,pw-1,https://github.com,'],
  roboform: ['Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2', 'GitHub,https://github.com,,alex,pw-1,,Work,'],
  zoho: ['Secret Name,SecretURL,SecretType,UserName,Password,Notes', 'GitHub,https://github.com,Web Account,alex,pw-1,'],
  kaspersky: ['Website name,Website URL,Login name,Login,Password,Comment', 'GitHub,https://github.com,,alex,pw-1,'],
};

test('every built-in import format is recognised and keeps user and password', () => {
  for (const [id, lines] of Object.entries(SAMPLES)) {
    const r = formats.detectAndParse(`${lines.join('\n')}\n`);
    assert.ok([id.replace(/2$/, ''), id === 'chrome' ? 'edge' : id].includes(r.format), `${id}: recognised as ${r.format}`);
    assert.strictEqual(r.items.length, 1, id);
    assert.strictEqual(r.items[0].username, 'alex', `${id}: user`);
    assert.strictEqual(r.items[0].password, 'pw-1', `${id}: password`);
  }
  assert.ok(Object.keys(SAMPLES).length >= formats.FORMATS.length - 4, 'nearly every format has a sample');
});

test('export → import keeps everything; transfer copies between vaults', async () => {
  const { pm } = manager();
  const a = await pm.create({ type: 'hostwerk', name: 'A', password: 'master-pw-123' });
  const b = await pm.create({ type: 'hostwerk', name: 'B', password: 'master-pw-456' });
  await pm.addItem(a.id, { type: 'login', name: 'Mail', username: 'me@x', password: 'Pw,with"quote', urls: ['https://mail.x'], folder: 'Work', totp: 'JBSWY3DPEHPK3PXP', notes: 'line1\nline2' });
  await pm.addItem(a.id, { type: 'login', name: 'Shop', username: 'me', password: 'pw2' });
  for (const kind of ['bitwarden-json', 'bitwarden-csv', 'generic-csv']) {
    const e = await pm.exportText(a.id, kind);
    const back = formats.detectAndParse(e.text).items;
    const mail = back.find((x) => x.name === 'Mail');
    assert.strictEqual(mail.password, 'Pw,with"quote', kind);
    assert.strictEqual(mail.username, 'me@x', kind);
    if (kind !== 'generic-csv') assert.strictEqual(mail.folder, 'Work', kind);
  }
  const tr = await pm.transfer(a.id, b.id);
  assert.strictEqual(tr.copied, 2);
  assert.strictEqual((await pm.items(b.id)).length, 2);
  assert.strictEqual((await pm.allWithSecrets(b.id)).find((x) => x.name === 'Shop').password, 'pw2');
});

test('KeePass export: a real .kdbx that opens again with its own password', async (t) => {
  if (!hasLib('kdbxweb') || !hasLib('hash-wasm')) { t.skip('kdbxweb/hash-wasm not found (they come with Hostwerk)'); return; }
  const { pm } = manager();
  const v = await pm.create({ type: 'hostwerk', name: 'Home', password: 'master-pw-123' });
  await pm.addItem(v.id, { type: 'login', name: 'GitHub', username: 'alex', password: 'gh-secret', urls: ['https://github.com'], folder: 'Dev/Code', totp: 'JBSWY3DPEHPK3PXP', fields: [{ name: 'PIN', value: '1234', hidden: true }] });
  const gone = await pm.addItem(v.id, { type: 'login', name: 'Old', password: 'x' });
  await pm.removeItem(v.id, gone.id);
  await assert.rejects(pm.exportKdbx(v.id, 'short'), /8 characters/);
  const e = await pm.exportKdbx(v.id, 'kdbx-pass-1');
  assert.ok(e.name.endsWith('.kdbx') && Buffer.isBuffer(e.data));
  const kdbx = lib('kdbxweb');
  const db = await kdbx.Kdbx.load(new Uint8Array(e.data).buffer, new kdbx.Credentials(kdbx.ProtectedValue.fromString('kdbx-pass-1')));
  const all = []; const walk = (g, p) => { for (const x of g.entries) all.push([x, p]); for (const s of g.groups) walk(s, p ? `${p}/${s.name}` : s.name); }; walk(db.getDefaultGroup(), '');
  assert.strictEqual(all.length, 1, 'trashed items stay out');
  const [entry, group] = all[0];
  assert.strictEqual(group, 'Dev/Code');
  assert.strictEqual(entry.fields.get('Password').getText(), 'gh-secret');
  assert.strictEqual(entry.fields.get('UserName'), 'alex');
  assert.strictEqual(entry.fields.get('otp').getText(), 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(entry.fields.get('PIN').getText(), '1234');
  await assert.rejects(kdbx.Kdbx.load(new Uint8Array(e.data).buffer, new kdbx.Credentials(kdbx.ProtectedValue.fromString('wrong-pass'))));
});

test('vault as a service: save, update (history), find, reveal only own entries; locked and missing vaults', async () => {
  const { pm } = manager();
  const svc = pm.vaultService();
  assert.deepStrictEqual(svc.status().available, false);
  await assert.rejects(svc.save({ source: 'file-share', key: 'sftp:alex', password: 'x' }), /No vault yet/);
  const v = await pm.create({ type: 'hostwerk', name: 'Home', password: 'master-pw-123' });
  assert.strictEqual(svc.status().vault.id, v.id);
  await assert.rejects(svc.save({ source: 'Bad Id', key: 'k', password: 'x' }), /source/);
  const first = await svc.save({ source: 'file-share', key: 'sftp:alex', name: 'SFTP alex', username: 'alex', password: 'one-1', url: 'sftp://pc:2222' });
  assert.strictEqual(first.updated, false);
  const second = await svc.save({ source: 'file-share', key: 'sftp:alex', name: 'SFTP alex', username: 'alex', password: 'two-2' });
  assert.strictEqual(second.updated, true); assert.strictEqual(second.id, first.id);
  const it = await pm.store(v.id).get(first.id);
  assert.strictEqual(it.password, 'two-2'); assert.strictEqual(it.history[0].password, 'one-1', 'old password in the history');
  assert.strictEqual(it.folder, 'Hostwerk');
  assert.deepStrictEqual(await svc.find({ source: 'file-share', key: 'sftp:alex' }), { id: first.id, name: 'SFTP alex', username: 'alex', url: 'sftp://pc:2222' });
  assert.strictEqual(await svc.find({ source: 'mail-server', key: 'sftp:alex' }), null, 'another extension never sees it');
  assert.deepStrictEqual(await svc.reveal({ source: 'file-share', key: 'sftp:alex' }), { username: 'alex', password: 'two-2' });
  assert.ok(recorded.some((x) => /saved by the extension file-share/.test(x.action)) && recorded.some((x) => /read by the extension file-share/.test(x.action)));
  pm.lock(v.id);
  assert.strictEqual(svc.status().locked, true);
  await assert.rejects(svc.save({ source: 'file-share', key: 'k', password: 'x' }), (e) => e.status === 423 && /locked/.test(e.message));
});

test('sharing: change and take back rights, admins are never targets, expired shares are cleaned up', async () => {
  const { pm } = manager();
  const v = await pm.create({ type: 'hostwerk', name: 'S', password: 'master-pw-123' });
  const it = await pm.addItem(v.id, { type: 'login', name: 'Router', username: 'admin', password: 'R-1' });
  pm.setShare(v.id, it.id, { m1: 'read', m2: 'read', a: 'read' });
  assert.deepStrictEqual(Object.keys(pm.getShare(v.id, it.id)).sort(), ['m1', 'm2'], 'admins see everything anyway – no share');
  pm.setShare(v.id, it.id, { m1: 'read' });
  assert.strictEqual((await pm.sharedWith('m2')).length, 0, 'taken back');
  pm.setShare(v.id, it.id, { m1: 'read' }, { m1: Date.now() + 60000 });
  assert.ok(pm.getShareUntil(v.id, it.id).m1 > Date.now());
  pm.shares[`${v.id}:${it.id}`].until = { m1: Date.now() - 1 };
  pm.expireShares();
  assert.deepStrictEqual(pm.getShare(v.id, it.id), {}, 'expired share removed');
});

test('browser pairing: automatic pairing only right after “Install”, from an extension origin; keys expire', () => {
  const { pm, S } = manager();
  const req = (origin, body = {}) => ({ headers: { origin }, body });
  assert.throws(() => pm.autoPair(req('chrome-extension://abcdefghijklmnop')), /Pairing not allowed/);
  pm.openPairWindow('edge');
  assert.throws(() => pm.autoPair(req('https://evil.example')), /Only for the browser extension/);
  const p = pm.autoPair(req('chrome-extension://abcdefghijklmnop', { browser: 'Edg/141' }));
  assert.strictEqual(p.name, 'Edge');
  assert.throws(() => pm.autoPair(req('chrome-extension://abcdefghijklmnop')), /Pairing not allowed/, 'the window closes after one pairing');
  pm.openPairWindow('chrome'); pm.pairWindow.until = Date.now() - 1;
  assert.throws(() => pm.autoPair(req('chrome-extension://abcdefghijklmnop')), /Pairing not allowed/, 'window over');
  const auth = { headers: { 'x-hostwerk-ext': p.token } };
  assert.ok(pm.extAuth(auth));
  S.passwords.ext.find((x) => x.id === p.id).until = Date.now() - 1;
  assert.strictEqual(pm.extAuth(auth), null, 'expired key no longer works');
});

test('routes of the browser extension: status, match, fill and save with the pairing key', async () => {
  const { pm } = manager();
  const v = await pm.create({ type: 'hostwerk', name: 'Home', password: 'master-pw-123' });
  await pm.addItem(v.id, { type: 'login', name: 'GitHub', username: 'alex', password: 'gh-pw', urls: ['https://github.com'] });
  const routes = {};
  const r = {}; for (const m of ['get', 'post', 'put', 'delete']) r[m] = (p, fn) => { routes[`${m.toUpperCase()} ${p}`] = fn; };
  pm.extRoutes(r);
  const call = (key, { token, query = {}, body = {} } = {}) => new Promise((resolve) => {
    const res = { statusCode: 200, status(c) { this.statusCode = c; return this; }, json(x) { resolve({ status: this.statusCode, body: x }); } };
    routes[key]({ headers: token ? { 'x-hostwerk-ext': token } : {}, query, body }, res);
  });
  assert.strictEqual((await call('GET /pw/ext/status')).status, 401, 'without key nothing');
  const { code } = pm.pairCode();
  const { token } = (await call('POST /pw/ext/pair', { body: { code, name: 'Firefox' } })).body;
  const st = await call('GET /pw/ext/status', { token });
  assert.strictEqual(st.body.vaults[0].id, v.id);
  const m = await call('GET /pw/ext/match', { token, query: { url: 'https://github.com/login' } });
  const hit = (m.body.items || m.body)[0];
  assert.ok(hit && hit.name === 'GitHub' && !('password' in hit), 'matches without secrets');
  const fill = await call('GET /pw/ext/fill', { token, query: { vault: v.id, item: hit.id } });
  assert.strictEqual(fill.body.password, 'gh-pw');
  const saved = await call('POST /pw/ext/save', { token, body: { vault: v.id, url: 'https://shop.example/login', host: 'shop.example', username: 'kim', password: 'shop-pw' } });
  assert.strictEqual(saved.body.name, 'shop.example');
  assert.ok(recorded.some((x) => /Filled in in the browser \(Firefox\)/.test(x.action)));
});
