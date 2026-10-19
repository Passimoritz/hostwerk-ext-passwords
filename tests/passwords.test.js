'use strict';
/*
 * Password manager without Hostwerk: TOTP (RFC test vector), generator and rating, the encrypted vault file (create,
 * lock, wrong password, items, trash, history), import formats, the manager with vaults, security check (without HIBP),
 * sharing, browser pairing, and German messages. The full server with a real browser is tested by Hostwerk's
 * scripts/pw-test.js, pw-share-test.js, pw-providers-test.js and pw-extension-e2e.js.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const de = require('../locales/de.json');
const host = require('../server/host');

const fill = (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? v[k] : m)) : s);
let lang = 'en';
const recorded = [];
host.bind({
  t: (s, v) => fill(lang === 'de' && de[s] ? de[s] : s, v),
  core: (n) => ({ secrets: { seal: (x) => `enc:${x}`, open: (x) => String(x || '').replace(/^enc:/, '') }, safewrite: { writeFileSafe: (f, d, o) => fs.writeFileSync(f, d, o) } }[n]),
  lib: (n) => require(n),
  broadcast: () => {},
});
const c = require('../server/crypto');
const formats = require('../server/formats');
const { VaultStore } = require('../server/store');
const { PasswordManager } = require('../server/manager');

process.env.HW_TEST = '1';
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hw-pw-'));
function manager() {
  const dir = tmp();
  const S = { general: { language: lang }, users: [{ id: 'm1', name: 'Helper', role: 'mitglied' }] };
  const ctx = { settings: { get: () => S, save: () => {} }, paths: { data: dir, base: dir, cache: dir, bin: dir }, audit: { record: (x) => recorded.push(x) }, uiPort: () => 7000 };
  return { pm: new PasswordManager(ctx), S, dir };
}

test('TOTP: RFC 6238 test vector, otpauth addresses; generator and rating', () => {
  assert.strictEqual(c.totp('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59 * 1000).code, '287082');
  const o = c.totp('otpauth://totp/Hostwerk:test?secret=JBSWY3DPEHPK3PXP&issuer=Hostwerk');
  assert.ok(/^\d{6}$/.test(o.code) && o.issuer === 'Hostwerk');
  assert.strictEqual(c.generate({ length: 24 }).length, 24);
  assert.ok(c.strength(c.generate({ length: 24 })).score >= 3);
  const weak = c.strength('password123');
  assert.ok(weak.score <= 1 && weak.hints.includes('well-known word'));
  assert.ok(/^[A-Z][a-z]+-[A-Z][a-z]+-[A-Z][a-z]+-[A-Z][a-z]+\d\d$/.test(c.passphrase(4)));
  assert.strictEqual(c.base32Encode(c.base32Decode('JBSWY3DPEHPK3PXP')), 'JBSWY3DPEHPK3PXP');
});

test('vault file: create, lock, wrong password (German), items, trash, history', async () => {
  lang = 'de';
  const file = path.join(tmp(), 'v.hwvault');
  const v = new VaultStore(file, { autoLockMin: 0 });
  await assert.rejects(v.create('kurz'), /mindestens 8 Zeichen/);
  await v.create('master-pw-123');
  const it = v.add({ type: 'login', name: 'GitHub', username: 'alex', password: 'one-1', urls: ['github.com'] });
  v.update(it.id, { password: 'two-2' });
  assert.strictEqual(v.get(it.id).history[0].password, 'one-1', 'old password kept in the history');
  assert.ok(!('password' in v.list()[0]) && v.list()[0].hasPassword, 'lists never contain secrets');
  assert.strictEqual(v.matches('https://api.github.com/x').length, 1, 'subdomains match');
  v.trash(it.id, true);
  assert.strictEqual(v.list().length, 0); assert.strictEqual(v.list({ trashed: '1' }).length, 1);
  assert.strictEqual(v.list({ trashed: '0' }).length, 0, '"0" from the address bar is not true');
  v.lock();
  assert.throws(() => v.list(), /Tresor ist gesperrt/);
  await assert.rejects(v.unlock('falsch-falsch'), (e) => e.status === 401 && /Master-Passwort falsch/.test(e.message));
  await v.unlock('master-pw-123');
  assert.strictEqual(v.list({ trashed: true })[0].name, 'GitHub');
  assert.ok(!fs.readFileSync(file, 'utf8').includes('GitHub'), 'file is encrypted');
  lang = 'en';
});

test('import formats: Chrome, Bitwarden JSON, generic CSV with German headers', () => {
  const chrome = formats.detectAndParse('name,url,username,password,note\nGitHub,https://github.com,alex,pw1,\n');
  assert.strictEqual(chrome.format, 'chrome'); assert.strictEqual(chrome.items[0].username, 'alex');
  const bw = formats.detectAndParse(JSON.stringify({ encrypted: false, folders: [{ id: 'f', name: 'Work' }], items: [{ type: 1, name: 'Mail', folderId: 'f', login: { username: 'a', password: 'b', uris: [{ uri: 'https://mail.x' }] } }] }));
  assert.strictEqual(bw.items[0].folder, 'Work');
  const gen = formats.detectAndParse('Titel;Benutzer;Password\nRouter;admin;geheim\n');
  assert.strictEqual(gen.format, 'generic'); assert.strictEqual(gen.items[0].password, 'geheim');
  assert.throws(() => formats.detectAndParse('a,b\n1,2\n'), /Format not recognised/);
  const csv = formats.exportCsv([{ type: 'login', name: 'X', username: 'u', password: 'p,q', urls: ['https://x'] }], 'chrome');
  assert.ok(csv.includes('"p,q"'));
});

test('manager: vaults, items, security check, import, data in settings.passwords', async () => {
  const { pm, S } = manager();
  const v = await pm.create({ type: 'hostwerk', name: 'Home', password: 'master-pw-123' });
  assert.strictEqual(S.passwords.defaultId, v.id);
  await pm.addItem(v.id, { type: 'login', name: 'A', username: 'x', password: 'password123', urls: ['https://github.com'] });
  await pm.addItem(v.id, { type: 'login', name: 'B', username: 'y', password: 'password123' });
  const r = await pm.audit(v.id, { hibp: false });
  assert.strictEqual(r.counts.reused, 2); assert.ok(r.counts.weak >= 2); assert.strictEqual(r.counts.no2fa, 1);
  assert.ok(r.score < 100);
  const imp = await pm.importText(v.id, 'name,url,username,password,note\nA,https://github.com,x,password123,\nC,https://c.example,z,Zz-9!long-enough,\n');
  assert.strictEqual(imp.added, 1, 'duplicates skipped'); assert.strictEqual(imp.skipped, 1);
  assert.ok(recorded.some((x) => /items imported/.test(x.action)));
  await assert.rejects(pm.remove(v.id, { password: 'wrong-password' }), (e) => e.status === 401);
  assert.strictEqual(pm.list().length, 1);
  await pm.remove(v.id, { password: 'master-pw-123', deleteFile: true });
  assert.strictEqual(pm.list().length, 0);
});

test('sharing with members: only known members, end date in the past refused, expired shares end', async () => {
  const { pm } = manager();
  const v = await pm.create({ type: 'hostwerk', name: 'Shared', password: 'master-pw-123' });
  const it = await pm.addItem(v.id, { type: 'login', name: 'Wi-Fi', username: 'guest', password: 'Guest-Pass-1' });
  assert.throws(() => pm.setShare(v.id, it.id, { m1: 'read' }, { m1: Date.now() - 1000 }), /end date is in the past/);
  const r = pm.setShare(v.id, it.id, { m1: 'read', ghost: 'read' });
  assert.deepStrictEqual(Object.keys(r.users), ['m1'], 'unknown members ignored');
  assert.strictEqual((await pm.sharedWith('m1'))[0].name, 'Wi-Fi');
  assert.strictEqual((await pm.revealShared('m1', `${v.id}:${it.id}`, 'Helper')).password, 'Guest-Pass-1');
  pm.shares[`${v.id}:${it.id}`].until = { m1: Date.now() - 5 };
  assert.strictEqual((await pm.sharedWith('m1')).length, 0);
  await assert.rejects(pm.revealShared('m1', `${v.id}:${it.id}`, 'Helper'), /Not shared with you/);
});

test('browser pairing: code once, key per browser, revoke', () => {
  const { pm, S } = manager();
  assert.throws(() => pm.pair('000000'), /Pairing code invalid/);
  const { code } = pm.pairCode();
  const p = pm.pair(code, { name: 'Edge', browser: 'Edg/141' });
  assert.throws(() => pm.pair(code), /invalid or expired/, 'a code works only once');
  assert.ok(pm.extAuth({ headers: { 'x-hostwerk-ext': p.token } }));
  assert.ok(!S.passwords.ext[0].token && S.passwords.ext[0].hash, 'only the hash is stored');
  assert.throws(() => pm.autoPair({ headers: { origin: 'https://evil.example' } }), /Only for the browser extension/);
  pm.revokeExt(p.id);
  assert.strictEqual(pm.extAuth({ headers: { 'x-hostwerk-ext': p.token } }), null);
});

test('every German text has a value', () => {
  for (const [k, v] of Object.entries(de)) if (k !== '$patterns') assert.ok(typeof v === 'string' && v.trim(), k);
});
