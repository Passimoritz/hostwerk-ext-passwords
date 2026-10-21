'use strict';
/*
 * Tresor 2.0: Format 3 (eigener Tresor-Schlüssel, Argon2id, Kopf als AAD), Anheben alter Dateien, Passwortwechsel mit
 * Anhängen, atomares Schreiben, neue Eintragsarten (SSH, Passkeys), Import/Export-Rundreisen je Format mit selbst
 * erzeugten Beispieldateien (Bitwarden JSON + mit Passwort, KeePass .kdbx + XML, 1Password .1pux, Enpass, CSV mit eigener
 * Spaltenzuordnung), Duplikate, Warnung vor unverschlüsseltem Export, Sicherungs-Zentrale, Generator-Regeln.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const host = require('../server/host');

const HW = path.join(__dirname, '..', '..', '..', 'hostwerk');
const lib = (n) => require(require.resolve(n, { paths: [HW, __dirname] }));
const hasLib = (n) => { try { lib(n); return true; } catch { return false; } };
host.bind({
  t: (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? v[k] : m)) : s),
  lang: () => 'en',
  core: (n) => ({ secrets: { seal: (x) => `enc:${x}`, open: (x) => String(x || '').replace(/^enc:/, '') } }[n]),
  lib,
  broadcast: () => {},
});
process.env.HW_TEST = '1';
const pwc = require('../server/crypto');
const io = require('../server/io');
const formats = require('../server/formats');
const { VaultStore } = require('../server/store');
const { PasswordManager } = require('../server/manager');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hw-pw3-'));
function manager() {
  const dir = tmp();
  const S = { general: { language: 'en' }, users: [] };
  const ctx = { settings: { get: () => S, save: () => {} }, paths: { data: dir, base: dir, cache: dir, bin: path.join(dir, 'bin') }, audit: { record: () => {} }, uiPort: () => 7000, sshKeys: { dir: path.join(dir, 'ssh') } };
  return { pm: new PasswordManager(ctx), S, dir, ctx };
}
/** Kleinste ZIP-Datei (ohne Kompression) – für eine selbst erzeugte .1pux. */
function zipStore(files) {
  const parts = []; const central = []; let off = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content); const n = Buffer.from(name); const crc = zlib.crc32(data);
    const h = Buffer.alloc(30); h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt32LE(crc, 14); h.writeUInt32LE(data.length, 18); h.writeUInt32LE(data.length, 22); h.writeUInt16LE(n.length, 26);
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt32LE(crc, 16); c.writeUInt32LE(data.length, 20); c.writeUInt32LE(data.length, 24); c.writeUInt16LE(n.length, 28); c.writeUInt32LE(off, 42);
    parts.push(h, n, data); central.push(c, n); off += 30 + n.length + data.length;
  }
  const cd = Buffer.concat(central);
  const e = Buffer.alloc(22); e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(central.length / 2, 8); e.writeUInt16LE(central.length / 2, 10); e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cd, e]);
}
const PASSKEY = { credentialId: '0f8e3c2a-1b4d-4e6f-8a9b-0c1d2e3f4a5b', keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256', keyValue: crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url'), rpId: 'github.com', rpName: 'GitHub', userHandle: 'dXNlcg', userName: 'alex', counter: '0', discoverable: 'true' };

test('format 3: own vault key wrapped with Argon2id, header bound as AAD, wrong password, tampering', async (t) => {
  if (!hasLib('hash-wasm')) { t.skip('hash-wasm not found (comes with Hostwerk)'); return; }
  const file = path.join(tmp(), 'v.hwvault');
  const v = new VaultStore(file, { autoLockMin: 0 });
  await v.create('master-pw-123');
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.strictEqual(j.v, 3); assert.strictEqual(j.kdf.alg, 'argon2id'); assert.ok(j.kdf.m >= 65536 && j.kdf.t >= 3); assert.ok(j.key && j.key.data, 'wrapped vault key');
  v.add({ type: 'login', name: 'GitHub', username: 'alex', password: 'gh-1' });
  v.lock();
  await assert.rejects(v.unlock('wrong-password'), (e) => e.status === 401);
  await v.unlock('master-pw-123');
  assert.strictEqual(v.list()[0].name, 'GitHub');
  v.lock();
  // Kopf verändert (schwächere Ableitung untergeschoben) → nichts entschlüsselbar
  const bad = { ...j, kdf: { ...j.kdf, t: 1 } }; fs.writeFileSync(file + '.x', JSON.stringify(bad));
  await assert.rejects(new VaultStore(file + '.x').unlock('master-pw-123'), (e) => e.status === 401);
  assert.ok(!fs.readdirSync(path.dirname(file)).some((f) => f.endsWith('.tmp')), 'no half written files left');
});

test('old formats (scrypt, v2) open and are lifted to format 3 on unlock', async () => {
  const file = path.join(tmp(), 'old.hwvault');
  const salt = crypto.randomBytes(16).toString('base64');
  const kdf = { N: 2 ** 15, r: 8, p: 1 };
  const key = await pwc.deriveKeyAsync('master-pw-123', Buffer.from(salt, 'base64'), kdf);
  const enc = pwc.encrypt(key, JSON.stringify({ items: [{ id: 'a1', type: 'login', name: 'Old', password: 'p', urls: [] }], folders: [], created: 1 }), `hostwerk-vault:v2:${salt}:${kdf.N}:${kdf.r}:${kdf.p}`);
  fs.writeFileSync(file, JSON.stringify({ v: 2, hostwerkVault: 1, salt, kdf, ...enc }));
  const v = new VaultStore(file, { autoLockMin: 0 });
  await v.unlock('master-pw-123');
  assert.strictEqual(v.get('a1').name, 'Old');
  const j = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.strictEqual(j.v, 3, 'lifted to format 3'); assert.ok(j.key);
  v.lock(); await v.unlock('master-pw-123'); assert.strictEqual(v.get('a1').password, 'p');
});

test('attachments: encrypted, limits, survive a new master password, gone with the item', async () => {
  const file = path.join(tmp(), 'a.hwvault');
  const v = new VaultStore(file, { autoLockMin: 0 });
  await v.create('master-pw-123');
  const it = v.add({ type: 'note', name: 'Recovery codes', notes: 'x' });
  const meta = v.addAttachment(it.id, { name: 'codes.txt', mime: 'text/plain', data: Buffer.from('1111-2222') });
  assert.ok(!fs.readFileSync(v.attFile(meta.id), 'utf8').includes('1111'), 'file is encrypted');
  assert.throws(() => v.addAttachment(it.id, { name: 'big', data: Buffer.alloc(6 * 1024 * 1024) }), (e) => e.status === 413);
  await v.changePassword('master-pw-123', 'new-master-456');
  v.lock(); await v.unlock('new-master-456');
  assert.strictEqual(v.attachment(it.id, meta.id).data.toString(), '1111-2222', 'vault key stayed – attachment still readable');
  v.trash(it.id, true); v.emptyTrash();
  assert.ok(!fs.existsSync(v.attFile(meta.id)));
});

test('SSH keys: create, read back public part and fingerprint, hand over to ~/.ssh without overwriting', async (t) => {
  if (!hasLib('ssh2')) { t.skip('ssh2 not found (comes with Hostwerk)'); return; }
  const sshkey = require('../server/sshkey');
  const k = sshkey.generate('test@hostwerk');
  assert.ok(/^ssh-ed25519 /.test(k.publicKey) && /^SHA256:/.test(k.fingerprint));
  const d = sshkey.describe({ privateKey: k.privateKey });
  assert.strictEqual(d.publicKey.split(' ')[1], k.publicKey.split(' ')[1]);
  assert.throws(() => sshkey.describe({ privateKey: 'hello' }), /does not look like/);
  const { pm, ctx } = manager();
  const v = await pm.create({ type: 'hostwerk', name: 'K', password: 'master-pw-123' });
  const it = await pm.addItem(v.id, { type: 'ssh', name: 'Server', ssh: { privateKey: k.privateKey } });
  const full = await pm.item(v.id, it.id);
  assert.strictEqual(full.ssh.fingerprint, k.fingerprint, 'public part derived when saving');
  const r = await pm.sshInstall(v.id, it.id, 'id_test');
  assert.ok(fs.existsSync(path.join(ctx.sshKeys.dir, 'id_test.pub')) && r.ok);
  await assert.rejects(pm.sshInstall(v.id, it.id, 'id_test'), (e) => e.status === 409);
});

test('Bitwarden JSON: SSH keys, passkeys, history and cards survive export → import; with password too', async () => {
  const items = [
    { type: 'login', name: 'GitHub', username: 'alex', password: 'gh-2', urls: ['https://github.com'], totp: 'JBSWY3DPEHPK3PXP', folder: 'Dev', passkeys: [PASSKEY], history: [{ password: 'gh-1', until: 1700000000000 }] },
    { type: 'ssh', name: 'Server', ssh: { privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n', publicKey: 'ssh-ed25519 AAAA test', fingerprint: 'SHA256:x', keyType: 'ssh-ed25519' } },
    { type: 'card', name: 'Visa', card: { holder: 'A B', number: '4111111111111111', expiry: '12/2030', cvv: '123', brand: 'Visa' } },
  ];
  const back = formats.detectAndParse(formats.exportBitwardenJson(items, ['Dev'])).items;
  const gh = back.find((x) => x.name === 'GitHub');
  assert.strictEqual(gh.passkeys[0].keyValue, PASSKEY.keyValue); assert.strictEqual(gh.history[0].password, 'gh-1'); assert.strictEqual(gh.folder, 'Dev');
  assert.strictEqual(back.find((x) => x.name === 'Server').ssh.publicKey, 'ssh-ed25519 AAAA test');
  assert.strictEqual(back.find((x) => x.name === 'Visa').card.number, '4111111111111111');
  const enc = await io.bitwardenEncrypted(items, 'export-pass-1');
  const j = JSON.parse(enc);
  assert.ok(j.encrypted && j.passwordProtected && /^2\./.test(j.data) && !enc.includes('gh-2'));
  await assert.rejects(io.parseInput({ text: enc }), (e) => e.needsPassword);
  await assert.rejects(io.parseInput({ text: enc, password: 'wrong-pass' }), (e) => e.status === 401);
  const ok = await io.parseInput({ text: enc, password: 'export-pass-1' });
  assert.strictEqual(ok.items.find((x) => x.name === 'GitHub').password, 'gh-2');
});

test('KeePass: .kdbx with passkey (KeePassXC fields) round trip, KeePass XML, wrong password', async (t) => {
  if (!hasLib('kdbxweb') || !hasLib('hash-wasm')) { t.skip('kdbxweb/hash-wasm not found'); return; }
  const buf = await io.writeKdbx([{ type: 'login', name: 'GitHub', username: 'alex', password: 'gh', urls: ['https://github.com'], folder: 'Dev/Code', totp: 'JBSWY3DPEHPK3PXP', passkeys: [PASSKEY], fields: [{ name: 'PIN', value: '1', hidden: true }] }], 'kdbx-pass-1');
  await assert.rejects(io.parseInput({ data: buf.toString('base64'), name: 'x.kdbx' }), (e) => e.needsPassword);
  await assert.rejects(io.parseInput({ data: buf.toString('base64'), name: 'x.kdbx', password: 'nope-nope' }), (e) => e.status === 401);
  const r = await io.parseInput({ data: buf.toString('base64'), name: 'x.kdbx', password: 'kdbx-pass-1' });
  const it = r.items[0];
  assert.strictEqual(it.folder, 'Dev/Code'); assert.strictEqual(it.password, 'gh'); assert.strictEqual(it.totp, 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(it.passkeys[0].credentialId, PASSKEY.credentialId); assert.strictEqual(it.passkeys[0].keyValue, PASSKEY.keyValue, 'private key PEM ⇄ base64url');
  const xml = `<?xml version="1.0" encoding="utf-8"?><KeePassFile><Meta><RecycleBinUUID>BIN</RecycleBinUUID></Meta><Root><Group><UUID>ROOT</UUID><Name>Database</Name>
    <Entry><String><Key>Title</Key><Value>Mail &amp; more</Value></String><String><Key>UserName</Key><Value>me</Value></String><String><Key>Password</Key><Value ProtectInMemory="True">p&lt;1</Value></String><Tags>a;b</Tags>
      <History><Entry><String><Key>Password</Key><Value>old</Value></String></Entry></History></Entry>
    <Group><UUID>G1</UUID><Name>Work</Name><Entry><String><Key>Title</Key><Value>VPN</Value></String><String><Key>Password</Key><Value>v</Value></String><String><Key>Token</Key><Value ProtectInMemory="True">t</Value></String></Entry></Group>
    <Group><UUID>BIN</UUID><Name>Recycle Bin</Name><Entry><String><Key>Title</Key><Value>Gone</Value></String></Entry></Group>
  </Group></Root></KeePassFile>`;
  const x = await io.parseInput({ text: xml });
  assert.strictEqual(x.format, 'keepass-xml');
  assert.deepStrictEqual(x.items.map((i) => i.name), ['Mail & more', 'VPN'], 'recycle bin stays out, history entries are no items');
  assert.strictEqual(x.items[0].password, 'p<1'); assert.deepStrictEqual(x.items[0].tags, ['a', 'b']); assert.strictEqual(x.items[0].history[0].password, 'old');
  assert.strictEqual(x.items[1].folder, 'Work'); assert.ok(x.items[1].fields.find((f) => f.name === 'Token').hidden);
});

test('1Password .1pux, Enpass JSON and a CSV with own column assignment', async (t) => {
  if (!hasLib('yauzl')) { t.skip('yauzl not found'); return; }
  const data = { accounts: [{ attrs: { name: 'Me' }, vaults: [{ attrs: { name: 'Private' }, items: [
    { uuid: 'u1', favIndex: 1, createdAt: 1700000000, state: 'active', categoryUuid: '001', overview: { title: 'GitHub', url: 'https://github.com', tags: ['dev'] }, details: { loginFields: [{ designation: 'username', value: 'alex' }, { designation: 'password', value: 'gh-1' }], notesPlain: 'n', sections: [{ fields: [{ title: 'one-time password', id: 'otp', value: { totp: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP' } }, { title: 'PIN', id: 'pin', value: { concealed: '9999' } }] }], passwordHistory: [{ value: 'gh-0', time: 1690000000 }] } },
    { uuid: 'u2', state: 'archived', categoryUuid: '001', overview: { title: 'Old' }, details: {} },
    { uuid: 'u3', state: 'active', categoryUuid: '002', overview: { title: 'Card' }, details: { sections: [{ fields: [{ id: 'cardholder', title: 'holder', value: { string: 'A B' } }, { id: 'ccnum', title: 'number', value: { creditCardNumber: '4111' } }, { id: 'expiry', title: 'expiry', value: { monthYear: 203012 } }] }] } },
  ] }] }] };
  const pux = zipStore({ 'export.attributes': '{}', 'export.data': JSON.stringify(data) });
  const r = await io.parseInput({ data: pux.toString('base64'), name: 'me.1pux' });
  assert.strictEqual(r.format, '1pux'); assert.strictEqual(r.items.length, 2, 'archived stays out');
  const gh = r.items[0];
  assert.strictEqual(gh.username, 'alex'); assert.strictEqual(gh.password, 'gh-1'); assert.ok(gh.totp.startsWith('otpauth://')); assert.ok(gh.favorite); assert.strictEqual(gh.folder, 'Private');
  assert.strictEqual(gh.history[0].password, 'gh-0'); assert.ok(gh.fields.find((f) => f.name === 'PIN' && f.hidden));
  assert.deepStrictEqual(r.items[1].card, { holder: 'A B', number: '4111', expiry: '12/2030', cvv: '', brand: '', pin: '' });
  const en = await io.parseInput({ text: JSON.stringify({ folders: [], items: [{ title: 'Mail', category: 'login', favorite: 1, note: 'x', fields: [{ label: 'E-mail', type: 'email', value: 'a@b' }, { label: 'Password', type: 'password', value: 'pw', sensitive: 1 }, { label: 'Website', type: 'url', value: 'https://mail.b' }] }] }) });
  assert.strictEqual(en.format, 'enpass-json'); assert.strictEqual(en.items[0].username, 'a@b'); assert.strictEqual(en.items[0].password, 'pw');
  // CSV ohne bekannte Spalten: Vorschau verlangt eine Zuordnung, danach klappt es
  const csv = 'Konto;Login;Geheim\nRouter;admin;r0uter!\n';
  await assert.rejects(io.parseInput({ text: csv }), (e) => e.needsMapping && e.head.includes('Geheim'));
  const m = await io.parseInput({ text: csv, mapping: { name: 'Konto', username: 'Login', password: 'Geheim' } });
  assert.strictEqual(m.format, 'mapped'); assert.strictEqual(m.items[0].password, 'r0uter!');
});

test('manager: preview counts duplicates, unencrypted export needs confirmation, encrypted exports, backups', async (t) => {
  const { pm } = manager();
  const v = await pm.create({ type: 'hostwerk', name: 'Home', password: 'master-pw-123' });
  await pm.addItem(v.id, { type: 'login', name: 'A', username: 'x', password: 'p1', urls: ['https://a.example'] });
  const text = 'name,url,username,password,note\nA,https://a.example,x,p1,\nB,https://b.example,y,p2,\n';
  const pre = await pm.importPreview(v.id, { text });
  assert.strictEqual(pre.count, 2); assert.strictEqual(pre.duplicates, 1);
  const need = await pm.importPreview(v.id, { text: 'a;b\n1;2\n' });
  assert.ok(need.needsMapping && need.head.length === 2);
  const imp = await pm.importFile(v.id, { text });
  assert.strictEqual(imp.added, 1); assert.strictEqual(imp.skipped, 1);
  await assert.rejects(pm.exportFile(v.id, { kind: 'chrome-csv' }), (e) => e.status === 428);
  assert.ok((await pm.exportFile(v.id, { kind: 'chrome-csv', plain: true })).data.toString().includes('p2'));
  await assert.rejects(pm.exportFile(v.id, { kind: 'bitwarden-encrypted', password: 'short' }), /8 characters/);
  const enc = await pm.exportFile(v.id, { kind: 'bitwarden-encrypted', password: 'export-pass-1' });
  assert.ok(!enc.data.toString().includes('b.example'), 'nothing readable in the encrypted file'); // (nicht nach „p2“ suchen – kommt zufällig im Base64 vor)
  // Sicherung: Stand anlegen, ändern, zurückholen
  const src = pm.backupSource();
  assert.ok(pm.backupVault(v.id, { force: true }));
  assert.strictEqual(src.list().length, 1);
  await pm.addItem(v.id, { type: 'login', name: 'Later', password: 'x' });
  await src.restore(src.list()[0].id);
  await pm.unlock(v.id, 'master-pw-123');
  assert.ok(!(await pm.items(v.id)).some((x) => x.name === 'Later'), 'restored the older state');
  assert.strictEqual(src.list().length, 2, 'the state before restoring was kept too');
  const stats = await pm.stats(v.id);
  assert.strictEqual(stats.all, 2); assert.strictEqual(stats.login, 2);
  if (!hasLib('hash-wasm')) t.diagnostic('argon2 not available – format 3 with scrypt');
});

test('generator rules per site (also subdomains), clipboard and icon settings', async () => {
  const { pm } = manager();
  pm.setGenRule('https://www.bank.example/login', { length: 12, symbols: false });
  const o = pm.genFor('https://online.bank.example/');
  assert.strictEqual(o.length, 12); assert.strictEqual(o.symbols, false); assert.strictEqual(o.site, 'bank.example');
  const pw = pwc.generate(o); assert.strictEqual(pw.length, 12); assert.ok(/^[A-Za-z0-9]+$/.test(pw));
  assert.deepStrictEqual(pm.genFor('https://other.example', { length: 30 }), { length: 30 });
  pm.setGenRule('bank.example', null); assert.deepStrictEqual(pm.genRules, {});
  assert.strictEqual(await pm.siteIcon('192.168.1.1'), null, 'no IP addresses'); assert.strictEqual(await pm.siteIcon('nas.local'), null, 'no local names');
});
