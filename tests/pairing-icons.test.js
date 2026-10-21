'use strict';
/*
 * 2.1: Browser-Erweiterung koppelt sich wartungsfrei wieder (Ordner-Ticket überlebt Neustart, Port steht in der Datei,
 * gleicher Browser ersetzt seinen alten Eintrag), Zustand für die Karte (Version, veraltet, letzte Ursache), „Hallo“ nur
 * von Erweiterungen – und eigene Bilder je Eintrag (Hostwerk-Tresor verschlüsselt, KeePass als Custom Icon, Export/Import).
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const host = require('../server/host');

const HW = path.join(__dirname, '..', '..', '..', 'hostwerk');
const lib = (n) => require(require.resolve(n, { paths: [HW, __dirname] }));
const hasLib = (n) => { try { lib(n); return true; } catch { return false; } };
host.bind({ t: (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? v[k] : m)) : s), lang: () => 'en', core: (n) => ({ secrets: { seal: (x) => `enc:${x}`, open: (x) => String(x || '').replace(/^enc:/, '') }, util: { zipDir: async () => {} } }[n]), lib, broadcast: () => {} });
process.env.HW_TEST = '1';
const io = require('../server/io');
const { PasswordManager } = require('../server/manager');

function manager(port = 7780) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hw-pw21-'));
  const S = { general: { language: 'en' }, users: [] };
  const ctx = { settings: { get: () => S, save: () => {} }, paths: { data: dir, base: dir, cache: dir, bin: dir }, audit: { record: () => {} }, uiPort: () => port };
  return { pm: new PasswordManager(ctx), S, dir, ctx };
}
/** Kleines echtes PNG (1×1) – reicht als Bild. */
function png() {
  const crc = (b) => { const c = Buffer.alloc(4); c.writeUInt32BE(zlib.crc32(b) >>> 0); return c; };
  const chunk = (type, data) => { const len = Buffer.alloc(4); len.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type), data]); return Buffer.concat([len, td, crc(td)]); };
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(1, 0); ihdr.writeUInt32BE(1, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(Buffer.from([0, 255, 0, 0, 255]))), chunk('IEND', Buffer.alloc(0))]);
}

test('folder ticket: survives a restart, is reusable, replaces the old entry of the same browser, port in the file', async () => {
  const { pm, S, ctx } = manager(7781);
  const dir = path.join(ctx.paths.base, 'browser-erweiterung', 'hostwerk-passwoerter');
  fs.mkdirSync(dir, { recursive: true });
  pm.writePairingFile(dir, 'Chrome');
  const file = JSON.parse(fs.readFileSync(path.join(dir, 'hostwerk-pairing.json'), 'utf8'));
  assert.strictEqual(file.port, 7781); assert.ok(/^[a-f0-9]{48}$/.test(file.ticket));
  assert.ok(!JSON.stringify(S.passwords).includes(file.ticket), 'only the hash is stored');
  // „Neustart“: neuer Manager mit denselben Einstellungen (Speicher-Kopplungen sind weg, das Ticket gilt weiter)
  const pm2 = new PasswordManager({ ...ctx, uiPort: () => 7785 });
  const a = pm2.pair(file.ticket, { name: 'Chrome', browser: 'Chrome/141', version: '1.6.0' });
  assert.ok(a.token);
  const b = pm2.pair(file.ticket, { name: 'Chrome', browser: 'Chrome/141', version: '1.6.0' });
  assert.ok(b.token && b.token !== a.token, 'reusable');
  assert.strictEqual(S.passwords.ext.filter((x) => x.browser === 'Chrome/141').length, 1, 'same browser replaces its old entry');
  assert.strictEqual(pm2.extAuth({ headers: { 'x-hostwerk-ext': a.token } }), null, 'old key is gone');
  // Port gewechselt: die Datei bekommt den neuen Port, das gültige Ticket bleibt
  pm2.writePairingFile(dir);
  const f2 = JSON.parse(fs.readFileSync(path.join(dir, 'hostwerk-pairing.json'), 'utf8'));
  assert.strictEqual(f2.port, 7785); assert.strictEqual(f2.ticket, file.ticket); assert.strictEqual(f2.name, 'Chrome');
  // Abgelaufenes Ticket → klare Ursache für die Karte
  S.passwords.extTickets[0].until = Date.now() - 1;
  assert.throws(() => pm2.pair(file.ticket, { browser: 'Edg/141' }), (e) => e.status === 401 && e.reason === 'ticket' && /out of date/.test(e.message));
  assert.strictEqual(pm2.extState().error.reason, 'ticket');
});

test('extension card state: version and outdated, hello only from extensions, last error', () => {
  const { pm } = manager();
  const latest = pm.extVersion();
  assert.ok(/^\d+\.\d+\.\d+$/.test(latest));
  assert.throws(() => pm.extHello({ headers: { origin: 'https://evil.example' }, body: {} }), (e) => e.status === 403);
  const h = pm.extHello({ headers: { origin: 'chrome-extension://abcdefghijklmnop' }, body: { version: '1.0.0', paired: false, reason: 'expired', browser: 'Chrome/141' } });
  assert.strictEqual(h.latest, latest);
  const st = pm.extState();
  assert.ok(st.hello.outdated && st.hello.reason === 'expired' && st.hello.paired === false);
  const { code } = pm.pairCode();
  const p = pm.pair(code, { name: 'Edge', browser: 'Edg/141', version: '1.0.0' });
  assert.ok(pm.extState().ext[0].outdated);
  pm.extAuth({ headers: { 'x-hostwerk-ext': p.token, 'x-hostwerk-ext-version': latest } });
  const e = pm.extState().ext[0];
  assert.ok(!e.outdated && e.version === latest && e.lastUse && !('hash' in e));
  assert.throws(() => pm.autoPair({ headers: { origin: 'chrome-extension://abcdefghijklmnop' }, body: {} }), /Pairing not allowed/);
  assert.strictEqual(pm.extState().error.reason, 'window');
});

test('own image per item: Hostwerk vault (encrypted), only real images, not for Bitwarden; ext route as data address', async () => {
  const { pm } = manager();
  const v = await pm.create({ type: 'hostwerk', name: 'Home', password: 'master-pw-123' });
  const it = await pm.addItem(v.id, { type: 'login', name: 'Router', password: 'x' });
  const img = png();
  const r = await pm.setItemIcon(v.id, it.id, `data:image/png;base64,${img.toString('base64')}`);
  assert.ok(r.hasIcon && r.iconV);
  assert.ok((await pm.items(v.id))[0].hasIcon, 'list knows it (without the data)');
  assert.ok(!('icon' in (await pm.items(v.id))[0]));
  assert.ok((await pm.itemIcon(v.id, it.id)).data.equals(img));
  assert.ok(!fs.readFileSync(pm.file(v.id), 'utf8').includes(img.toString('base64').slice(0, 20)), 'encrypted in the vault file');
  await assert.rejects(pm.setItemIcon(v.id, it.id, Buffer.from('<svg onload=alert(1)></svg>').toString('base64')), (e) => e.status === 400);
  await assert.rejects(pm.setItemIcon(v.id, it.id, `data:image/png;base64,${Buffer.concat([img, Buffer.alloc(140 * 1024)]).toString('base64')}`), (e) => e.status === 400);
  // Ändern lässt das Bild stehen, Entfernen löscht es
  await pm.updateItem(v.id, it.id, { password: 'y' });
  assert.ok((await pm.item(v.id, it.id)).hasIcon);
  await pm.setItemIcon(v.id, it.id, null);
  assert.strictEqual(await pm.itemIcon(v.id, it.id), null);
  const bw = await pm.create({ type: 'bitwarden', name: 'BW', cfg: { email: 'a@b.example' } });
  await assert.rejects(pm.setItemIcon(bw.id, 'x', img.toString('base64')), /Bitwarden only shows website icons/);
  assert.strictEqual(pm.iconSupport('keepass').ok, true);
});

test('KeePass: own image as custom icon in the file, round trip through export and import (kdbx + XML)', async (t) => {
  if (!hasLib('kdbxweb') || !hasLib('hash-wasm')) { t.skip('kdbxweb/hash-wasm not found'); return; }
  const img = png();
  const buf = await io.writeKdbx([{ type: 'login', name: 'NAS', password: 'n', icon: { data: img.toString('base64'), mime: 'image/png' } }], 'kdbx-pass-1');
  const back = await io.parseInput({ data: buf.toString('base64'), name: 'x.kdbx', password: 'kdbx-pass-1' });
  assert.ok(Buffer.from(back.items[0].icon.data, 'base64').equals(img), 'custom icon came back');
  // Als verbundener KeePass-Tresor: Bild setzen, Datei neu öffnen, Bild ist da
  const { pm, dir } = manager();
  const file = path.join(dir, 'k.kdbx'); fs.writeFileSync(file, await io.writeKdbx([{ type: 'login', name: 'Router', password: 'r' }], 'kdbx-pass-1'));
  const v = await pm.create({ type: 'keepass', name: 'KP', cfg: { file, password: 'kdbx-pass-1' } });
  await pm.unlock(v.id);
  const id = (await pm.items(v.id))[0].id;
  await pm.setItemIcon(v.id, id, img.toString('base64'));
  pm.lock(v.id); await pm.unlock(v.id);
  assert.ok((await pm.items(v.id))[0].hasIcon);
  assert.ok((await pm.itemIcon(v.id, id)).data.equals(img));
  const xml = `<KeePassFile><Meta><CustomIcons><Icon><UUID>AAA=</UUID><Data>${img.toString('base64')}</Data></Icon></CustomIcons></Meta><Root><Group><Name>DB</Name><Entry><CustomIconUUID>AAA=</CustomIconUUID><String><Key>Title</Key><Value>Mail</Value></String></Entry></Group></Root></KeePassFile>`;
  const x = await io.parseInput({ text: xml });
  assert.ok(Buffer.from(x.items[0].icon.data, 'base64').equals(img));
});
