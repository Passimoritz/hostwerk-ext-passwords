'use strict';
/*
 * Anbieter-Programme (bw, op) mit Attrappen – ohne Netz, ohne echte Konten:
 *   nicht eingerichtet → keine Meldung, kein Download, keine Prüfung
 *   Programm fehlt     → Einrichten lädt es (Auftrag), Verbinden sagt „Bitwarden verbinden“ statt „bw nicht installiert“
 *   veraltet           → Update mit Probelauf; scheitert er, bleibt die alte Version (Rücksprung, echte Selbstwartung)
 *   blockiert          → Smart App Control wird erkannt und verständlich erklärt
 *   Herkunft           → nur Adressen des Herstellers, Prüfsumme und (Windows) Signatur des Herstellers
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const host = require('../server/host');

const HW = path.join(__dirname, '..', '..', '..', 'hostwerk');
const hasCore = fs.existsSync(path.join(HW, 'server', 'core', 'keeper.js'));
let net = 0; // Netzaufrufe der Attrappe
const fakeRelease = { version: '2026.10.0' };
const cmp = (a, b) => { const x = String(a).split('.').map(Number); const y = String(b).split('.').map(Number); for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0) ? 1 : -1; } return 0; };
const download = {
  cached: (k, ttl, fn) => fn(),
  fetchJson: async (url) => { net++; if (/github/.test(url)) return [{ tag_name: `cli-v${fakeRelease.version}`, prerelease: false, html_url: 'https://github.com/bitwarden/clients/releases', assets: [{ name: `bw-${process.platform === 'win32' ? 'windows' : 'linux'}${process.platform !== 'win32' && os.arch() === 'arm64' ? '-arm64' : ''}-${fakeRelease.version}.zip`, browser_download_url: fakeRelease.url || `https://github.com/bitwarden/clients/releases/download/cli-v${fakeRelease.version}/bw.zip`, digest: `sha256:${'a'.repeat(64)}` }] }]; return { version: fakeRelease.version }; },
  downloadFile: async (url, dest, opts) => { net++; download.lastSha = opts.sha256; fs.writeFileSync(dest, `zip ${fakeRelease.version}`); return dest; },
  extractZip: async (zip, dir) => { const v = fs.readFileSync(zip, 'utf8').split(' ')[1]; fs.writeFileSync(path.join(dir, process.platform === 'win32' ? 'bw.exe' : 'bw'), `fake bw ${v}`); },
  cmpVersion: cmp,
};
const jobs = { runJob: (title, fn) => { const job = { id: `job-${Date.now()}`, progress() {}, log(m) { job.logs.push(m); }, logs: [] }; job.promise = Promise.resolve().then(() => fn(job)); return job; } };
host.bind({
  t: (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? v[k] : m)) : s),
  lang: () => 'en',
  core: (n) => ({ secrets: { seal: (x) => `enc:${x}`, open: (x) => String(x || '').replace(/^enc:/, '') }, download, jobs, platform: { which: async () => null } }[n]),
  lib: (n) => require(require.resolve(n, { paths: [HW, __dirname] })),
  broadcast: () => {},
});
process.env.HW_TEST = '1';
const { PasswordManager } = require('../server/manager');

function manager() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hw-pwcli-'));
  const S = { general: { language: 'en' }, users: [] };
  const notes = {};
  const ctx = { settings: { get: () => S, save: () => {} }, paths: { data: dir, base: dir, cache: dir, bin: path.join(dir, 'bin') }, audit: { record: () => {} }, uiPort: () => 7000, keeper: { note: (k, x) => { notes[k] = x; } } };
  fs.mkdirSync(ctx.paths.bin, { recursive: true });
  if (hasCore) { const { Keeper } = require(path.join(HW, 'server', 'core', 'keeper.js')); const k = new Keeper(ctx); ctx.keeper = Object.assign(k, { note: (key, x) => { notes[key] = x; } }); }
  const pm = new PasswordManager(ctx);
  // Probelauf ohne echtes Programm: die Attrappe nennt die Version aus der Datei
  pm.clis.run = async (name, exe) => { const txt = fs.readFileSync(exe, 'utf8'); if (txt.includes('broken')) return { code: 1, out: '', err: 'crash' }; if (txt.includes('blocked')) return { code: 3236495362, out: '', err: '', blocked: true }; return { code: 0, out: txt.split(' ')[2] + '\n', err: '' }; };
  return { pm, S, notes, ctx };
}
process.env.HW_PW_FAKE_SIGNER = 'CN=Bitwarden Inc., O=Bitwarden Inc., C=US';

test('not set up: no program needed, no download, no check, no error', async () => {
  const { pm, notes } = manager();
  net = 0;
  assert.deepStrictEqual(pm.clis.needed(), []);
  const r = await pm.clis.check();
  assert.strictEqual(net, 0, 'nothing loaded from the internet');
  assert.ok(notes['pw-cli-bw-check'].ok && /not needed/.test(notes['pw-cli-bw-check'].text));
  assert.strictEqual(r.bw.needed, false);
  const q = pm.clis.quick('bw');
  assert.ok(!q.installed && !q.needed && !q.error);
  // Ein KeePass-Tresor braucht kein Programm
  await pm.create({ type: 'keepass', name: 'K', cfg: { file: 'x.kdbx' } });
  assert.deepStrictEqual(pm.clis.needed(), []);
});

test('program missing: setting up Bitwarden loads it, connecting says what to do', async () => {
  const { pm } = manager();
  let started = 0;
  const real = pm.clis.install.bind(pm.clis);
  pm.clis.install = (name) => { started++; return { id: `job-${name}`, promise: Promise.resolve() }; };
  const v = await pm.create({ type: 'bitwarden', name: 'BW', cfg: { email: 'a@b.example', password: 'pw' } });
  assert.strictEqual(v.cliJob, 'job-bw'); assert.strictEqual(started, 1);
  assert.deepStrictEqual(pm.clis.needed(), ['bw']);
  await assert.rejects(pm.unlock(v.id, 'pw'), (e) => e.pwCode === 'PW_CLI_MISSING' && /Connect Bitwarden/.test(e.message) && !/not installed/.test(e.message) && /signature/.test(e.hint));
  const op = await pm.create({ type: 'onepassword', name: '1P', cfg: { token: 'ops_x' } });
  assert.strictEqual(op.cliJob, 'job-op');
  await assert.rejects(pm.unlock(op.id), (e) => e.pwCode === 'PW_CLI_MISSING' && /Connect 1Password/.test(e.message));
  pm.clis.install = real;
  // Während des Ladens: freundlicher Hinweis statt Fehler
  pm.clis.state.op = { installing: true };
  await assert.rejects(pm.unlock(op.id), (e) => e.pwCode === 'PW_CLI_INSTALLING');
});

test('install: only from the maker, checksum handed to the download, signature checked', async () => {
  const { pm } = manager();
  await pm.create({ type: 'bitwarden', name: 'BW', cfg: { email: 'a@b.example' } }).catch(() => {});
  fakeRelease.version = '2026.10.0'; fakeRelease.url = null;
  const r = await pm.clis.install('bw', { manual: true }).promise;
  assert.strictEqual(r.version, '2026.10.0');
  assert.strictEqual(download.lastSha, 'a'.repeat(64), 'SHA-256 of the GitHub release is checked while downloading');
  assert.ok(pm.clis.ownExe('bw'));
  assert.ok(!fs.existsSync(path.join(pm.ctx.paths.bin, 'pw-bw.neu')), 'no leftovers');
  // Fremde Adresse → nichts installiert
  fakeRelease.version = '2026.10.1'; fakeRelease.url = 'https://evil.example/bw.zip';
  await assert.rejects(pm.clis.install('bw', { manual: true }).promise, /Unexpected download address/);
  fakeRelease.url = null;
  // Falsche Signatur (Windows) → nicht übernommen
  if (process.platform === 'win32') {
    process.env.HW_PW_FAKE_SIGNER = 'CN=Somebody Else';
    fakeRelease.version = '2026.10.2';
    await assert.rejects(pm.clis.install('bw', { manual: true }).promise, /signature does not fit/);
    process.env.HW_PW_FAKE_SIGNER = 'CN=Bitwarden Inc., O=Bitwarden Inc., C=US';
    assert.match(fs.readFileSync(pm.clis.ownExe('bw'), 'utf8'), /2026\.10\.0/, 'old version stays');
  }
});

test('outdated: update with test run, a broken version is rolled back and skipped', { skip: !hasCore && 'Hostwerk core (keeper) not found' }, async () => {
  const { pm, notes } = manager();
  await pm.create({ type: 'bitwarden', name: 'BW', cfg: { email: 'a@b.example' } });
  fakeRelease.version = '2026.9.0';
  await pm.clis.install('bw').promise;
  // Neue Version startet nicht → alte bleibt aktiv
  fakeRelease.version = '2026.11.0';
  const ex = download.extractZip;
  download.extractZip = async (zip, dir) => fs.writeFileSync(path.join(dir, process.platform === 'win32' ? 'bw.exe' : 'bw'), 'fake bw broken');
  await pm.clis.check();
  assert.match(fs.readFileSync(pm.clis.ownExe('bw'), 'utf8'), /2026\.9\.0/, 'rolled back to the working version');
  assert.ok(pm.ctx.keeper.isBad('pw-cli-bw', '2026.11.0'), 'broken version is skipped from now on');
  download.extractZip = ex;
  // Die nächste Version klappt → wird übernommen
  fakeRelease.version = '2026.12.0';
  await pm.clis.check();
  assert.match(fs.readFileSync(pm.clis.ownExe('bw'), 'utf8'), /2026\.12\.0/);
  assert.ok(notes['pw-cli-bw-check'].ok);
});

test('blocked by Smart App Control: recognised and explained, last version stays', async () => {
  const { pm } = manager();
  await pm.create({ type: 'bitwarden', name: 'BW', cfg: { email: 'a@b.example' } });
  fakeRelease.version = '2026.10.0';
  await pm.clis.install('bw').promise;
  fakeRelease.version = '2026.10.5';
  const ex = download.extractZip;
  download.extractZip = async (zip, dir) => fs.writeFileSync(path.join(dir, process.platform === 'win32' ? 'bw.exe' : 'bw'), 'fake bw blocked');
  await assert.rejects(pm.clis.install('bw', { manual: true }).promise, (e) => e.pwCode === 'PW_CLI_BLOCKED' && /Smart App Control/.test(e.message) && /reputation/.test(e.hint));
  download.extractZip = ex;
  assert.ok(pm.clis.quick('bw').blocked);
  assert.match(fs.readFileSync(pm.clis.ownExe('bw'), 'utf8'), /2026\.10\.0/);
});

test('a running program that Windows blocks gives the clear message (fake bw with status 0xC0E90002)', { skip: process.platform !== 'win32' && 'Windows only' }, async () => {
  const { pm } = manager();
  const fake = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'hw-fakebw-')), 'fake.js');
  fs.writeFileSync(fake, "process.exit(-1058471934);\n");
  process.env.HW_PW_FAKE_CLI = fake;
  try {
    const v = await pm.create({ type: 'bitwarden', name: 'BW', cfg: { email: 'a@b.example', password: 'pw' } }).catch(() => null);
    const id = v ? v.id : pm.list()[0].id;
    await assert.rejects(pm.unlock(id, 'pw'), (e) => e.pwCode === 'PW_CLI_BLOCKED');
  } finally { delete process.env.HW_PW_FAKE_CLI; }
});
