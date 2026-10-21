'use strict';
/*
 * Provider programs: Bitwarden/Vaultwarden and 1Password only let other programs in through their official command-line
 * tools (bw, op). Hostwerk fetches them itself – only from the maker – and keeps them current:
 *
 *   bw  GitHub release of bitwarden/clients (tag cli-v…); SHA-256 from the release (GitHub "digest"), on Windows also the
 *       Authenticode signature "Bitwarden Inc.". Without the GitHub API the version comes from vault.bitwarden.com/download
 *       (redirect) – then the signature alone has to fit (Windows), otherwise nothing is installed.
 *   op  version from app-updates.agilebits.com, file from cache.agilebits.com; on Windows the signature "AgileBits".
 *
 * Install = Hostwerk's self-maintenance (keeper.attempt): new version next to the old one, test run (--version with an own
 * data folder, never the user's), only then switch over; a failing version is skipped and the old one stays.
 * Smart App Control/WDAC blocking the program is recognised (spawn error / status 0xC0E90002) and explained.
 *
 * Only providers that are set up need a program: the daily check, updates and every error message only concern programs
 * of existing Bitwarden/1Password vaults. Without one nothing is downloaded, checked or reported.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const host = require('./host');
const { T } = require('./i18n');

const IS_WIN = process.platform === 'win32';
// 0xC0E90002 – STATUS_SYSTEM_INTEGRITY_POLICY_VIOLATION (Smart App Control / WDAC)
const BLOCK_CODES = new Set([3236495362, -1058471934]);
const ARCH = os.arch() === 'arm64' ? 'arm64' : 'amd64';

/** Known programs: label, providers that need them, signer on Windows, page with the maker's documentation. */
const CLIS = {
  bw: { label: 'Bitwarden CLI', product: 'Bitwarden', providers: ['bitwarden'], signer: /\bBitwarden Inc\./, page: 'https://bitwarden.com/help/cli/' },
  op: { label: '1Password CLI', product: '1Password', providers: ['onepassword'], signer: /\bAgile ?Bits\b/i, page: 'https://developer.1password.com/docs/cli/' },
};

/** Error with a code the interface reacts to (offer the download, explain the block) – the text says what to do. */
function cliError(code, name, msg, hint) { return Object.assign(new Error(msg), { status: 409, pwCode: code, cli: name, hint }); }

class Clis {
  /** pm = PasswordManager (settings, paths, keeper, vault list). */
  constructor(pm) { this.pm = pm; this.found = {}; this.state = {}; this.versions = {}; }
  get ctx() { return this.pm.ctx; }
  dir(name) { return path.join(this.ctx.paths.bin, `pw-${name}`); }
  ownExe(name) { const exe = path.join(this.dir(name), IS_WIN ? `${name}.exe` : name); return fs.existsSync(exe) ? exe : null; }
  /** Program path: own copy first, otherwise one found on the PATH (looked up once). */
  path(name) { return this.ownExe(name) || this.found[name] || null; }
  async lookup(name) {
    // Tests: Nachbildung der echten Programme (fake-bw, fake-op – ein Node-Skript, siehe providers.runCli)
    if (process.env.HW_TEST === '1' && process.env.HW_PW_FAKE_CLI && !this.ownExe(name)) return `fake-${name}`;
    if (this.found[name] === undefined) { try { this.found[name] = (await host.core('platform').which(name)) || null; } catch { this.found[name] = null; } }
    return this.path(name);
  }
  /** Programs that set-up vaults need right now. */
  needed() { const types = new Set(this.pm.list().map((i) => i.type)); return Object.keys(CLIS).filter((n) => CLIS[n].providers.some((p) => types.has(p))); }
  /** Environment for test runs: own data folder, never %APPDATA%\Bitwarden CLI or ~/.config/op of the user. */
  probeEnv(name) { const d = path.join(this.dir(name) + '.probe'); fs.mkdirSync(d, { recursive: true }); return name === 'bw' ? { BITWARDENCLI_APPDATA_DIR: d, NODE_OPTIONS: '' } : { OP_CONFIG_DIR: d }; }

  /** State without starting anything (for every page load). */
  quick(name) {
    const st = this.state[name] || {};
    return { installed: !!this.path(name), own: !!this.ownExe(name), needed: this.needed().includes(name), installing: !!st.installing, blocked: !!st.blocked, error: st.error || null, version: this.versions[name] || null, label: CLIS[name].label };
  }
  /** Full state with the version of the program (test run with --version). */
  async status(name) {
    const exe = await this.lookup(name);
    const out = this.quick(name);
    out.path = exe;
    if (exe) {
      const r = await this.run(name, exe, ['--version'], { timeout: 15000 });
      if (r.blocked) { this.state[name] = { ...this.state[name], blocked: true }; out.blocked = true; } else if (r.code === 0) { this.versions[name] = (r.out || r.err).trim().split('\n')[0].replace(/^v/, '') || null; out.version = this.versions[name]; out.blocked = false; if (this.state[name]) this.state[name].blocked = false; }
    }
    return out;
  }
  async run(name, exe, args, opts = {}) {
    const { runCli } = require('./providers');
    const r = await runCli(exe, args, { env: this.probeEnv(name), ...opts });
    return { ...r, blocked: r.blocked || BLOCK_CODES.has(r.code) };
  }

  /** Program for a vault – or an error that says what to do (connect = download, blocked = explanation). */
  async ensure(name) {
    const exe = await this.lookup(name);
    const c = CLIS[name];
    // Zuletzt blockiert: einmal neu probieren (Windows lässt es inzwischen vielleicht zu)
    if (this.state[name] && this.state[name].blocked && exe && (await this.status(name)).blocked) throw this.blockedError(name);
    if (exe) return exe;
    if (this.state[name] && this.state[name].installing) throw cliError('PW_CLI_INSTALLING', name, T('Hostwerk is still loading the {label} – one moment, then connect again.', { label: c.label }), null);
    throw cliError('PW_CLI_MISSING', name, T('{product} is not connected yet – click “Connect {product}”, Hostwerk then loads the official program ({cli}) by itself.', { product: c.product, cli: name }),
      T('{product} only lets other programs in through its official command-line program “{cli}”. Hostwerk downloads it once from {product}, checks the signature and keeps it up to date – you do not have to install anything.', { product: c.product, cli: name }));
  }
  markBlocked(name) { this.state[name] = { ...(this.state[name] || {}), blocked: true }; }
  blockedError(name) {
    const c = CLIS[name];
    return cliError('PW_CLI_BLOCKED', name, T('Windows is blocking the {label} (Smart App Control). Hostwerk tries again with the next version – until then: export from {product} and import the file, that works without the program.', { label: c.label, product: c.product }),
      T('Smart App Control only lets programs start that Microsoft knows. {product} signs its program, but brand-new versions sometimes have no “reputation” yet. Hostwerk keeps the last working version and checks every day whether a newer one starts.', { product: c.product }));
  }

  /* ---------- newest version from the maker ---------- */
  async latest(name) {
    const dl = host.core('download');
    const cat = (this.pm.catalog && this.pm.catalog.clis) || {};
    if (name === 'bw') {
      const plat = IS_WIN ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux';
      const suffix = !IS_WIN && ARCH === 'arm64' ? '-arm64' : '';
      try {
        const rels = await dl.cached('pw-bw-rel', 3600e3, () => dl.fetchJson(cat.bwReleases ? `${cat.bwReleases}?per_page=60` : 'https://api.github.com/repos/bitwarden/clients/releases?per_page=60'));
        const rel = (rels || []).find((r) => /^cli-v\d/.test(r.tag_name) && !r.prerelease && !r.draft);
        if (rel) {
          const version = rel.tag_name.replace(/^cli-v/, '');
          const asset = (rel.assets || []).find((a) => a.name === `bw-${plat}${suffix}-${version}.zip`) || (rel.assets || []).find((a) => a.name === `bw-oss-${plat}${suffix}-${version}.zip`);
          const sha256 = asset && /^sha256:[0-9a-f]{64}$/.test(asset.digest || '') ? asset.digest.slice(7) : null;
          return { version, url: asset ? asset.browser_download_url : null, sha256, page: rel.html_url };
        }
      } catch { /* GitHub nicht erreichbar oder Limit – Rückfall unten */ }
      // Rückfall: Bitwardens eigene Download-Adresse leitet auf die aktuelle Datei weiter (Version steht im Namen)
      const r = await fetch(`https://vault.bitwarden.com/download/?app=cli&platform=${plat}`, { redirect: 'manual', signal: AbortSignal.timeout(15000) });
      const loc = r.headers.get('location') || '';
      const m = loc.match(/^https:\/\/github\.com\/bitwarden\/clients\/releases\/download\/cli-v([\d.]+)\/(bw-[a-z0-9-]+-[\d.]+\.zip)$/);
      if (!m) throw new Error(T('No CLI version found'));
      return { version: m[1], url: loc, sha256: null, page: CLIS.bw.page };
    }
    if (name === 'op') {
      const j = await dl.cached('pw-op-rel', 3600e3, () => dl.fetchJson(cat.opCheck || 'https://app-updates.agilebits.com/check/1/0/CLI2/en/2.0.0/N'));
      const version = String((j && j.version) || '').replace(/^v/, '');
      if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(T('No CLI version found'));
      const base = cat.opBase || 'https://cache.agilebits.com/dist/1P/op2/pkg';
      const plat = IS_WIN ? 'windows' : process.platform === 'darwin' ? 'darwin' : 'linux';
      return { version, url: `${base}/v${version}/op_${plat}_${ARCH}_v${version}.zip`, sha256: null, page: CLIS.op.page };
    }
    throw new Error(T('Unknown CLI'));
  }

  /** Windows: Authenticode signature of the program → { status, subject } (PowerShell, path through the environment). */
  async signature(exe) {
    if (!IS_WIN) return null;
    if (process.env.HW_TEST === '1' && process.env.HW_PW_FAKE_SIGNER !== undefined) return { status: 'Valid', subject: process.env.HW_PW_FAKE_SIGNER };
    const { runCli } = require('./providers');
    const ps = '$s = Get-AuthenticodeSignature -LiteralPath $env:HW_PW_EXE; [pscustomobject]@{ status = [string]$s.Status; subject = [string]$s.SignerCertificate.Subject } | ConvertTo-Json -Compress';
    const r = await runCli('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], { env: { HW_PW_EXE: exe }, timeout: 60000 });
    try { return JSON.parse(r.out.trim()); } catch { return null; }
  }

  /**
   * Download and install (job with progress). manual = clicked by the user: a version that failed before is tried again
   * (e.g. after Smart App Control allowed it), otherwise the keeper skips it.
   */
  install(name, { manual = false } = {}) {
    const c = CLIS[name];
    if (!c) throw new Error(T('Unknown CLI'));
    // Läuft schon ein Download (z. B. vom Einrichten), denselben Auftrag zurückgeben statt einen zweiten zu starten
    if (this.jobs && this.jobs[name]) return this.jobs[name];
    this.jobs = this.jobs || {};
    const job = host.core('jobs').runJob(T('Download {label}', { label: c.label }), async (job) => {
      this.state[name] = { installing: true };
      try {
        const l = await this.latest(name);
        if (!l.url) throw new Error(T('No download found for this system: {page}', { page: l.page || '' }));
        if (!/^https:\/\/(github\.com\/bitwarden\/clients\/releases\/download\/|cache\.agilebits\.com\/)/.test(l.url)) throw new Error(T('Unexpected download address – only files from the maker are installed.'));
        if (!l.sha256 && !IS_WIN) job.log(T('No checksum published – the file comes straight from the maker over HTTPS.'));
        if (!l.sha256 && IS_WIN) job.log(T('No checksum published – Hostwerk checks the maker’s Windows signature instead.'));
        const key = `pw-cli-${name}`;
        const keeper = this.ctx.keeper;
        if (manual && keeper && keeper.data && keeper.data[key] && Array.isArray(keeper.data[key].bad)) keeper.data[key].bad = keeper.data[key].bad.filter((v) => v !== l.version);
        const dir = this.dir(name);
        const dl = host.core('download');
        const plan = {
          label: T('Password manager: {label}', { label: c.label }), version: l.version, present: () => !!this.ownExe(name),
          install: async () => {
            const tmp = dir + '.neu'; fs.rmSync(tmp, { recursive: true, force: true }); fs.mkdirSync(tmp, { recursive: true });
            const zip = path.join(this.ctx.paths.cache, `pw-${name}-${l.version}.zip`);
            fs.rmSync(zip, { force: true });
            await dl.downloadFile(l.url, zip, { sha256: l.sha256 || undefined, onProgress: (a, b) => job.progress(b ? (a / b) * 80 : 40, T('Downloading {name} {version}', { name, version: l.version })) });
            await dl.extractZip(zip, tmp);
            fs.rmSync(zip, { force: true });
            const exe = path.join(tmp, IS_WIN ? `${name}.exe` : name);
            if (!fs.existsSync(exe)) throw new Error(T('Program not found in the archive'));
            if (!IS_WIN) fs.chmodSync(exe, 0o755);
            return { tmp, exe };
          },
          probe: async ({ exe }) => {
            job.progress(85, T('Checking signature and test run'));
            const sig = await this.signature(exe);
            if (sig && (sig.status !== 'Valid' || !c.signer.test(sig.subject || ''))) throw new Error(T('The signature does not fit ({status}, {subject}) – the file is not installed.', { status: sig.status || '?', subject: sig.subject || '?' }));
            if (IS_WIN && !sig && !l.sha256) throw new Error(T('Neither checksum nor signature could be checked – the file is not installed.'));
            const t = await this.run(name, exe, ['--version'], { timeout: 30000 });
            if (t.blocked) { this.state[name] = { installing: true, blocked: true }; throw new Error(T('Smart App Control blocks the program.')); }
            if (t.code !== 0) throw new Error(T('Does not start: {out}', { out: String(t.err || t.out).slice(0, 200) }));
            const v = (t.out || t.err).trim().split('\n')[0].replace(/^v/, '');
            if (v && v !== l.version) job.log(T('Version according to the program: {v}', { v }));
          },
          activate: async ({ tmp }) => { fs.rmSync(dir, { recursive: true, force: true }); fs.renameSync(tmp, dir); this.pm.relock(c.providers); },
          discard: async (x) => { if (x && x.tmp) fs.rmSync(x.tmp, { recursive: true, force: true }); },
        };
        const r = keeper ? await keeper.attempt(key, plan) : await (async () => { const x = await plan.install(); try { await plan.probe(x); await plan.activate(x); return { ok: true }; } catch (e) { await plan.discard(x); return { ok: false, error: e.message }; } })();
        if (!r.ok) {
          const blocked = !!(this.state[name] && this.state[name].blocked);
          this.state[name] = { blocked, error: blocked ? null : r.error || T('Test run failed') };
          if (blocked) throw this.blockedError(name);
          const bad = r.skipped && keeper && keeper.isBad && keeper.isBad(key, l.version);
          throw new Error(bad ? T('Version {v} already failed the test run – Hostwerk waits for the next one.', { v: l.version }) : r.skipped ? T('The {label} is being loaded right now – one moment.', { label: c.label }) : r.error || T('Test run failed'));
        }
        this.state[name] = {};
        this.versions[name] = l.version;
        return { version: l.version, path: this.path(name) };
      } catch (e) { if (this.state[name] && this.state[name].installing) this.state[name] = { error: e.message }; throw e; }
    }, { key: `pw-cli-${name}` });
    this.jobs[name] = job;
    const done = () => { if (this.jobs[name] === job) delete this.jobs[name]; };
    if (job && job.promise && job.promise.then) job.promise.then(done, done); else done();
    return job;
  }

  /**
   * Daily check (self-maintenance): only programs that set-up vaults need. Own copies are updated (with test run),
   * missing ones are loaded; programs found on the PATH belong to the system and are left alone.
   */
  async check() {
    const { cmpVersion } = host.core('download');
    const need = this.needed();
    const out = {};
    for (const name of Object.keys(CLIS)) {
      const label = T('Password manager: {name} CLI', { name });
      if (!need.includes(name)) { this.pm.note(`pw-cli-${name}-check`, true, label, T('not needed – no {product} vault set up', { product: CLIS[name].product })); out[name] = { needed: false }; continue; }
      try {
        const st = await this.status(name);
        const l = await this.latest(name);
        out[name] = { ...st, latest: l.version };
        const outdated = st.own && st.version && cmpVersion(l.version, st.version) > 0;
        if ((outdated || !st.installed) && !(this.state[name] && this.state[name].installing)) await this.install(name).promise.catch(() => {});
        const now = this.quick(name);
        this.pm.note(`pw-cli-${name}-check`, !now.blocked && now.installed, label, now.blocked ? T('blocked by Smart App Control – the last working version stays') : now.installed ? T('installed {v}, current {latest}', { v: this.versions[name] || st.version || '?', latest: l.version }) : T('not installed (current {latest})', { latest: l.version }));
      } catch (e) { out[name] = { needed: true, error: e.message }; this.pm.note(`pw-cli-${name}-check`, false, label, T('Version check failed: {msg}', { msg: e.message })); }
    }
    return out;
  }
}

module.exports = { Clis, CLIS, BLOCK_CODES, cliError };
