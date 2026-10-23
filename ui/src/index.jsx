import { useEffect, useState, useRef } from 'react';
import { KeyRound, Lock, Unlock, Plus, Star, Trash2, Copy, RefreshCw, ShieldCheck, Upload, Download, Puzzle, Settings2, Link2, EyeOff, Wand2, Terminal } from 'lucide-react';
import { get, post, put, del, useApi, on, waitJob, fmtDate, HAS_DESKTOP } from '@hostwerk/api';
import { Btn, Tabs, Field, Switch, SettingRow, Seg, Empty, Loading, Callout, Modal, toast, promptDialog, InfoTip, PathInput, TileEmpty } from '@hostwerk/ui';
import * as HUI from '@hostwerk/ui';
import { SvcImage, contextMenu, useNew, FavMark, favSort, favMenuItem } from '@hostwerk/kit';
import { t } from '@hostwerk/i18n';
import { VaultView, REQUIRED, fieldLabel, clearLater } from './Vault';
import { SharedWithMe } from './Share';
import { ExtGuide, ExtLinked, extSteps, BrowserMark, BROWSER_COLORS } from './Guide';
import './style.css';

/*
 * Passwords: own Hostwerk vault or connected services (Bitwarden/Vaultwarden, 1Password, KeePass, pass, LastPass) plus
 * import/export for all others – items, folders, tags, TOTP, generator, security check, browser extension, provider CLIs
 * with self-maintenance. Addresses: #/ext/passwords[/<vault>[/<tab>]] and #/ext/passwords/_/<browser|settings>.
 */
const BASE = '/ext/passwords';
const BROWSERS = [{ id: 'chrome', label: 'Chrome' }, { id: 'edge', label: 'Edge' }, { id: 'firefox', label: 'Firefox' }, { id: 'brave', label: 'Brave' }, { id: 'opera', label: 'Opera' }, { id: 'vivaldi', label: 'Vivaldi' }];
/** Browser id from the user agent token or name ("Edg/141", "Chrome") → chrome/edge/… */
const browserId = (ua, name) => { const s = `${ua || ''} ${name || ''}`.toLowerCase(); return s.includes('edg') ? 'edge' : s.includes('firefox') ? 'firefox' : s.includes('opr') || s.includes('opera') ? 'opera' : s.includes('brave') ? 'brave' : s.includes('vivaldi') ? 'vivaldi' : 'chrome'; };
const copyText = (x) => { try { navigator.clipboard.writeText(x); clearLater(x); toast('Copied'); } catch { /* ignore */ } };
const KEEPASS_FILTER = () => [{ name: t('KeePass database'), extensions: ['kdbx', 'kdb'] }];

function CreateDialog({ data, onClose, onDone }) {
  const [type, setType] = useState('hostwerk');
  const [f, setF] = useState({ name: '', password: '', password2: '', cfg: {} });
  const [busy, setBusy] = useState(false);
  const P = data.providers.find((p) => p.id === type);
  const own = type === 'hostwerk' || type === 'import'; // "Other service" = own vault the export is imported into
  const missing = own ? [] : (REQUIRED[type] || []).concat(type === 'keepass' || type === 'lastpass' ? ['password'] : []).filter((k) => !String(f.cfg[k] || '').trim());
  const create = async () => {
    if (own && f.password !== f.password2) return toast.error(t('The passwords do not match.'));
    setBusy(true);
    try {
      const r = await post('/pw', { type: own ? 'hostwerk' : type, name: f.name || (type === 'import' ? t('Imported vault') : ''), password: f.password, cfg: f.cfg });
      toast.success(t('{name} created', { name: r.name }));
      // Anbieter mit eigenem Programm: Hostwerk lädt es schon im Hintergrund – bis zum Verbinden ist es meist da
      if (r.cliJob && P) toast(t('Hostwerk is loading the official {label} program in the background.', { label: P.label }));
      onDone(r, type === 'import');
    } catch (e) { toast.error(e.message); }
    setBusy(false);
    return undefined;
  };
  const cliOk = !P || !P.cli || (data.cli && data.cli[P.cli] && data.cli[P.cli].installed);
  const cliBlocked = P && P.cli && data.cli && data.cli[P.cli] && data.cli[P.cli].blocked;
  const blocked = own ? f.password.length < 8 || f.password !== f.password2 : missing.length > 0;
  return (
    <Modal title="Add a password manager" onClose={onClose} size="lg" footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" busy={busy} disabled={blocked} title={missing.length ? t('Still missing: {list}', { list: missing.map((k) => fieldLabel(P, k)).join(', ') }) : undefined} onClick={create}>{type === 'import' ? t('Create & import') : own ? t('Create') : t('Connect')}</Btn></>}>
      <div className="stack">
        <div className="pw-types">
          <button className={`pw-type ${type === 'hostwerk' ? 'on' : ''}`} aria-pressed={type === 'hostwerk'} onClick={() => setType('hostwerk')}><KeyRound /><b>{t('Hostwerk vault')}</b><span>{t('Own encrypted vault on this PC')}</span></button>
          {data.providers.map((p) => <button key={p.id} className={`pw-type ${type === p.id ? 'on' : ''}`} aria-pressed={type === p.id} onClick={() => setType(p.id)}><img className="pw-type-logo" src={`/api/icons/pw/_${p.id}?auto=1`} alt="" onError={(e) => { e.currentTarget.style.display = 'none'; }} /><b>{p.label}</b><span>{p.readonly ? t('read only') : t('manage directly')}</span></button>)}
          <button className={`pw-type ${type === 'import' ? 'on' : ''}`} aria-pressed={type === 'import'} onClick={() => setType('import')}><Upload /><b>{t('Other service')}</b><span>{t('Google, Apple, Proton, Dashlane … by import')}</span></button>
        </div>
        {type === 'import' && <InfoTip>Google, Apple, Proton, Dashlane, NordPass & co. have no interface – Hostwerk creates an own vault for them and opens the import right away: drag in the service’s export file, Hostwerk recognises the format itself. You can always go back with “Export” in the service’s format.</InfoTip>}
        <div className="form-grid">
          <Field label="Name" className="span-2"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder={type === 'hostwerk' ? t('My vault') : type === 'import' ? t('e.g. Google passwords') : P && P.label} /></Field>
          {own && <><Field label="Master password"><input className="input" type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field><Field label="Repeat"><input className="input" type="password" value={f.password2} onChange={(e) => setF({ ...f, password2: e.target.value })} /></Field><div className="span-2"><Callout kind="warn" dismissible={false}>The master password cannot be recovered – without it the vault is lost. Hostwerk stores it nowhere.</Callout></div></>}
          {!own && P && P.fields.map(([k, l, kind]) => <Field key={k} label={t(l) + (missing.includes(k) ? ' *' : '')} className={kind === 'path' ? 'span-2' : ''}>{(kind === 'path' ? <PathInput value={f.cfg[k] || ''} onChange={(v) => setF({ ...f, cfg: { ...f.cfg, [k]: v } })} mode={k === 'store' ? 'folder' : 'file'} filters={k === 'file' ? KEEPASS_FILTER() : undefined} title={t(l)} placeholder={k === 'file' ? 'Passwords.kdbx' : ''} /> : <input className="input" type={kind === 'password' ? 'password' : 'text'} value={f.cfg[k] || ''} onChange={(e) => setF({ ...f, cfg: { ...f.cfg, [k]: e.target.value } })} />)}</Field>)}
          {!own && P && <div className="span-2 small muted">{t(P.hint)}</div>}
          {P && P.cli && !cliOk && <div className="span-2 small muted row-tight"><Download size={14} aria-hidden="true" />{t('Hostwerk loads the official program “{cli}” by itself – from the maker, with a signature check.', { cli: P.cli })}</div>}
          {cliBlocked && <div className="span-2"><Callout kind="warn" dismissible={false}>{t('Windows (Smart App Control) is currently blocking the program “{cli}”. Hostwerk tries again with every new version – until then, importing an export file works without it.', { cli: P.cli })}</Callout></div>}
        </div>
      </div>
    </Modal>
  );
}

/** Remove a vault – always with a password (or the name for providers without a stored password). */
async function removeVault(v, reload) {
  const own = v.type === 'hostwerk';
  const stored = !own && v.cfg && v.cfg.password;
  const r = await promptDialog({
    title: t('Remove {name}?', { name: v.name }),
    text: own ? t('For safety, removing needs the master password of this vault.') : stored ? t('For safety, removing needs the stored password of this provider. Nothing changes at the provider itself.') : t('To confirm, type the name “{name}”. Nothing changes at the provider itself.', { name: v.name }),
    label: own ? t('Master password') : stored ? t('Password') : t('Name'),
    password: own || !!stored, danger: true, confirm: t('Remove'),
    checkbox: own ? { label: t('Delete the vault file for good (otherwise it stays under data/passwoerter)'), checked: false } : null,
  });
  if (!r) return;
  const value = typeof r === 'object' ? r.value : r;
  // Typed name: the name as shown in the other language counts too (the interface translates names like “My vault”)
  const norm = (x) => String(x || '').trim().replace(/\s+/g, ' ').toLowerCase();
  const confirmName = !own && !stored && [v.name, t(v.name)].some((x) => norm(x) === norm(value)) ? v.name : value;
  try {
    await del(`/pw/${v.id}`, own || stored ? { password: value, deleteFile: !!(r && r.checked) } : { confirm: confirmName });
    toast.success(t('{name} removed', { name: v.name })); reload();
  } catch (e) { toast.error(e.message); }
}

/**
 * Browser extension card: shows the current state first – connected (browser, version, last seen, remove), waiting (only
 * the next step lights up), problem (cause + fix) – and keeps the full guide one click away ("Show guide").
 * The state comes from Hostwerk (/pw/ext/state): pairings, the extension's last "hello" and the last pairing error.
 */
const REASON = {
  ticket: { text: 'The pairing file in the extension folder is out of date.', fix: 'Install again – the extension then connects by itself.' },
  expired: { text: 'The extension lost its pairing (e.g. after removing it in Hostwerk).', fix: 'Install again – the extension then connects by itself.' },
  window: { text: 'The extension asked to pair, but “Install” was clicked more than 15 minutes ago.', fix: 'Install again – the extension then connects by itself.' },
  'needs-install': { text: 'The extension is loaded but not paired yet.', fix: 'Install again – the extension then connects by itself.' },
  unknown: { text: 'An extension with another id asked to pair (e.g. a copy from somewhere else).', fix: 'Load the folder below in the browser, or pair with a code.' },
  code: { text: 'A pairing code was wrong or expired.', fix: 'Show a new pairing code.' },
};
function ExtensionCard({ data, reload }) {
  const [code, setCode] = useState(null);
  const [left, setLeft] = useState(0);
  const det = useApi('/pw/browsers', [], { live: false });
  const st = useApi('/pw/ext/state', [], { live: false, poll: true });
  useEffect(() => on('passwords-ext', () => st.reload()), []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => on('passwords', () => st.reload()), []); // eslint-disable-line react-hooks/exhaustive-deps
  const found = det.data || [];
  const [browser, setBrowserRaw] = useState(null);
  const pickedOnce = useRef(false);
  useEffect(() => { if (!pickedOnce.current && det.data) { pickedOnce.current = true; if (found[0] && BROWSERS.some((b) => b.id === found[0].id)) setBrowserRaw(found[0].id); else setBrowserRaw('chrome'); } }, [det.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const setBrowser = (b) => { pickedOnce.current = true; setBrowserRaw(b); };
  const browserOpts = [...BROWSERS].sort((a, b) => Number(found.some((f) => f.id === b.id)) - Number(found.some((f) => f.id === a.id)))
    .map((b) => { const f = found.find((x) => x.id === b.id); return { id: b.id, label: <span className={`br-opt ${f ? 'have' : 'miss'}`}><span className="br-dot" style={{ '--br': BROWSER_COLORS[b.id] }} />{b.label}{f && f.default ? <span className="br-def">{t('Default')}</span> : null}</span> }; });
  const [inst, setInst] = useState(null);
  const [busy, setBusy] = useState(false);
  const [guide, setGuide] = useState(false);
  const fx = browser === 'firefox';
  const label = (BROWSERS.find((b) => b.id === browser) || BROWSERS[0]).label;
  const isFound = found.some((f) => f.id === browser);
  // Live countdown of the pairing code; expired → hide it
  useEffect(() => {
    if (!code) return undefined;
    const tick = () => { const l = Math.max(0, Math.round((code.until - Date.now()) / 1000)); setLeft(l); if (l <= 0) setCode(null); };
    tick(); const x = setInterval(tick, 500); return () => clearInterval(x);
  }, [code]);
  const newCode = async () => { try { const c = await get('/pw/ext/pair-code'); setCode({ ...c, until: Date.now() + (c.expiresIn || 600) * 1000 }); } catch (e) { toast.error(e.message); } };
  const install = async () => {
    setBusy(true);
    try { const r = await post('/pw/extension/install', { browser }); setInst(r); setGuide(true); if (r.opened) toast.success(r.mode === 'dev' ? t('Extension page opened in {label}', { label }) : t('{label} opened – click “Add” there', { label })); else toast.warn(t('{label} could not be opened – the steps below still apply', { label })); st.reload(); } catch (e) { toast.error(e.message); }
    setBusy(false);
  };
  const mode = inst ? inst.mode : null;
  const s = st.data || {};
  const live = (s.ext || []).filter((e) => !e.expired);
  const since = inst ? inst.since : 0;
  const linkedNow = inst && live.find((e) => e.created >= since);
  useEffect(() => { if (linkedNow) { toast.success(t('{name} is connected to Hostwerk', { name: linkedNow.name })); reload(); } }, [linkedNow && linkedNow.id]); // eslint-disable-line react-hooks/exhaustive-deps
  // Welcher Schritt ist dran? Ohne „Hallo“ der Erweiterung: laden (Schritt 3 bzw. „Hinzufügen“); mit „Hallo“: verbinden
  const helloAfter = s.hello && (!inst || s.hello.at >= since);
  const steps = extSteps({ mode, fx, label, registered: inst && inst.registered });
  const current = inst && !linkedNow ? (helloAfter ? steps.length - 1 : Math.max(0, steps.length - 2)) : null;
  // Problem: letzte Ursache aus Hostwerk (Kopplungsfehler) oder das „Hallo“ einer ungekoppelten Erweiterung
  const problem = !linkedNow && ((s.error && (!inst || s.error.at >= since - 1000) && REASON[s.error.reason] && { ...REASON[s.error.reason], reason: s.error.reason }) || (s.hello && !s.hello.paired && s.hello.reason && REASON[s.hello.reason] && { ...REASON[s.hello.reason], reason: s.hello.reason }));
  const outdated = live.filter((e) => e.outdated);
  const mm = Math.floor(left / 60); const ss = String(left % 60).padStart(2, '0');
  const showGuide = guide || (!live.length && !problem) || (inst && !linkedNow);
  return (
    <div className="card">
      <div className="card-head"><Puzzle size={16} aria-hidden="true" /><h3>Browser extension</h3><InfoTip>{t('The extension only talks to your Hostwerk (127.0.0.1). It finds Hostwerk again by itself after a restart or a port change and pairs again with the file in its folder – no code needed.')}</InfoTip></div>
      <div className="card-body stack pw-ext-card">
        {/* Zustand zuerst */}
        {linkedNow ? <ExtLinked name={linkedNow.name} browser={label} />
          : live.length > 0 && <div className="stack pw-gap-1" role="status"><div className="small bold row-tight"><span className="live" aria-hidden="true" />{t('Connected')}</div>
            <div className="pw-ext-list">{live.map((e, i) => { const id = browserId(e.browser, e.name); const active = e.lastUse && Date.now() - e.lastUse < 10 * 60000; return <div key={e.id} className="pw-ext-row" style={{ animationDelay: `${i * 40}ms` }}><BrowserMark id={id} /><span className="grow small">{e.name} <span className="muted tiny">{e.browser ? e.browser.replace(/\/[\d.]+$/, '') + ' · ' : ''}{e.version ? t('version {v}', { v: e.version }) + ' · ' : ''}{e.lastUse ? t('last seen {date}', { date: fmtDate(e.lastUse) }) : t('paired {date}', { date: fmtDate(e.created) })}</span>{e.outdated && <span className="tiny c-warn pw-ext-old">{t('Older version – click “Update now” in the extension’s popup (or reload it in the browser’s extension page).')}</span>}</span>{active && <span className="live" title={t('Used in the last 10 minutes')} />}<button type="button" className="btn ghost xs icon" title={t('Remove pairing')} aria-label={t('Remove the pairing of {name}', { name: e.name })} onClick={async () => { await del(`/pw/ext/${e.id}`); reload(); st.reload(); }}><Trash2 /></button></div>; })}</div>
            {outdated.length > 0 && <div className="tiny muted">{t('Hostwerk already put version {v} into the extension folder.', { v: s.latest })}</div>}
          </div>}
        {problem && <Callout kind="warn" dismissible={false}><div className="stack pw-gap-1"><b>{t(problem.text)}</b><span className="small">{t(problem.fix)}</span><div className="row-tight">{problem.reason === 'code' ? <Btn className="xs" icon={KeyRound} onClick={newCode}>Show pairing code</Btn> : <Btn className="xs primary" icon={Download} busy={busy} disabled={!browser} onClick={install}>{t('Install in {label}', { label })}</Btn>}</div></div></Callout>}
        {s.hello && !s.hello.paired && !problem && !linkedNow && <div className="small muted" role="status">{t('The extension is loaded (version {v}) and is connecting …', { v: s.hello.version || '?' })}</div>}

        {/* Anleitung: aufgeklappt, solange nichts verbunden ist oder gerade installiert wird */}
        {!showGuide ? <div><button type="button" className="btn ghost sm" aria-expanded="false" onClick={() => setGuide(true)}>{t('Show guide')}</button></div> : <>
          <div className="row pw-ext-pick"><span className="small bold">{t('Browser')}</span>{browser ? <Seg value={browser} onChange={(b) => { setBrowser(b); setInst(null); }} options={browserOpts} /> : <span className="small muted">{t('Looking for browsers …')}</span>}{det.data && <span className="tiny muted">{found.length ? t('{n} found on this PC – marked in colour', { n: found.length }) : t('No browser found – choose yours.')}</span>}</div>
          <div className="row pw-ext-pick">
            <Btn className="primary sm" icon={Download} busy={busy} disabled={!browser} title={isFound ? '' : t('{label} was not found on this PC', { label })} onClick={install}>{t('Install in {label}', { label })}</Btn>
            <a className="btn sm" href={`/api/pw/extension/${browser}`}><Download />{fx ? t('Download .xpi') : t('Download ZIP')}</a>
            {live.length > 0 && <button type="button" className="btn ghost sm" aria-expanded="true" onClick={() => setGuide(false)}>{t('Hide guide')}</button>}
          </div>
          {inst && !linkedNow ? (
            <div className="stack pw-gap-1">
              <div className="small bold">{inst.opened ? t('{label} is open – this is how it goes on', { label }) : t('The extension is ready')}</div>
              {mode === 'dev' && <div className="row-tight small"><span className="muted">{fx ? t('File') : t('Folder')}</span><code className="ellipsis pw-ext-path">{inst.dir || inst.file}</code><button type="button" className="btn ghost xs icon" title={t('Copy path')} aria-label={t('Copy path')} onClick={() => copyText(inst.dir || inst.file)}><Copy /></button>{!inst.opened && inst.url && <span className="tiny muted">{t('→ open {url} in the browser', { url: inst.url })}</span>}</div>}
              {mode === 'store' && !inst.opened && inst.page && <a className="btn sm" href={inst.page} target="_blank" rel="noreferrer">{t('Open the store page')}</a>}
              <ExtGuide steps={steps} current={current} />
              <div className="row-tight tiny muted" role="status"><RefreshCw size={12} className="spin" aria-hidden="true" />{helloAfter ? t('The extension is loaded – it is connecting …') : t('Waiting for the extension – once it is loaded it connects by itself.')}</div>
            </div>
          ) : browser && !inst ? <div className="stack pw-gap-1"><div className="small muted">{t('This is how it goes – “Install in {label}” does the start:', { label })}</div><ExtGuide steps={extSteps({ mode: null, fx, label })} /></div> : null}
          <details className="pw-ext-code"><summary className="small">{t('Pair with a code instead')}</summary>
            <div className="stack pw-gap-1">
              <div className="row-tight"><Btn className="sm" icon={code ? RefreshCw : KeyRound} onClick={newCode}>{code ? t('New pairing code') : t('Show pairing code')}</Btn>{code && <Btn className="sm ghost" icon={EyeOff} onClick={() => setCode(null)}>Hide</Btn>}</div>
              {code && (
                <div className="pw-code">
                  <b>{code.code}</b>
                  <div className="grow small muted">{t('Port {port} · valid for', { port: code.port })} <b className={left < 60 ? 'c-warn' : ''}>{mm}:{ss}</b> · {t('enter it in the extension’s popup')}<div className="progress pw-code-bar"><div style={{ width: `${(left / (code.expiresIn || 600)) * 100}%` }} /></div></div>
                  <button type="button" className="btn ghost xs icon" title={t('Copy code')} aria-label={t('Copy code')} onClick={() => copyText(code.code)}><Copy /></button>
                </div>
              )}
            </div>
          </details>
        </>}
        <div className="tiny muted">{t('In the browser: click the icon for matches of the page, search and the generator; Ctrl+Shift+L fills in the first match; after a sign-in the extension offers to save it.')}</div>
      </div>
    </div>
  );
}

/** Provider programs: only interesting for set-up providers – the others are shown calmly as “not needed”. */
function CliCard({ data, reload }) {
  const [st, setSt] = useState(data.cli || null);
  const [busy, setBusy] = useState(null);
  useEffect(() => { get('/pw/cli').then(setSt).catch(() => {}); }, []);
  const inst = async (n) => { setBusy(n); try { const r = await post(`/pw/cli/${n}/install`); const j = await waitJob(r.job); toast.success(t('{n} {v} downloaded and checked', { n, v: j.result.version })); setSt(await get('/pw/cli')); reload(); } catch (e) { toast.error(e.message); setSt(await get('/pw/cli').catch(() => st)); } setBusy(null); };
  const ROWS = [['bw', 'Bitwarden CLI (bw)', 'for Bitwarden and Vaultwarden'], ['op', '1Password CLI (op)', 'for 1Password with a service account']];
  const state = (s2) => {
    if (s2.blocked) return <span className="c-warn">{t('blocked by Smart App Control – Hostwerk tries again with the next version')}</span>;
    if (s2.installed) return `${t('installed {v}', { v: s2.version || '' })}${s2.latest ? ` · ${t('current {v}', { v: s2.latest })}` : ''}${s2.own === false ? ` · ${t('from the system')}` : ''}`;
    if (!s2.needed) return t('not needed – no such vault set up');
    if (s2.installing) return t('is being loaded …');
    if (s2.error) return <span className="c-err">{s2.error}</span>;
    return t('not loaded yet – happens when connecting');
  };
  return (
    <div className="card">
      <div className="card-head"><Settings2 size={16} aria-hidden="true" /><h3>Provider programs</h3><InfoTip>{t('Bitwarden and 1Password only let other programs in through their official command-line programs. Hostwerk loads them when you connect, checks checksum and signature, tests every new version before switching and keeps the last working one. Without such a vault nothing is downloaded or checked.')}</InfoTip></div>
      {!st ? <Loading /> : ROWS.map(([n, l, x]) => { const s2 = st[n] || {}; return (
        <div key={n} className="list-item"><div className="ico"><Link2 aria-hidden="true" /></div>
          <div className="grow small"><b>{l}</b> <span className="muted">{t(x)}</span><div className="tiny muted">{state(s2)}</div></div>
          {(s2.needed || s2.own) && <Btn className="xs" icon={s2.installed ? RefreshCw : Download} busy={busy === n || !!s2.installing} onClick={() => inst(n)}>{s2.installed ? t('Check for update') : t('Load now')}</Btn>}
        </div>); })}
      {st && st.kdbxweb && <div className="card-body tiny muted">{t('KeePass library kdbxweb {v}', { v: st.kdbxweb.version })}{st.kdbxweb.latest && st.kdbxweb.latest !== st.kdbxweb.version ? ` ${t('(npm: {v} – comes with the next Hostwerk update)', { v: st.kdbxweb.latest })}` : ''} · {t('leak check through pwnedpasswords.com')}{data.catalog && data.catalog.updated ? ` · ${t('catalogue from {date}', { date: data.catalog.updated })}` : ''}</div>}
    </div>
  );
}

/** Generator rules per site (length/characters the site allows) – the browser extension uses them too. */
function GenRules() {
  const [rules, setRules] = useState(null);
  useEffect(() => { get('/pw/gen-rules').then(setRules).catch(() => setRules({})); }, []);
  const drop = async (site) => { try { setRules(await put('/pw/gen-rules', { site, opts: null })); } catch (e) { toast.error(e.message); } };
  const desc = (o) => (o.words ? t('{n} words', { n: o.words }) : `${t('{n} characters', { n: o.length })} · ${[o.upper && 'A–Z', o.lower && 'a–z', o.digits && '0–9', o.symbols && '!@#'].filter(Boolean).join(' ')}`);
  return (
    <div className="card">
      <div className="card-head"><Wand2 size={16} aria-hidden="true" /><h3>Generator rules</h3><InfoTip>{t('Add a rule in the generator (“Rule for this site”). New passwords for that site and its subdomains then follow it – here and in the browser extension.')}</InfoTip></div>
      {!rules ? <Loading /> : Object.keys(rules).length === 0 ? <TileEmpty text={t('No rules yet – every site gets 20 characters with all character kinds.')} />
        : Object.entries(rules).map(([site, o]) => <div key={site} className="list-item"><div className="grow small"><b>{site}</b> <span className="muted tiny">{desc(o)}</span></div><button type="button" className="btn ghost xs icon" title={t('Remove rule')} aria-label={t('Remove the rule for {site}', { site })} onClick={() => drop(site)}><Trash2 /></button></div>)}
    </div>
  );
}

export function PasswordsPage({ path = [] }) {
  // Members (own sign-in through remote access) only see what is shared with them
  const me = useApi('/pw/shared/mine', [], { live: false, poll: true });
  if (!me.data) return <Loading />;
  if (me.data.member) return <div className="page"><div className="page-head"><div><h1><KeyRound size={22} /> Passwords</h1><p>Logins shared with you.</p></div></div><SharedWithMe /></div>;
  const [first, second] = path;
  return first === '_' ? <PasswordsMain tab={second} /> : <PasswordsMain id={first} tab={second} />;
}

function PasswordsMain({ id, tab }) {
  const d = useApi('/pw');
  const [create, setCreate] = useState(false);
  const [cfg, setCfg] = useState(null);
  useNew('pw', () => setCreate(true));
  useEffect(() => on('passwords', () => d.reload()), []); // eslint-disable-line react-hooks/exhaustive-deps
  if (!d.data) return <Loading />;
  const data = d.data;
  const cur = id && data.instances.find((x) => x.id === id);
  const view = cur ? 'vault' : tab || 'overview';
  const rename = async (v) => { const n = await promptDialog({ title: t('Rename'), label: t('Name'), value: v.name }); if (n) { await put(`/pw/${v.id}`, { name: n }); d.reload(); } };
  return (
    <div className="page fade-in">
      <div className="page-head">
        <div><h1><KeyRound size={22} /> {t('Passwords')}{cur ? <> <span className="muted">/</span> {cur.name}</> : ''}</h1><p>{cur ? `${cur.label}${cur.locked ? ` · ${t('locked')}` : ''}` : t('Own vault or an existing password manager – with browser extension, security check and import from every common service.')}</p></div>
        <div className="actions">{cur && <a className="btn" href={`#${BASE}`}>{t('All vaults')}</a>}{data.instances.some((x) => !x.locked) && <Btn className="ghost" icon={Lock} onClick={async () => { await post('/pw/lock-all'); toast(t('All locked')); }}>Lock all</Btn>}<Btn className="primary" icon={Plus} onClick={() => setCreate(true)}>Add</Btn></div>
      </div>
      {!cur && <Tabs tabs={[{ id: 'overview', label: t('Vaults'), icon: KeyRound }, { id: 'browser', label: t('Browser'), icon: Puzzle }, { id: 'settings', label: t('Settings'), icon: Settings2 }]} value={view === 'einstellungen' ? 'settings' : view} onChange={(x) => { location.hash = x === 'overview' ? BASE : `${BASE}/_/${x}`; }} />}
      {cur && <VaultView key={cur.id + cur.locked} v={cur} data={data} reload={d.reload} initialTab={tab} onCfg={() => setCfg(cur)} />}
      {!cur && view === 'overview' && (data.instances.length === 0 ? <Empty icon={KeyRound} title="No password manager yet" text="Create a Hostwerk vault or connect Bitwarden, 1Password, KeePass & co. Google, Apple, Proton and others without an interface come by import."><Btn className="primary" icon={Plus} onClick={() => setCreate(true)}>Add</Btn></Empty> : (
        <div className="grid grid-3">{favSort('pw', data.instances).map((v) => <a key={v.id} className={`card svc-card ${v.locked ? '' : 'running'}`} href={`#${BASE}/${v.id}`} onContextMenu={(e) => contextMenu(e, [
          { label: t('Open'), icon: KeyRound, onClick: () => { location.hash = `${BASE}/${v.id}`; } },
          favMenuItem('pw', v.id),
          !v.locked && { label: t('Lock'), icon: Lock, onClick: () => post(`/pw/${v.id}/lock`).then(d.reload).catch((er) => toast.error(er.message)) },
          !v.locked && { label: t('Security check'), icon: ShieldCheck, onClick: () => { location.hash = `${BASE}/${v.id}/audit`; } },
          !v.locked && { label: t('Import / export'), icon: Upload, onClick: () => { location.hash = `${BASE}/${v.id}/io`; } },
          !v.default && { label: t('Make default vault'), icon: Star, onClick: () => put('/pw', { defaultId: v.id }).then(d.reload) },
          { label: t('Rename'), icon: RefreshCw, onClick: () => rename(v) },
          { label: v.type === 'hostwerk' ? t('Master password') : t('Access'), icon: Settings2, onClick: () => setCfg(v) },
          '-',
          { label: t('Remove …'), icon: Trash2, danger: true, onClick: () => removeVault(v, d.reload) },
        ])}><div className="card-body row" style={{ gap: 12 }}><SvcImage kind="pw" id={v.id} name={v.name} className="svc-icon" fallback={<div className="svc-icon pw"><KeyRound /></div>} /><FavMark kind="pw" id={v.id} /><div className="grow" style={{ minWidth: 0 }}><div className="bold ellipsis">{v.name}{v.default && <Star size={11} className="c-warn" style={{ marginLeft: 4 }} aria-label={t('Default vault')} />}</div><div className="tiny muted">{v.label} · {v.locked ? t('locked') : t('unlocked')}{v.audit ? ` · ${t('security {score}/100', { score: v.audit.score })}` : ''}</div></div>{v.locked ? <Lock size={16} className="muted" aria-label={t('locked')} /> : <Unlock size={16} className="c-ok" aria-label={t('unlocked')} />}</div></a>)}</div>
      ))}
      {!cur && view === 'browser' && !HAS_DESKTOP && <InfoTip pop={false} title="Browser extension">The extension only talks to a Hostwerk on the same machine (127.0.0.1). This server has no screen interface – use Hostwerk on your PC for it, or open Passwords here in the web interface.</InfoTip>}
      {!cur && view === 'browser' && HAS_DESKTOP && <div className="grid split-side"><ExtensionCard data={data} reload={d.reload} /><InfoTip><b>{t('How does Hostwerk install it?')}</b> {t('If the extension is in the browser’s store, Hostwerk tells the browser about it the official way and opens the store page – one click on “Add”. Otherwise the browser loads it as an “unpacked extension” (developer mode). Either way it pairs itself, without a code.')}</InfoTip></div>}
      {!cur && (view === 'settings' || view === 'einstellungen') && <SettingsView data={data} reload={d.reload} rename={rename} setCfg={setCfg} />}
      {create && <CreateDialog data={data} onClose={() => setCreate(false)} onDone={(r, imp) => { setCreate(false); d.reload(); if (r && r.id) location.hash = `${BASE}/${r.id}${imp ? '/io' : ''}`; }} />}
      {cfg && <CfgDialog v={cfg} data={data} onClose={() => setCfg(null)} onDone={() => { setCfg(null); d.reload(); }} />}
    </div>
  );
}

/** Einstellungs-Gruppen: links die Liste (Pfeiltasten wechseln), rechts genau eine Gruppe – gemerkt je Rechner. */
const SET_GROUPS = [
  { id: 'lock', label: 'Locking', icon: Lock },
  { id: 'fill', label: 'Filling in', icon: Puzzle },
  { id: 'general', label: 'General', icon: Settings2 },
  { id: 'vaults', label: 'Vaults', icon: KeyRound },
  { id: 'providers', label: 'Provider programs', icon: Terminal },
  { id: 'generator', label: 'Generator', icon: Wand2 },
];
function SettingsView({ data, reload, rename, setCfg }) {
  const [g, setGRaw] = useState(() => { try { return localStorage.getItem('pw:settings') || 'lock'; } catch { return 'lock'; } });
  const setG = (v) => { setGRaw(v); try { localStorage.setItem('pw:settings', v); } catch { /* egal */ } };
  const keys = (e) => {
    const i = SET_GROUPS.findIndex((x) => x.id === g);
    const n = e.key === 'ArrowDown' ? i + 1 : e.key === 'ArrowUp' ? i - 1 : null;
    if (n == null || !SET_GROUPS[n]) return;
    e.preventDefault(); setG(SET_GROUPS[n].id);
    const el = e.currentTarget.querySelector(`[data-group="${SET_GROUPS[n].id}"]`); if (el) el.focus();
  };
  const cur = SET_GROUPS.find((x) => x.id === g) || SET_GROUPS[0];
  const af = data.autofill || {};
  const body = (
      <div className="stack pw-set-body">
        {cur.id === 'lock' && <div className="card"><div className="card-head"><Lock size={16} /><h3>Locking</h3></div><div className="card-body stack">
          <SettingRow title="Lock automatically" text="Lock Hostwerk vaults again after being idle (minutes, 0 = never)."><input className="input sm pw-num" type="number" min={0} max={240} aria-label={t('Minutes')} defaultValue={data.autoLockMin} onBlur={(e) => put('/pw', { autoLockMin: Number(e.target.value) })} /></SettingRow>
          <SettingRow title="Clear the clipboard" text="Copied passwords and codes are removed from the clipboard again after this many seconds (0 = never)."><input className="input sm pw-num" type="number" min={0} max={600} aria-label={t('Seconds')} defaultValue={data.clipboardSec ?? 30} onBlur={(e) => put('/pw', { clipboardSec: Number(e.target.value) }).then(reload)} /></SettingRow>
        </div></div>}
        {cur.id === 'fill' && <div className="card"><div className="card-head"><Puzzle size={16} /><h3>Filling in</h3></div><div className="card-body stack">
          <SettingRow title="Suggestions in the sign-in field" text="When you click into a sign-in field, the extension shows fitting logins right below – one click fills them in."><Switch checked={af.inline !== false} onChange={(v) => put('/pw', { autofill: { inline: v } }).then(reload)} /></SettingRow>
          <SettingRow title="Fill in on load" text="If exactly one login fits, it is already in the form when the page opens (without sending it)."><Switch checked={af.onLoad === true} onChange={(v) => put('/pw', { autofill: { onLoad: v } }).then(reload)} /></SettingRow>
          <SettingRow title="Auto sign-in in the browser" text="If exactly one login fits a sign-in page, the extension fills it in and signs you in right away. Off by default."><Switch checked={!!data.autoLogin} onChange={(v) => put('/pw', { autoLogin: v }).then(reload)} /></SettingRow>
          <SettingRow title="Suggest strong passwords" text="When you sign up or change a password, the extension suggests a strong password."><Switch checked={af.suggest !== false} onChange={(v) => put('/pw', { autofill: { suggest: v } }).then(reload)} /></SettingRow>
          <SettingRow title="Offer to save new logins" text="After a sign-in with an unknown login a 1 appears on the Hostwerk icon – save it in the popup."><Switch checked={af.offerSave !== false} onChange={(v) => put('/pw', { autofill: { offerSave: v } }).then(reload)} /></SettingRow>
        </div></div>}
        {cur.id === 'general' && <div className="card"><div className="card-head"><Settings2 size={16} /><h3>General</h3></div><div className="card-body stack">
          <SettingRow title="Default vault" text="New logins you save in the browser end up here."><select className="select sm" aria-label={t('Default vault')} value={data.defaultId || ''} onChange={(e) => put('/pw', { defaultId: e.target.value }).then(reload)}>{data.instances.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></SettingRow>
          <SettingRow title="Website icons" text="Shows the icon of each website in the list. Hostwerk loads it once from the site itself and keeps it on this PC."><Switch checked={data.icons !== false} onChange={(v) => put('/pw', { icons: v }).then(reload)} /></SettingRow>
          <SettingRow title="Leak check (Have I Been Pwned)" text="In the security check only the first 5 characters of the password hash are sent (k-anonymity)."><Switch checked={data.hibp} onChange={(v) => put('/pw', { hibp: v }).then(reload)} /></SettingRow>
        </div></div>}
        {cur.id === 'vaults' && <div className="card"><div className="card-head"><KeyRound size={16} /><h3>Manage vaults</h3><span className="badge">{data.instances.length}</span></div>{data.instances.length ? data.instances.map((v) => <div key={v.id} className="list-item"><div className="grow small"><b>{v.name}</b> <span className="muted">{v.label}</span></div><Btn className="xs ghost" onClick={() => rename(v)}>Rename</Btn>{v.type === 'hostwerk' ? <Btn className="xs ghost" onClick={() => setCfg(v)}>Master password</Btn> : <Btn className="xs ghost" onClick={() => setCfg(v)}>Access</Btn>}<button type="button" className="btn ghost xs icon" title={t('Remove …')} aria-label={t('Remove …')} onClick={() => removeVault(v, reload)}><Trash2 /></button></div>) : <TileEmpty icon={KeyRound} text={t('No vault yet')} />}</div>}
        {cur.id === 'providers' && <><CliCard data={data} reload={reload} /><InfoTip><b>{t('No maintenance:')}</b> {t('provider programs are checked every day and updated with a test run, new import formats and services come through the online catalogue.')} <b>{t('The AI helper has no access at all')}</b> {t('to vaults, items or vault files – neither reading nor searching.')}</InfoTip></>}
        {cur.id === 'generator' && <GenRules />}
      </div>
  );
  // Neuere Hostwerk-Versionen bringen das Einstellungs-Layout mit linker Navigation selbst mit – dann dieses, sonst das eigene
  if (HUI.SettingsLayout) {
    return <HUI.SettingsLayout groups={SET_GROUPS.map((x) => ({ id: x.id, label: t(x.label), icon: x.icon }))} value={cur.id} onChange={setG} label={t('Settings')}>{body}</HUI.SettingsLayout>;
  }
  return (
    <div className="pw-set">
      <nav className="card pw-set-nav" aria-label={t('Settings')}>
        <ul onKeyDown={keys}>
          {SET_GROUPS.map((x) => (
            <li key={x.id}><button type="button" data-group={x.id} className={`pw-set-item ${x.id === cur.id ? 'on' : ''}`} aria-current={x.id === cur.id ? 'true' : undefined} tabIndex={x.id === cur.id ? 0 : -1} onClick={() => setG(x.id)}><x.icon size={15} aria-hidden="true" />{t(x.label)}</button></li>
          ))}
        </ul>
      </nav>
      {body}
    </div>
  );
}

function CfgDialog({ v, data, onClose, onDone }) {
  const P = data.providers.find((p) => p.id === v.type);
  const [f, setF] = useState({ old: '', pw: '', pw2: '', cfg: { ...(v.cfg || {}) } });
  const save = async () => {
    try {
      if (v.type === 'hostwerk') { if (f.pw !== f.pw2) return toast.error(t('The passwords do not match')); await post(`/pw/${v.id}/password`, { oldPassword: f.old, newPassword: f.pw }); toast.success(t('Master password changed')); }
      else { await put(`/pw/${v.id}`, { cfg: f.cfg }); toast.success(t('Saved')); }
      onDone();
    } catch (e) { toast.error(e.message); }
    return undefined;
  };
  return (
    <Modal title={v.type === 'hostwerk' ? t('Change master password') : t('{name}: access', { name: v.name })} onClose={onClose} footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" onClick={save}>Save</Btn></>}>
      <div className="stack">
        {v.type === 'hostwerk' ? <><Field label="Current master password"><input className="input" type="password" value={f.old} onChange={(e) => setF({ ...f, old: e.target.value })} /></Field><Field label="New"><input className="input" type="password" value={f.pw} onChange={(e) => setF({ ...f, pw: e.target.value })} /></Field><Field label="Repeat"><input className="input" type="password" value={f.pw2} onChange={(e) => setF({ ...f, pw2: e.target.value })} /></Field></>
          : P && P.fields.map(([k, l, kind]) => <Field key={k} label={t(l)}>{(kind === 'path' ? <PathInput value={f.cfg[k] || ''} onChange={(x) => setF({ ...f, cfg: { ...f.cfg, [k]: x } })} mode={k === 'store' ? 'folder' : 'file'} filters={k === 'file' ? KEEPASS_FILTER() : undefined} title={t(l)} placeholder={k === 'file' ? 'Passwords.kdbx' : ''} /> : <input className="input" type={kind === 'password' ? 'password' : 'text'} value={f.cfg[k] || ''} placeholder={kind === 'password' && v.cfg[k] === '••••' ? t('stored – type to change it') : ''} onChange={(e) => setF({ ...f, cfg: { ...f.cfg, [k]: e.target.value } })} />)}</Field>)}
      </div>
    </Modal>
  );
}

/**
 * Kachel „Sicherheitsprüfung“ (Übersicht): Ergebnis der letzten Prüfung des Standard-Tresors – schwache, mehrfach
 * genutzte und geleakte Passwörter. „Jetzt prüfen“ startet die Prüfung (mit Leak-Abgleich, falls eingeschaltet).
 */
function SecurityTile() {
  const d = useApi('/pw', [], { live: false });
  const vault = d.data && (d.data.instances.find((x) => x.default) || d.data.instances[0]);
  const last = useApi(vault ? `/pw/${vault.id}/audit` : null, [vault && vault.id], { live: false });
  const [busy, setBusy] = useState(false);
  if (d.error && !d.data) return <TileEmpty icon={ShieldCheck} text={t('Could not load the vaults')} action={t('Try again')} onClick={() => d.reload()} />;
  if (!d.data) return <div className="card-body"><Loading /></div>;
  if (!vault) return <TileEmpty icon={KeyRound} text={t('No vault yet')} action={t('Create vault')} href="#/ext/passwords" />;
  const open = `#/ext/passwords/${encodeURIComponent(vault.id)}/audit`;
  if (vault.locked) return <TileEmpty icon={Lock} text={t('“{name}” is locked – unlock it to check.', { name: vault.name })} action={t('Unlock')} href={open} />;
  const r = last.data && last.data.last;
  const check = async () => { setBusy(true); try { const x = await post(`/pw/${vault.id}/audit`); last.setData({ ...(last.data || {}), last: x }); } catch (e) { toast.error(e); } setBusy(false); };
  if (!r) return <TileEmpty icon={ShieldCheck} text={t('Not checked yet')} action={t('Check now')} onClick={check} />;
  const bad = r.counts.weak + r.counts.reused + r.counts.leaked;
  return (
    <div className="card-body stack pw-tile">
      <div className="row-tight"><span className={`pw-tile-score ${r.score >= 90 ? 'c-ok' : r.score >= 60 ? 'c-warn' : 'c-err'}`}>{r.score}</span><span className="small muted grow">{t('of 100 · {name}', { name: vault.name })}</span></div>
      <div className="row-tight pw-tile-counts">
        <span className={`badge ${r.counts.leaked ? 'err' : ''}`}>{t('{n} leaked', { n: r.counts.leaked })}</span>
        <span className={`badge ${r.counts.weak ? 'warn' : ''}`}>{t('{n} weak', { n: r.counts.weak })}</span>
        <span className={`badge ${r.counts.reused ? 'warn' : ''}`}>{t('{n} reused', { n: r.counts.reused })}</span>
      </div>
      <div className="row-tight"><span className="tiny muted grow">{bad ? t('Checked {when}', { when: fmtDate(r.at) }) : t('All good – checked {when}', { when: fmtDate(r.at) })}</span><Btn className="xs" icon={RefreshCw} busy={busy} onClick={check}>Check now</Btn><a className="btn xs" href={open}>Details</a></div>
    </div>
  );
}

export default {
  pages: { main: PasswordsPage },
  slots: {
    'dashboard.tiles': [{ id: 'security', title: 'Password check', icon: ShieldCheck, size: 'third', Component: SecurityTile }],
  },
};
