import { useEffect, useState, useRef } from 'react';
import { KeyRound, Lock, Unlock, Plus, Star, Trash2, Copy, RefreshCw, ShieldCheck, Upload, Download, Puzzle, Settings2, Link2, EyeOff } from 'lucide-react';
import { get, post, put, del, useApi, on, waitJob, fmtDate, HAS_DESKTOP } from '@hostwerk/api';
import { Btn, Tabs, Field, Switch, SettingRow, Seg, Empty, Loading, Callout, Modal, toast, promptDialog, InfoTip, PathInput, TileEmpty } from '@hostwerk/ui';
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
    try { const r = await post('/pw', { type: own ? 'hostwerk' : type, name: f.name || (type === 'import' ? t('Imported vault') : ''), password: f.password, cfg: f.cfg }); toast.success(t('{name} created', { name: r.name })); onDone(r, type === 'import'); } catch (e) { toast.error(e.message); }
    setBusy(false);
    return undefined;
  };
  const cliOk = !P || !P.cli || (data.cli && data.cli[P.cli] && data.cli[P.cli].installed);
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
          {P && P.cli && !cliOk && <div className="span-2"><Callout kind="warn" dismissible={false}>{t('The program “{cli}” is not downloaded yet – download it under “Provider programs” (Hostwerk checks it with a test run).', { cli: P.cli })}</Callout></div>}
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

function ExtensionCard({ data, reload }) {
  const [code, setCode] = useState(null);
  const [left, setLeft] = useState(0);
  const det = useApi('/pw/browsers', [], { live: false });
  const found = det.data || [];
  const [browser, setBrowserRaw] = useState(null);
  const pickedOnce = useRef(false);
  useEffect(() => { if (!pickedOnce.current && det.data) { pickedOnce.current = true; if (found[0] && BROWSERS.some((b) => b.id === found[0].id)) setBrowserRaw(found[0].id); else setBrowserRaw('chrome'); } }, [det.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const setBrowser = (b) => { pickedOnce.current = true; setBrowserRaw(b); };
  const browserOpts = [...BROWSERS].sort((a, b) => Number(found.some((f) => f.id === b.id)) - Number(found.some((f) => f.id === a.id)))
    .map((b) => { const f = found.find((x) => x.id === b.id); return { id: b.id, label: <span className={`br-opt ${f ? 'have' : 'miss'}`}><span className="br-dot" style={{ '--br': BROWSER_COLORS[b.id] }} />{b.label}{f && f.default ? <span className="br-def">{t('Default')}</span> : null}</span> }; });
  const [inst, setInst] = useState(null);
  const [busy, setBusy] = useState(false);
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
    try { const r = await post('/pw/extension/install', { browser }); setInst(r); if (r.opened) toast.success(r.mode === 'dev' ? t('Extension page opened in {label}', { label }) : t('{label} opened – click “Add” there', { label })); else toast.warn(t('{label} could not be opened – the steps below still apply', { label })); } catch (e) { toast.error(e.message); }
    setBusy(false);
  };
  const mode = inst ? inst.mode : null;
  const steps = inst ? extSteps({ mode, fx, label, registered: inst.registered }) : [];
  // After installing, wait until the extension pairs itself (one-time ticket in the folder)
  const [linked, setLinked] = useState(null);
  useEffect(() => {
    if (!inst || !inst.autoPair || linked) return undefined;
    const x = setInterval(async () => { try { const r = await get(`/pw/ext/paired-since?t=${inst.since}`); if (r.paired) { setLinked(r.name); reload(); toast.success(t('{name} is connected to Hostwerk', { name: r.name })); } } catch { /* ignore */ } }, 2000);
    return () => clearInterval(x);
  }, [inst, linked]); // eslint-disable-line react-hooks/exhaustive-deps
  const mm = Math.floor(left / 60); const ss = String(left % 60).padStart(2, '0');
  return (
    <div className="card">
      <div className="card-head"><Puzzle size={16} /><h3>Browser extension</h3><InfoTip>{t('The extension only talks to your Hostwerk (127.0.0.1).')}</InfoTip></div>
      <div className="card-body stack" style={{ gap: 12 }}>
        <div className="row" style={{ gap: 10, flexWrap: 'wrap', alignItems: 'center' }}><span className="small bold">{t('Browser')}</span>{browser ? <Seg value={browser} onChange={(b) => { setBrowser(b); setInst(null); setLinked(null); }} options={browserOpts} /> : <span className="small muted">{t('Looking for browsers …')}</span>}{det.data && <span className="tiny muted">{found.length ? t('{n} found on this PC – marked in colour', { n: found.length }) : t('No browser found – choose yours.')}</span>}</div>
        <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
          <Btn className="primary sm" icon={Download} busy={busy} disabled={!browser} title={isFound ? '' : t('{label} was not found on this PC', { label })} onClick={install}>{t('Install in {label}', { label })}</Btn>
          <a className="btn sm" href={`/api/pw/extension/${browser}`}><Download />{fx ? t('Download .xpi') : t('Download ZIP')}</a>
        </div>
        {inst && linked ? (
          <ExtLinked name={linked} browser={label} />
        ) : inst ? (
          <div className="stack" style={{ gap: 8 }}>
            <div className="small bold">{inst.opened ? t('{label} is open – this is how it goes on', { label }) : t('The extension is ready')}</div>
            {mode === 'dev' && <div className="row-tight small" style={{ margin: '4px 0 6px' }}><span className="muted">{fx ? t('File') : t('Folder')}</span><code className="ellipsis" style={{ maxWidth: 420 }}>{inst.dir || inst.file}</code><button className="btn ghost xs icon" title="Copy path" aria-label={t('Copy path')} onClick={() => copyText(inst.dir || inst.file)}><Copy /></button>{!inst.opened && inst.url && <span className="tiny muted">{t('→ open {url} in the browser', { url: inst.url })}</span>}</div>}
            {mode === 'store' && !inst.opened && inst.page && <a className="btn sm" href={inst.page} target="_blank" rel="noreferrer">{t('Open the store page')}</a>}
            <ExtGuide steps={steps} waiting={!!inst.autoPair} />
            {inst.autoPair && <div className="row-tight tiny muted" style={{ marginTop: 6 }}><RefreshCw size={12} className="spin" />{t('Waiting for the extension – once it is loaded it connects by itself.')}</div>}
            {mode === 'dev' && <div className="tiny muted">{t('The browsers themselves ask for developer mode – they only install extensions from their store silently.')}</div>}
          </div>
        ) : browser ? <div className="stack" style={{ gap: 8 }}><div className="small muted">{t('This is how it goes – “Install in {label}” does the start:', { label })}</div><ExtGuide steps={extSteps({ mode: null, fx, label })} /></div> : null}
        <div className="stack" style={{ gap: 6 }}>
          <div className="row-tight"><Btn className="sm" icon={code ? RefreshCw : KeyRound} onClick={newCode}>{code ? t('New pairing code') : t('Show pairing code')}</Btn>{code && <Btn className="sm ghost" icon={EyeOff} onClick={() => setCode(null)}>Hide</Btn>}</div>
          {code && (
            <div className="pw-code">
              <b>{code.code}</b>
              <div className="grow small muted">{t('Port {port} · valid for', { port: code.port })} <b className={left < 60 ? 'c-warn' : ''}>{mm}:{ss}</b> · {t('enter it in the extension’s popup')}<div className="progress" style={{ marginTop: 6 }}><div style={{ width: `${(left / (code.expiresIn || 600)) * 100}%` }} /></div></div>
              <button className="btn ghost xs icon" title="Copy code" aria-label={t('Copy code')} onClick={() => copyText(code.code)}><Copy /></button>
            </div>
          )}
        </div>
        <div className="tiny muted">{t('In the browser: click the icon for matches of the page, search and the generator; Ctrl+Shift+L fills in the first match; after a sign-in the extension offers to save it. Load updates again here – Hostwerk reports them under self-maintenance.')}</div>
        {data.ext.length > 0 && <div className="stack" style={{ gap: 6 }}><div className="small bold">{t('Paired browsers')}</div><div className="pw-ext-list">{data.ext.map((e, i) => { const id = browserId(e.browser, e.name); const active = e.lastUse && Date.now() - e.lastUse < 10 * 60000; return <div key={e.id} className="pw-ext-row" style={{ animationDelay: `${i * 40}ms` }}><BrowserMark id={id} /><span className="grow small">{e.name} <span className="muted tiny">{e.browser ? e.browser.replace(/\/[\d.]+$/, '') + ' · ' : ''}{t('paired {date}', { date: fmtDate(e.created) })}{e.lastUse ? ` · ${t('last {date}', { date: fmtDate(e.lastUse) })}` : ''}</span></span>{active && <span className="live" title={t('Used in the last 10 minutes')} />}<button className="btn ghost xs icon" title="Remove pairing" aria-label={t('Remove pairing')} onClick={async () => { await del(`/pw/ext/${e.id}`); reload(); }}><Trash2 /></button></div>; })}</div></div>}
      </div>
    </div>
  );
}

function CliCard({ data, reload }) {
  const [st, setSt] = useState(data.cli || null);
  const [busy, setBusy] = useState(null);
  useEffect(() => { get('/pw/cli').then(setSt).catch(() => {}); }, []);
  const inst = async (n) => { setBusy(n); try { const r = await post(`/pw/cli/${n}/install`); const j = await waitJob(r.job); toast.success(t('{n} {v} downloaded and checked', { n, v: j.result.version })); setSt(await get('/pw/cli')); reload(); } catch (e) { toast.error(e.message); } setBusy(null); };
  return (
    <div className="card">
      <div className="card-head"><Settings2 size={16} /><h3>Provider programs</h3><InfoTip>{t('Self-maintenance: version check every day, update with a test run.')}</InfoTip></div>
      {!st ? <Loading /> : [['bw', 'Bitwarden CLI (bw)', 'for Bitwarden and Vaultwarden'], ['op', '1Password CLI (op)', 'for 1Password with a service account']].map(([n, l, x]) => <div key={n} className="list-item"><div className="ico"><Link2 /></div><div className="grow small"><b>{l}</b> <span className="muted">{t(x)}</span><div className="tiny muted">{st[n] && st[n].installed ? t('installed {v}', { v: st[n].version || '' }) : t('not installed')}{st[n] && st[n].latest ? ` · ${t('current {v}', { v: st[n].latest })}` : ''}</div></div><Btn className="xs" icon={Download} busy={busy === n} onClick={() => inst(n)}>{st[n] && st[n].installed ? t('Update') : t('Download')}</Btn></div>)}
      {st && st.kdbxweb && <div className="card-body tiny muted">{t('KeePass library kdbxweb {v}', { v: st.kdbxweb.version })}{st.kdbxweb.latest && st.kdbxweb.latest !== st.kdbxweb.version ? ` ${t('(npm: {v} – comes with the next Hostwerk update)', { v: st.kdbxweb.latest })}` : ''} · {t('leak check through pwnedpasswords.com')}{data.catalog && data.catalog.updated ? ` · ${t('catalogue from {date}', { date: data.catalog.updated })}` : ''}</div>}
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
      {!cur && (view === 'settings' || view === 'einstellungen') && (
        <div className="grid grid-2">
          <div className="stack">
            <div className="card"><div className="card-head"><Settings2 size={16} /><h3>Behaviour</h3></div><div className="card-body stack">
              <SettingRow title="Lock automatically" text="Lock Hostwerk vaults again after being idle (minutes, 0 = never)."><input className="input sm" type="number" min={0} max={240} style={{ width: 80 }} aria-label={t('Minutes')} defaultValue={data.autoLockMin} onBlur={(e) => put('/pw', { autoLockMin: Number(e.target.value) })} /></SettingRow>
              <SettingRow title="Auto sign-in in the browser" text="If exactly one login fits a sign-in page, the extension fills it in and signs you in right away. Off by default."><Switch checked={!!data.autoLogin} onChange={(v) => put('/pw', { autoLogin: v }).then(d.reload)} /></SettingRow>
              <SettingRow title="Suggestions in the sign-in field" text="When you click into a sign-in field, the extension shows fitting logins right below – one click fills them in."><Switch checked={(data.autofill || {}).inline !== false} onChange={(v) => put('/pw', { autofill: { inline: v } }).then(d.reload)} /></SettingRow>
              <SettingRow title="Fill in on load" text="If exactly one login fits, it is already in the form when the page opens (without sending it)."><Switch checked={(data.autofill || {}).onLoad === true} onChange={(v) => put('/pw', { autofill: { onLoad: v } }).then(d.reload)} /></SettingRow>
              <SettingRow title="Suggest strong passwords" text="When you sign up or change a password, the extension suggests a strong password."><Switch checked={(data.autofill || {}).suggest !== false} onChange={(v) => put('/pw', { autofill: { suggest: v } }).then(d.reload)} /></SettingRow>
              <SettingRow title="Offer to save new logins" text="After a sign-in with an unknown login a 1 appears on the Hostwerk icon – save it in the popup."><Switch checked={(data.autofill || {}).offerSave !== false} onChange={(v) => put('/pw', { autofill: { offerSave: v } }).then(d.reload)} /></SettingRow>
              <SettingRow title="Leak check (Have I Been Pwned)" text="In the security check only the first 5 characters of the password hash are sent (k-anonymity)."><Switch checked={data.hibp} onChange={(v) => put('/pw', { hibp: v }).then(d.reload)} /></SettingRow>
              <SettingRow title="Default vault" text="New logins you save in the browser end up here."><select className="select sm" aria-label={t('Default vault')} value={data.defaultId || ''} onChange={(e) => put('/pw', { defaultId: e.target.value }).then(d.reload)}>{data.instances.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}</select></SettingRow>
            </div></div>
            <div className="card"><div className="card-head"><Trash2 size={16} /><h3>Manage vaults</h3></div>{data.instances.map((v) => <div key={v.id} className="list-item"><div className="grow small"><b>{v.name}</b> <span className="muted">{v.label}</span></div><Btn className="xs ghost" onClick={() => rename(v)}>Rename</Btn>{v.type === 'hostwerk' ? <Btn className="xs ghost" onClick={() => setCfg(v)}>Master password</Btn> : <Btn className="xs ghost" onClick={() => setCfg(v)}>Access</Btn>}<button className="btn ghost xs icon" title="Remove …" aria-label={t('Remove …')} onClick={() => removeVault(v, d.reload)}><Trash2 /></button></div>)}</div>
          </div>
          <div className="stack"><CliCard data={data} reload={d.reload} /><InfoTip><b>{t('No maintenance:')}</b> {t('provider programs are checked every day and updated with a test run, new import formats and services come through the online catalogue.')} <b>{t('The AI helper has no access at all')}</b> {t('to vaults, items or vault files – neither reading nor searching.')}</InfoTip></div>
        </div>
      )}
      {create && <CreateDialog data={data} onClose={() => setCreate(false)} onDone={(r, imp) => { setCreate(false); d.reload(); if (r && r.id) location.hash = `${BASE}/${r.id}${imp ? '/io' : ''}`; }} />}
      {cfg && <CfgDialog v={cfg} data={data} onClose={() => setCfg(null)} onDone={() => { setCfg(null); d.reload(); }} />}
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
  if (!vault) return <TileEmpty icon={KeyRound} text={t('No vault yet')} action={t('Create vault')} href="#/passwoerter" />;
  const open = `#/passwoerter/${encodeURIComponent(vault.id)}/audit`;
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
