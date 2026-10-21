import { useEffect, useMemo, useRef, useState } from 'react';
import { KeyRound, Lock, Unlock, Plus, Search, Star, Trash2, ShieldCheck, Upload, Globe, Folder, StickyNote, CreditCard, User, Wand2, AlertTriangle, XCircle, CheckCircle2, Info, ArrowRightLeft, Settings2, Link2, KeySquare, Fingerprint, Paperclip, Tag, RotateCcw, Keyboard } from 'lucide-react';
import { get, post, on, fmtDate, waitJob } from '@hostwerk/api';
import { Btn, Empty, Loading, Callout, toast, InfoTip } from '@hostwerk/ui';
import { SvcImage, AiHint } from '@hostwerk/kit';
import { t } from '@hostwerk/i18n';
import { ItemView, ItemDialog, Generator, SiteIcon, StrengthDot, TYPE_LABEL, copy, clip } from './Item';
import { ImportExport } from './IO';

export { clearLater, Generator } from './Item';

/*
 * Ein Tresor: gesperrt → Entsperren/Verbinden (Anbieter-Programme lädt Hostwerk dabei selbst), entsperrt → klassisches
 * Drei-Spalten-Layout guter Passwort-Manager: Navigation (Arten, Favoriten, Ordner, Schlagwörter, Papierkorb, Werkzeuge),
 * Liste (Symbol, Name, Benutzer, Stärke-Punkt) und Detail. Tastatur: Strg+F sucht, ↑/↓ wählt, Strg+C kopiert das
 * Passwort, Strg+Umschalt+C den Benutzernamen. Schmale Fenster zeigen Liste und Detail nacheinander.
 */

/* Required data per provider – without it "Connect" is not offered at all, only "Enter access". */
export const REQUIRED = { onepassword: ['token'], keepass: ['file'], bitwarden: ['email'], lastpass: ['email'], pass: [] };
export const fieldLabel = (P, k) => t((P && (P.fields.find((f) => f[0] === k) || [])[1]) || k);
const PRODUCT = { bw: 'Bitwarden', op: '1Password' };

/** Locked vault / provider not connected yet. Missing provider programs are loaded right here with one click. */
function Locked({ v, data, reload, onCfg }) {
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(null);
  const [problem, setProblem] = useState(null); // { code, message, hint }
  const P = data.providers.find((p) => p.id === v.type);
  const cli = v.cli || (P && P.cli) || null;
  const cs = cli && data.cli ? data.cli[cli] : null;
  const missing = (REQUIRED[v.type] || []).filter((k) => !v.cfg || !v.cfg[k]);
  const stored = v.cfg && v.cfg.password;
  const needsPw = v.type === 'hostwerk' || (['bitwarden', 'keepass', 'lastpass'].includes(v.type) && !stored);
  const product = PRODUCT[cli] || (P && P.label) || v.label;
  const loadCli = async () => {
    setBusy('cli');
    try { const r = await post(`/pw/cli/${cli}/install`); await waitJob(r.job); reload(); return true; } catch (e) { setProblem({ code: e.code, message: e.message, hint: e.hint }); return false; } finally { setBusy(null); }
  };
  const connect = async () => {
    setProblem(null);
    if (cli && cs && !cs.installed && !(await loadCli())) return;
    setBusy('unlock');
    try { await post(`/pw/${v.id}/unlock`, { password: pw }); setPw(''); reload(); } catch (e) {
      if (e.code === 'PW_CLI_MISSING' && cli && (await loadCli())) { try { await post(`/pw/${v.id}/unlock`, { password: pw }); setPw(''); reload(); } catch (e2) { toast.error(e2.message); } } else if (e.code && /^PW_/.test(e.code)) setProblem({ code: e.code, message: e.message, hint: e.hint }); else toast.error(e.message);
    }
    setBusy(null);
  };
  const label = v.type === 'hostwerk' ? t('Unlock') : cli && cs && !cs.installed ? t('Connect {product}', { product }) : t('Connect');
  return (
    <div className="card pw-locked"><div className="card-body stack">
      <div className="row-tight"><SvcImage kind="pw" id={v.id} name={v.name} size={30} className="svc-icon" fallback={<Lock size={18} />} /><b>{v.name}</b><span className="badge">{v.label}</span></div>
      {missing.length > 0 ? <>
        <div className="small">{t('To connect, this is still missing:')} <b>{missing.map((k) => fieldLabel(P, k)).join(', ')}</b> {P && P.hint ? <InfoTip>{t(P.hint)}</InfoTip> : null}</div>
        <div><Btn className="primary" icon={Settings2} onClick={onCfg}>Enter access</Btn></div>
      </> : <>
        {needsPw && <div className="small muted">{v.type === 'hostwerk' ? t('Enter the master password to unlock the vault.') : t('Enter the provider’s master password – Hostwerk does not remember it (to store it: “Access”).')}</div>}
        <form className="row-tight" onSubmit={(e) => { e.preventDefault(); connect(); }}>
          {needsPw && <input className="input grow" type="password" autoComplete="current-password" aria-label={t('Master password')} placeholder={t('Master password')} value={pw} onChange={(e) => setPw(e.target.value)} autoFocus />}
          <Btn className="primary" icon={v.type === 'hostwerk' ? Unlock : Link2} busy={!!busy} type="submit">{label}</Btn>
          {v.type !== 'hostwerk' && <Btn className="ghost" icon={Settings2} title={t('Access')} aria-label={t('Access')} onClick={onCfg} />}
        </form>
        {busy === 'cli' && <div className="small muted" role="status">{t('Hostwerk is loading the official {product} program and checks its signature …', { product })}</div>}
        {cli && cs && !cs.installed && !busy && !problem && <div className="tiny muted">{t('{product} only lets other programs in through its official program “{cli}” – Hostwerk loads it once and keeps it up to date.', { product, cli })}</div>}
      </>}
      {problem && <Callout kind={problem.code === 'PW_CLI_BLOCKED' ? 'warn' : 'error'} dismissible={false}><div className="stack pw-gap-1"><span>{problem.message}</span>{problem.hint && <span className="tiny muted">{problem.hint}</span>}<div className="row-tight">{cli && <Btn className="xs" icon={RotateCcw} onClick={connect}>Try again</Btn>}<a className="btn xs ghost" href={`#/ext/passwords/${v.id}/io`}>{t('Import an export file instead')}</a></div></div></Callout>}
    </div></div>
  );
}

/* Navigation: Arten, Favoriten, Ordner, Schlagwörter, Papierkorb; Werkzeuge darunter */
const KINDS = [
  { key: 'all', label: 'All items', icon: KeyRound, q: {} },
  { key: 'fav', label: 'Favourites', icon: Star, q: { fav: 1 }, n: 'fav' },
  { key: 'login', label: 'Logins', icon: Globe, q: { type: 'login' }, n: 'login' },
  { key: 'note', label: 'Notes', icon: StickyNote, q: { type: 'note' }, n: 'note' },
  { key: 'card', label: 'Cards', icon: CreditCard, q: { type: 'card' }, n: 'card' },
  { key: 'identity', label: 'Identities', icon: User, q: { type: 'identity' }, n: 'identity' },
  { key: 'ssh', label: 'SSH keys', icon: KeySquare, q: { type: 'ssh' }, n: 'ssh' },
  { key: 'passkey', label: 'Passkeys', icon: Fingerprint, q: { has: 'passkey' }, n: 'passkey' },
  { key: 'files', label: 'Files', icon: Paperclip, q: { has: 'files' }, n: 'files' },
];
const TOOLS = [{ key: 'tool:audit', label: 'Security report', icon: ShieldCheck }, { key: 'tool:io', label: 'Import / export', icon: ArrowRightLeft }, { key: 'tool:generator', label: 'Generator', icon: Wand2 }];
const PRESET = { login: 'login', note: 'note', card: 'card', identity: 'identity', ssh: 'ssh' };

function queryFor(nav) {
  const k = KINDS.find((x) => x.key === nav);
  if (k) return k.q;
  if (nav.startsWith('folder:')) return { folder: nav.slice(7) };
  if (nav.startsWith('tag:')) return { tag: nav.slice(4) };
  if (nav === 'trash') return { trashed: 1 };
  return {};
}

export function VaultView({ v, data, reload, initialTab, onCfg }) {
  if (v.locked) return <Locked v={v} data={data} reload={reload} onCfg={onCfg} />;
  return <VaultApp v={v} data={data} reload={reload} initialTab={initialTab} />;
}

function VaultApp({ v, data, reload, initialTab }) {
  const [nav, setNav] = useState(['audit', 'io', 'generator'].includes(initialTab) ? `tool:${initialTab}` : 'all');
  const [q, setQ] = useState('');
  const [items, setItems] = useState(null);
  const [stats, setStats] = useState(null);
  const [sel, setSel] = useState(null);
  const [edit, setEdit] = useState(undefined); // undefined = zu, null = neu, Objekt = bearbeiten
  const [audit, setAudit] = useState(v.audit);
  const [busy, setBusy] = useState(null);
  const search = useRef(null);
  const list = useRef(null);
  const own = v.type === 'hostwerk';
  const tool = nav.startsWith('tool:') ? nav.slice(5) : null;
  clip.sec = data.clipboardSec ?? 30;
  const load = () => {
    if (tool) return;
    const params = new URLSearchParams(Object.entries({ q, ...queryFor(nav) }).filter(([, x]) => x !== '' && x != null).map(([k, x]) => [k, String(x)]));
    get(`/pw/${v.id}/items?${params}`).then(setItems).catch((e) => toast.error(e.message));
    get(`/pw/${v.id}/stats`).then(setStats).catch(() => {});
  };
  useEffect(() => { const x = setTimeout(load, q ? 180 : 0); return () => clearTimeout(x); }, [v.id, nav, q]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { setSel(null); }, [nav]);
  useEffect(() => on('passwords', (m) => { if (!m || !m.id || m.id === v.id) load(); }), [v.id, nav, q]); // eslint-disable-line react-hooks/exhaustive-deps

  // Tastatur: Strg+F Suche, ↑/↓ Auswahl, Strg+C Passwort, Strg+Umschalt+C Benutzer (nicht in Eingabefeldern/Dialogen)
  const selRef = useRef(sel); selRef.current = sel;
  const itemsRef = useRef(items); itemsRef.current = items;
  useEffect(() => {
    const onKey = async (e) => {
      if (tool || edit !== undefined) return;
      if (e.target.closest && e.target.closest('[role="dialog"], .modal')) return;
      const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) && e.target !== search.current;
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === 'f') { e.preventDefault(); search.current && search.current.focus(); search.current && search.current.select(); return; }
      const list2 = itemsRef.current || [];
      if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && !inField && list2.length && (e.target === search.current || (list.current && list.current.contains(e.target)))) {
        e.preventDefault();
        const i = list2.findIndex((x) => x.id === selRef.current);
        const n = e.key === 'ArrowDown' ? Math.min(list2.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1);
        setSel(list2[n].id);
        const el = list.current && list.current.querySelector(`[data-id="${list2[n].id}"]`); if (el) { el.scrollIntoView({ block: 'nearest' }); if (e.target !== search.current) el.focus(); }
        return;
      }
      if (mod && e.key.toLowerCase() === 'c' && selRef.current && !inField && !String(window.getSelection() || '')) {
        e.preventDefault();
        try { const it = await get(`/pw/${v.id}/items/${selRef.current}`); if (e.shiftKey) { if (it.username) copy(it.username, t('Username copied')); } else if (it.password) copy(it.password, t('Password copied')); } catch (er) { toast.error(er.message); }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [tool, edit, v.id]);

  const runAudit = async () => { setBusy('audit'); try { setAudit(await post(`/pw/${v.id}/audit`)); } catch (e) { toast.error(e.message); } setBusy(null); };
  const issues = audit && audit.counts ? audit.counts.leaked + audit.counts.weak + audit.counts.reused : 0;
  const cnt = (k) => (stats && k ? stats[k] : null);
  const kinds = KINDS.filter((k) => k.key === 'all' || (stats && stats[k.n] > 0) || (k.key === nav));
  const folders = (stats && stats.folders) || [];
  const tags = (stats && stats.tags) || [];
  const empty = stats && stats.all === 0 && nav === 'all' && !q;
  const preset = PRESET[nav] || 'login';
  const NavBtn = ({ k, label, icon: I, n, badge }) => <button type="button" className={`pw-nav-btn ${nav === k ? 'active' : ''}`} aria-current={nav === k ? 'page' : undefined} onClick={() => setNav(k)}><I size={15} aria-hidden="true" /><span className="grow ellipsis">{label}</span>{badge ? <span className="badge err">{badge}</span> : n != null ? <span className="pw-nav-n">{n}</span> : null}</button>;
  const switcher = data.instances.length > 1;
  return (
    <div className={`pw-app ${sel && !tool ? 'has-sel' : ''} ${tool ? 'has-tool' : ''}`}>
      <datalist id="pw-folders">{folders.map((f) => <option key={f.name} value={f.name} />)}</datalist>
      <nav className="pw-nav" aria-label={t('Vault navigation')}>
        {switcher && <select className="select sm pw-switch" aria-label={t('Switch vault')} value={v.id} onChange={(e) => { location.hash = `#/ext/passwords/${e.target.value}`; }}>{data.instances.map((x) => <option key={x.id} value={x.id}>{x.name}{x.locked ? ` · ${t('locked')}` : ''}</option>)}</select>}
        {!v.readonly && <Btn className="primary sm pw-new" icon={Plus} onClick={() => setEdit(null)}>New item</Btn>}
        <div className="pw-nav-group">{kinds.map((k) => <NavBtn key={k.key} k={k.key} label={t(k.label)} icon={k.icon} n={k.key === 'all' ? cnt('all') : cnt(k.n)} />)}</div>
        {folders.length > 0 && <div className="pw-nav-group"><div className="pw-nav-title">{t('Folders')}</div>{folders.map((f) => <NavBtn key={f.name} k={`folder:${f.name}`} label={f.name} icon={Folder} n={f.count} />)}</div>}
        {tags.length > 0 && <div className="pw-nav-group"><div className="pw-nav-title">{t('Tags')}</div>{tags.slice(0, 20).map((x) => <NavBtn key={x.name} k={`tag:${x.name}`} label={x.name} icon={Tag} n={x.count} />)}</div>}
        {own && <div className="pw-nav-group"><NavBtn k="trash" label={t('Trash')} icon={Trash2} n={cnt('trash') || null} /></div>}
        <div className="pw-nav-group pw-nav-tools">{TOOLS.map((x) => <NavBtn key={x.key} k={x.key} label={t(x.label)} icon={x.icon} badge={x.key === 'tool:audit' ? issues || null : null} />)}<button type="button" className="pw-nav-btn" onClick={async () => { await post(`/pw/${v.id}/lock`); reload(); }}><Lock size={15} aria-hidden="true" /><span className="grow">{t('Lock')}</span></button></div>
      </nav>

      {!tool && <section className="pw-list-col" aria-label={t('Items')}>
        <div className="pw-list-head">
          <div className="input-icon grow"><Search aria-hidden="true" /><input ref={search} className="input sm" type="search" aria-label={t('Search (Ctrl+F)')} placeholder={t('Search …')} value={q} onChange={(e) => setQ(e.target.value)} /></div>
          <InfoTip icon={Keyboard}>{t('Ctrl+F search · ↑/↓ choose · Ctrl+C copy password · Ctrl+Shift+C copy username')}</InfoTip>
        </div>
        {nav === 'trash' && items && items.length > 0 && <div className="pw-list-bar"><span className="tiny muted grow">{t('Items in the trash stay until you empty it.')}</span><Btn className="xs ghost" onClick={async () => { const r = await post(`/pw/${v.id}/trash/empty`); toast.success(t('{n} deleted for good', { n: r.removed })); load(); }}>Empty trash</Btn></div>}
        <div ref={list} className="pw-list" role="listbox" aria-label={t('Items')}>
          {!items ? <Loading /> : items.length === 0 ? (empty ? null : <div className="pw-list-none small muted">{q ? t('Nothing found for “{q}”.', { q }) : nav === 'trash' ? t('The trash is empty.') : t('Nothing here yet.')}</div>) : items.map((it) => (
            <div key={it.id} data-id={it.id} className={`pw-item ${sel === it.id ? 'active' : ''}`} role="option" aria-selected={sel === it.id} tabIndex={sel === it.id || (!sel && it === items[0]) ? 0 : -1} onClick={() => setSel(it.id)} onKeyDown={(e) => { if (e.key === 'Enter') setSel(it.id); }}>
              <SiteIcon host={it.host} name={it.name} type={it.type} />
              <div className="grow pw-item-text"><div className="small bold ellipsis">{it.name}{it.favorite && <Star size={11} className="pw-fav-mark" aria-label={t('Favourite')} />}</div><div className="tiny muted ellipsis">{it.username || it.host || it.notesPreview || (it.cardLast4 ? `•••• ${it.cardLast4}` : '') || t(TYPE_LABEL[it.type] || 'Login')}</div></div>
              <div className="pw-item-tags">{it.hasTotp && <span className="pw-chip" title={t('2FA code saved')}>2FA</span>}{it.passkeyCount > 0 && <Fingerprint size={13} aria-label={t('Passkey')} />}{it.attachmentCount > 0 && <Paperclip size={13} aria-label={t('Attachments')} />}<StrengthDot score={it.pwScore} /></div>
              {nav === 'trash' && <Btn className="xs" onClick={async (e) => { e.stopPropagation(); await post(`/pw/${v.id}/items/${it.id}/restore`); load(); }}>Restore</Btn>}
            </div>
          ))}
        </div>
      </section>}

      {!tool && <section className="pw-detail-col" aria-label={t('Details')}>
        {sel ? <ItemView v={v} id={sel} onEdit={(it) => setEdit(it)} onChanged={(id) => { if (!id) setSel(null); load(); }} onBack={() => setSel(null)} />
          : empty ? <Empty icon={KeyRound} title="Your vault is still empty" text="Create the first item – or bring everything over from your old password manager in one go.">{!v.readonly && <div className="row-tight"><Btn className="primary" icon={Plus} onClick={() => setEdit(null)}>New item</Btn><Btn icon={Upload} onClick={() => setNav('tool:io')}>Import</Btn></div>}</Empty>
          : <div className="pw-detail-hint"><KeyRound size={28} aria-hidden="true" /><div className="small">{t('Pick an item – a click on the copy symbol copies the value.')}</div><div className="tiny muted">{t('Ctrl+F search · ↑/↓ choose · Ctrl+C copy password')}</div></div>}
      </section>}

      {tool === 'audit' && <section className="pw-tool" aria-label={t('Security report')}><Audit v={v} audit={audit} busy={busy === 'audit'} onRun={runAudit} onOpen={(id) => { setNav('all'); setTimeout(() => setSel(id), 50); }} /></section>}
      {tool === 'io' && <section className="pw-tool" aria-label={t('Import / export')}><ImportExport v={v} data={data} onDone={() => { setNav('all'); load(); }} /></section>}
      {tool === 'generator' && <section className="pw-tool" aria-label={t('Generator')}><div className="card"><div className="card-head"><Wand2 size={16} aria-hidden="true" /><h3>Generate a password</h3></div><div className="card-body"><Generator /></div></div></section>}

      {edit !== undefined && <ItemDialog v={v} item={edit} preset={preset} onClose={() => setEdit(undefined)} onSaved={(r) => { setEdit(undefined); load(); if (r && r.id) setSel(r.id); }} />}
    </div>
  );
}

/* Sicherheitsbericht: schwach, mehrfach, alt, ohne 2FA, geleakt – nach Art filterbar */
const KIND_LABEL = { leaked: 'leaked', weak: 'weak', reused: 'reused', no2fa: 'without 2FA', old: 'old', empty: 'without password' };
function Audit({ v, audit, busy, onRun, onOpen }) {
  const [kind, setKind] = useState('');
  const shown = useMemo(() => (audit && audit.findings ? audit.findings.filter((f) => !kind || f.kind === kind) : []), [audit, kind]);
  return (
    <div className="stack">
      <div className="row"><Btn className="primary" icon={ShieldCheck} busy={busy} onClick={onRun}>Check now</Btn><span className="small muted grow">{t('Weak, reused, old and leaked passwords and important services without 2FA.')}</span><InfoTip>{t('The leak check asks Have I Been Pwned with only the first 5 characters of the password’s SHA-1 hash (k-anonymity) – the password never leaves this PC. It can be switched off in the settings.')}</InfoTip></div>
      {!audit && <Empty icon={ShieldCheck} title="Not checked yet" text="The check takes a few seconds and shows what to change first." />}
      {audit && <div className="pw-io">
        <div className="card">
          <div className="card-head"><ShieldCheck size={16} aria-hidden="true" /><h3>Result</h3><span className={`badge ${audit.score >= 90 ? '' : audit.score >= 60 ? 'warn' : 'err'}`}>{audit.score}/100</span><span className="tiny muted">{fmtDate(audit.at)}</span></div>
          <div className="card-body row pw-audit-counts">{[['leaked', 'c-err'], ['weak', 'c-err'], ['reused', 'c-warn'], ['no2fa', 'c-warn'], ['old', 'muted']].map(([k, c]) => <button key={k} type="button" className={`pw-audit-n ${kind === k ? 'active' : ''}`} aria-pressed={kind === k} onClick={() => setKind(kind === k ? '' : k)}><b className={c}>{audit.counts[k]}</b><span className="tiny muted">{t(KIND_LABEL[k])}</span></button>)}<div className="pw-audit-n"><b>{audit.counts.items}</b><span className="tiny muted">{t('checked')}</span></div></div>
          {shown.map((f, i) => <div key={i} className="list-item pw-finding"><div className={`ico ${f.level === 'err' ? 'c-err' : f.level === 'warn' ? 'c-warn' : 'muted'}`}>{f.level === 'err' ? <XCircle /> : f.level === 'warn' ? <AlertTriangle /> : <Info />}</div><div className="grow small pw-finding-text"><b>{f.name}</b>{f.username ? <span className="muted"> · {f.username}</span> : null}<div className="tiny muted">{f.text}</div></div>{f.itemId && <Btn className="xs" onClick={() => onOpen(f.itemId)}>Open</Btn>}</div>)}
          {audit.findings.length === 0 && <div className="card-body small c-ok row-tight"><CheckCircle2 size={14} aria-hidden="true" />{t('Nothing stands out.')}</div>}
        </div>
        <AiHint item="pw" title={t('AI: what first?')} input={`Vault ${v.name}: ${audit.counts.items} items, score ${audit.score}. Leaked ${audit.counts.leaked}, weak ${audit.counts.weak}, reused ${audit.counts.reused}, without 2FA ${audit.counts.no2fa}, old ${audit.counts.old}.\n${audit.findings.slice(0, 25).map((f) => `- ${f.name}${f.username ? ' (' + f.username + ')' : ''}: ${f.text}`).join('\n')}`} />
      </div>}
    </div>
  );
}

