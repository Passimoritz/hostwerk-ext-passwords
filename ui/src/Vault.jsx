import { useEffect, useState } from 'react';
import { KeyRound, Lock, Unlock, Plus, Search, Star, Trash2, Copy, Eye, EyeOff, RefreshCw, ShieldCheck, Upload, Download, Globe, Folder, StickyNote, CreditCard, User, Wand2, AlertTriangle, XCircle, CheckCircle2, Info, Clock, ExternalLink, History, ArrowRightLeft, Settings2, Link2, Users } from 'lucide-react';
import { get, post, put, del, on, fmtDate, openExternal } from '@hostwerk/api';
import { Btn, Tabs, Field, Seg, Empty, Loading, Callout, Modal, toast, confirmDialog, promptDialog, DropZone, InfoTip } from '@hostwerk/ui';
import { SvcImage, AiHint } from '@hostwerk/kit';
import { t } from '@hostwerk/i18n';
import { ShareDialog } from './Share';

/* Required data per provider – without it "Connect" is not offered at all, only "Enter access". */
export const REQUIRED = { onepassword: ['token'], keepass: ['file'], bitwarden: ['email'], lastpass: ['email'], pass: [] };
export const fieldLabel = (P, k) => t((P && (P.fields.find((f) => f[0] === k) || [])[1]) || k);

export const TYPE_ICON = { login: Globe, note: StickyNote, card: CreditCard, identity: User };
export const TYPE_LABEL = { login: 'Login', note: 'Note', card: 'Card', identity: 'Identity' };
// Remove copied values from the clipboard again after 30 s (only if the same value is still there)
const CLEAR_MS = 30000;
export const clearLater = (text) => setTimeout(async () => { try { const cur = await navigator.clipboard.readText(); if (cur === text) await navigator.clipboard.writeText(''); } catch { /* without read access: better not overwrite anything */ } }, CLEAR_MS);
const copy = async (text, what) => { try { await navigator.clipboard.writeText(text); clearLater(text); toast.success(t('{what} – cleared from the clipboard in 30 seconds', { what: what || t('Copied') })); } catch { toast.error('Clipboard not available'); } };

function Strength({ s }) { if (!s) return null; const col = ['var(--err)', 'var(--err)', 'var(--warn)', 'var(--ok)', 'var(--ok)'][s.score]; return <div className="pw-strength"><div className="bar"><div style={{ width: `${(s.score + 1) * 20}%`, background: col }} /></div><span className="tiny" style={{ color: col }}>{s.label}{s.hints && s.hints.length ? ` · ${s.hints.join(', ')}` : ''}</span></div>; }

export function Generator({ onUse }) {
  const [opts, setOpts] = useState({ length: 20, lower: true, upper: true, digits: true, symbols: true, words: 0 });
  const [out, setOut] = useState(null);
  const gen = async () => setOut(await post('/pw/generate', opts));
  useEffect(() => { gen(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="row"><code className="grow pw-gen" role="button" tabIndex={0} title={t('Copy')} onClick={() => out && copy(out.password)} onKeyDown={(e) => { if (e.key === 'Enter' && out) copy(out.password); }}>{out ? out.password : '…'}</code><Btn className="sm" icon={RefreshCw} onClick={gen}>New</Btn>{onUse && <Btn className="sm primary" onClick={() => out && onUse(out.password)}>Use</Btn>}</div>
      {out && <Strength s={out.strength} />}
      <Seg value={opts.words ? 'words' : 'chars'} onChange={(v) => setOpts({ ...opts, words: v === 'words' ? 4 : 0 })} options={[{ id: 'chars', label: t('Characters') }, { id: 'words', label: t('Words (passphrase)') }]} />
      {opts.words ? <label className="small row-tight">{t('Words')} <input className="input xs" type="number" min={3} max={10} value={opts.words} onChange={(e) => setOpts({ ...opts, words: Number(e.target.value) })} style={{ width: 70 }} /></label>
        : <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}><label className="small row-tight">{t('Length')} <input className="input xs" type="number" min={8} max={128} value={opts.length} onChange={(e) => setOpts({ ...opts, length: Number(e.target.value) })} style={{ width: 70 }} /></label>{[['upper', 'A–Z'], ['lower', 'a–z'], ['digits', '0–9'], ['symbols', '!@#']].map(([k, l]) => <label key={k} className="check small"><input type="checkbox" checked={opts[k]} onChange={(e) => setOpts({ ...opts, [k]: e.target.checked })} />{l}</label>)}</div>}
    </div>
  );
}

const IDENTITY = [['firstName', 'First name'], ['lastName', 'Last name'], ['company', 'Company'], ['email', 'E-mail'], ['phone', 'Phone'], ['birthday', 'Birthday'], ['address', 'Street'], ['zip', 'Postcode'], ['city', 'City'], ['country', 'Country']];

function ItemDialog({ v, item, onClose, onSaved }) {
  const [f, setF] = useState(() => item ? { ...item, url: (item.urls || [])[0] || '', urls: item.urls || [], card: item.card || {}, identity: item.identity || {} } : { type: 'login', name: '', username: '', password: '', url: '', urls: [], notes: '', totp: '', folder: '', tags: [], fields: [], favorite: false, card: {}, identity: {} });
  const [show, setShow] = useState(false);
  const [gen, setGen] = useState(false);
  const [st, setSt] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { const x = setTimeout(() => { if (f.password) post('/pw/strength', { password: f.password }).then(setSt).catch(() => {}); else setSt(null); }, 250); return () => clearTimeout(x); }, [f.password]);
  const save = async () => {
    setBusy(true);
    try { const body = { ...f, urls: [f.url, ...f.urls.slice(1)].filter(Boolean) }; const r = item ? await put(`/pw/${v.id}/items/${item.id}`, body) : await post(`/pw/${v.id}/items`, body); toast.success(item ? t('Saved') : t('Created')); onSaved(r); } catch (e) { toast.error(e.message); }
    setBusy(false);
  };
  const T = f.type;
  return (
    <Modal title={item ? t('Edit {name}', { name: item.name }) : t('New item')} onClose={onClose} size="lg" footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" busy={busy} disabled={!f.name} onClick={save}>Save</Btn></>}>
      <div className="stack">
        {!item && <Seg value={T} onChange={(x) => setF({ ...f, type: x })} options={Object.entries(TYPE_LABEL).map(([id, label]) => ({ id, label: t(label), icon: TYPE_ICON[id] }))} />}
        <div className="form-grid">
          <Field label="Name" className="span-2"><input className="input" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} autoFocus /></Field>
          {T === 'login' && <>
            <Field label="Username / e-mail"><input className="input" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></Field>
            <Field label="Address (URL)"><input className="input mono" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://…" /></Field>
            <Field label="Password" className="span-2"><div className="row-tight"><input className="input mono grow" type={show ? 'text' : 'password'} aria-label={t('Password')} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /><button className="btn ghost sm icon" aria-label={show ? t('Hide') : t('Show')} onClick={() => setShow(!show)}>{show ? <EyeOff /> : <Eye />}</button><Btn className="sm" icon={Wand2} onClick={() => setGen(!gen)}>Generate</Btn></div><Strength s={st} />{gen && <div className="card" style={{ marginTop: 8 }}><div className="card-body"><Generator onUse={(p) => { setF({ ...f, password: p }); setGen(false); }} /></div></div>}</Field>
            <Field label="2FA (TOTP secret or otpauth:// address)" className="span-2"><input className="input mono" value={f.totp} onChange={(e) => setF({ ...f, totp: e.target.value })} placeholder="JBSWY3DPEHPK3PXP / otpauth://totp/…" /></Field>
          </>}
          {T === 'card' && <>
            <Field label="Card holder"><input className="input" value={f.card.holder || ''} onChange={(e) => setF({ ...f, card: { ...f.card, holder: e.target.value } })} /></Field>
            <Field label="Brand"><input className="input" value={f.card.brand || ''} onChange={(e) => setF({ ...f, card: { ...f.card, brand: e.target.value } })} placeholder="Visa, Mastercard …" /></Field>
            <Field label="Card number"><input className="input mono" value={f.card.number || ''} onChange={(e) => setF({ ...f, card: { ...f.card, number: e.target.value } })} /></Field>
            <Field label="Valid until / security code"><div className="row-tight"><input className="input mono" aria-label={t('Valid until')} placeholder={t('MM/YY')} value={f.card.expiry || ''} onChange={(e) => setF({ ...f, card: { ...f.card, expiry: e.target.value } })} /><input className="input mono" aria-label="CVV" placeholder="CVV" type="password" value={f.card.cvv || ''} onChange={(e) => setF({ ...f, card: { ...f.card, cvv: e.target.value } })} /></div></Field>
          </>}
          {T === 'identity' && IDENTITY.map(([k, l]) => <Field key={k} label={t(l)}><input className="input" value={f.identity[k] || ''} onChange={(e) => setF({ ...f, identity: { ...f.identity, [k]: e.target.value } })} /></Field>)}
          <Field label="Folder"><input className="input" value={f.folder} onChange={(e) => setF({ ...f, folder: e.target.value })} list="pw-folders" /></Field>
          <Field label="Tags (comma)"><input className="input" value={(f.tags || []).join(', ')} onChange={(e) => setF({ ...f, tags: e.target.value.split(',').map((x) => x.trim()).filter(Boolean) })} /></Field>
          <Field label={T === 'note' ? t('Note') : t('Notes')} className="span-2"><textarea className="input" rows={T === 'note' ? 8 : 3} value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} /></Field>
        </div>
        <div>
          <div className="small bold">{t('Extra fields')}</div>
          {(f.fields || []).map((x, i) => <div key={i} className="row-tight" style={{ marginTop: 4 }}><input className="input sm" aria-label={t('Name')} placeholder="Name" value={x.name} onChange={(e) => { const n = [...f.fields]; n[i] = { ...x, name: e.target.value }; setF({ ...f, fields: n }); }} /><input className="input sm mono grow" aria-label={t('Value')} type={x.hidden ? 'password' : 'text'} placeholder="Value" value={x.value} onChange={(e) => { const n = [...f.fields]; n[i] = { ...x, value: e.target.value }; setF({ ...f, fields: n }); }} /><label className="check tiny"><input type="checkbox" checked={!!x.hidden} onChange={(e) => { const n = [...f.fields]; n[i] = { ...x, hidden: e.target.checked }; setF({ ...f, fields: n }); }} />{t('secret')}</label><button className="btn ghost xs icon" aria-label={t('Remove field')} onClick={() => setF({ ...f, fields: f.fields.filter((_, k) => k !== i) })}><Trash2 /></button></div>)}
          <button className="btn ghost xs" style={{ marginTop: 4 }} onClick={() => setF({ ...f, fields: [...(f.fields || []), { name: '', value: '', hidden: false }] })}><Plus />{t('Field')}</button>
        </div>
        <label className="check small"><input type="checkbox" checked={!!f.favorite} onChange={(e) => setF({ ...f, favorite: e.target.checked })} />{t('Favourite')}</label>
      </div>
    </Modal>
  );
}

function ItemView({ v, id, onEdit, onChanged }) {
  const [it, setIt] = useState(null);
  const [sharing, setSharing] = useState(false);
  const [show, setShow] = useState(false);
  const [totp, setTotp] = useState(null);
  useEffect(() => { setIt(null); setShow(false); get(`/pw/${v.id}/items/${id}`).then(setIt).catch((e) => toast.error(e.message)); }, [v.id, id]);
  // Hide a shown password again after 20 s
  useEffect(() => { if (!show) return undefined; const x = setTimeout(() => setShow(false), 20000); return () => clearTimeout(x); }, [show]);
  useEffect(() => { if (!it || !it.totp) { setTotp(null); return undefined; } const load = () => get(`/pw/${v.id}/items/${id}/totp`).then(setTotp).catch(() => {}); load(); const x = setInterval(load, 1000); return () => clearInterval(x); }, [it, v.id, id]);
  if (!it) return <Loading />;
  const I = TYPE_ICON[it.type] || Globe;
  const own = v.type === 'hostwerk';
  const Row = ({ label, value, secret, mono = true, link }) => value ? <div className="pw-row"><span className="tiny muted">{label}</span><div className="row-tight"><span className={`${mono ? 'mono' : ''} small ellipsis grow`} role="button" tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => copy(value, t('{label} copied', { label }))} onKeyDown={(e) => { if (e.key === 'Enter') copy(value, t('{label} copied', { label })); }}>{secret && !show ? '••••••••••' : value}</span>{link && <button className="btn ghost xs icon" aria-label={t('Open')} onClick={() => openExternal(value.startsWith('http') ? value : 'https://' + value)}><ExternalLink /></button>}<button className="btn ghost xs icon" title="Copy" aria-label={t('Copy')} onClick={() => copy(value, t('{label} copied', { label }))}><Copy /></button></div></div> : null;
  const remove = async () => { if (await confirmDialog({ title: own ? t('Move “{name}” to the trash?', { name: it.name }) : t('Delete “{name}”?', { name: it.name }), confirm: 'Yes', danger: !own })) { await del(`/pw/${v.id}/items/${id}`); onChanged(null); } };
  return (
    <div className="card pw-view">
      <div className="card-head"><I size={16} /><h3 className="ellipsis">{it.name}</h3>{it.favorite && <Star size={14} className="c-warn" aria-label={t('Favourite')} />}<span className="badge">{t(TYPE_LABEL[it.type])}</span>
        <div className="right row-tight">{own && <button className="btn ghost sm icon" title="Share with members" aria-label={t('Share with members')} onClick={() => setSharing(true)}><Users /></button>}<button className="btn ghost sm icon" title={show ? t('Hide') : t('Show')} aria-label={show ? t('Hide') : t('Show')} onClick={() => setShow(!show)}>{show ? <EyeOff /> : <Eye />}</button>{!v.readonly && <Btn className="sm" onClick={() => onEdit(it)}>Edit</Btn>}{!v.readonly && <button className="btn ghost sm icon" title={own ? t('To the trash') : t('Delete')} aria-label={own ? t('To the trash') : t('Delete')} onClick={remove}><Trash2 /></button>}</div>
      </div>
      <div className="card-body stack" style={{ gap: 6 }}>
        <Row label={t('Username')} value={it.username} />
        <Row label={t('Password')} value={it.password} secret />
        {totp && totp.code && <div className="pw-row"><span className="tiny muted">{t('2FA code')}</span><div className="row-tight"><b className="mono" role="button" tabIndex={0} style={{ fontSize: 18, letterSpacing: 2, cursor: 'pointer' }} onClick={() => copy(totp.code, t('Code copied'))} onKeyDown={(e) => { if (e.key === 'Enter') copy(totp.code, t('Code copied')); }}>{totp.code.replace(/(\d{3})(\d{3})/, '$1 $2')}</b><span className="tiny muted">{t('{n} s left', { n: totp.remaining })}</span><div className="pw-totp"><div style={{ width: `${(totp.remaining / totp.period) * 100}%` }} /></div></div></div>}
        {(it.urls || []).map((u) => <Row key={u} label={t('Address')} value={u} link />)}
        {it.card && <>{[[t('Holder'), it.card.holder, false], [t('Number'), it.card.number, true], [t('Valid until'), it.card.expiry, false], ['CVV', it.card.cvv, true], [t('Brand'), it.card.brand, false]].map(([l, val, s]) => <Row key={l} label={l} value={val} secret={s} />)}</>}
        {it.identity && Object.entries(it.identity).filter(([, val]) => val).map(([k, val]) => <Row key={k} label={t((IDENTITY.find(([x]) => x === k) || [k, k])[1])} value={val} mono={false} />)}
        {(it.fields || []).map((f, i) => <Row key={i} label={f.name} value={f.value} secret={f.hidden} />)}
        {it.notes && <div className="pw-row"><span className="tiny muted">{t('Notes')}</span><pre className="small" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{it.notes}</pre></div>}
        <div className="tiny muted row" style={{ gap: 10, flexWrap: 'wrap' }}>{it.folder && <span><Folder size={11} /> {it.folder}</span>}{(it.tags || []).map((x) => <span key={x} className="badge">{x}</span>)}{it.passwordChanged && <span><Clock size={11} /> {t('Password changed {date}', { date: fmtDate(it.passwordChanged) })}</span>}{it.history && it.history.length > 0 && <span><History size={11} /> {t('{n} earlier passwords', { n: it.history.length })}</span>}</div>
        {sharing && <ShareDialog vault={v.id} item={it.id} name={it.name} onClose={() => setSharing(false)} />}
        {show && it.history && it.history.length > 0 && <details><summary className="tiny">{t('Earlier passwords')}</summary>{it.history.map((h, i) => <div key={i} className="tiny mono">{h.password} <span className="muted">{t('until {date}', { date: fmtDate(h.until) })}</span></div>)}</details>}
      </div>
    </div>
  );
}

export function VaultView({ v, data, reload, initialTab, onCfg }) {
  const [q, setQ] = useState('');
  const [folder, setFolder] = useState('');
  const [type, setType] = useState('');
  const [trashed, setTrashed] = useState(false);
  const [items, setItems] = useState(null);
  const [sel, setSel] = useState(null);
  const [edit, setEdit] = useState(undefined);
  const [folders, setFolders] = useState([]);
  const [pw, setPw] = useState('');
  const [tab, setTab] = useState(['items', 'audit', 'io', 'generator'].includes(initialTab) ? initialTab : 'items');
  const [audit, setAudit] = useState(v.audit);
  const [busy, setBusy] = useState(null);
  const load = () => { if (v.locked) return; get(`/pw/${v.id}/items?q=${encodeURIComponent(q)}&folder=${encodeURIComponent(folder)}&type=${type}&trashed=${trashed ? 1 : 0}`).then(setItems).catch((e) => toast.error(e.message)); get(`/pw/${v.id}/folders`).then(setFolders).catch(() => {}); };
  useEffect(() => { const x = setTimeout(load, q ? 200 : 0); return () => clearTimeout(x); }, [v.id, v.locked, q, folder, type, trashed]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => on('passwords', (m) => { if (!m.id || m.id === v.id) load(); }), [v.id, q, folder, type, trashed]); // eslint-disable-line react-hooks/exhaustive-deps
  const unlock = async () => { setBusy('unlock'); try { await post(`/pw/${v.id}/unlock`, { password: pw }); setPw(''); reload(); } catch (e) { toast.error(e.message); } setBusy(null); };
  if (v.locked) {
    const P = data.providers.find((p) => p.id === v.type);
    const missing = (REQUIRED[v.type] || []).filter((k) => !v.cfg || !v.cfg[k]);
    const stored = v.cfg && v.cfg.password; // master password stored (delivered masked)
    const needsPw = v.type === 'hostwerk' || (['bitwarden', 'keepass', 'lastpass'].includes(v.type) && !stored);
    return (
      <div className="card"><div className="card-body stack" style={{ maxWidth: 480, gap: 10 }}>
        <div className="row-tight"><SvcImage kind="pw" id={v.id} name={v.name} size={30} className="svc-icon" fallback={<Lock size={18} />} /><b>{v.name}</b><span className="badge">{v.label}</span></div>
        {missing.length > 0 ? <>
          <InfoTip>{t('To connect, this is still missing:')} <b>{missing.map((k) => fieldLabel(P, k)).join(', ')}</b>.{P && P.hint ? <div className="tiny muted" style={{ marginTop: 4 }}>{t(P.hint)}</div> : null}</InfoTip>
          <div><Btn className="primary" icon={Settings2} onClick={onCfg}>Enter access</Btn></div>
        </> : needsPw ? <>
          <div className="small muted">{v.type === 'hostwerk' ? t('Enter the master password to unlock the vault.') : t('Enter the provider’s master password – Hostwerk does not remember it (to store it: “Access”).')}</div>
          <form className="row-tight" onSubmit={(e) => { e.preventDefault(); unlock(); }}><input className="input grow" type="password" aria-label={t('Master password')} placeholder="Master password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus /><Btn className="primary" icon={Unlock} busy={busy === 'unlock'} type="submit">{v.type === 'hostwerk' ? t('Unlock') : t('Connect')}</Btn>{v.type !== 'hostwerk' && <Btn className="ghost" icon={Settings2} title="Access" aria-label={t('Access')} onClick={onCfg} />}</form>
        </> : <div className="row-tight"><Btn className="primary" icon={Link2} busy={busy === 'unlock'} onClick={unlock}>Connect</Btn><Btn className="ghost" icon={Settings2} onClick={onCfg}>Access</Btn></div>}
      </div></div>
    );
  }
  const runAudit = async () => { setBusy('audit'); try { setAudit(await post(`/pw/${v.id}/audit`)); setTab('audit'); } catch (e) { toast.error(e.message); } setBusy(null); };
  const issues = audit && audit.counts ? audit.counts.leaked + audit.counts.weak + audit.counts.reused : 0;
  const tabs = [{ id: 'items', label: t('Items'), icon: KeyRound }, { id: 'audit', label: t('Security'), icon: ShieldCheck, badge: issues || null }, { id: 'io', label: t('Import / export'), icon: ArrowRightLeft }, { id: 'generator', label: t('Generator'), icon: Wand2 }];
  return (
    <div className="stack">
      <datalist id="pw-folders">{folders.map((f) => <option key={f.name} value={f.name} />)}</datalist>
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      {tab === 'items' && (
        <div className="pw-layout">
          <div className="pw-side">
            <div className="input-icon"><Search /><input className="input sm" aria-label={t('Search')} placeholder="Search …" value={q} onChange={(e) => setQ(e.target.value)} /></div>
            <Seg value={type} onChange={setType} options={[{ id: '', label: t('All') }, ...Object.entries(TYPE_LABEL).map(([id, label]) => ({ id, label: t(label), icon: TYPE_ICON[id] }))]} />
            {folders.length > 0 && <div className="stack" style={{ gap: 2 }}><button className={`link-btn small ${!folder ? 'bold' : ''}`} onClick={() => setFolder('')}><Folder size={12} /> {t('All folders')}</button>{folders.map((f) => <button key={f.name} className={`link-btn small ${folder === f.name ? 'bold' : ''}`} onClick={() => setFolder(f.name)}><Folder size={12} /> {f.name} <span className="muted tiny">{f.count}</span></button>)}</div>}
            {v.type === 'hostwerk' && <button className={`link-btn small ${trashed ? 'bold' : ''}`} onClick={() => setTrashed(!trashed)}><Trash2 size={12} /> {t('Trash')}</button>}
            {trashed && <Btn className="xs ghost" onClick={async () => { const r = await post(`/pw/${v.id}/trash/empty`); toast.success(t('{n} deleted for good', { n: r.removed })); load(); }}>Empty trash</Btn>}
            {!v.readonly && <Btn className="primary sm" icon={Plus} onClick={() => setEdit(null)}>New item</Btn>}
            <Btn className="sm ghost" icon={Lock} onClick={async () => { await post(`/pw/${v.id}/lock`); reload(); }}>Lock</Btn>
          </div>
          <div className="pw-list">
            {!items ? <Loading /> : items.length === 0 ? <Empty icon={KeyRound} title={q ? t('Nothing found') : t('No items yet')} text={q ? '' : t('Create the first login or import from another password manager (Import / export tab).')} /> : items.map((it) => { const I = TYPE_ICON[it.type] || Globe; return (
              <div key={it.id} className={`list-item ${sel === it.id ? 'active' : ''}`} role="button" tabIndex={0} style={{ cursor: 'pointer' }} onClick={() => setSel(it.id)} onKeyDown={(e) => { if (e.key === 'Enter') setSel(it.id); }}>
                <div className="ico"><I /></div>
                <div className="grow" style={{ minWidth: 0 }}><div className="small bold ellipsis">{it.favorite && <Star size={11} className="c-warn" />} {it.name}</div><div className="tiny muted ellipsis">{it.username || (it.urls || [])[0] || it.notesPreview || t(TYPE_LABEL[it.type])}{it.hasTotp ? ' · 2FA' : ''}</div></div>
                {trashed ? <Btn className="xs" onClick={async (e) => { e.stopPropagation(); await post(`/pw/${v.id}/items/${it.id}/restore`); load(); }}>Restore</Btn> : null}
              </div>
            ); })}
          </div>
          <div className="pw-detail">{sel ? <ItemView v={v} id={sel} onEdit={(it) => setEdit(it)} onChanged={() => { setSel(null); load(); }} /> : <div className="card"><div className="card-body small muted">{t('Pick an item on the left – a click on a value copies it.')}</div></div>}</div>
        </div>
      )}
      {tab === 'audit' && (
        <div className="stack">
          <div className="row"><Btn className="primary" icon={ShieldCheck} busy={busy === 'audit'} onClick={runAudit}>Check now</Btn><span className="small muted">{t('Weak, reused, old and leaked passwords (Have I Been Pwned, only the start of the hash leaves the PC) and important services without 2FA.')}</span></div>
          {audit && (
            <div className="grid split-side">
              <div className="card">
                <div className="card-head"><ShieldCheck size={16} /><h3>Result</h3><span className="badge">{audit.score}/100</span><span className="tiny muted">{fmtDate(audit.at)}</span></div>
                <div className="card-body row" style={{ gap: 14, flexWrap: 'wrap' }}>{[['leaked', audit.counts.leaked, 'c-err'], ['weak', audit.counts.weak, 'c-err'], ['reused', audit.counts.reused, 'c-warn'], ['without 2FA', audit.counts.no2fa, 'c-warn'], ['old', audit.counts.old, 'muted'], ['checked', audit.counts.items, '']].map(([l, n, c]) => <div key={l}><div className={`bold ${c}`} style={{ fontSize: 20 }}>{n}</div><div className="tiny muted">{t(l)}</div></div>)}</div>
                {audit.findings.map((f, i) => <div key={i} className="list-item" style={{ padding: '5px 12px' }}><div className={`ico ${f.level === 'err' ? 'c-err' : f.level === 'warn' ? 'c-warn' : 'muted'}`}>{f.level === 'err' ? <XCircle /> : f.level === 'warn' ? <AlertTriangle /> : <Info />}</div><div className="grow small" style={{ minWidth: 0 }}><b>{f.name}</b>{f.username ? <span className="muted"> · {f.username}</span> : null}<div className="tiny muted">{f.text}</div></div>{f.itemId && <Btn className="xs" onClick={() => { setTab('items'); setSel(f.itemId); }}>Open</Btn>}</div>)}
                {audit.findings.length === 0 && <div className="card-body small c-ok row-tight"><CheckCircle2 size={14} />{t('Nothing stands out.')}</div>}
              </div>
              <AiHint item="pw" title={t('AI: what first?')} input={`Vault ${v.name}: ${audit.counts.items} items, score ${audit.score}. Leaked ${audit.counts.leaked}, weak ${audit.counts.weak}, reused ${audit.counts.reused}, without 2FA ${audit.counts.no2fa}, old ${audit.counts.old}.\n${audit.findings.slice(0, 25).map((f) => `- ${f.name}${f.username ? ' (' + f.username + ')' : ''}: ${f.text}`).join('\n')}`} />
            </div>
          )}
        </div>
      )}
      {tab === 'io' && <ImportExport v={v} data={data} onDone={load} />}
      {tab === 'generator' && <div className="card"><div className="card-head"><Wand2 size={16} /><h3>Generate a password</h3></div><div className="card-body"><Generator /></div></div>}
      {edit !== undefined && <ItemDialog v={v} item={edit} onClose={() => setEdit(undefined)} onSaved={(r) => { setEdit(undefined); load(); if (r && r.id) setSel(r.id); }} />}
    </div>
  );
}

const EXPORTS = [['kdbx', 'KeePass (.kdbx, encrypted)'], ['bitwarden-json', 'Bitwarden/Vaultwarden (JSON)'], ['bitwarden-csv', 'Bitwarden (CSV)'], ['chrome-csv', 'Chrome / Edge / Google / Apple (CSV)'], ['keepass-csv', 'KeePass (CSV)'], ['generic-csv', 'General (CSV)']];
const WAY = { import: 'Import/export', manual: 'by hand', 'native-readonly': 'read', native: 'direct' };

function ImportExport({ v, data, onDone }) {
  const [preview, setPreview] = useState(null);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [to, setTo] = useState('');
  const others = data.instances.filter((x) => x.id !== v.id && !x.locked && !x.readonly);
  const onFile = async (files) => { const x = await files[0].text(); setText(x); try { setPreview(await post(`/pw/${v.id}/import-preview`, { text: x })); } catch (e) { toast.error(e.message); setPreview(null); } };
  const doImport = async () => { setBusy(true); try { const r = await post(`/pw/${v.id}/import`, { text }); toast.success(r.skipped ? t('{n} items imported ({label}), {s} duplicates skipped', { n: r.added, label: r.label, s: r.skipped }) : t('{n} items imported ({label})', { n: r.added, label: r.label })); setPreview(null); setText(''); onDone(); } catch (e) { toast.error(e.message); } setBusy(false); };
  const doExport = async (kind) => {
    // KeePass-Datei: eigenes Passwort für die Datei (sie ist verschlüsselt, anders als CSV/JSON)
    let password;
    if (kind === 'kdbx') { password = await promptDialog({ title: t('Password for the KeePass file'), text: t('KeePass and KeePassXC open the file with this password. At least 8 characters – it can differ from your master password.'), label: t('Password'), password: true, confirm: t('Export'), validate: (x) => (String(x || '').length < 8 ? t('At least 8 characters') : null) }); if (!password) return; }
    const res = await fetch(`/api/pw/${v.id}/export`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind, password }) }); if (!res.ok) { toast.error((await res.json()).error); return; } const blob = await res.blob(); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); const m = (res.headers.get('content-disposition') || '').match(/filename="([^"]+)"/); a.download = m ? decodeURIComponent(m[1]) : 'export'; a.click(); };
  const cat = (data.catalog && data.catalog.providers) || [];
  return (
    <div className="grid grid-2">
      <div className="stack">
        <div className="card">
          <div className="card-head"><Upload size={16} /><h3>Import</h3><span className="small muted">{t('The format is recognised')}</span></div>
          <div className="card-body stack" style={{ gap: 8 }}>
            <DropZone accept=".csv,.json,.txt,.1pux" onFiles={onFile}><Upload size={22} /><div className="bold" style={{ marginTop: 6 }}>{t('Drop the export file')}</div><div className="small">{t('CSV or JSON in {n} formats (Bitwarden, Chrome, Firefox, Apple, 1Password, LastPass, Dashlane, NordPass, Proton, KeePass …)', { n: data.formats.length })}</div></DropZone>
            {preview && <div className="stack" style={{ gap: 6 }}><div className="small">{t('{label} recognised · {n} items', { label: preview.label, n: preview.count })}</div>{preview.sample.map((s, i) => <div key={i} className="tiny muted ellipsis">• {s.name} · {s.username || (s.urls || [])[0] || s.type}</div>)}<div className="row"><Btn className="primary" icon={Upload} busy={busy} onClick={doImport}>{t('Take over {n} items', { n: preview.count })}</Btn><Btn className="ghost" onClick={() => { setPreview(null); setText(''); }}>Discard</Btn></div></div>}
            <Callout kind="warn" dismissible={false}>Export files are not encrypted – delete them after the import (Hostwerk → Files → empty the trash).</Callout>
          </div>
        </div>
        <div className="card">
          <div className="card-head"><Download size={16} /><h3>Export</h3></div>
          <div className="card-body row" style={{ gap: 6, flexWrap: 'wrap' }}>{EXPORTS.map(([k, l]) => <Btn key={k} className="sm" icon={Download} onClick={() => doExport(k)}>{t(l)}</Btn>)}</div>
          {others.length > 0 && <div className="card-body row" style={{ borderTop: '1px solid var(--line)' }}><span className="small">{t('Copy into another vault:')}</span><select className="select sm" aria-label={t('Target vault')} value={to} onChange={(e) => setTo(e.target.value)}><option value="">{t('choose …')}</option>{others.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select><Btn className="sm" icon={ArrowRightLeft} disabled={!to} onClick={async () => { const r = await post(`/pw/${v.id}/transfer`, { to }); toast.success(t('{n} items copied', { n: r.copied })); }}>Copy</Btn></div>}
        </div>
      </div>
      <div className="card">
        <div className="card-head"><Info size={16} /><h3>How to get your data</h3><span className="small muted">{t('{n} services in the catalogue', { n: cat.length })}</span></div>
        <div className="card-body stack" style={{ gap: 6 }}>{cat.filter((p) => p.way !== 'native' || p.id === 'vaultwarden').map((p) => <div key={p.id} className="small"><b>{p.name}</b> <span className="badge">{t(WAY[p.way] || 'direct')}</span><div className="tiny muted">{p.text}</div></div>)}</div>
      </div>
    </div>
  );
}
