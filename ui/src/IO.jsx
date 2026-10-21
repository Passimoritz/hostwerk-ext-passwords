import { useState } from 'react';
import { Upload, Download, ArrowRightLeft, Info, Lock, ShieldAlert, KeyRound, ArchiveRestore, FileWarning } from 'lucide-react';
import { post } from '@hostwerk/api';
import { Btn, Field, Callout, DropZone, toast, confirmDialog, promptDialog, InfoTip } from '@hostwerk/ui';
import { t } from '@hostwerk/i18n';

/*
 * Import / export of a vault:
 *   Import – drop any export file (CSV/JSON of every common service, KeePass .kdbx/XML, 1Password .1pux, Bitwarden with
 *   password). Hostwerk recognises the format, asks for a password when the file is encrypted, offers an own column
 *   assignment for unknown CSV files and shows how many items are already there (duplicates are skipped).
 *   Export – encrypted (KeePass, Bitwarden with password) first; unencrypted only after a clear warning.
 */
const BINARY = /\.(kdbx|1pux|zip)$/i;
const ENCRYPTED = [['kdbx', 'KeePass (.kdbx)', 'Opens in KeePass, KeePassXC, KeePassDX, Strongbox – with passkeys and 2FA.'], ['bitwarden-encrypted', 'Bitwarden (JSON with password)', 'Imports in Bitwarden and Vaultwarden – “Password protected” export format.']];
const PLAIN = [['bitwarden-json', 'Bitwarden / Vaultwarden (JSON)'], ['bitwarden-csv', 'Bitwarden (CSV)'], ['chrome-csv', 'Chrome / Edge / Google / Apple (CSV)'], ['keepass-csv', 'KeePass (CSV)'], ['generic-csv', 'General (CSV)']];
const WAY = { import: 'Import/export', manual: 'by hand', 'native-readonly': 'read', native: 'direct' };
const FIELD_LABEL = { name: 'Name', url: 'Address (URL)', username: 'Username', password: 'Password', notes: 'Notes', totp: '2FA', folder: 'Folder', tags: 'Tags', favorite: 'Favourite', type: 'Kind' };
const TYPE_PL = { login: 'logins', note: 'notes', card: 'cards', identity: 'identities', ssh: 'SSH keys' };

const readFile = (file) => new Promise((ok, fail) => {
  const r = new FileReader();
  r.onerror = fail;
  if (BINARY.test(file.name)) { r.onload = () => ok({ data: String(r.result).split(',')[1] || '', name: file.name }); r.readAsDataURL(file); } else { r.onload = () => ok({ text: String(r.result), name: file.name }); r.readAsText(file); }
});

async function download(v, body) {
  const res = await fetch(`/api/pw/${v.id}/export`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  if (!res.ok) { let msg = `${res.status}`; try { msg = (await res.json()).error; } catch { /* leer */ } toast.error(msg); return; }
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement('a'); a.href = url;
  const m = (res.headers.get('content-disposition') || '').match(/filename="([^"]+)"/);
  a.download = m ? decodeURIComponent(m[1]) : 'export'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  toast.success(t('Export saved – it is in your downloads folder.'));
}

export function ImportExport({ v, data, onDone }) {
  const [file, setFile] = useState(null);      // { text | data, name }
  const [pass, setPass] = useState('');
  const [mapping, setMapping] = useState(null);
  const [preview, setPreview] = useState(null);
  const [skip, setSkip] = useState(true);
  const [folder, setFolder] = useState('');
  const [busy, setBusy] = useState(null);
  const [to, setTo] = useState('');
  const others = data.instances.filter((x) => x.id !== v.id && !x.locked && !x.readonly);
  const reset = () => { setFile(null); setPass(''); setMapping(null); setPreview(null); setFolder(''); };
  const check = async (f = file, extra = {}) => {
    setBusy('preview');
    try { const p = await post(`/pw/${v.id}/import-preview`, { ...f, password: extra.password ?? pass, mapping: extra.mapping ?? mapping }); setPreview(p); if (p.mapping && !mapping) setMapping(p.mapping); } catch (e) { toast.error(e.message); setPreview(null); }
    setBusy(null);
  };
  const onFiles = async (files) => { if (!files[0]) return; reset(); try { const f = await readFile(files[0]); setFile(f); check(f, { password: '', mapping: null }); } catch { toast.error(t('The file cannot be read.')); } };
  const doImport = async () => {
    setBusy('import');
    try {
      const r = await post(`/pw/${v.id}/import`, { ...file, password: pass, mapping, skipDuplicates: skip, folder });
      toast.success(r.skipped ? t('{n} items imported ({label}), {s} duplicates skipped', { n: r.added, label: r.label, s: r.skipped }) : t('{n} items imported ({label})', { n: r.added, label: r.label }));
      reset(); onDone();
    } catch (e) { toast.error(e.message); }
    setBusy(null);
  };
  const exportEnc = async (kind, label) => {
    const pw = await promptDialog({ title: t('Password for the file'), text: t('{label} – the file is encrypted with this password. At least 8 characters; it can differ from your master password. Keep it safe: without it the file cannot be opened.', { label: t(label) }), label: t('Password'), password: true, confirm: t('Export'), validate: (x) => (String(x || '').length < 8 ? t('At least 8 characters') : null) });
    if (!pw) return;
    const again = await promptDialog({ title: t('Repeat the password'), label: t('Password'), password: true, confirm: t('Export') });
    if (again !== pw) { toast.error(t('The passwords do not match.')); return; }
    setBusy(kind); await download(v, { kind, password: pw }); setBusy(null);
  };
  const exportPlain = async (kind, label) => {
    const r = await confirmDialog({ title: t('Export without encryption?'), text: t('The file “{label}” contains every password in plain text. Anyone who gets it can read everything. Only use it to move to another manager right away, and delete it afterwards (also from the recycle bin).', { label: t(label) }), confirm: t('Export unencrypted'), danger: true, checkbox: { label: t('I understand – the file is not protected'), checked: false } });
    if (!r || !r.ok) return;
    if (!r.checked) { toast.error(t('Please tick the box first.')); return; }
    setBusy(kind); await download(v, { kind, plain: true }); setBusy(null);
  };
  const cat = (data.catalog && data.catalog.providers) || [];
  const needMap = preview && (preview.needsMapping || preview.format === 'generic' || preview.format === 'mapped');
  const head = (preview && preview.head) || [];
  return (
    <div className="pw-io">
      <div className="stack">
        <div className="card">
          <div className="card-head"><Upload size={16} aria-hidden="true" /><h3>Import</h3><InfoTip>{t('Hostwerk recognises the format by itself: CSV or JSON of every common service, KeePass (.kdbx, XML), 1Password (.1pux) and Bitwarden exports with a password. Items that are already in the vault (same name, user and address) are skipped.')}</InfoTip></div>
          <div className="card-body stack">
            {!file && <DropZone accept=".csv,.json,.txt,.xml,.1pux,.kdbx" onFiles={onFiles}><Upload size={22} aria-hidden="true" /><div className="bold pw-drop-title">{t('Drop the export file')}</div><div className="small">{t('{n} formats – Bitwarden, 1Password, KeePass, LastPass, Dashlane, NordPass, Proton Pass, Enpass, Keeper, RoboForm, Chrome, Edge, Firefox, Apple …', { n: data.formats.length + 4 })}</div></DropZone>}
            {file && <div className="row-tight small"><FileWarning size={14} aria-hidden="true" /><b className="grow ellipsis">{file.name}</b><Btn className="xs ghost" onClick={reset}>Choose another file</Btn></div>}
            {preview && preview.needsPassword && <form className="stack" onSubmit={(e) => { e.preventDefault(); check(file, { password: pass }); }}>
              <Callout kind="info" dismissible={false}>{preview.message}</Callout>
              <div className="row-tight"><input className="input grow" type="password" autoComplete="off" aria-label={t('Password of the file')} placeholder={t('Password of the file')} value={pass} onChange={(e) => setPass(e.target.value)} autoFocus /><Btn className="primary" icon={KeyRound} busy={busy === 'preview'} type="submit">Open</Btn></div>
            </form>}
            {needMap && head.length > 0 && <div className="stack">
              <div className="small">{preview.needsMapping ? t('Hostwerk does not know these columns – tell it which column holds what:') : t('Columns recognised – check the assignment:')}</div>
              <div className="pw-map">{(preview.fields || []).map((k) => <label key={k} className="pw-map-row small"><span>{t(FIELD_LABEL[k] || k)}</span><select className="select sm" value={(mapping || {})[k] || ''} onChange={(e) => { const m = { ...(mapping || {}) }; if (e.target.value) m[k] = e.target.value; else delete m[k]; setMapping(m); check(file, { mapping: m }); }}><option value="">{t('– none –')}</option>{head.map((h) => <option key={h} value={h}>{h}</option>)}</select></label>)}</div>
            </div>}
            {preview && !preview.needsPassword && !preview.needsMapping && <div className="stack pw-preview">
              <div className="row-tight"><b>{t('{label} recognised', { label: preview.label })}</b><span className="badge">{t('{n} items', { n: preview.count })}</span>{preview.duplicates ? <span className="badge warn">{t('{n} already there', { n: preview.duplicates })}</span> : null}</div>
              <div className="tiny muted">{Object.entries(preview.counts || {}).map(([k, n]) => `${n} ${t(TYPE_PL[k] || k)}`).join(' · ')}</div>
              <ul className="pw-sample">{preview.sample.map((s, i) => <li key={i} className="small ellipsis"><b>{s.name}</b>{s.username ? ` · ${s.username}` : ''}{s.url ? <span className="muted"> · {s.url}</span> : null}{s.hasTotp ? <span className="badge">2FA</span> : null}{s.passkeys ? <span className="badge">{t('Passkey')}</span> : null}</li>)}</ul>
              <div className="form-grid"><Field label="Into folder (optional)"><input className="input" value={folder} onChange={(e) => setFolder(e.target.value)} placeholder={t('keep the folders of the file')} list="pw-folders" /></Field><label className="check small pw-skip"><input type="checkbox" checked={skip} onChange={(e) => setSkip(e.target.checked)} />{t('Skip items that are already there')}</label></div>
              <div className="row"><Btn className="primary" icon={Upload} busy={busy === 'import'} disabled={!preview.count} onClick={doImport}>{t('Take over {n} items', { n: skip && preview.duplicates ? preview.count - preview.duplicates : preview.count })}</Btn><Btn className="ghost" onClick={reset}>Discard</Btn></div>
            </div>}
            <Callout kind="warn" dismissible={false}>{t('Export files of other services are usually not encrypted – delete them after the import (and empty the recycle bin).')}</Callout>
          </div>
        </div>
        <div className="card">
          <div className="card-head"><Download size={16} aria-hidden="true" /><h3>Export</h3></div>
          <div className="card-body stack">
            <div className="small bold row-tight"><Lock size={14} aria-hidden="true" />{t('Encrypted – recommended')}</div>
            {ENCRYPTED.map(([k, l, d]) => <div key={k} className="pw-line"><div className="grow small"><b>{t(l)}</b><div className="tiny muted">{t(d)}</div></div><Btn className="sm" icon={Download} busy={busy === k} onClick={() => exportEnc(k, l)}>Export</Btn></div>)}
            <div className="small bold row-tight pw-plain-head"><ShieldAlert size={14} aria-hidden="true" />{t('Unencrypted – only for moving')}</div>
            <div className="row pw-plain">{PLAIN.map(([k, l]) => <Btn key={k} className="sm ghost" icon={Download} busy={busy === k} onClick={() => exportPlain(k, l)}>{t(l)}</Btn>)}</div>
          </div>
          {others.length > 0 && <div className="card-body row pw-transfer"><span className="small">{t('Copy into another vault:')}</span><select className="select sm" aria-label={t('Target vault')} value={to} onChange={(e) => setTo(e.target.value)}><option value="">{t('choose …')}</option>{others.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select><Btn className="sm" icon={ArrowRightLeft} disabled={!to} onClick={async () => { try { const r = await post(`/pw/${v.id}/transfer`, { to }); toast.success(t('{n} items copied', { n: r.copied })); } catch (e) { toast.error(e.message); } }}>Copy</Btn></div>}
        </div>
        {v.type === 'hostwerk' && <div className="card"><div className="card-head"><ArchiveRestore size={16} aria-hidden="true" /><h3>Backups</h3><InfoTip>{t('Hostwerk copies the encrypted vault file once a day when it changed and keeps 14 copies. They show up in the backup centre, where you can restore them – without the master password they are useless to anyone else.')}</InfoTip></div>
          <div className="card-body row"><Btn className="sm" icon={ArchiveRestore} busy={busy === 'backup'} onClick={async () => { setBusy('backup'); try { await post(`/pw/${v.id}/backup`); toast.success(t('Backup created')); } catch (e) { toast.error(e.message); } setBusy(null); }}>Back up now</Btn><a className="btn sm ghost" href="#/sicherungen">{t('Open the backup centre')}</a></div>
        </div>}
      </div>
      <div className="card">
        <div className="card-head"><Info size={16} aria-hidden="true" /><h3>How to get your data</h3><span className="small muted">{t('{n} services in the catalogue', { n: cat.length })}</span></div>
        <div className="card-body stack pw-cat">{cat.filter((p) => p.way !== 'native' || p.id === 'vaultwarden').map((p) => <div key={p.id} className="small"><b>{p.name}</b> <span className="badge">{t(WAY[p.way] || 'direct')}</span><div className="tiny muted">{p.text}</div></div>)}</div>
      </div>
    </div>
  );
}
