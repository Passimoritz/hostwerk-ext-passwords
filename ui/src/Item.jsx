import { useEffect, useRef, useState } from 'react';
import { Star, Trash2, Copy, Eye, EyeOff, RefreshCw, Globe, StickyNote, CreditCard, User, Wand2, Plus, ExternalLink, History, Users, KeySquare, Fingerprint, Paperclip, Download, ClipboardPaste, ImageUp, Folder, Clock, Terminal, Upload, Save } from 'lucide-react';
import { get, post, put, del, fmtDate, openExternal } from '@hostwerk/api';
import { Btn, Field, Seg, Loading, Modal, toast, confirmDialog, promptDialog, InfoTip } from '@hostwerk/ui';
import { t } from '@hostwerk/i18n';
import jsQR from 'jsqr';
import { ShareDialog } from './Share';

/*
 * Einzelner Eintrag: Anzeige (Kopierfelder, Anzeigen/Verbergen, 2FA-Code mit Ablaufring, Verlauf, Passkeys, Anhänge,
 * SSH-Schlüssel) und Bearbeiten (alle Arten, QR-Code aus Bild oder Zwischenablage, SSH-Schlüssel erzeugen) – dazu die
 * kleinen Bausteine, die Liste und Werkzeuge teilen (Kopieren mit Leeren der Zwischenablage, Stärke, Webseiten-Symbol).
 */
export const TYPE_ICON = { login: Globe, note: StickyNote, card: CreditCard, identity: User, ssh: KeySquare };
export const TYPE_LABEL = { login: 'Login', note: 'Note', card: 'Card', identity: 'Identity', ssh: 'SSH key' };

/* ---------- clipboard: cleared again after the set time (only if the same value is still there) ---------- */
export const clip = { sec: 30 };
export const clearLater = (text) => { if (!clip.sec) return; setTimeout(async () => { try { const cur = await navigator.clipboard.readText(); if (cur === text) await navigator.clipboard.writeText(''); } catch { /* without read access: better not overwrite anything */ } }, clip.sec * 1000); };
export const copy = async (text, what) => {
  try { await navigator.clipboard.writeText(text); clearLater(text); toast.success(clip.sec ? t('{what} – cleared from the clipboard in {n} seconds', { what: what || t('Copied'), n: clip.sec }) : (what || t('Copied'))); } catch { toast.error(t('Clipboard not available')); }
};

const SCORE_COLOR = ['var(--err)', 'var(--err)', 'var(--warn)', 'var(--ok)', 'var(--ok)'];
export function Strength({ s }) {
  if (!s) return null;
  const col = SCORE_COLOR[s.score];
  return <div className="pw-strength"><div className="bar" role="meter" aria-valuemin={0} aria-valuemax={4} aria-valuenow={s.score} aria-label={t('Password strength')}><div style={{ width: `${(s.score + 1) * 20}%`, background: col }} /></div><span className="tiny" style={{ color: col }}>{s.label}{s.hints && s.hints.length ? ` · ${s.hints.join(', ')}` : ''}</span></div>;
}
const SCORE_LABEL = ['very weak', 'weak', 'medium', 'strong', 'very strong'];
/** Small dot in the list: red weak, amber medium, green strong (with text for screen readers and the tooltip). */
export function StrengthDot({ score }) {
  if (score == null) return null;
  const k = score <= 1 ? 'weak' : score === 2 ? 'fair' : 'strong';
  return <span className={`pw-dot pw-dot-${k}`} role="img" aria-label={t('Password: {label}', { label: t(SCORE_LABEL[score]) })} title={t('Password: {label}', { label: t(SCORE_LABEL[score]) })} />;
}

/** Website icon (cached locally by Hostwerk) – otherwise the first letter on a colour from the name. */
export function SiteIcon({ host, name, type, size = 32 }) {
  const [bad, setBad] = useState(false);
  useEffect(() => setBad(false), [host]);
  const I = TYPE_ICON[type] || Globe;
  const hue = [...String(name || '?')].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 360, 7);
  if (host && !bad && type === 'login') return <img className="pw-ico" src={`/api/pw/icon/${encodeURIComponent(host)}`} alt="" width={size} height={size} loading="lazy" onError={() => setBad(true)} />;
  return <span className="pw-ico pw-ico-letter" aria-hidden="true" style={{ width: size, height: size, '--pw-hue': hue }}>{type === 'login' || !type ? String(name || '?').trim().charAt(0).toUpperCase() || '?' : <I size={Math.round(size * 0.5)} />}</span>;
}

/* ---------- TOTP: computed in the browser (WebCrypto), otherwise asked from Hostwerk every second ---------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function parseOtp(input) {
  const s = String(input || '').trim();
  if (/^otpauth:\/\//i.test(s)) { try { const u = new URL(s); return { secret: u.searchParams.get('secret') || '', digits: Number(u.searchParams.get('digits')) || 6, period: Number(u.searchParams.get('period')) || 30, algorithm: (u.searchParams.get('algorithm') || 'SHA1').toUpperCase() }; } catch { /* below */ } }
  return { secret: s.replace(/\s+/g, ''), digits: 6, period: 30, algorithm: 'SHA1' };
}
async function totpLocal(input, at = Date.now()) {
  const o = parseOtp(input);
  const clean = o.secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
  if (!clean || !(globalThis.crypto && crypto.subtle)) return null;
  let bits = 0; let value = 0; const key = [];
  for (const ch of clean) { value = (value << 5) | B32.indexOf(ch); bits += 5; if (bits >= 8) { key.push((value >>> (bits - 8)) & 0xff); bits -= 8; } }
  const counter = Math.floor(at / 1000 / o.period);
  const msg = new DataView(new ArrayBuffer(8)); msg.setUint32(0, Math.floor(counter / 2 ** 32)); msg.setUint32(4, counter >>> 0);
  const hash = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }[o.algorithm] || 'SHA-1';
  const k = await crypto.subtle.importKey('raw', new Uint8Array(key), { name: 'HMAC', hash }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', k, msg.buffer));
  const off = h[h.length - 1] & 0xf;
  const num = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return { code: String(num % 10 ** o.digits).padStart(o.digits, '0'), period: o.period, remaining: o.period - (Math.floor(at / 1000) % o.period) };
}
export function TotpCode({ secret, vault, item }) {
  const [c, setC] = useState(null);
  useEffect(() => {
    let live = true;
    const tick = async () => { let r = null; try { r = await totpLocal(secret); } catch { r = null; } if (!r && vault && item) r = await get(`/pw/${vault}/items/${item}/totp`).catch(() => null); if (live) setC(r && r.code ? r : null); };
    tick(); const x = setInterval(tick, 1000);
    return () => { live = false; clearInterval(x); };
  }, [secret, vault, item]);
  if (!c) return <span className="tiny muted">{t('No valid 2FA secret')}</span>;
  const frac = c.remaining / c.period;
  const R = 9; const L = 2 * Math.PI * R;
  const pretty = c.code.length === 6 ? `${c.code.slice(0, 3)} ${c.code.slice(3)}` : c.code;
  return (
    <div className="row-tight pw-totp-row">
      <button type="button" className="pw-totp-code mono" onClick={() => copy(c.code, t('Code copied'))} aria-label={t('Copy 2FA code {code}', { code: c.code })}>{pretty}</button>
      <svg className={`pw-ring ${c.remaining <= 5 ? 'pw-ring-ending' : ''}`} width="24" height="24" viewBox="0 0 24 24" role="img" aria-label={t('{n} s left', { n: c.remaining })}><circle cx="12" cy="12" r={R} className="pw-ring-bg" /><circle cx="12" cy="12" r={R} className="pw-ring-fg" strokeDasharray={L} strokeDashoffset={L * (1 - frac)} transform="rotate(-90 12 12)" /></svg>
      <span className="tiny muted" aria-hidden="true">{c.remaining}s</span>
    </div>
  );
}

/* ---------- QR code of a 2FA setup: from an image file or the clipboard (jsQR, all in the browser) ---------- */
async function qrFromBlob(blob) {
  const bmp = await createImageBitmap(blob);
  const scale = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
  const cv = document.createElement('canvas'); cv.width = Math.round(bmp.width * scale); cv.height = Math.round(bmp.height * scale);
  const g = cv.getContext('2d'); g.drawImage(bmp, 0, 0, cv.width, cv.height);
  const img = g.getImageData(0, 0, cv.width, cv.height);
  const r = jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
  return r ? r.data : null;
}
export function QrButtons({ onResult }) {
  const file = useRef(null);
  const take = (text) => {
    if (!text) { toast.error(t('No QR code found in the image.')); return; }
    if (/^otpauth-migration:/i.test(text)) { toast.error(t('This is a Google Authenticator transfer code – please scan the QR code of the website itself.')); return; }
    if (!/^otpauth:\/\/totp\//i.test(text)) { toast.error(t('The QR code holds no 2FA setup (otpauth://totp/…).')); return; }
    onResult(text); toast.success(t('2FA secret taken from the QR code'));
  };
  const fromClipboard = async () => {
    try {
      const items = await navigator.clipboard.read();
      for (const it of items) { const ty = it.types.find((x) => x.startsWith('image/')); if (ty) { take(await qrFromBlob(await it.getType(ty))); return; } }
      const txt = await navigator.clipboard.readText().catch(() => '');
      if (/^otpauth:/i.test(txt.trim())) take(txt.trim()); else toast.error(t('No image in the clipboard – copy the QR code first (e.g. with Win+Shift+S).'));
    } catch { toast.error(t('Clipboard not available')); }
  };
  return (
    <div className="row-tight">
      <input ref={file} type="file" accept="image/*" hidden onChange={async (e) => { const f = e.target.files[0]; e.target.value = ''; if (f) { try { take(await qrFromBlob(f)); } catch { toast.error(t('The image cannot be read.')); } } }} />
      <Btn className="xs" icon={ImageUp} onClick={() => file.current.click()}>QR from image</Btn>
      <Btn className="xs ghost" icon={ClipboardPaste} onClick={fromClipboard}>QR from clipboard</Btn>
    </div>
  );
}

/* ---------- generator (also used inside the editor) ---------- */
export function Generator({ onUse, site: initialSite = '' }) {
  const [opts, setOpts] = useState({ length: 20, lower: true, upper: true, digits: true, symbols: true, words: 0 });
  const [out, setOut] = useState(null);
  const [site, setSite] = useState(initialSite);
  const gen = async (o = opts) => setOut(await post('/pw/generate', o));
  // Neu erzeugen, sobald sich eine Einstellung ändert (auch beim ersten Anzeigen)
  useEffect(() => { const x = setTimeout(() => gen(opts), 120); return () => clearTimeout(x); }, [opts]); // eslint-disable-line react-hooks/exhaustive-deps
  // Regel der Seite übernehmen (falls es eine gibt)
  useEffect(() => { if (!initialSite) return; post('/pw/generate', { url: initialSite }).then((r) => { if (r.rule) get('/pw/gen-rules').then((rules) => { const o = rules[r.rule]; if (o) setOpts(o); }); }).catch(() => {}); }, [initialSite]);
  const saveRule = async () => { try { await put('/pw/gen-rules', { site, opts }); toast.success(t('Rule saved for {site}', { site })); } catch (e) { toast.error(e.message); } };
  return (
    <div className="stack pw-gen-box">
      <div className="row"><button type="button" className="grow pw-gen mono" onClick={() => out && copy(out.password)} aria-label={t('Copy the generated password')}>{out ? out.password : '…'}</button><Btn className="sm" icon={RefreshCw} onClick={() => gen()}>New</Btn>{onUse && <Btn className="sm primary" onClick={() => out && onUse(out.password)}>Use</Btn>}</div>
      {out && <Strength s={out.strength} />}
      <Seg value={opts.words ? 'words' : 'chars'} onChange={(v) => setOpts({ ...opts, words: v === 'words' ? 4 : 0 })} options={[{ id: 'chars', label: t('Characters') }, { id: 'words', label: t('Words (passphrase)') }]} />
      {opts.words ? <label className="small row-tight">{t('Words')} <input className="input xs pw-num" type="number" min={3} max={10} value={opts.words} onChange={(e) => setOpts({ ...opts, words: Number(e.target.value) })} /></label>
        : <div className="row pw-gen-opts"><label className="small row-tight">{t('Length')} <input className="input xs pw-num" type="number" min={8} max={128} value={opts.length} onChange={(e) => setOpts({ ...opts, length: Number(e.target.value) })} /></label>{[['upper', 'A–Z'], ['lower', 'a–z'], ['digits', '0–9'], ['symbols', '!@#']].map(([k, l]) => <label key={k} className="check small"><input type="checkbox" checked={opts[k]} onChange={(e) => setOpts({ ...opts, [k]: e.target.checked })} />{l}</label>)}</div>}
      <div className="row-tight pw-gen-rule"><input className="input sm grow" aria-label={t('Website for a rule')} placeholder={t('Website, e.g. bank.example')} value={site} onChange={(e) => setSite(e.target.value)} /><Btn className="sm ghost" icon={Save} disabled={!site.trim()} onClick={saveRule}>Rule for this site</Btn><InfoTip>{t('Some sites only allow certain characters or lengths. A rule remembers these settings – the browser extension and this generator use them for the site and its subdomains.')}</InfoTip></div>
    </div>
  );
}

/* ---------- detail view ---------- */
function Row({ label, value, secret, shown, mono = true, link, multiline }) {
  if (!value) return null;
  const vis = !secret || shown;
  return (
    <div className="pw-row">
      <span className="pw-row-label">{label}</span>
      <div className="row-tight">
        {multiline ? <pre className={`pw-row-value grow ${mono ? 'mono' : ''}`}>{vis ? value : '••••••••••'}</pre> : <span className={`pw-row-value grow ellipsis ${mono ? 'mono' : ''}`}>{vis ? value : '••••••••••'}</span>}
        {link && <button type="button" className="btn ghost xs icon" title={t('Open')} aria-label={t('Open {label}', { label })} onClick={() => openExternal(/^https?:\/\//.test(value) ? value : `https://${value}`)}><ExternalLink /></button>}
        <button type="button" className="btn ghost xs icon" title={t('Copy')} aria-label={t('Copy {label}', { label })} onClick={() => copy(value, t('{label} copied', { label }))}><Copy /></button>
      </div>
    </div>
  );
}
const IDENTITY = [['title', 'Title'], ['firstName', 'First name'], ['lastName', 'Last name'], ['company', 'Company'], ['email', 'E-mail'], ['phone', 'Phone'], ['birthday', 'Birthday'], ['address', 'Street'], ['zip', 'Postcode'], ['city', 'City'], ['state', 'State / region'], ['country', 'Country'], ['passport', 'Passport number'], ['license', 'Driving licence'], ['taxId', 'Tax / social security number']];
const fmtSize = (n) => (n > 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`);
const toB64 = (file) => new Promise((ok, fail) => { const r = new FileReader(); r.onload = () => ok(String(r.result).split(',')[1] || ''); r.onerror = fail; r.readAsDataURL(file); });

export function ItemView({ v, id, onEdit, onChanged, onBack }) {
  const [it, setIt] = useState(null);
  const [sharing, setSharing] = useState(false);
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(null);
  const file = useRef(null);
  const load = () => get(`/pw/${v.id}/items/${id}`).then(setIt).catch((e) => toast.error(e.message));
  useEffect(() => { setIt(null); setShow(false); load(); }, [v.id, id]); // eslint-disable-line react-hooks/exhaustive-deps
  // Hide shown secrets again after 20 s
  useEffect(() => { if (!show) return undefined; const x = setTimeout(() => setShow(false), 20000); return () => clearTimeout(x); }, [show]);
  if (!it) return <div className="pw-detail-card"><Loading /></div>;
  const own = v.type === 'hostwerk';
  const remove = async () => { if (await confirmDialog({ title: own ? t('Move “{name}” to the trash?', { name: it.name }) : t('Delete “{name}”?', { name: it.name }), confirm: t('Yes'), danger: !own })) { try { await del(`/pw/${v.id}/items/${id}`); onChanged(null); } catch (e) { toast.error(e.message); } } };
  const fav = async () => { try { const r = await put(`/pw/${v.id}/items/${id}`, { ...it, favorite: !it.favorite, passkeys: undefined }); setIt({ ...it, favorite: r.favorite }); onChanged(id); } catch (e) { toast.error(e.message); } };
  const addFile = async (f) => {
    if (!f) return;
    if (f.size > 5 * 1048576) { toast.error(t('Attachments can be at most {mb} MB.', { mb: 5 })); return; }
    setBusy('file');
    try { await post(`/pw/${v.id}/items/${id}/files`, { name: f.name, mime: f.type, data: await toB64(f) }); toast.success(t('{name} attached (encrypted)', { name: f.name })); load(); onChanged(id); } catch (e) { toast.error(e.message); }
    setBusy(null);
  };
  const getFile = async (a) => {
    const res = await fetch(`/api/pw/${v.id}/items/${id}/files/${a.id}`);
    if (!res.ok) { toast.error(t('The attachment cannot be opened.')); return; }
    const url = URL.createObjectURL(await res.blob()); const el = document.createElement('a'); el.href = url; el.download = a.name; el.click(); setTimeout(() => URL.revokeObjectURL(url), 10000);
  };
  const dropFile = async (a) => { if (!(await confirmDialog({ title: t('Remove “{name}”?', { name: a.name }), confirm: t('Remove'), danger: true }))) return; await del(`/pw/${v.id}/items/${id}/files/${a.id}`); load(); onChanged(id); };
  const dropPasskey = async (p) => { if (!(await confirmDialog({ title: t('Remove the passkey for {rp}?', { rp: p.rpId }), text: t('Signing in with this passkey no longer works from an export of this vault. The passkey in your browser or phone stays.'), confirm: t('Remove'), danger: true }))) return; await del(`/pw/${v.id}/items/${id}/passkeys`, { credentialId: p.credentialId }); load(); };
  const sshInstall = async () => {
    const name = await promptDialog({ title: t('Hand the key to Hostwerk'), text: t('Hostwerk saves it as a file in your SSH folder ({dir}) – then it shows up under SSH keys and works for Git, SFTP and publishing. Existing files are never overwritten.', { dir: '~/.ssh' }), label: t('File name'), value: `id_${(it.ssh.keyType || 'key').replace(/^ssh-/, '').replace(/\W/g, '')}_${it.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 30)}`, confirm: t('Save') });
    if (!name) return;
    try { const r = await post(`/pw/${v.id}/items/${id}/ssh-install`, { name }); toast.success(t('Saved as {path}', { path: r.path })); } catch (e) { toast.error(e.message); }
  };
  const I = TYPE_ICON[it.type] || Globe;
  return (
    <div className="pw-detail-card">
      <div className="pw-detail-head">
        {onBack && <button type="button" className="btn ghost sm pw-back" onClick={onBack} aria-label={t('Back to the list')}>←</button>}
        <SiteIcon host={(it.urls || [])[0] ? (() => { try { return new URL(/^https?:\/\//.test(it.urls[0]) ? it.urls[0] : `https://${it.urls[0]}`).hostname; } catch { return ''; } })() : ''} name={it.name} type={it.type} size={40} />
        <div className="grow pw-detail-title"><h2 className="ellipsis">{it.name}</h2><div className="tiny muted row-tight"><I size={12} aria-hidden="true" />{t(TYPE_LABEL[it.type] || 'Login')}{it.folder && <><Folder size={12} aria-hidden="true" />{it.folder}</>}</div></div>
        <div className="row-tight pw-detail-actions">
          {!v.readonly && <button type="button" className={`btn ghost sm icon ${it.favorite ? 'pw-fav-on' : ''}`} aria-pressed={!!it.favorite} title={it.favorite ? t('Remove from favourites') : t('Add to favourites')} aria-label={it.favorite ? t('Remove from favourites') : t('Add to favourites')} onClick={fav}><Star /></button>}
          {own && <button type="button" className="btn ghost sm icon" title={t('Share with members')} aria-label={t('Share with members')} onClick={() => setSharing(true)}><Users /></button>}
          <button type="button" className="btn ghost sm icon" title={show ? t('Hide') : t('Show')} aria-label={show ? t('Hide secrets') : t('Show secrets')} aria-pressed={show} onClick={() => setShow(!show)}>{show ? <EyeOff /> : <Eye />}</button>
          {!v.readonly && <Btn className="sm" onClick={() => onEdit(it)}>Edit</Btn>}
          {!v.readonly && <button type="button" className="btn ghost sm icon" title={own ? t('To the trash') : t('Delete')} aria-label={own ? t('To the trash') : t('Delete')} onClick={remove}><Trash2 /></button>}
        </div>
      </div>
      <div className="pw-detail-body">
        <section className="pw-sec">
          <Row label={t('Username')} value={it.username} />
          <Row label={t('Password')} value={it.password} secret shown={show} />
          {it.password && it.pwStrength && <Strength s={it.pwStrength} />}
          {it.totp && <div className="pw-row"><span className="pw-row-label">{t('2FA code')}</span><TotpCode secret={it.totp} vault={v.id} item={id} /></div>}
          {(it.urls || []).map((u, i) => <Row key={u + i} label={i ? t('Address {n}', { n: i + 1 }) : t('Address')} value={u} link />)}
        </section>
        {it.card && <section className="pw-sec">{[[t('Holder'), it.card.holder, false], [t('Number'), it.card.number, true], [t('Valid until'), it.card.expiry, false], ['CVV', it.card.cvv, true], ['PIN', it.card.pin, true], [t('Brand'), it.card.brand, false]].map(([l, val, s]) => <Row key={l} label={l} value={val} secret={s} shown={show} />)}</section>}
        {it.identity && <section className="pw-sec">{IDENTITY.map(([k, l]) => <Row key={k} label={t(l)} value={it.identity[k]} mono={false} />)}</section>}
        {it.ssh && <section className="pw-sec">
          <Row label={t('Public key')} value={it.ssh.publicKey} />
          <Row label={t('Fingerprint')} value={it.ssh.fingerprint} />
          <Row label={t('Private key')} value={it.ssh.privateKey} secret shown={show} multiline />
          {own && it.ssh.privateKey && <div><Btn className="sm" icon={Terminal} onClick={sshInstall}>Hand to Hostwerk’s SSH keys</Btn></div>}
        </section>}
        {(it.fields || []).length > 0 && <section className="pw-sec"><h3 className="pw-sec-title">{t('Extra fields')}</h3>{it.fields.map((f, i) => <Row key={i} label={f.name} value={f.value} secret={f.hidden} shown={show} />)}</section>}
        {it.notes && <section className="pw-sec"><h3 className="pw-sec-title">{t('Notes')}</h3><pre className="pw-notes">{it.notes}</pre><button type="button" className="btn ghost xs" onClick={() => copy(it.notes, t('Notes copied'))}><Copy />{t('Copy')}</button></section>}
        {(it.passkeys || []).length > 0 && <section className="pw-sec"><h3 className="pw-sec-title"><Fingerprint size={14} aria-hidden="true" /> {t('Passkeys')} <InfoTip>{t('Passkeys come along when you import from Bitwarden or KeePassXC and go out again with their exports. Signing in with them works in your browser or phone – Hostwerk keeps them safe.')}</InfoTip></h3>
          {it.passkeys.map((p) => <div key={p.credentialId} className="pw-line"><Fingerprint size={16} aria-hidden="true" /><div className="grow small"><b>{p.rpName || p.rpId}</b> · {p.userName || p.userDisplayName || '–'}<div className="tiny muted">{p.rpId}{p.creationDate ? ` · ${fmtDate(Date.parse(p.creationDate))}` : ''}</div></div>{own && <button type="button" className="btn ghost xs icon" aria-label={t('Remove the passkey for {rp}', { rp: p.rpId })} title={t('Remove')} onClick={() => dropPasskey(p)}><Trash2 /></button>}</div>)}
        </section>}
        {own && <section className="pw-sec"><h3 className="pw-sec-title"><Paperclip size={14} aria-hidden="true" /> {t('Attachments')} <InfoTip>{t('Encrypted with the vault – at most 5 MB per file and 50 MB per vault. Good for recovery codes, key files or a scan of an ID.')}</InfoTip></h3>
          {(it.attachments || []).map((a) => <div key={a.id} className="pw-line"><Paperclip size={16} aria-hidden="true" /><span className="grow small ellipsis">{a.name} <span className="muted tiny">{fmtSize(a.size)}</span></span><button type="button" className="btn ghost xs icon" title={t('Download')} aria-label={t('Download {name}', { name: a.name })} onClick={() => getFile(a)}><Download /></button><button type="button" className="btn ghost xs icon" title={t('Remove')} aria-label={t('Remove {name}', { name: a.name })} onClick={() => dropFile(a)}><Trash2 /></button></div>)}
          <input ref={file} type="file" hidden onChange={(e) => { const f = e.target.files[0]; e.target.value = ''; addFile(f); }} />
          <div><Btn className="xs ghost" icon={Upload} busy={busy === 'file'} onClick={() => file.current.click()}>Attach a file</Btn></div>
        </section>}
        {(it.history || []).length > 0 && <section className="pw-sec"><details><summary className="small"><History size={14} aria-hidden="true" /> {t('{n} earlier passwords', { n: it.history.length })}</summary>{it.history.map((h, i) => <div key={i} className="pw-line"><span className="grow mono small ellipsis">{show ? h.password : '••••••••'}</span><span className="tiny muted">{h.until ? t('until {date}', { date: fmtDate(h.until) }) : ''}</span><button type="button" className="btn ghost xs icon" title={t('Copy')} aria-label={t('Copy earlier password')} onClick={() => copy(h.password, t('Earlier password copied'))}><Copy /></button></div>)}</details></section>}
        <div className="tiny muted row pw-meta">{(it.tags || []).map((x) => <span key={x} className="badge">{x}</span>)}{it.updated && <span><Clock size={11} aria-hidden="true" /> {t('changed {date}', { date: fmtDate(it.updated) })}</span>}{it.passwordChanged && it.password && <span>{t('password from {date}', { date: fmtDate(it.passwordChanged) })}</span>}{it.created && <span>{t('created {date}', { date: fmtDate(it.created) })}</span>}</div>
      </div>
      {sharing && <ShareDialog vault={v.id} item={it.id} name={it.name} onClose={() => setSharing(false)} />}
    </div>
  );
}

/* ---------- editor ---------- */
const EMPTY = { type: 'login', name: '', username: '', password: '', url: '', urls: [], notes: '', totp: '', folder: '', tags: [], fields: [], favorite: false, card: {}, identity: {}, ssh: {} };
export function ItemDialog({ v, item, preset = 'login', onClose, onSaved }) {
  const [f, setF] = useState(() => (item ? { ...EMPTY, ...item, url: (item.urls || [])[0] || '', urls: item.urls || [], card: item.card || {}, identity: item.identity || {}, ssh: item.ssh || {} } : { ...EMPTY, type: preset }));
  const [show, setShow] = useState(false);
  const [gen, setGen] = useState(false);
  const [st, setSt] = useState(null);
  const [busy, setBusy] = useState(false);
  const own = v.type === 'hostwerk';
  useEffect(() => { const x = setTimeout(() => { if (f.password) post('/pw/strength', { password: f.password }).then(setSt).catch(() => {}); else setSt(null); }, 250); return () => clearTimeout(x); }, [f.password]);
  const set = (k, val) => setF((o) => ({ ...o, [k]: val }));
  const sub = (k, key, val) => setF((o) => ({ ...o, [k]: { ...o[k], [key]: val } }));
  const save = async () => {
    setBusy(true);
    try {
      const { passkeys, attachments, history, pwStrength, ...rest } = f; // eslint-disable-line no-unused-vars
      const body = { ...rest, urls: [f.url, ...f.urls.slice(1)].filter(Boolean) };
      const r = item ? await put(`/pw/${v.id}/items/${item.id}`, body) : await post(`/pw/${v.id}/items`, body);
      toast.success(item ? t('Saved') : t('Created'));
      onSaved(r);
    } catch (e) { toast.error(e.message); }
    setBusy(false);
  };
  const newKey = async () => { try { const k = await post('/pw/ssh/generate', { comment: f.name || 'hostwerk' }); setF((o) => ({ ...o, ssh: k })); toast.success(t('New ed25519 key created')); } catch (e) { toast.error(e.message); } };
  const readKey = async () => { if (!f.ssh.privateKey && !f.ssh.publicKey) return; try { const k = await post('/pw/ssh/describe', f.ssh); setF((o) => ({ ...o, ssh: { ...o.ssh, ...k } })); } catch (e) { toast.error(e.message); } };
  const host = (() => { try { return f.url ? new URL(/^https?:\/\//.test(f.url) ? f.url : `https://${f.url}`).hostname : ''; } catch { return ''; } })();
  const T = f.type;
  const types = Object.entries(TYPE_LABEL).filter(([id]) => own || id !== 'ssh');
  return (
    <Modal title={item ? t('Edit {name}', { name: item.name }) : t('New item')} onClose={onClose} size="lg" footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" busy={busy} disabled={!f.name.trim()} onClick={save}>Save</Btn></>}>
      <div className="stack">
        {!item && <Seg value={T} onChange={(x) => set('type', x)} options={types.map(([id, label]) => ({ id, label: t(label), icon: TYPE_ICON[id] }))} />}
        <div className="form-grid">
          <Field label="Name" className="span-2"><input className="input" value={f.name} onChange={(e) => set('name', e.target.value)} autoFocus /></Field>
          {T === 'login' && <>
            <Field label="Username / e-mail"><input className="input" autoComplete="off" value={f.username} onChange={(e) => set('username', e.target.value)} /></Field>
            <Field label="Address (URL)"><input className="input mono" value={f.url} onChange={(e) => set('url', e.target.value)} placeholder="https://…" /></Field>
            <Field label="Password" className="span-2"><div className="row-tight"><input className="input mono grow" autoComplete="new-password" type={show ? 'text' : 'password'} aria-label={t('Password')} value={f.password} onChange={(e) => set('password', e.target.value)} /><button type="button" className="btn ghost sm icon" aria-label={show ? t('Hide') : t('Show')} title={show ? t('Hide') : t('Show')} onClick={() => setShow(!show)}>{show ? <EyeOff /> : <Eye />}</button><Btn className="sm" icon={Wand2} aria-expanded={gen} onClick={() => setGen(!gen)}>Generate</Btn></div><Strength s={st} />{gen && <div className="card pw-gen-inline"><div className="card-body"><Generator site={host} onUse={(p) => { set('password', p); setGen(false); }} /></div></div>}</Field>
            <Field label="2FA (TOTP secret or otpauth:// address)" className="span-2"><div className="stack pw-gap-1"><input className="input mono" value={f.totp} onChange={(e) => set('totp', e.target.value)} placeholder="JBSWY3DPEHPK3PXP / otpauth://totp/…" /><QrButtons onResult={(x) => set('totp', x)} />{f.totp && <TotpCode secret={f.totp} />}</div></Field>
          </>}
          {T === 'card' && <>
            <Field label="Card holder"><input className="input" value={f.card.holder || ''} onChange={(e) => sub('card', 'holder', e.target.value)} /></Field>
            <Field label="Brand"><input className="input" value={f.card.brand || ''} onChange={(e) => sub('card', 'brand', e.target.value)} placeholder="Visa, Mastercard …" /></Field>
            <Field label="Card number"><input className="input mono" inputMode="numeric" autoComplete="off" value={f.card.number || ''} onChange={(e) => sub('card', 'number', e.target.value)} /></Field>
            <Field label="Valid until / security code"><div className="row-tight"><input className="input mono" aria-label={t('Valid until')} placeholder={t('MM/YY')} value={f.card.expiry || ''} onChange={(e) => sub('card', 'expiry', e.target.value)} /><input className="input mono" aria-label="CVV" placeholder="CVV" type="password" autoComplete="off" value={f.card.cvv || ''} onChange={(e) => sub('card', 'cvv', e.target.value)} /><input className="input mono" aria-label="PIN" placeholder="PIN" type="password" autoComplete="off" value={f.card.pin || ''} onChange={(e) => sub('card', 'pin', e.target.value)} /></div></Field>
          </>}
          {T === 'identity' && IDENTITY.map(([k, l]) => <Field key={k} label={t(l)}><input className="input" value={f.identity[k] || ''} onChange={(e) => sub('identity', k, e.target.value)} /></Field>)}
          {T === 'ssh' && <>
            <div className="span-2 row-tight"><Btn className="sm" icon={KeySquare} onClick={newKey}>Create a new key (ed25519)</Btn><span className="tiny muted">{t('or paste an existing private key below')}</span></div>
            <Field label="Private key" className="span-2"><textarea className="input mono" rows={6} spellCheck={false} value={f.ssh.privateKey || ''} onChange={(e) => sub('ssh', 'privateKey', e.target.value)} onBlur={readKey} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" /></Field>
            <Field label="Public key" className="span-2"><textarea className="input mono" rows={2} spellCheck={false} value={f.ssh.publicKey || ''} onChange={(e) => sub('ssh', 'publicKey', e.target.value)} onBlur={readKey} placeholder="ssh-ed25519 AAAA…" /></Field>
            {f.ssh.fingerprint && <div className="span-2 tiny muted mono">{f.ssh.fingerprint}</div>}
          </>}
          <Field label="Folder"><input className="input" value={f.folder} onChange={(e) => set('folder', e.target.value)} list="pw-folders" placeholder={t('e.g. Work/Servers')} /></Field>
          <Field label="Tags (comma)"><input className="input" value={(f.tags || []).join(', ')} onChange={(e) => set('tags', e.target.value.split(',').map((x) => x.trim()).filter(Boolean))} /></Field>
          <Field label={T === 'note' ? t('Note') : t('Notes')} className="span-2"><textarea className="input" rows={T === 'note' ? 10 : 3} value={f.notes} onChange={(e) => set('notes', e.target.value)} /></Field>
        </div>
        <div>
          <div className="small bold">{t('Extra fields')}</div>
          {(f.fields || []).map((x, i) => <div key={i} className="row-tight pw-field-row"><input className="input sm" aria-label={t('Field name')} placeholder={t('Name')} value={x.name} onChange={(e) => { const n = [...f.fields]; n[i] = { ...x, name: e.target.value }; set('fields', n); }} /><input className="input sm mono grow" aria-label={t('Field value')} type={x.hidden && !show ? 'password' : 'text'} placeholder={t('Value')} value={x.value} onChange={(e) => { const n = [...f.fields]; n[i] = { ...x, value: e.target.value }; set('fields', n); }} /><label className="check tiny"><input type="checkbox" checked={!!x.hidden} onChange={(e) => { const n = [...f.fields]; n[i] = { ...x, hidden: e.target.checked }; set('fields', n); }} />{t('secret')}</label><button type="button" className="btn ghost xs icon" aria-label={t('Remove field')} title={t('Remove field')} onClick={() => set('fields', f.fields.filter((_, k) => k !== i))}><Trash2 /></button></div>)}
          <button type="button" className="btn ghost xs pw-add-field" onClick={() => set('fields', [...(f.fields || []), { name: '', value: '', hidden: false }])}><Plus />{t('Field')}</button>
        </div>
        <label className="check small"><input type="checkbox" checked={!!f.favorite} onChange={(e) => set('favorite', e.target.checked)} />{t('Favourite')}</label>
      </div>
    </Modal>
  );
}
