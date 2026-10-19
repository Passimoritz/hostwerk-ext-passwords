import { useEffect, useState } from 'react';
import { Copy, Eye, EyeOff, KeyRound, Lock, Users, ShieldCheck } from 'lucide-react';
import { get, post, put, useApi, useRefresh } from '@hostwerk/api';
import { Btn, Empty, Loading, Modal, Seg, toast, useInterval } from '@hostwerk/ui';
import { t } from '@hostwerk/i18n';

const copyText = async (x, msg) => { try { await navigator.clipboard.writeText(x); toast.success(msg); setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 45000); } catch { toast.error('Copying is not possible'); } };

/** Share an item with members: per member "not", "view & copy" or "copy only". */
export function ShareDialog({ vault, item, name, onClose }) {
  const d = useApi(`/pw/${vault}/items/${item}/share`, [], { live: false });
  const [users, setUsers] = useState(null);
  const [until, setUntil] = useState({});
  useEffect(() => { if (d.data && !users) { setUsers(d.data.users || {}); setUntil(d.data.until || {}); } }, [d.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const save = async () => { try { const u = Object.fromEntries(Object.entries(until).filter(([k, v]) => users[k] && v)); await put(`/pw/${vault}/items/${item}/share`, { users, until: u }); toast.success(Object.keys(users).length ? t('Share saved') : t('No longer shared')); onClose(); } catch (e) { toast.error(e.message); } };
  // Time limit: "no end" or a day (until 23:59 of that day)
  const dayValue = (x) => (x ? new Date(x - new Date(x).getTimezoneOffset() * 60000).toISOString().slice(0, 10) : '');
  const setDay = (uid, v) => setUntil((x) => ({ ...x, [uid]: v ? new Date(`${v}T23:59:00`).getTime() : null }));
  const today = dayValue(Date.now());
  return (
    <Modal title={t('Share “{name}”', { name })} subtitle="Members see the login in their view “Shared with me” – only while your vault is unlocked. Every access is in the change log." onClose={onClose}
      footer={<><Btn onClick={onClose}>Cancel</Btn><Btn className="primary" disabled={!users} onClick={save}>Save</Btn></>}>
      {!d.data || !users ? <Loading /> : d.data.members.length === 0
        ? <Empty icon={Users} title="No members yet" text="Members come with the “Team & users” extension (Go live → Users). Then you can share single logins with them here." />
        : <div className="stack" style={{ gap: 8 }}>{d.data.members.map((m) => (
          <div key={m.id} className="row-tight"><Users size={14} className="muted" /><b className="grow">{m.name}</b>
            <Seg value={users[m.id] || 'none'} onChange={(v) => setUsers((u) => { const n = { ...u }; if (v === 'none') delete n[m.id]; else n[m.id] = v; return n; })} options={[{ id: 'none', label: t('Not') }, { id: 'copy', label: t('Copy only') }, { id: 'read', label: t('View & copy') }]} />
            {users[m.id] && <label className="row-tight small" title={t('The share ends by itself at the end of this day')}>{t('until')} <input type="date" className="input" style={{ width: 'auto' }} min={today} value={dayValue(until[m.id])} onChange={(e) => setDay(m.id, e.target.value)} aria-label={t('Limit the share for {name}', { name: m.name })} />{until[m.id] && <button type="button" className="link-btn tiny" onClick={() => setDay(m.id, '')}>{t('no end')}</button>}</label>}
          </div>))}
          <div className="tiny muted">With a date the share ends by itself at the end of that day – ideal for helpers on the weekend. Without a date it stays until you end it.</div>
          <div className="tiny muted">“Copy only”: the password is never shown, only put on the clipboard (and cleared again after 45 s).</div>
        </div>}
    </Modal>
  );
}

/** "Shared with me" – for members. */
export function SharedWithMe({ compact = false }) {
  const [d, setD] = useState(null);
  const [shown, setShown] = useState({});
  const [codes, setCodes] = useState({});
  const [q, setQ] = useState('');
  const load = () => get('/pw/shared/mine').then(setD).catch((e) => setD({ items: [], error: e.message }));
  useEffect(() => { load(); }, []);
  useRefresh(load); // reload quietly after installs, changes and finished jobs
  useInterval(() => { get('/pw/shared/mine').then(setD).catch(() => {}); }, 20000);
  const reveal = (x) => post('/pw/shared/mine/reveal', { key: x.key });
  const act = async (x, what) => {
    try {
      const r = await reveal(x);
      if (what === 'user') return copyText(r.username, t('Username copied'));
      if (what === 'pass') return copyText(r.password, t('Password copied – cleared after 45 s'));
      if (what === 'show') { setShown((s) => ({ ...s, [x.key]: r.password })); setTimeout(() => setShown((s) => { const n = { ...s }; delete n[x.key]; return n; }), 20000); return undefined; }
      if (what === 'totp' && r.totp) { setCodes((c) => ({ ...c, [x.key]: r.totp })); return copyText(r.totp.code, t('2FA code copied')); }
    } catch (e) { toast.error(e.message); }
    return undefined;
  };
  if (!d) return <Loading />;
  const items = d.items.filter((x) => !q || `${x.name} ${x.username} ${(x.urls || []).join(' ')}`.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className={compact ? 'stack' : 'card'} style={compact ? { gap: 8 } : undefined}>
      {!compact && <div className="card-head"><ShieldCheck size={16} /><h3>Shared with me</h3><span className="badge">{d.items.length}</span></div>}
      <div className={compact ? '' : 'card-body stack'} style={{ gap: 8 }}>
        {d.items.length > 4 && <input className="input" aria-label={t('Search')} placeholder="Search …" value={q} onChange={(e) => setQ(e.target.value)} />}
        {d.items.length === 0 && <Empty icon={KeyRound} title="Nothing shared yet" text="When someone shares a login with you, it shows up here." />}
        {items.map((x) => x.locked ? (
          <div key={x.key} className="pw-shared-row muted"><Lock size={14} /><span className="grow small">{t('An item from “{vault}” – the vault is locked right now.', { vault: x.vaultName })}</span></div>
        ) : (
          <div key={x.key} className="pw-shared-row">
            <KeyRound size={14} className="muted" />
            <div className="grow" style={{ minWidth: 0 }}><b className="ellipsis">{x.name}</b>{x.until && <span className="badge warn" style={{ marginLeft: 6 }} title={t('The share ends by itself then')}>{t('until {date}', { date: new Date(x.until).toLocaleDateString() })}</span>}<div className="tiny muted ellipsis">{x.username}{x.urls && x.urls[0] ? ` · ${x.urls[0].replace(/^https?:\/\//, '')}` : ''}</div>{shown[x.key] && <div className="mono small">{shown[x.key]}</div>}{codes[x.key] && <div className="mono small">2FA: {codes[x.key].code}</div>}</div>
            {x.username && <button className="btn ghost xs icon" title="Copy username" aria-label={t('Copy username')} onClick={() => act(x, 'user')}><Copy /></button>}
            <button className="btn xs" title="Copy password" onClick={() => act(x, 'pass')}><KeyRound size={12} />{t('Password')}</button>
            {x.mode === 'read' && <button className="btn ghost xs icon" title={shown[x.key] ? t('Hide') : t('Show (20 s)')} aria-label={shown[x.key] ? t('Hide') : t('Show (20 s)')} onClick={() => (shown[x.key] ? setShown((s) => { const n = { ...s }; delete n[x.key]; return n; }) : act(x, 'show'))}>{shown[x.key] ? <EyeOff /> : <Eye />}</button>}
            {x.hasTotp && <button className="btn ghost xs" title="Copy 2FA code" onClick={() => act(x, 'totp')}>2FA</button>}
          </div>
        ))}
      </div>
    </div>
  );
}
