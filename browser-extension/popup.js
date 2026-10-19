/* Hostwerk Passwords – popup. Shows exactly one view depending on the state: pair, offline, locked or logins. */
const T = self.HW_T;
T.dom(document.body);
const api = typeof browser !== 'undefined' ? browser : chrome;
const $ = (id) => document.getElementById(id);
const send = (msg) => new Promise((res) => api.runtime.sendMessage(msg, (r) => { void api.runtime.lastError; res(r || {}); }));
const VIEWS = ['pairView', 'offlineView', 'lockedView', 'mainView', 'unpairConfirm'];
let tab = null; let status = null;

function show(id, on) { $(id).classList.toggle('hid', !on); }
function view(id) { for (const v of VIEWS) show(v, v === id); show('foot', id === 'mainView'); show('lockBtn', id === 'mainView'); $(id).classList.remove('fade'); void $(id).offsetWidth; $(id).classList.add('fade'); }
function state(text, kind) { $('state').textContent = text; $('dot').className = `dot ${kind || ''}`; }
const el = (tag, props = {}, ...kids) => { const e = document.createElement(tag); Object.assign(e, props); for (const k of kids) e.append(k); return e; };
function hue(s) { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) % 360; return h; }

async function activeTab() { const [t] = await api.tabs.query({ active: true, currentWindow: true }); return t || null; }

async function init() {
  tab = tab || await activeTab();
  status = await send({ type: 'status', fresh: true });
  if (!status.paired) { state(T('Not paired'), 'off'); view('pairView'); waitForPair(); return; }
  if (status.offline) { state(T('No connection'), 'off'); $('offlineText').textContent = status.error || T('Is Hostwerk running on this PC?'); view('offlineView'); return; }
  const vaults = status.vaults || [];
  const open = vaults.filter((v) => !v.locked);
  if (!open.length && vaults.length) return showLocked(vaults);
  state(status.name ? T('Connected · {name}', { name: status.name }) : T('Connected'));
  view('mainView'); movePill();
  const locked = vaults.filter((v) => v.locked);
  show('moreLocked', locked.length > 0);
  if (locked.length) { $('moreLocked').textContent = T('🔒 {names} locked – unlock', { names: locked.map((v) => v.name).join(', ') }); $('moreLocked').onclick = () => showLocked(vaults); }
  const pending = tab ? await send({ type: 'pending-save', tabId: tab.id }) : null;
  if (pending && pending.password) {
    show('saveBox', true); $('saveText').textContent = T('{user} on {host}', { user: pending.username || T('(no user)'), host: pending.host });
    $('saveYes').onclick = async () => { $('saveYes').disabled = true; const r = await send({ type: 'save', data: pending }); $('saveYes').disabled = false; if (r.error) { $('saveText').textContent = r.error; return; } show('saveBox', false); await send({ type: 'clear-pending', tabId: tab.id }); loadMatches(); };
    $('saveNo').onclick = async () => { show('saveBox', false); await send({ type: 'clear-pending', tabId: tab.id }); };
  } else show('saveBox', false);
  await loadMatches();
}

/* ---------- locked ---------- */
function showLocked(vaults) {
  state(T('Locked'), 'off');
  view('lockedView');
  $('lockArt').classList.remove('open');
  const locked = vaults.filter((v) => v.locked);
  const sel = $('vaultSel'); sel.replaceChildren();
  for (const v of locked) sel.append(el('option', { value: v.id, textContent: v.default ? T('{name} (default)', { name: v.name }) : v.name, selected: !!v.default }));
  show('vaultSel', locked.length > 1);
  $('lockedTitle').textContent = locked.length > 1 ? T('Vaults locked') : locked[0] ? T('{name} locked', { name: locked[0].name }) : T('Vault locked');
  setTimeout(() => $('unlockPw').focus(), 60);
}
$('unlockForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pw = $('unlockPw').value; if (!pw) { $('unlockPw').focus(); return; }
  const id = $('vaultSel').value || ((status.vaults || []).find((v) => v.locked) || {}).id;
  $('unlockMsg').textContent = ''; $('unlockBtn').disabled = true; $('unlockPw').disabled = true;
  $('unlockLbl').textContent = T('Unlocking …'); state(T('Unlocking …'), 'busy');
  const r = await send({ type: 'unlock', id, password: pw });
  $('unlockBtn').disabled = false; $('unlockPw').disabled = false; $('unlockLbl').textContent = T('Unlock');
  if (r.error) {
    state(T('Locked'), 'off');
    $('unlockMsg').textContent = r.status === 401 && /gekoppelt|paired/i.test(r.error) ? T('The pairing is no longer valid – please pair again.') : r.error;
    $('unlockForm').classList.remove('shake'); void $('unlockForm').offsetWidth; $('unlockForm').classList.add('shake');
    $('unlockPw').select(); return;
  }
  $('unlockPw').value = '';
  $('lockArt').classList.add('open');
  setTimeout(init, 380);
});

/* ---------- logins ---------- */
function itemRow(it, i = 0) {
  const name = it.name || '';
  const av = el('div', { className: 'av', textContent: (name.trim()[0] || '?').toUpperCase() }); av.style.background = `hsl(${hue(name)} 55% 46%)`;
  const fillBtn = el('button', { className: 'p s', textContent: T('Fill in') });
  const d = el('div', { className: 'item' }, av, el('div', { className: 'n' }, el('b', { textContent: name }), el('span', { textContent: (it.username || (it.urls || [])[0] || '') + (it.vaultName ? ' · ' + it.vaultName : '') })), fillBtn);
  d.style.animationDelay = `${Math.min(i, 8) * 25}ms`;
  fillBtn.onclick = async () => {
    fillBtn.disabled = true;
    const r = await send({ type: 'fill-active', vault: it.vault, item: it.id });
    if (r.error) { fillBtn.disabled = false; fillBtn.textContent = T('Error'); fillBtn.title = r.error; return; }
    if (r.totp && r.totp.code) { try { await navigator.clipboard.writeText(r.totp.code); } catch { /* ignore */ } }
    window.close();
  };
  if (it.hasTotp) {
    const t = el('button', { className: 's', title: T('Copy the code of the two-factor sign-in'), textContent: '2FA' });
    t.onclick = async () => { const r = await send({ type: 'fill', vault: it.vault, item: it.id }); if (r.totp && r.totp.code) { try { await navigator.clipboard.writeText(r.totp.code); } catch { /* ignore */ } t.textContent = r.totp.code; } };
    d.append(t);
  }
  return d;
}
async function loadMatches() {
  const box = $('matches'); box.replaceChildren();
  if (!tab || !/^https?:/.test(tab.url || '')) { $('matchEmptyText').textContent = T('There is nothing to fill in on this page.'); show('matchEmpty', true); return; }
  const m = await send({ type: 'match', url: tab.url });
  if (m.error) { $('matchEmptyText').textContent = m.error; show('matchEmpty', true); return; }
  (m.items || []).forEach((it, i) => box.appendChild(itemRow(it, i)));
  let host = ''; try { host = new URL(tab.url).hostname; } catch { /* ignore */ }
  $('matchEmptyText').textContent = host ? T('No logins for {host}.', { host }) : T('No logins for this page.');
  show('matchEmpty', !(m.items || []).length);
}

/* ---------- tabs with a sliding marker ---------- */
const TABS = [['tabMatch', 'viewMatch'], ['tabSearch', 'viewSearch'], ['tabGen', 'viewGen']];
function movePill() { const on = document.querySelector('.tabs button.on'); if (!on) return; $('pill').style.left = `${on.offsetLeft}px`; $('pill').style.width = `${on.offsetWidth}px`; }
for (const [t, v] of TABS) $(t).onclick = () => {
  for (const [t2, v2] of TABS) { $(t2).classList.toggle('on', t2 === t); show(v2, v2 === v); }
  movePill();
  if (v === 'viewSearch') $('q').focus();
  if (v === 'viewGen' && $('genOut').textContent === '–') $('genBtn').click();
};
let searchTimer = null;
$('q').addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    const q = $('q').value.trim().toLowerCase(); const box = $('results'); box.replaceChildren(); if (!q) return;
    const m = await send({ type: 'search', q }); const seen = new Set(); let i = 0;
    for (const it of m.items || []) { if (seen.has(it.id)) continue; seen.add(it.id); box.appendChild(itemRow(it, i++)); }
    if (!box.children.length) box.append(el('div', { className: 'empty', textContent: m.error || T('Nothing found.') }));
  }, 200);
});

/* ---------- generate ---------- */
function meter(pw) { const s = Math.min(1, (pw.length / 24) * (/[^A-Za-z0-9]/.test(pw) ? 1 : 0.8)); $('genMeter').style.width = `${Math.round(s * 100)}%`; $('genMeter').style.background = s > 0.75 ? 'var(--ok)' : s > 0.45 ? 'var(--ac)' : 'var(--bad)'; }
$('genLen').addEventListener('input', () => { $('genLenV').textContent = $('genLen').value; clearTimeout(searchTimer); searchTimer = setTimeout(() => $('genBtn').click(), 120); });
$('genSym').addEventListener('change', () => $('genBtn').click());
$('genBtn').onclick = async () => { const r = await send({ type: 'generate', opts: { length: Number($('genLen').value) || 20, symbols: $('genSym').checked } }); $('genOut').textContent = r.password || r.error || '–'; if (r.password) meter(r.password); };
$('genCopy').onclick = async () => { try { await navigator.clipboard.writeText($('genOut').textContent); $('genCopy').textContent = T('Copied ✓'); } catch { $('genCopy').textContent = T('Not possible'); } setTimeout(() => { $('genCopy').textContent = T('Copy'); }, 1500); };
$('genFill').onclick = async () => { if (!tab) return; try { await api.tabs.sendMessage(tab.id, { type: 'do-fill', data: { password: $('genOut').textContent, username: '' } }); window.close(); } catch { $('genFill').textContent = T('No field found'); } };

/* ---------- pairing ---------- */
let pairWait = null;
function waitForPair() {
  clearInterval(pairWait);
  // The background looks for Hostwerk; once paired: connection animation and go on
  pairWait = setInterval(async () => { const s = await send({ type: 'status' }); if (s.paired) { clearInterval(pairWait); $('pairArt').classList.add('ok'); state(T('Paired'), ''); setTimeout(init, 600); } }, 1500);
}
$('pairBtn').onclick = async () => {
  $('pairMsg').textContent = ''; $('pairBtn').disabled = true;
  const r = await send({ type: 'pair', port: $('port').value.trim(), code: $('code').value.trim(), name: $('pname').value.trim() || 'Browser' });
  $('pairBtn').disabled = false;
  if (r.error) { $('pairMsg').textContent = r.error; return; }
  $('pairArt').classList.add('ok'); setTimeout(init, 500);
};

/* ---------- other ---------- */
$('retryBtn').onclick = () => { state(T('Connecting …'), 'busy'); init(); };
$('lockBtn').onclick = async () => { await send({ type: 'lock' }); init(); };
$('unpair').onclick = (e) => { e.preventDefault(); view('unpairConfirm'); };
$('unpairNo').onclick = () => init();
$('unpairYes').onclick = async () => { $('unpairYes').disabled = true; await send({ type: 'unpair' }); $('unpairYes').disabled = false; init(); };
addEventListener('unload', () => clearInterval(pairWait));
init();
