/* Hostwerk Passwords – background: talks to the local Hostwerk (127.0.0.1:<port>) and passes matches, fill-in data and
 * save requests between the page (content.js) and the popup (popup.js).
 * Runs in Chrome/Edge/Brave (service worker) and Firefox (background script). No contact to other servers. */
if (typeof self.HW_T === 'undefined' && typeof importScripts === 'function') importScripts('i18n.js');
const T = self.HW_T;
const api = typeof browser !== 'undefined' ? browser : chrome;

async function cfg() { const s = await api.storage.local.get(['port', 'token', 'name']); return s.port && s.token ? s : null; }
async function call(method, path, body) {
  const c = await cfg();
  if (!c) throw new Error(T('Not paired with Hostwerk yet.'));
  const r = await fetch(`http://127.0.0.1:${c.port}/api${path}`, { method, headers: { 'content-type': 'application/json', 'x-hostwerk-ext': c.token }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  // Removed in Hostwerk (pairing removed there) → forget it here too instead of reporting "not paired" forever
  if (r.status === 401 && /nicht gekoppelt|not paired/i.test(j.error || '')) { await api.storage.local.remove(['port', 'token', 'name']); statusCache = null; }
  if (!r.ok) throw Object.assign(new Error(j.error || T('Hostwerk answers with {status}', { status: r.status })), { status: r.status });
  return j;
}
/* Cache the status briefly: every page with a sign-in field asks for it – without a cache requests pile up */
let statusCache = null;
async function status(fresh) {
  if (!fresh && statusCache && Date.now() - statusCache.at < 3000) return statusCache.v;
  const c = await cfg(); if (!c) return { paired: false };
  let v; try { v = { paired: true, ...(await call('GET', '/pw/ext/status')) }; } catch (e) { v = (await cfg()) ? { paired: true, offline: e.status !== 401, error: e.message } : { paired: false }; }
  statusCache = { at: Date.now(), v };
  return v;
}
/* Locked/unlocked: tell every tab so the suggestions in the field are right at once */
async function changed() {
  statusCache = null;
  try { for (const t of await api.tabs.query({})) api.tabs.sendMessage(t.id, { type: 'hw-state' }).catch?.(() => {}); } catch { /* ignore */ }
}
async function pair(port, code, name) {
  const r = await fetch(`http://127.0.0.1:${port}/api/pw/ext/pair`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code, name, browser: navigator.userAgent.match(/(Firefox|Edg|OPR|Brave|Chrome)\/[\d.]+/)?.[0] || '' }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || T('Pairing failed'));
  await api.storage.local.set({ port: Number(port), token: j.token, name: j.name });
  return j;
}
/* Automatic pairing: when installing, Hostwerk puts hostwerk-pairing.json (port + one-time ticket) into the extension
 * folder. On the first start we pair ourselves with it – no code to type. */
async function autoPair() {
  if (await cfg()) return;
  try {
    const r = await fetch(api.runtime.getURL('hostwerk-pairing.json'));
    if (!r.ok) return;
    const p = await r.json();
    if (p && p.port && p.ticket) await pair(p.port, p.ticket, p.name || 'Browser');
  } catch { /* no file (store, Firefox, ZIP download) */ }
  if (!(await cfg())) await findHostwerk();
}
/* Without the file (store version, signed Firefox file): look for Hostwerk on the usual ports. Hostwerk only hands out a key
 * if you just clicked "Install" there (15 minutes) – and only to extensions, never to web pages. */
const PORTS = [7780, 7781, 7782, 7783, 7784, 7785, 7786, 7787, 7788, 7789];
let searching = false;
async function findHostwerk() {
  if (searching) return; searching = true;
  try {
    for (let round = 0; round < 90 && !(await cfg()); round++) {
      for (const port of PORTS) {
        try {
          const r = await fetch(`http://127.0.0.1:${port}/api/pw/ext/autopair`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ browser: navigator.userAgent.match(/(Firefox|Edg|OPR|Brave|Chrome)\/[\d.]+/)?.[0] || '' }), signal: AbortSignal.timeout(1500) });
          if (!r.ok) continue;
          const j = await r.json();
          if (j.token) { await api.storage.local.set({ port, token: j.token, name: j.name }); await changed(); return; }
        } catch { /* port free or no Hostwerk */ }
      }
      await new Promise((ok) => setTimeout(ok, 10000));
    }
  } finally { searching = false; }
}
api.runtime.onInstalled.addListener(() => { autoPair(); });
api.runtime.onStartup.addListener(() => { autoPair(); });
autoPair();

const pendingSaves = new Map(); // tabId -> { url, host, username, password }

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'status': return status(!!msg.fresh);
        case 'pair': { const j = await pair(msg.port, msg.code, msg.name); await changed(); return j; }
        // Also remove it in Hostwerk – otherwise the browser would stay under "paired browsers" there
        case 'unpair': { try { await call('DELETE', '/pw/ext/self'); } catch { /* offline: Hostwerk removes it on the next 401 at the latest */ } await api.storage.local.clear(); await changed(); return { ok: true }; }
        case 'match': return call('GET', `/pw/ext/match?url=${encodeURIComponent(msg.url)}`);
        case 'fill': return call('GET', `/pw/ext/fill?vault=${encodeURIComponent(msg.vault)}&item=${encodeURIComponent(msg.item)}`);
        case 'unlock': { const j = await call('POST', '/pw/ext/unlock', { id: msg.id, password: msg.password }); await changed(); return j; }
        case 'lock': { const j = await call('POST', '/pw/ext/lock'); await changed(); return j; }
        // "Unlock" from the field menu: open the popup (Chrome 127+/Firefox), otherwise as a small window
        case 'open-unlock': { try { if (api.action.openPopup) { await api.action.openPopup(); return { ok: true }; } } catch { /* not allowed */ } await api.windows.create({ url: api.runtime.getURL('popup.html'), type: 'popup', width: 380, height: 520 }); return { ok: true }; }
        case 'generate': return call('POST', '/pw/ext/generate', msg.opts || {});
        case 'search': return call('GET', `/pw/ext/search?q=${encodeURIComponent(msg.q || '')}`);
        // Number of matching logins on the icon (only while nothing waits to be saved)
        case 'badge': { if (sender.tab && !pendingSaves.has(sender.tab.id)) { try { await api.action.setBadgeText({ tabId: sender.tab.id, text: msg.count ? String(msg.count) : '' }); await api.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: '#7C5CFF' }); } catch { /* ignore */ } } return { ok: true }; }
        case 'save': return call('POST', '/pw/ext/save', msg.data);
        case 'offer-save': { if (sender.tab) { pendingSaves.set(sender.tab.id, { ...msg.data, at: Date.now() }); try { await api.action.setBadgeText({ tabId: sender.tab.id, text: '1' }); await api.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: '#FF5A1F' }); } catch { /* ignore */ } } return { ok: true }; }
        case 'pending-save': { const t = msg.tabId; const p = pendingSaves.get(t); return p && Date.now() - p.at < 10 * 60000 ? p : null; }
        case 'clear-pending': { pendingSaves.delete(msg.tabId); try { await api.action.setBadgeText({ tabId: msg.tabId, text: '' }); } catch { /* ignore */ } return { ok: true }; }
        case 'fill-active': { const [tab] = await api.tabs.query({ active: true, currentWindow: true }); if (!tab) throw new Error(T('No tab')); const data = await call('GET', `/pw/ext/fill?vault=${encodeURIComponent(msg.vault)}&item=${encodeURIComponent(msg.item)}`); await api.tabs.sendMessage(tab.id, { type: 'do-fill', data }); return { ok: true, totp: data.totp }; }
        default: return { error: T('Unknown') };
      }
    } catch (e) { return { error: e.message, status: e.status }; }
  })().then(sendResponse);
  return true;
});

/* Shortcut (Ctrl+Shift+L, can be changed in the browser under Extensions → Keyboard shortcuts) and right-click menu:
 * both fill in the first matching login – also works on pages that catch key presses. */
async function fillFirst(tabId) { try { await api.tabs.sendMessage(tabId, { type: 'fill-first' }); } catch { /* no page with the content script */ } }
if (api.commands && api.commands.onCommand) api.commands.onCommand.addListener(async (cmd) => { if (cmd !== 'fill-first') return; const [tab] = await api.tabs.query({ active: true, currentWindow: true }); if (tab) fillFirst(tab.id); });
if (api.contextMenus) {
  api.runtime.onInstalled.addListener(() => { try { api.contextMenus.create({ id: 'hw-fill', title: T('Hostwerk: fill in login'), contexts: ['editable'] }); } catch { /* already there */ } });
  api.contextMenus.onClicked.addListener((info, tab) => { if (info.menuItemId === 'hw-fill' && tab) fillFirst(tab.id); });
}
