/* Hostwerk Passwords – background: talks to the local Hostwerk (127.0.0.1:<port>) and passes matches, fill-in data and
 * save requests between the page (content.js) and the popup (popup.js).
 * Runs in Chrome/Edge/Brave (service worker) and Firefox (background script). No contact to other servers.
 *
 * Keeps itself connected without help:
 *   - Hostwerk on another port (restart, port change) → looks on the port from hostwerk-pairing.json and the usual ports
 *   - key no longer valid (removed in Hostwerk, expired) → pairs again with the folder ticket from hostwerk-pairing.json
 *   - every problem has a reason (offline / expired / needs-install / locked) – the popup shows it with the fix
 *   - says hello to Hostwerk with its version, so Hostwerk can show "connected" or "please reload" */
if (typeof self.HW_T === 'undefined' && typeof importScripts === 'function') importScripts('i18n.js');
const T = self.HW_T;
const api = typeof browser !== 'undefined' ? browser : chrome;
const VERSION = api.runtime.getManifest().version;
const UA = () => (navigator.userAgent.match(/(Firefox|Edg|OPR|Brave|Chrome)\/[\d.]+/) || [''])[0];
const PORTS = [7780, 7781, 7782, 7783, 7784, 7785, 7786, 7787, 7788, 7789];
let problem = null; // { reason: 'offline' | 'expired' | 'needs-install', message }

async function cfg() { const s = await api.storage.local.get(['port', 'token', 'name']); return s.port && s.token ? s : null; }
const timeout = (ms) => (typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(ms) : undefined);
/** hostwerk-pairing.json from the own folder (Hostwerk refreshes it on every start: port + reusable ticket). */
async function filePairing() {
  try { const r = await fetch(`${api.runtime.getURL('hostwerk-pairing.json')}?t=${Date.now()}`, { cache: 'no-store' }); if (!r.ok) return null; const p = await r.json(); return p && p.port ? p : null; } catch { return null; }
}
async function candidates() {
  const c = await cfg(); const f = await filePairing();
  return [...new Set([c && c.port, f && f.port, ...PORTS].filter(Boolean).map(Number))];
}
async function raw(port, method, path, { body, token, ms = 4000 } = {}) {
  const headers = { 'content-type': 'application/json', 'x-hostwerk-ext-version': VERSION };
  if (token) headers['x-hostwerk-ext'] = token;
  const r = await fetch(`http://127.0.0.1:${port}/api${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: timeout(ms) });
  const j = await r.json().catch(() => ({}));
  return { r, j };
}
/** Tell Hostwerk who we are (version, paired, what went wrong) – shows up on its extension card. */
async function hello(port, extra = {}) { try { await raw(port, 'POST', '/pw/ext/hello', { body: { version: VERSION, paired: !!(await cfg()), browser: UA(), ...extra }, ms: 1500 }); } catch { /* not there */ } }

async function pair(port, code, name) {
  const { r, j } = await raw(port, 'POST', '/pw/ext/pair', { body: { code, name, browser: UA(), version: VERSION } });
  if (!r.ok) throw Object.assign(new Error(j.error || T('Pairing failed')), { status: r.status, reason: j.reason || null });
  await api.storage.local.set({ port: Number(port), token: j.token, name: j.name, off: false });
  problem = null;
  return j;
}

/**
 * Pair without help: first with the folder ticket (works again and again, also after a Hostwerk restart), then the
 * short window after "Install" in Hostwerk. Remembers the reason when it does not work. One run at a time.
 */
let pairing = null;
function ensurePaired() {
  if (pairing) return pairing;
  pairing = (async () => {
    if (await cfg()) return true;
    problem = null;
    // Selbst im Popup gelöst: nicht still neu koppeln – erst wieder nach „Installieren“ in Hostwerk oder mit Code
    const off = (await api.storage.local.get(['off'])).off === true;
    const f = off ? null : await filePairing();
    const ports = await candidates();
    let answered = null;
    if (f && f.ticket) {
      for (const port of ports) {
        try { await pair(port, f.ticket, f.name || 'Browser'); await changed(); return true; } catch (e) {
          if (e.status) { answered = port; problem = { reason: 'expired', message: e.message }; break; }
        }
      }
    }
    for (const port of ports) {
      try {
        const { r, j } = await raw(port, 'POST', '/pw/ext/autopair', { body: { browser: UA() }, ms: 1500 });
        if (r.ok && j.token) { await api.storage.local.set({ port, token: j.token, name: j.name, off: false }); problem = null; await changed(); return true; }
        answered = answered || port;
        if (!problem) problem = { reason: 'needs-install', message: T('In Hostwerk open Passwords → Browser and click “Install” for this browser – it connects by itself.') };
      } catch { /* no Hostwerk on this port */ }
    }
    if (!answered) problem = { reason: 'offline', message: T('Hostwerk is not running on this PC – start it, the extension connects by itself.') };
    else hello(answered, { reason: problem && problem.reason });
    return false;
  })().finally(() => { setTimeout(() => { pairing = null; }, 1500); });
  return pairing;
}
/** Hostwerk moved to another port (restart, change): look for it with the key we have. */
async function relocate() {
  const c = await cfg(); if (!c) return false;
  for (const port of await candidates()) {
    if (port === c.port) continue;
    try { const { r } = await raw(port, 'GET', '/pw/ext/status', { token: c.token, ms: 1500 }); if (r.ok) { await api.storage.local.set({ port }); return 'ok'; } if (r.status === 401) { await api.storage.local.remove(['port', 'token', 'name']); return 'unpaired'; } } catch { /* next */ }
  }
  return false;
}

async function call(method, path, body, retry = true) {
  let c = await cfg();
  if (!c) { if (!(await ensurePaired())) throw Object.assign(new Error((problem && problem.message) || T('Not paired with Hostwerk yet.')), { status: 401, reason: problem && problem.reason }); c = await cfg(); }
  let res;
  try { res = await raw(c.port, method, path, { body, token: c.token }); } catch {
    const where = retry ? await relocate() : false;
    if (where === 'ok' || (where === 'unpaired' && (await ensurePaired()))) return call(method, path, body, false);
    problem = { reason: 'offline', message: T('Hostwerk is not running on this PC – start it, the extension connects by itself.') };
    throw Object.assign(new Error(problem.message), { status: 0, reason: 'offline' });
  }
  const { r, j } = res;
  // Key no longer valid (removed in Hostwerk, expired, other Hostwerk) → forget it and pair again with the folder ticket
  if (r.status === 401 && /nicht gekoppelt|not paired/i.test(j.error || '')) {
    await api.storage.local.remove(['port', 'token', 'name']); statusCache = null;
    if (retry && (await ensurePaired())) return call(method, path, body, false);
    throw Object.assign(new Error((problem && problem.message) || j.error), { status: 401, reason: (problem && problem.reason) || 'expired' });
  }
  if (!r.ok) throw Object.assign(new Error(j.error || T('Hostwerk answers with {status}', { status: r.status })), { status: r.status });
  return j;
}
const newer = (a, b) => { if (!a || !b) return false; const x = a.split('.').map(Number); const y = b.split('.').map(Number); for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); return false; };
/* Cache the status briefly: every page with a sign-in field asks for it – without a cache requests pile up */
let statusCache = null;
let helloAt = 0;
async function status(fresh) {
  if (!fresh && statusCache && Date.now() - statusCache.at < 3000) return statusCache.v;
  let v;
  try {
    const s = await call('GET', '/pw/ext/status');
    v = { paired: true, ...s, version: VERSION, update: newer(s.latest, VERSION) ? s.latest : null };
    if (Date.now() - helloAt > 10 * 60000) { helloAt = Date.now(); const c = await cfg(); if (c) hello(c.port); }
  } catch (e) { v = (await cfg()) && e.reason !== 'expired' ? { paired: true, offline: true, reason: e.reason || 'offline', error: e.message, version: VERSION } : { paired: false, reason: e.reason || (problem && problem.reason) || null, message: e.message, version: VERSION }; }
  statusCache = { at: Date.now(), v };
  return v;
}
/* Locked/unlocked: tell every tab so the suggestions in the field are right at once */
async function changed() {
  statusCache = null;
  try { for (const t of await api.tabs.query({})) api.tabs.sendMessage(t.id, { type: 'hw-state' }).catch?.(() => {}); } catch { /* ignore */ }
}
/* Not paired after install: keep trying for a while (Hostwerk may still be starting, "Install" may come later) */
let searching = false;
async function keepTrying() {
  if (searching) return; searching = true;
  try { for (let round = 0; round < 90 && !(await cfg()); round++) { if (await ensurePaired()) return; await new Promise((ok) => setTimeout(ok, 10000)); } } finally { searching = false; }
}
async function start() { if (!(await cfg())) keepTrying(); else status(true).catch(() => {}); }
api.runtime.onInstalled.addListener(() => { start(); });
api.runtime.onStartup.addListener(() => { start(); });
start();

const pendingSaves = new Map(); // tabId -> { url, host, username, password }

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case 'status': return status(!!msg.fresh);
        case 'pair': { const j = await pair(msg.port, msg.code, msg.name); await changed(); return j; }
        // Also remove it in Hostwerk – otherwise the browser would stay under "paired browsers" there
        case 'unpair': { try { await call('DELETE', '/pw/ext/self', undefined, false); } catch { /* offline: Hostwerk removes it on the next 401 at the latest */ } await api.storage.local.clear(); await api.storage.local.set({ off: true }); await changed(); return { ok: true }; }
        // Update from Hostwerk: the folder already holds the new files – reloading picks them up
        case 'reload': { setTimeout(() => api.runtime.reload(), 100); return { ok: true }; }
        case 'match': return call('GET', `/pw/ext/match?url=${encodeURIComponent(msg.url)}`);
        case 'fill': return call('GET', `/pw/ext/fill?vault=${encodeURIComponent(msg.vault)}&item=${encodeURIComponent(msg.item)}`);
        // Own image of an item (data: address) – the popup cannot send the key itself
        case 'icon': { const j = await call('GET', `/pw/ext/icon?vault=${encodeURIComponent(msg.vault)}&item=${encodeURIComponent(msg.item)}`); return j; }
        case 'unlock': { const j = await call('POST', '/pw/ext/unlock', { id: msg.id, password: msg.password }); await changed(); return j; }
        case 'lock': { const j = await call('POST', '/pw/ext/lock'); await changed(); return j; }
        // "Unlock" from the field menu: open the popup (Chrome 127+/Firefox), otherwise as a small window
        case 'open-unlock': { try { if (api.action.openPopup) { await api.action.openPopup(); return { ok: true }; } } catch { /* not allowed */ } await api.windows.create({ url: api.runtime.getURL('popup.html'), type: 'popup', width: 380, height: 520 }); return { ok: true }; }
        case 'generate': return call('POST', '/pw/ext/generate', { ...(msg.opts || {}), url: msg.url || (sender.tab && sender.tab.url) || undefined });
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
    } catch (e) { return { error: e.message, status: e.status, reason: e.reason || null }; }
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
