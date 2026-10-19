/* Hostwerk Passwörter – Hintergrund: spricht mit dem lokalen Hostwerk (127.0.0.1:<port>) und reicht Treffer,
 * Ausfüll-Daten und Speichern-Wünsche zwischen Seite (content.js) und Oberfläche (popup.js) durch.
 * Läuft in Chrome/Edge/Brave (Service Worker) und Firefox (Hintergrundskript). Kein Kontakt zu fremden Servern. */
const api = typeof browser !== 'undefined' ? browser : chrome;

async function cfg() { const s = await api.storage.local.get(['port', 'token', 'name']); return s.port && s.token ? s : null; }
async function call(method, path, body) {
  const c = await cfg();
  if (!c) throw new Error('Noch nicht mit Hostwerk gekoppelt.');
  const r = await fetch(`http://127.0.0.1:${c.port}/api${path}`, { method, headers: { 'content-type': 'application/json', 'x-hostwerk-ext': c.token }, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  // In Hostwerk ausgetragen (Kopplung dort gelöst) → hier auch vergessen, statt endlos „nicht gekoppelt“ zu melden
  if (r.status === 401 && /nicht gekoppelt/i.test(j.error || '')) { await api.storage.local.remove(['port', 'token', 'name']); statusCache = null; }
  if (!r.ok) throw Object.assign(new Error(j.error || `Hostwerk antwortet mit ${r.status}`), { status: r.status });
  return j;
}
/* Status kurz zwischenspeichern: jede Seite mit Anmeldefeld fragt ihn – ohne Zwischenspeicher hagelt es Anfragen */
let statusCache = null;
async function status(fresh) {
  if (!fresh && statusCache && Date.now() - statusCache.at < 3000) return statusCache.v;
  const c = await cfg(); if (!c) return { paired: false };
  let v; try { v = { paired: true, ...(await call('GET', '/pw/ext/status')) }; } catch (e) { v = (await cfg()) ? { paired: true, offline: e.status !== 401, error: e.message } : { paired: false }; }
  statusCache = { at: Date.now(), v };
  return v;
}
/* Gesperrt/entsperrt: alle Tabs informieren, damit Vorschläge im Feld sofort stimmen */
async function changed() {
  statusCache = null;
  try { for (const t of await api.tabs.query({})) api.tabs.sendMessage(t.id, { type: 'hw-state' }).catch?.(() => {}); } catch { /* egal */ }
}
async function pair(port, code, name) {
  const r = await fetch(`http://127.0.0.1:${port}/api/pw/ext/pair`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code, name, browser: navigator.userAgent.match(/(Firefox|Edg|OPR|Brave|Chrome)\/[\d.]+/)?.[0] || '' }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'Kopplung fehlgeschlagen');
  await api.storage.local.set({ port: Number(port), token: j.token, name: j.name });
  return j;
}
/* Automatische Kopplung: Hostwerk legt beim Installieren hostwerk-pairing.json (Port + Einmal-Ticket) in den
 * Erweiterungsordner. Beim ersten Start koppeln wir uns damit selbst – kein Code abtippen nötig. */
async function autoPair() {
  if (await cfg()) return;
  try {
    const r = await fetch(api.runtime.getURL('hostwerk-pairing.json'));
    if (!r.ok) return;
    const p = await r.json();
    if (p && p.port && p.ticket) await pair(p.port, p.ticket, p.name || 'Browser');
  } catch { /* keine Datei (Store, Firefox, ZIP-Download) */ }
  if (!(await cfg())) await findHostwerk();
}
/* Ohne Datei (Store-Fassung, signierte Firefox-Datei): Hostwerk auf den üblichen Ports suchen. Hostwerk gibt nur dann einen
 * Schlüssel heraus, wenn du dort gerade „Installieren“ geklickt hast (15 Minuten) – und nur an Erweiterungen, nie an Webseiten. */
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
        } catch { /* Port frei oder kein Hostwerk */ }
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
        // Auch in Hostwerk austragen – sonst stünde der Browser dort weiter unter „Gekoppelte Browser“
        case 'unpair': { try { await call('DELETE', '/pw/ext/self'); } catch { /* offline: Hostwerk trägt ihn spätestens beim nächsten 401 aus */ } await api.storage.local.clear(); await changed(); return { ok: true }; }
        case 'match': return call('GET', `/pw/ext/match?url=${encodeURIComponent(msg.url)}`);
        case 'fill': return call('GET', `/pw/ext/fill?vault=${encodeURIComponent(msg.vault)}&item=${encodeURIComponent(msg.item)}`);
        case 'unlock': { const j = await call('POST', '/pw/ext/unlock', { id: msg.id, password: msg.password }); await changed(); return j; }
        case 'lock': { const j = await call('POST', '/pw/ext/lock'); await changed(); return j; }
        // Aus dem Feld-Menü „Entsperren“: Popup öffnen (Chrome 127+/Firefox), sonst als kleines Fenster
        case 'open-unlock': { try { if (api.action.openPopup) { await api.action.openPopup(); return { ok: true }; } } catch { /* nicht erlaubt */ } await api.windows.create({ url: api.runtime.getURL('popup.html'), type: 'popup', width: 380, height: 520 }); return { ok: true }; }
        case 'generate': return call('POST', '/pw/ext/generate', msg.opts || {});
        case 'search': return call('GET', `/pw/ext/search?q=${encodeURIComponent(msg.q || '')}`);
        // Zahl passender Zugänge am Symbol (nur wenn nichts zum Speichern wartet)
        case 'badge': { if (sender.tab && !pendingSaves.has(sender.tab.id)) { try { await api.action.setBadgeText({ tabId: sender.tab.id, text: msg.count ? String(msg.count) : '' }); await api.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: '#7C5CFF' }); } catch { /* egal */ } } return { ok: true }; }
        case 'save': return call('POST', '/pw/ext/save', msg.data);
        case 'offer-save': { if (sender.tab) { pendingSaves.set(sender.tab.id, { ...msg.data, at: Date.now() }); try { await api.action.setBadgeText({ tabId: sender.tab.id, text: '1' }); await api.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: '#FF5A1F' }); } catch { /* egal */ } } return { ok: true }; }
        case 'pending-save': { const t = msg.tabId; const p = pendingSaves.get(t); return p && Date.now() - p.at < 10 * 60000 ? p : null; }
        case 'clear-pending': { pendingSaves.delete(msg.tabId); try { await api.action.setBadgeText({ tabId: msg.tabId, text: '' }); } catch { /* egal */ } return { ok: true }; }
        case 'fill-active': { const [tab] = await api.tabs.query({ active: true, currentWindow: true }); if (!tab) throw new Error('Kein Tab'); const data = await call('GET', `/pw/ext/fill?vault=${encodeURIComponent(msg.vault)}&item=${encodeURIComponent(msg.item)}`); await api.tabs.sendMessage(tab.id, { type: 'do-fill', data }); return { ok: true, totp: data.totp }; }
        default: return { error: 'Unbekannt' };
      }
    } catch (e) { return { error: e.message, status: e.status }; }
  })().then(sendResponse);
  return true;
});

/* Tastenkürzel (Strg+Umschalt+L, im Browser unter Erweiterungen → Tastenkombinationen änderbar) und Rechtsklick-Menü:
 * beides füllt den ersten passenden Zugang aus – funktioniert auch auf Seiten, die Tastendrücke abfangen. */
async function fillFirst(tabId) { try { await api.tabs.sendMessage(tabId, { type: 'fill-first' }); } catch { /* keine Seite mit Inhalt-Skript */ } }
if (api.commands && api.commands.onCommand) api.commands.onCommand.addListener(async (cmd) => { if (cmd !== 'fill-first') return; const [tab] = await api.tabs.query({ active: true, currentWindow: true }); if (tab) fillFirst(tab.id); });
if (api.contextMenus) {
  api.runtime.onInstalled.addListener(() => { try { api.contextMenus.create({ id: 'hw-fill', title: 'Hostwerk: Zugang ausfüllen', contexts: ['editable'] }); } catch { /* schon da */ } });
  api.contextMenus.onClicked.addListener((info, tab) => { if (info.menuItemId === 'hw-fill' && tab) fillFirst(tab.id); });
}
