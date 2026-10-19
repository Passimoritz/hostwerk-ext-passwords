/* Hostwerk Passwörter – Seite: Anmeldeformulare erkennen und ausfüllen, Vorschläge direkt im Feld, starke Passwörter
 * bei der Registrierung vorschlagen, neue Zugänge nach dem Absenden zum Speichern anbieten.
 * Das Menü im Feld liegt in einem Shadow-DOM – Seiten-CSS kann es weder verstellen noch auslesen. */
(() => {
  const api = typeof browser !== 'undefined' ? browser : chrome;
  if (window.__hwpw) return; window.__hwpw = true;
  const send = (msg) => new Promise((res) => { try { api.runtime.sendMessage(msg, (r) => { void api.runtime.lastError; res(r || {}); }); } catch { res({}); } });
  const visible = (el) => { if (!el || !el.isConnected) return false; const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none'; };
  const pwFields = () => [...document.querySelectorAll('input[type="password"]')].filter(visible);
  const isNewPw = (el) => /new-password/.test(el.autocomplete || '') || /neu|new|regist|sign.?up|confirm|wiederhol|repeat/i.test(`${el.name} ${el.id} ${el.placeholder} ${el.getAttribute('aria-label') || ''}`);
  const userFieldFor = (pw) => {
    const form = pw.form || document;
    const cands = [...form.querySelectorAll('input')].filter((i) => visible(i) && !['password', 'hidden', 'submit', 'button', 'checkbox', 'radio', 'search'].includes(i.type));
    const score = (i) => { const s = `${i.name} ${i.id} ${i.autocomplete} ${i.placeholder} ${i.type} ${i.getAttribute('aria-label') || ''}`.toLowerCase(); return (/user|benutzer|login|e-?mail|konto|account|name|kennung/.test(s) ? 2 : 0) + (i.type === 'email' ? 2 : 0) + (i.autocomplete === 'username' ? 3 : 0); };
    const before = cands.filter((i) => i.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING);
    return [...before].sort((a, b) => score(b) - score(a))[0] || cands.sort((a, b) => score(b) - score(a))[0] || null;
  };
  const loginInputs = () => { const out = new Set(); for (const pw of pwFields()) { out.add(pw); const u = userFieldFor(pw); if (u) out.add(u); } for (const u of document.querySelectorAll('input[autocomplete="username"],input[type="email"]')) if (visible(u)) out.add(u); return [...out]; };
  const setVal = (el, v) => { if (!el) return; el.focus(); const proto = Object.getPrototypeOf(el); const d = Object.getOwnPropertyDescriptor(proto, 'value') || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value'); d.set.call(el, v); for (const t of ['input', 'change']) el.dispatchEvent(new Event(t, { bubbles: true })); };
  const fill = (data) => {
    const pws = pwFields();
    const pw = (document.activeElement && document.activeElement.type === 'password' && visible(document.activeElement)) ? document.activeElement : pws[0];
    if (pw) { if (data.password) setVal(pw, data.password); const u = userFieldFor(pw); if (u && data.username) setVal(u, data.username); }
    else { const u = [...document.querySelectorAll('input[type="email"],input[autocomplete="username"],input[name*="user"],input[name*="mail"],input[id*="user"]')].find(visible); if (u && data.username) setVal(u, data.username); }
    if (data.totp && data.totp.code) { const otp = [...document.querySelectorAll('input[autocomplete="one-time-code"],input[name*="otp"],input[name*="code"],input[id*="otp"],input[name*="totp"]')].find(visible); if (otp) setVal(otp, data.totp.code); }
    hideMenu();
  };
  const fillItem = async (it) => { const d = await send({ type: 'fill', vault: it.vault, item: it.id }); if (d && !d.error) fill(d); return d; };

  /* ---------- Einstellungen + Treffer (einmal je Seite, bei Bedarf neu) ---------- */
  let cfg = null; let cfgAt = 0; let matches = null;
  // Gesperrt/entsperrt ändert sich jederzeit → nicht ewig merken (Hintergrund hält den Status ohnehin 3 s vor)
  const loadCfg = async () => { if (cfg && Date.now() - cfgAt < 5000) return cfg; cfgAt = Date.now(); const st = await send({ type: 'status' }); cfg = st && st.paired && !st.offline ? { ...(st.autofill || {}), autoLogin: !!st.autoLogin, locked: (st.vaults || []).some((v) => v.locked) } : null; return cfg; };
  const loadMatches = async (force) => { if (matches && !force) return matches; const m = await send({ type: 'match', url: location.href }); matches = m && !m.error ? m : { items: [], locked: [] }; send({ type: 'badge', count: (matches.items || []).length }); return matches; };

  /* ---------- Menü im Feld (Shadow-DOM) ---------- */
  let host = null; let menuFor = null;
  const css = `:host{all:initial}.m{position:fixed;z-index:2147483647;min-width:260px;max-width:340px;font:13px/1.4 system-ui,"Segoe UI",sans-serif;color:#14181d;background:#fff;border:1px solid #d9dce3;border-radius:10px;box-shadow:0 12px 32px -8px rgba(0,0,0,.35);overflow:hidden}
  @media (prefers-color-scheme:dark){.m{color:#eceae6;background:#1d2228;border-color:#2f363f}.i:hover,.i:focus{background:#262c34}.mu{color:#9aa1a9}}
  .h{display:flex;align-items:center;gap:6px;padding:7px 10px;font-weight:650;font-size:12px;border-bottom:1px solid rgba(128,128,128,.25)}.h i{width:8px;height:8px;border-radius:50%;background:#ff5a1f;display:inline-block}
  .i{display:flex;flex-direction:column;padding:7px 10px;cursor:pointer;border:0;background:none;width:100%;text-align:left;font:inherit;color:inherit}.i:hover,.i:focus{background:#f2f3f6;outline:none}
  .i b{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.mu{color:#5c636b;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.gen{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}`;
  const hideMenu = () => { if (host) host.remove(); host = null; menuFor = null; };
  const showMenu = (input, rows) => {
    hideMenu(); if (!rows.length) return;
    host = document.createElement('hostwerk-pw'); const root = host.attachShadow({ mode: 'closed' });
    const st = document.createElement('style'); st.textContent = css; root.appendChild(st);
    const m = document.createElement('div'); m.className = 'm'; m.setAttribute('role', 'listbox');
    const head = document.createElement('div'); head.className = 'h'; head.append(document.createElement('i'), 'Hostwerk Passwörter'); m.appendChild(head);
    for (const r of rows) {
      const b = document.createElement('button'); b.className = 'i'; b.type = 'button';
      const t = document.createElement('b'); t.textContent = r.title; b.appendChild(t);
      if (r.sub) { const s = document.createElement('span'); s.className = r.mono ? 'mu gen' : 'mu'; s.textContent = r.sub; b.appendChild(s); }
      b.addEventListener('mousedown', (e) => { e.preventDefault(); e.stopPropagation(); r.run(); });
      m.appendChild(b);
    }
    const rc = input.getBoundingClientRect();
    m.style.left = `${Math.max(4, Math.min(rc.left, innerWidth - 350))}px`;
    m.style.top = `${rc.bottom + 4 + 200 > innerHeight ? Math.max(4, rc.top - 4 - Math.min(260, 40 + rows.length * 46)) : rc.bottom + 4}px`;
    root.appendChild(m); document.documentElement.appendChild(host); menuFor = input;
  };
  const onFocus = async (e) => {
    const el = e.target; if (!(el instanceof HTMLInputElement) || !visible(el)) return;
    const c = await loadCfg(); if (!c || c.inline === false) return;
    const isLogin = loginInputs().includes(el);
    if (el.type === 'password' && isNewPw(el) && c.suggest !== false) {
      const g = await send({ type: 'generate', opts: { length: 20, symbols: true } });
      if (g && g.password) return showMenu(el, [{ title: 'Starkes Passwort verwenden', sub: g.password, mono: true, run: () => { for (const p of pwFields().filter(isNewPw)) setVal(p, g.password); hideMenu(); } }]);
    }
    if (!isLogin) return;
    // Master-Passwort nie im Seitenfeld abfragen (die Seite könnte Tastendrücke mitlesen) – dafür das Popup öffnen
    if (c.locked) return showMenu(el, [{ title: '🔒 Tresor entsperren', sub: 'Öffnet Hostwerk Passwörter – danach erscheinen hier deine Zugänge', run: () => { hideMenu(); send({ type: 'open-unlock' }); } }]);
    const m = await loadMatches();
    const items = (m.items || []).slice(0, 6);
    if (!items.length) return;
    showMenu(el, items.map((it) => ({ title: it.name, sub: `${it.username || '(ohne Benutzer)'}${it.vaultName ? ' · ' + it.vaultName : ''}`, run: () => fillItem(it) })));
  };
  document.addEventListener('focusin', onFocus, true);
  document.addEventListener('mousedown', (e) => { if (host && e.target !== menuFor && e.target !== host) hideMenu(); }, true);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideMenu(); }, true);
  window.addEventListener('scroll', () => { if (host) hideMenu(); }, true);

  api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'do-fill') { fill(msg.data); sendResponse({ ok: true }); }
    if (msg.type === 'hw-state') { cfg = null; matches = null; if (pwFields().length) loadMatches(true); sendResponse({ ok: true }); }
    if (msg.type === 'has-login') sendResponse({ has: pwFields().length > 0 });
    if (msg.type === 'fill-first') { loadMatches(true).then((m) => { const it = (m.items || [])[0]; if (it) fillItem(it); sendResponse({ ok: !!it }); }); }
    return true;
  });

  /* ---------- Speichern anbieten (nach dem Absenden) ---------- */
  const captured = new WeakMap();
  const capture = () => { for (const pw of pwFields()) { if (!pw.value) continue; const u = userFieldFor(pw); captured.set(pw, { username: u ? u.value : '', password: pw.value }); } };
  document.addEventListener('input', (e) => { if (e.target && e.target.type === 'password') capture(); }, true);
  const offer = async () => {
    const c = await loadCfg(); if (c && c.offerSave === false) return;
    const pw = pwFields().find((p) => captured.get(p)); const v = pw && captured.get(pw); if (!v || !v.password || v.password.length < 4) return;
    // schon gespeichert (gleicher Benutzer + gleiches Passwort)? dann nicht fragen
    const m = await loadMatches(); if ((m.items || []).some((it) => it.username === v.username && it.samePassword)) return;
    send({ type: 'offer-save', data: { url: location.origin, host: location.hostname, name: document.title.split(/[|–-]/)[0].trim().slice(0, 60) || location.hostname, username: v.username, password: v.password } });
  };
  document.addEventListener('submit', () => { capture(); offer(); }, true);
  document.addEventListener('click', (e) => { const b = e.target && e.target.closest && e.target.closest('button,input[type="submit"]'); if (b && pwFields().length) { capture(); setTimeout(offer, 50); } }, true);
  document.addEventListener('keydown', (e) => { if (e.key === 'Enter' && e.target && e.target.type === 'password') { capture(); setTimeout(offer, 50); } }, true);

  /* ---------- Beim Laden: ausfüllen (Option) bzw. Auto-Login (Option) ---------- */
  const onLoad = async () => {
    if (!pwFields().length) return;
    const c = await loadCfg(); if (!c || c.locked) return;
    const m = await loadMatches(); const items = m.items || [];
    if (items.length !== 1 || items[0].noAutoLogin) return; // nur eindeutig
    if (!c.onLoad && !c.autoLogin) return;
    const key = 'hwpw-auto:' + location.origin + location.pathname;
    try { if (Date.now() - Number(sessionStorage.getItem(key) || 0) < 120000) return; } catch { /* egal */ }
    const d = await fillItem(items[0]); if (!d || d.error) return;
    try { sessionStorage.setItem(key, String(Date.now())); } catch { /* egal */ }
    if (!c.autoLogin) return; // nur ausfüllen
    const pw = pwFields()[0]; const form = pw && pw.form;
    setTimeout(() => { const btn = form && [...form.querySelectorAll('button[type="submit"],input[type="submit"],button:not([type])')].find(visible); if (btn) btn.click(); else if (form && form.requestSubmit) form.requestSubmit(); }, 350);
  };
  if (document.readyState === 'complete') setTimeout(onLoad, 500); else window.addEventListener('load', () => setTimeout(onLoad, 500));
  // Seiten, die das Formular erst später zeigen (Single-Page-Apps): Treffer-Zahl auffrischen, sobald ein Passwortfeld auftaucht
  // Gedrosselt (höchstens alle 400 ms, erst billige Suche, dann Sichtbarkeit) und nach dem ersten Fund abgeschaltet –
  // sonst rechnet die Erweiterung bei jeder DOM-Änderung jeder Seite mit
  let seen = !!document.querySelector('input[type="password"]') && pwFields().length > 0; let queued = false;
  const mo = new MutationObserver(() => {
    if (seen || queued) return; queued = true;
    setTimeout(() => { queued = false; if (seen || !document.querySelector('input[type="password"]') || !pwFields().length) return; seen = true; mo.disconnect(); loadMatches(true); setTimeout(onLoad, 300); }, 400);
  });
  if (!seen) mo.observe(document.documentElement, { childList: true, subtree: true });
})();
