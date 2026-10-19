/* Hostwerk Passwords – texts. The source is English; German comes from the table below when the browser runs in German.
 * One plain file (no _locales folder): Hostwerk copies the extension file by file when it installs it.
 * Used by background.js (importScripts / background.scripts), content.js and popup.js. */
(() => {
  const DE = {
    'Hostwerk Passwords': 'Hostwerk Passwörter',
    'Connecting …': 'Verbinde …',
    'Lock all vaults': 'Alle Tresore sperren',
    'Hostwerk is looking for you right now – in Hostwerk open Passwords → Browser and click “Install” for this browser. Pairing then happens by itself.': 'Hostwerk sucht dich gerade selbst – öffne in Hostwerk Passwörter → Browser und klicke bei diesem Browser auf „Installieren“. Die Kopplung passiert dann von allein.',
    'Pair with a code instead': 'Lieber mit Code koppeln',
    'Port': 'Port',
    'Hostwerk port': 'Port von Hostwerk',
    '6-digit code': '6-stelliger Code',
    'Pairing code': 'Kopplungscode',
    'Name of this browser (e.g. Chrome laptop)': 'Name dieses Browsers (z. B. Chrome Laptop)',
    'Name of this browser': 'Name dieses Browsers',
    'Pair': 'Koppeln',
    'Hostwerk does not answer': 'Hostwerk antwortet nicht',
    'Is Hostwerk running on this PC?': 'Läuft Hostwerk auf diesem PC?',
    'Try again': 'Erneut versuchen',
    'Vault locked': 'Tresor gesperrt',
    'Vault': 'Tresor',
    'Master password': 'Master-Passwort',
    'Unlock': 'Entsperren',
    'Save this login?': 'Zugang speichern?',
    'Save': 'Speichern',
    'No': 'Nein',
    'This page': 'Diese Seite',
    'Search': 'Suchen',
    'Generate': 'Erzeugen',
    'No logins for this page.': 'Keine Zugänge für diese Seite.',
    'Name, user, address …': 'Name, Benutzer, Adresse …',
    'Length': 'Länge',
    'Symbols': 'Sonderzeichen',
    'New': 'Neu',
    'Copy': 'Kopieren',
    'Into the password field': 'Ins Passwortfeld',
    'Ctrl': 'Strg',
    'fills in': 'füllt aus',
    'Remove pairing': 'Kopplung lösen',
    'Remove the pairing with Hostwerk?': 'Kopplung mit Hostwerk lösen?',
    'The browser is also removed in Hostwerk. You can pair again any time under Passwords → Browser.': 'Der Browser wird auch in Hostwerk ausgetragen. Neu koppeln geht jederzeit über Passwörter → Browser.',
    'Remove': 'Lösen',
    'Cancel': 'Abbrechen',
    'Not paired': 'Nicht gekoppelt',
    'No connection': 'Keine Verbindung',
    'Connected': 'Verbunden',
    'Connected · {name}': 'Verbunden · {name}',
    '🔒 {names} locked – unlock': '🔒 {names} gesperrt – entsperren',
    '(no user)': '(ohne Benutzer)',
    '{user} on {host}': '{user} auf {host}',
    'Locked': 'Gesperrt',
    '{name} (default)': '{name} (Standard)',
    'Vaults locked': 'Tresore gesperrt',
    '{name} locked': '{name} gesperrt',
    'Unlocking …': 'Entsperre …',
    'The pairing is no longer valid – please pair again.': 'Die Kopplung gilt nicht mehr – bitte neu koppeln.',
    'Fill in': 'Ausfüllen',
    'Error': 'Fehler',
    'Copy the code of the two-factor sign-in': 'Code der Zwei-Faktor-Anmeldung kopieren',
    'There is nothing to fill in on this page.': 'Auf dieser Seite gibt es nichts auszufüllen.',
    'No logins for {host}.': 'Keine Zugänge für {host}.',
    'this page': 'diese Seite',
    'Nothing found.': 'Nichts gefunden.',
    'Copied ✓': 'Kopiert ✓',
    'Not possible': 'Nicht möglich',
    'No field found': 'Kein Feld gefunden',
    'Paired': 'Gekoppelt',
    'Not paired with Hostwerk yet.': 'Noch nicht mit Hostwerk gekoppelt.',
    'Hostwerk answers with {status}': 'Hostwerk antwortet mit {status}',
    'Pairing failed': 'Kopplung fehlgeschlagen',
    'No tab': 'Kein Tab',
    'Unknown': 'Unbekannt',
    'Hostwerk: fill in login': 'Hostwerk: Zugang ausfüllen',
    'Use strong password': 'Starkes Passwort verwenden',
    '🔒 Unlock vault': '🔒 Tresor entsperren',
    'Opens Hostwerk Passwords – then your logins show up here': 'Öffnet Hostwerk Passwörter – danach erscheinen hier deine Zugänge',
  };
  const lang = (() => { try { return String((typeof navigator !== 'undefined' && (navigator.language || '')) || '').toLowerCase(); } catch { return ''; } })();
  const de = lang.startsWith('de');
  const fill = (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? String(v[k]) : m)) : s);
  const T = (s, v) => fill(de && DE[s] ? DE[s] : s, v);
  /** Translate a whole page: text nodes and the placeholder/title/aria-label attributes (popup.html). */
  T.dom = (root) => {
    if (!de || !root) return;
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    for (let n = w.nextNode(); n; n = w.nextNode()) { const raw = n.nodeValue; const t = raw.trim(); if (t && DE[t]) n.nodeValue = raw.replace(t, DE[t]); }
    for (const el of root.querySelectorAll('[placeholder],[title],[aria-label]')) for (const a of ['placeholder', 'title', 'aria-label']) { const v = el.getAttribute(a); if (v && DE[v]) el.setAttribute(a, DE[v]); }
    if (document.documentElement) document.documentElement.lang = 'de';
  };
  T.lang = de ? 'de' : 'en';
  (typeof self !== 'undefined' ? self : window).HW_T = T;
})();
