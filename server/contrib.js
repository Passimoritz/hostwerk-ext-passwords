'use strict';
/*
 * Beiträge zu Hostwerks Bereichen (SDK 3.5, host.contribute): Selbstwartung (Prüfung + Katalog), Logos der Anbieter
 * und das Änderungsprotokoll. Bis Hostwerk 3.1 standen diese Teile im Kern.
 */

// Logos der Anbieter (simple-icons) – „_<anbieter>“ steht für das Logo ohne Tresor (Auswahl beim Anlegen)
const BRAND = { bitwarden: ['bitwarden', '#175DDC'], onepassword: ['1password', '#0094F5'], keepass: ['keepassxc', '#6CAC4D'], lastpass: ['lastpass', '#D32D27'] };

function contributions(pw) {
  const name = (id) => { try { return pw.get(id).name; } catch { return id; } };
  return {
    keeper: {
      checks: [{ label: 'Passwort-Manager (CLIs, Bibliothek, Leck-Prüfung, Katalog)', run: () => pw.check() }],
      catalogs: [{ id: 'pw', label: 'Passwort-Manager (Anbieter, Formate, CLIs)', key: 'pw-katalog', text: 'täglich' }],
    },
    icons: {
      kind: 'pw',
      sources(id) {
        let type = null;
        try { type = String(id).startsWith('_') ? String(id).slice(1) : pw.get(id).type; } catch { /* unbekannt */ }
        const b = BRAND[type];
        return b ? [{ url: `https://cdn.jsdelivr.net/npm/simple-icons@v13/icons/${b[0]}.svg`, color: b[1] }] : [];
      },
    },
    audit: {
      // Lese- und Prüfaufrufe gehören nicht ins Protokoll
      ignore: [/^\/pw\/(generate|strength|pwned|totp)$/, /^\/pw\/[^/]+\/(audit|import-preview|export|unlock|lock|sync)$/, /^\/pw\/lock-all$/, /^\/pw\/ext\//],
      routes: [
        [/^\/pw\/([^/]+)\/items\/([^/]+)$/, (m, c, req) => ({ kind: 'Passwörter', target: name(m[1]), action: req.method === 'DELETE' ? 'Eintrag gelöscht' : 'Eintrag geändert' })],
        [/^\/pw\/([^/]+)\/items$/, (m) => ({ kind: 'Passwörter', target: name(m[1]), action: 'Eintrag angelegt' })],
        [/^\/pw\/([^/]+)\/(password|transfer|import)$/, (m) => ({ kind: 'Passwörter', target: name(m[1]), action: { password: 'Master-Passwort geändert', transfer: 'Einträge in anderen Tresor kopiert', import: 'Import' }[m[2]] })],
        [/^\/pw$/, (m, c, req) => ({ kind: 'Passwörter', target: (req.body || {}).name || 'Tresor', action: req.method === 'PUT' ? 'Einstellungen geändert' : 'Tresor angelegt' })],
        [/^\/pw\/([^/]+)$/, (m, c, req) => ({ kind: 'Passwörter', target: name(m[1]), action: req.method === 'DELETE' ? 'Tresor entfernt' : 'Tresor geändert' })],
      ],
    },
  };
}

module.exports = { contributions, BRAND };
