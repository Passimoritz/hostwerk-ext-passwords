## 1.1.0

- Vault as a service for other extensions (`host.use('passwordVault')`: status, save, find, reveal) – each extension only sees its own entries, every access is logged. / Tresor als Dienst für andere Erweiterungen (`host.use('passwordVault')`: status, save, find, reveal) – jede Erweiterung sieht nur ihre eigenen Einträge, jeder Zugriff wird protokolliert.
- Dashboard tile “Password check” with the score and leaked, weak and reused passwords of the default vault. / Kachel „Passwort-Prüfung“ mit Punktzahl und geleakten, schwachen und mehrfach genutzten Passwörtern des Standard-Tresors.
- Export as an encrypted KeePass file (.kdbx, KDBX 4 with Argon2id) with its own password – folders become groups, 2FA and own fields come along. / Export als verschlüsselte KeePass-Datei (.kdbx, KDBX 4 mit Argon2id) mit eigenem Passwort – Ordner werden Gruppen, 2FA und eigene Felder kommen mit.
- Fixed: 1Password and Dashlane exports were recognised as Apple Passwords (tags and 2FA got lost). / Behoben: 1Password- und Dashlane-Exporte wurden als Apple-Passwörter erkannt (Schlagwörter und 2FA gingen verloren).
- Many more tests: every import format, export → import, transfer, KeePass file, sharing, automatic browser pairing, expired keys and the routes of the browser extension. / Viel mehr Tests: jedes Importformat, Export → Import, Übertragen, KeePass-Datei, Teilen, automatische Browser-Kopplung, abgelaufene Schlüssel und die Routen der Browser-Erweiterung.
- Browser brand colours live in one place with a reason (only in the small browser mark); numbers in the leak check follow Hostwerk’s language. / Browser-Markenfarben an einer Stelle mit Begründung (nur im kleinen Browser-Zeichen); Zahlen in der Leak-Prüfung folgen Hostwerks Sprache.
- The release contains the offline catalogue (`data/`) again – it packs everything except the repository tooling. The page sits at the bottom next to “Live”; other extensions may add tabs. / Das Release enthält wieder den Offline-Katalog (`data/`) – es packt alles außer dem Repo-Werkzeug. Die Seite steht unten bei „Livebetrieb“; andere Erweiterungen dürfen Reiter ergänzen.

## 1.0.2

- Browsers that are not installed are shown dimmed but readable (contrast, WCAG AA). / Nicht installierte Browser gedämpft, aber gut lesbar (Kontrast, WCAG AA).

## 1.0.1

- Browser extension in English and German (follows the browser language), version 1.5.0. / Browser-Erweiterung auf Englisch und Deutsch (richtet sich nach der Browsersprache), Fassung 1.5.0.
- Password generator for Hostwerk's AI tool directly from the extension (no bridge in the core any more). / Passwort-Generator für das KI-Werkzeug direkt aus der Erweiterung (keine Brücke mehr im Kern).

## 1.0.0

- First release as its own extension (before: built into Hostwerk). Data stays where it was. / Erste Fassung als eigene Erweiterung (vorher fest in Hostwerk). Daten bleiben, wo sie waren.
