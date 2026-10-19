![Passwort-Manager](banner.svg)

# Passwort-Manager

Eigener verschlüsselter Tresor auf diesem PC oder die Anbindung an den Passwort-Manager, den du schon nutzt – Bitwarden/Vaultwarden, 1Password, KeePass, pass oder LastPass. Alles andere (Google, Apple, Proton, Dashlane …) kommt per Import.

[English](README.md) · Offizielle [Hostwerk](https://github.com/Passimoritz/hostwerk-public)-Erweiterung (SDK 2.7, native Erweiterung)

![Bildschirmfoto](docs/screenshot.de.png)

## Was sie kann

- Hostwerk-Tresor: AES-256-GCM, Schlüssel aus dem Master-Passwort (scrypt), sperrt sich nach Leerlauf selbst
- Zugänge, Notizen, Karten und Identitäten mit Ordnern, Schlagwörtern, Favoriten, Passwort-Verlauf und Papierkorb
- 2FA-Codes (TOTP), Passwort-Generator und Passphrasen
- Sicherheitsprüfung: schwache, doppelte, alte und geleakte Passwörter (Have I Been Pwned mit k-Anonymität) und wichtige Dienste ohne 2FA
- Import aus 18 Formaten, Export als Bitwarden-JSON oder CSV, Kopieren zwischen Tresoren
- Browser-Erweiterung für Chrome, Edge, Firefox, Brave, Opera und Vivaldi – koppelt sich selbst, Vorschläge direkt im Anmeldefeld
- Einzelne Zugänge mit Mitgliedern teilen (braucht „Team & Benutzer“), auch befristet
- Anbieter-Programme (bw, op) werden täglich geprüft und mit Probelauf aktualisiert

## Installieren

In Hostwerk unter **Erweiterungen → Entdecken** auf „Installieren“ klicken. Wer die Funktion schon in Hostwerk 2.8 benutzt hat, bekommt die Erweiterung beim Update automatisch – mit allen Daten.

Native Erweiterungen laufen als Teil von Hostwerk (eigener Server- und Oberflächen-Teil). Darum installiert Hostwerk sie nur aus dem offiziellen Katalog (mit Prüfsumme) oder im Entwickler-Modus.

## Daten

`settings.passwords, data/passwoerter/*.hwvault` – genau dort, wo Hostwerk sie schon immer abgelegt hat. Entfernen der Erweiterung löscht nichts.

## Entwickeln

```bash
node --test tests/*.test.js          # Tests
node build-native.js .               # Oberfläche bauen (sdk/build-native.js aus hostwerk-public)
node check.js . --strict             # Prüfung wie im Katalog (sdk/check.js)
```

Quelltext der Oberfläche in `ui/src`, Server-Teil in `server/`. Texte im Code sind Englisch, Deutsch steht in `locales/de.json`.

## Lizenz

MIT
