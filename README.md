![Password manager](banner.svg)

# Password manager

Own encrypted vault on this PC or a connection to the password manager you already use – Bitwarden/Vaultwarden, 1Password, KeePass, pass or LastPass. Everything else (Google, Apple, Proton, Dashlane …) comes in by import.

[Deutsch](README.de.md) · An official [Hostwerk](https://github.com/Passimoritz/hostwerk-public) extension (native extension, Hostwerk 3.0 or newer)

![Screenshot](docs/screenshot.png)

## What it does

- Hostwerk vault (format 3): a random vault key encrypts everything with AES-256-GCM, the master password (Argon2id, 64 MiB) only wraps that key – a new master password never re-encrypts attachments; older vaults are lifted quietly on unlock; every write is atomic. Locks itself after being idle
- Three columns like a real password manager: navigation (all, favourites, logins, notes, cards, identities, SSH keys, passkeys, files, folders, tags, trash), list with website icons (cached locally) and a strength dot, detail with copy buttons. Keyboard: Ctrl+F, ↑/↓, Ctrl+C (password), Ctrl+Shift+C (username)
- 2FA codes (TOTP) with a countdown ring – the QR code is read from an image or the clipboard
- SSH keys (create ed25519 or paste, public part + fingerprint, hand over to Hostwerk’s SSH keys), passkeys (kept, shown, exported to Bitwarden and KeePassXC), encrypted attachments (5 MB each, 50 MB per vault), extra fields, password history
- Generator for characters or passphrases, with **rules per site** (also used by the browser extension); the clipboard is cleared after a time you choose
- Security report: weak, reused, old and leaked passwords (Have I Been Pwned with k-anonymity, can be switched off) and important services without 2FA – also as a dashboard tile “Password check”
- Import: CSV/JSON of every common service, **KeePass .kdbx and XML**, **1Password .1pux**, **Bitwarden JSON with password**, Enpass JSON, any CSV with your own column assignment – with preview and duplicate detection
- Export encrypted (KeePass .kdbx, Bitwarden JSON with password); unencrypted only after a clear warning. Copy between vaults
- Daily encrypted backups (14 kept) in Hostwerk’s backup centre, including restore
- Own images per item (Hostwerk vault encrypted, KeePass as custom icons) – shown in list, detail and browser extension; Bitwarden/1Password/pass/LastPass keep the website icon
- Browser extension for Chrome, Edge, Firefox, Brave, Opera and Vivaldi – pairs itself, suggestions right in the sign-in field
  - stays connected without help: after a Hostwerk restart, a port change or an update it pairs again with the file in its folder; the popup names the real cause (Hostwerk not running, pairing ran out, vault locked) and offers “Update now”
- Share single logins with members (needs “Team & users”), also time-limited
- **Vault service for other extensions**: file share, mail server, router or cloud backup keep their logins in the vault with one call – each extension only ever sees its own entries

## Providers without extra installs

Bitwarden/Vaultwarden and 1Password only let other programs in through their official command-line programs (`bw`, `op`). You never have to install them: Hostwerk loads the program **when you connect** – `bw` from Bitwarden’s GitHub release (SHA-256 of the release + Windows signature “Bitwarden Inc.”), `op` from cache.agilebits.com (Windows signature “AgileBits”) – into its own `bin` folder, tests it with `--version` (own data folder) and keeps it current: every new version gets a test run first, a broken one is skipped and the last working one stays. If Windows’ Smart App Control blocks a program, Hostwerk says so plainly and offers the import as a way around.

Only set-up providers count: without a Bitwarden or 1Password vault nothing is downloaded, checked or reported. KeePass is read and written directly; pass and lastpass-cli come from the Linux/macOS package manager; Google, Apple, Proton, Dashlane, NordPass & co. come by import.

## For other extensions

```js
const vault = await host.use('passwordVault');
vault.status();                                         // { available, vault: { id, name }, locked, readonly }
await vault.save({ source: 'file-share', key: 'sftp:alex', name: 'SFTP alex', username: 'alex', password, url: 'sftp://pc:2222' });
await vault.find({ source: 'file-share', key: 'sftp:alex' });    // without the password
await vault.reveal({ source: 'file-share', key: 'sftp:alex' });  // { username, password } – logged in the change log
```

Saving the same `source` + `key` again updates the entry (the old password stays in its history). A locked vault answers with status 423 and a message to unlock it under Passwords.

## Install

Needs Hostwerk 3.0 or newer. Website icons and handing SSH keys to `~/.ssh` go through Hostwerk itself (permissions `fetch:icons` and `write:ssh-keys`, SDK 3.3): Hostwerk only loads icons from public addresses and never overwrites a key. Entries it adds for the browser extension (Chrome/Edge registry key, Linux file) show up in the extension pop-up under “What it set up on your PC” and can be removed when uninstalling.

In Hostwerk: **Extensions → Discover** and click “Install”. If you already used this feature in Hostwerk 2.8, the update installs the extension by itself – with all your data.

Native extensions run as part of Hostwerk (own server and interface part). That is why Hostwerk only installs them from the official catalogue (with checksum) or in developer mode.

## Data

`settings.passwords`, `data/passwoerter/*.hwvault` (+ attachments in `*.files/`, backups in `sicherungen/`, website icons in `symbole/`) – exactly where Hostwerk always kept it. Removing the extension deletes nothing.

## Develop

```bash
node --test tests/*.test.js          # tests
node build-native.js .               # build the interface (sdk/build-native.js from hostwerk-public)
node check.js . --strict             # same check as the catalogue (sdk/check.js)
```

Interface source in `ui/src`, server part in `server/`. Texts in the code are English, German is in `locales/de.json`.

## License

MIT
