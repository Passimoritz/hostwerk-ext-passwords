'use strict';
/*
 * Password manager: Hostwerk vault, Bitwarden/Vaultwarden, 1Password, KeePass, pass, LastPass, import/export, security
 * check, TOTP, sharing with members and the browser extension. Provides ctx.pw (Hostwerk's AI tools, audit log, icons and
 * self-removal use it when it is there). The browser extension talks to the public routes (own key per browser).
 */
const host = require('./host');
const { PasswordManager } = require('./manager');

exports.activate = (h) => {
  host.bind(h);
  const pw = h.provide('pw', new PasswordManager(h.ctx));
  // Tresor als Dienst: andere Erweiterungen legen Zugänge mit host.use('passwordVault') ab
  h.provide('passwordVault', pw.vaultService());
  pw.routes(h.router);
  pw.extRoutes(h.publicRouter);
  // Verschlüsselte Stände der Hostwerk-Tresore in der Sicherungs-Zentrale (SDK 2.10) – ältere Hostwerk-Versionen ohne sie
  if (h.backups && h.backups.register && h.ctx.backupCenter) { try { h.backups.register(pw.backupSource()); } catch (e) { if (h.log) h.log('backups', e.message); } }
  h.on('shutdown', () => pw.stop());
  // Entpackte Browser-Erweiterung (falls installiert): aktuelle Dateien + Kopplungsdatei mit dem Port von heute
  const t = setTimeout(() => { try { pw.refreshExtensionFolder(); } catch { /* nächster Start */ } }, 2000);
  if (t.unref) t.unref();
};

exports.deactivate = () => {};
