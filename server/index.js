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
  pw.routes(h.router);
  pw.extRoutes(h.publicRouter);
  h.on('shutdown', () => pw.stop());
};

exports.deactivate = () => {};
