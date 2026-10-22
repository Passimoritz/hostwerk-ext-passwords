'use strict';
/*
 * Access to Hostwerk's building blocks for every module of the password manager (bound once at activation).
 * Unit tests bind a small fake host.
 */
let H = null;
function bind(host) { H = host; require('./i18n').bind(host); }
const need = () => { if (!H) throw new Error('password manager: host not bound'); return H; };
const core = (name) => need().core(name);
const lib = (name) => need().lib(name);
const broadcast = (msg) => { if (H && H.broadcast) H.broadcast(msg); };
const appRoot = () => (H && H.appRoot) || null;
/** Stabiler Hostwerk-Dienst vorhanden UND erlaubt? (host.supports, SDK 3.3 – ältere Hostwerk-Versionen: nein) */
const can = (name) => { try { return !!(H && typeof H.supports === 'function' && H.supports(name)); } catch { return false; } };
/** Der gebundene host selbst (für die stabilen Dienste host.icons, host.sshKeys, host.traces) */
const h = () => need();

module.exports = { bind, core, lib, broadcast, appRoot, can, h };
