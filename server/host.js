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

module.exports = { bind, core, lib, broadcast, appRoot };
