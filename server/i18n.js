'use strict';
/*
 * Texts of the server part: English source, German from locales/de.json – through Hostwerk's translator (host.t), bound
 * once at activation. Without a host (unit tests of single modules) the English text is used.
 */
let translate = null;
const fill = (s, v) => (v ? String(s).replace(/\{(\w+)\}/g, (m, k) => (v[k] !== undefined ? String(v[k]) : m)) : String(s));
const T = (s, v) => (translate ? translate(s, v) : fill(s, v));
function bind(host) { translate = host && host.t ? host.t : null; }

module.exports = { T, bind };
