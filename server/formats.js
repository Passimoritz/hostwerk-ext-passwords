'use strict';
/*
 * Import/export formats: Hostwerk recognises the export files of common password managers and browsers by itself (header
 * line or JSON structure) and maps the columns. New formats come through the online catalogue (pw-catalog.json →
 * formats[]) without a new build.
 */
const { T } = require('./i18n');

/** Robust CSV reader (quotes, line breaks inside fields, ; or , or tab). */
function parseCsv(text) {
  const t = String(text || '').replace(/^﻿/, '');
  const first = t.split(/\r?\n/)[0] || '';
  const sep = [',', ';', '\t'].map((s) => [s, (first.match(new RegExp(s === '\t' ? '\t' : `\\${s}`, 'g')) || []).length]).sort((a, b) => b[1] - a[1])[0][0];
  const rows = []; let row = []; let cur = ''; let q = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) { if (c === '"') { if (t[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; continue; }
    if (c === '"') q = true; else if (c === sep) { row.push(cur); cur = ''; } else if (c === '\n' || c === '\r') { if (c === '\r' && t[i + 1] === '\n') i++; row.push(cur); rows.push(row); row = []; cur = ''; } else cur += c;
  }
  if (cur !== '' || row.length) { row.push(cur); rows.push(row); }
  const head = (rows.shift() || []).map((h) => h.trim());
  return { head, rows: rows.filter((r) => r.some((x) => x !== '')).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] ?? '']))) };
}
function toCsv(head, rows) { const esc = (v) => { const s = String(v ?? ''); return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }; return [head.map(esc).join(','), ...rows.map((r) => head.map((h) => esc(r[h])).join(','))].join('\r\n') + '\r\n'; }

/*
 * Built-in formats: detect = header patterns (all must be there, case does not matter), map = column → field.
 * The generic format also knows German column names (Benutzer, Kennwort, Notiz …), since many exports use them.
 */
const FORMATS = [
  { id: 'bitwarden-csv', label: 'Bitwarden / Vaultwarden (CSV)', detect: ['folder', 'type', 'name', 'login_uri', 'login_username', 'login_password'], map: { name: 'name', username: 'login_username', password: 'login_password', url: 'login_uri', notes: 'notes', totp: 'login_totp', folder: 'folder', favorite: 'favorite', type: 'type' } },
  { id: 'chrome', label: 'Google Chrome / Google Password Manager (CSV)', detect: ['name', 'url', 'username', 'password'], map: { name: 'name', url: 'url', username: 'username', password: 'password', notes: 'note' } },
  { id: 'edge', label: 'Microsoft Edge (CSV)', detect: ['name', 'url', 'username', 'password'], map: { name: 'name', url: 'url', username: 'username', password: 'password', notes: 'note' } },
  { id: 'firefox', label: 'Firefox (CSV)', detect: ['url', 'username', 'password', 'httprealm'], map: { url: 'url', username: 'username', password: 'password', timeCreated: 'timeCreated' }, nameFromUrl: true },
  { id: 'apple', label: 'Apple Passwords / iCloud Keychain (CSV)', detect: ['title', 'url', 'username', 'password'], map: { name: 'Title', url: 'URL', username: 'Username', password: 'Password', notes: 'Notes', totp: 'OTPAuth' } },
  { id: '1password-csv', label: '1Password (CSV)', detect: ['title', 'url', 'username', 'password', 'archived'], // „Archived“ unterscheidet 1Password von Apple (beide mit Title/Url)
    map: { name: 'Title', url: 'Url', username: 'Username', password: 'Password', notes: 'Notes', totp: 'OTPAuth', tags: 'Tags' } },
  { id: 'lastpass', label: 'LastPass (CSV)', detect: ['url', 'username', 'password', 'extra', 'name', 'grouping'], map: { url: 'url', username: 'username', password: 'password', notes: 'extra', name: 'name', folder: 'grouping', favorite: 'fav', totp: 'totp' } },
  { id: 'dashlane', label: 'Dashlane (CSV)', detect: ['username', 'password', 'url', 'title', 'otpsecret'], map: { username: 'username', password: 'password', url: 'url', name: 'title', notes: 'note', totp: 'otpSecret' } },
  { id: 'nordpass', label: 'NordPass (CSV)', detect: ['name', 'url', 'username', 'password', 'note', 'folder'], map: { name: 'name', url: 'url', username: 'username', password: 'password', notes: 'note', folder: 'folder' } },
  { id: 'protonpass', label: 'Proton Pass (CSV)', detect: ['type', 'name', 'url', 'email', 'username', 'password'], map: { type: 'type', name: 'name', url: 'url', username: 'username', email: 'email', password: 'password', notes: 'note', totp: 'totp', folder: 'vault' } },
  { id: 'keepass-csv', label: 'KeePass / KeePassXC (CSV)', detect: ['group', 'title', 'username', 'password', 'url'], map: { folder: 'Group', name: 'Title', username: 'Username', password: 'Password', url: 'URL', notes: 'Notes', totp: 'TOTP' } },
  { id: 'enpass', label: 'Enpass (CSV)', detect: ['title', 'username', 'password'], map: { name: 'Title', username: 'Username', password: 'Password', url: 'Url', notes: 'Note' } },
  { id: 'keeper', label: 'Keeper (CSV)', detect: ['folder', 'title', 'login', 'password', 'website address'], map: { folder: 'Folder', name: 'Title', username: 'Login', password: 'Password', url: 'Website Address', notes: 'Notes' } },
  { id: 'roboform', label: 'RoboForm (CSV)', detect: ['name', 'url', 'login', 'pwd'], map: { name: 'Name', url: 'Url', username: 'Login', password: 'Pwd', notes: 'Note', folder: 'Folder' } },
  { id: 'zoho', label: 'Zoho Vault (CSV)', detect: ['secret name', 'secreturl', 'username', 'password'], map: { name: 'Secret Name', url: 'SecretURL', username: 'UserName', password: 'Password', notes: 'Notes' } },
  { id: 'kaspersky', label: 'Kaspersky Password Manager (CSV)', detect: ['website name', 'website url', 'login', 'password'], map: { name: 'Website name', url: 'Website URL', username: 'Login', password: 'Password', notes: 'Comment' } },
  { id: 'generic', label: 'General CSV (name, address, user, password)', detect: ['password'], map: { name: /^(name|titel|title|bezeichnung|account|konto)$/i, url: /^(url|website|adresse|site|login_uri|web)$/i, username: /^(user(name)?|benutzer(name)?|login|e-?mail|email)$/i, password: /^(pass(word|wort)?|pwd|kennwort)$/i, notes: /^(note[s]?|notiz(en)?|extra|comment|bemerkung)$/i, totp: /^(totp|otp|otpauth|2fa)$/i, folder: /^(folder|ordner|group|gruppe|grouping|vault|category|kategorie)$/i } },
];
let extra = [];
function setExtraFormats(list) { extra = (Array.isArray(list) ? list : []).filter((f) => f && f.id && Array.isArray(f.detect) && f.map); }
const allFormats = () => [...extra, ...FORMATS];

function col(row, spec) {
  if (!spec) return '';
  if (spec instanceof RegExp) { const k = Object.keys(row).find((h) => spec.test(h.trim())); return k ? row[k] : ''; }
  const k = Object.keys(row).find((h) => h.trim().toLowerCase() === String(spec).toLowerCase());
  return k ? row[k] : '';
}

/** Fields a CSV column can be assigned to (generic import with own assignment). */
const MAP_FIELDS = ['name', 'url', 'username', 'password', 'notes', 'totp', 'folder', 'tags', 'favorite', 'type'];
/** Best guess which column holds which field (for the assignment dialog of a general CSV). */
function guessMapping(head) {
  const g = FORMATS.find((f) => f.id === 'generic').map;
  const out = {};
  for (const k of MAP_FIELDS) { const re = g[k] || (k === 'tags' ? /^(tags?|schlagw(ö|oe)rter|labels?)$/i : k === 'favorite' ? /^(fav(orite|ourite)?|favorit)$/i : k === 'type' ? /^(type|typ|art)$/i : null); const h = re && head.find((x) => re.test(x.trim())); if (h) out[k] = h; }
  return out;
}

/** Text (CSV or JSON) → { format, label, items[], head?, mapping? }. mapping = own column assignment { field: column }. */
function detectAndParse(text, { mapping = null } = {}) {
  const t = String(text || '').trim();
  if (t.startsWith('{') || t.startsWith('[')) return parseJson(t);
  const { head, rows } = parseCsv(t);
  const low = head.map((h) => h.toLowerCase());
  // The most exact format wins (most matching headers) – Chrome/Apple/1Password share name/url/username/password
  const hits = allFormats().filter((f) => f.id !== 'generic' && f.detect.every((d) => low.includes(d.toLowerCase()))).sort((a, b) => b.detect.length - a.detect.length);
  const own = mapping && typeof mapping === 'object' ? Object.fromEntries(Object.entries(mapping).filter(([k, v]) => MAP_FIELDS.includes(k) && head.includes(v))) : null;
  const fmt = own && Object.keys(own).length ? { id: 'mapped', label: 'CSV with your column assignment', map: own }
    : hits[0] || allFormats().find((f) => f.id === 'generic' && f.detect.every((d) => low.some((h) => h.includes(d))));
  if (!fmt) throw Object.assign(new Error(T('Format not recognised. Columns: {cols}. Expected are exports of Bitwarden, Chrome, Edge, Firefox, Apple, 1Password, LastPass, Dashlane, NordPass, Proton Pass, KeePass, Enpass, Keeper, RoboForm, Zoho or a CSV with the columns name/URL/user/password.', { cols: head.join(', ') })), { head, needsMapping: head.length > 1 });
  const items = rows.map((r) => {
    const m = fmt.map;
    const type = String(col(r, m.type) || 'login').toLowerCase();
    const url = col(r, m.url);
    let name = col(r, m.name);
    if (!name && (fmt.nameFromUrl || url)) { try { name = new URL(url).hostname; } catch { name = url || 'Import'; } }
    const username = col(r, m.username) || col(r, m.email);
    const it = { type: /note|notiz/.test(type) ? 'note' : /card|karte/.test(type) ? 'card' : /identity|identität/.test(type) ? 'identity' : 'login', name: name || 'Import', username, password: col(r, m.password), urls: url ? [url] : [], notes: col(r, m.notes), totp: col(r, m.totp), folder: col(r, m.folder), tags: String(col(r, m.tags) || '').split(/[;,]/).map((x) => x.trim()).filter(Boolean), favorite: /^(1|true|yes|ja)$/i.test(String(col(r, m.favorite) || '')), source: fmt.id };
    // Remaining columns become extra fields (e.g. security questions)
    const used = new Set(Object.values(m).filter((v) => typeof v === 'string').map((v) => v.toLowerCase()));
    it.fields = Object.entries(r).filter(([k, v]) => v && !used.has(k.trim().toLowerCase()) && !Object.values(m).some((re) => re instanceof RegExp && re.test(k.trim()))).slice(0, 10).map(([k, v]) => ({ name: k.trim(), value: String(v).slice(0, 500), hidden: /pass|secret|pin|cvv/i.test(k) }));
    return it;
  });
  return { format: fmt.id, label: T(fmt.label), items, head, mapping: fmt.id === 'generic' ? guessMapping(head) : fmt.id === 'mapped' ? fmt.map : null };
}

function parseJson(t) {
  const j = JSON.parse(t);
  if (j && j.encrypted === true && !Array.isArray(j.items)) {
    if (j.passwordProtected) throw Object.assign(new Error(T('This Bitwarden export is protected with a password – enter it to import.')), { status: 428, needsPassword: true });
    throw new Error(T('This Bitwarden export is locked to the Bitwarden account (“account restricted”). Export again with “Password protected” or unencrypted – or connect the account directly.'));
  }
  // Enpass JSON: items[] mit fields[] (label/type/value)
  if (j && Array.isArray(j.items) && j.items.some((x) => x && Array.isArray(x.fields) && x.category !== undefined)) {
    const folders = new Map((j.folders || []).map((f) => [f.uuid, f.title]));
    return { format: 'enpass-json', label: 'Enpass (JSON)', items: j.items.filter((x) => !x.trashed && !x.archived).map((x) => {
      const fs = x.fields || [];
      const by = (type) => (fs.find((f) => f.type === type && f.value) || {}).value || '';
      const used = new Set();
      const pick = (type) => { const f = fs.find((y) => y.type === type && y.value && !used.has(y)); if (f) used.add(f); return f ? f.value : ''; };
      const username = pick('username') || pick('email'); const password = pick('password'); const url = pick('url'); const totp = pick('totp');
      const cat = String(x.category || '').toLowerCase();
      const type = cat === 'note' ? 'note' : cat === 'creditcard' ? 'card' : cat === 'identity' ? 'identity' : 'login';
      const card = type === 'card' ? { holder: by('ccName'), number: by('ccNumber'), expiry: by('ccExpiry'), cvv: by('ccCvc'), brand: by('ccType'), pin: by('ccPin') } : undefined;
      return { type, name: x.title || 'Import', username, password, urls: url ? [url] : [], totp, notes: x.note || '', folder: (x.folders || []).map((id) => folders.get(id)).filter(Boolean)[0] || '', favorite: !!x.favorite, tags: [], card, fields: fs.filter((f) => f.value && !used.has(f) && !/^(section|ccName|ccNumber|ccExpiry|ccCvc|ccType|ccPin)$/.test(f.type)).slice(0, 20).map((f) => ({ name: f.label || f.type, value: String(f.value), hidden: !!f.sensitive })), source: 'enpass-json' };
    }) };
  }
  // Bitwarden/Vaultwarden JSON (passwortgeschützte Exporte entschlüsselt io.js vorher)
  if (j && Array.isArray(j.items) && (j.folders !== undefined || j.encrypted !== undefined)) return parseBitwarden(j);
  // 1Password 1PUX/JSON (simplified) or Proton Pass JSON
  if (j && j.vaults && typeof j.vaults === 'object') {
    const items = [];
    for (const [vid, v] of Object.entries(j.vaults)) for (const it of v.items || []) {
      const c = it.data && it.data.content ? it.data.content : {};
      items.push({ type: it.data && it.data.type === 'note' ? 'note' : it.data && it.data.type === 'creditCard' ? 'card' : 'login', name: (it.data && it.data.metadata && it.data.metadata.name) || 'Import', username: c.username || c.itemEmail || c.itemUsername || '', password: c.password || '', urls: c.urls || [], totp: c.totpUri || '', notes: (it.data && it.data.metadata && it.data.metadata.note) || '', folder: v.name || vid, source: 'protonpass-json' });
    }
    return { format: 'protonpass-json', label: 'Proton Pass (JSON)', items };
  }
  if (Array.isArray(j) && j.length && j[0] && (j[0].password !== undefined || j[0].login !== undefined)) {
    return { format: 'generic-json', label: T('General JSON list'), items: j.map((i) => ({ type: 'login', name: i.name || i.title || i.url || 'Import', username: i.username || i.user || i.login || i.email || '', password: i.password || i.pass || '', urls: [i.url || i.uri || i.website].filter(Boolean), notes: i.notes || i.note || '', totp: i.totp || '', folder: i.folder || i.group || '', source: 'generic-json' })) };
  }
  throw new Error(T('JSON format not recognised (supported: Bitwarden/Vaultwarden export, Proton Pass, a general list).'));
}

/* ---------- export ---------- */
/* Bitwarden-Typen: 1 Zugang, 2 sichere Notiz, 3 Karte, 4 Identität, 5 SSH-Schlüssel */
const BW_TYPE = { 1: 'login', 2: 'note', 3: 'card', 4: 'identity', 5: 'ssh' };
const BW_NUM = { login: 1, note: 2, card: 3, identity: 4, ssh: 5 };
function parseBitwarden(j) {
  const folders = new Map((j.folders || []).map((f) => [f.id, f.name]));
  const date = (s) => (s ? Date.parse(s) || null : null);
  return { format: 'bitwarden-json', label: 'Bitwarden / Vaultwarden (JSON)', items: j.items.filter((i) => !i.deletedDate).map((i) => {
    const login = i.login || {};
    return {
      type: BW_TYPE[i.type] || 'login', name: i.name || 'Import', username: login.username || '', password: login.password || '', urls: (login.uris || []).map((u) => u.uri).filter(Boolean), totp: login.totp || '', notes: i.notes || '',
      folder: folders.get(i.folderId) || '', favorite: !!i.favorite, fields: (i.fields || []).map((f) => ({ name: f.name || '', value: f.value || '', hidden: f.type === 1 })).filter((f) => f.name),
      card: i.card ? { holder: i.card.cardholderName || '', number: i.card.number || '', expiry: i.card.expMonth ? `${i.card.expMonth}/${i.card.expYear || ''}` : '', cvv: i.card.code || '', brand: i.card.brand || '' } : undefined,
      identity: i.identity ? { title: i.identity.title || '', firstName: i.identity.firstName || '', lastName: i.identity.lastName || '', company: i.identity.company || '', email: i.identity.email || '', phone: i.identity.phone || '', address: [i.identity.address1, i.identity.address2, i.identity.address3].filter(Boolean).join(', '), zip: i.identity.postalCode || '', city: i.identity.city || '', state: i.identity.state || '', country: i.identity.country || '', passport: i.identity.passportNumber || '', license: i.identity.licenseNumber || '', taxId: i.identity.ssn || '' } : undefined,
      ssh: i.sshKey ? { privateKey: i.sshKey.privateKey || '', publicKey: i.sshKey.publicKey || '', fingerprint: i.sshKey.keyFingerprint || '', keyType: String(i.sshKey.publicKey || '').split(' ')[0] || '' } : undefined,
      passkeys: Array.isArray(login.fido2Credentials) ? login.fido2Credentials : [],
      history: (i.passwordHistory || []).map((h) => ({ password: h.password, until: date(h.lastUsedDate) })),
      created: date(i.creationDate), passwordChanged: date(login.passwordRevisionDate), source: 'bitwarden-json',
    };
  }) };
}
function exportBitwardenJson(items, folders = []) {
  const { randomUUID } = require('crypto');
  const fids = new Map(folders.map((f) => [f, randomUUID()]));
  const iso = (t) => (t ? new Date(t).toISOString() : null);
  return JSON.stringify({ encrypted: false, folders: [...fids.entries()].map(([name, id]) => ({ id, name })), items: items.map((i) => ({
    id: randomUUID(), folderId: fids.get(i.folder) || null, type: BW_NUM[i.type] || 1, reprompt: 0, name: i.name, notes: i.notes || null, favorite: !!i.favorite,
    fields: (i.fields || []).map((f) => ({ name: f.name, value: f.value, type: f.hidden ? 1 : 0, linkedId: null })),
    login: i.type === 'login' ? { uris: (i.urls || []).map((u) => ({ match: null, uri: u })), username: i.username || null, password: i.password || null, totp: i.totp || null, passwordRevisionDate: iso(i.passwordChanged), fido2Credentials: (i.passkeys || []).length ? i.passkeys : [] } : undefined,
    card: i.type === 'card' && i.card ? { cardholderName: i.card.holder || null, brand: i.card.brand || null, number: i.card.number || null, expMonth: (i.card.expiry || '').split('/')[0] || null, expYear: (i.card.expiry || '').split('/')[1] || null, code: i.card.cvv || null } : undefined,
    identity: i.type === 'identity' && i.identity ? { title: i.identity.title || null, firstName: i.identity.firstName || null, lastName: i.identity.lastName || null, company: i.identity.company || null, email: i.identity.email || null, phone: i.identity.phone || null, address1: i.identity.address || null, postalCode: i.identity.zip || null, city: i.identity.city || null, state: i.identity.state || null, country: i.identity.country || null, passportNumber: i.identity.passport || null, licenseNumber: i.identity.license || null, ssn: i.identity.taxId || null } : undefined,
    sshKey: i.type === 'ssh' && i.ssh ? { privateKey: i.ssh.privateKey || '', publicKey: i.ssh.publicKey || '', keyFingerprint: i.ssh.fingerprint || '' } : undefined,
    secureNote: i.type === 'note' ? { type: 0 } : undefined,
    passwordHistory: (i.history || []).length ? i.history.map((h) => ({ lastUsedDate: iso(h.until) || iso(Date.now()), password: h.password })) : null,
    creationDate: iso(i.created), revisionDate: iso(i.updated),
  })) }, null, 1);
}
function exportCsv(items, flavor = 'generic') {
  if (flavor === 'chrome') return toCsv(['name', 'url', 'username', 'password', 'note'], items.filter((i) => i.type === 'login').map((i) => ({ name: i.name, url: (i.urls || [])[0] || '', username: i.username, password: i.password, note: i.notes })));
  if (flavor === 'keepass') return toCsv(['Group', 'Title', 'Username', 'Password', 'URL', 'Notes', 'TOTP'], items.map((i) => ({ Group: i.folder, Title: i.name, Username: i.username, Password: i.password, URL: (i.urls || [])[0] || '', Notes: i.notes, TOTP: i.totp })));
  return toCsv(['folder', 'favorite', 'type', 'name', 'notes', 'fields', 'login_uri', 'login_username', 'login_password', 'login_totp'], items.map((i) => ({ folder: i.folder, favorite: i.favorite ? 1 : '', type: i.type, name: i.name, notes: i.notes, fields: (i.fields || []).map((f) => `${f.name}: ${f.value}`).join('\n'), login_uri: (i.urls || []).join(','), login_username: i.username, login_password: i.password, login_totp: i.totp })));
}

module.exports = { parseCsv, toCsv, detectAndParse, parseBitwarden, exportBitwardenJson, exportCsv, guessMapping, MAP_FIELDS, FORMATS, setExtraFormats, allFormats };
