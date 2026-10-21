'use strict';
/*
 * Files in and out – everything beyond plain text:
 *   KeePass .kdbx (KDBX 3/4, read + write, with passkeys in KeePassXC's KPEX_PASSKEY_* fields) and KeePass XML,
 *   1Password .1pux (ZIP with export.data), Bitwarden JSON with password (read + write).
 * Text formats (CSV/JSON of every common service, own column assignment) come from formats.js.
 * Nothing here keeps files: input arrives as text or Base64 from the interface and leaves as a buffer.
 */
const crypto = require('crypto');
const path = require('path');
const host = require('./host');
const formats = require('./formats');
const { iconOf } = require('./store');
const pwc = require('./crypto');
const { T } = require('./i18n');

const needPassword = (msg) => Object.assign(new Error(msg), { status: 428, needsPassword: true });
const KDBX_MAGIC = Buffer.from([0x03, 0xd9, 0xa2, 0x9a]);

/* kdbxweb has no Argon2 – hash-wasm (pure WebAssembly, also runs under Smart App Control) provides it */
let argonReady = false;
function kdbxLib() {
  const kdbx = host.lib('kdbxweb');
  if (!argonReady) {
    const hw = host.lib('hash-wasm');
    kdbx.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type) => {
      const fn = type === 0 ? hw.argon2d : type === 1 ? hw.argon2i : hw.argon2id;
      const out = await fn({ password: new Uint8Array(password), salt: new Uint8Array(salt), parallelism, iterations, memorySize: memory, hashLength: length, outputType: 'binary' });
      return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
    });
    argonReady = true;
  }
  return kdbx;
}

/* ---------- passkeys: Bitwarden (fido2Credentials) ⇄ KeePassXC (KPEX_PASSKEY_*) ---------- */
const b64u = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = (s) => Buffer.from(String(s || '').replace(/-/g, '+').replace(/_/g, '/'), 'base64');
/** Bitwarden keeps a 16-byte id as GUID text, longer ones as "b64.<base64url>". */
function credIdBytes(id) {
  const s = String(id || '');
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return Buffer.from(s.replace(/-/g, ''), 'hex');
  return fromB64u(s.replace(/^b64\./, ''));
}
function credIdText(bytes) {
  if (bytes.length === 16) { const h = bytes.toString('hex'); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`; }
  return `b64.${b64u(bytes)}`;
}
const pemOf = (der) => `-----BEGIN PRIVATE KEY-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----\n`;
const derOf = (pem) => Buffer.from(String(pem || '').replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
function passkeyToKeepass(p) {
  return { KPEX_PASSKEY_CREDENTIAL_ID: b64u(credIdBytes(p.credentialId)), KPEX_PASSKEY_PRIVATE_KEY_PEM: p.keyValue ? pemOf(fromB64u(p.keyValue)) : '', KPEX_PASSKEY_RELYING_PARTY: p.rpId || '', KPEX_PASSKEY_USERNAME: p.userName || '', KPEX_PASSKEY_USER_HANDLE: p.userHandle || '' };
}
function passkeyFromKeepass(get) {
  const id = get('KPEX_PASSKEY_CREDENTIAL_ID'); const rp = get('KPEX_PASSKEY_RELYING_PARTY');
  if (!id || !rp) return null;
  const pem = get('KPEX_PASSKEY_PRIVATE_KEY_PEM');
  return { credentialId: credIdText(fromB64u(id)), keyType: 'public-key', keyAlgorithm: 'ECDSA', keyCurve: 'P-256', keyValue: pem ? b64u(derOf(pem)) : '', rpId: rp, rpName: rp, userHandle: get('KPEX_PASSKEY_USER_HANDLE') || '', userName: get('KPEX_PASSKEY_USERNAME') || '', counter: '0', discoverable: 'true' };
}

/* ---------- KeePass (.kdbx) ---------- */
const STD = new Set(['Title', 'UserName', 'Password', 'URL', 'Notes', 'otp', 'TOTP Seed', 'TimeOtp-Secret-Base32']);
const kval = (e, k) => { const v = e.fields.get(k); if (!v) return ''; return typeof v === 'string' ? v : v.getText(); };
/** Entries of an open kdbxweb database → items (recycle bin stays out, groups become folders). */
function kdbxItems(db) {
  const out = [];
  const bin = db.meta.recycleBinUuid && db.meta.recycleBinUuid.id;
  const rec = (g, name) => {
    if (bin && g.uuid && g.uuid.id === bin) return;
    for (const e of g.entries) {
      const get = (k) => kval(e, k);
      const url = get('URL');
      const pk = passkeyFromKeepass(get);
      const ci = e.customIcon && db.meta.customIcons.get(e.customIcon.id);
      out.push({
        icon: ci ? iconOf({ data: Buffer.from(ci.data) }) : null,
        type: 'login', name: get('Title') || T('(untitled)'), username: get('UserName') || (pk && pk.userName) || '', password: get('Password'), urls: url ? [url] : (pk ? [`https://${pk.rpId}`] : []),
        totp: get('otp') || get('TOTP Seed') || get('TimeOtp-Secret-Base32'), notes: get('Notes'), folder: name, tags: e.tags || [], favorite: false,
        fields: [...e.fields.keys()].filter((k) => !STD.has(k) && !k.startsWith('KPEX_PASSKEY_')).map((k) => ({ name: k, value: get(k), hidden: typeof e.fields.get(k) !== 'string' })),
        passkeys: pk ? [pk] : [],
        history: (e.history || []).map((h) => ({ password: kval(h, 'Password'), until: h.times.lastModTime ? h.times.lastModTime.getTime() : null })).filter((h) => h.password).reverse().slice(0, 10),
        created: e.times.creationTime ? e.times.creationTime.getTime() : null, source: 'kdbx',
      });
    }
    for (const s of g.groups) rec(s, name ? `${name}/${s.name}` : s.name);
  };
  rec(db.getDefaultGroup(), '');
  return out;
}
async function readKdbx(buf, password, keyFile = null) {
  const kdbx = kdbxLib();
  try {
    const db = await kdbx.Kdbx.load(new Uint8Array(buf).buffer, new kdbx.Credentials(password ? kdbx.ProtectedValue.fromString(password) : null, keyFile ? new Uint8Array(keyFile).buffer : null));
    return kdbxItems(db);
  } catch (e) { throw Object.assign(new Error(T('The KeePass file cannot be opened (password/key file?): {msg}', { msg: e.message })), { status: 401 }); }
}
/**
 * KeePass file (KDBX 4, Argon2id) with its own password – folders become groups, 2FA as "otp", extra fields stay (secret ones
 * protected), passkeys as KeePassXC fields, card/SSH data in the notes and fields.
 */
async function writeKdbx(items, password, title = 'Hostwerk') {
  const kdbx = kdbxLib();
  const db = kdbx.Kdbx.create(new kdbx.Credentials(kdbx.ProtectedValue.fromString(password)), title);
  const P = (s) => kdbx.ProtectedValue.fromString(String(s || ''));
  const groups = new Map([['', db.getDefaultGroup()]]);
  const groupFor = (folder) => {
    let key = ''; let g = db.getDefaultGroup();
    for (const p of String(folder || '').split('/').map((x) => x.trim()).filter(Boolean)) { key = key ? `${key}/${p}` : p; if (!groups.has(key)) groups.set(key, db.createGroup(g, p)); g = groups.get(key); }
    return g;
  };
  for (const it of items) {
    const e = db.createEntry(groupFor(it.folder));
    e.fields.set('Title', it.name || '');
    e.fields.set('UserName', it.username || '');
    e.fields.set('Password', P(it.password));
    e.fields.set('URL', (it.urls || [])[0] || '');
    const extra = [];
    if (it.card) extra.push(`${T('Card')}: ${it.card.number || ''} ${it.card.expiry || ''}`.trim());
    const notes = [it.notes || '', ...(it.urls || []).slice(1).map((u) => `URL: ${u}`), ...extra].filter(Boolean).join('\n');
    e.fields.set('Notes', notes);
    if (it.totp) e.fields.set('otp', P(it.totp));
    for (const f of it.fields || []) if (f && f.name && !STD.has(f.name)) e.fields.set(String(f.name), f.hidden ? P(f.value) : String(f.value || ''));
    if (it.card) { for (const [k, v] of [['Card holder', it.card.holder], ['Card number', it.card.number], ['Valid until', it.card.expiry], ['CVV', it.card.cvv]]) if (v) e.fields.set(k, k === 'CVV' || k === 'Card number' ? P(v) : String(v)); }
    if (it.ssh) { if (it.ssh.privateKey) e.fields.set('SSH private key', P(it.ssh.privateKey)); if (it.ssh.publicKey) e.fields.set('SSH public key', it.ssh.publicKey); }
    if (it.identity) for (const [k, v] of Object.entries(it.identity)) if (v) e.fields.set(k, String(v));
    const pk = (it.passkeys || [])[0];
    if (pk) for (const [k, v] of Object.entries(passkeyToKeepass(pk))) if (v) e.fields.set(k, k === 'KPEX_PASSKEY_PRIVATE_KEY_PEM' ? P(v) : String(v));
    e.tags = Array.isArray(it.tags) ? it.tags : [];
    // Eigenes Bild → „Custom Icon“ der KeePass-Datei
    if (it.icon && it.icon.data) { const u = kdbx.KdbxUuid.random(); db.meta.customIcons.set(u.id, { data: new Uint8Array(Buffer.from(it.icon.data, 'base64')).buffer, name: it.name || '', lastModified: new Date() }); e.customIcon = u; }
  }
  return Buffer.from(await db.save());
}

/* ---------- KeePass XML (KeePass 2 "XML export", unencrypted) ---------- */
const ENT = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };
const unxml = (s) => String(s).replace(/&(#x[0-9a-f]+|#\d+|\w+);/gi, (m, e) => (e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : ENT[e] ?? m));
/** Small XML reader: elements, attributes, text (CDATA, comments and declarations are handled). */
function parseXml(xml) {
  const root = { name: '#', children: [], text: '' };
  const stack = [root];
  const re = /<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<(\/?)([A-Za-z_][\w.:-]*)((?:\s+[\w.:-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/g;
  let m;
  while ((m = re.exec(xml))) {
    const top = stack[stack.length - 1];
    if (m[1] !== undefined) { top.text += m[1]; continue; }
    if (m[3]) {
      if (m[2]) { if (stack.length > 1) stack.pop(); continue; }
      const attrs = {}; for (const a of m[4].matchAll(/([\w.:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) attrs[a[1]] = unxml(a[2] ?? a[3]);
      const el = { name: m[3], attrs, children: [], text: '' };
      top.children.push(el);
      if (!m[5]) stack.push(el);
    } else if (m[6] !== undefined) top.text += unxml(m[6]);
  }
  return root;
}
const kid = (el, name) => el.children.find((c) => c.name === name);
const kids = (el, name) => el.children.filter((c) => c.name === name);
function keepassXmlItems(xml) {
  const doc = parseXml(xml);
  const file = kid(doc, 'KeePassFile');
  const rootEl = file && kid(file, 'Root');
  if (!rootEl) throw new Error(T('This XML file is not a KeePass export.'));
  const meta = kid(file, 'Meta');
  const bin = meta && kid(meta, 'RecycleBinUUID') ? kid(meta, 'RecycleBinUUID').text.trim() : '';
  // Eigene Symbole: <Meta><CustomIcons><Icon><UUID/><Data/> (Base64), Einträge verweisen mit <CustomIconUUID>
  const icons = new Map(); const ci = meta && kid(meta, 'CustomIcons');
  for (const ic of ci ? kids(ci, 'Icon') : []) { const u = kid(ic, 'UUID'); const d = kid(ic, 'Data'); if (u && d) icons.set(u.text.trim(), d.text.trim()); }
  const out = [];
  const rec = (g, name) => {
    const uuid = kid(g, 'UUID') ? kid(g, 'UUID').text.trim() : '';
    if (bin && uuid === bin) return;
    for (const e of kids(g, 'Entry')) {
      const vals = new Map(); const secret = new Set();
      for (const s of kids(e, 'String')) { const k = kid(s, 'Key') ? kid(s, 'Key').text : ''; const v = kid(s, 'Value'); if (!k) continue; vals.set(k, v ? v.text : ''); if (v && /true/i.test(v.attrs.Protected || v.attrs.ProtectInMemory || '')) secret.add(k); }
      const get = (k) => vals.get(k) || '';
      const pk = passkeyFromKeepass(get);
      const tags = kid(e, 'Tags') ? kid(e, 'Tags').text.split(/[;,]/).map((x) => x.trim()).filter(Boolean) : [];
      const hist = kid(e, 'History') ? kids(kid(e, 'History'), 'Entry').map((h) => { const s = kids(h, 'String').find((x) => kid(x, 'Key') && kid(x, 'Key').text === 'Password'); return s && kid(s, 'Value') ? kid(s, 'Value').text : ''; }).filter(Boolean).reverse().slice(0, 10).map((p) => ({ password: p, until: null })) : [];
      const iu = kid(e, 'CustomIconUUID') ? kid(e, 'CustomIconUUID').text.trim() : '';
      out.push({ icon: iu && icons.has(iu) ? iconOf(icons.get(iu)) : null, type: 'login', name: get('Title') || T('(untitled)'), username: get('UserName'), password: get('Password'), urls: get('URL') ? [get('URL')] : [], totp: get('otp') || get('TOTP Seed'), notes: get('Notes'), folder: name, tags, favorite: false, fields: [...vals.keys()].filter((k) => !STD.has(k) && !k.startsWith('KPEX_PASSKEY_') && vals.get(k)).map((k) => ({ name: k, value: vals.get(k), hidden: secret.has(k) })), passkeys: pk ? [pk] : [], history: hist, source: 'keepass-xml' });
    }
    for (const s of kids(g, 'Group')) { const n = kid(s, 'Name') ? kid(s, 'Name').text : ''; rec(s, name ? `${name}/${n}` : n); }
  };
  // Die oberste Gruppe ist die Datenbank selbst – ihr Name wird kein Ordner
  for (const g of kids(rootEl, 'Group')) rec(g, '');
  return out;
}

/* ---------- 1Password (.1pux) ---------- */
function unzipEntry(buf, wanted) {
  const yauzl = host.lib('yauzl');
  return new Promise((ok, fail) => {
    yauzl.fromBuffer(buf, { lazyEntries: true }, (err, zip) => {
      if (err) return fail(err);
      let found = false;
      zip.on('entry', (e) => {
        if (e.fileName !== wanted) return zip.readEntry();
        found = true;
        if (e.uncompressedSize > 200 * 1024 * 1024) return fail(new Error('export.data too large'));
        return zip.openReadStream(e, (e2, s) => { if (e2) return fail(e2); const parts = []; s.on('data', (d) => parts.push(d)); s.on('end', () => { zip.close(); ok(Buffer.concat(parts)); }); s.on('error', fail); return undefined; });
      });
      zip.on('end', () => { if (!found) fail(new Error(T('No “{name}” in the archive – is this a 1Password export (.1pux)?', { name: wanted }))); });
      zip.readEntry();
      return undefined;
    });
  });
}
const CAT = { '001': 'login', '005': 'login', '003': 'note', '002': 'card', '004': 'identity', 114: 'ssh', 105: 'ssh' };
function opValue(v) {
  if (v == null || typeof v !== 'object') return v == null ? '' : String(v);
  for (const k of ['concealed', 'string', 'totp', 'url', 'phone', 'creditCardNumber', 'creditCardType', 'menu', 'gender']) if (typeof v[k] === 'string') return v[k];
  if (v.email) return typeof v.email === 'string' ? v.email : v.email.email_address || '';
  if (v.monthYear) { const s = String(v.monthYear); return `${s.slice(4)}/${s.slice(0, 4)}`; }
  if (v.date) return new Date(Number(v.date) * 1000).toISOString().slice(0, 10);
  if (v.address) return [v.address.street, v.address.zip, v.address.city, v.address.state, v.address.country].filter(Boolean).join(', ');
  if (v.sshKey) return v.sshKey.privateKey || '';
  return '';
}
async function read1pux(buf) {
  const j = JSON.parse((await unzipEntry(buf, 'export.data')).toString('utf8'));
  const out = [];
  for (const acc of j.accounts || []) for (const vault of acc.vaults || []) for (const it of vault.items || []) {
    if (it.state && it.state !== 'active') continue;
    const d = it.details || {}; const o = it.overview || {};
    const type = CAT[it.categoryUuid] || 'login';
    const lf = d.loginFields || [];
    const fields = []; const sec = {}; let totp = ''; let ssh = null;
    for (const s of d.sections || []) for (const f of s.fields || []) {
      const v = f.value || {};
      if (v.totp) { totp = totp || v.totp; continue; }
      if (v.sshKey) { ssh = { privateKey: v.sshKey.privateKey || '', publicKey: (v.sshKey.metadata || {}).publicKey || '', fingerprint: (v.sshKey.metadata || {}).fingerprint || '', keyType: (v.sshKey.metadata || {}).keyType || '' }; continue; }
      const val = opValue(v);
      if (!val) continue;
      sec[String(f.id || '').toLowerCase()] = val;
      fields.push({ name: f.title || f.id || '', value: val, hidden: v.concealed !== undefined });
    }
    const pick = (...ids) => { for (const id of ids) if (sec[id]) { const i = fields.findIndex((f) => f.value === sec[id]); if (i >= 0) fields.splice(i, 1); return sec[id]; } return ''; };
    const urls = [...new Set([o.url, ...(o.urls || []).map((u) => u.url)].filter(Boolean))];
    const card = type === 'card' ? { holder: pick('cardholder'), number: pick('ccnum'), expiry: pick('expiry'), cvv: pick('cvv'), brand: pick('type'), pin: pick('pin') } : undefined;
    const identity = type === 'identity' ? { firstName: pick('firstname'), lastName: pick('lastname'), company: pick('company'), email: pick('email'), phone: pick('defphone', 'cellphone', 'homephone'), address: pick('address'), birthday: pick('birthdate') } : undefined;
    out.push({
      type, name: o.title || 'Import', username: (lf.find((f) => f.designation === 'username') || {}).value || '', password: (lf.find((f) => f.designation === 'password') || {}).value || d.password || '',
      urls, totp, notes: d.notesPlain || '', folder: (vault.attrs && vault.attrs.name) || '', tags: o.tags || [], favorite: Number(it.favIndex) > 0, fields: fields.filter((f) => f.name).slice(0, 30), card, identity, ssh: ssh || undefined,
      history: (d.passwordHistory || []).map((h) => ({ password: h.value, until: h.time ? h.time * 1000 : null })).filter((h) => h.password).slice(0, 10),
      created: it.createdAt ? it.createdAt * 1000 : null, source: '1pux',
    });
  }
  return { format: '1pux', label: '1Password (.1pux)', items: out };
}

/* ---------- Bitwarden JSON with password ---------- */
async function bitwardenOpen(j, password) {
  if (!password) throw needPassword(T('This Bitwarden export is protected with a password – enter it to import.'));
  const keys = await pwc.bitwardenKey(password, j.salt, j);
  pwc.bwDecrypt(keys, j.encKeyValidation_DO_NOT_EDIT); // falsches Passwort → 401
  return JSON.parse(pwc.bwDecrypt(keys, j.data));
}
async function bitwardenEncrypted(items, password) {
  const salt = crypto.randomBytes(16).toString('base64');
  const kdf = { kdfType: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null };
  const keys = await pwc.bitwardenKey(password, salt, kdf);
  const folders = [...new Set(items.map((x) => x.folder).filter(Boolean))];
  return JSON.stringify({ encrypted: true, passwordProtected: true, salt, ...kdf, encKeyValidation_DO_NOT_EDIT: pwc.bwEncrypt(keys, crypto.randomUUID()), data: pwc.bwEncrypt(keys, formats.exportBitwardenJson(items, folders)) }, null, 2);
}

/**
 * Any import file → { format, label, items, head?, mapping? }. text = text files, data = Base64 for binary ones (.kdbx, .1pux),
 * password for encrypted files (otherwise an error with needsPassword), mapping = own column assignment for CSV.
 */
async function parseInput({ text = null, data = null, name = '', password = '', mapping = null } = {}) {
  const buf = data ? Buffer.from(String(data), 'base64') : null;
  const ext = path.extname(String(name || '')).toLowerCase();
  if (buf && (ext === '.kdbx' || buf.subarray(0, 4).equals(KDBX_MAGIC))) {
    if (!password) throw needPassword(T('The KeePass file is encrypted – enter its password.'));
    return { format: 'kdbx', label: 'KeePass (.kdbx)', items: await readKdbx(buf, password) };
  }
  if (buf && (ext === '.1pux' || (buf[0] === 0x50 && buf[1] === 0x4b))) return read1pux(buf);
  const t = String(text ?? (buf ? buf.toString('utf8') : '')).replace(/^﻿/, '').trim();
  if (!t) throw Object.assign(new Error(T('The file is empty.')), { status: 400 });
  if (t.startsWith('<')) return { format: 'keepass-xml', label: 'KeePass (XML)', items: keepassXmlItems(t) };
  if (t.startsWith('{')) {
    let j = null; try { j = JSON.parse(t); } catch { /* formats meldet es */ }
    if (j && j.encrypted === true && j.passwordProtected && j.data) return formats.parseBitwarden(await bitwardenOpen(j, password));
  }
  return formats.detectAndParse(t, { mapping });
}

module.exports = { parseInput, readKdbx, writeKdbx, kdbxItems, kdbxLib, keepassXmlItems, read1pux, bitwardenOpen, bitwardenEncrypted, passkeyToKeepass, passkeyFromKeepass, parseXml };
