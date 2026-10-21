'use strict';
/*
 * SSH keys in the vault: create ed25519 pairs (OpenSSH format) and read pasted/imported keys – public part, fingerprint
 * (SHA256 like ssh-keygen -l) and type. Uses ssh2 (comes with Hostwerk); without it only public keys are recognised.
 */
const crypto = require('crypto');
const host = require('./host');
const { T } = require('./i18n');

const ssh2 = () => { try { return host.lib('ssh2'); } catch { return null; } };
/** SHA256:… fingerprint of an OpenSSH public key line ("ssh-ed25519 AAAA… comment"). */
function fingerprint(pubLine) {
  const b64 = String(pubLine || '').trim().split(/\s+/)[1];
  if (!b64) return '';
  return 'SHA256:' + crypto.createHash('sha256').update(Buffer.from(b64, 'base64')).digest('base64').replace(/=+$/, '');
}

/** New ed25519 key pair → { privateKey, publicKey, fingerprint, keyType } */
function generate(comment = 'hostwerk') {
  const lib = ssh2();
  if (!lib || !lib.utils.generateKeyPairSync) throw new Error(T('Creating SSH keys needs Hostwerk’s ssh2 library.'));
  const c = String(comment || 'hostwerk').replace(/[^\w@.\- ]/g, '').slice(0, 80) || 'hostwerk';
  const k = lib.utils.generateKeyPairSync('ed25519', { comment: c });
  const publicKey = String(k.public).trim();
  return { privateKey: String(k.private).trim() + '\n', publicKey, fingerprint: fingerprint(publicKey), keyType: 'ssh-ed25519' };
}

/**
 * Describe a key the user pasted or an import brought: private key (OpenSSH/PEM, without passphrase) → public part;
 * public key alone is fine too. Unreadable keys are kept as they are (an error only when nothing fits).
 */
function describe({ privateKey = '', publicKey = '' } = {}) {
  const priv = String(privateKey || '').trim();
  let pub = String(publicKey || '').trim();
  let keyType = pub.split(/\s+/)[0] || '';
  if (priv) {
    const lib = ssh2();
    const parsed = lib ? lib.utils.parseKey(priv) : null;
    if (parsed && !(parsed instanceof Error)) {
      const k = Array.isArray(parsed) ? parsed[0] : parsed;
      keyType = k.type;
      if (!pub) pub = `${k.type} ${k.getPublicSSH().toString('base64')}${k.comment ? ` ${k.comment}` : ''}`;
    } else if (parsed instanceof Error && /passphrase/i.test(parsed.message)) {
      if (!pub) throw Object.assign(new Error(T('This SSH key is protected with a passphrase – please also paste the public key (.pub).')), { status: 400 });
    } else if (!/PRIVATE KEY/.test(priv)) throw Object.assign(new Error(T('This does not look like an SSH private key.')), { status: 400 });
  }
  if (pub && !/^(ssh-|ecdsa-|sk-)/.test(pub)) throw Object.assign(new Error(T('This does not look like an SSH public key.')), { status: 400 });
  return { privateKey: priv ? priv + '\n' : '', publicKey: pub, fingerprint: pub ? fingerprint(pub) : '', keyType };
}

module.exports = { generate, describe, fingerprint };
