const te = new TextEncoder();
const td = new TextDecoder();
const PBKDF2_ITERATIONS = 600000;
const AES_BITS = 256;
const RSA_BITS = 4096;
const APP_ID = 'Admin Toolbox Secure Password Share';
const MIN_IMPORTED_ITERATIONS = 100000;
const MAX_IMPORTED_ITERATIONS = 1000000;
const MAX_PACKAGE_CHARS = 2 * 1024 * 1024;
const MAX_JWK_CHARS = 16 * 1024;
const MAX_PASSPHRASE_CHARS = 1024;
const MAX_CIPHERTEXT_BYTES = 1024 * 1024;
function b64(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode(...bytes.subarray(i, Math.min(i + chunk, bytes.length)));
  }
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}
function unb64(text) {
  if (typeof text !== 'string' || text.length > Math.ceil(MAX_CIPHERTEXT_BYTES * 4 / 3) + 8 || !/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) {
    throw new Error('Package contains an invalid or oversized Base64URL field.');
  }
  const normalized = text.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(text.length / 4) * 4, '=');
  const raw = atob(normalized);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}
function hex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}
function copyText(text, button) {
  navigator.clipboard?.writeText(text).then(() => {
    const old = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => button.textContent = old, 1200);
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  });
}
function setMessage(el, text, kind = '') {
  el.textContent = text;
  el.className = `notice ${kind}`.trim();
}
async function derivePasswordKey(passphrase, salt, iterations = PBKDF2_ITERATIONS) {
  const material = await crypto.subtle.importKey(
    'raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: AES_BITS },
    false,
    ['encrypt', 'decrypt']
  );
}
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}
async function publicKeyFingerprint(publicKey) {
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
  return hex(await sha256(spki));
}
function packageSummary(pkg) {
  const alg = pkg?.alg || 'unknown';
  if (alg === 'PBKDF2-SHA256/AES-256-GCM') return `Password-protected package · PBKDF2-SHA-256 · ${pkg.iterations.toLocaleString()} iterations · AES-256-GCM`;
  if (alg === 'RSA-OAEP-SHA256') return `Recipient-key package · RSA-OAEP-4096 · SHA-256`;
  return `Unknown package format`;
}
export function validatePackage(pkg) {
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) throw new Error('Package is not valid JSON.');
  if (pkg.format !== 'admin-toolbox-secure-secret' || pkg.version !== 1 || pkg.type !== 'secret') throw new Error('Unsupported package format, version or type.');
  if (pkg.alg === 'PBKDF2-SHA256/AES-256-GCM') {
    if (pkg.kdf !== 'PBKDF2-HMAC-SHA256') throw new Error('Unsupported password KDF.');
    if (!Number.isSafeInteger(pkg.iterations) || pkg.iterations < MIN_IMPORTED_ITERATIONS || pkg.iterations > MAX_IMPORTED_ITERATIONS) {
      throw new Error(`PBKDF2 iteration count must be between ${MIN_IMPORTED_ITERATIONS.toLocaleString()} and ${MAX_IMPORTED_ITERATIONS.toLocaleString()}.`);
    }
    const salt = unb64(pkg.salt);
    const iv = unb64(pkg.iv);
    const aad = unb64(pkg.aad);
    const ciphertext = unb64(pkg.ciphertext);
    if (salt.length !== 16) throw new Error('Package salt must be exactly 16 bytes.');
    if (iv.length !== 12) throw new Error('Package AES-GCM IV must be exactly 12 bytes.');
    if (new TextDecoder().decode(aad) !== APP_ID + '|v1|password') throw new Error('Package additional authenticated data is invalid.');
    if (ciphertext.length < 16 || ciphertext.length > MAX_CIPHERTEXT_BYTES) throw new Error('Package ciphertext length is invalid or exceeds 1 MiB.');
    return { algorithm: 'password', salt, iv, aad, ciphertext };
  }
  if (pkg.alg === 'RSA-OAEP-SHA256') {
    const ciphertext = unb64(pkg.ciphertext);
    if (ciphertext.length !== RSA_BITS / 8) throw new Error('RSA package ciphertext must be exactly 512 bytes for a 4096-bit key.');
    if (typeof pkg.recipientKeyFingerprint !== 'string' || !/^[a-f0-9]{64}$/i.test(pkg.recipientKeyFingerprint)) {
      throw new Error('RSA package recipient fingerprint is invalid.');
    }
    return { algorithm: 'rsa', ciphertext };
  }
  throw new Error('Unsupported package encryption algorithm.');
}
export function validatePackageText(text) {
  if (typeof text !== 'string' || text.length > MAX_PACKAGE_CHARS) throw new Error('Package JSON is missing or exceeds the 2 MiB import limit.');
  const pkg = JSON.parse(text);
  validatePackage(pkg);
  return pkg;
}
export function validateRsaJwk(jwk, privateKey = false) {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk) || jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
    throw new Error('A valid RSA JWK is required.');
  }
  const modulus = unb64(jwk.n);
  const exponent = unb64(jwk.e);
  if (modulus.length !== RSA_BITS / 8 || !(modulus[0] & 0x80)) throw new Error('Only 4096-bit RSA keys are supported.');
  if (exponent.length !== 3 || exponent[0] !== 1 || exponent[1] !== 0 || exponent[2] !== 1) throw new Error('RSA exponent must be 65537.');
  const privateFields = ['d', 'p', 'q', 'dp', 'dq', 'qi'];
  if (!privateKey && privateFields.some(field => field in jwk)) throw new Error('Provide a public JWK only; do not paste private key material here.');
  if (privateKey) {
    if (privateFields.some(field => typeof jwk[field] !== 'string' || !jwk[field])) throw new Error('The private JWK is incomplete.');
    if (unb64(jwk.d).length !== 512 || ['p', 'q', 'dp', 'dq', 'qi'].some(field => unb64(jwk[field]).length !== 256)) {
      throw new Error('RSA private-key component lengths are invalid for a 4096-bit key.');
    }
  }
  if (Array.isArray(jwk.oth) && jwk.oth.length) throw new Error('Multi-prime RSA keys are not supported.');
}
export function parseJwkText(text, privateKey = false) {
  if (typeof text !== 'string' || text.length > MAX_JWK_CHARS) throw new Error('JWK JSON exceeds the 16 KiB import limit.');
  const jwk = JSON.parse(text);
  validateRsaJwk(jwk, privateKey);
  return jwk;
}

async function encryptWithPassphrase(secret, passphrase, metadata) {
  if (typeof secret !== 'string' || te.encode(secret).length > 64 * 1024) throw new Error('Secret must be text and no larger than 64 KiB.');
  if (typeof passphrase !== 'string' || !passphrase) throw new Error('A passphrase is required.');
  if (passphrase.length < 12) throw new Error('Use a passphrase of at least 12 characters.');
  if (passphrase.length > MAX_PASSPHRASE_CHARS) throw new Error('Passphrases are limited to 1,024 characters.');
  const label = metadata?.label;
  if (label !== undefined && (typeof label !== 'string' || label.length > 256)) throw new Error('Label must be 256 characters or fewer.');
  const payload = JSON.stringify({ secret, ...(label ? { label } : {}), createdAt: new Date().toISOString() });
  if (te.encode(payload).length > 65 * 1024) throw new Error('Encrypted payload exceeds the 65 KiB limit.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePasswordKey(passphrase, salt);
  const aad = te.encode(APP_ID + '|v1|password');
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, te.encode(payload));
  return {
    format: 'admin-toolbox-secure-secret',
    version: 1,
    type: 'secret',
    alg: 'PBKDF2-SHA256/AES-256-GCM',
    kdf: 'PBKDF2-HMAC-SHA256',
    iterations: PBKDF2_ITERATIONS,
    salt: b64(salt),
    iv: b64(iv),
    aad: b64(aad),
    ciphertext: b64(new Uint8Array(cipher)),
  };
}
async function decryptWithPassphrase(pkg, passphrase) {
  const validated = validatePackage(pkg);
  if (validated.algorithm !== 'password') throw new Error('This package does not use passphrase encryption.');
  if (typeof passphrase !== 'string' || !passphrase) throw new Error('A passphrase is required.');
  if (passphrase.length > MAX_PASSPHRASE_CHARS) throw new Error('Passphrases are limited to 1,024 characters.');
  const key = await derivePasswordKey(passphrase, validated.salt, pkg.iterations);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: validated.iv, additionalData: validated.aad, tagLength: 128 }, key, validated.ciphertext);
  return JSON.parse(td.decode(plain));
}
async function generateRecipientKeys() {
  return crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: RSA_BITS, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
}
async function exportPublicJwk(key) {
  return crypto.subtle.exportKey('jwk', key);
}
async function exportPrivateJwk(key) {
  return crypto.subtle.exportKey('jwk', key);
}
async function importPublicJwk(jwk) {
  validateRsaJwk(jwk, false);
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}
async function importPrivateJwk(jwk) {
  validateRsaJwk(jwk, true);
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}
async function encryptToRecipient(secret, publicKey, metadata) {
  if (typeof secret !== 'string' || te.encode(secret).length > 350) throw new Error('Secret must be text and no larger than 350 bytes for recipient-key mode.');
  const label = metadata?.label;
  if (label !== undefined && (typeof label !== 'string' || label.length > 256)) throw new Error('Label must be 256 characters or fewer.');
  const payload = JSON.stringify({ secret, ...(label ? { label } : {}), createdAt: new Date().toISOString() });
  const plaintext = te.encode(payload);
  if (plaintext.length > 446) {
    throw new Error('The recipient-key format is intentionally limited to short secrets. Use a passphrase package for longer text.');
  }
  const cipher = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, plaintext);
  return {
    format: 'admin-toolbox-secure-secret',
    version: 1,
    type: 'secret',
    alg: 'RSA-OAEP-SHA256',
    ciphertext: b64(new Uint8Array(cipher)),
    recipientKeyFingerprint: await publicKeyFingerprint(publicKey),
  };
}
async function decryptWithPrivateKey(pkg, privateKey) {
  const validated = validatePackage(pkg);
  if (validated.algorithm !== 'rsa') throw new Error('This package does not use recipient-key encryption.');
  const privateJwk = await crypto.subtle.exportKey('jwk', privateKey);
  const publicKey = await importPublicJwk({ kty: privateJwk.kty, n: privateJwk.n, e: privateJwk.e });
  const fingerprint = await publicKeyFingerprint(publicKey);
  if (fingerprint.toLowerCase() !== pkg.recipientKeyFingerprint.toLowerCase()) throw new Error('This package was encrypted for a different recipient key.');
  const plain = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, validated.ciphertext);
  return JSON.parse(td.decode(plain));
}
function renderPasswordMode(root) {
  root.innerHTML = `
    <section class="card">
      <h2>Passphrase-protected package</h2>
      <p>Encrypt a password locally with AES-256-GCM. Send the resulting package through one channel and the passphrase through another.</p>
      <label>Label / account <input id="ss-label" autocomplete="off" placeholder="e.g. Domain admin account"></label>
      <label>Password / secret <input id="ss-secret" type="password" autocomplete="new-password"></label>
      <label>Passphrase <input id="ss-pass" type="password" autocomplete="new-password" placeholder="At least 12 characters"></label>
      <div class="actions"><button class="btn" id="ss-encrypt">Encrypt package</button></div>
      <div id="ss-pass-msg"></div>
      <textarea id="ss-pass-out" class="mono" rows="12" placeholder="Encrypted package will appear here" readonly></textarea>
      <div class="actions"><button class="btn" id="ss-copy" disabled>Copy package</button></div>
    </section>
    <section class="card">
      <h2>Decrypt a package</h2>
      <textarea id="ss-pass-in" class="mono" rows="10" placeholder="Paste encrypted package JSON here"></textarea>
      <label>Passphrase <input id="ss-decrypt-pass" type="password" autocomplete="new-password"></label>
      <div class="actions"><button class="btn" id="ss-decrypt">Decrypt locally</button></div>
      <div id="ss-dec-msg"></div>
      <pre id="ss-dec-out" class="mono"></pre>
    </section>
  `;
  let latest = null;
  const msg = root.querySelector('#ss-pass-msg');
  root.querySelector('#ss-encrypt').onclick = async () => {
    try {
      latest = await encryptWithPassphrase(
        root.querySelector('#ss-secret').value,
        root.querySelector('#ss-pass').value,
        { label: root.querySelector('#ss-label').value || undefined }
      );
      root.querySelector('#ss-pass-out').value = JSON.stringify(latest, null, 2);
      root.querySelector('#ss-copy').disabled = false;
      setMessage(msg, 'Encrypted locally. The plaintext secret is not put in the package.', 'good');
    } catch (e) { setMessage(msg, e.message, 'error'); }
  };
  root.querySelector('#ss-copy').onclick = e => copyText(JSON.stringify(latest, null, 2), e.currentTarget);
  root.querySelector('#ss-decrypt').onclick = async () => {
    try {
      const pkg = validatePackageText(root.querySelector('#ss-pass-in').value);
      const result = await decryptWithPassphrase(pkg, root.querySelector('#ss-decrypt-pass').value);
      root.querySelector('#ss-dec-out').textContent = JSON.stringify(result, null, 2);
      setMessage(root.querySelector('#ss-dec-msg'), 'Decryption succeeded locally.', 'good');
    } catch (e) {
      root.querySelector('#ss-dec-out').textContent = '';
      setMessage(root.querySelector('#ss-dec-msg'), 'Decryption failed. Check the package and passphrase.', 'error');
    }
  };
}
function renderRecipientMode(root) {
  root.innerHTML = `
    <section class="card">
      <h2>Recipient-key mode</h2>
      <p>The recipient generates a key pair locally. Share only the public key. The sender encrypts the secret to that public key; the recipient decrypts with the private key.</p>
      <div class="actions"><button class="btn" id="ss-genkeys">Generate recipient key pair</button></div>
      <div id="ss-key-msg"></div>
      <label>Public key JSON <textarea id="ss-pub" class="mono" rows="8" placeholder="Generate a key pair first" readonly></textarea></label>
      <label>Private key JSON <textarea id="ss-priv" class="mono" rows="8" placeholder="Keep this private and back it up securely" readonly></textarea></label>
      <div class="actions"><button class="btn" id="ss-copy-pub" disabled>Copy public key</button><button class="btn" id="ss-copy-priv" disabled>Copy private key</button></div>
    </section>
    <section class="card">
      <h2>Encrypt to recipient</h2>
      <label>Recipient public key JSON <textarea id="ss-recipient-pub" class="mono" rows="8"></textarea></label>
      <label>Label / account <input id="ss-r-label" autocomplete="off" placeholder="e.g. VPN account"></label>
      <label>Password / secret <input id="ss-r-secret" type="password" autocomplete="new-password"></label>
      <div class="actions"><button class="btn" id="ss-r-encrypt">Encrypt to recipient</button></div>
      <div id="ss-r-msg"></div>
      <textarea id="ss-r-out" class="mono" rows="10" readonly></textarea>
      <div class="actions"><button class="btn" id="ss-r-copy" disabled>Copy package</button></div>
    </section>
    <section class="card">
      <h2>Decrypt with private key</h2>
      <label>Private key JSON <textarea id="ss-dec-priv" class="mono" rows="8"></textarea></label>
      <label>Encrypted package JSON <textarea id="ss-r-in" class="mono" rows="8"></textarea></label>
      <div class="actions"><button class="btn" id="ss-r-decrypt">Decrypt locally</button></div>
      <div id="ss-r-dec-msg"></div>
      <pre id="ss-r-dec-out" class="mono"></pre>
    </section>
  `;
  let publicJwk = null;
  let privateJwk = null;
  let latest = null;
  root.querySelector('#ss-genkeys').onclick = async () => {
    try {
      const pair = await generateRecipientKeys();
      publicJwk = await exportPublicJwk(pair.publicKey);
      privateJwk = await exportPrivateJwk(pair.privateKey);
      root.querySelector('#ss-pub').value = JSON.stringify(publicJwk, null, 2);
      root.querySelector('#ss-priv').value = JSON.stringify(privateJwk, null, 2);
      root.querySelector('#ss-copy-pub').disabled = false;
      root.querySelector('#ss-copy-priv').disabled = false;
      const fp = await publicKeyFingerprint(pair.publicKey);
      setMessage(root.querySelector('#ss-key-msg'), `Key pair generated locally. Public-key fingerprint: ${fp}`, 'good');
    } catch (e) { setMessage(root.querySelector('#ss-key-msg'), e.message, 'error'); }
  };
  root.querySelector('#ss-copy-pub').onclick = e => copyText(JSON.stringify(publicJwk, null, 2), e.currentTarget);
  root.querySelector('#ss-copy-priv').onclick = e => copyText(JSON.stringify(privateJwk, null, 2), e.currentTarget);
  root.querySelector('#ss-r-encrypt').onclick = async () => {
    try {
      const jwk = parseJwkText(root.querySelector('#ss-recipient-pub').value, false);
      const key = await importPublicJwk(jwk);
      latest = await encryptToRecipient(
        root.querySelector('#ss-r-secret').value,
        key,
        { label: root.querySelector('#ss-r-label').value || undefined }
      );
      root.querySelector('#ss-r-out').value = JSON.stringify(latest, null, 2);
      root.querySelector('#ss-r-copy').disabled = false;
      setMessage(root.querySelector('#ss-r-msg'), `Encrypted locally for recipient key ${latest.recipientKeyFingerprint}`, 'good');
    } catch (e) { setMessage(root.querySelector('#ss-r-msg'), e.message, 'error'); }
  };
  root.querySelector('#ss-r-copy').onclick = e => copyText(JSON.stringify(latest, null, 2), e.currentTarget);
  root.querySelector('#ss-r-decrypt').onclick = async () => {
    try {
      const jwk = parseJwkText(root.querySelector('#ss-dec-priv').value, true);
      const key = await importPrivateJwk(jwk);
      const pkg = validatePackageText(root.querySelector('#ss-r-in').value);
      const result = await decryptWithPrivateKey(pkg, key);
      root.querySelector('#ss-r-dec-out').textContent = JSON.stringify(result, null, 2);
      setMessage(root.querySelector('#ss-r-dec-msg'), 'Decryption succeeded locally.', 'good');
    } catch (e) {
      root.querySelector('#ss-r-dec-out').textContent = '';
      setMessage(root.querySelector('#ss-r-dec-msg'), 'Decryption failed. Check the key and package.', 'error');
    }
  };
}
export function renderSShare(app) {
  app.innerHTML = `
    <section class="card">
      <h1>Secure Password Share</h1>
      <p class="small">Encrypt secrets in your browser for manual, out-of-band sharing. Nothing is uploaded, stored, or looked up.</p>
      <div class="notice warning"><strong>Important:</strong> this tool transports encrypted packages; it does not provide a server-side one-time secret service. Delete plaintext copies after use and verify recipient identity through a trusted channel.</div>
      <div class="actions">
        <button class="btn" id="ss-tab-pass">Passphrase package</button>
        <button class="btn" id="ss-tab-key">Recipient-key package</button>
      </div>
    </section>
    <div id="ss-root"></div>
    <section class="card">
      <h2>Local-only design</h2>
      <ul>
        <li>No API calls, DNS lookups, reputation lookups, or server-side storage.</li>
        <li>Encryption uses the browser Web Crypto API.</li>
        <li>Passphrase mode uses PBKDF2-HMAC-SHA-256 + AES-256-GCM.</li>
        <li>Recipient-key mode uses RSA-OAEP with SHA-256 and 4096-bit keys.</li>
        <li>Generated private keys are exportable because this app deliberately avoids persistent browser storage; protect the downloaded private key yourself.</li>
      </ul>
    </section>
  `;
  const child = app.querySelector('#ss-root');
  app.querySelector('#ss-tab-pass').onclick = () => renderPasswordMode(child);
  app.querySelector('#ss-tab-key').onclick = () => renderRecipientMode(child);
  renderPasswordMode(child);
}