const te = new TextEncoder();
const td = new TextDecoder();

const PBKDF2_ITERATIONS = 600000;
const AES_BITS = 256;
const RSA_BITS = 4096;
const APP_ID = 'Admin Toolbox Secure Password Share';

function b64(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode(...bytes.subarray(i, Math.min(i + chunk, bytes.length)));
  }
  return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function unb64(text) {
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

function validatePackage(pkg) {
  if (!pkg || typeof pkg !== 'object') throw new Error('Package is not valid JSON.');
  if (pkg.format !== 'admin-toolbox-secure-secret' || pkg.version !== 1) throw new Error('Unsupported package format or version.');
  if (!pkg.alg) throw new Error('Package is missing its encryption algorithm.');
}

async function encryptWithPassphrase(secret, passphrase, metadata) {
  if (!passphrase) throw new Error('A passphrase is required.');
  if (passphrase.length < 12) throw new Error('Use a passphrase of at least 12 characters.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePasswordKey(passphrase, salt);
  const aad = te.encode(APP_ID + '|v1|password');
  const payload = JSON.stringify({ secret, ...metadata, createdAt: new Date().toISOString() });
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
  if (pkg.alg !== 'PBKDF2-SHA256/AES-256-GCM') throw new Error('This package does not use passphrase encryption.');
  const salt = unb64(pkg.salt);
  const iv = unb64(pkg.iv);
  const aad = unb64(pkg.aad);
  const key = await derivePasswordKey(passphrase, salt, pkg.iterations);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, unb64(pkg.ciphertext));
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
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

async function importPrivateJwk(jwk) {
  return crypto.subtle.importKey(
    'jwk', jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}

async function encryptToRecipient(secret, publicKey, metadata) {
  const payload = JSON.stringify({ secret, ...metadata, createdAt: new Date().toISOString() });
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
  if (pkg.alg !== 'RSA-OAEP-SHA256') throw new Error('This package does not use recipient-key encryption.');
  const plain = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, unb64(pkg.ciphertext));
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
      const pkg = JSON.parse(root.querySelector('#ss-pass-in').value);
      validatePackage(pkg);
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
      const jwk = JSON.parse(root.querySelector('#ss-recipient-pub').value);
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
      const jwk = JSON.parse(root.querySelector('#ss-dec-priv').value);
      const key = await importPrivateJwk(jwk);
      const pkg = JSON.parse(root.querySelector('#ss-r-in').value);
      validatePackage(pkg);
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
      <p>
        <p class="small">
        Encrypt secrets in your browser for manual, out-of-band sharing. Nothing is uploaded, stored, or looked up.
        </p>
      </p>
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