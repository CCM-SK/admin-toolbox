function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function pretty(value) {
    return JSON.stringify(value, null, 2);
}

function base64urlToBytes(value) {
    const clean = String(value || '').replace(/\s+/g, '');
    if (!clean) return new Uint8Array();
    if (!/^[A-Za-z0-9_-]+={0,2}$/.test(clean)) {
        throw new Error('Invalid Base64URL data.');
    }
    let b64 = clean.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    try {
        const binary = atob(b64);
        return Uint8Array.from(binary, c => c.charCodeAt(0));
    } catch {
        throw new Error('Invalid Base64URL data.');
    }
}

function base64urlDecodeText(value) {
    return new TextDecoder('utf-8', { fatal: true }).decode(base64urlToBytes(value));
}

function base64urlToHex(value) {
    return Array.from(base64urlToBytes(value), b => b.toString(16).padStart(2, '0')).join('');
}

function readableTime(seconds) {
    if (typeof seconds !== 'number' || !Number.isFinite(seconds)) return '—';
    const d = new Date(seconds * 1000);
    if (Number.isNaN(d.getTime())) return 'Invalid time';
    return `${d.toLocaleString()} (${d.toISOString()})`;
}

function timeBadge(seconds, mode) {
    if (typeof seconds !== 'number' || !Number.isFinite(seconds)) {
        return { label: 'NOT PRESENT', cls: 'badge', detail: 'Not present or not numeric' };
    }
    const now = Date.now() / 1000;
    if (mode === 'exp') {
        return seconds < now
            ? { label: 'EXPIRED', cls: 'badge danger', detail: readableTime(seconds) }
            : { label: 'NOT EXPIRED', cls: 'badge ok', detail: readableTime(seconds) };
    }
    if (mode === 'nbf') {
        return seconds > now
            ? { label: 'NOT YET VALID', cls: 'badge warn', detail: readableTime(seconds) }
            : { label: 'ACTIVE', cls: 'badge ok', detail: readableTime(seconds) };
    }
    return { label: 'PRESENT', cls: 'badge ok', detail: readableTime(seconds) };
}

function claimText(value) {
    if (value === undefined || value === null) return '—';
    if (Array.isArray(value)) return value.join(', ');
    if (typeof value === 'object') return pretty(value);
    return String(value);
}

function detect(value) {
    const text = value.trim();
    if (!text) throw new Error('Paste a JWT, JWS, JWK, or JWK Set.');

    if (text.startsWith('{') || text.startsWith('[')) {
        try {
            return { type: 'json', value: JSON.parse(text) };
        } catch {
            throw new Error('The input looks like JSON, but the JSON is invalid.');
        }
    }

    const parts = text.split('.');
    if (parts.length === 3) return { type: 'jws', value: text };
    if (parts.length === 5) return { type: 'jwe', value: text };
    throw new Error('Unrecognized input. Expected 3-part JWT/JWS, 5-part JWE, JWK JSON, or JWK Set JSON.');
}

function signatureDescription(alg) {
    const map = {
        HS256: 'HMAC + SHA-256',
        HS384: 'HMAC + SHA-384',
        HS512: 'HMAC + SHA-512',
        RS256: 'RSA PKCS#1 v1.5 + SHA-256',
        RS384: 'RSA PKCS#1 v1.5 + SHA-384',
        RS512: 'RSA PKCS#1 v1.5 + SHA-512',
        PS256: 'RSA-PSS + SHA-256',
        PS384: 'RSA-PSS + SHA-384',
        PS512: 'RSA-PSS + SHA-512',
        ES256: 'ECDSA P-256 + SHA-256',
        ES384: 'ECDSA P-384 + SHA-384',
        ES512: 'ECDSA P-521 + SHA-512',
        EdDSA: 'EdDSA'
    };
    return map[alg] || 'Algorithm name only; no verification performed';
}

function renderStart(app) {
    app.innerHTML = `
      <section class="card">
        <div class="row between">
          <div>
            <h2>JWT / JWS / JWK Decoder</h2>
            <p class="small">Inspect token headers, claims, timestamps, signatures and JWK fields locally</p>
          </div>
          <span class="badge warn">DECODE ONLY - DOES NOT VERIFY</span>
        </div>

        <div class="notice warning">
          <strong>Important:</strong> decoding is not verification. This tool does not prove authenticity,
          validate issuer trust, verify signatures, retrieve keys, check revocation and does not contact any remote service
        </div>

        <label for="jwt-input">JWT / JWS / JWK / JWK Set</label>
        <textarea id="jwt-input" rows="11"
          placeholder="Paste a compact JWT/JWS or JWK JSON here…"></textarea>

        <div class="row" style="margin-top:.75rem">
          <button class="btn" type="button" id="jwt-decode">Decode</button>
          <button class="btn secondary" type="button" id="jwt-clear">Clear</button>
          <button class="btn secondary" type="button" id="jwt-paste">Paste</button>
        </div>
        <div id="jwt-message" class="notice hidden" role="status"></div>
      </section>
    `;
}

function renderJwk(app, obj) {
    const set = obj && Array.isArray(obj.keys);
    const keys = set ? obj.keys : [obj];
    if (!keys.length || keys.some(k => !k || typeof k !== 'object' || Array.isArray(k) || !k.kty)) {
        throw new Error('JSON input is not a valid JWK or JWK Set.');
    }

    const binaryFields = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'x', 'y', 'k'];

    app.innerHTML = `
      <section class="card">
        <div class="row between">
          <div>
            <h2>JWT / JWS / JWK Decoder</h2>
            <p class="muted">${set ? 'JWK Set' : 'JWK'} inspection</p>
          </div>
          <span class="badge warn">DECODE ONLY — DOES NOT VERIFY</span>
        </div>

        <div class="grid two">
          <div class="stat"><span>Input</span><strong>${set ? 'JWK Set' : 'JWK'}</strong></div>
          <div class="stat"><span>Key count</span><strong>${keys.length}</strong></div>
        </div>

        <div class="notice warning">
          A decoded JWK is just supplied key data. This view does not establish trust or prove that a key belongs to an issuer.
        </div>

        ${keys.map((key, i) => `
          <div class="card">
            <div class="row between">
              <h3>Key ${i + 1}</h3>
              <span class="badge ok">${escapeHtml(key.kty)}</span>
            </div>

            <div class="grid two">
              <div class="stat"><span>kty</span><strong>${escapeHtml(key.kty)}</strong></div>
              <div class="stat"><span>kid</span><strong>${escapeHtml(key.kid || '—')}</strong></div>
              <div class="stat"><span>alg</span><strong>${escapeHtml(key.alg || '—')}</strong></div>
              <div class="stat"><span>use</span><strong>${escapeHtml(key.use || '—')}</strong></div>
              <div class="stat"><span>key_ops</span><strong>${escapeHtml(Array.isArray(key.key_ops) ? key.key_ops.join(', ') : '—')}</strong></div>
              <div class="stat"><span>crv</span><strong>${escapeHtml(key.crv || '—')}</strong></div>
            </div>

            <h4>JWK JSON</h4>
            <pre class="mono">${escapeHtml(pretty(key))}</pre>

            <h4>Base64URL key fields</h4>
            <pre class="mono">${
                binaryFields
                    .filter(k => typeof key[k] === 'string')
                    .map(k => {
                        try {
                            const bytes = base64urlToBytes(key[k]);
                            return `${k}: ${key[k]}\n  decoded bytes: ${bytes.length}\n  hex: ${base64urlToHex(key[k])}`;
                        } catch {
                            return `${k}: ${key[k]}\n  invalid Base64URL`;
                        }
                    })
                    .join('\n\n') || 'No standard Base64URL key fields present.'
            }</pre>
          </div>
        `).join('')}
      </section>
    `;
}

function renderJws(app, token) {
    const parts = token.split('.');
    const [encodedHeader, encodedPayload, encodedSignature] = parts;

    let header, claims;
    try {
        header = JSON.parse(base64urlDecodeText(encodedHeader));
    } catch {
        throw new Error('JWS header is not valid Base64URL-encoded JSON.');
    }
    try {
        claims = JSON.parse(base64urlDecodeText(encodedPayload));
    } catch {
        throw new Error('JWT claims are not valid Base64URL-encoded JSON.');
    }

    if (!header || typeof header !== 'object' || Array.isArray(header)) {
        throw new Error('JWS header must be a JSON object.');
    }
    if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
        throw new Error('JWT claims must be a JSON object.');
    }

    const exp = timeBadge(claims.exp, 'exp');
    const nbf = timeBadge(claims.nbf, 'nbf');
    const now = Math.floor(Date.now() / 1000);

    let expiryClass = 'ok';
    let expiryMessage = 'No expiry problem detected';
    if (typeof claims.exp === 'number' && claims.exp < now) {
        expiryClass = 'danger';
        expiryMessage = 'Token is expired according to exp';
    } else if (typeof claims.nbf === 'number' && claims.nbf > now) {
        expiryClass = 'warn';
        expiryMessage = 'Token is not yet valid according to nbf';
    }

    let sigBytes = new Uint8Array();
    try { sigBytes = base64urlToBytes(encodedSignature); } catch { /* metadata only */ }

    app.innerHTML = `
      <section class="card">
        <div class="row between">
          <div>
            <h2>JWT / JWS Decoder</h2>
            <p class="muted">Decoded compact JWS/JWT inspection.</p>
          </div>
          <span class="badge warn">DECODE ONLY — DOES NOT VERIFY</span>
        </div>

        <div class="notice ${expiryClass}">
          <strong>${escapeHtml(expiryMessage)}</strong>
          <div class="muted" style="margin-top:.35rem">
            Expiry status is calculated from the supplied claims and your browser's current clock.
            It is not an authenticity check.
          </div>
        </div>

        <div class="grid three">
          <div class="stat"><span>Algorithm</span><strong>${escapeHtml(header.alg || '—')}</strong></div>
          <div class="stat"><span>Type</span><strong>${escapeHtml(header.typ || '—')}</strong></div>
          <div class="stat"><span>Key ID</span><strong>${escapeHtml(header.kid || '—')}</strong></div>
        </div>

        <h3>Claims summary</h3>
        <div class="grid two">
          <div class="stat"><span>Issuer (iss)</span><strong>${escapeHtml(claimText(claims.iss))}</strong></div>
          <div class="stat"><span>Audience (aud)</span><strong>${escapeHtml(claimText(claims.aud))}</strong></div>
          <div class="stat"><span>Subject (sub)</span><strong>${escapeHtml(claimText(claims.sub))}</strong></div>
          <div class="stat"><span>JWT ID (jti)</span><strong>${escapeHtml(claimText(claims.jti))}</strong></div>
        </div>

        <h3>Time claims</h3>
        <div class="grid three">
          <div class="stat">
            <span>Issued at (iat)</span>
            <strong>${escapeHtml(readableTime(claims.iat))}</strong>
            <div class="muted">${typeof claims.iat === 'number' ? `Unix: ${claims.iat}` : 'Not present'}</div>
          </div>
          <div class="stat">
            <span>Expires (exp)</span>
            <strong>${escapeHtml(exp.detail)}</strong>
            ${typeof claims.exp === 'number' ? `<div style="margin-top:.35rem"><span class="${exp.cls}">${escapeHtml(exp.label)}</span></div><div class="muted">Unix: ${claims.exp}</div>` : ''}
          </div>
          <div class="stat">
            <span>Not before (nbf)</span>
            <strong>${escapeHtml(nbf.detail)}</strong>
            ${typeof claims.nbf === 'number' ? `<div style="margin-top:.35rem"><span class="${nbf.cls}">${escapeHtml(nbf.label)}</span></div><div class="muted">Unix: ${claims.nbf}</div>` : ''}
          </div>
        </div>

        <h3>Header</h3>
        <pre class="mono">${escapeHtml(pretty(header))}</pre>

        <h3>Claims</h3>
        <pre class="mono">${escapeHtml(pretty(claims))}</pre>

        <h3>Base64URL-decoded contents</h3>
        <div class="card">
          <h4>Header segment</h4>
          <pre class="mono">${escapeHtml(base64urlDecodeText(encodedHeader))}</pre>
          <div class="muted">Encoded: ${escapeHtml(encodedHeader)} · ${base64urlToBytes(encodedHeader).length} decoded bytes</div>
        </div>

        <div class="card">
          <h4>Payload / claims segment</h4>
          <pre class="mono">${escapeHtml(base64urlDecodeText(encodedPayload))}</pre>
          <div class="muted">Encoded: ${escapeHtml(encodedPayload)} · ${base64urlToBytes(encodedPayload).length} decoded bytes</div>
        </div>

        <h3>Signature metadata</h3>
        <div class="card">
          <div class="grid three">
            <div class="stat"><span>Algorithm</span><strong>${escapeHtml(header.alg || '—')}</strong></div>
            <div class="stat"><span>Signature bytes</span><strong>${sigBytes.length}</strong></div>
            <div class="stat"><span>Meaning</span><strong>${escapeHtml(signatureDescription(header.alg))}</strong></div>
          </div>
          <div class="muted" style="margin-top:.75rem">
            The signature is only Base64URL-decoded. It has not been cryptographically verified.
          </div>
          <pre class="mono">${escapeHtml(encodedSignature)}</pre>
        </div>

        <h3>Compact token</h3>
        <pre class="mono">${escapeHtml(token)}</pre>
      </section>
    `;
}

export function renderJwt(app) {
    renderStart(app);

    const input = app.querySelector('#jwt-input');
    const message = app.querySelector('#jwt-message');

    function showError(text) {
        message.textContent = text || '';
        message.className = text ? 'notice danger' : 'notice hidden';
    }

    function decode() {
        try {
            const detected = detect(input.value);
            if (detected.type === 'json') {
                renderJwk(app, detected.value);
            } else if (detected.type === 'jws') {
                renderJws(app, detected.value);
            } else {
                throw new Error('Five-part JWE detected. This decoder does not decrypt JWE; encrypted content remains encrypted.');
            }
        } catch (err) {
            showError(err?.message || 'Unable to decode input.');
        }
    }

    app.querySelector('#jwt-decode').addEventListener('click', decode);
    app.querySelector('#jwt-clear').addEventListener('click', () => {
        input.value = '';
        showError('');
    });
    app.querySelector('#jwt-paste').addEventListener('click', async () => {
        try {
            input.value = await navigator.clipboard.readText();
            decode();
        } catch {
            showError('Clipboard access was blocked. Use Ctrl+V instead.');
        }
    });
}