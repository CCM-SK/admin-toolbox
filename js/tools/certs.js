import { escapeHtml } from '../utils.js';

const MAX_CERT_FILE_BYTES = 5 * 1024 * 1024;

export function renderCerts(app) {
  app.innerHTML = `
    <section class="card">
      <h2>Certificate / CSR inspector</h2>
      <p class="small">Paste PEM or load a PEM/DER certificate or CSR. Parsing is local and deliberately conservative. DER files are parsed as binary data.</p>
      <textarea id="pem" placeholder="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"></textarea>
      <div class="row generated-style-d2c171b1">
        <input id="cf" type="file" accept=".pem,.crt,.cer,.der,.csr,.txt" hidden>
        <button class="btn" id="pick" type="button">Choose file</button>
        <button class="btn primary" id="parse" type="button">Inspect</button>
      </div>
      <p id="certFileInfo" class="small" aria-live="polite"></p>
    </section>
    <section class="card" id="certResult"></section>
  `;
  const input = app.querySelector('#pem');
  const fileInput = app.querySelector('#cf');
  const result = app.querySelector('#certResult');
  const fileInfo = app.querySelector('#certFileInfo');
  let selectedDer = null;

  app.querySelector('#pick').onclick = () => fileInput.click();
  input.addEventListener('input', () => { selectedDer = null; fileInfo.textContent = ''; });
  fileInput.onchange = async () => {
    const file = fileInput.files?.[0];
    fileInput.value = '';
    if (!file) return;
    if (file.size > MAX_CERT_FILE_BYTES) {
      result.innerHTML = `<div class="status danger">File exceeds the 5 MiB safety limit.</div>`;
      return;
    }
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const maybeText = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      if (/-----BEGIN [^-]+-----/.test(maybeText)) {
        selectedDer = null;
        input.value = maybeText.trim();
        fileInfo.textContent = `${file.name} loaded as PEM text (${bytes.length.toLocaleString()} bytes).`;
      } else {
        selectedDer = bytes;
        input.value = '';
        fileInfo.textContent = `${file.name} loaded as binary DER (${bytes.length.toLocaleString()} bytes).`;
      }
      result.innerHTML = '';
    } catch (error) {
      result.innerHTML = `<div class="status danger">${escapeHtml(error.message || 'Unable to read file.')}</div>`;
    }
  };
  app.querySelector('#parse').onclick = () => {
    try {
      if (selectedDer) result.innerHTML = renderAsn1(selectedDer, 'DER file');
      else result.innerHTML = parsePem(input.value);
    } catch (error) {
      result.innerHTML = `<div class="status danger">${escapeHtml(error.message)}</div>`;
    }
  };
}

export function parsePem(text) {
  const match = String(text).trim().match(/-----BEGIN ([^-]+)-----([\s\S]+?)-----END \1-----/);
  if (!match) throw new Error('PEM block not recognized. Paste a PEM certificate or CSR, or load a DER file.');
  const type = match[1].trim();
  const base64 = match[2].replace(/\s+/g, '');
  if (!base64 || !/^[A-Za-z0-9+/]*={0,2}$/.test(base64) || base64.length % 4 === 1) {
    throw new Error('PEM payload is not valid Base64.');
  }
  let raw;
  try { raw = atob(base64); } catch { throw new Error('PEM payload is not valid Base64.'); }
  const der = Uint8Array.from(raw, char => char.charCodeAt(0));
  return renderAsn1(der, `PEM ${type}`);
}

export function renderAsn1(der, type) {
  if (!(der instanceof Uint8Array) || !der.length) throw new Error('No DER data was supplied.');
  const strings = new ASN1(der).strings();
  const dnsLike = new Set(strings.filter(value => /^[A-Za-z0-9*._-]+\.[A-Za-z]{2,}$/.test(value)));
  const dateLike = strings.filter(value => /^\d{12,14}Z$/.test(value));
  const rows = strings.slice(0, 200).map(value => `
    <tr><td class="mono">${escapeHtml(value)}</td><td>${dnsLike.has(value) ? 'DNS-like' : ''}</td></tr>
  `).join('');
  return `
    <div class="grid">
      <div class="stat"><span>Input type</span><strong>${escapeHtml(type)}</strong></div>
      <div class="stat"><span>DER bytes</span><strong>${der.length.toLocaleString()}</strong></div>
      <div class="stat"><span>Decoded strings</span><strong>${strings.length.toLocaleString()}</strong></div>
      <div class="stat"><span>Date-like values</span><strong>${dateLike.length.toLocaleString()}</strong></div>
    </div>
    <h3>Decoded ASN.1 strings</h3>
    <div class="table-wrap"><table><thead><tr><th>Value</th><th>Heuristic</th></tr></thead><tbody>${rows}</tbody></table></div>
    <p class="small">This is not a PKI validator. It does not perform chain building, signature verification, revocation, trust-store checks, OCSP or CRL lookups. The string classification is heuristic.</p>
  `;
}

class ASN1 {
  constructor(bytes) { this.bytes = bytes; this.pos = 0; this.nodes = 0; }
  read(limit = this.bytes.length, depth = 0) {
    if (depth > 64) throw new Error('DER nesting exceeds the 64-level safety limit.');
    if (++this.nodes > 100000) throw new Error('DER structure exceeds the 100,000-node safety limit.');
    if (this.pos + 2 > limit) throw new Error('Malformed DER: truncated ASN.1 header.');
    const tag = this.bytes[this.pos++];
    const lengthByte = this.bytes[this.pos++];
    let length;
    if (lengthByte < 128) length = lengthByte;
    else {
      const count = lengthByte & 127;
      if (count === 0 || count > 4 || this.pos + count > limit) throw new Error('Unsupported or malformed ASN.1 length.');
      length = 0;
      for (let i = 0; i < count; i++) length = (length * 256) + this.bytes[this.pos++];
    }
    const contentStart = this.pos;
    const contentEnd = contentStart + length;
    if (contentEnd > limit || contentEnd > this.bytes.length) throw new Error('Malformed DER: ASN.1 length exceeds the available data.');
    const children = [];
    if (tag & 32) {
      while (this.pos < contentEnd) children.push(this.read(contentEnd, depth + 1));
      if (this.pos !== contentEnd) throw new Error('Malformed DER: constructed value length mismatch.');
    } else this.pos = contentEnd;
    return { tag, cs: contentStart, ce: contentEnd, children };
  }
  strings() {
    const supportedStringTags = new Set([12, 18, 19, 20, 22, 23, 24, 30]);
    const root = this.read();
    if (this.pos !== this.bytes.length) throw new Error('Malformed DER: unexpected trailing bytes.');
    const values = [];
    const walk = node => {
      if (!node) return;
      const tagNumber = node.tag & 31;
      if (supportedStringTags.has(tagNumber)) {
        const bytes = this.bytes.slice(node.cs, node.ce);
        const value = tagNumber === 30
          ? Array.from({ length: Math.floor(bytes.length / 2) }, (_, index) => String.fromCharCode((bytes[index * 2] << 8) | bytes[index * 2 + 1])).join('')
          : new TextDecoder().decode(bytes);
        if (value) values.push(value);
      }
      for (const child of node.children || []) walk(child);
    };
    walk(root);
    return values;
  }
}
