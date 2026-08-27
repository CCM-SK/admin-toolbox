import { $, escapeHtml } from '../utils.js';

export function renderCerts(app) {
  app.innerHTML = `
    <section class="card">
      <h2>Certificate / CSR inspector</h2>
      <p>
        <p class="small">
        Paste PEM or load a PEM/DER certificate or CSR. Parsing is local and deliberately conservative.
        </p>
      </p>
      <textarea id="pem" placeholder="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"></textarea>
      <div class="row" style="margin-top:10px">
        <input id="cf" type="file" accept=".pem,.crt,.cer,.csr,.txt" hidden>
        <button class="btn" id="pick">Choose file</button>
        <button class="btn primary" id="parse">Inspect</button>
      </div>
    </section>
    <section class="card" id="certResult"></section>
  `;

  $('#pick').onclick = () => $('#cf').click();

  $('#cf').onchange = async e => {
    const f = e.target.files[0];
    if (!f) return;
    const buf = await f.arrayBuffer();
    const bytes = new Uint8Array(buf);
    $('#pem').value = new TextDecoder().decode(bytes).trim();
  };

  $('#parse').onclick = () => {
    try {
      $('#certResult').innerHTML = parsePem($('#pem').value);
    } catch (e) {
      $('#certResult').innerHTML = `<div class="status danger">${escapeHtml(e.message)}</div>`;
    }
  };
}

// Extracts the DER payload from a PEM block, walks it as ASN.1, and
// summarizes any printable strings found inside (heuristically flagging
// DNS-like values). This is a viewer(!!!), not a validator.
function parsePem(s) {
  const match = s.match(/-----BEGIN ([^-]+)-----([\s\S]+?)-----END \1-----/);
  if (!match) {
    throw new Error('PEM block not recognized. This inspector currently requires PEM input.');
  }

  const type = match[1];
  const base64 = match[2].replace(/\s+/g, '');
  const der = Uint8Array.from(atob(base64), c => c.charCodeAt(0));

  const strings = new ASN1(der).strings();
  const dnsLike = strings.filter(x => /^[A-Za-z0-9*._-]+\.[A-Za-z]{2,}$/.test(x));
  const dateLike = strings.filter(x => /^\d{12,14}Z$/.test(x));

  const rows = strings
    .slice(0, 200)
    .map(x => `
      <tr>
        <td class="mono">${escapeHtml(x)}</td>
        <td>${dnsLike.includes(x) ? 'DNS-like' : ''}</td>
      </tr>
    `)
    .join('');

  return `
    <div class="grid">
      <div class="stat"><span>PEM type</span><strong>${escapeHtml(type)}</strong></div>
      <div class="stat"><span>DER bytes</span><strong>${der.length}</strong></div>
      <div class="stat"><span>Decoded strings</span><strong>${strings.length}</strong></div>
      <div class="stat"><span>Date-like values</span><strong>${dateLike.length}</strong></div>
    </div>
    <h3>Decoded ASN.1 strings</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Value</th><th>Heuristic</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="small">
      This is not a PKI validator. It does not perform chain building, signature
      verification, revocation, trust-store checks, OCSP or CRL lookups.
    </p>
  `;
}

class ASN1 {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  read() {
    if (this.pos + 2 > this.bytes.length) return null;

    const tag = this.bytes[this.pos++];
    const lengthByte = this.bytes[this.pos++];

    let length;
    if (lengthByte < 128) {
      length = lengthByte;
    } else {
      const numLengthBytes = lengthByte & 127;
      if (!numLengthBytes || numLengthBytes > 4) {
        throw new Error('Unsupported ASN.1 length');
      }
      length = 0;
      for (let i = 0; i < numLengthBytes; i++) {
        length = (length << 8) | this.bytes[this.pos++];
      }
    }

    const contentStart = this.pos;
    const contentEnd = contentStart + length;
    if (contentEnd > this.bytes.length) {
      throw new Error('Malformed DER');
    }

    const isConstructed = tag & 32;
    const children = [];
    if (isConstructed) {
      while (this.pos < contentEnd) {
        children.push(this.read());
      }
    } else {
      this.pos = contentEnd;
    }

    return { tag, cs: contentStart, ce: contentEnd, children };
  }

  strings() {
    const STRING_TAGS = [12, 18, 19, 20, 22, 23, 24, 30];
    const root = this.read();
    const out = [];

    const walk = node => {
      if (!node) return;

      const tagNumber = node.tag & 31;
      if (STRING_TAGS.includes(tagNumber)) {
        const bytes = this.bytes.slice(node.cs, node.ce);
        const str =
          tagNumber === 30
            ? [...Array(bytes.length / 2)]
                .map((_, i) => String.fromCharCode((bytes[i * 2] << 8) | bytes[i * 2 + 1]))
                .join('')
            : new TextDecoder().decode(bytes);
        if (str) out.push(str);
      }

      for (const child of node.children || []) walk(child);
    };

    walk(root);
    return out;
  }
}
