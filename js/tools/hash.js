import { $, escapeHtml, formatBytes, hex, dropBinder } from '../utils.js';

export function renderHash(app) {
  app.innerHTML = `
    <section class="card">
      <h2>File hashing</h2>
      <p>SHA-256 and SHA-1 use Web Crypto. MD5 is bundled as local JavaScript for legacy comparisons.</p>
      <div class="dropzone" id="hashDrop">
        Drop one or more files here, or <button class="btn" id="hashPick">choose files</button>
        <input id="hashFile" type="file" multiple hidden>
      </div>
    </section>
    <section class="card">
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>File</th><th>Size</th><th>SHA-256</th><th>SHA-1</th><th>MD5</th></tr>
          </thead>
          <tbody id="hashRows"></tbody>
        </table>
      </div>
    </section>
  `;

  const input = $('#hashFile');
  $('#hashPick').onclick = () => input.click();
  input.onchange = () => process([...input.files]);
  dropBinder($('#hashDrop'), process);

  async function process(files) {
    const tbody = $('#hashRows');
    tbody.innerHTML = '';

    for (const f of files) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escapeHtml(f.name)}</td>
        <td>${formatBytes(f.size)}</td>
        <td class="mono">calculating…</td>
        <td class="mono">calculating…</td>
        <td class="mono">calculating…</td>
      `;
      tbody.appendChild(tr);

      const buf = await f.arrayBuffer();
      tr.cells[2].textContent = hex(await crypto.subtle.digest('SHA-256', buf));
      tr.cells[3].textContent = hex(await crypto.subtle.digest('SHA-1', buf));
      tr.cells[4].textContent = md5(new Uint8Array(buf));
    }
  }
}

const MD5_K = [
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const MD5_SHIFT = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

function md5(input) {
  const INITIAL_A = 0x67452301;
  const INITIAL_B = 0xefcdab89;
  const INITIAL_C = 0x98badcfe;
  const INITIAL_D = 0x10325476;

  const len = input.length;
  const paddedLen = ((len + 9 + 63) >> 6) << 6;
  const bytes = new Uint8Array(paddedLen);
  bytes.set(input);
  bytes[len] = 0x80;
  const bitLen = len * 8;
  for (let i = 0; i < 8; i++) {
    bytes[paddedLen - 8 + i] = (bitLen / 2 ** (8 * i)) & 255;
  }

  let a = INITIAL_A, b = INITIAL_B, c = INITIAL_C, d = INITIAL_D;

  // Process the message in successive 64-byte (16 x 32-bit word) chunks
  for (let offset = 0; offset < paddedLen; offset += 64) {
    const M = new Uint32Array(16);
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      M[i] = bytes[j] | (bytes[j + 1] << 8) | (bytes[j + 2] << 16) | (bytes[j + 3] << 24);
    }

    let A = a, B = b, C = c, D = d;

    for (let i = 0; i < 64; i++) {
      let F, g, shift;

      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
        shift = MD5_SHIFT[i % 4];
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
        shift = MD5_SHIFT[4 + (i % 4)];
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
        shift = MD5_SHIFT[8 + (i % 4)];
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
        shift = MD5_SHIFT[12 + (i % 4)];
      }

      const rotateInput = (A + F + MD5_K[i] + M[g]) >>> 0;
      const rotated = ((rotateInput << shift) | (rotateInput >>> (32 - shift))) >>> 0;

      A = D;
      D = C;
      C = B;
      B = (B + rotated) >>> 0;
    }

    a = (a + A) >>> 0;
    b = (b + B) >>> 0;
    c = (c + C) >>> 0;
    d = (d + D) >>> 0;
  }

  return [a, b, c, d]
    .map(word => [0, 8, 16, 24].map(shift => ((word >>> shift) & 255).toString(16).padStart(2, '0')).join(''))
    .join('');
}
