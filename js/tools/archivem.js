const APP_STYLE = `
.am-wrap {
  display: grid;
  gap: 16px;
}

/* Match App2's drop zone */
.dropzone {
  min-height: 92px;
  padding: 20px 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  flex-wrap: wrap;

  background: #f8fafc;
  border: 2px dashed #d6dfeb;
  border-radius: 10px;

  color: #0f172a;
  text-align: center;

  transition:
    border-color 0.15s ease,
    background 0.15s ease,
    box-shadow 0.15s ease;
}

.dropzone.drag {
  border-color: #4f8cff;
  background: #eef5ff;
  box-shadow: 0 0 0 3px rgba(79, 140, 255, 0.12);
}

.dropzone .btn {
  padding: 8px 12px;
  border: 1px solid #d6dfeb;
  border-radius: 8px;
  background: #fff;
  color: #0f172a;
  cursor: pointer;
  font: inherit;
}

.dropzone .btn:hover {
  background: #f8fafc;
}

#amName {
  margin-top: -6px;
}

#amNote {
  margin-top: -4px;
  font-size: 0.82rem;
}

.am-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 10px;
}

.am-stat {
  padding: 12px;
  background: var(--panel, #fff);
  border: 1px solid var(--border, #d7dce2);
  border-radius: 10px;
}

.am-stat b {
  display: block;
  font-size: 1.2rem;
}

.am-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.9rem;
}

.am-table th,
.am-table td {
  padding: 8px;
  border-bottom: 1px solid var(--border, #e2e6ea);
  text-align: left;
  vertical-align: top;
}

.am-table th {
  position: sticky;
  top: 0;
  background: var(--panel, #fff);
}

.am-scroll {
  max-height: 420px;
  overflow: auto;
  border: 1px solid var(--border, #d7dce2);
  border-radius: 10px;
}

.am-muted {
  color: var(--muted, #667085);
}

.am-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  word-break: break-all;
}

.am-badge {
  display: inline-block;
  padding: 3px 8px;
  border: 1px solid var(--border, #d7dce2);
  border-radius: 999px;
  font-size: 0.78rem;
}

.am-good {
  color: #0f7b3e;
  background: #ecfdf3;
}

.am-warn {
  color: #8a5a00;
  background: #fff8e1;
}

.am-bad {
  color: #a61b1b;
  background: #fff1f1;
}

.am-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.am-btn {
  padding: 8px 12px;
  background: var(--panel, #fff);
  border: 1px solid var(--border, #c8ced6);
  border-radius: 8px;
  cursor: pointer;
  font: inherit;
}

.am-btn:hover {
  filter: brightness(0.98);
}
`;

function fmtBytes(n) {
  if (!Number.isFinite(n)) return '—';

  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let x = n;

  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }

  return `${x.toLocaleString(undefined, {
    maximumFractionDigits: i ? 2 : 0
  })} ${units[i]}`;
}

function esc(s) {
  return String(s ?? '').replace(
    /[&<>"']/g,
    c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[c])
  );
}

function u16(a, o) {
  return a[o] | (a[o + 1] << 8);
}

function u32(a, o) {
  return (
    a[o] |
    (a[o + 1] << 8) |
    (a[o + 2] << 16) |
    (a[o + 3] << 24)
  ) >>> 0;
}

function u64LE(a, o) {
  const lo = BigInt(u32(a, o));
  const hi = BigInt(u32(a, o + 4));
  return (hi << 32n) | lo;
}

function decodeName(bytes, utf8 = false) {
  try {
    return new TextDecoder(
      utf8 ? 'utf-8' : 'windows-1252',
      { fatal: false }
    ).decode(bytes);
  } catch {
    return new TextDecoder().decode(bytes);
  }
}

function findSig(bytes, sig, start, end) {
  for (let i = end - 4; i >= start; i--) {
    if (u32(bytes, i) === sig) return i;
  }
  return -1;
}

function parseZip(buffer) {
  const b = new Uint8Array(buffer);

  const end = Math.min(b.length, 65557);
  const start = b.length - end;

  const eocd = findSig(
    b,
    0x06054b50,
    start,
    b.length
  );

  if (eocd < 0) {
    throw new Error(
      'ZIP end-of-central-directory record was not found.'
    );
  }

  let count = u16(b, eocd + 10);
  let cdSize = u32(b, eocd + 12);
  let cdOff = u32(b, eocd + 16);

  let zip64 = false;

  if (
    count === 0xffff ||
    cdSize === 0xffffffff ||
    cdOff === 0xffffffff
  ) {
    const loc = findSig(
      b,
      0x07064b50,
      Math.max(0, eocd - 128),
      eocd
    );

    if (loc >= 0) {
      const zOff = u64LE(b, loc + 8);

      if (zOff <= BigInt(Number.MAX_SAFE_INTEGER)) {
        const zo = Number(zOff);

        const z = findSig(
          b,
          0x06064b50,
          Math.max(0, zo - 16),
          Math.min(b.length, zo + 24)
        );

        if (z >= 0) {
          zip64 = true;

          const recCount = u64LE(b, z + 32);
          const recSize = u64LE(b, z + 40);
          const recOff = u64LE(b, z + 48);

          if (recCount <= BigInt(Number.MAX_SAFE_INTEGER)) {
            count = Number(recCount);
          } else {
            count = 0;
          }

          if (recSize <= BigInt(Number.MAX_SAFE_INTEGER)) {
            cdSize = Number(recSize);
          }

          if (recOff <= BigInt(Number.MAX_SAFE_INTEGER)) {
            cdOff = Number(recOff);
          }
        }
      }
    }
  }

  const entries = [];
  let p = cdOff;
  let folderCount = 0;
  let fileBytes = 0;

  for (
    let i = 0;
    i < count && p + 46 <= b.length;
    i++
  ) {
    if (u32(b, p) !== 0x02014b50) break;

    const flags = u16(b, p + 8);
    const method = u16(b, p + 10);
    const crc = u32(b, p + 16);
    const csize0 = u32(b, p + 20);
    const usize0 = u32(b, p + 24);

    const nlen = u16(b, p + 28);
    const xlen = u16(b, p + 30);
    const clen = u16(b, p + 32);

    const extAttr = u32(b, p + 38);

    const raw = b.slice(
      p + 46,
      p + 46 + nlen
    );

    const name = decodeName(
      raw,
      (flags & 0x800) !== 0
    );

    let csize = BigInt(csize0);
    let usize = BigInt(usize0);

    if (
      csize0 === 0xffffffff ||
      usize0 === 0xffffffff
    ) {
      let xp = p + 46 + nlen;
      const xe = xp + xlen;

      while (xp + 4 <= xe) {
        const id = u16(b, xp);
        const sz = u16(b, xp + 2);
        const data = xp + 4;

        if (id === 0x0001) {
          let q = data;

          if (
            usize0 === 0xffffffff &&
            q + 8 <= data + sz
          ) {
            usize = u64LE(b, q);
            q += 8;
          }

          if (
            csize0 === 0xffffffff &&
            q + 8 <= data + sz
          ) {
            csize = u64LE(b, q);
          }
        }

        xp += 4 + sz;
      }
    }

    const dir =
      name.endsWith('/') ||
      (extAttr & 0x10) !== 0;

    if (dir) {
      folderCount++;
    } else if (
      usize <= BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      fileBytes += Number(usize);
    }

    const ratio =
      Number(usize) > 0 &&
      Number(csize) >= 0
        ? (
            1 -
            Number(csize) /
              Math.max(1, Number(usize))
          ) * 100
        : 0;

    entries.push({
      name,
      isDirectory: dir,
      size:
        usize <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(usize)
          : 0,
      compressedSize:
        csize <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(csize)
          : 0,
      compression: method,
      crc32: crc
        .toString(16)
        .padStart(8, '0')
        .toUpperCase(),
      encrypted: (flags & 1) !== 0,
      ratio: ratio.toFixed(1),
      extraBytes: xlen,
      comment: decodeName(
        b.slice(
          p + 46 + nlen + xlen,
          p + 46 + nlen + xlen + clen
        ),
        true
      )
    });

    p += 46 + nlen + xlen + clen;
  }

  return {
    format: 'ZIP',
    zip64,
    entries,
    fileCount: entries.length - folderCount,
    folderCount,
    totalUncompressed: fileBytes
  };
}

function octal(bytes, o, n) {
  const s = new TextDecoder()
    .decode(bytes.slice(o, o + n))
    .replace(/\0.*$/, '')
    .trim();

  if (!s) return 0;

  return (
    parseInt(
      s.replace(/^0+/, '') || '0',
      8
    ) || 0
  );
}

function parseTar(buffer) {
  const b = new Uint8Array(buffer);

  const entries = [];
  let p = 0;
  let total = 0;
  let folders = 0;
  let guard = 0;

  while (
    p + 512 <= b.length &&
    guard++ < 200000
  ) {
    const block = b.slice(p, p + 512);

    if (block.every(x => x === 0)) {
      break;
    }

    const name = new TextDecoder()
      .decode(block.slice(0, 100))
      .replace(/\0.*$/, '');

    const prefix = new TextDecoder()
      .decode(block.slice(345, 500))
      .replace(/\0.*$/, '');

    const full = prefix
      ? `${prefix}/${name}`
      : name;

    const size = octal(block, 124, 12);
    const mtime = octal(block, 136, 12);
    const type = String.fromCharCode(
      block[156] || 48
    );

    const isDir =
      type === '5' ||
      full.endsWith('/');

    if (isDir) {
      folders++;
    } else {
      total += size;
    }

    entries.push({
      name: full,
      isDirectory: isDir,
      size,
      compressedSize: null,
      type,
      mtime: mTimeSafe(mtime),
      mode: octal(block, 100, 8).toString(8),
      uid: octal(block, 108, 8),
      gid: octal(block, 116, 8),
      linkName: new TextDecoder()
        .decode(block.slice(157, 257))
        .replace(/\0.*$/, '')
    });

    p += 512 + Math.ceil(size / 512) * 512;
  }

  return {
    format: 'TAR',
    entries,
    fileCount: entries.length - folders,
    folderCount: folders,
    totalUncompressed: total
  };
}

function mTimeSafe(sec) {
  return sec
    ? new Date(sec * 1000).toISOString()
    : '—';
}

function detectFormat(bytes) {
  if (
    bytes.length >= 4 &&
    (
      u32(bytes, 0) === 0x04034b50 ||
      u32(bytes, 0) === 0x06054b50 ||
      u32(bytes, 0) === 0x08074b50
    )
  ) {
    return 'ZIP';
  }

  if (
    bytes.length >= 7 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x61 &&
    bytes[2] === 0x72 &&
    bytes[3] === 0x21 &&
    bytes[4] === 0x1a &&
    bytes[5] === 0x07 &&
    (
      bytes[6] === 0x00 ||
      bytes[6] === 0x01
    )
  ) {
    return 'RAR';
  }

  if (
    bytes.length >= 6 &&
    bytes[0] === 0x37 &&
    bytes[1] === 0x7a &&
    bytes[2] === 0xbc &&
    bytes[3] === 0xaf &&
    bytes[4] === 0x27 &&
    bytes[5] === 0x1c
  ) {
    return '7Z';
  }

  if (
    bytes.length >= 2 &&
    bytes[0] === 0x1f &&
    bytes[1] === 0x8b
  ) {
    return 'GZIP';
  }

  if (bytes.length >= 512) {
    const magic = new TextDecoder()
      .decode(bytes.slice(257, 262));

    if (magic === 'ustar') {
      return 'TAR';
    }
  }

  return 'UNKNOWN';
}

function formatMethod(n) {
  return (
    {
      0: 'Store',
      8: 'Deflate',
      12: 'BZIP2',
      14: 'LZMA',
      93: 'Zstandard'
    }[n] || `Method ${n}`
  );
}

function renderResults(state) {
  const e = state.entries || [];

  const summary = `
    <div class="am-grid">
      <div class="am-stat">
        <span>Format</span>
        <b>${esc(state.format)}</b>
      </div>

      <div class="am-stat">
        <span>Entries</span>
        <b>${e.length.toLocaleString()}</b>
      </div>

      <div class="am-stat">
        <span>Files</span>
        <b>${state.fileCount.toLocaleString()}</b>
      </div>

      <div class="am-stat">
        <span>Folders</span>
        <b>${state.folderCount.toLocaleString()}</b>
      </div>

      <div class="am-stat">
        <span>Uncompressed</span>
        <b>${fmtBytes(state.totalUncompressed)}</b>
      </div>

      <div class="am-stat">
        <span>Inspection</span>
        <b>Metadata only</b>
      </div>
    </div>
  `;

  if (state.limited) {
    return (
      summary +
      `
        <div class="am-stat">
          <span class="am-badge am-warn">
            ${esc(state.format)} detected
          </span>
          <p>${esc(state.message)}</p>
        </div>
      `
    );
  }

  const rows = e
    .map(
      (x, i) => `
        <tr>
          <td>${i + 1}</td>
          <td class="am-code">${esc(x.name)}</td>
          <td>${x.isDirectory ? 'Folder' : 'File'}</td>
          <td>${fmtBytes(x.size)}</td>
          <td>
            ${
              x.compressedSize == null
                ? '—'
                : fmtBytes(x.compressedSize)
            }
          </td>
          <td>
            ${
              x.compression == null
                ? '—'
                : esc(
                    state.format === 'ZIP'
                      ? formatMethod(x.compression)
                      : x.type
                  )
            }
          </td>
          <td>${esc(x.crc32 || '—')}</td>
          <td>${x.encrypted ? 'Yes' : 'No'}</td>
        </tr>
      `
    )
    .join('');

  return (
    summary +
    `
      <div class="am-actions">
        <button class="am-btn" id="amCopy">
          Copy manifest JSON
        </button>
      </div>

      <div class="am-scroll">
        <table class="am-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Name</th>
              <th>Type</th>
              <th>Size</th>
              <th>Compressed</th>
              <th>Method</th>
              <th>CRC</th>
              <th>Encrypted</th>
            </tr>
          </thead>

          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    `
  );
}

export function renderArchiveM(app) {
  app.innerHTML = '';

  const style = document.createElement('style');
  style.textContent = APP_STYLE;
  app.appendChild(style);

  app.insertAdjacentHTML(
    'beforeend',
    `
      <section class="card am-wrap">

        <div>
          <h2>Archive manifest viewer</h2>

          <p class="am-muted">
            Inspect archive metadata in your browser without extracting
            archive files to disk or uploading them.
          </p>
        </div>

        <div class="dropzone" id="amDrop">
        Drop an archive here, or
        <button class="btn" id="amPick" type="button">
            choose an archive
        </button>

        <input
            id="amFile"
            type="file"
            hidden
            accept=".zip,.tar,.gz,.tgz,.7z,.rar,application/zip,application/gzip,application/x-7z-compressed,application/vnd.rar"
        >
        </div>

        <div
          id="amName"
          class="am-muted"
          aria-live="polite"
        ></div>

        <div
          id="amNote"
          class="am-muted"
        >
          ZIP and TAR are enumerated from metadata. 7z/RAR are recognized
          but not unpacked or falsely reported as fully parsed.
        </div>

        <div id="amResults"></div>

      </section>
    `
  );

  const fileInput = app.querySelector('#amFile');
  const drop = app.querySelector('#amDrop');
  const pick = app.querySelector('#amPick');
  const nameEl = app.querySelector('#amName');
  const results = app.querySelector('#amResults');

  let lastManifest = null;

  pick.addEventListener('click', () => {
    fileInput.click();
  });

  fileInput.addEventListener('change', e => {
    const file = e.target.files?.[0];

    if (file) {
      inspect(file);
    }
  });


  ['dragenter', 'dragover'].forEach(eventName => {
    drop.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();

      drop.classList.add('drag');
      if (e.dataTransfer) {
        e.dataTransfer.dropEffect = 'copy';
      }
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    drop.addEventListener(eventName, e => {
      e.preventDefault();
      e.stopPropagation();

      drop.classList.remove('drag');
    });
  });

  drop.addEventListener('drop', e => {
    const file = e.dataTransfer?.files?.[0];

    if (file) {
      inspect(file);
    }
  });

  async function inspect(file) {
    nameEl.textContent = file.name;

    results.innerHTML = `
      <div class="am-stat">
        <span>Inspection</span>
        <b>Reading archive metadata…</b>
      </div>
    `;

    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);

      const fmt = detectFormat(bytes);

      let state;

      if (fmt === 'ZIP') {
        state = parseZip(buffer);
        state.fileName = file.name;
      }

      else if (fmt === 'TAR') {
        state = parseTar(buffer);
        state.fileName = file.name;
      }

      else if (fmt === 'GZIP') {
        state = {
          format: 'GZIP',
          entries: [],
          fileCount: 0,
          folderCount: 0,
          totalUncompressed: null,
          limited: true,
          message:
            'GZIP is a single compressed stream rather than a multi-entry archive. The tool can inspect the GZIP header, but it does not inflate the stream just to synthesize a manifest.'
        };
      }

      else if (fmt === '7Z') {
        state = {
          format: '7Z',
          entries: [],
          fileCount: 0,
          folderCount: 0,
          totalUncompressed: null,
          limited: true,
          message:
            '7z was detected, but this browser-only module intentionally does not execute a 7z decompressor. It avoids presenting an incomplete or misleading file listing.'
        };
      }

      else if (fmt === 'RAR') {
        state = {
          format: 'RAR',
          entries: [],
          fileCount: 0,
          folderCount: 0,
          totalUncompressed: null,
          limited: true,
          message:
            'RAR was detected, but this browser-only module intentionally does not execute a RAR decompressor.'
        };
      }

      else {
        throw new Error(
          'The file signature was not recognized as ZIP, TAR, GZIP, 7z, or RAR.'
        );
      }

      lastManifest = {
        file: file.name,
        bytes: file.size,
        inspectedAt: new Date().toISOString(),
        ...state
      };

      results.innerHTML = renderResults(state);

      const copyButton = app.querySelector('#amCopy');

      copyButton?.addEventListener('click', async () => {
        try {
          await navigator.clipboard?.writeText(
            JSON.stringify(lastManifest, null, 2)
          );
        } catch {
          // Clipboard may be unavailable in some browsers/contexts
        }
      });

    } catch (err) {
      results.innerHTML = `
        <div class="am-stat am-bad">
          <b>Could not inspect archive.</b>
          <p>${esc(err?.message || 'Unknown error')}</p>
        </div>
      `;
    }
  }
}