const APP_STYLE = `
  .am-wrap {
    display: grid;
    gap: 16px;
  }

  .am-toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
  }

  .am-drop {
    padding: 18px;
    border: 1px dashed var(--border, #c8ced6);
    border-radius: 12px;
    background: var(--panel, #fff);
  }

  .am-drop.drag {
    outline: 2px solid #4f8cff;
    background: #eef5ff;
  }

  .am-input {
    display: none;
  }

  .am-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 10px;
  }

  .am-stat {
    padding: 12px;
    border: 1px solid var(--border, #d7dce2);
    border-radius: 10px;
    background: var(--panel, #fff);
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

  .am-code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    word-break: break-all;
  }

  .am-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .am-btn {
    padding: 8px 12px;
    border: 1px solid var(--border, #c8ced6);
    border-radius: 8px;
    background: var(--panel, #fff);
    cursor: pointer;
  }

  .am-btn:hover {
    filter: brightness(0.98);
  }
`;

function fmtBytes(n) {
  if (!Number.isFinite(n)) {
    return '—';
  }

  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let index = 0;
  let value = n;

  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index++;
  }

  return `${value.toLocaleString(undefined, {
    maximumFractionDigits: index ? 2 : 0,
  })} ${units[index]}`;
}

function esc(s) {
  return String(s ?? '').replace(
    /[&<>"']/g,
    (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    })[char],
  );
}

function u16(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function u32(bytes, offset) {
  return (
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)
  ) >>> 0;
}

function u64LE(bytes, offset) {
  const lo = BigInt(u32(bytes, offset));
  const hi = BigInt(u32(bytes, offset + 4));

  return (hi << 32n) | lo;
}

function decodeName(bytes, utf8 = false) {
  try {
    return new TextDecoder(
      utf8 ? 'utf-8' : 'windows-1252',
      { fatal: false },
    ).decode(bytes);
  } catch {
    return new TextDecoder().decode(bytes);
  }
}

function findSig(bytes, sig, start, end) {
  for (let i = end - 4; i >= start; i--) {
    if (u32(bytes, i) === sig) {
      return i;
    }
  }

  return -1;
}

function parseZip(buffer) {
  const bytes = new Uint8Array(buffer);
  const end = Math.min(bytes.length, 65557);
  const start = bytes.length - end;
  const eocd = findSig(
    bytes,
    0x06054b50,
    start,
    bytes.length,
  );

  if (eocd < 0) {
    throw new Error(
      'ZIP end-of-central-directory record was not found.',
    );
  }

  let count = u16(bytes, eocd + 10);
  let cdSize = u32(bytes, eocd + 12);
  let cdOff = u32(bytes, eocd + 16);
  let zip64 = false;

  if (
    count === 0xffff ||
    cdSize === 0xffffffff ||
    cdOff === 0xffffffff
  ) {
    const loc = findSig(
      bytes,
      0x07064b50,
      Math.max(0, eocd - 128),
      eocd,
    );

    if (loc >= 0) {
      const zip64Offset = u64LE(bytes, loc + 8);

      if (zip64Offset <= BigInt(Number.MAX_SAFE_INTEGER)) {
        const offset = Number(zip64Offset);
        const record = findSig(
          bytes,
          0x06064b50,
          Math.max(0, offset - 16),
          Math.min(bytes.length, offset + 24),
        );

        if (record >= 0) {
          zip64 = true;

          const recordCount = u64LE(bytes, record + 32);
          const recordSize = u64LE(bytes, record + 40);
          const recordOffset = u64LE(bytes, record + 48);

          count =
            recordCount <= BigInt(Number.MAX_SAFE_INTEGER)
              ? Number(recordCount)
              : 0;

          if (recordSize <= BigInt(Number.MAX_SAFE_INTEGER)) {
            cdSize = Number(recordSize);
          }

          if (recordOffset <= BigInt(Number.MAX_SAFE_INTEGER)) {
            cdOff = Number(recordOffset);
          }
        }
      }
    }
  }

  const entries = [];
  let position = cdOff;
  let folderCount = 0;
  let fileBytes = 0;

  for (
    let i = 0;
    i < count && position + 46 <= bytes.length;
    i++
  ) {
    if (u32(bytes, position) !== 0x02014b50) {
      break;
    }

    const flags = u16(bytes, position + 8);
    const method = u16(bytes, position + 10);
    const crc = u32(bytes, position + 16);
    const compressedSizeRaw = u32(bytes, position + 20);
    const uncompressedSizeRaw = u32(bytes, position + 24);

    const nameLength = u16(bytes, position + 28);
    const extraLength = u16(bytes, position + 30);
    const commentLength = u16(bytes, position + 32);

    const externalAttributes = u32(bytes, position + 38);

    const rawName = bytes.slice(
      position + 46,
      position + 46 + nameLength,
    );

    let name = decodeName(
      rawName,
      (flags & 0x800) !== 0,
    );

    let compressedSize = BigInt(compressedSizeRaw);
    let uncompressedSize = BigInt(uncompressedSizeRaw);

    if (
      compressedSizeRaw === 0xffffffff ||
      uncompressedSizeRaw === 0xffffffff
    ) {
      let extraPosition = position + 46 + nameLength;
      const extraEnd = extraPosition + extraLength;

      while (extraPosition + 4 <= extraEnd) {
        const id = u16(bytes, extraPosition);
        const size = u16(bytes, extraPosition + 2);
        const data = extraPosition + 4;

        if (id === 0x0001) {
          let offset = data;

          if (
            uncompressedSizeRaw === 0xffffffff &&
            offset + 8 <= data + size
          ) {
            uncompressedSize = u64LE(bytes, offset);
            offset += 8;
          }

          if (
            compressedSizeRaw === 0xffffffff &&
            offset + 8 <= data + size
          ) {
            compressedSize = u64LE(bytes, offset);
            offset += 8;
          }
        }

        extraPosition += 4 + size;
      }
    }

    const isDirectory =
      name.endsWith('/') ||
      (externalAttributes & 0x10) !== 0;

    if (isDirectory) {
      folderCount++;
    } else if (
      uncompressedSize <= BigInt(Number.MAX_SAFE_INTEGER)
    ) {
      fileBytes += Number(uncompressedSize);
    }

    const ratio =
      Number(uncompressedSize) > 0 &&
      Number(compressedSize) >= 0
        ? (1 -
            Number(compressedSize) /
              Math.max(1, Number(uncompressedSize))) *
          100
        : 0;

    entries.push({
      name,
      isDirectory,
      size:
        uncompressedSize <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(uncompressedSize)
          : 0,
      compressedSize:
        compressedSize <= BigInt(Number.MAX_SAFE_INTEGER)
          ? Number(compressedSize)
          : 0,
      compression: method,
      crc32: crc
        .toString(16)
        .padStart(8, '0')
        .toUpperCase(),
      encrypted: (flags & 1) !== 0,
      ratio: ratio.toFixed(1),
      extraBytes: extraLength,
      comment: decodeName(
        bytes.slice(
          position + 46 + nameLength + extraLength,
          position +
            46 +
            nameLength +
            extraLength +
            commentLength,
        ),
        true,
      ),
    });

    position +=
      46 + nameLength + extraLength + commentLength;
  }

  return {
    format: 'ZIP',
    zip64,
    entries,
    fileCount: entries.length - folderCount,
    folderCount,
    totalUncompressed: fileBytes,
  };
}

function octal(bytes, offset, length) {
  const value = new TextDecoder()
    .decode(bytes.slice(offset, offset + length))
    .replace(/\0.*$/, '')
    .trim();

  if (!value) {
    return 0;
  }

  return (
    parseInt(value.replace(/^0+/, '') || '0', 8) || 0
  );
}

function parseTar(buffer) {
  const bytes = new Uint8Array(buffer);
  const entries = [];

  let position = 0;
  let total = 0;
  let folders = 0;
  let guard = 0;

  while (
    position + 512 <= bytes.length &&
    guard++ < 200000
  ) {
    const block = bytes.slice(position, position + 512);

    if (block.every((byte) => byte === 0)) {
      break;
    }

    const name = new TextDecoder()
      .decode(block.slice(0, 100))
      .replace(/\0.*$/, '');

    const prefix = new TextDecoder()
      .decode(block.slice(345, 500))
      .replace(/\0.*$/, '');

    const fullName = prefix
      ? `${prefix}/${name}`
      : name;

    const size = octal(block, 124, 12);
    const mtime = octal(block, 136, 12);
    const type = String.fromCharCode(block[156] || 48);

    const isDirectory =
      type === '5' || fullName.endsWith('/');

    if (isDirectory) {
      folders++;
    } else {
      total += size;
    }

    entries.push({
      name: fullName,
      isDirectory,
      size,
      compressedSize: null,
      type,
      mtime: mTimeSafe(mtime),
      mode: octal(block, 100, 8).toString(8),
      uid: octal(block, 108, 8),
      gid: octal(block, 116, 8),
      linkName: new TextDecoder()
        .decode(block.slice(157, 257))
        .replace(/\0.*$/, ''),
    });

    position += 512 + Math.ceil(size / 512) * 512;
  }

  return {
    format: 'TAR',
    entries,
    fileCount: entries.length - folders,
    folderCount: folders,
    totalUncompressed: total,
  };
}

function mTimeSafe(seconds) {
  return seconds
    ? new Date(seconds * 1000).toISOString()
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
    (bytes[6] === 0x00 || bytes[6] === 0x01)
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

function formatMethod(method) {
  return (
    {
      0: 'Store',
      8: 'Deflate',
      12: 'BZIP2',
      14: 'LZMA',
      93: 'Zstandard',
    }[method] || `Method ${method}`
  );
}

function renderResults(state) {
  const entries = state.entries || [];

  const summary = `
    <div class="am-grid">
      <div class="am-stat">
        <span>Format</span>
        <b>${esc(state.format)}</b>
      </div>

      <div class="am-stat">
        <span>Entries</span>
        <b>${entries.length.toLocaleString()}</b>
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
    return `
      ${summary}

      <div class="am-drop">
        <span class="am-badge am-warn">
          ${esc(state.format)} detected
        </span>

        <p>${esc(state.message)}</p>
      </div>
    `;
  }

  const rows = entries
    .map(
      (entry, index) => `
        <tr>
          <td>${index + 1}</td>
          <td class="am-code">${esc(entry.name)}</td>
          <td>${entry.isDirectory ? 'Folder' : 'File'}</td>
          <td>${fmtBytes(entry.size)}</td>
          <td>
            ${
              entry.compressedSize == null
                ? '—'
                : fmtBytes(entry.compressedSize)
            }
          </td>
          <td>
            ${
              entry.compression == null
                ? '—'
                : esc(
                    state.format === 'ZIP'
                      ? formatMethod(entry.compression)
                      : entry.type,
                  )
            }
          </td>
          <td>${esc(entry.crc32 || '—')}</td>
          <td>${entry.encrypted ? 'Yes' : 'No'}</td>
        </tr>
      `,
    )
    .join('');

  return `
    ${summary}

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
  `;
}

export function renderArchive(app) {
  const style = document.createElement('style');

  style.textContent = APP_STYLE;
  app.appendChild(style);

  app.innerHTML += `
    <section class="card am-wrap">
      <div>
        <h2>Archive manifest viewer</h2>

        <p class="am-muted">
          Inspect archive metadata in your browser without extracting
          archive files to disk or uploading them.
        </p>
      </div>

      <div class="am-drop" id="amDrop">
        <input
          class="am-input"
          id="amFile"
          type="file"
          accept=".zip,.tar,.gz,.tgz,.7z,.rar,application/zip,application/gzip,application/x-7z-compressed,application/vnd.rar"
        >

        <label for="amFile" class="am-btn">
          Choose archive
        </label>

        <span id="amName" class="am-muted">
          or drop an archive here
        </span>

        <div
          id="amNote"
          class="am-muted"
          style="margin-top: 10px"
        >
          ZIP and TAR are enumerated from metadata. 7z/RAR are
          recognized but not unpacked or falsely reported as fully
          parsed.
        </div>
      </div>

      <div id="amResults"></div>
    </section>
  `;

  const fileInput = app.querySelector('#amFile');
  const drop = app.querySelector('#amDrop');
  const nameEl = app.querySelector('#amName');
  const results = app.querySelector('#amResults');

  let lastManifest = null;

  async function inspect(file) {
    nameEl.textContent = file.name;
    results.innerHTML = `
      <div class="am-drop">
        Reading archive metadata…
      </div>
    `;

    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const format = detectFormat(bytes);

      let state;

      if (format === 'ZIP') {
        state = parseZip(buffer);
        state.fileName = file.name;
      } else if (format === 'TAR') {
        state = parseTar(buffer);
        state.fileName = file.name;
      } else if (format === 'GZIP') {
        state = {
          format: 'GZIP',
          entries: [],
          fileCount: 0,
          folderCount: 0,
          totalUncompressed: null,
          limited: true,
          message:
            'GZIP is a single compressed stream rather than a multi-entry archive. The tool can inspect the GZIP header, but it does not inflate the stream just to synthesize a manifest.',
        };
      } else if (format === '7Z') {
        state = {
          format: '7Z',
          entries: [],
          fileCount: 0,
          folderCount: 0,
          totalUncompressed: null,
          limited: true,
          message:
            '7z was detected, but this browser-only module intentionally does not execute a 7z decompressor. It avoids presenting an incomplete or misleading file listing.',
        };
      } else if (format === 'RAR') {
        state = {
          format: 'RAR',
          entries: [],
          fileCount: 0,
          folderCount: 0,
          totalUncompressed: null,
          limited: true,
          message:
            'RAR was detected, but this browser-only module intentionally does not execute a RAR decompressor.',
        };
      } else {
        throw new Error(
          'The file signature was not recognized as ZIP, TAR, GZIP, 7z, or RAR.',
        );
      }

      lastManifest = {
        file: file.name,
        bytes: file.size,
        inspectedAt: new Date().toISOString(),
        ...state,
      };

      results.innerHTML = renderResults(state);

      app.querySelector('#amCopy')?.addEventListener(
        'click',
        async () => {
          await navigator.clipboard?.writeText(
            JSON.stringify(lastManifest, null, 2),
          );
        },
      );
    } catch (err) {
      results.innerHTML = `
        <div class="am-drop am-bad">
          <b>Could not inspect archive.</b>
          <p>${esc(err.message)}</p>
        </div>
      `;
    }
  }

  fileInput.addEventListener('change', (event) => {
    const file = event.target.files?.[0];

    if (file) {
      inspect(file);
    }
  });

  ['dragenter', 'dragover'].forEach((eventName) => {
    drop.addEventListener(eventName, (event) => {
      event.preventDefault();
      drop.classList.add('drag');
    });
  });

  ['dragleave', 'drop'].forEach((eventName) => {
    drop.addEventListener(eventName, (event) => {
      event.preventDefault();
      drop.classList.remove('drag');
    });
  });

  drop.addEventListener('drop', (event) => {
    const file = event.dataTransfer.files?.[0];

    if (file) {
      inspect(file);
    }
  });
}