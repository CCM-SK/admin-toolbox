export function renderArchive(app) {
  app.innerHTML = `
    <style>
      ${APP_STYLE}
    </style>

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