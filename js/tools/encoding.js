function utf8Encode(text) {
    return new TextEncoder().encode(text);
}

function utf8Decode(bytes) {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

function bytesToHex(bytes) {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(value) {
    const clean = value.replace(/\s+/g, '');
    if (!clean) return new Uint8Array();
    if (!/^[0-9a-fA-F]+$/.test(clean)) {
        throw new Error('Hex input contains a non-hexadecimal character.');
    }
    if (clean.length % 2) {
        throw new Error('Hex input must contain an even number of hexadecimal digits.');
    }
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
}

function bytesToBase64(bytes) {
    let out = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
        out += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(out);
}

function base64ToBytes(value) {
    const clean = value.replace(/\s+/g, '');
    if (!clean) return new Uint8Array();
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 === 1) {
        throw new Error('Invalid Base64 input.');
    }
    let padded = clean;
    while (padded.length % 4) padded += '=';
    const binary = atob(padded);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value) {
    const clean = value.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    return base64ToBytes(clean);
}

function printableAsciiPercent(bytes) {
    if (!bytes.length) return 0;
    let printable = 0;
    for (const b of bytes) {
        if (b >= 0x20 && b <= 0x7e) printable++;
    }
    return Math.round(printable * 100 / bytes.length);
}

function asciiPreview(bytes) {
    return Array.from(bytes, b => (b >= 0x20 && b <= 0x7e) ? String.fromCharCode(b) : '·').join('');
}

function formatBytes(n) {
    return `${n.toLocaleString()} byte${n === 1 ? '' : 's'}`;
}

function decodeInput(value, type) {
    switch (type) {
        case 'text': return utf8Encode(value);
        case 'base64': return base64ToBytes(value);
        case 'base64url': return base64UrlToBytes(value);
        case 'hex': return hexToBytes(value);
        case 'url': return utf8Encode(decodeURIComponent(value));
        default: throw new Error(`Unsupported input type: ${type}`);
    }
}

function encodeOutput(bytes, type) {
    switch (type) {
        case 'text': return utf8Decode(bytes);
        case 'base64': return bytesToBase64(bytes);
        case 'base64url': return bytesToBase64Url(bytes);
        case 'hex': return bytesToHex(bytes);
        case 'url': return encodeURIComponent(utf8Decode(bytes));
        default: throw new Error(`Unsupported output type: ${type}`);
    }
}

function makeSection(id, title) {
    return `
      <div class="card">
        <div class="row between">
          <h3>${title}</h3>
          <button class="btn secondary" type="button" data-copy="${id}">Copy</button>
        </div>
        <textarea id="${id}" rows="4" readonly></textarea>
        <div class="muted" id="${id}-stats">0 bytes</div>
      </div>`;
}

export function renderEncoding(app) {
    app.innerHTML = `
      <section class="card">
        <div class="row between">
          <div>
            <h2>Encoding Converter</h2>
            <p class="muted">Text ↔ Base64 ↔ Base64URL ↔ Hex ↔ URL encoding. Everything runs locally.</p>
          </div>
          <span class="badge ok"></span>
        </div>

        <div class="grid two">
          <div class="card compact">
            <label for="encoding-input-type">Input</label>
            <select id="encoding-input-type">
              <option value="text">Text (UTF-8)</option>
              <option value="base64">Base64</option>
              <option value="base64url">Base64URL</option>
              <option value="hex">Hex</option>
              <option value="url">URL encoding</option>
            </select>
          </div>
          <div class="card compact">
            <label for="encoding-output-type">Output</label>
            <select id="encoding-output-type">
              <option value="base64">Base64</option>
              <option value="text">Text (UTF-8)</option>
              <option value="base64url">Base64URL</option>
              <option value="hex">Hex</option>
              <option value="url">URL encoding</option>
            </select>
          </div>
        </div>

        <div class="card">
          <div class="row between">
            <label for="encoding-source">Input value</label>
            <button class="btn secondary" type="button" id="encoding-clear">Clear</button>
          </div>
          <textarea id="encoding-source" rows="6" placeholder="Enter a value…"></textarea>
          <div class="row between">
            <span class="muted" id="encoding-source-stats">0 bytes</span>
            <span class="muted" id="encoding-source-utf8">UTF-8: —</span>
          </div>
        </div>

        <div class="row">
          <button class="btn" type="button" id="encoding-convert">Convert →</button>
          <button class="btn secondary" type="button" id="encoding-swap">Swap</button>
          <button class="btn secondary" type="button" id="encoding-paste">Paste</button>
        </div>

        <div class="card">
          <div class="row between">
            <label for="encoding-result">Result</label>
            <button class="btn secondary" type="button" id="encoding-copy-result">Copy result</button>
          </div>
          <textarea id="encoding-result" rows="6" readonly placeholder="Result appears here…"></textarea>
          <div class="muted" id="encoding-result-stats">0 bytes</div>
        </div>

        <div id="encoding-message" class="notice hidden" role="status"></div>

        <div class="grid two">
          ${makeSection('encoding-base64', 'Base64')}
          ${makeSection('encoding-base64url', 'Base64URL')}
          ${makeSection('encoding-hex', 'Hex')}
          ${makeSection('encoding-url', 'URL encoding')}
        </div>

        <div class="card">
          <h3>Byte / character view</h3>
          <div class="grid three">
            <div class="stat"><span>Characters (decoded UTF-8)</span><strong id="encoding-chars">0</strong></div>
            <div class="stat"><span>Byte length</span><strong id="encoding-bytes">0</strong></div>
            <div class="stat"><span>Printable ASCII</span><strong id="encoding-ascii">0%</strong></div>
          </div>
          <pre id="encoding-preview" class="mono"></pre>
        </div>
      </section>
    `;

    const $ = s => app.querySelector(s);
    const source = $('#encoding-source');
    const result = $('#encoding-result');
    const inputType = $('#encoding-input-type');
    const outputType = $('#encoding-output-type');
    const message = $('#encoding-message');

    function showMessage(text, kind = 'error') {
        message.textContent = text || '';
        message.className = text ? `notice ${kind}` : 'notice hidden';
    }

    function updateByteView(bytes) {
        const text = utf8Decode(bytes);

        $('#encoding-chars').textContent = text.length.toLocaleString();
        $('#encoding-bytes').textContent = bytes.length.toLocaleString();
        $('#encoding-ascii').textContent = `${printableAsciiPercent(bytes)}%`;

        const sample = bytes.slice(0, 256);
        const hex = bytesToHex(sample).replace(/(..)/g, '$1 ').trim();
        const ascii = asciiPreview(sample);

        $('#encoding-preview').textContent =
            `HEX   ${hex}\nASCII ${ascii}` +
            (bytes.length > 256
                ? `\n\nShowing first 256 bytes of ${bytes.length}.`
                : '');
    }

    function updateSourceStats(bytes, validUtf8 = true) {
        $('#encoding-source-stats').textContent = formatBytes(bytes.length);
        $('#encoding-source-utf8').textContent = `UTF-8: ${validUtf8 ? 'valid' : 'invalid'}`;
    }

    function setInspection(id, value, bytes) {
        $(`#${id}`).value = value;
        $(`#${id}-stats`).textContent = formatBytes(bytes.length);
    }

    function updateInspection(bytes) {
        setInspection('encoding-base64', bytesToBase64(bytes), bytes);
        setInspection('encoding-base64url', bytesToBase64Url(bytes), bytes);
        setInspection('encoding-hex', bytesToHex(bytes), bytes);
        setInspection('encoding-url', encodeURIComponent(utf8Decode(bytes)), bytes);
    }

    function convert() {
        try {
            const bytes = decodeInput(source.value, inputType.value);
            const out = encodeOutput(bytes, outputType.value);
            result.value = out;
            updateSourceStats(bytes, true);
            updateByteView(bytes);
            updateInspection(bytes);

            let resultBytes;
            try {
                resultBytes = utf8Encode(out);
            } catch {
                resultBytes = new Uint8Array();
            }
            $('#encoding-result-stats').textContent =
                `${formatBytes(resultBytes.length)} output`;
            showMessage('Conversion successful.', 'success');
        } catch (err) {
            result.value = '';
            updateSourceStats(new Uint8Array(), false);
            updateByteView(new Uint8Array());
            showMessage(err?.message || 'Conversion failed.');
        }
    }

    source.value = 'Hello, world! ✓';
    inputType.value = 'text';
    outputType.value = 'base64';
    convert();

    $('#encoding-convert').addEventListener('click', convert);

    $('#encoding-clear').addEventListener('click', () => {
        source.value = '';
        result.value = '';
        updateSourceStats(new Uint8Array());
        updateByteView(new Uint8Array());
        showMessage('');
    });

    $('#encoding-swap').addEventListener('click', () => {
        const currentInput = inputType.value;
        inputType.value = outputType.value;
        outputType.value = currentInput;
        if (result.value) {
            source.value = result.value;
            convert();
        }
    });

    $('#encoding-paste').addEventListener('click', async () => {
        try {
            source.value = await navigator.clipboard.readText();
            convert();
        } catch {
            showMessage('Clipboard access was blocked. Use Ctrl+V instead.');
        }
    });

    $('#encoding-copy-result').addEventListener('click', async () => {
        if (!result.value) return;
        try {
            await navigator.clipboard.writeText(result.value);
            showMessage('Result copied to clipboard.', 'success');
        } catch {
            result.focus();
            result.select();
            document.execCommand('copy');
            showMessage('Result copied to clipboard.', 'success');
        }
    });

    for (const button of app.querySelectorAll('[data-copy]')) {
        button.addEventListener('click', async () => {
            const value = $(`#${button.dataset.copy}`).value;
            try {
                await navigator.clipboard.writeText(value);
                showMessage('Copied to clipboard.', 'success');
            } catch {
                const el = $(`#${button.dataset.copy}`);
                el.focus();
                el.select();
                document.execCommand('copy');
                showMessage('Copied to clipboard.', 'success');
            }
        });
    }
}