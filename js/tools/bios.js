const VENDOR_HINTS = [
  ['AMI', /^(ami|american\s+megatrends)\b/i],
  ['Award', /^award\b/i],
  ['Phoenix', /^phoenix\b/i],
  ['Dell', /^(dell|supportassist|diagnostic)\b/i],
  ['HP', /^(hp|hewlett[- ]packard)\b/i],
  ['Lenovo', /^lenovo\b/i],
  ['ASUS', /^asus\b/i],
  ['MSI', /^msi\b/i],
  ['Gigabyte', /^gigabyte\b/i]
];

const FAMILY_LABELS = {
  beep: 'Beep / speaker POST pattern',
  qcode: 'Two-character / Q-Code style display',
  hex: 'Hexadecimal POST / diagnostic code',
  decimal: 'Numeric POST / diagnostic code',
  branded: 'Vendor-branded diagnostic code',
  text: 'Textual BIOS/UEFI message',
  unknown: 'Unclassified diagnostic input'
};

function esc(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function $(sel, root = document) { return root.querySelector(sel); }

function copyText(text) {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text);
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  ta.remove();
  return Promise.resolve();
}

function detectVendor(text) {
  for (const [name, re] of VENDOR_HINTS) if (re.test(text)) return name;
  return null;
}

function detectBeep(text) {
  const hasBeepWord = /\b(beeps?|tones?)\b/i.test(text);
  const hasPatternWords = /\b(long|short)\b/i.test(text);
  const hasSequence = /\b\d+(?:\s*[-+,x]\s*\d+)+\b/i.test(text);
  if (!hasBeepWord && !(hasPatternWords && hasSequence)) return null;

  const numbers = [...text.matchAll(/\b\d+\b/g)].map(m => m[0]);
  const toneWords = [...text.matchAll(/\b(?:long|short|beep|beeps|tone|tones)\b/gi)]
    .map(m => m[0].toLowerCase());

  return {
    family: 'beep',
    parts: [
      { label: 'Pattern text', value: text, meaning: 'Original beep/tone wording' },
      ...(numbers.length ? [{ label: 'Numbers', value: numbers.join(', '), meaning: 'Counts/sequence values present in the report' }] : []),
      ...(toneWords.length ? [{ label: 'Tone words', value: [...new Set(toneWords)].join(', '), meaning: 'Long/short/beep/tone descriptors' }] : []),
      {
        label: 'Normalized search form',
        value: text.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(),
        meaning: 'Simplified form useful when searching'
      }
    ]
  };
}

function splitCode(token) {
  const parts = [];
  const prefix = token.match(/^([A-Za-z]{1,8})(?=[-_:.]?\d)/);
  if (prefix) parts.push({
    label: 'Letter prefix',
    value: prefix[1],
    meaning: 'Prefix/mnemonic/vendor marker; meaning is vendor-specific'
  });

  const separators = [...token.matchAll(/[-_:.\/#]+/g)].map(m => m[0]);
  if (separators.length) parts.push({
    label: 'Separator(s)',
    value: [...new Set(separators)].join('  '),
    meaning: 'Formatting separators; generally not meaningful alone'
  });

  const hex = token.match(/(?:0x)?([0-9A-Fa-f]{2,8})$/);
  if (hex && /[A-Fa-f]/.test(hex[1])) parts.push({
    label: 'Hex-looking portion',
    value: hex[0],
    meaning: 'Hex-looking component; interpretation depends on BIOS/vendor'
  });

  const numeric = token.match(/(?:^|[-_:.#])(\d{1,8})(?:$|[-_:.#])/);
  if (numeric) parts.push({
    label: 'Numeric portion',
    value: numeric[1],
    meaning: 'Numeric diagnostic value; interpretation depends on code family'
  });

  const suffix = token.match(/[-_:.#]([A-Za-z]{1,8})$/);
  if (suffix) parts.push({
    label: 'Suffix',
    value: suffix[1],
    meaning: 'Trailing mnemonic/vendor-specific component'
  });

  if (!parts.length) parts.push({
    label: 'Raw token',
    value: token,
    meaning: 'No standard substructure confidently recognized'
  });
  return parts;
}

function buildSearchTerms(input, vendor, family, parts) {
  const set = new Set([input]);
  if (vendor) set.add(`${vendor} ${input}`);
  const primary = parts.find(p => p.label === 'Primary code');
  if (primary) {
    set.add(`BIOS POST ${primary.value}`);
    set.add(`POST code ${primary.value}`);
    if (vendor) set.add(`${vendor} POST code ${primary.value}`);
  }
  if (family === 'beep') {
    set.add(`BIOS beep code ${input}`);
    if (vendor) set.add(`${vendor} beep code ${input}`);
  }
  return [...set];
}

function analyze(raw, vendorChoice) {
  const input = raw.trim().replace(/\s+/g, ' ');
  if (!input) return { status: 'empty' };

  const vendor = vendorChoice !== 'auto' ? vendorChoice : detectVendor(input);
  const beep = detectBeep(input);
  if (beep) {
    return {
      status: 'ok',
      family: beep.family,
      vendor,
      verdict: 'This looks like a beep/tone POST pattern. Search the exact sequence with the system or motherboard model.',
      parts: beep.parts,
      searchTerms: buildSearchTerms(input, vendor, beep.family, beep.parts)
    };
  }

  const tokens = input.split(/\s+/);
  const codeToken = tokens.find(t =>
    /^(?:0x)?[0-9A-Fa-f]{2,8}$/.test(t) ||
    /^[A-Za-z]{1,8}[-_:.#]?\d{1,8}[A-Za-z0-9_-]*$/i.test(t)
  );

  let family = 'text';
  if (codeToken) {
    if (/^(?:0x)?[0-9A-Fa-f]{2,8}$/i.test(codeToken) && /[A-Fa-f]/.test(codeToken)) {
      family = codeToken.length >= 4 ? 'hex' : 'qcode';
    } else if (/^\d+$/.test(codeToken)) {
      family = codeToken.length <= 2 ? 'qcode' : 'decimal';
    } else {
      family = 'branded';
    }
  }

  const parts = [];
  if (codeToken) {
    parts.push({
      label: 'Primary code',
      value: codeToken,
      meaning: 'Token that most resembles a BIOS/POST diagnostic code'
    });
    parts.push(...splitCode(codeToken));
    const context = tokens.filter(t => t !== codeToken).join(' ');
    if (context) parts.push({
      label: 'Context text',
      value: context,
      meaning: 'Keep this context when searching the exact vendor message'
    });
  } else {
    parts.push({
      label: 'Full message',
      value: input,
      meaning: 'No compact code token was confidently identified'
    });
  }

  return {
    status: 'ok',
    family,
    vendor,
    verdict: codeToken
      ? 'Code structure identified. Meanings are vendor/model-specific, so search the generated terms rather than interpreting fragments in isolation.'
      : 'This looks more like a BIOS/UEFI text message. Search the exact wording with the vendor and system/motherboard model.',
    parts,
    searchTerms: buildSearchTerms(input, vendor, family, parts)
  };
}

function renderResult(app, result) {
  const resultEl = $('#bios-result', app);
  if (result.status === 'empty') {
    resultEl.innerHTML = '';
    return;
  }

  resultEl.innerHTML = `
    <div class="card">
      <div class="row between">
        <div>
          <h3>Quick interpretation</h3>
          <p>${esc(result.verdict)}</p>
        </div>
        <div class="row">
          <span class="badge">${esc(FAMILY_LABELS[result.family] || FAMILY_LABELS.unknown)}</span>
          ${result.vendor ? `<span class="badge ok">${esc(result.vendor)}</span>` : ''}
        </div>
      </div>
    </div>

    <div class="card">
      <h3>How the code is built</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Part</th><th>Value</th><th>Meaning for search</th></tr></thead>
          <tbody>
            ${result.parts.map(p => `
              <tr>
                <td>${esc(p.label)}</td>
                <td><code>${esc(p.value)}</code></td>
                <td>${esc(p.meaning)}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="row between">
        <div>
          <h3>Search-ready queries</h3>
          <p class="muted">Add the exact computer/motherboard model for better results.</p>
        </div>
        <button class="btn secondary" type="button" id="bios-copy-search">Copy all</button>
      </div>
      ${result.searchTerms.map((term, i) => `
        <div class="row between search-term" style="gap:.75rem;margin:.35rem 0">
          <code>${esc(term)}</code>
          <button class="btn secondary" type="button" data-copy-term="${i}">Copy</button>
        </div>`).join('')}
    </div>

    <div class="card">
      <h3>Important limitation</h3>
      <p class="muted">
        BIOS/UEFI POST codes are vendor-, model-, generation-, and display-specific.
        The same value can mean different things on different systems. This tool
        intentionally emphasizes decomposition and searchability instead of giving
        a potentially incorrect universal fault description.
      </p>
    </div>
  `;

  $('#bios-copy-search', app).addEventListener('click', async () => {
    await copyText(result.searchTerms.join('\n'));
    flash(app, 'Search queries copied.');
  });

  app.querySelectorAll('[data-copy-term]').forEach(btn => {
    btn.addEventListener('click', async () => {
      await copyText(result.searchTerms[Number(btn.dataset.copyTerm)]);
      flash(app, 'Copied.');
    });
  });
}

function flash(app, text) {
  const el = $('#bios-message', app);
  el.className = 'notice success';
  el.textContent = text;
  clearTimeout(el._timer);
  el._timer = setTimeout(() => {
    el.className = 'notice hidden';
    el.textContent = '';
  }, 2200);
}

export function renderBiosInterpreter(app) {
  app.innerHTML = `
    <section class="card">
      <div class="row between">
        <div>
          <h2>BIOS / POST Error Interpreter</h2>
          <p class="muted">
            Break a BIOS/UEFI diagnostic code into searchable parts without
            pretending vendor-specific meanings are universal.
          </p>
        </div>
        <span class="badge ok">LOCAL ONLY</span>
      </div>

      <div class="grid two">
        <div>
          <label for="bios-code">BIOS / POST code or message</label>
          <input id="bios-code" type="text"
            placeholder="e.g. A2, 0x55, 1 long 2 short, 9C, memory initialization"
            autocomplete="off" spellcheck="false">
        </div>
        <div>
          <label for="bios-vendor">Vendor hint</label>
          <select id="bios-vendor">
            <option value="auto">Auto-detect</option>
            <option value="AMI">AMI / American Megatrends</option>
            <option value="Award">Award</option>
            <option value="Phoenix">Phoenix</option>
            <option value="Dell">Dell</option>
            <option value="HP">HP</option>
            <option value="Lenovo">Lenovo</option>
            <option value="ASUS">ASUS</option>
            <option value="MSI">MSI</option>
            <option value="Gigabyte">Gigabyte</option>
          </select>
        </div>
      </div>

      <div class="row">
        <button class="btn" type="button" id="bios-analyze">Analyze</button>
        <button class="btn secondary" type="button" id="bios-example">Load example</button>
        <button class="btn secondary" type="button" id="bios-clear">Clear</button>
      </div>

      <div id="bios-message" class="notice hidden" role="status"></div>
      <div id="bios-result"></div>

      <div class="card">
        <h3>Privacy / scope</h3>
        <p class="muted">
          The entered code never leaves the browser. No DNS request, lookup,
          search-engine query, vendor website request, or reputation service is used.
        </p>
      </div>
    </section>
  `;

  const code = $('#bios-code', app);
  const vendor = $('#bios-vendor', app);

  const analyzeNow = () => renderResult(app, analyze(code.value, vendor.value));

  $('#bios-analyze', app).addEventListener('click', analyzeNow);
  code.addEventListener('keydown', e => { if (e.key === 'Enter') analyzeNow(); });

  $('#bios-example', app).addEventListener('click', () => {
    code.value = 'A2';
    vendor.value = 'auto';
    analyzeNow();
  });

  $('#bios-clear', app).addEventListener('click', () => {
    code.value = '';
    $('#bios-result', app).innerHTML = '';
    $('#bios-message', app).className = 'notice hidden';
  });
}
