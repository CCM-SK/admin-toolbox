import { $, escapeHtml, downloadText, dropBinder, formatBytes } from '../utils.js';
export const metadata = {
  id: 'logs',
  title: 'Log / CSV inspector',
  description: 'Load CSV or plain text logs, search them, count values, and export filtered data',
  path: '/#logs'
};

const LARGE_FILE_THRESHOLD = 10 * 1024 * 1024;
const MAX_LARGE_FILE_SIZE = 250 * 1024 * 1024;
const LARGE_PREVIEW_LIMIT = 1000;
const EXAMPLE_LOG = `2026-10-12T08:15:23Z INFO host=web01 user=alice request=/health status=200\n2026-10-12T08:16:02Z WARN host=web01 user=alice request=/login status=401\n2026-10-12T08:17:11Z ERROR host=db01 process=sqlservr.exe message="connection timeout"`;

export function renderLogs(app) {
  // Keep this tool instance's controls isolated when several tools are mounted.
  const $ = (selector, root = app) => root.querySelector(selector);
  app.innerHTML = `
    <section class="card">
      <h2>Log / CSV inspector</h2>
      <p class="small">CSV, simple TSV-like delimited text, JSON arrays, and plain-text logs. Processing stays in memory.</p>
      <div class="dropzone" id="logDrop">
        Drop a file here, or <button class="btn" id="logPick" type="button">choose a file</button>
        <input id="logFile" type="file" hidden>
      </div>
      <details class="log-paste-panel">
        <summary>Paste text or load a sample</summary>
        <textarea id="logPaste" rows="7" spellcheck="false" placeholder="Paste log lines or CSV here"></textarea>
        <div class="actions">
          <button class="btn" id="logLoadText" type="button">Load pasted text</button>
          <button class="btn" id="logExample" type="button">Load example</button>
        </div>
      </details>
    </section>
    <section class="card" id="logWork" hidden>
      <div class="grid-2">
        <div><label for="logSearch">Search</label><input id="logSearch" placeholder="substring or /regex/flags"></div>
        <div id="logColumnWrap"><label for="logColumn">Count values in column</label><select id="logColumn"><option value="">- select -</option></select></div>
      </div>
      <div class="result-actions">
        <button class="btn" id="logCsv" type="button">Export visible CSV</button>
        <button class="btn" id="logJson" type="button">Export visible JSON</button>
        <button class="btn" id="logLargeExport" type="button" hidden>Export matching lines</button>
        <button class="btn" id="logCancel" type="button" hidden>Cancel processing</button>
      </div>
      <div id="logLargeStatus" class="notice" hidden aria-live="polite"></div>
      <div id="logStats"></div>
      <div class="table-wrap" id="logTable"></div>
    </section>
  `;
  const drop = $('#logDrop', app);
  const file = $('#logFile', app);
  const work = $('#logWork', app);
  const paste = $('#logPaste', app);
  const largeStatus = $('#logLargeStatus', app);
  const largeExport = $('#logLargeExport', app);
  const cancelButton = $('#logCancel', app);
  let mode = 'text';
  let headers = [];
  let rows = [];
  let largeFile = null;
  let worker = null;
  let requestId = 0;
  let activeRequest = null;
  let searchTimer = null;
  const onToolDeactivate = event => {
    if (event.detail?.toolId !== 'logs' || (event.detail?.scope && event.detail.scope !== app)) return;
    if (worker) worker.terminate();
    worker = null;
    activeRequest = null;
    largeFile = null;
    if (searchTimer !== null) clearTimeout(searchTimer);
    document.removeEventListener('toolbox:tool-deactivate', onToolDeactivate);
  };
  document.addEventListener('toolbox:tool-deactivate', onToolDeactivate);

  $('#logPick', app).onclick = () => file.click();
  file.onchange = () => {
    if (file.files[0]) load(file.files[0]);
    file.value = '';
  };
  dropBinder(drop, files => files[0] && load(files[0]));
  $('#logExample', app).onclick = () => {
    paste.value = EXAMPLE_LOG;
    loadText(paste.value, 'example.log');
  };
  $('#logLoadText', app).onclick = () => loadText(paste.value, 'pasted-log.txt');

  function setMode(nextMode) {
    mode = nextMode;
    $('#logColumnWrap', app).hidden = mode === 'large';
    $('#logCsv', app).hidden = mode === 'large';
    $('#logJson', app).hidden = mode === 'large';
    largeExport.hidden = mode !== 'large';
  }
  function setWorkflowText(text) {
    if (new TextEncoder().encode(text).byteLength <= 8 * 1024 * 1024) app.dataset.workflowText = text;
    else delete app.dataset.workflowText;
  }
  async function load(f) {
    if (f.size > MAX_LARGE_FILE_SIZE) {
      if (worker) { worker.terminate(); worker = null; }
      largeFile = null;
      activeRequest = null;
      cancelButton.hidden = true;
      largeExport.disabled = false;
      $('#logStats', app).innerHTML = '';
      $('#logTable', app).innerHTML = '';
      setMode('text');
      largeStatus.hidden = false;
      largeStatus.className = 'notice error';
      largeStatus.textContent = `File is ${formatBytes(f.size)}. The current large-file limit is ${formatBytes(MAX_LARGE_FILE_SIZE)}.`;
      work.hidden = false;
      return;
    }
    work.hidden = false;
    if (f.size >= LARGE_FILE_THRESHOLD) {
      loadLargeFile(f);
      return;
    }
    if (worker) { worker.terminate(); worker = null; }
    largeFile = null;
    activeRequest = null;
    cancelButton.hidden = true;
    largeStatus.hidden = true;
    const text = await f.text();
    setWorkflowText(text);
    parseText(text, f.name);
  }
  function loadText(text, name) {
    if (worker) { worker.terminate(); worker = null; }
    largeFile = null;
    activeRequest = null;
    cancelButton.hidden = true;
    largeStatus.hidden = true;
    work.hidden = false;
    setWorkflowText(text);
    parseText(text, name);
  }
  function parseText(text, name) {
    const trimmed = text.trim();
    if (!trimmed) throw new Error('No text to inspect.');
    if (name.toLowerCase().endsWith('.json') || trimmed.startsWith('[')) {
      try {
        const data = JSON.parse(trimmed);
        if (!Array.isArray(data) || !data.length || typeof data[0] !== 'object') throw new Error('Not an array of objects');
        headers = [...new Set(data.flatMap(o => Object.keys(o)))];
        rows = data.map(o => headers.map(h => o?.[h] ?? ''));
        setMode('csv');
      } catch {
        headers = ['line'];
        rows = text.split(/\r?\n/).filter(Boolean).map(line => [line]);
        setMode('text');
      }
    } else if (text.includes(',') || text.includes('\t')) {
      const firstLine = text.split(/\r?\n/)[0];
      const delim = firstLine.includes('\t') ? '\t' : ',';
      const parsed = parseDelimited(text, delim);
      headers = (parsed.shift() || []).map((h, i) => h || `Column ${i + 1}`);
      rows = parsed;
      setMode('csv');
    } else {
      headers = ['line'];
      rows = text.split(/\r?\n/).filter(Boolean).map(line => [line]);
      setMode('text');
    }
    const columnSelect = $('#logColumn', app);
    columnSelect.innerHTML = '<option value="">- select -</option>' + headers.map((h, i) => `<option value="${i}">${escapeHtml(h)}</option>`).join('');
    render();
  }
  function parseDelimited(text, delim) {
    const result = [];
    let row = [], cell = '', inQuotes = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i], next = text[i + 1];
      if (inQuotes) {
        if (c === '"' && next === '"') { cell += '"'; i++; }
        else if (c === '"') inQuotes = false;
        else cell += c;
      } else if (c === '"') inQuotes = true;
      else if (c === delim) { row.push(cell); cell = ''; }
      else if (c === '\n') { row.push(cell); result.push(row); row = []; cell = ''; }
      else if (c !== '\r') cell += c;
    }
    if (cell !== '' || row.length) { row.push(cell); result.push(row); }
    const width = Math.max(0, ...result.map(r => r.length));
    return result.filter(r => r.length === width && r.some(x => x !== ''));
  }
  function filtered() {
    const query = $('#logSearch', app).value.trim();
    if (!query) return rows;
    let matches = r => r.join(' ').toLowerCase().includes(query.toLowerCase());
    if (query.startsWith('/') && query.lastIndexOf('/') > 0) {
      const lastSlash = query.lastIndexOf('/');
      try {
        const re = new RegExp(query.slice(1, lastSlash), query.slice(lastSlash + 1));
        matches = r => { re.lastIndex = 0; return re.test(r.join(' ')); };
      } catch { /* keep substring matching */ }
    }
    return rows.filter(matches);
  }
  function render() {
    if (mode === 'large') { searchLarge(); return; }
    const visibleRows = filtered();
    const columnIndex = $('#logColumn', app).value;
    let statsHtml = `<div class="grid"><div class="stat"><span>Rows</span><strong>${visibleRows.length}</strong></div><div class="stat"><span>Columns</span><strong>${headers.length}</strong></div>`;
    if (columnIndex !== '') {
      const counts = new Map();
      for (const row of visibleRows) { const key = String(row[columnIndex] ?? ''); counts.set(key, (counts.get(key) || 0) + 1); }
      const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
      statsHtml += `<div class="stat"><span>Unique values</span><strong>${counts.size}</strong><div class="small">${top.map(([k, v]) => `${escapeHtml(k)}: ${v}`).join(' · ')}</div></div>`;
    }
    $('#logStats', app).innerHTML = statsHtml + '</div>';
    const headerHtml = headers.map(h => `<th>${escapeHtml(h)}</th>`).join('');
    const bodyHtml = visibleRows.slice(0, 1000).map(row => `<tr>${row.map(cell => `<td>${escapeHtml(String(cell ?? ''))}</td>`).join('')}</tr>`).join('');
    $('#logTable', app).innerHTML = `<table><thead><tr>${headerHtml}</tr></thead><tbody>${bodyHtml}</tbody></table><p class="small">Showing up to 1,000 visible rows. Source: ${escapeHtml(largeFile?.name || 'loaded text')}.</p>`;
  }
  function ensureWorker() {
    if (worker) return worker;
    worker = new Worker(new URL('../workers/log-worker.js', import.meta.url), { type: 'module' });
    worker.addEventListener('message', event => {
      const data = event.data || {};
      if (data.id !== activeRequest) return;
      if (data.type === 'progress') {
        largeStatus.hidden = false;
        largeStatus.className = 'notice';
        largeStatus.textContent = `Scanning ${formatBytes(data.bytesRead)} of ${formatBytes(data.fileSize)} · ${data.lines.toLocaleString()} lines · ${data.matched.toLocaleString()} matches`;
      } else if (data.type === 'result') {
        cancelButton.hidden = true;
        largeExport.disabled = false;
        largeStatus.hidden = false;
        largeStatus.className = 'notice good';
        largeStatus.textContent = `Complete: ${data.lines.toLocaleString()} lines scanned, ${data.matched.toLocaleString()} matches in ${formatBytes(data.fileSize)}.${data.skippedOversizedLines ? ` Skipped ${data.skippedOversizedLines.toLocaleString()} line(s) over 1 MiB of UTF-8 text.` : ''} Showing ${data.preview.length.toLocaleString()} preview lines${data.previewOmitted ? `; ${data.previewOmitted.toLocaleString()} additional matches omitted from preview` : ''}.`;
        $('#logStats', app).innerHTML = `<div class="grid"><div class="stat"><span>Lines scanned</span><strong>${data.lines.toLocaleString()}</strong></div><div class="stat"><span>Matches</span><strong>${data.matched.toLocaleString()}</strong></div><div class="stat"><span>File size</span><strong>${formatBytes(data.fileSize)}</strong></div></div>`;
        $('#logTable', app).innerHTML = `<table><thead><tr><th>Line</th></tr></thead><tbody>${data.preview.map(line => `<tr><td>${escapeHtml(line)}</td></tr>`).join('')}</tbody></table><p class="small">Preview limited to ${LARGE_PREVIEW_LIMIT.toLocaleString()} rows. Use Export matching lines for the complete filtered result (up to 24 MiB).</p>`;
      } else if (data.type === 'exported') {
        cancelButton.hidden = true;
        largeExport.disabled = false;
        const url = URL.createObjectURL(data.blob);
        const link = document.createElement('a');
        link.href = url; link.download = `filtered-${largeFile?.name || 'log'}.txt`;
        document.body.appendChild(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        largeStatus.className = 'notice good';
        largeStatus.textContent = `Exported ${data.matched.toLocaleString()} matching lines (${formatBytes(data.bytes)}).`;
      } else if (data.type === 'error') {
        cancelButton.hidden = true;
        largeExport.disabled = false;
        largeStatus.hidden = false;
        largeStatus.className = 'notice error';
        largeStatus.textContent = data.message;
      }
    });
    worker.addEventListener('error', event => {
      largeExport.disabled = false;
      largeStatus.hidden = false;
      largeStatus.className = 'notice error';
      largeStatus.textContent = `Worker error: ${event.message || 'unable to process the file'}`;
      cancelButton.hidden = true;
    });
    return worker;
  }
  function sendLargeJob(type = 'scan') {
    if (!largeFile) return;
    const currentId = ++requestId;
    if (activeRequest !== null) worker?.postMessage({ type: 'cancel', id: activeRequest });
    activeRequest = currentId;
    cancelButton.hidden = false;
    largeExport.disabled = type === 'export';
    largeStatus.hidden = false;
    largeStatus.className = 'notice';
    largeStatus.textContent = type === 'export' ? 'Preparing filtered export in the background…' : 'Scanning file in the background…';
    ensureWorker().postMessage({ type, id: currentId, file: largeFile, query: $('#logSearch', app).value });
  }
  function searchLarge() { sendLargeJob('scan'); }
  function loadLargeFile(f) {
    delete app.dataset.workflowText;
    paste.value = '';
    if (worker) worker.terminate();
    worker = null;
    largeFile = f;
    largeExport.disabled = false;
    setMode('large');
    headers = ['line']; rows = [];
    $('#logColumn', app).innerHTML = '<option value="">Not available in large-file mode</option>';
    largeStatus.hidden = false;
    largeStatus.className = 'notice';
    largeStatus.textContent = `Large-file mode: ${formatBytes(f.size)}. Search and line filtering run in a background worker; CSV column analysis is disabled for this file.`;
    searchLarge();
  }
  $('#logSearch', app).oninput = () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(render, mode === 'large' ? 350 : 0);
  };
  $('#logColumn', app).onchange = render;
  $('#logCsv', app).onclick = () => {
    const escapeCell = value => '"' + String(value ?? '').replaceAll('"', '""') + '"';
    const visibleRows = filtered();
    downloadText('filtered.csv', [headers.map(escapeCell).join(','), ...visibleRows.map(row => row.map(escapeCell).join(','))].join('\n'), 'text/csv;charset=utf-8');
  };
  $('#logJson', app).onclick = () => {
    const visibleRows = filtered();
    downloadText('filtered.json', JSON.stringify(visibleRows.map(row => Object.fromEntries(headers.map((h, i) => [h, row[i] ?? '']))), null, 2), 'application/json;charset=utf-8');
  };
  largeExport.onclick = () => sendLargeJob('export');
  cancelButton.onclick = () => {
    if (activeRequest !== null) worker?.postMessage({ type: 'cancel', id: activeRequest });
    activeRequest = null;
    largeExport.disabled = false;
    cancelButton.hidden = true;
    largeStatus.className = 'notice warn';
    largeStatus.textContent = 'Processing cancelled. The file remains loaded; change the search or start another scan to continue.';
  };
}
