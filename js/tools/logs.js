import { $, escapeHtml, downloadText, dropBinder } from '../utils.js';

export function renderLogs(app) {
  app.innerHTML = `
    <section class="card">
      <h2>Log / CSV inspector</h2>
      <p class="small">
        CSV, simple TSV-like delimited text, JSON arrays, and plain-text logs.
        Processing stays in memory.
      </p>
      <div class="dropzone" id="logDrop">
        Drop a file here, or <button class="btn" id="logPick">choose a file</button>
        <input id="logFile" type="file" hidden>
      </div>
    </section>

    <section class="card" id="logWork" hidden>
      <div class="grid-2">
        <div>
          <label for="logSearch">Search</label>
          <input id="logSearch" placeholder="substring or /regex/flags">
        </div>
        <div>
          <label for="logColumn">Count values in column</label>
          <select id="logColumn"><option value="">— select —</option></select>
        </div>
      </div>
      <div class="result-actions">
        <button class="btn" id="logCsv">Export visible CSV</button>
        <button class="btn" id="logJson">Export visible JSON</button>
      </div>
      <div id="logStats"></div>
      <div class="table-wrap" id="logTable"></div>
    </section>
  `;

  const drop = $('#logDrop');
  const file = $('#logFile');
  const work = $('#logWork');

  let mode = 'text';   // 'text' | 'csv'
  let headers = [];
  let rows = [];

  $('#logPick').onclick = () => file.click();
  file.onchange = () => file.files[0] && load(file.files[0]);
  dropBinder(drop, files => files[0] && load(files[0]));

  async function load(f) {
    const text = await f.text();
    const trimmed = text.trim();
    work.hidden = false;

    const looksLikeJson = f.name.toLowerCase().endsWith('.json') || trimmed.startsWith('[');

    if (looksLikeJson) {
      try {
        const data = JSON.parse(trimmed);
        if (!Array.isArray(data) || !data.length || typeof data[0] !== 'object') {
          throw new Error('Not an array of objects');
        }
        headers = [...new Set(data.flatMap(o => Object.keys(o)))];
        rows = data.map(o => headers.map(h => o?.[h] ?? ''));
        mode = 'csv';
      } catch {
        mode = 'text';
        headers = ['line'];
        rows = text.split(/\r?\n/).filter(Boolean).map(line => [line]);
      }
    } else if (text.includes(',') || text.includes('\t')) {
      const firstLine = text.split(/\r?\n/)[0];
      const delim = firstLine.includes('\t') ? '\t' : ',';
      const parsed = parseDelimited(text, delim);
      headers = (parsed.shift() || []).map((h, i) => h || `Column ${i + 1}`);
      rows = parsed;
      mode = 'csv';
    } else {
      mode = 'text';
      headers = ['line'];
      rows = text.split(/\r?\n/).filter(Boolean).map(line => [line]);
    }

    const columnSelect = $('#logColumn');
    columnSelect.innerHTML =
      '<option value="">— select —</option>' +
      headers.map((h, i) => `<option value="${i}">${escapeHtml(h)}</option>`).join('');

    render();
  }

  function parseDelimited(text, delim) {
    const rows = [];
    let row = [];
    let cell = '';
    let inQuotes = false;

    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      const next = text[i + 1];

      if (inQuotes) {
        if (c === '"' && next === '"') {
          cell += '"';
          i++;
        } else if (c === '"') {
          inQuotes = false;
        } else {
          cell += c;
        }
      } else if (c === '"') {
        inQuotes = true;
      } else if (c === delim) {
        row.push(cell);
        cell = '';
      } else if (c === '\n') {
        row.push(cell);
        rows.push(row);
        row = [];
        cell = '';
      } else if (c !== '\r') {
        cell += c;
      }
    }

    if (cell !== '' || row.length) {
      row.push(cell);
      rows.push(row);
    }

    const width = Math.max(0, ...rows.map(r => r.length));
    return rows.filter(r => r.length === width);
  }

  function filtered() {
    const query = $('#logSearch').value.trim();
    if (!query) return rows;

    let matches = r => r.join(' ').toLowerCase().includes(query.toLowerCase());
    if (query.startsWith('/') && query.lastIndexOf('/') > 0) {
      const lastSlash = query.lastIndexOf('/');
      try {
        const re = new RegExp(query.slice(1, lastSlash), query.slice(lastSlash + 1));
        matches = r => re.test(r.join(' '));
      } catch {
      }
    }

    return rows.filter(matches);
  }

  function render() {
    const visibleRows = filtered();
    const columnIndex = $('#logColumn').value;

    let statsHtml = `
      <div class="grid">
        <div class="stat"><span>Rows</span><strong>${visibleRows.length}</strong></div>
        <div class="stat"><span>Columns</span><strong>${headers.length}</strong></div>
    `;

    if (columnIndex !== '') {
      const counts = new Map();
      for (const r of visibleRows) {
        const key = String(r[columnIndex] ?? '');
        counts.set(key, (counts.get(key) || 0) + 1);
      }
      const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
      statsHtml += `
        <div class="stat">
          <span>Unique values</span>
          <strong>${counts.size}</strong>
          <div class="small">${top.map(([k, v]) => `${escapeHtml(k)}: ${v}`).join(' · ')}</div>
        </div>
      `;
    }
    statsHtml += '</div>';
    $('#logStats').innerHTML = statsHtml;

    const headerHtml = headers.map(h => `<th>${escapeHtml(h)}</th>`).join('');
    const bodyHtml = visibleRows
      .slice(0, 1000)
      .map(r => `<tr>${r.map(c => `<td>${escapeHtml(String(c ?? ''))}</td>`).join('')}</tr>`)
      .join('');

    $('#logTable').innerHTML = `
      <table>
        <thead><tr>${headerHtml}</tr></thead>
        <tbody>${bodyHtml}</tbody>
      </table>
      <p class="small">Showing up to 1,000 visible rows.</p>
    `;
  }

  $('#logSearch').oninput = render;
  $('#logColumn').onchange = render;

  $('#logCsv').onclick = () => {
    const escapeCell = x => '"' + String(x ?? '').replaceAll('"', '""') + '"';
    const visibleRows = filtered();
    const csv = [
      headers.map(escapeCell).join(','),
      ...visibleRows.map(r => r.map(escapeCell).join(',')),
    ].join('\n');
    downloadText('filtered.csv', csv, 'text/csv;charset=utf-8');
  };

  $('#logJson').onclick = () => {
    const visibleRows = filtered();
    const json = JSON.stringify(
      visibleRows.map(r => Object.fromEntries(headers.map((h, i) => [h, r[i] ?? '']))),
      null,
      2
    );
    downloadText('filtered.json', json, 'application/json;charset=utf-8');
  };
}
