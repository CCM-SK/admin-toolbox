import { $, escapeHtml, downloadText, dropBinder, enableToolDragging } from '../utils.js';
async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  textarea.remove();
}
const LARGE_LINE_THRESHOLD = 3000;
const CONTEXT_LINES = 2;
function compareKey(line, opts) {
  if (opts.ignoreBlank && line.trim() === '') return '\u0000BLANK\u0000';
  let key = line;
  if (opts.ignoreWhitespace) key = key.trim().replace(/\s+/g, ' ');
  if (opts.ignoreCase) key = key.toLowerCase();
  return key;
}

function myersDiff(a, b) {
  const N = a.length;
  const M = b.length;
  if (N === 0 && M === 0) return [];
  const max = N + M;
  const offset = max;
  const v = new Int32Array(2 * max + 1);
  const trace = [];
  let found = false;
  outer:
  for (let d = 0; d <= max; d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])) {
        x = v[offset + k + 1];
      } else {
        x = v[offset + k - 1] + 1;
      }
      let y = x - k;
      while (x < N && y < M && a[x] === b[y]) { x++; y++; }
      v[offset + k] = x;
      if (x >= N && y >= M) {
        found = true;
        break outer;
      }
    }
  }
  if (!found) return [];
  let x = N;
  let y = M;
  const ops = [];
  for (let d = trace.length - 1; d >= 0; d--) {
    const vd = trace[d];
    const k = x - y;
    const prevK = (k === -d || (k !== d && vd[offset + k - 1] < vd[offset + k + 1]))
      ? k + 1
      : k - 1;
    const prevX = vd[offset + prevK];
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      x--; y--;
      ops.push({ type: 'same', aIndex: x, bIndex: y });
    }
    if (d > 0) {
      if (x === prevX) {
        y--;
        ops.push({ type: 'add', bIndex: y });
      } else {
        x--;
        ops.push({ type: 'del', aIndex: x });
      }
    }
    x = prevX; y = prevY;
  }
  return ops.reverse();
}
function diffLines(linesA, linesB, opts) {
  const keysA = linesA.map(l => compareKey(l, opts));
  const keysB = linesB.map(l => compareKey(l, opts));
  const maxCommon = Math.min(keysA.length, keysB.length);
  let start = 0;
  while (start < maxCommon && keysA[start] === keysB[start]) start++;
  let endA = keysA.length;
  let endB = keysB.length;
  while (endA > start && endB > start && keysA[endA - 1] === keysB[endB - 1]) {
    endA--; endB--;
  }
  const result = [];
  for (let i = 0; i < start; i++) {
    result.push({ type: 'same', line: linesA[i], oldIndex: i, newIndex: i });
  }
  const midOps = myersDiff(keysA.slice(start, endA), keysB.slice(start, endB));
  for (const op of midOps) {
    if (op.type === 'same') {
      result.push({ type: 'same', line: linesA[start + op.aIndex], oldIndex: start + op.aIndex, newIndex: start + op.bIndex });
    } else if (op.type === 'del') {
      result.push({ type: 'del', line: linesA[start + op.aIndex], oldIndex: start + op.aIndex });
    } else {
      result.push({ type: 'add', line: linesB[start + op.bIndex], newIndex: start + op.bIndex });
    }
  }
  for (let i = endA; i < keysA.length; i++) {
    result.push({ type: 'same', line: linesA[i], oldIndex: i, newIndex: endB + (i - endA) });
  }
  return result;
}
function getStructure(line) {
  const trimmed = line.trim();
  if (!trimmed) {
    return { type: 'blank', key: null };
  }
  const sectionMatch = trimmed.match(/^\[([^\]]+)\]$/);
  if (sectionMatch) {
    return { type: 'section', key: sectionMatch[1].trim() };
  }
  const colonMatch = trimmed.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
  if (colonMatch) {
    return { type: 'setting', key: colonMatch[1] };
  }
  const equalsMatch = trimmed.match(/^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/);
  if (equalsMatch) {
    return { type: 'setting', key: equalsMatch[1] };
  }
  const jsonMatch = trimmed.match(/^["']?([A-Za-z0-9_.-]+)["']?\s*:\s*(.*)$/);
  if (jsonMatch) {
    return { type: 'setting', key: jsonMatch[1] };
  }
  const xmlMatch = trimmed.match(/^<([A-Za-z0-9_.-]+)(?:\s|>)/);
  if (xmlMatch) {
    return { type: 'section', key: xmlMatch[1] };
  }
  if (/^\s+/.test(line)) {
    return { type: 'continuation', key: null };
  }
  return { type: 'text', key: null };
}
function groupDiff(diff) {
  const groups = [];
  let current = null;
  let unchangedSinceChange = 0;
  for (const item of diff) {
    if (item.type !== 'same') {
      const structure = getStructure(item.line);
      if (
        !current ||
        unchangedSinceChange > CONTEXT_LINES ||
        (structure.key && current.key && structure.key !== current.key && structure.type !== 'continuation')
      ) {
        current = { items: [], key: structure.key || null, type: structure.type };
        groups.push(current);
      }
      current.items.push(item);
      unchangedSinceChange = 0;
    } else if (current) {
      current.items.push(item);
      unchangedSinceChange++;
    } else {
      groups.push({ items: [item], key: null, type: 'same' });
    }
  }
  return groups;
}
function buildHunks(diffItems) {
  const groups = groupDiff(diffItems);
  const hunks = [];
  let lastOld = 0;
  let lastNew = 0;
  for (const group of groups) {
    const changed = group.items.some(item => item.type !== 'same');
    if (!changed) {
      for (const item of group.items) {
        if (item.oldIndex !== undefined) lastOld = item.oldIndex + 1;
        if (item.newIndex !== undefined) lastNew = item.newIndex + 1;
      }
      continue;
    }
    const hunkItems = [];
    let sameRun = 0;
    for (const item of group.items) {
      if (item.type === 'same') {
        sameRun++;
        if (sameRun <= CONTEXT_LINES) hunkItems.push(item);
        continue;
      }
      sameRun = 0;
      hunkItems.push(item);
    }
    if (!hunkItems.length) continue;
    const oldNums = hunkItems.filter(it => it.oldIndex !== undefined).map(it => it.oldIndex);
    const newNums = hunkItems.filter(it => it.newIndex !== undefined).map(it => it.newIndex);
    const oldCount = oldNums.length;
    const newCount = newNums.length;
    const oldStart = oldCount ? Math.min(...oldNums) + 1 : lastOld + 1;
    const newStart = newCount ? Math.min(...newNums) + 1 : lastNew + 1;
    hunks.push({ oldStart, oldCount, newStart, newCount, items: hunkItems });
    if (oldCount) lastOld = Math.max(...oldNums) + 1;
    if (newCount) lastNew = Math.max(...newNums) + 1;
  }
  return hunks;
}
function buildDiff(a, b, opts) {
  const linesA = a.split(/\r?\n/);
  const linesB = b.split(/\r?\n/);
  const hunks = buildHunks(diffLines(linesA, linesB, opts));
  if (!hunks.length) return '--- old\n+++ new\n(no differences)';
  const out = ['--- old', '+++ new'];
  for (const hunk of hunks) {
    out.push(`@@ -${hunk.oldStart},${hunk.oldCount} +${hunk.newStart},${hunk.newCount} @@`);
    for (const item of hunk.items) {
      const prefix = item.type === 'add' ? '+ ' : item.type === 'del' ? '- ' : '  ';
      out.push(prefix + item.line);
    }
  }
  return out.join('\n');
}
function render(a, b, opts) {
  const linesA = a.split(/\r?\n/);
  const linesB = b.split(/\r?\n/);
  const hunks = buildHunks(diffLines(linesA, linesB, opts));
  if (!hunks.length) {
    return `<div class="status ok"><strong>No differences</strong><div class="small">The two inputs are identical${opts.ignoreWhitespace || opts.ignoreCase || opts.ignoreBlank ? ' under the selected "Ignore" options' : ''}.</div></div>`;
  }
  const parts = [];
  for (const hunk of hunks) {
    parts.push(
      `<div class="mono small" style="color:var(--accent);margin-top:10px">` +
      `@@ -${hunk.oldStart},${hunk.oldCount} +${hunk.newStart},${hunk.newCount} @@` +
      `</div>`
    );
    for (const item of hunk.items) {
      const cls = item.type === 'add' ? 'diff-add' : item.type === 'del' ? 'diff-del' : 'diff-same';
      const prefix = item.type === 'add' ? '+' : item.type === 'del' ? '-' : ' ';
      const oldNum = item.oldIndex !== undefined ? String(item.oldIndex + 1) : '';
      const newNum = item.newIndex !== undefined ? String(item.newIndex + 1) : '';
      parts.push(
        `<div class="mono ${cls}" style="display:flex;gap:8px;padding:1px 4px">` +
        `<span style="width:44px;flex:none;text-align:right;opacity:.55">${escapeHtml(oldNum)}</span>` +
        `<span style="width:44px;flex:none;text-align:right;opacity:.55">${escapeHtml(newNum)}</span>` +
        `<span style="flex:1;white-space:pre-wrap">${escapeHtml(prefix + ' ' + item.line)}</span>` +
        `</div>`
      );
    }
  }
  return parts.join('');
}
export function renderDiff(app) {
  app.innerHTML = `
    <div class="tool-window" id="diffWindow">
    <div class="tool-window-header" id="diffDragHandle" title="Drag tool">
      <span class="tool-drag-grip" aria-hidden="true">\u22ee\u22ee</span>
      <strong>Configuration diff</strong>
    </div>
    <section class="card">
      <h2>Configuration diff</h2>
      <p class="small">Compare two configuration files or snippets. Everything runs locally in this browser.</p>
      <div class="drop-grid">
        <div class="dropzone" id="aDrop">
          <label for="a">Left / old</label>
          <textarea id="a" placeholder="Paste old configuration, or drop a file here"></textarea>
          <input id="af" type="file" hidden>
        </div>
        <div class="dropzone" id="bDrop">
          <label for="b">Right / new</label>
          <textarea id="b" placeholder="Paste new configuration, or drop a file here"></textarea>
          <input id="bf" type="file" hidden>
        </div>
      </div>
      <div class="row" style="margin-top:10px">
        <span class="small" style="font-weight:600">Ignore:</span>
        <label class="small"><input type="checkbox" id="optWs"> Whitespace</label>
        <label class="small"><input type="checkbox" id="optCase"> Case</label>
        <label class="small"><input type="checkbox" id="optBlank"> Blank lines</label>
      </div>
      <div id="sizeWarning"></div>
      <div class="row" style="margin-top:10px">
        <button class="btn" id="ap">Load left file</button>
        <button class="btn" id="bp">Load right file</button>
        <button class="btn primary" id="go">Compare</button>
        <button class="btn" id="clearBtn">Clear</button>
        <span class="spacer"></span>
        <button class="btn" id="copyOut">Copy diff</button>
        <button class="btn" id="exp">Export diff</button>
      </div>
    </section>
    <section class="card"><div id="diffOut"></div></section>
    </div>
  `;
  const aInput = $('#a');
  const bInput = $('#b');
  const af = $('#af');
  const bf = $('#bf');
  const warningEl = $('#sizeWarning');
  $('#ap').onclick = () => af.click();
  $('#bp').onclick = () => bf.click();
  af.onchange = async e => {
    const file = e.target.files?.[0];
    if (file) aInput.value = await file.text();
    e.target.value = '';
    updateSizeWarning();
  };
  bf.onchange = async e => {
    const file = e.target.files?.[0];
    if (file) bInput.value = await file.text();
    e.target.value = '';
    updateSizeWarning();
  };
  dropBinder($('#aDrop'), async files => {
    if (files[0]) aInput.value = await files[0].text();
    updateSizeWarning();
  });
  dropBinder($('#bDrop'), async files => {
    if (files[0]) bInput.value = await files[0].text();
    updateSizeWarning();
  });
  aInput.addEventListener('input', updateSizeWarning);
  bInput.addEventListener('input', updateSizeWarning);
  function currentOptions() {
    return {
      ignoreWhitespace: $('#optWs').checked,
      ignoreCase: $('#optCase').checked,
      ignoreBlank: $('#optBlank').checked
    };
  }
  function updateSizeWarning() {
    const aLines = aInput.value ? aInput.value.split(/\r?\n/).length : 0;
    const bLines = bInput.value ? bInput.value.split(/\r?\n/).length : 0;
    if (aLines > LARGE_LINE_THRESHOLD || bLines > LARGE_LINE_THRESHOLD) {
      warningEl.innerHTML = `
        <div class="status warn" style="margin-top:10px">
          <strong>Large input (${aLines} / ${bLines} lines)</strong>
          <div class="small">Comparing files this large can be slow and memory-heavy in the browser, especially if they are mostly different rather than mostly similar. It will still run, but expect a delay.</div>
        </div>
      `;
    } else {
      warningEl.innerHTML = '';
    }
  }
  $('#go').onclick = () => {
    updateSizeWarning();
    $('#diffOut').innerHTML = render(aInput.value, bInput.value, currentOptions());
  };
  $('#clearBtn').onclick = () => {
    aInput.value = '';
    bInput.value = '';
    $('#diffOut').innerHTML = '';
    warningEl.innerHTML = '';
  };
  $('#copyOut').onclick = () => copyText(buildDiff(aInput.value, bInput.value, currentOptions()));
  $('#exp').onclick = () =>
    downloadText('diff.txt', buildDiff(aInput.value, bInput.value, currentOptions()));
  enableToolDragging(
    $('#diffWindow'),
    $('#diffDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );
}