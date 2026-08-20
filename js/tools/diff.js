import { $, escapeHtml, downloadText } from '../utils.js';

export function renderDiff(app) {
  app.innerHTML = `
    <section class="card">
      <h2>Configuration diff</h2>
      <div class="drop-grid">
        <div>
          <label for="a">Left / old</label>
          <textarea id="a" placeholder="Paste old configuration"></textarea>
          <input id="af" type="file" hidden>
        </div>
        <div>
          <label for="b">Right / new</label>
          <textarea id="b" placeholder="Paste new configuration"></textarea>
          <input id="bf" type="file" hidden>
        </div>
      </div>
      <div class="row" style="margin-top:10px">
        <button class="btn" id="ap">Load left file</button>
        <button class="btn" id="bp">Load right file</button>
        <button class="btn primary" id="go">Compare</button>
        <button class="btn" id="exp">Export diff</button>
      </div>
    </section>
    <section class="card"><div id="diffOut"></div></section>
  `;

  $('#ap').onclick = () => $('#af').click();
  $('#bp').onclick = () => $('#bf').click();
  $('#af').onchange = async e => { $('#a').value = await e.target.files[0].text(); };
  $('#bf').onchange = async e => { $('#b').value = await e.target.files[0].text(); };

  $('#go').onclick = compare;
  $('#exp').onclick = () => downloadText('diff.txt', buildDiff($('#a').value, $('#b').value));

  function compare() {
    $('#diffOut').innerHTML = render(buildDiff($('#a').value, $('#b').value));
  }

  function buildDiff(a, b) {
    const linesA = a.split(/\r?\n/);
    const linesB = b.split(/\r?\n/);
    const lineCount = Math.max(linesA.length, linesB.length);

    const out = ['--- old', '+++ new'];
    for (let i = 0; i < lineCount; i++) {
      if (linesA[i] === linesB[i]) {
        out.push('  ' + (linesA[i] ?? ''));
      } else {
        if (linesA[i] !== undefined) out.push('- ' + linesA[i]);
        if (linesB[i] !== undefined) out.push('+ ' + linesB[i]);
      }
    }
    return out.join('\n');
  }

  function render(diffText) {
    const lines = diffText
      .split('\n')
      .map(line => {
        const cls = line.startsWith('+ ') ? 'diff-add' : line.startsWith('- ') ? 'diff-del' : 'diff-same';
        return `<div class="${cls}">${escapeHtml(line)}</div>`;
      })
      .join('');
    return `<div class="mono">${lines}</div>`;
  }
}
