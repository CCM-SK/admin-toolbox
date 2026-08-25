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

  $('#af').onchange = async e => {
    const file = e.target.files?.[0];
    if (file) $('#a').value = await file.text();
  };

  $('#bf').onchange = async e => {
    const file = e.target.files?.[0];
    if (file) $('#b').value = await file.text();
  };

  $('#go').onclick = compare;
  $('#exp').onclick = () =>
    downloadText('diff.txt', buildDiff($('#a').value, $('#b').value));

  function compare() {
    $('#diffOut').innerHTML = render(buildDiff($('#a').value, $('#b').value));
  }

  function diffLines(linesA, linesB) {
    const n = linesA.length;
    const m = linesB.length;

    const dp = Array.from({ length: n + 1 }, () =>
      new Uint32Array(m + 1)
    );

    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        if (linesA[i] === linesB[j]) {
          dp[i][j] = dp[i + 1][j + 1] + 1;
        } else {
          dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
        }
      }
    }

    const result = [];

    let i = 0;
    let j = 0;

    while (i < n && j < m) {
      if (linesA[i] === linesB[j]) {
        result.push({
          type: 'same',
          line: linesA[i],
          oldIndex: i,
          newIndex: j
        });
        i++;
        j++;
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        result.push({
          type: 'del',
          line: linesA[i],
          oldIndex: i
        });
        i++;
      } else {
        result.push({
          type: 'add',
          line: linesB[j],
          newIndex: j
        });
        j++;
      }
    }

    while (i < n) {
      result.push({
        type: 'del',
        line: linesA[i],
        oldIndex: i
      });
      i++;
    }

    while (j < m) {
      result.push({
        type: 'add',
        line: linesB[j],
        newIndex: j
      });
      j++;
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
      return {
        type: 'section',
        key: sectionMatch[1].trim()
      };
    }

    const colonMatch = trimmed.match(
      /^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/
    );
    if (colonMatch) {
      return {
        type: 'setting',
        key: colonMatch[1]
      };
    }

    const equalsMatch = trimmed.match(
      /^([A-Za-z0-9_.-]+)\s*=\s*(.*)$/
    );
    if (equalsMatch) {
      return {
        type: 'setting',
        key: equalsMatch[1]
      };
    }

    const jsonMatch = trimmed.match(
      /^["']?([A-Za-z0-9_.-]+)["']?\s*:\s*(.*)$/
    );
    if (jsonMatch) {
      return {
        type: 'setting',
        key: jsonMatch[1]
      };
    }

    const xmlMatch = trimmed.match(/^<([A-Za-z0-9_.-]+)(?:\s|>)/);
    if (xmlMatch) {
      return {
        type: 'section',
        key: xmlMatch[1]
      };
    }

    if (/^\s+/.test(line)) {
      return {
        type: 'continuation',
        key: null
      };
    }

    return {
      type: 'text',
      key: null
    };
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
          unchangedSinceChange > 2 ||
          (
            structure.key &&
            current.key &&
            structure.key !== current.key &&
            structure.type !== 'continuation'
          )
        ) {
          current = {
            items: [],
            key: structure.key || null,
            type: structure.type
          };
          groups.push(current);
        }

        current.items.push(item);
        unchangedSinceChange = 0;
      } else {
        if (current) {
          current.items.push(item);
          unchangedSinceChange++;
        } else {
          groups.push({
            items: [item],
            key: null,
            type: 'same'
          });
        }
      }
    }

    return groups;
  }

  function buildDiff(a, b) {
    const linesA = a.split(/\r?\n/);
    const linesB = b.split(/\r?\n/);

    const rawDiff = diffLines(linesA, linesB);
    const groups = groupDiff(rawDiff);

    const out = ['--- old', '+++ new'];

    for (const group of groups) {
      const changed = group.items.some(item => item.type !== 'same');

      if (!changed) {
        for (const item of group.items) {
          out.push('  ' + item.line);
        }
        continue;
      }

      let sameCount = 0;

      for (const item of group.items) {
        if (item.type === 'same') {
          sameCount++;

          // Only show up to 2 context lines around grouped changes.
          if (sameCount <= 2) {
            out.push('  ' + item.line);
          }

          continue;
        }

        sameCount = 0;

        if (item.type === 'del') {
          out.push('- ' + item.line);
        } else if (item.type === 'add') {
          out.push('+ ' + item.line);
        }
      }
    }

    return out.join('\n');
  }

  function render(diffText) {
    const lines = diffText
      .split('\n')
      .map(line => {
        const cls =
          line.startsWith('+ ')
            ? 'diff-add'
            : line.startsWith('- ')
              ? 'diff-del'
              : 'diff-same';

        return `<div class="${cls}">${escapeHtml(line)}</div>`;
      })
      .join('');

    return `<div class="mono">${lines}</div>`;
  }
}
