function downloadText(
  text,
  filename,
  mime = 'text/plain;charset=utf-8'
) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();

  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function lineCol(text, offset) {
  const before = text.slice(0, Math.max(0, offset));
  const ls = before.split(/\r?\n/);

  return {
    line: ls.length,
    column: ls.at(-1).length + 1
  };
}

function jsonParse(text) {
  try {
    return {
      ok: true,
      value: JSON.parse(text)
    };
  } catch (e) {
    const m = e.message.match(/position (\d+)/i);
    const loc = m ? lineCol(text, +m[1]) : {};

    return {
      ok: false,
      error: {
        message: e.message,
        line: loc.line,
        column: loc.column
      }
    };
  }
}

function sortKeys(v) {
  if (Array.isArray(v)) {
    return v.map(sortKeys);
  }

  if (v && typeof v === 'object') {
    return Object.fromEntries(
      Object.keys(v)
        .sort((a, b) => a.localeCompare(b))
        .map(k => [k, sortKeys(v[k])])
    );
  }

  return v;
}

function repairJson(text) {
  let s = String(text ?? '').trim();
  let out = '';
  let str = false;
  let esc = false;

  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const n = s[i + 1];

    if (str) {
      out += c;

      if (esc) {
        esc = false;
      } else if (c === '\\') {
        esc = true;
      } else if (c === '"') {
        str = false;
      }

      continue;
    }

    if (c === '"') {
      str = true;
      out += c;
      continue;
    }

    if (c === '/' && n === '/') {
      while (i < s.length && s[i] !== '\n') i++;
      out += '\n';
      continue;
    }

    if (c === '/' && n === '*') {
      i += 2;

      while (
        i < s.length &&
        !(s[i] === '*' && s[i + 1] === '/')
      ) {
        i++;
      }

      i++;
      continue;
    }

    out += c;
  }

  return out
    .replace(
      /'([^'\\]*(?:\\.[^'\\]*)*)'/g,
      (_, b) =>
        `"${b
          .replace(/\\'/g, "'")
          .replace(/"/g, '\\"')}"`
    )
    .replace(
      /([{,]\s*)([A-Za-z_$][A-Za-z0-9_$.-]*)(\s*:)/g,
      '$1"$2"$3'
    )
    .replace(/,\s*([}\]])/g, '$1')
    .replace(
      /\bundefined\b|\bNaN\b|\bInfinity\b/g,
      'null'
    );
}

function yamlComment(line) {
  let q = null;
  let esc = false;

  for (let i = 0; i < line.length; i++) {
    const c = line[i];

    if (q === '"') {
      if (esc) {
        esc = false;
      } else if (c === '\\') {
        esc = true;
      } else if (c === '"') {
        q = null;
      }
    } else if (q === "'") {
      if (c === "'") {
        if (line[i + 1] === "'") {
          i++;
        } else {
          q = null;
        }
      }
    } else if (c === '"' || c === "'") {
      q = c;
    } else if (
      c === '#' &&
      (i === 0 || /\s/.test(line[i - 1]))
    ) {
      return line.slice(0, i).trimEnd();
    }
  }

  return line;
}

function yamlSplit(s) {
  let q = null;
  let d = 0;
  let esc = false;

  for (let i = 0; i < s.length; i++) {
    const c = s[i];

    if (q === '"') {
      if (esc) {
        esc = false;
      } else if (c === '\\') {
        esc = true;
      } else if (c === '"') {
        q = null;
      }
    } else if (q === "'") {
      if (c === "'") {
        if (s[i + 1] === "'") {
          i++;
        } else {
          q = null;
        }
      }
    } else if (c === '"' || c === "'") {
      q = c;
    } else if (c === '[' || c === '{') {
      d++;
    } else if (c === ']' || c === '}') {
      d--;
    } else if (
      c === ':' &&
      !d &&
      (i + 1 === s.length || /\s/.test(s[i + 1]))
    ) {
      return [
        s.slice(0, i).trim(),
        s.slice(i + 1).trim()
      ];
    }
  }

  return null;
}

function yamlScalar(raw) {
  const v = raw.trim();

  if (v === '') {
    return null;
  }

  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    if (v[0] === '"') {
      try {
        return JSON.parse(v);
      } catch {}
    }

    return v.slice(1, -1).replace(/''/g, "'");
  }

  if (/^(null|Null|NULL|~)$/.test(v)) {
    return null;
  }

  if (/^(true|True|TRUE)$/.test(v)) {
    return true;
  }

  if (/^(false|False|FALSE)$/.test(v)) {
    return false;
  }

  if (
    (v.startsWith('[') && v.endsWith(']')) ||
    (v.startsWith('{') && v.endsWith('}'))
  ) {
    try {
      return JSON.parse(v.replace(/'/g, '"'));
    } catch {}
  }

  if (
    /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(v)
  ) {
    const n = Number(v);

    if (Number.isFinite(n)) {
      return n;
    }
  }

  return v;
}

function parseYaml(text) {
  const src = String(text ?? '')
    .replace(/\r\n?/g, '\n')
    .split('\n');

  const lines = [];

  src.forEach((raw, i) => {
    if (/\t/.test(raw)) {
      throw Object.assign(
        new Error(
          'Tabs are not supported for YAML indentation.'
        ),
        { yamlLine: i + 1 }
      );
    }

    const s = yamlComment(raw);

    if (
      !s.trim() ||
      /^\s*(---|\.\.\.)\s*$/.test(s)
    ) {
      return;
    }

    const indent = s.match(/^ */)[0].length;

    lines.push({
      raw: s.slice(indent),
      indent,
      line: i + 1
    });
  });

  if (!lines.length) {
    return null;
  }

  function block(pos, indent) {
    const list =
      lines[pos].indent === indent &&
      lines[pos].raw.startsWith('-');

    const obj = list ? [] : {};

    while (
      pos < lines.length &&
      lines[pos].indent === indent
    ) {
      const ln = lines[pos];

      if (list) {
        if (!ln.raw.startsWith('-')) {
          throw Object.assign(
            new Error(
              'Mixed YAML mapping/list content.'
            ),
            { yamlLine: ln.line }
          );
        }

        const item = ln.raw.slice(1).trim();
        pos++;

        if (!item) {
          if (
            pos < lines.length &&
            lines[pos].indent > indent
          ) {
            const [v, n] = block(
              pos,
              lines[pos].indent
            );

            obj.push(v);
            pos = n;
          } else {
            obj.push(null);
          }

          continue;
        }

        const kv = yamlSplit(item);

        if (!kv) {
          obj.push(yamlScalar(item));
          continue;
        }

        const itemObj = {};
        let key = kv[0].replace(
          /^['"]|['"]$/g,
          ''
        );

        if (kv[1] === '') {
          if (
            pos < lines.length &&
            lines[pos].indent > indent
          ) {
            const [v, n] = block(
              pos,
              lines[pos].indent
            );

            itemObj[key] = v;
            pos = n;
          } else {
            itemObj[key] = null;
          }
        } else {
          itemObj[key] = yamlScalar(kv[1]);
        }

        while (
          pos < lines.length &&
          lines[pos].indent > indent
        ) {
          const child = lines[pos];
          const ckv = yamlSplit(child.raw);

          if (!ckv) {
            break;
          }

          pos++;

          const ck = ckv[0].replace(
            /^['"]|['"]$/g,
            ''
          );

          if (
            ckv[1] === '' &&
            pos < lines.length &&
            lines[pos].indent > child.indent
          ) {
            const [v, n] = block(
              pos,
              lines[pos].indent
            );

            itemObj[ck] = v;
            pos = n;
          } else {
            itemObj[ck] = yamlScalar(ckv[1]);
          }
        }

        obj.push(itemObj);
      } else {
        const kv = yamlSplit(ln.raw);

        if (!kv) {
          throw Object.assign(
            new Error(
              `Expected "key: value" at line ${ln.line}.`
            ),
            { yamlLine: ln.line }
          );
        }

        pos++;

        const key = kv[0].replace(
          /^['"]|['"]$/g,
          ''
        );

        if (kv[1] === '') {
          if (
            pos < lines.length &&
            lines[pos].indent > indent
          ) {
            const [v, n] = block(
              pos,
              lines[pos].indent
            );

            obj[key] = v;
            pos = n;
          } else {
            obj[key] = null;
          }
        } else {
          obj[key] = yamlScalar(kv[1]);
        }
      }
    }

    return [obj, pos];
  }

  const [v, p] = block(
    0,
    lines[0].indent
  );

  if (p < lines.length) {
    throw Object.assign(
      new Error(
        `Could not parse YAML near line ${lines[p].line}.`
      ),
      { yamlLine: lines[p].line }
    );
  }

  return v;
}

function yamlString(v, ind = 0) {
  const pad = ' '.repeat(ind);

  if (v === null) {
    return 'null';
  }

  if (
    typeof v === 'boolean' ||
    typeof v === 'number'
  ) {
    return String(v);
  }

  if (typeof v === 'string') {
    if (
      v === '' ||
      /[\s:#{}\[\],&*!?|>'"%@`]/.test(v) ||
      /^(true|false|null|~|-?\d+(?:\.\d+)?)$/i.test(v)
    ) {
      return JSON.stringify(v);
    }

    return v;
  }

  if (Array.isArray(v)) {
    if (!v.length) {
      return '[]';
    }

    return v
      .map(x => {
        const s = yamlString(x, ind + 2);

        return s.includes('\n')
          ? `${pad}-\n${s}`
          : `${pad}- ${s}`;
      })
      .join('\n');
  }

  if (v && typeof v === 'object') {
    const ks = Object.keys(v);

    if (!ks.length) {
      return '{}';
    }

    return ks
      .map(k => {
        const key =
          /^[A-Za-z_][A-Za-z0-9_.-]*$/.test(k)
            ? k
            : JSON.stringify(k);

        const s = yamlString(v[k], ind + 2);

        return s.includes('\n')
          ? `${pad}${key}:\n${s}`
          : `${pad}${key}: ${s}`;
      })
      .join('\n');
  }

  return JSON.stringify(String(v));
}

function xmlParse(text) {
  const doc = new DOMParser().parseFromString(
    text,
    'application/xml'
  );

  if (doc.querySelector('parsererror')) {
    throw new Error(
      doc
        .querySelector('parsererror')
        .textContent.replace(/\s+/g, ' ')
        .trim()
    );
  }

  return doc;
}

function xmlToJson(node) {
  const o = {};

  for (const a of node.attributes) {
    o[`@${a.name}`] = a.value;
  }

  const es = [...node.children];

  const t = [...node.childNodes]
    .filter(
      n => n.nodeType === Node.TEXT_NODE
    )
    .map(n => n.nodeValue)
    .join('')
    .trim();

  if (!es.length) {
    if (Object.keys(o).length) {
      if (t) {
        o['#text'] = t;
      }

      return o;
    }

    return t;
  }

  for (const e of es) {
    const k = e.nodeName;
    const v = xmlToJson(e);

    o[k] =
      k in o
        ? Array.isArray(o[k])
          ? [...o[k], v]
          : [o[k], v]
        : v;
  }

  if (t) {
    o['#text'] = t;
  }

  return o;
}

function xmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function jsonToXml(v, root = 'root') {
  function node(name, x) {
    const n = name.replace(
      /[^A-Za-z0-9_.:-]/g,
      '_'
    );

    if (Array.isArray(x)) {
      return x
        .map(i => node(n, i))
        .join('\n');
    }

    if (x === null) {
      return `<${n} xsi:nil="true"/>`;
    }

    if (x && typeof x === 'object') {
      let a = '';
      let c = '';

      for (const [k, val] of Object.entries(x)) {
        if (k.startsWith('@')) {
          a += ` ${k.slice(1)}="${xmlEscape(val)}"`;
        } else if (k === '#text') {
          c += xmlEscape(val);
        } else {
          c += node(k, val);
        }
      }

      return `<${n}${a}>${c}</${n}>`;
    }

    return `<${n}>${xmlEscape(x)}</${n}>`;
  }

  return `<?xml version="1.0" encoding="UTF-8"?>\n${node(
    root,
    v
  )}`;
}

function xmlPretty(text) {
  const raw =
    new XMLSerializer().serializeToString(
      xmlParse(text)
    );

  return raw
    .replace(/(>)(<)/g, '$1\n$2')
    .split('\n')
    .map(s => s.trim())
    .filter(Boolean)
    .join('\n');
}

function tokens(path) {
  let s = path.trim();

  if (s.startsWith('$')) {
    s = s.slice(1);
  }

  const t = [];
  let i = 0;

  while (i < s.length) {
    if (s[i] === '.') {
      i++;

      const m = s
        .slice(i)
        .match(
          /^([A-Za-z_$][A-Za-z0-9_$-]*)/
        );

      if (!m) {
        throw Error('Invalid JSONPath.');
      }

      t.push({ k: m[1] });
      i += m[1].length;

    } else if (s[i] === '[') {
      const e = s.indexOf(']', i);

      if (e < 0) {
        throw Error(
          'Unclosed JSONPath bracket.'
        );
      }

      const x = s
        .slice(i + 1, e)
        .trim();

      if (/^\d+$/.test(x)) {
        t.push({ i: +x });

      } else if (x === '*') {
        t.push({ w: 1 });

      } else if (
        (x[0] === '"' && x.at(-1) === '"') ||
        (x[0] === "'" && x.at(-1) === "'")
      ) {
        t.push({ k: x.slice(1, -1) });

      } else {
        throw Error(
          `Unsupported JSONPath expression [${x}].`
        );
      }

      i = e + 1;

    } else {
      const m = s
        .slice(i)
        .match(
          /^([A-Za-z_$][A-Za-z0-9_$-]*)/
        );

      if (!m) {
        throw Error('Invalid JSONPath.');
      }

      t.push({ k: m[1] });
      i += m[1].length;
    }
  }

  return t;
}

function jp(root, path) {
  let cur = [{ v: root, p: '$' }];

  for (const q of tokens(path)) {
    const next = [];

    for (const x of cur) {
      if (
        q.k &&
        x.v &&
        typeof x.v === 'object' &&
        q.k in x.v
      ) {
        next.push({
          v: x.v[q.k],
          p: `${x.p}.${q.k}`
        });

      } else if (
        q.i !== undefined &&
        Array.isArray(x.v) &&
        q.i < x.v.length
      ) {
        next.push({
          v: x.v[q.i],
          p: `${x.p}[${q.i}]`
        });

      } else if (q.w) {
        if (Array.isArray(x.v)) {
          x.v.forEach((v, i) =>
            next.push({
              v,
              p: `${x.p}[${i}]`
            })
          );
        } else if (
          x.v &&
          typeof x.v === 'object'
        ) {
          Object.keys(x.v).forEach(k =>
            next.push({
              v: x.v[k],
              p: `${x.p}.${k}`
            })
          );
        }
      }
    }

    cur = next;
  }

  return cur;
}

function diff(a, b) {
  const A = a
    .replace(/\r\n?/g, '\n')
    .split('\n');

  const B = b
    .replace(/\r\n?/g, '\n')
    .split('\n');

  const d = Array.from(
    { length: A.length + 1 },
    () => Array(B.length + 1).fill(0)
  );

  for (let i = A.length - 1; i >= 0; i--) {
    for (let j = B.length - 1; j >= 0; j--) {
      d[i][j] =
        A[i] === B[j]
          ? d[i + 1][j + 1] + 1
          : Math.max(
              d[i + 1][j],
              d[i][j + 1]
            );
    }
  }

  const o = [];
  let i = 0;
  let j = 0;

  while (
    i < A.length &&
    j < B.length
  ) {
    if (A[i] === B[j]) {
      o.push('  ' + A[i++]);
    } else if (
      d[i + 1][j] >= d[i][j + 1]
    ) {
      o.push('- ' + A[i++]);
    } else {
      o.push('+ ' + B[j++]);
    }
  }

  while (i < A.length) {
    o.push('- ' + A[i++]);
  }

  while (j < B.length) {
    o.push('+ ' + B[j++]);
  }

  return o.join('\n');
}

function parse(format, text) {
  if (format === 'json') {
    return jsonParse(text);
  }

  if (format === 'yaml') {
    try {
      return {
        ok: true,
        value: parseYaml(text)
      };
    } catch (e) {
      return {
        ok: false,
        error: {
          message: e.message,
          line: e.yamlLine
        }
      };
    }
  }

  try {
    return {
      ok: true,
      value: xmlParse(text)
    };
  } catch (e) {
    return {
      ok: false,
      error: {
        message: e.message
      }
    };
  }
}

export function renderDataWorkbench(app) {
  app.innerHTML = `
    <section class="card">
      <div class="row between">
        <div>
          <h2>JSON / YAML / XML Workbench</h2>
          <p class="muted">
            Format, validate, minify, sort, convert, repair, extract, and diff locally.
          </p>
        </div>

        <span class="badge ok"></span>
      </div>

      <!-- Operation buttons -->
      <div class="row">
        ${[
          'format',
          'validate',
          'minify',
          'sort',
          'convert',
          'diff'
        ]
          .map(
            x => `
              <button
                class="btn ${
                  x === 'format'
                    ? 'primary'
                    : 'secondary'
                }"
                type="button"
                data-tab="${x}"
              >
                ${x[0].toUpperCase() + x.slice(1)}
              </button>
            `
          )
          .join('')}
      </div>

      <div class="card">
        <div class="row between">
          <label for="dw-format">
            Input format
          </label>

          <select id="dw-format">
            <option value="json">JSON</option>
            <option value="yaml">YAML</option>
            <option value="xml">XML</option>
          </select>
        </div>

        <div class="row between">
          <label for="dw-input">
            Input value
          </label>

          <button
            class="btn secondary"
            type="button"
            id="dw-clear"
          >
            Clear
          </button>
        </div>

        <textarea
          id="dw-input"
          rows="14"
          placeholder="Paste JSON, YAML, or XML…"
        ></textarea>

        <div class="row">
          <button
            class="btn primary"
            type="button"
            id="dw-run"
          >
            Run
          </button>

          <button
            class="btn secondary"
            type="button"
            id="dw-copy"
          >
            Copy result
          </button>

          <button
            class="btn secondary"
            type="button"
            id="dw-download"
          >
            Download
          </button>
        </div>
      </div>

      <div id="dw-extra"></div>

      <div
        id="dw-status"
        class="notice hidden"
        role="status"
      ></div>

      <div class="card">
        <div class="row between">
          <label for="dw-result">
            Result
          </label>

          <span
            class="muted"
            id="dw-info"
          >
            —
          </span>
        </div>

        <textarea
          id="dw-result"
          rows="14"
          readonly
          placeholder="Result appears here…"
        ></textarea>
      </div>

      <div class="card">
        <div class="row between">
          <h3>JSONPath evaluator</h3>
          <span class="muted">
            Query parsed data
          </span>
        </div>

        <div class="row">
          <input
            id="dw-jp"
            value="$.users[0].name"
            placeholder="$.users[0].name"
          >

          <button
            class="btn secondary"
            type="button"
            id="dw-jp-run"
          >
            Evaluate
          </button>
        </div>

        <pre
          id="dw-jp-out"
          class="mono"
        ></pre>
      </div>

      <div class="card">
        <div class="row between">
          <h3>Extract a value by path</h3>
          <span class="muted">
            JSONPath-style lookup
          </span>
        </div>

        <div class="row">
          <input
            id="dw-path"
            value="users[0].name"
            placeholder="users[0].name"
          >

          <button
            class="btn secondary"
            type="button"
            id="dw-path-run"
          >
            Extract
          </button>
        </div>

        <pre
          id="dw-path-out"
          class="mono"
        ></pre>
      </div>

      <div class="card">
        <div class="row between">
          <h3>Repair common JSON mistakes</h3>

          <button
            class="btn secondary"
            type="button"
            id="dw-repair"
          >
            Repair JSON
          </button>
        </div>

        <pre
          id="dw-repair-out"
          class="mono"
        ></pre>
      </div>

      <div class="card">
        <h3>Syntax / error location</h3>

        <pre
          id="dw-error"
          class="mono"
        >No operation run yet.</pre>
      </div>
    </section>
  `;

  const $ = s => app.querySelector(s);

  let tab = 'format';
  let last = '';

  function status(
    text,
    kind = 'error'
  ) {
    $('#dw-status').textContent = text;
    $('#dw-status').className = text
      ? `notice ${kind}`
      : 'notice hidden';
  }

  function options() {
    const e = $('#dw-extra');

    if (tab === 'diff') {
      e.innerHTML = `
        <div class="card">
          <div class="row between">
            <label for="dw-right">
              Compare against
            </label>

            <button
              class="btn secondary"
              type="button"
              id="dw-clear-right"
            >
              Clear
            </button>
          </div>

          <textarea
            id="dw-right"
            rows="14"
            placeholder="Paste second document…"
          ></textarea>
        </div>
      `;

      $('#dw-clear-right').onclick = () => {
        $('#dw-right').value = '';
      };

    } else if (tab === 'convert') {
      const f = $('#dw-format').value;

      const ts =
        f === 'json'
          ? ['yaml', 'xml']
          : f === 'yaml'
            ? ['json', 'xml']
            : ['json', 'yaml'];

      e.innerHTML = `
        <div class="card">
          <div class="grid two">
            <div class="card compact">
              <label for="dw-target">
                Convert to
              </label>

              <select id="dw-target">
                ${ts
                  .map(
                    x =>
                      `<option value="${x}">
                        ${x.toUpperCase()}
                      </option>`
                  )
                  .join('')}
              </select>
            </div>

            <div class="card compact">
              <label for="dw-root">
                XML root
              </label>

              <input
                id="dw-root"
                value="root"
                placeholder="root"
              >
            </div>
          </div>
        </div>
      `;

    } else {
      e.innerHTML = '';
    }
  }

  function run() {
    const f = $('#dw-format').value;

    if (tab === 'diff') {
      const l = parse(
        f,
        $('#dw-input').value
      );

      const r = parse(
        f,
        $('#dw-right').value
      );

      if (!l.ok || !r.ok) {
        status(
          'Both documents must be valid.'
        );

        $('#dw-error').textContent =
          (l.ok ? r.error : l.error).message;

        return;
      }

      const lt =
        f === 'json'
          ? JSON.stringify(
              l.value,
              null,
              2
            )
          : f === 'yaml'
            ? yamlString(l.value)
            : xmlPretty(
                $('#dw-input').value
              );

      const rt =
        f === 'json'
          ? JSON.stringify(
              r.value,
              null,
              2
            )
          : f === 'yaml'
            ? yamlString(r.value)
            : xmlPretty(
                $('#dw-right').value
              );

      last = diff(lt, rt);

      $('#dw-result').value = last;

      $('#dw-info').textContent =
        `${last.split('\n').length} lines`;

      status(
        'Diff generated locally.',
        'success'
      );

      return;
    }

    const p = parse(
      f,
      $('#dw-input').value
    );

    if (!p.ok) {
      last = '';
      $('#dw-result').value = '';

      $('#dw-error').textContent =
        `${p.error.message}${
          p.error.line
            ? ` Line ${p.error.line}.`
            : ''
        }`;

      status(
        'Parse/validation failed.'
      );

      return;
    }

    let out = '';

    try {
      if (
        tab === 'format' ||
        tab === 'validate'
      ) {
        out =
          f === 'json'
            ? JSON.stringify(
                p.value,
                null,
                2
              )
            : f === 'yaml'
              ? yamlString(p.value)
              : xmlPretty(
                  $('#dw-input').value
                );

      } else if (tab === 'minify') {
        out =
          f === 'json'
            ? JSON.stringify(p.value)
            : f === 'yaml'
              ? yamlString(p.value).replace(
                  /\n\s+/g,
                  '\n'
                )
              : new XMLSerializer()
                  .serializeToString(
                    p.value
                  );

      } else if (tab === 'sort') {
        if (f !== 'json') {
          throw Error(
            'Sort keys currently applies to JSON only.'
          );
        }

        out = JSON.stringify(
          sortKeys(p.value),
          null,
          2
        );

      } else if (tab === 'convert') {
        const t = $('#dw-target').value;

        if (f === 'xml') {
          const j = xmlToJson(
            p.value.documentElement
          );

          out =
            t === 'json'
              ? JSON.stringify(
                  j,
                  null,
                  2
                )
              : yamlString(j);

        } else if (t === 'xml') {
          out = jsonToXml(
            p.value,
            $('#dw-root').value || 'root'
          );

        } else {
          out =
            t === 'json'
              ? JSON.stringify(
                  p.value,
                  null,
                  2
                )
              : yamlString(p.value);
        }
      }

      last = out;
      $('#dw-result').value = out;

      $('#dw-info').textContent =
        `${out.length.toLocaleString()} characters`;

      $('#dw-error').textContent =
        'No syntax error.';

      status(
        tab === 'validate'
          ? 'Valid input.'
          : 'Operation completed locally.',
        'success'
      );

    } catch (e) {
      last = '';
      $('#dw-result').value = '';
      $('#dw-error').textContent =
        e.message;

      status(
        'Operation failed.'
      );
    }
  }

  /*
   * Operation buttons.
   * These use the same btn primary/secondary
   * visual hierarchy as Script 2.
   */
  app
    .querySelectorAll('[data-tab]')
    .forEach(button => {
      button.onclick = () => {
        tab = button.dataset.tab;

        app
          .querySelectorAll('[data-tab]')
          .forEach(x => {
            const active =
              x === button;

            x.classList.toggle(
              'primary',
              active
            );

            x.classList.toggle(
              'secondary',
              !active
            );
          });

        options();
      };
    });

  $('#dw-format').onchange = () => {
    options();
  };

  $('#dw-run').onclick = run;

  $('#dw-clear').onclick = () => {
    $('#dw-input').value = '';

    if ($('#dw-right')) {
      $('#dw-right').value = '';
    }

    $('#dw-result').value = '';
    last = '';

    status('');

    $('#dw-error').textContent =
      'No operation run yet.';
  };

  $('#dw-copy').onclick = async () => {
    if (!last) return;

    try {
      await navigator.clipboard.writeText(
        last
      );

      status(
        'Copied.',
        'success'
      );
    } catch {
      const e = $('#dw-result');

      e.focus();
      e.select();

      document.execCommand('copy');

      status(
        'Copied.',
        'success'
      );
    }
  };

  $('#dw-download').onclick = () => {
    if (last) {
      downloadText(
        last,
        `admin-toolbox-${tab}.txt`
      );
    }
  };

  $('#dw-jp-run').onclick = () => {
    const p = parse(
      $('#dw-format').value,
      $('#dw-input').value
    );

    if (!p.ok) {
      $('#dw-jp-out').textContent =
        p.error.message;

      return;
    }

    let root = p.value;

    if (
      $('#dw-format').value === 'xml'
    ) {
      root = xmlToJson(
        root.documentElement
      );
    }

    try {
      const r = jp(
        root,
        $('#dw-jp').value
      );

      $('#dw-jp-out').textContent =
        r.length
          ? r
              .map(
                x =>
                  `${x.p} = ${JSON.stringify(
                    x.v,
                    null,
                    2
                  )}`
              )
              .join('\n')
          : 'No matches.';

    } catch (e) {
      $('#dw-jp-out').textContent =
        e.message;
    }
  };

  $('#dw-path-run').onclick = () => {
    const p = parse(
      $('#dw-format').value,
      $('#dw-input').value
    );

    if (!p.ok) {
      $('#dw-path-out').textContent =
        p.error.message;

      return;
    }

    let root = p.value;

    if (
      $('#dw-format').value === 'xml'
    ) {
      root = xmlToJson(
        root.documentElement
      );
    }

    try {
      let path =
        $('#dw-path').value.trim();

      path = path.startsWith('$')
        ? path
        : '$.' + path;

      const r = jp(
        root,
        path
      );

      $('#dw-path-out').textContent =
        r.length
          ? r
              .map(x =>
                JSON.stringify(
                  x.v,
                  null,
                  2
                )
              )
              .join('\n---\n')
          : 'No value found.';

    } catch (e) {
      $('#dw-path-out').textContent =
        e.message;
    }
  };

  $('#dw-repair').onclick = () => {
    const fixed = repairJson(
      $('#dw-input').value
    );

    const p = jsonParse(fixed);

    $('#dw-repair-out').textContent =
      p.ok
        ? fixed
        : `Repair result is still invalid JSON.

${p.error.message}

${fixed}`;
  };

  options();
}