import { addWorkflowArtifact } from '../workflow.js';

const RULES = [
  {
    id: 'AWS_ACCESS_KEY',
    name: 'AWS access key',
    severity: 'high',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    id: 'GITHUB_TOKEN',
    name: 'GitHub token',
    severity: 'high',
    re: /\bgh[pousr]_[A-Za-z0-9_]{20,255}\b/g,
  },
  {
    id: 'SLACK_TOKEN',
    name: 'Slack token',
    severity: 'high',
    re: /\bxox[baprs]-[0-9A-Za-z-]{10,200}\b/g,
  },
  {
    id: 'GOOGLE_API_KEY',
    name: 'Google API key',
    severity: 'high',
    re: /\bAIza[0-9A-Za-z_-]{30,45}\b/g,
  },
  {
    id: 'JWT',
    name: 'JWT',
    severity: 'medium',
    re: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
  },
  {
    id: 'PRIVATE_KEY',
    name: 'Private key block',
    severity: 'high',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 |ENCRYPTED )?PRIVATE KEY-----/g,
  },
  {
    id: 'BASIC_AUTH_URL',
    name: 'Credentialed URL',
    severity: 'high',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/]+@[^\s]+/gi,
  },
  {
    id: 'CONNECTION_STRING',
    name: 'Connection string',
    severity: 'high',
    re: /\b(?:Server|Data Source|Host|Endpoint)\s*=\s*[^;\r\n]+(?:;\s*(?:User ID|UID|Username)\s*=\s*[^;\r\n]+)?(?:;\s*(?:Password|PWD)\s*=\s*[^;\r\n]+)?/gi,
  },
  {
    id: 'AZURE_STORAGE_KEY',
    name: 'Azure storage key assignment',
    severity: 'high',
    re: /\b(?:AccountKey|azure_storage_key|storage[_-]?account[_-]?key)\s*[:=]\s*[A-Za-z0-9+/=]{30,}\b/gi,
  },
  {
    id: 'GENERIC_SECRET_ASSIGN',
    name: 'Secret/password/token assignment',
    severity: 'medium',
    re: /\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*(['"]?)[^\s'"`]{6,}\1/gi,
  },
  {
    id: 'BEARER',
    name: 'Bearer token',
    severity: 'medium',
    re: /\bBearer\s+[A-Za-z0-9._~+\/-]{20,}=*/gi,
  },
  {
    id: 'BASIC_HEADER',
    name: 'Basic authorization header',
    severity: 'medium',
    re: /\bAuthorization\s*:\s*Basic\s+[A-Za-z0-9+/=]{12,}/gi,
  },
  {
    id: 'PASSWORD_FLAG',
    name: 'Password on command line',
    severity: 'medium',
    re: /\s(?:-p|--password|--passwd|--pwd)\s+[^\s]+/gi,
  },
];
function esc(s) {
  return String(s ?? '').replace(
    /[&<>"']/g,
    c => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }[c]),
  );
}
function shannon(s) {
  const m = new Map();
  for (const ch of s) {
    m.set(ch, (m.get(ch) || 0) + 1);
  }
  let h = 0;
  for (const n of m.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
function redact(v) {
  if (v.length <= 6) {
    return '••••••';
  }
  return `${v.slice(0, 3)}${'•'.repeat(
    Math.min(24, Math.max(4, v.length - 5)),
  )}${v.slice(-2)}`;
}
function lineContext(text, start, end) {
  const lineStart = text.lastIndexOf('\n', start - 1) + 1;
  const lineEnd = text.indexOf('\n', end);
  return {
    line: text.slice(
      lineStart,
      lineEnd < 0 ? text.length : lineEnd,
    ),
    lineNumber: text.slice(0, start).split('\n').length,
  };
}
function scan(text) {
  const hits = [];
  const seen = new Set();
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(text))) {
      const raw = m[0];
      let value = raw;
      if (rule.id === 'GENERIC_SECRET_ASSIGN') {
        const parts = raw.split(/[:=]/);
        value = parts[parts.length - 1]
          .trim()
          .replace(/^['"]|['"]$/g, '');
      }
      const entropy = value.length >= 8
        ? shannon(value)
        : 0;
      const key = `${rule.id}:${m.index}:${raw}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      const ctx = lineContext(
        text,
        m.index,
        m.index + raw.length,
      );
      hits.push({
        rule: rule.id,
        name: rule.name,
        severity: rule.severity,
        start: m.index,
        end: m.index + raw.length,
        line: ctx.lineNumber,
        context: ctx.line.replace(raw, redact(raw)),
        redacted: redact(raw),
        entropy: Math.round(entropy * 100) / 100,
        note: rule.note || '',
      });
    }
  }
  const lines = text.split(/\n/);
  let offset = 0;
  for (const line of lines) {
    const m = line.match(
      /\b([A-Za-z][A-Za-z0-9_.-]{2,40})\s*[:=]\s*([A-Za-z0-9+/_=-]{20,})\s*$/,
    );
    if (m) {
      const val = m[2];
      if (
        !/^(true|false|null|undefined|localhost)$/i.test(val)
      ) {
        const ent = shannon(val);
        if (ent >= 4.0) {
          hits.push({
            rule: 'HIGH_ENTROPY_ASSIGNMENT',
            name: 'High-entropy assignment',
            severity: 'low',
            start: offset + m.index,
            end: offset + m.index + m[0].length,
            line: lines.indexOf(line) + 1,
            context: line.replace(val, redact(val)),
            redacted: redact(val),
            entropy: Math.round(ent * 100) / 100,
            note:
              'Heuristic only; this can also match hashes, IDs and opaque configuration values.',
          });
        }
      }
    }
    offset += line.length + 1;
  }
  hits.sort(
    (a, b) =>
      ({ high: 0, medium: 1, low: 2 }[a.severity] -
        { high: 0, medium: 1, low: 2 }[b.severity]) ||
      a.line - b.line,
  );
  return hits;
}
export function renderSDetector(app) {
  app.innerHTML = '';
  app.insertAdjacentHTML(
    'beforeend',
    `
      <section class="card sd-wrap">
        <div>
          <h2>Secrets detector</h2>
          <p class="small sd-muted">
            Paste configuration or log text. Everything is analyzed locally.
            Findings are redacted by default and exports never contain the full detected secret.
          </p>
        </div>
        <textarea
          class="sd-text"
          id="sdInput"
          spellcheck="false"
          placeholder="Paste config, logs, environment variables, connection strings, HTTP headers, scripts, etc."
        ></textarea>
        <div class="sd-toolbar">
          <button class="btn primary" id="sdScan">Scan</button>
          <button class="btn secondary" id="sdClear">Clear</button>
            <label class="checkline">
            <input
                type="checkbox"
                id="sdIgnoreComments"
            >
            Ignore obvious comments
            </label>
        </div>
        <div id="sdResults"></div>
      </section>
    `,
  );
  const input = app.querySelector('#sdInput');
  const out = app.querySelector('#sdResults');
  let last = [];
  function run() {
    let text = input.value;
    if (app.querySelector('#sdIgnoreComments').checked) {
      text = text
        .split('\n')
        .filter(l => !/^\s*(#|;|\/\/)/.test(l))
        .join('\n');
    }
    last = scan(text);
    const counts = {
      high: last.filter(x => x.severity === 'high').length,
      medium: last.filter(x => x.severity === 'medium').length,
      low: last.filter(x => x.severity === 'low').length,
    };
    out.innerHTML =
      `
        <div class="sd-grid">
          <div class="sd-stat">
            <span>Total findings</span>
            <b>${last.length}</b>
          </div>
          <div class="sd-stat">
            <span>High</span>
            <b>${counts.high}</b>
          </div>
          <div class="sd-stat">
            <span>Medium</span>
            <b>${counts.medium}</b>
          </div>
          <div class="sd-stat">
            <span>Low / heuristic</span>
            <b>${counts.low}</b>
          </div>
        </div>
      ` +
      `
        <div class="sd-actions">
          <button class="sd-btn" id="sdCopy" type="button">Copy redacted report</button>
          <button class="sd-btn" id="sdToWorkflow" type="button">Add redacted report to workflow</button>
        </div>
      ` +
      (
        last.length
          ? last
              .map(
                (x, i) => `
                  <article class="sd-hit ${esc(x.severity)}">
                    <div class="sd-tags">
                      <span class="sd-tag">
                        ${esc(x.severity.toUpperCase())}
                      </span>
                      <span class="sd-tag">
                        ${esc(x.name)}
                      </span>
                      <span class="sd-tag">
                        line ${x.line}
                      </span>
                      ${
                        x.entropy
                          ? `
                            <span class="sd-tag">
                              entropy ${x.entropy}
                            </span>
                          `
                          : ''
                      }
                    </div>
                    <div class="sd-code">
                      ${esc(x.context)}
                    </div>
                    ${
                      x.note
                        ? `
                          <div
                            class="sd-muted generated-style-62838f56"

                          >
                            ${esc(x.note)}
                          </div>
                        `
                        : ''
                    }
                  </article>
                `,
              )
              .join('')
          : `
              <div class="sd-stat sd-good">
                <b>✓ No likely secrets found</b>
                <span>
                  This is heuristic analysis, not proof of absence.
                </span>
              </div>
            `
      );
    app
      .querySelector('#sdCopy')
      ?.addEventListener(
        'click',
        () =>
          navigator.clipboard?.writeText(
            JSON.stringify(
              {
                scannedAt: new Date().toISOString(),
                findings: last,
              },
              null,
              2,
            ),
          ),
      );
    app.querySelector('#sdToWorkflow')?.addEventListener('click', () => {
      try {
        const report = JSON.stringify({ scannedAt: new Date().toISOString(), findings: last }, null, 2);
        const item = addWorkflowArtifact({ name: 'Secrets detector redacted report', source: 'Secrets Detector', content: report, contentType: 'application/json' });
        const button = app.querySelector('#sdToWorkflow');
        button.textContent = `Added (${item.bytes.toLocaleString()} bytes)`;
      } catch (error) {
        const button = app.querySelector('#sdToWorkflow');
        button.textContent = error.message;
      }
    });
  }
  app
    .querySelector('#sdScan')
    .addEventListener('click', run);
  app
    .querySelector('#sdClear')
    .addEventListener('click', () => {
      input.value = '';
      out.innerHTML = '';
      last = [];
      input.focus();
    });
}