import { $, escapeHtml, downloadText } from '../utils.js';

const RULES = [
  {
    id: 'invoke-expression',
    sev: 'danger',
    title: 'Invoke-Expression',
    re: /\bInvoke-Expression\b|\bIEX\b/i,
    why: 'Executes dynamically constructed PowerShell and can make code difficult to audit safely.',
  },
  {
    id: 'download-exec',
    sev: 'danger',
    title: 'Download + execute pattern',
    re: /(Invoke-WebRequest|iwr|curl|wget)[^\n|]*\|\s*(IEX|Invoke-Expression|iex)\b/i,
    why: 'Looks like content retrieved from a remote source is being executed.',
  },
  {
    id: 'credential-literal',
    sev: 'danger',
    title: 'Credential-like literal',
    re: /\b(password|passwd|pwd|secret|token|apikey|api_key)\s*=\s*['"][^'"]+['"]/i,
    why: 'A secret-like value appears to be hard-coded in the script.',
  },
  {
    id: 'secure-string',
    sev: 'warn',
    title: 'ConvertTo-SecureString with plaintext',
    re: /ConvertTo-SecureString\s+['"]/i,
    why: 'A literal secret appears to be converted at runtime; verify that a secure secret source is used instead.',
  },
  {
    id: 'silently-continue',
    sev: 'warn',
    title: 'SilentlyContinue',
    re: /-ErrorAction\s+SilentlyContinue\b/i,
    why: 'Suppressing errors can hide operational failures during administration.',
  },
  {
    id: 'write-host',
    sev: 'warn',
    title: 'Write-Host',
    re: /\bWrite-Host\b/i,
    why: 'Write-Host is intended for interactive display and is often less useful than structured output/logging.',
  },
  {
    id: 'aliases',
    sev: 'style',
    title: 'Common aliases',
    re: /(^|[\s|;{(])(gci|gc|ls|dir|cat|type|cp|copy|mv|move|rm|del|ni|md|mkdir|rmdir|where|where-object|%|select|select-object|sort|sort-object|ft|format-table|fl|format-list)(?=\s|$|[|;)}])/i,
    why: 'Explicit cmdlet names are generally easier to read and maintain in shared administrative scripts.',
  },
  {
    id: 'positional-params',
    sev: 'style',
    title: 'Potentially opaque positional parameters',
    re: /\b(Get-[A-Za-z-]+|Set-[A-Za-z-]+|New-[A-Za-z-]+|Remove-[A-Za-z-]+)\s+(-?\w+\s+)?['"][^'"]+['"]/i,
    why: 'Consider named parameters where they improve clarity and reduce ambiguity.',
  },
];

const ALIASES = new Map(
  Object.entries({
    '%': 'ForEach-Object',
    '?': 'Where-Object',
    where: 'Where-Object',
    select: 'Select-Object',
    sort: 'Sort-Object',

    gci: 'Get-ChildItem',
    ls: 'Get-ChildItem',
    dir: 'Get-ChildItem',

    gc: 'Get-Content',
    cat: 'Get-Content',
    type: 'Get-Content',

    cp: 'Copy-Item',
    copy: 'Copy-Item',

    mv: 'Move-Item',
    move: 'Move-Item',

    rm: 'Remove-Item',
    del: 'Remove-Item',

    ni: 'New-Item',
    md: 'New-Item',
    mkdir: 'New-Item',

    rmdir: 'Remove-Item',

    ft: 'Format-Table',
    fl: 'Format-List',
  }),
);

export function renderPowershell(app) {
  app.innerHTML = `
    <section class="card">
      <h2>PowerShell analyzer</h2>
      <p class="small">
        Static analysis only. Nothing is executed, imported, or sent anywhere.
        Checks common security, reliability, and readability issues.
      </p>

      <label for="psCode">PowerShell</label>

      <textarea
        id="psCode"
        class="mono"
        style="min-height:340px"
        placeholder="Paste PowerShell here"
      ></textarea>

      <div class="row" style="margin-top:10px">
        <button class="btn primary" id="psAnalyze">Analyze</button>
        <button class="btn" id="psClear">Clear</button>
        <button class="btn" id="psExport">Export report</button>
      </div>
    </section>

    <section class="card" id="psResults" hidden>
      <div id="psSummary"></div>
      <div id="psFindings"></div>
      <div id="psAliases"></div>
    </section>
  `;

  const input = $('#psCode');
  const results = $('#psResults');

  let report = null;

  $('#psAnalyze').onclick = () => {
    report = analyze(input.value);
    render(report);
  };

  $('#psClear').onclick = () => {
    input.value = '';
    results.hidden = true;
    report = null;
    input.focus();
  };

  $('#psExport').onclick = () => {
    if (!report) {
      report = analyze(input.value);
    }

    downloadText(
      'powershell-analysis.json',
      JSON.stringify(report, null, 2),
      'application/json;charset=utf-8',
    );
  };

  input.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      $('#psAnalyze').click();
    }
  });

  function analyze(code) {
    const lines = code.split(/\r?\n/);
    const findings = [];

    for (let i = 0; i < lines.length; i++) {
      for (const rule of RULES) {
        rule.re.lastIndex = 0;

        if (rule.re.test(lines[i])) {
          findings.push({
            line: i + 1,
            severity: rule.sev,
            title: rule.title,
            why: rule.why,
            code: lines[i].trim(),
            id: rule.id,
          });
        }
      }
    }

    const aliases = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      const re =
        /(^|[\s|;{(])(%|\?|where|select|sort|gci|ls|dir|gc|cat|type|cp|copy|mv|move|rm|del|ni|md|mkdir|rmdir|ft|fl)(?=\s|$|[|;)}])/gi;

      let m;

      while ((m = re.exec(line))) {
        aliases.push({
          line: i + 1,
          alias: m[2],
          expansion:
            ALIASES.get(m[2].toLowerCase()) ||
            ALIASES.get(m[2]) ||
            'unknown',
        });
      }
    }

    const metrics = {
      lines: lines.length,
      nonEmpty: lines.filter((x) => x.trim()).length,
      findings: findings.length,
      dangerous: findings.filter((x) => x.severity === 'danger').length,
      warnings: findings.filter((x) => x.severity === 'warn').length,
      style: findings.filter((x) => x.severity === 'style').length,
      aliases: aliases.length,
    };

    return {
      application: 'Admin Toolbox - PowerShell analyzer',
      generatedAt: new Date().toISOString(),
      metrics,
      findings,
      aliases,
    };
  }

  function render(r) {
    results.hidden = false;

    $('#psSummary').innerHTML = `
      <div class="grid">
        ${stat('Lines', r.metrics.lines)}
        ${stat('Findings', r.metrics.findings)}
        ${stat('Security concerns', r.metrics.dangerous)}
        ${stat('Warnings', r.metrics.warnings)}
        ${stat('Style', r.metrics.style)}
        ${stat('Aliases', r.metrics.aliases)}
      </div>
    `;

    $('#psFindings').innerHTML =
      '<h3>Findings</h3>' +
      (r.findings.length
        ? r.findings
            .map(
              (f) => `
                <div class="status ${
                  f.severity === 'danger'
                    ? 'danger'
                    : f.severity === 'warn'
                      ? 'warn'
                      : 'ok'
                }">
                  <strong>
                    Line ${f.line}: ${escapeHtml(f.title)}
                  </strong>

                  <div>${escapeHtml(f.why)}</div>
                  <code>${escapeHtml(f.code)}</code>
                </div>
              `,
            )
            .join('')
        : '<p class="status ok">No configured findings.</p>');

    const aliasRows = r.aliases
      .map(
        (a) => `
          <tr>
            <td>${a.line}</td>
            <td><code>${escapeHtml(a.alias)}</code></td>
            <td>${escapeHtml(a.expansion)}</td>
          </tr>
        `,
      )
      .join('');

    $('#psAliases').innerHTML =
      '<h3>Alias report</h3>' +
      (aliasRows
        ? `
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Line</th>
                  <th>Alias</th>
                  <th>Expansion</th>
                </tr>
              </thead>
              <tbody>
                ${aliasRows}
              </tbody>
            </table>
          </div>
        `
        : '<p class="small">No common aliases detected.</p>');
  }

  function stat(label, value) {
    return `
      <div class="stat">
        <span>${label}</span>
        <strong>${value}</strong>
      </div>
    `;
  }
}
