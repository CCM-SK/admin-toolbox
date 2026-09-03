const esc = v => String(v ?? '')
  .replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

function parseGpResult(text) {
  const raw = String(text ?? '').replace(/\r\n?/g, '\n');
  const lines = raw.split('\n');
  const out = {
    raw,
    computer: { applied: [], denied: [], filtering: [], settings: [], context: {}, clues: [] },
    user: { applied: [], denied: [], filtering: [], settings: [], context: {}, clues: [] },
    global: {},
    findings: [],
    warnings: []
  };

  let scope = null;
  let mode = null;
  let current = null;

  const target = () => scope ? out[scope] : null;
  const addGpo = (kind, name) => {
    const t = target();
    if (!t || !name) return null;
    const arr = t[kind];
    const existing = arr.find(x => x.name.toLowerCase() === name.toLowerCase());
    if (existing) return existing;
    const item = { name, reason: '', details: [] };
    arr.push(item);
    current = item;
    return item;
  };

  for (const original of lines) {
    const line = original.replace(/\uFEFF/g, '');
    const t = line.trim();
    if (!t) continue;

    let m;
    if (/^(COMPUTER)\s+(?:SETTINGS|CONFIGURATION|POLICY)\b/i.test(t)) {
      scope = 'computer'; mode = null; current = null; continue;
    }
    if (/^(USER)\s+(?:SETTINGS|CONFIGURATION|POLICY)\b/i.test(t)) {
      scope = 'user'; mode = null; current = null; continue;
    }

    m = t.match(/^Site Name\s*:\s*(.+)$/i); if (m) { out.global.site = m[1]; continue; }
    m = t.match(/^Domain Name\s*:\s*(.+)$/i); if (m) { out.global.domain = m[1]; continue; }
    m = t.match(/^Domain Controller\s*:\s*(.+)$/i); if (m) { out.global.domainController = m[1]; continue; }
    m = t.match(/^(?:Organizational Unit|OU)\s*:\s*(.+)$/i); if (m) { out.global.ou = m[1]; continue; }
    m = t.match(/^(?:Computer Name|Host Name|Host)\s*:\s*(.+)$/i); if (m) { out.global.computer = m[1]; continue; }
    m = t.match(/^User(?: Name)?\s*:\s*(.+)$/i); if (m) { out.global.user = m[1]; continue; }

    if (/^Applied Group Policy Objects\b/i.test(t) || /^Applied GPOs?\b/i.test(t)) {
      mode = 'applied'; current = null; continue;
    }
    if (/^Denied Group Policy Objects\b/i.test(t) ||
        /^The following GPOs were not applied because they were denied\b/i.test(t) ||
        /^Denied GPOs?\b/i.test(t)) {
      mode = 'denied'; current = null; continue;
    }

    if (/^(?:Security Settings|Administrative Templates|Windows Settings|Folder Redirection|Scripts|Software Settings)\b/i.test(t)) {
      mode = 'settings'; current = null; continue;
    }

    m = t.match(/^Security Filtering\s*:\s*(.+)$/i);
    if (m && target()) {
      target().filtering.push(m[1]);
      if (current) current.details.push(`Security Filtering: ${m[1]}`);
      continue;
    }

    m = t.match(/^(?:Reason Denied|Denied Reason|Reason for denial|Reason)\s*:\s*(.+)$/i);
    if (m && current) { current.reason = m[1]; continue; }

    m = t.match(/^WMI Filter\s*:\s*(.+)$/i);
    if (m && target()) {
      target().settings.push(`WMI Filter: ${m[1]}`);
      if (current) current.details.push(`WMI Filter: ${m[1]}`);
      continue;
    }

    m = t.match(/^(?:Site|Domain|OU|Organizational Unit|Group Policy Inheritance|Inheritance|Link|Linked|Block Inheritance|Enforced|No Override)\s*:\s*(.+)$/i);
    if (m && target()) {
      const key = t.split(':')[0].trim();
      target().context[key] = m[1];
      if (/inherit|enforced|override|link/i.test(key)) target().clues.push(t);
      continue;
    }

    if (scope && mode === 'settings') {
      if (t.length < 300) target().settings.push(t);
      continue;
    }

    if (scope && mode && !t.includes(':')) {
      const indent = line.search(/\S/);
      if (indent >= 0 && indent <= 12 &&
          !/^(?:The following|Applied|Denied|Computer|User|Security|Filtering|Reason|Winning|Group Policy|Registry|Windows|System|Name|Site|Domain|OU|Forest)\b/i.test(t) &&
          t.length < 220) {
        addGpo(mode === 'denied' ? 'denied' : 'applied', t);
        continue;
      }
    }

    if (scope) {
      const kv = t.match(/^([^:]{1,120}):\s*(.{1,240})$/);
      if (kv && mode === 'settings') target().settings.push(`${kv[1].trim()}: ${kv[2].trim()}`);
    }
  }

  const all = raw.toLowerCase();
  if (/security filtering/.test(all)) out.findings.push({
    level:'info', title:'Security filtering evidence',
    detail:'The report contains security-filtering information. A GPO can be out of scope when the computer/user lacks the required security-filtering membership.'
  });
  if (/wmi filter/.test(all)) out.findings.push({
    level:'info', title:'WMI filtering evidence',
    detail:'A WMI filter is mentioned. A false WMI filter result can prevent a GPO from applying.'
  });
  if (/block inheritance/.test(all)) out.findings.push({
    level:'warning', title:'Block Inheritance evidence',
    detail:'Block Inheritance is mentioned. Check whether relevant links are also Enforced.'
  });
  if (/(enforced|no override)/.test(all)) out.findings.push({
    level:'info', title:'Enforced / No Override evidence',
    detail:'An enforced policy/link is mentioned; this can change normal precedence and inheritance behavior.'
  });
  if (/loopback/.test(all)) out.findings.push({
    level:'info', title:'Loopback processing evidence',
    detail:'Loopback processing is mentioned, which can change how user configuration is selected.'
  });
  if (/precedence|winning gpo|overridden|conflict|conflicting/.test(all)) out.findings.push({
    level:'warning', title:'Precedence / conflict evidence',
    detail:'The report contains explicit wording associated with policy precedence or conflicts. Review the nearby detailed lines.'
  });

  if (/denied/.test(all) && !out.computer.denied.length && !out.user.denied.length) {
    out.warnings.push('“Denied” appears in the report, but no denied GPO names were confidently parsed. This may be a formatting/version variant.');
  }

  return out;
}

function badge(kind, text) {
  const cls = kind === 'bad' ? 'bad' : kind === 'warn' ? 'warn' : 'ok';
  return `<span class="badge ${cls}">${esc(text)}</span>`;
}

function listGpos(items, denied=false) {
  if (!items.length) return '<div class="muted">None confidently identified.</div>';
  return items.map(g => `
    <div class="card compact">
      <div class="row between">
        <strong>${esc(g.name)}</strong>${badge(denied?'bad':'ok', denied?'DENIED':'APPLIED')}
      </div>
      ${g.reason ? `<div><b>Reason:</b> ${esc(g.reason)}</div>` : ''}
      ${g.details.length ? `<ul>${g.details.map(d=>`<li>${esc(d)}</li>`).join('')}</ul>` : ''}
    </div>`).join('');
}

function contextHtml(obj) {
  const entries = Object.entries(obj);
  if (!entries.length) return '<div class="muted">No explicit context fields confidently parsed.</div>';
  return `<table><tbody>${entries.map(([k,v])=>`<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('')}</tbody></table>`;
}

function scopeHtml(title, data) {
  const settings = [...new Set(data.settings)];
  return `
    <div class="card">
      <h2>${title}</h2>
      <div class="grid two">
        <div><h3>Applied GPOs</h3>${listGpos(data.applied)}</div>
        <div><h3>Denied GPOs</h3>${listGpos(data.denied,true)}</div>
      </div>
      <div class="grid two">
        <div>
          <h3>Security filtering</h3>
          ${data.filtering.length ? `<ul>${[...new Set(data.filtering)].map(x=>`<li>${esc(x)}</li>`).join('')}</ul>` : '<div class="muted">No explicit filtering line parsed.</div>'}
        </div>
        <div>
          <h3>Inheritance / context</h3>
          ${contextHtml(data.context)}
        </div>
      </div>
      <h3>Security settings / Administrative Templates / other details</h3>
      ${settings.length ? `<ul>${settings.slice(0,300).map(x=>`<li class="mono">${esc(x)}</li>`).join('')}</ul>` : '<div class="muted">No detailed settings confidently extracted.</div>'}
    </div>`;
}

export function renderGpResult(app) {
  app.innerHTML = `
    <section class="card">
      <div class="row between">
        <div>
          <h2>GPResult Analyzer</h2>
          <p class="muted">Paste <span class="mono">gpresult /r</span>, <span class="mono">gpresult /z</span>, or similar output. Parsing is entirely local.</p>
        </div>
        <span class="badge ok">LOCAL ONLY</span>
      </div>

      <div class="card">
        <label for="gp-input">GPResult output</label>
        <textarea id="gp-input" rows="18" placeholder="Paste gpresult output here…"></textarea>
        <div class="row">
          <button class="btn" type="button" id="gp-analyze">Analyze</button>
          <button class="btn secondary" type="button" id="gp-example">Load example</button>
          <button class="btn secondary" type="button" id="gp-clear">Clear</button>
        </div>
      </div>

      <div id="gp-message" class="notice hidden" role="status"></div>
      <div id="gp-results">
        <div class="card"><h2>Quick view</h2><div class="muted">Paste a GPResult report and click Analyze.</div></div>
      </div>
    </section>`;

  const $ = s => app.querySelector(s);
  const input = $('#gp-input');
  const msg = $('#gp-message');
  const results = $('#gp-results');

  const example = `Group Policy Results
Domain Name: contoso.local
Domain Controller: DC01.contoso.local
Site Name: Default-First-Site-Name

COMPUTER SETTINGS
    Applied Group Policy Objects
        Default Domain Policy
        Workstations Baseline
        Endpoint Security

    The following GPOs were not applied because they were denied
        Legacy Workstations Policy
            Reason Denied: Security Filtering
            Security Filtering: Domain Admins

    Security Settings
        Password Policy: Minimum password length = 14
        User Account Control: Enabled

USER SETTINGS
    Applied Group Policy Objects
        Default Domain Policy
        User Desktop Policy

    The following GPOs were not applied because they were denied
        Finance Drive Mapping
            Reason Denied: WMI Filter
            WMI Filter: Laptop Only

    Administrative Templates
        OneDrive: Enabled
        Control Panel\\\\Personalization: Enabled

Group Policy Inheritance
    Domain: contoso.local
    OU: OU=Workstations,DC=contoso,DC=local
    Block Inheritance: No
    Enforced: Yes`;

  function showMessage(text, kind='error') {
    msg.textContent = text || '';
    msg.className = text ? `notice ${kind}` : 'notice hidden';
  }

  function render(data) {
    const applied = data.computer.applied.length + data.user.applied.length;
    const denied = data.computer.denied.length + data.user.denied.length;
    const review = data.findings.filter(x=>x.level==='warning').length + data.warnings.length;

    const ctx = {};
    for (const [k,v] of Object.entries(data.global)) ctx[k] = v;

    results.innerHTML = `
      <div class="card">
        <h2>Quick view</h2>
        <div class="grid three">
          <div class="stat"><span>Applied GPOs</span><strong>${applied}</strong></div>
          <div class="stat"><span>Denied GPOs</span><strong>${denied}</strong></div>
          <div class="stat"><span>Review items</span><strong>${review}</strong></div>
        </div>
        <h3>Site / domain / OU context</h3>
        ${contextHtml(ctx)}
      </div>

      ${data.findings.length || data.warnings.length ? `
        <div class="card">
          <h2>Important findings</h2>
          ${data.findings.map(f=>`<div class="notice ${f.level==='warning'?'warn':'success'}"><b>${esc(f.title)}</b><br>${esc(f.detail)}</div>`).join('')}
          ${data.warnings.map(w=>`<div class="notice warn"><b>Parser warning</b><br>${esc(w)}</div>`).join('')}
        </div>` : ''}

      ${scopeHtml('Computer Configuration', data.computer)}
      ${scopeHtml('User Configuration', data.user)}

      <div class="card">
        <h2>Raw report</h2>
        <details><summary>Show original pasted text</summary><pre class="mono">${esc(data.raw)}</pre></details>
      </div>`;
  }

  $('#gp-analyze').addEventListener('click', () => {
    if (!input.value.trim()) return showMessage('Paste a GPResult report first.');
    try { render(parseGpResult(input.value)); showMessage('GPResult analyzed locally.', 'success'); }
    catch (e) { showMessage(e?.message || 'Could not analyze the report.'); }
  });

  $('#gp-example').addEventListener('click', () => {
    input.value = example;
    render(parseGpResult(input.value));
    showMessage('Example loaded and analyzed.', 'success');
  });

  $('#gp-clear').addEventListener('click', () => {
    input.value = '';
    results.innerHTML = '<div class="card"><h2>Quick view</h2><div class="muted">Paste a GPResult report and click Analyze.</div></div>';
    showMessage('');
  });
}