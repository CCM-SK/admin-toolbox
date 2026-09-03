const esc = v => String(v ?? '')
  .replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

function parseGpResult(text) {
  const raw = String(text ?? '').replace(/\r\n?/g, '\n');
  const lines = raw.split('\n');
  const out = {
    raw,
    computer: {
      applied: [], denied: [], filtering: [], securityGroups: [],
      settings: [], context: {}, clues: []
    },
    user: {
      applied: [], denied: [], filtering: [], securityGroups: [],
      settings: [], context: {}, clues: []
    },
    global: {},
    findings: [],
    warnings: []
  };

  let scope = null;
  let mode = null;
  let current = null;

  const target = () => scope ? out[scope] : null;
  const pushUnique = (arr, v) => { if (v && !arr.includes(v)) arr.push(v); };

  const addGpo = (kind, name) => {
    const t = target();
    if (!t || !name) return null;
    const arr = t[kind];
    const existing = arr.find(x => x.name.toLowerCase() === name.toLowerCase());
    if (existing) {
      current = existing;
      return existing;
    }
    const item = { name: name.trim(), reason: '', details: [] };
    arr.push(item);
    current = item;
    return item;
  };

  function sectionFromLine(t) {
    if (/^(COMPUTER|COMPUTERSETTINGS|COMPUTER-EINSTELLUNGEN)\b/i.test(t)) return 'computer';
    if (/^(USER|BENUTZER|BENUTZEREINSTELLUNGEN)\b/i.test(t)) return 'user';
    if (/^COMPUTER\s+(?:SETTINGS|CONFIGURATION|POLICY)\b/i.test(t)) return 'computer';
    if (/^USER\s+(?:SETTINGS|CONFIGURATION|POLICY)\b/i.test(t)) return 'user';
    return null;
  }

  function isAppliedHeader(t) {
    return /^(?:APPLIED GROUP POLICY OBJECTS|APPLIED GPOs?)\b/i.test(t) ||
           /^ANGEWENDETE GRUPPENRICHTLINIENOBJEKTE\b/i.test(t);
  }

  function isDeniedHeader(t) {
    return /^(?:DENIED GROUP POLICY OBJECTS|DENIED GPOs?)\b/i.test(t) ||
           /^THE FOLLOWING GPOs? WERE NOT APPLIED\b/i.test(t) ||
           /^FOLGENDE HERAUSGEFILTERTE GRUPPENRICHTLINIEN WERDEN NICHT ANGEWENDET\b/i.test(t);
  }

  function isSecurityGroupsHeader(t) {
    return /^(?:THE USER IS A MEMBER OF THE FOLLOWING SECURITY GROUPS|USER IS A MEMBER OF THE FOLLOWING SECURITY GROUPS)\b/i.test(t) ||
           /^DER BENUTZER IST MITGLIED DER FOLGENDEN SICHERHEITSGRUPPEN\b/i.test(t) ||
           /^DER COMPUTER IST MITGLIED DER FOLGENDEN SICHERHEITSGRUPPEN\b/i.test(t);
  }

  function isSettingsHeader(t) {
    return /^(?:SECURITY SETTINGS|ADMINISTRATIVE TEMPLATES|WINDOWS SETTINGS|FOLDER REDIRECTION|SCRIPTS|SOFTWARE SETTINGS|PRINTERS|REGISTRY)\b/i.test(t) ||
           /^(?:SICHERHEITSEINSTELLUNGEN|ADMINISTRATIVE VORLAGEN|WINDOWS-EINSTELLUNGEN|ORDNERUMLEITUNG|SKRIPTE|SOFTWAREEINSTELLUNGEN|DRUCKER|REGISTRIERUNG)\b/i.test(t);
  }

  for (const original of lines) {
    const line = original.replace(/\uFEFF/g, '');
    const t = line.trim();
    if (!t) continue;

    // Main localized scope headings.
    const detectedScope = sectionFromLine(t);
    if (detectedScope) {
      scope = detectedScope;
      mode = null;
      current = null;
      continue;
    }

    let m;

    // Global / localized context fields.
    const contextPatterns = [
      [/^Site Name\s*:\s*(.+)$/i, 'site'],
      [/^Standortname\s*:\s*(.+)$/i, 'site'],
      [/^Domain Name\s*:\s*(.+)$/i, 'domain'],
      [/^Domänenname\s*:\s*(.+)$/i, 'domain'],
      [/^Domain Controller\s*:\s*(.+)$/i, 'domainController'],
      [/^Gruppenrichtlinieanwendung von\s*:\s*(.+)$/i, 'domainController'],
      [/^(?:Organizational Unit|OU)\s*:\s*(.+)$/i, 'ou'],
      [/^(?:Computer Name|Host Name|Host)\s*:\s*(.+)$/i, 'computer'],
      [/^(?:Computername|Computer)\s*:\s*(.+)$/i, 'computer'],
      [/^User(?: Name)?\s*:\s*(.+)$/i, 'user'],
      [/^Benutzer(?:name)?\s*:\s*(.+)$/i, 'user'],
      [/^Forest Name\s*:\s*(.+)$/i, 'forest'],
      [/^Domänentyp\s*:\s*(.+)$/i, 'domainType'],
      [/^Betriebssystemversion\s*:\s*(.+)$/i, 'osVersion'],
      [/^Betriebssystemkonfiguration\s*:\s*(.+)$/i, 'osConfig'],
      [/^Roamingprofil\s*:\s*(.+)$/i, 'roamingProfile'],
      [/^Lokales Profil\s*:\s*(.+)$/i, 'localProfile'],
      [/^Langsame Verbindung\?\s*(.+)$/i, 'slowLink'],
      [/^Schwellenwert für langsame Verbindung\s*:\s*(.+)$/i, 'slowLinkThreshold'],
      [/^Letzte Gruppenrichtlinienanwendung\s*:\s*(.+)$/i, 'lastPolicyApplication']
    ];
    for (const [rx, key] of contextPatterns) {
      m = t.match(rx);
      if (m) { out.global[key] = m[1].trim(); continue; }
    }

    if (isAppliedHeader(t)) {
      mode = 'applied';
      current = null;
      continue;
    }

    if (isDeniedHeader(t)) {
      mode = 'denied';
      current = null;
      continue;
    }

    if (isSecurityGroupsHeader(t)) {
      mode = 'securityGroups';
      current = null;
      continue;
    }

    if (/^(?:Group Policy Inheritance|Inheritance)\b/i.test(t) ||
        /^Gruppenrichtlinienvererbung\b/i.test(t)) {
      mode = 'context';
      current = null;
      continue;
    }

    if (isSettingsHeader(t)) {
      mode = 'settings';
      current = null;
      continue;
    }

    // If a denied section is active, these explanations belong to the preceding GPO.
    m = t.match(/^(?:Reason Denied|Denied Reason|Reason for denial|Reason)\s*:\s*(.+)$/i);
    if (m && current) {
      current.reason = m[1].trim();
      continue;
    }

    m = t.match(/^Filterung\s*:\s*(.+)$/i);
    if (m && target()) {
      target().filtering.push(m[1].trim());
      if (current) current.details.push(`Filtering: ${m[1].trim()}`);
      continue;
    }

    m = t.match(/^Security Filtering\s*:\s*(.+)$/i);
    if (m && target()) {
      target().filtering.push(m[1].trim());
      if (current) current.details.push(`Security Filtering: ${m[1].trim()}`);
      continue;
    }

    // Explicit German "Verweigert (Sicherheit)" / "Nicht angewendet (Leer)" etc.
    if (/^(?:Filterung|Filtering)\s*:/i.test(t) && target()) {
      const val = t.replace(/^(?:Filterung|Filtering)\s*:\s*/i, '').trim();
      target().filtering.push(val);
      if (current) current.details.push(`Filtering: ${val}`);
      continue;
    }

    m = t.match(/^WMI Filter\s*:\s*(.+)$/i);
    if (m && target()) {
      target().settings.push(`WMI Filter: ${m[1].trim()}`);
      if (current) current.details.push(`WMI Filter: ${m[1].trim()}`);
      continue;
    }

    // German GPO denial explanation: "Filterung: Verweigert (Sicherheit)"
    // Also tolerate localized "Nicht angewendet".
    if (current && /^(?:Verweigert|Nicht angewendet|Abgelehnt|Gesperrt|Denied|Not Applied)/i.test(t)) {
      current.reason = t;
      current.details.push(t);
      continue;
    }

    // Context / inheritance details, both languages.
    m = t.match(/^(?:Site|Domain|OU|Organizational Unit|Group Policy Inheritance|Inheritance|Link|Linked|Block Inheritance|Enforced|No Override)\s*:\s*(.+)$/i);
    if (!m) {
      m = t.match(/^(?:Standort|Domäne|Organisationseinheit|Gruppenrichtlinienvererbung|Vererbung|Verknüpfung|Verknüpft|Vererbung blockieren|Erzwingen|Keine Überschreibung)\s*:\s*(.+)$/i);
    }
    if (m && target()) {
      const key = t.split(':')[0].trim();
      target().context[key] = m[1].trim();
      if (/inherit|vererb|enforced|erzwing|override|überschreib|link|verknüpf/i.test(key)) {
        target().clues.push(t);
      }
      continue;
    }

    // Security groups are usually one item per indented line. Avoid treating
    // headings and obvious key/value lines as groups.
    if (scope && mode === 'securityGroups') {
      if (!t.includes(':') && !/^-+$/.test(t) && t.length < 260) {
        target().securityGroups.push(t);
      }
      continue;
    }

    // Settings.
    if (scope && mode === 'settings') {
      if (t.length < 320) target().settings.push(t);
      continue;
    }

    // Applied/denied GPO names. Handle arbitrary indentation and non-colon lines.
    if (scope && (mode === 'applied' || mode === 'denied') && !t.includes(':')) {
      if (!/^[-=]+$/.test(t) &&
          !/^(?:Computer|User|Benutzer|Benutzereinstellungen|Computereinstellungen|The following|Folgende|Group Policy|Gruppenrichtlinien|Security|Sicherheit|Filtering|Filterung|Reason|Grund|Site|Standort|Domain|Domäne|OU|Organisationseinheit)/i.test(t) &&
          t.length < 250) {
        addGpo(mode, t);
        continue;
      }
    }

    // Capture common /z key-value policy detail.
    if (scope) {
      const kv = t.match(/^([^:]{1,120}):\s*(.{1,260})$/);
      if (kv && mode === 'settings') {
        target().settings.push(`${kv[1].trim()}: ${kv[2].trim()}`);
      }
    }
  }

  const lower = raw.toLowerCase();

  // Global findings.
  if (/security filtering|sicherheitsfilterung|filterung:\s*verweigert\s*\(sicherheit\)/i.test(raw)) {
    out.findings.push({
      level:'info',
      title:'Security filtering evidence',
      detail:'The report contains security-filtering evidence. A GPO may be outside scope when the computer/user is not included in the required security principals.'
    });
  }

  if (/wmi filter/i.test(raw)) {
    out.findings.push({
      level:'info',
      title:'WMI filtering evidence',
      detail:'A WMI filter is mentioned. A false WMI filter result can prevent a GPO from applying.'
    });
  }

  if (/block inheritance|vererbung blockieren/i.test(raw)) {
    out.findings.push({
      level:'warning',
      title:'Block Inheritance evidence',
      detail:'Block Inheritance is mentioned. Check whether the relevant GPO link is also Enforced.'
    });
  }

  if (/enforced|no override|erzwingen|keine überschreibung/i.test(raw)) {
    out.findings.push({
      level:'info',
      title:'Enforced / No Override evidence',
      detail:'An enforced / no-override relationship is mentioned; this can affect normal precedence and inheritance.'
    });
  }

  if (/loopback|schleifenverarbeitung/i.test(raw)) {
    out.findings.push({
      level:'info',
      title:'Loopback processing evidence',
      detail:'Loopback processing is mentioned, which can change how user policy is selected.'
    });
  }

  if (/precedence|winning gpo|overridden|override|conflict|conflicting|präzedenz|vorrang|konflikt|überschrieben/i.test(raw)) {
    out.findings.push({
      level:'warning',
      title:'Precedence / conflict evidence',
      detail:'The report contains wording associated with policy precedence or conflicts. Review the detailed report lines.'
    });
  }

  const totalDenied = out.computer.denied.length + out.user.denied.length;
  if (/denied|nicht angewendet|herausgefilterte gruppenrichtlinien|verweigert/i.test(lower) && totalDenied === 0) {
    out.warnings.push('The report contains denial/not-applied wording, but no denied GPO names were confidently parsed. This may be a formatting/version/localization variant.');
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
  const groups = [...new Set(data.securityGroups)];
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
      ${groups.length ? `
        <h3>Security groups (${groups.length})</h3>
        <div class="mono">${groups.map(x=>esc(x)).join('<br>')}</div>
      ` : ''}
    </div>`;
}

export function renderGpResult(app) {
  app.innerHTML = `
    <section class="card">
      <div class="row between">
        <div>
          <h2>GPResult Analyzer</h2>
          <p class="small">Paste <span class="mono">gpresult /r</span>, <span class="mono">gpresult /z</span>, or localized output. Parsing is entirely local.</p>
        </div>
        <span class="badge ok"></span>
      </div>

      <div class="card">
        <label for="gp-input">GPResult output</label>
        <textarea id="gp-input" rows="20" placeholder="Paste gpresult output here…"></textarea>
        <div class="row">
          <button class="btn primary" type="button" id="gp-analyze">Analyze</button>
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

  function showMessage(text, kind='error') {
    msg.textContent = text || '';
    msg.className = text ? `notice ${kind}` : 'notice hidden';
  }

  function render(data) {
    const applied = data.computer.applied.length + data.user.applied.length;
    const denied = data.computer.denied.length + data.user.denied.length;
    const review = data.findings.filter(x=>x.level==='warning').length + data.warnings.length;

    results.innerHTML = `
      <div class="card">
        <h2>Quick view</h2>
        <div class="grid three">
          <div class="stat"><span>Applied GPOs</span><strong>${applied}</strong></div>
          <div class="stat"><span>Denied GPOs</span><strong>${denied}</strong></div>
          <div class="stat"><span>Review items</span><strong>${review}</strong></div>
        </div>
        <h3>Scope / context</h3>
        ${contextHtml(data.global)}
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
    try {
      render(parseGpResult(input.value));
      showMessage('GPResult analyzed locally.', 'success');
    } catch (e) {
      showMessage(e?.message || 'Could not analyze the report.');
    }
  });

  $('#gp-clear').addEventListener('click', () => {
    input.value = '';
    results.innerHTML = '<div class="card"><h2>Quick view</h2><div class="muted">Paste a GPResult report and click Analyze.</div></div>';
    showMessage('');
  });
}