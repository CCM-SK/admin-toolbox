import { $, escapeHtml, downloadText, enableToolDragging } from '../utils.js';

export const metadata = {
  id: 'paloalto',
  title: 'Palo Alto Config Analyzer',
  description: 'Parse Palo Alto Networks PAN-OS configurations and security rule exports locally',
  path: '/#paloalto'
};

export function renderPaloAlto(app) {
  app.innerHTML = `
    <div class="tool-window" id="paloAltoWindow">
      <div class="tool-window-header" id="paloAltoDragHandle" title="Drag tool">
        <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
        <strong>Palo Alto Networks Config Analyzer</strong>
        <span class="small" style="margin-left:auto"></span>
      </div>
      <section class="card">
        <p class="small">
          Paste a PAN-OS configuration, <code>show</code>/<code>set</code> output,
          or a Security Policy rule export. The parser works entirely in the browser.
          No configuration data is uploaded or sent to external services.
        </p>
        <textarea id="paloAltoInput" spellcheck="false"
          placeholder="Examples:
set rulebase security rules Allow-DNS from Trust to Untrust source any destination any application dns service application-default action allow or paste a PAN-OS XML configuration export here..."></textarea>
        <div class="row" style="margin-top:10px">
          <input id="paloAltoFile" type="file"
            accept=".xml,.txt,.csv,.json,.conf,.cfg,.log" hidden>
          <button class="btn" id="paloAltoPick">Load config / export</button>
          <button class="btn primary" id="paloAltoAnalyze">Analyze</button>
          <button class="btn" id="paloAltoClear">Clear</button>
          <button class="btn" id="paloAltoExport" disabled>Export analysis JSON</button>
        </div>
        <div id="paloAltoFileInfo" class="small" style="margin-top:10px"></div>
      </section>
      <section class="card" id="paloAltoResult" hidden></section>
    </div>
  `;

  enableToolDragging(
    $('#paloAltoWindow'),
    $('#paloAltoDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );

  let lastAnalysis = null;

  $('#paloAltoPick').onclick = () => $('#paloAltoFile').click();

  $('#paloAltoFile').onchange = async e => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const text = await readLocalFile(file);
      $('#paloAltoInput').value = text;
      $('#paloAltoFileInfo').textContent =
        `Loaded ${file.name} locally (${text.length.toLocaleString()} characters).`;
    } catch (err) {
      $('#paloAltoFileInfo').textContent = '';
      showError(err.message || 'The file could not be read.');
    }
  };

  $('#paloAltoClear').onclick = () => {
    $('#paloAltoInput').value = '';
    $('#paloAltoFile').value = '';
    $('#paloAltoFileInfo').textContent = '';
    $('#paloAltoResult').hidden = true;
    $('#paloAltoResult').innerHTML = '';
    $('#paloAltoExport').disabled = true;
    lastAnalysis = null;
  };
  $('#paloAltoAnalyze').onclick = analyze;
  $('#paloAltoInput').addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyze();
  });
  $('#paloAltoExport').onclick = () => {
    if (!lastAnalysis) return;
    downloadText(
      'paloalto-config-analysis.json',
      JSON.stringify(lastAnalysis, null, 2),
      'application/json;charset=utf-8'
    );
  };

  function analyze() {
    const raw = $('#paloAltoInput').value;
    const result = $('#paloAltoResult');
    if (!raw.trim()) {
      result.hidden = false;
      result.innerHTML =
        `<div class="status warning">Paste a Palo Alto Networks configuration or rule export first.</div>`;
      return;
    }
    try {
      lastAnalysis = analyzePaloAlto(raw);
      result.hidden = false;
      result.innerHTML = renderAnalysis(lastAnalysis);
      $('#paloAltoExport').disabled = false;
    } catch (err) {
      showError(err.message || 'Palo Alto configuration parsing failed.');
    }
  }
  function showError(message) {
    const result = $('#paloAltoResult');
    result.hidden = false;
    result.innerHTML =
      `<div class="status danger">${escapeHtml(message)}</div>`;
  }
}

function analyzePaloAlto(raw) {
  const text = String(raw || '').replace(/^\uFEFF/, '');
  const format = detectFormat(text);
  let rules = [];
  let objects = [];
  let interfaces = [];
  let zones = [];
  let metadata = {};
  if (format === 'xml') {
    ({ rules, objects, interfaces, zones, metadata } = parseXmlConfig(text));
  } else if (format === 'set') {
    ({ rules, objects, interfaces, zones, metadata } = parseSetConfig(text));
  } else if (format === 'csv') {
    rules = parseRuleCsv(text);
  } else {
    ({ rules, objects, interfaces, zones, metadata } = parseTextShow(text));
  }
  const findings = analyzeRules(rules);
  const stats = buildStats(rules, findings);
  return {
    note: 'Local-only Palo Alto Networks PAN-OS configuration analysis. This tool does not contact Palo Alto, DNS, threat intelligence, or any remote service.',
    format,
    metadata,
    stats,
    rules,
    objects,
    interfaces,
    zones,
    findings,
    generatedAt: new Date().toISOString()
  };
}
function detectFormat(text) {
  const t = text.trim();
  if (/^<\?xml\b|^<config[\s>]/i.test(t) || /<security><rules>/i.test(t)) return 'xml';
  if (/^\s*set\s+(?:deviceconfig|rulebase|vsys|shared|network)\b/im.test(text)) {
    return 'set';
  }

  const firstLines = t.split(/\r?\n/).slice(0, 8);
  if (firstLines.some(x => /(?:^|,)rule(?:name)?(?:,|$)/i.test(x)) ||
      firstLines.some(x => /from,to,source,destination,application/i.test(x))) {
    return 'csv';
  }

  return 'text';
}

function parseXmlConfig(text) {
  let doc;
  try {
    doc = new DOMParser().parseFromString(text, 'application/xml');
  } catch {
    throw new Error('The browser could not parse the XML configuration.');
  }

  if (doc.querySelector('parsererror')) {
    throw new Error('The XML configuration is malformed or incomplete.');
  }

  const rules = [];
  const objects = [];
  const interfaces = [];
  const zones = [];
  const metadata = {};

  const versionNode = doc.querySelector('system > sw-version, sw-version');
  if (versionNode) metadata.panOsVersion = versionNode.textContent.trim();

  const hostname = firstXmlText(doc, [
    'hostname',
    'deviceconfig > system > hostname'
  ]);
  if (hostname) metadata.hostname = hostname;

  const ruleNodes = Array.from(
    doc.querySelectorAll(
      'security > rules > entry, security > rules > rule, ' +
      'rules > entry'
    )
  );

  for (const node of ruleNodes) {
    rules.push({
      name: attrOrChild(node, 'name') || '(unnamed rule)',
      source: 'XML',
      from: childValues(node, 'from'),
      to: childValues(node, 'to'),
      sourceAddresses: childValues(node, 'source'),
      destinationAddresses: childValues(node, 'destination'),
      applications: childValues(node, 'application'),
      services: childValues(node, 'service'),
      categories: childValues(node, 'category'),
      users: childValues(node, 'source-user'),
      action: childText(node, 'action') || 'unknown',
      disabled: childText(node, 'disabled') === 'yes',
      logStart: childText(node, 'log-start') === 'yes',
      logEnd: childText(node, 'log-end') === 'yes',
      description: childText(node, 'description') || ''
    });
  }

  const objectNodes = Array.from(
    doc.querySelectorAll(
      'address > entry, address-group > entry, ' +
      'service > entry, service-group > entry, ' +
      'application-group > entry, application-filter > entry'
    )
  );

  for (const node of objectNodes) {
    objects.push({
      name: node.getAttribute('name') || '(unnamed)',
      type: node.parentElement?.nodeName || 'object',
      value: directValue(node)
    });
  }

  const ifaceNodes = Array.from(
    doc.querySelectorAll(
      'interface > ethernet > entry, ' +
      'interface > aggregate-ethernet > entry, ' +
      'interface > vlan > entry, ' +
      'interface > loopback > entry'
    )
  );

  for (const node of ifaceNodes) {
    interfaces.push({
      name: node.getAttribute('name') || '(unnamed)',
      type: node.parentElement?.nodeName || 'interface',
      zone: firstXmlText(node, ['layer3 > interface-management-profile', 'zone']),
      ip: childValues(node, 'ip')
    });
  }

  const zoneNodes = Array.from(
    doc.querySelectorAll('zone > entry')
  );
  for (const node of zoneNodes) {
    zones.push({
      name: node.getAttribute('name') || '(unnamed)',
      mode: childText(node, 'network > layer3') ? 'layer3' :
            childText(node, 'network > layer2') ? 'layer2' : 'unknown'
    });
  }

  return { rules, objects, interfaces, zones, metadata };
}

function parseSetConfig(text) {
  const rules = [];
  const objects = [];
  const interfaces = [];
  const zones = [];
  const metadata = {};

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const tokens = tokenizeSet(line);
    if (!tokens.length || tokens[0].toLowerCase() !== 'set') continue;

    const lower = line.toLowerCase();

    if (lower.includes('rulebase security rules')) {
      const rule = parseSetRule(tokens);
      if (rule) rules.push(rule);
      continue;
    }

    if (lower.includes('deviceconfig') && lower.includes('hostname')) {
      const i = tokens.findIndex(x => x.toLowerCase() === 'hostname');
      if (i >= 0 && tokens[i + 1]) metadata.hostname = tokens[i + 1];
      continue;
    }

    if (lower.includes('address ')) {
      const idx = tokens.findIndex(x => x.toLowerCase() === 'address');
      if (idx >= 0 && tokens[idx + 1]) {
        objects.push({
          name: tokens[idx + 1],
          type: 'address',
          value: tokens.slice(idx + 2).join(' ')
        });
      }
      continue;
    }

    if (lower.includes('address-group ')) {
      const idx = tokens.findIndex(x => x.toLowerCase() === 'address-group');
      if (idx >= 0 && tokens[idx + 1]) {
        objects.push({
          name: tokens[idx + 1],
          type: 'address-group',
          value: tokens.slice(idx + 2).join(' ')
        });
      }
      continue;
    }

    if (lower.includes('network interface ')) {
      const idx = tokens.findIndex(x => x.toLowerCase() === 'interface');
      if (idx >= 0 && tokens[idx + 1]) {
        interfaces.push({
          name: tokens[idx + 1],
          type: 'interface',
          value: tokens.slice(idx + 2).join(' ')
        });
      }
    }

    if (lower.includes('network virtual-router') &&
        lower.includes('interface')) {
      const idx = tokens.findIndex(x => x.toLowerCase() === 'interface');
      if (idx >= 0 && tokens[idx + 1]) {
        interfaces.push({
          name: tokens[idx + 1],
          type: 'virtual-router interface',
          value: tokens.slice(idx + 2).join(' ')
        });
      }
    }
  }

  return {
    rules: mergeSetRules(rules),
    objects,
    interfaces,
    zones,
    metadata
  };
}

function parseSetRule(tokens) {
  const ruleIndex = tokens.findIndex(
    x => x.toLowerCase() === 'rules'
  );
  if (ruleIndex < 0 || !tokens[ruleIndex + 1]) return null;

  const name = tokens[ruleIndex + 1];
  const rest = tokens.slice(ruleIndex + 2);

  const rule = {
    name,
    source: 'set',
    from: [],
    to: [],
    sourceAddresses: [],
    destinationAddresses: [],
    applications: [],
    services: [],
    categories: [],
    users: [],
    action: 'unknown',
    disabled: false,
    logStart: false,
    logEnd: false,
    description: ''
  };

  const fields = {
    from: 'from',
    to: 'to',
    source: 'sourceAddresses',
    destination: 'destinationAddresses',
    application: 'applications',
    service: 'services',
    category: 'categories',
    'source-user': 'users'
  };

  for (let i = 0; i < rest.length; i++) {
    const key = rest[i];
    const prop = fields[key];

    if (prop) {
      const vals = [];
      i++;
      while (i < rest.length &&
             !fields[rest[i]] &&
             !['action', 'disabled', 'log-start', 'log-end', 'description']
               .includes(rest[i])) {
        vals.push(rest[i]);
        i++;
      }
      i--;
      rule[prop].push(...vals);
      continue;
    }

    if (key === 'action' && rest[i + 1]) {
      rule.action = rest[++i];
    } else if (key === 'disabled' && rest[i + 1]) {
      rule.disabled = rest[++i] === 'yes';
    } else if (key === 'log-start' && rest[i + 1]) {
      rule.logStart = rest[++i] === 'yes';
    } else if (key === 'log-end' && rest[i + 1]) {
      rule.logEnd = rest[++i] === 'yes';
    } else if (key === 'description' && rest[i + 1]) {
      rule.description = rest[++i];
    }
  }

  return rule;
}

function mergeSetRules(rules) {
  const map = new Map();

  for (const rule of rules) {
    const existing = map.get(rule.name);
    if (!existing) {
      map.set(rule.name, rule);
      continue;
    }

    for (const key of [
      'from',
      'to',
      'sourceAddresses',
      'destinationAddresses',
      'applications',
      'services',
      'categories',
      'users'
    ]) {
      existing[key] = unique([...existing[key], ...rule[key]]);
    }

    if (rule.action !== 'unknown') existing.action = rule.action;
    existing.disabled ||= rule.disabled;
    existing.logStart ||= rule.logStart;
    existing.logEnd ||= rule.logEnd;
    if (rule.description) existing.description = rule.description;
  }

  return [...map.values()];
}

function parseRuleCsv(text) {
  const rows = parseCsv(text);
  if (!rows.length) return [];

  const headers = rows[0].map(normalizeHeader);
  const rules = [];

  for (let i = 1; i < rows.length; i++) {
    const row = rows[i];
    if (!row.some(Boolean)) continue;

    const get = (...names) => {
      for (const name of names) {
        const idx = headers.indexOf(normalizeHeader(name));
        if (idx >= 0) return row[idx] || '';
      }
      return '';
    };

    rules.push({
      name: get('name', 'rule', 'rule name') || `Rule ${i}`,
      source: 'CSV',
      from: splitField(get('from', 'source zone')),
      to: splitField(get('to', 'destination zone')),
      sourceAddresses: splitField(get('source', 'source address', 'source addresses')),
      destinationAddresses: splitField(get('destination', 'destination address', 'destination addresses')),
      applications: splitField(get('application', 'applications')),
      services: splitField(get('service', 'services')),
      categories: splitField(get('category', 'categories', 'url category')),
      users: splitField(get('source-user', 'source user', 'users')),
      action: get('action') || 'unknown',
      disabled: /^(yes|true|disabled)$/i.test(get('disabled')),
      logStart: /^(yes|true)$/i.test(get('log-start')),
      logEnd: /^(yes|true)$/i.test(get('log-end')),
      description: get('description')
    });
  }

  return rules;
}

function parseTextShow(text) {
  const rules = [];
  const objects = [];
  const interfaces = [];
  const zones = [];
  const metadata = {};

  const lines = text.split(/\r?\n/);
  let currentRule = null;

  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;

    const hostname = line.match(/hostname\s*[:=]\s*(.+)$/i);
    if (hostname) metadata.hostname = hostname[1].trim();

    const ruleHeader = line.match(
      /(?:rule(?:base)?\s+security\s+rules?|security\s+rule)\s*[:=]?\s*(.+)$/i
    );

    if (ruleHeader) {
      if (currentRule) rules.push(currentRule);
      currentRule = emptyRule(ruleHeader[1].trim(), 'text');
      continue;
    }

    if (!currentRule) continue;

    const pair = line.match(/^([A-Za-z][A-Za-z _-]*)\s*[:=]\s*(.*)$/);
    if (!pair) continue;

    const key = normalizeHeader(pair[1]);
    const value = pair[2].trim();

    if (key === 'from') currentRule.from = splitField(value);
    else if (key === 'to') currentRule.to = splitField(value);
    else if (key === 'source') currentRule.sourceAddresses = splitField(value);
    else if (key === 'destination') currentRule.destinationAddresses = splitField(value);
    else if (key === 'application') currentRule.applications = splitField(value);
    else if (key === 'service') currentRule.services = splitField(value);
    else if (key === 'category') currentRule.categories = splitField(value);
    else if (key === 'source user') currentRule.users = splitField(value);
    else if (key === 'action') currentRule.action = value;
    else if (key === 'description') currentRule.description = value;
    else if (key === 'disabled') currentRule.disabled = /yes|true/i.test(value);
  }

  if (currentRule) rules.push(currentRule);

  return { rules, objects, interfaces, zones, metadata };
}

function analyzeRules(rules) {
  const findings = [];
  const shadowCandidates = [];

  for (let i = 0; i < rules.length; i++) {
    const r = rules[i];
    const name = r.name;

    if (r.disabled) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'DISABLED_RULE',
        text: 'Rule is disabled.'
      });
    }

    if (isAny(r.sourceAddresses) &&
        isAny(r.destinationAddresses) &&
        isAny(r.applications) &&
        isAny(r.services)) {
      findings.push({
        severity: 'warn',
        rule: name,
        code: 'VERY_BROAD_RULE',
        text: 'Source, destination, application and service are all effectively any. This rule can match a very large portion of traffic.'
      });
    }

    if (isAny(r.sourceAddresses)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_SOURCE',
        text: 'Source address is any.'
      });
    }

    if (isAny(r.destinationAddresses)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_DESTINATION',
        text: 'Destination address is any.'
      });
    }

    if (isAny(r.applications)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_APPLICATION',
        text: 'Application is any. Port/service matching may therefore carry more of the policy burden.'
      });
    }

    if (isAny(r.services)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_SERVICE',
        text: 'Service is any.'
      });
    }

    if (/^(allow|permit)$/i.test(r.action) &&
        isAny(r.sourceAddresses) &&
        isAny(r.destinationAddresses) &&
        isAny(r.services)) {
      findings.push({
        severity: 'warn',
        rule: name,
        code: 'BROAD_ALLOW',
        text: 'Allow rule has any source, destination and service. Review whether the scope is intentional.'
      });
    }

    if (/^(deny|drop|reject)$/i.test(r.action) &&
        isAny(r.sourceAddresses) &&
        isAny(r.destinationAddresses) &&
        isAny(r.applications) &&
        isAny(r.services)) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'CATCH_ALL_DENY',
        text: 'This looks like a catch-all deny rule, commonly used as a final policy boundary.'
      });
    }

    if (r.logStart && r.logEnd) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'LOG_START_END',
        text: 'Both session start and session end logging are enabled.'
      });
    }

    if (r.from.length && r.to.length &&
        r.from.some(x => x.toLowerCase() === 'any') &&
        r.to.some(x => x.toLowerCase() === 'any')) {
      findings.push({
        severity: 'info',
        rule: name,
        code: 'ANY_ZONES',
        text: 'Both source and destination zones are any.'
      });
    }

    shadowCandidates.push(r);
  }

  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      const a = rules[i];
      const b = rules[j];

      if (a.disabled || b.disabled) continue;
      if (!sameMatchScope(a, b)) continue;

      const aa = String(a.action).toLowerCase();
      const ba = String(b.action).toLowerCase();

      if (aa !== ba) {
        findings.push({
          severity: 'warn',
          rule: b.name,
          code: 'POTENTIAL_CONFLICT',
          text: `Rule "${b.name}" has the same parsed match scope as earlier rule "${a.name}", but a different action (${a.action} vs ${b.action}). In PAN-OS policy evaluation, rule order is therefore important.`
        });
      } else if (i < j) {
        findings.push({
          severity: 'info',
          rule: b.name,
          code: 'POTENTIAL_SHADOW',
          text: `Rule "${b.name}" appears to duplicate the parsed match scope of earlier rule "${a.name}".`
        });
      }
    }
  }

  if (rules.length) {
    const last = rules[rules.length - 1];
    if (/^(allow|permit)$/i.test(last.action) &&
        isAny(last.sourceAddresses) &&
        isAny(last.destinationAddresses)) {
      findings.push({
        severity: 'warn',
        rule: last.name,
        code: 'FINAL_BROAD_ALLOW',
        text: 'The final parsed rule is a broad allow. Verify that this is intentional; later policy entries cannot restrict traffic already matched by an earlier rule.'
      });
    }
  }

  return findings;
}

function sameMatchScope(a, b) {
  const keys = [
    'from',
    'to',
    'sourceAddresses',
    'destinationAddresses',
    'applications',
    'services',
    'categories',
    'users'
  ];

  return keys.every(k => setEqual(a[k], b[k]));
}

function buildStats(rules, findings) {
  return {
    totalRules: rules.length,
    enabledRules: rules.filter(r => !r.disabled).length,
    disabledRules: rules.filter(r => r.disabled).length,
    allowRules: rules.filter(r => /^(allow|permit)$/i.test(r.action)).length,
    denyRules: rules.filter(r => /^(deny|drop|reject)$/i.test(r.action)).length,
    unknownActions: rules.filter(r => !/^(allow|permit|deny|drop|reject)$/i.test(r.action)).length,
    warnings: findings.filter(f => f.severity === 'warn').length,
    info: findings.filter(f => f.severity === 'info').length
  };
}

function renderAnalysis(a) {
  const s = a.stats;

  const overall =
    s.warnings
      ? `<div class="status warning"><strong>${s.warnings} review item(s) found</strong><br>
         The analyzer found potentially broad, conflicting, duplicate, or otherwise noteworthy policy constructs.
         These are local heuristics, not a definitive security verdict.</div>`
      : `<div class="status success"><strong>No high-level policy warning was detected.</strong><br>
         This does not prove the configuration is secure; it means the local rule heuristics found no matching warning patterns.</div>`;

  const statCards = [
    ['Rules', s.totalRules],
    ['Enabled', s.enabledRules],
    ['Disabled', s.disabledRules],
    ['Allow', s.allowRules],
    ['Deny', s.denyRules],
    ['Warnings', s.warnings]
  ].map(([label, value]) =>
    `<div class="stat"><span>${escapeHtml(label)}</span><strong>${escapeHtml(String(value))}</strong></div>`
  ).join('');

  const findings = a.findings.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Details</th></tr></thead>
        <tbody>
          ${a.findings.map(f => `
            <tr>
              <td><strong>${escapeHtml(f.severity.toUpperCase())}</strong></td>
              <td>${escapeHtml(f.rule || '')}</td>
              <td><code>${escapeHtml(f.code)}</code></td>
              <td>${escapeHtml(f.text)}</td>
            </tr>`).join('')}
        </tbody>
      </table></div>`
    : `<div class="status success">No heuristic findings.</div>`;

  const rules = a.rules.length
    ? `<div class="table-wrap"><table>
        <thead><tr>
          <th>#</th><th>Rule</th><th>From</th><th>To</th>
          <th>Source</th><th>Destination</th><th>Application</th>
          <th>Service</th><th>Action</th>
        </tr></thead>
        <tbody>
          ${a.rules.map((r, i) => `
            <tr>
              <td>${i + 1}</td>
              <td><strong>${escapeHtml(r.name)}</strong>${r.disabled ? '<br><span class="small">disabled</span>' : ''}</td>
              <td>${list(r.from)}</td>
              <td>${list(r.to)}</td>
              <td>${list(r.sourceAddresses)}</td>
              <td>${list(r.destinationAddresses)}</td>
              <td>${list(r.applications)}</td>
              <td>${list(r.services)}</td>
              <td><strong>${escapeHtml(r.action)}</strong></td>
            </tr>`).join('')}
        </tbody>
      </table></div>`
    : `<div class="status warning">No security rules were recognized in this input.</div>`;

  const objects = a.objects.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Type</th><th>Value</th></tr></thead>
        <tbody>${a.objects.map(o =>
          `<tr><td>${escapeHtml(o.name)}</td><td>${escapeHtml(o.type)}</td><td class="mono">${escapeHtml(o.value || '')}</td></tr>`
        ).join('')}</tbody>
      </table></div>`
    : `<p class="small">No address/service objects were recognized.</p>`;

  const interfaces = a.interfaces.length
    ? `<div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Type</th><th>Details</th></tr></thead>
        <tbody>${a.interfaces.map(x =>
          `<tr><td>${escapeHtml(x.name)}</td><td>${escapeHtml(x.type)}</td><td>${escapeHtml(x.value || x.ip?.join(', ') || '')}</td></tr>`
        ).join('')}</tbody>
      </table></div>`
    : `<p class="small">No interfaces were recognized.</p>`;

  return `
    ${overall}

    <h3>Configuration overview</h3>
    <div class="grid">${statCards}</div>

    <p class="small">
      Detected format: <strong>${escapeHtml(a.format.toUpperCase())}</strong>
      ${a.metadata.hostname ? ` · Hostname: <strong>${escapeHtml(a.metadata.hostname)}</strong>` : ''}
      ${a.metadata.panOsVersion ? ` · PAN-OS: <strong>${escapeHtml(a.metadata.panOsVersion)}</strong>` : ''}
    </p>

    <h3>Rule analysis</h3>
    ${findings}

    <h3>Effective rule view</h3>
    <p class="small">
      Rules are displayed in input order. PAN-OS security policy evaluation is order-dependent:
      an earlier matching rule can prevent a later rule from being reached. The analyzer highlights obvious broad/duplicate/conflicting scopes but does not emulate the complete PAN-OS policy engine.
    </p>
    ${rules}

    <h3>Objects</h3>
    ${objects}

    <h3>Interfaces</h3>
    ${interfaces}

    <h3>Analysis limitations</h3>
    <ul class="small">
      <li>No DNS, URL filtering, threat-intelligence, WildFire, or cloud lookup is performed.</li>
      <li>Object groups are parsed where recognizable, but nested object resolution is intentionally conservative.</li>
      <li>Address, service, application, zone and user semantics are reported from the supplied data; unresolved references are not guessed.</li>
      <li>Potential conflicts and shadowing are heuristic. Full PAN-OS behavior can also depend on device groups, pre/post rules, shared policy, NAT/security policy interaction, profiles, tags and other configuration layers.</li>
    </ul>
  `;
}

function emptyRule(name, source) {
  return {
    name,
    source,
    from: [],
    to: [],
    sourceAddresses: [],
    destinationAddresses: [],
    applications: [],
    services: [],
    categories: [],
    users: [],
    action: 'unknown',
    disabled: false,
    logStart: false,
    logEnd: false,
    description: ''
  };
}

function childValues(node, name) {
  const parent = Array.from(node.children).find(
    x => x.tagName.toLowerCase() === name.toLowerCase()
  );
  if (!parent) return [];

  return Array.from(parent.children)
    .map(x => (x.textContent || '').trim())
    .filter(Boolean);
}

function childText(node, selector) {
  const found = node.querySelector(`:scope > ${selector}`);
  return found ? found.textContent.trim() : '';
}

function attrOrChild(node, name) {
  return node.getAttribute(name) || childText(node, name);
}

function firstXmlText(doc, selectors) {
  for (const selector of selectors) {
    const n = doc.querySelector(selector);
    if (n?.textContent?.trim()) return n.textContent.trim();
  }
  return '';
}

function directValue(node) {
  const parts = [];
  for (const child of node.children) {
    const text = child.textContent?.trim();
    if (text) parts.push(`${child.tagName}=${text}`);
  }
  return parts.join('; ');
}

function tokenizeSet(line) {
  const out = [];
  const re = /"((?:\\.|[^"])*)"|'((?:\\.|[^'])*)'|(\S+)/g;
  let m;
  while ((m = re.exec(line))) {
    const value = m[1] ?? m[2] ?? m[3];
    out.push(value.replace(/\\(["'])/g, '$1'));
  }
  return out;
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];

    if (c === '"') {
      if (quoted && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else {
        quoted = !quoted;
      }
    } else if (c === ',' && !quoted) {
      row.push(cell);
      cell = '';
    } else if ((c === '\n' || c === '\r') && !quoted) {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else {
      cell += c;
    }
  }

  if (cell || row.length) {
    row.push(cell);
    rows.push(row);
  }

  return rows;
}

function normalizeHeader(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ');
}

function splitField(value) {
  if (!value) return [];
  return String(value)
    .split(/[;,|]/)
    .map(x => x.trim())
    .filter(Boolean);
}

function list(values) {
  const v = values?.length ? values : ['any'];
  return v.map(x => `<code>${escapeHtml(x)}</code>`).join(' ');
}

function isAny(values) {
  return !values?.length ||
    values.some(v => ['any', 'all', '*'].includes(String(v).trim().toLowerCase()));
}

function unique(values) {
  return [...new Set(values)];
}

function setEqual(a, b) {
  const x = new Set((a || []).map(v => String(v).toLowerCase()));
  const y = new Set((b || []).map(v => String(v).toLowerCase()));
  if (x.size !== y.size) return false;
  for (const v of x) if (!y.has(v)) return false;
  return true;
}

async function readLocalFile(file) {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);

  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    try {
      return new TextDecoder('windows-1252').decode(bytes);
    } catch {
      return new TextDecoder().decode(bytes);
    }
  }
}