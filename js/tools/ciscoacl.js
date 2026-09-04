const esc = v => String(v ?? '')
  .replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

const ipToNum = ip => {
  const p = String(ip).split('.');
  if (p.length !== 4 || p.some(x => !/^\d+$/.test(x) || +x > 255)) return null;
  return p.reduce((n, x) => ((n * 256) + +x) >>> 0, 0) >>> 0;
};

function cidrContains(cidr, ip) {
  const [addr, prefixText] = String(cidr).split('/');
  const a = ipToNum(addr), b = ipToNum(ip), prefix = Number(prefixText);
  if (a == null || b == null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

function normalizeName(s) {
  return String(s).trim().toLowerCase();
}

function tokenise(line) {
  return line.trim().split(/\s+/);
}

function parseNetworkObject(tokens) {
  const idx = tokens.indexOf('network-object');
  if (idx < 0) return null;
  const rest = tokens.slice(idx + 1);
  if (!rest.length) return null;
  if (rest[0].toLowerCase() === 'host' && rest[1]) return {
    kind:'host', value:rest[1], text:`host ${rest[1]}`
  };
  if (rest[0].toLowerCase() === 'object' && rest[1]) return {
    kind:'object', value:rest[1], text:`object ${rest[1]}`
  };
  if (rest.length >= 2 && ipToNum(rest[0]) != null && ipToNum(rest[1]) != null) {
    const mask = rest[1].split('.').map(Number);
    let prefix = 0;
    for (const oct of mask) {
      let x = oct;
      for (let i=0;i<8;i++){ prefix += (x & 0x80) ? 1 : 0; x = (x << 1) & 0xFF; }
    }
    return { kind:'subnet', value:`${rest[0]}/${prefix}`, text:`${rest[0]} ${rest[1]}` };
  }
  return { kind:'raw', value:rest.join(' '), text:rest.join(' ') };
}

function parseServiceObject(tokens) {
  const idx = tokens.indexOf('service-object');
  if (idx < 0) return null;
  const rest = tokens.slice(idx + 1);
  if (!rest.length) return null;

  if (/^(tcp|udp|tcp-udp)$/i.test(rest[0])) {
    if (rest[1]) return { kind:'proto', value:rest.join(' '), text:rest.join(' ') };
  }
  if (/^(icmp|ip|gre|esp|ah|igmp)$/i.test(rest[0])) {
    return { kind:'proto', value:rest.join(' '), text:rest.join(' ') };
  }
  return { kind:'raw', value:rest.join(' '), text:rest.join(' ') };
}

function parseObjectGroup(lines, i) {
  const header = lines[i].trim();
  const m = header.match(/^object-group\s+(network|service|protocol)\s+(\S+)/i);
  if (!m) return null;

  const group = {
    type: m[1].toLowerCase(),
    name: m[2],
    members: [],
    line: i + 1
  };

  for (let j = i + 1; j < lines.length; j++) {
    const t = lines[j].trim();
    if (!t) continue;
    if (/^object-group\s+/i.test(t) || /^(?:access-list|object\s+|class-map|policy-map|interface|name)\b/i.test(t)) break;
    if (/^group-object\s+(\S+)/i.test(t)) {
      group.members.push({ kind:'group', value:RegExp.$1, text:`group-object ${RegExp.$1}` });
      continue;
    }

    if (group.type === 'network') {
      const n = parseNetworkObject(tokenise(t));
      if (n) group.members.push(n);
    } else if (group.type === 'service') {
      const s = parseServiceObject(tokenise(t));
      if (s) group.members.push(s);
    } else {
      group.members.push({ kind:'raw', value:t, text:t });
    }
  }
  return group;
}

function parseAcl(line, lineNo) {
  const t = line.trim();
  const m = t.match(/^access-list\s+(\S+)\s+(?:extended\s+)?(permit|deny)\s+(.+)$/i);
  if (!m) return null;

  const acl = m[1];
  const action = m[2].toLowerCase();
  const rest = m[3].trim();
  const tokens = tokenise(rest);
  let i = 0;

  const rule = {
    acl, action, line: lineNo, raw: t,
    protocol: null, source: null, sourcePort: null,
    destination: null, destinationPort: null,
    options: [], remark: null
  };

  const next = () => tokens[i++] || null;

  rule.protocol = next();

  function parseEndpoint() {
    const first = next();
    if (!first) return null;

    const lower = first.toLowerCase();
    if (lower === 'any') return { type:'any', value:'any' };
    if (lower === 'host') {
      const ip = next(); return ip ? { type:'host', value:ip } : { type:'raw', value:'host' };
    }
    if (lower === 'object') {
      const name = next(); return name ? { type:'object', value:name } : { type:'raw', value:'object' };
    }
    if (lower === 'object-group') {
      const name = next(); return name ? { type:'object-group', value:name } : { type:'raw', value:'object-group' };
    }
    if (ipToNum(first) != null) {
      const mask = next();
      if (mask && ipToNum(mask) != null) return { type:'subnet', value:`${first}/${mask}` };
      if (mask) i--;
      return { type:'host-or-ip', value:first };
    }
    return { type:'literal', value:first };
  }

  rule.source = parseEndpoint();

  if (['tcp','udp','tcp-udp'].includes(String(rule.protocol).toLowerCase())) {
    const p = tokens[i]?.toLowerCase();
    if (p && ['eq','neq','lt','gt','range'].includes(p)) {
      rule.sourcePort = { op: next(), value: p === 'range' ? `${next()} ${next()}` : next() };
    }
  }

  rule.destination = parseEndpoint();

  if (['tcp','udp','tcp-udp'].includes(String(rule.protocol).toLowerCase())) {
    const p = tokens[i]?.toLowerCase();
    if (p && ['eq','neq','lt','gt','range'].includes(p)) {
      rule.destinationPort = { op: next(), value: p === 'range' ? `${next()} ${next()}` : next() };
    }
  }

  rule.options = tokens.slice(i);
  return rule;
}

function parseConfig(text) {
  const raw = String(text ?? '').replace(/\r\n?/g, '\n');
  const lines = raw.split('\n');
  const objectGroups = {};
  const rules = [];
  const remarks = [];
  const globals = [];

  for (let i=0;i<lines.length;i++) {
    const t = lines[i].trim();
    if (!t || t.startsWith('!')) continue;

    const og = parseObjectGroup(lines, i);
    if (og) {
      objectGroups[normalizeName(og.name)] = og;
      continue;
    }

    let m = t.match(/^access-list\s+(\S+)\s+remark\s+(.+)$/i);
    if (m) {
      remarks.push({ acl:m[1], text:m[2], line:i+1 });
      continue;
    }

    const acl = parseAcl(t, i+1);
    if (acl) {
      rules.push(acl);
      continue;
    }

    if (/^(?:access-group|access-group\s)/i.test(t) ||
        /^(?:same-security-traffic|sysopt|object\b|name\b|nat\b|route\b)/i.test(t)) {
      globals.push({ line:i+1, text:t });
    }
  }

  return { raw, lines, objectGroups, rules, remarks, globals };
}

function expandMembers(name, groups, seen = new Set()) {
  const key = normalizeName(name);
  if (seen.has(key)) return [{ type:'cycle', value:name }];
  const g = groups[key];
  if (!g) return [{ type:'unresolved-group', value:name }];

  seen.add(key);
  const out = [];
  for (const member of g.members) {
    if (member.kind === 'group') out.push(...expandMembers(member.value, groups, new Set(seen)));
    else if (member.kind === 'object') out.push(...expandMembers(member.value, groups, new Set(seen)));
    else out.push(member);
  }
  return out;
}

function endpointText(ep, groups) {
  if (!ep) return '—';
  if (ep.type === 'object-group') {
    const members = expandMembers(ep.value, groups);
    if (members.some(x=>x.type === 'unresolved-group' || x.type === 'cycle')) {
      return `object-group ${ep.value}`;
    }
    if (!members.length) return `object-group ${ep.value} (empty)`;
    return members.map(x=>x.text || x.value).join(', ');
  }
  if (ep.type === 'object') {
    const vals = expandMembers(ep.value, groups);
    if (vals.length && !vals.some(x=>x.type === 'unresolved-group' || x.type === 'cycle')) {
      return vals.map(x=>x.text || x.value).join(', ');
    }
  }
  return ep.value;
}

const serviceMeaning = s => {
  if (!s) return 'any service/port';
  if (s.op === 'eq') return `port ${s.value}`;
  if (s.op === 'range') return `ports ${s.value}`;
  return `${s.op} ${s.value}`;
};

function ruleMeaning(r, groups) {
  const proto = r.protocol?.toLowerCase();
  const protoText = proto === 'ip' ? 'IP traffic' : `${r.protocol || 'unknown protocol'} traffic`;
  const src = endpointText(r.source, groups);
  const dst = endpointText(r.destination, groups);
  let text = `${r.action.toUpperCase()} ${protoText} from ${src} to ${dst}`;
  if (r.sourcePort) text += ` (source ${serviceMeaning(r.sourcePort)})`;
  if (r.destinationPort) text += ` (destination ${serviceMeaning(r.destinationPort)})`;
  if (r.options.length) text += ` [${r.options.join(' ')}]`;
  return text;
};

function endpointBroad(ep) {
  return ep?.type === 'any' || !ep;
}

function endpointsOverlap(a, b) {
  if (endpointBroad(a) || endpointBroad(b)) return true;
  if (a.type === 'object-group' || b.type === 'object-group') return true; // conservative without full tuple expansion
  if (a.type === 'object' || b.type === 'object') return true;
  if (a.type === 'host' && b.type === 'host') return a.value === b.value;
  if (a.type === 'host' && b.type === 'subnet') return cidrContains(b.value, a.value);
  if (b.type === 'host' && a.type === 'subnet') return cidrContains(a.value, b.value);
  if (a.type === 'subnet' && b.type === 'subnet') {
    return cidrContains(a.value, b.value.split('/')[0]) || cidrContains(b.value, a.value.split('/')[0]);
  }
  if (a.type === 'host-or-ip' && b.type === 'host-or-ip') return a.value === b.value;
  return true;
}

function servicesOverlap(a, b) {
  if (!a || !b) return true;
  if (a.op !== b.op) return true;
  if (a.op === 'eq') return a.value === b.value;
  if (a.op === 'range') return true;
  return true;
}

function analyze(data) {
  const findings = [];
  const aclMap = {};

  for (const r of data.rules) {
    (aclMap[r.acl] ||= []).push(r);
    const broad = endpointBroad(r.source) && endpointBroad(r.destination);
    if (broad && r.action === 'permit') {
      findings.push({
        level: 'high', line:r.line, acl:r.acl,
        title:'Very broad permit',
        detail:'This rule permits traffic from any source to any destination for the specified protocol/service. Review whether this scope is intentional.'
      });
    }

    if (r.protocol?.toLowerCase() === 'ip' && broad && r.action === 'permit') {
      findings.push({
        level:'high', line:r.line, acl:r.acl,
        title:'Permit any/any IP traffic',
        detail:'Effectively permits all IP traffic represented by the protocol match.'
      });
    }

    if (r.source?.type === 'any' && r.destination?.type === 'any' &&
        ['tcp','udp','tcp-udp'].includes(r.protocol?.toLowerCase()) &&
        !r.destinationPort && r.action === 'permit') {
      findings.push({
        level:'high', line:r.line, acl:r.acl,
        title:'Any-to-any protocol permit without destination port',
        detail:'The rule permits the protocol between any source and destination without a destination service restriction.'
      });
    }

    for (const opt of r.options) {
      if (/log/i.test(opt)) break;
      if (/established/i.test(opt)) {
        findings.push({
          level:'info', line:r.line, acl:r.acl,
          title:'State/established qualifier',
          detail:'This rule contains an established-state-related qualifier; exact semantics depend on the platform and version.'
        });
        break;
      }
    }
  }

  // Shadow / overlap analysis within each ACL, preserving first-match semantics.
  for (const [acl, rules] of Object.entries(aclMap)) {
    for (let i=0;i<rules.length;i++) {
      const later = rules[i];
      for (let j=0;j<i;j++) {
        const earlier = rules[j];
        if (earlier.action === 'deny' && later.action === 'permit' &&
            String(earlier.protocol).toLowerCase() === String(later.protocol).toLowerCase() &&
            endpointsOverlap(earlier.source, later.source) &&
            endpointsOverlap(earlier.destination, later.destination) &&
            servicesOverlap(earlier.destinationPort, later.destinationPort)) {
          findings.push({
            level:'high', line:later.line, acl,
            title:'Potentially shadowed permit',
            detail:`An earlier deny on line ${earlier.line} overlaps this rule. Because ACLs are first-match, some or all traffic matching this permit may never reach it.`
          });
          break;
        }
      }

      for (let j=0;j<i;j++) {
        const earlier = rules[j];
        if (earlier.action !== later.action &&
            earlier.action === 'permit' &&
            later.action === 'deny' &&
            String(earlier.protocol).toLowerCase() === String(later.protocol).toLowerCase() &&
            endpointsOverlap(earlier.source, later.source) &&
            endpointsOverlap(earlier.destination, later.destination) &&
            servicesOverlap(earlier.destinationPort, later.destinationPort)) {
          findings.push({
            level:'warning', line:later.line, acl,
            title:'Potentially unreachable deny',
            detail:`An earlier permit on line ${earlier.line} overlaps this deny. Because ACLs are first-match, portions of this deny may never be reached.`
          });
          break;
        }
      }
    }
  }

  for (const [name, group] of Object.entries(data.objectGroups)) {
    if (!group.members.length) {
      findings.push({
        level:'warning', line:group.line,
        title:'Empty object-group',
        detail:`${group.name} is defined but contains no parsed members.`
      });
    }
    for (const member of group.members) {
      if (member.kind === 'group' && !data.objectGroups[normalizeName(member.value)]) {
        findings.push({
          level:'warning', line:group.line,
          title:'Unresolved group reference',
          detail:`${group.name} references object-group ${member.value}, which was not found in the pasted text.`
        });
      }
    }
  }

  return findings;
}

function levelBadge(level) {
  if (level === 'high') return '<span class="badge bad">HIGH</span>';
  if (level === 'warning') return '<span class="badge warn">REVIEW</span>';
  return '<span class="badge ok">INFO</span>';
}

function renderRule(r, groups) {
  return `
    <div class="card compact">
      <div class="row between">
        <div>
          <strong>Line ${r.line} · ${esc(r.acl)}</strong>
          ${levelBadge(r.action === 'deny' ? 'info' : 'ok')}
        </div>
        <span class="mono">${esc(r.action.toUpperCase())}</span>
      </div>
      <div><b>Effect:</b> ${esc(ruleMeaning(r, groups))}</div>
      <details>
        <summary>Parsed fields</summary>
        <table><tbody>
          <tr><th>Protocol</th><td>${esc(r.protocol || '—')}</td></tr>
          <tr><th>Source</th><td>${esc(endpointText(r.source, groups))}</td></tr>
          <tr><th>Source port</th><td>${esc(r.sourcePort ? serviceMeaning(r.sourcePort) : 'Any')}</td></tr>
          <tr><th>Destination</th><td>${esc(endpointText(r.destination, groups))}</td></tr>
          <tr><th>Destination port</th><td>${esc(r.destinationPort ? serviceMeaning(r.destinationPort) : 'Any')}</td></tr>
          <tr><th>Options</th><td class="mono">${esc(r.options.join(' ') || '—')}</td></tr>
          <tr><th>Original</th><td class="mono">${esc(r.raw)}</td></tr>
        </tbody></table>
      </details>
    </div>`;
}

export function renderCiscoFirewall(app) {
  app.innerHTML = `
    <section class="card">
      <div class="row between">
        <div>
          <h2>Cisco Firewall Rule Analyzer</h2>
          <p class="small">Paste Cisco ASA / ASA-like ACL and object-group configuration. The tool explains rule meaning locally and highlights likely policy problems.</p>
        </div>
        <span class="badge ok"></span>
      </div>

      <div class="card">
        <label for="cisco-fw-input">Cisco configuration / ACL output</label>
        <textarea id="cisco-fw-input" rows="20"
          placeholder="Paste access-list, object-group, object, and related policy lines here…"></textarea>
        <div class="row">
          <button class="btn primary" type="button" id="cisco-fw-analyze">Analyze</button>
          <button class="btn secondary" type="button" id="cisco-fw-example">Load example</button>
          <button class="btn secondary" type="button" id="cisco-fw-clear">Clear</button>
        </div>
      </div>

      <div id="cisco-fw-message" class="notice hidden" role="status"></div>
      <div id="cisco-fw-results">
        <div class="card"><h2>Quick view</h2><div class="muted">Paste configuration and click Analyze.</div></div>
      </div>
    </section>`;

  const $ = s => app.querySelector(s);
  const input = $('#cisco-fw-input');
  const results = $('#cisco-fw-results');
  const message = $('#cisco-fw-message');

  const example = `object-group network WEB_SERVERS
 network-object host 10.20.10.10
 network-object host 10.20.10.11

object-group service HTTPS tcp-udp
 port-object eq https
 port-object eq 443

access-list OUTSIDE_IN extended permit tcp any object-group WEB_SERVERS eq 443 log
access-list OUTSIDE_IN extended deny ip any any
access-list DMZ_IN extended permit ip object-group WEB_SERVERS 10.30.0.0 255.255.255.0
access-list DMZ_IN extended deny tcp any host 10.30.20.10 eq 22
access-list DMZ_IN extended permit tcp any host 10.30.20.10 eq 443
`;

  function showMessage(text, kind='error') {
    message.textContent = text || '';
    message.className = text ? `notice ${kind}` : 'notice hidden';
  }

  function render(data) {
    const findings = analyze(data);
    const high = findings.filter(x=>x.level==='high').length;
    const review = findings.filter(x=>x.level==='warning').length;
    const aclNames = [...new Set(data.rules.map(r=>r.acl))];

    results.innerHTML = `
      <div class="card">
        <h2>Quick view</h2>
        <div class="grid four">
          <div class="stat"><span>ACL rules</span><strong>${data.rules.length}</strong></div>
          <div class="stat"><span>ACLs</span><strong>${aclNames.length}</strong></div>
          <div class="stat"><span>Object-groups</span><strong>${Object.keys(data.objectGroups).length}</strong></div>
          <div class="stat"><span>High-risk findings</span><strong>${high}</strong></div>
        </div>
        <div class="muted" style="margin-top:.75rem">
          Analysis is based only on the pasted text. It does not know interface direction, NAT behavior,
          routing, inspection policy, VPN policy, identity rules, or platform-version-specific semantics unless those are included in the pasted configuration.
        </div>
      </div>

      ${findings.length ? `
        <div class="card">
          <h2>Findings</h2>
          ${findings.map(f=>`
            <div class="notice ${f.level==='high'?'bad':f.level==='warning'?'warn':'success'}">
              ${levelBadge(f.level)}
              <b>${esc(f.title)}</b>
              ${f.acl ? ` <span class="mono">${esc(f.acl)}</span>` : ''}
              ${f.line ? ` <span class="mono">line ${f.line}</span>` : ''}
              <br>${esc(f.detail)}
            </div>`).join('')}
        </div>` : `
        <div class="notice success">
          No obvious problems were found by the local heuristics.
        </div>`}

      <div class="card">
        <h2>Effective rule meaning</h2>
        ${aclNames.map(acl => `
          <h3>${esc(acl)}</h3>
          ${data.rules.filter(r=>r.acl===acl).map(r=>renderRule(r, data.objectGroups)).join('') || '<div class="muted">No parsed rules.</div>'}
        `).join('')}
      </div>

      <div class="card">
        <h2>Object-groups</h2>
        ${Object.values(data.objectGroups).length
          ? Object.values(data.objectGroups).map(g=>`
            <div class="card compact">
              <div class="row between"><strong>${esc(g.name)}</strong><span class="badge ok">${esc(g.type)}</span></div>
              <ul>${g.members.length ? g.members.map(m=>`<li class="mono">${esc(m.text || m.value)}</li>`).join('') : '<li>Empty / not parsed</li>'}</ul>
            </div>`).join('')
          : '<div class="muted">No object-groups parsed.</div>'}
      </div>

      <div class="card">
        <h2>Remarks</h2>
        ${data.remarks.length
          ? `<ul>${data.remarks.map(r=>`<li><b>${esc(r.acl)}</b> line ${r.line}: ${esc(r.text)}</li>`).join('')}</ul>`
          : '<div class="muted">No ACL remarks parsed.</div>'}
      </div>

      <div class="card">
        <h2>Unparsed / other configuration lines</h2>
        ${data.globals.length
          ? `<ul>${data.globals.map(x=>`<li class="mono">line ${x.line}: ${esc(x.text)}</li>`).join('')}</ul>`
          : '<div class="muted">None recognized.</div>'}
      </div>

      <div class="card">
        <h2>Raw configuration</h2>
        <details><summary>Show original pasted text</summary><pre class="mono">${esc(data.raw)}</pre></details>
      </div>`;
  }

  $('#cisco-fw-analyze').addEventListener('click', () => {
    if (!input.value.trim()) return showMessage('Paste Cisco firewall configuration first.');
    try {
      render(parseConfig(input.value));
      showMessage('Cisco firewall configuration analyzed locally.', 'success');
    } catch (e) {
      showMessage(e?.message || 'Could not analyze the configuration.');
    }
  });

  $('#cisco-fw-example').addEventListener('click', () => {
    input.value = example;
    render(parseConfig(input.value));
    showMessage('Example configuration loaded and analyzed.', 'success');
  });

  $('#cisco-fw-clear').addEventListener('click', () => {
    input.value = '';
    results.innerHTML = '<div class="card"><h2>Quick view</h2><div class="muted">Paste configuration and click Analyze.</div></div>';
    showMessage('');
  });
}