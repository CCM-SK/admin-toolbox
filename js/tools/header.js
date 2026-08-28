import { $, escapeHtml, downloadText } from '../utils.js';

export const metadata = {
  id: 'mail-header',
  title: 'Mail-Header analyzer',
  description: 'Analyze message headers locally',
  path: '/#header'
};

export function renderHeader(app) {
app.innerHTML = `
  <section class="card">
    <h2>E-mail message header analyzer</h2>
    <p class="small">
      Paste complete message headers or load an <code>.eml</code> or Outlook <code>.msg</code> file.
      Authentication results are read locally. No DNS, reputation, URL, or external-service lookups are performed.
    </p>
    <textarea
      id="mailHeaders"
      spellcheck="false"
      placeholder="Authentication-Results: mx.example; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com\nReceived-SPF: pass (receiver: domain of sender@example.com designates 203.0.113.10 as permitted sender)\nDKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; ...\nFrom: Sender <sender@example.com>\nTo: recipient@example.net\nSubject: Example\nDate: Thu, 20 Aug 2026 14:00:00 +0000\nMessage-ID: <...>\nReceived: from ..."
    ></textarea>
    <div class="row mail-header-actions">
      <input
        id="mailHeaderFile"
        type="file"
        accept=".eml,.msg,.txt,.log,message/rfc822"
        hidden
      >
      <button class="btn" id="mailHeaderPick">Load .eml / .msg file</button>
      <button class="btn primary" id="mailHeaderAnalyze">Analyze</button>
      <button class="btn" id="mailHeaderClear">Clear</button>
    </div>

    <div id="mailHeaderFileInfo" class="small mail-header-file-info"></div>
  </section>
  <section class="card" id="mailHeaderResult" hidden></section>
`;

  $('#mailHeaderPick').onclick = () => $('#mailHeaderFile').click();
  $('#mailHeaderFile').onchange = async e => {
    const f = e.target.files?.[0];
    if (!f) return;
    try {
      const info = $('#mailHeaderFileInfo');
      info.textContent = `Reading ${f.name} locally…`;
      const lower = f.name.toLowerCase();
      if (lower.endsWith('.msg')) {
        const msg = await parseMsgFile(f);
        $('#mailHeaders').value = msg.headers || buildSyntheticHeaders(msg.properties);
        info.textContent = msg.note;
      } else {
        const raw = await readLocalTextFile(f);
        $('#mailHeaders').value = extractEmlHeaders(raw);
        info.textContent = `Loaded ${f.name} locally. The RFC header section was extracted in the browser.`;
      }
    } catch (err) {
      $('#mailHeaderFileInfo').textContent = '';
      const result = $('#mailHeaderResult');
      result.hidden = false;
      result.innerHTML = `<div class="status danger">${escapeHtml(err.message || 'The message file could not be read.')}</div>`;
    }
  };
  $('#mailHeaderClear').onclick = () => {
    $('#mailHeaders').value = '';
    $('#mailHeaderResult').hidden = true;
    $('#mailHeaderResult').innerHTML = '';
    $('#mailHeaderFileInfo').textContent = '';
    $('#mailHeaderFile').value = '';
  };
  $('#mailHeaderAnalyze').onclick = analyze;
  $('#mailHeaders').addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyze();
  });

  function analyze() {
    const raw = $('#mailHeaders').value;
    const result = $('#mailHeaderResult');
    if (!raw.trim()) {
      result.hidden = false;
      result.innerHTML = `<div class="status warning">Paste message headers first.</div>`;
      return;
    }
    try {
      const headers = parseHeaders(raw);
      const analysis = analyzeHeaders(headers);
      result.hidden = false;
      result.innerHTML = renderResult(analysis, raw);
      bindExports(analysis, raw);
    } catch (e) {
      result.hidden = false;
      result.innerHTML = `<div class="status danger">${escapeHtml(e.message || 'Header parsing failed.')}</div>`;
    }
  }
}

function parseHeaders(raw) {
  const headerPart = raw.replace(/^\uFEFF/, '').split(/\r?\n\r?\n/, 1)[0];
  const physical = headerPart.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const unfolded = [];
  for (const line of physical) {
    if (/^[ \t]/.test(line)) {
      if (!unfolded.length) continue;
      unfolded[unfolded.length - 1] += ' ' + line.trim();
    } else if (line.trim() === '') {
      continue;
    } else {
      unfolded.push(line);
    }
  }
  const out = [];
  for (const line of unfolded) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const name = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    out.push({ name, value, originalName: line.slice(0, idx).trim() });
  }
  if (!out.length) throw new Error('No RFC-style message headers were found.');
  return out;
}

function values(headers, name) {
  return headers.filter(h => h.name === name).map(h => h.value);
}
function first(headers, name) {
  return values(headers, name)[0] || '';
}
function last(headers, name) {
  const vs = values(headers, name);
  return vs[vs.length - 1] || '';
}
function hasToken(value, token) {
  return new RegExp(`(?:^|[;\\s])${escapeRegExp(token)}(?:[=;\\s]|$)`, 'i').test(value);
}
function escapeRegExp(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function parseAuthResults(headers) {
  const ars = values(headers, 'authentication-results');
  const out = { records: [], spf: [], dkim: [], dmarc: [], arc: [], compauth: [] };
  for (const raw of ars) {
    const clean = raw.replace(/[\r\n]+/g, ' ');
    const authserv = clean.split(/[;\s]/, 1)[0] || '';
    const record = { raw, authserv, spf: [], dkim: [], dmarc: [], arc: [], compauth: [] };
    const re = /(?:^|[;\s])([a-z][a-z0-9_-]*)=([a-z][a-z0-9_-]*)(?=\s|;|$)([^;]*)/gi;
    let m;
    while ((m = re.exec(clean))) {
      const mechanism = m[1].toLowerCase();
      const result = m[2].toLowerCase();
      const params = (m[3] || '').trim();
      const item = { mechanism, result, params };
      if (mechanism === 'spf') record.spf.push(item);
      else if (mechanism === 'dkim') record.dkim.push(item);
      else if (mechanism === 'dmarc') record.dmarc.push(item);
      else if (mechanism === 'arc') record.arc.push(item);
      else if (mechanism === 'compauth') record.compauth.push(item);
    }
    out.records.push(record);
    out.spf.push(...record.spf);
    out.dkim.push(...record.dkim);
    out.dmarc.push(...record.dmarc);
    out.arc.push(...record.arc);
    out.compauth.push(...record.compauth);
  }
  return out;
}

function parseReceivedSpf(headers) {
  return values(headers, 'received-spf').map(raw => {
    const firstWord = raw.trim().split(/[\s(]/)[0].toLowerCase();
    const props = {};
    for (const m of raw.matchAll(/([a-z][a-z0-9_-]*)=([^\s;,)]+)/gi)) props[m[1].toLowerCase()] = m[2].replace(/^['"]|['"]$/g, '');
    return { result: firstWord, props, raw };
  });
}

function parseAuthSignature(headers, name) {
  return values(headers, name).map(raw => {
    const fields = {};
    for (const m of raw.matchAll(/(^|;)\s*([a-z][a-z0-9_-]*)\s*=\s*([^;]*)/gi)) {
      fields[m[2].toLowerCase()] = m[3].trim();
    }
    return { fields, raw };
  });
}

function parseAddressHeader(value) {
  const match = value.match(/^(.*?)\s*<([^<>\s]+)>\s*$/);
  const address = (match ? match[2] : value).trim();
  const name = match ? match[1].replace(/^"|"$/g, '').trim() : '';
  const at = address.lastIndexOf('@');
  return { name, address, domain: at > -1 ? address.slice(at + 1).toLowerCase() : '' };
}

function parseDomainFromAuth(items) {
  const domains = [];
  for (const item of items) {
    const m = item.params.match(/(?:^|\s)(?:header\.d|smtp\.mailfrom|smtp\.helo|header\.from)=([^\s;]+)/i);
    if (m) domains.push(m[1].toLowerCase());
  }
  return domains;
}

function resultState(value, options = {}) {
  const v = String(value || '').toLowerCase();
  if (v === 'pass' || v === 'valid' || v === 'bestguesspass') return 'good';
  if (v === 'fail' || v === 'hardfail' || v === 'invalid') return 'bad';
  if (v === 'softfail' || v === 'neutral' || v === 'temperror' || v === 'permerror') return 'warn';
  return options.empty ? 'neutral' : 'unknown';
}

function analyzeHeaders(headers) {
  const auth = parseAuthResults(headers);
  const receivedSpf = parseReceivedSpf(headers);
  const dkimSigs = parseAuthSignature(headers, 'dkim-signature');
  const arcSigs = parseAuthSignature(headers, 'arc-seal');
  const from = parseAddressHeader(first(headers, 'from'));
  const returnPath = parseAddressHeader(first(headers, 'return-path'));
  const replyTo = parseAddressHeader(first(headers, 'reply-to'));
  const subject = first(headers, 'subject');
  const messageId = first(headers, 'message-id');
  const date = first(headers, 'date');
  const received = values(headers, 'received');
  const replyMismatch = !!(replyTo.domain && from.domain && replyTo.domain !== from.domain);

  const spfItem = auth.spf.find(x => x.result) || (receivedSpf[0] && { result: receivedSpf[0].result, params: receivedSpf[0].raw });
  const dkimItem = auth.dkim.find(x => x.result);
  const dmarcItem = auth.dmarc.find(x => x.result);
  const arcItem = auth.arc.find(x => x.result);
  const compauthItem = auth.compauth.find(x => x.result);

  const dmarcDomain = dmarcItem ? parseDomainFromAuth([dmarcItem])[0] : '';
  const dkimDomains = parseDomainFromAuth(auth.dkim);
  const spfDomains = parseDomainFromAuth(auth.spf);

  const checks = [
    makeAuthCheck('SPF', spfItem?.result, spfItem ? 'Authentication-Results / Received-SPF' : 'No SPF result found', spfDomains[0] || ''),
    makeAuthCheck('DKIM', dkimItem?.result, dkimItem ? 'Authentication-Results' : (dkimSigs.length ? 'DKIM-Signature present, but no DKIM= result was found' : 'No DKIM result or signature found'), dkimDomains[0] || dkimSigs[0]?.fields?.d || ''),
    makeAuthCheck('DMARC', dmarcItem?.result, dmarcItem ? 'Authentication-Results' : 'No DMARC result found', dmarcDomain || from.domain),
    makeAuthCheck('ARC', arcItem?.result, arcItem ? 'Authentication-Results' : (arcSigs.length ? 'ARC-Seal present, but no ARC= result was found' : 'ARC is optional and was not reported'), '')
  ];
  if (compauthItem) checks.push(makeAuthCheck('CompAuth', compauthItem.result, 'Authentication-Results', ''));

  const alignment = deriveAlignment(from.domain, dmarcDomain, dkimDomains, spfDomains, dmarcItem?.result);
  checks.push(alignment);

  const anomalies = [];
  if (!from.address) anomalies.push({ level: 'bad', text: 'No From header was found.' });
  if (!date) anomalies.push({ level: 'warn', text: 'No Date header was found.' });
  if (!messageId) anomalies.push({ level: 'warn', text: 'No Message-ID header was found.' });
  if (replyMismatch) anomalies.push({ level: 'warn', text: `Reply-To domain (${replyTo.domain}) differs from From domain (${from.domain}). This is not automatically malicious, but it deserves attention.` });
  if (received.length === 0) anomalies.push({ level: 'warn', text: 'No Received headers were found. A normal Internet-delivered message usually has at least one.' });
  if (headers.filter(h => h.name === 'return-path').length > 1) anomalies.push({ level: 'warn', text: 'Multiple Return-Path headers were present.' });

  const summary = summarize(checks, anomalies);
  return {
    checks,
    summary,
    headers,
    auth,
    receivedSpf,
    dkimSigs,
    arcSigs,
    from,
    returnPath,
    replyTo,
    subject,
    date,
    messageId,
    received,
    anomalies,
    counts: {
      totalHeaders: headers.length,
      uniqueNames: new Set(headers.map(h => h.name)).size,
      received: received.length,
      authResults: values(headers, 'authentication-results').length,
      dkimSignatures: dkimSigs.length,
      arcSeals: arcSigs.length
    }
  };
}

function makeAuthCheck(label, value, source, detail) {
  const state = resultState(value, { empty: true });
  const normalized = value ? String(value).toLowerCase() : '';
  let explanation = source;
  if (normalized === 'pass') explanation = `${source}${detail ? ` · ${detail}` : ''}`;
  else if (!value) explanation = source;
  else explanation = `${source} · reported ${normalized}`;
  return { label, state, value: normalized || 'not found', explanation };
}

function deriveAlignment(fromDomain, dmarcDomain, dkimDomains, spfDomains, dmarcResult) {
  if (!fromDomain || !dmarcResult) return { label: 'DMARC alignment', state: 'neutral', value: 'not established', explanation: 'Requires a DMARC result plus domain information to interpret alignment.' };
  const fromD = fromDomain.toLowerCase();
  const dmarcD = (dmarcDomain || '').toLowerCase();
  const dkimAligned = dkimDomains.some(d => relaxedDomainMatch(fromD, d));
  const spfAligned = spfDomains.some(d => relaxedDomainMatch(fromD, d));
  if (dmarcResult.toLowerCase() === 'pass' && (dkimAligned || spfAligned)) {
    return { label: 'DMARC alignment', state: 'good', value: 'aligned', explanation: `From=${fromD}; ${dkimAligned ? 'DKIM' : 'SPF'} domain is aligned.` };
  }
  if (dmarcResult.toLowerCase() === 'pass') return { label: 'DMARC alignment', state: 'good', value: 'pass reported', explanation: 'DMARC passed at the sending receiver. Header data available here did not independently establish which aligned identifier supplied the pass.' };
  return { label: 'DMARC alignment', state: resultState(dmarcResult), value: dmarcResult.toLowerCase(), explanation: `From=${fromD}${dmarcD ? `; DMARC domain=${dmarcD}` : ''}` };
}

function relaxedDomainMatch(a, b) {
  const x = String(a || '').toLowerCase().replace(/\.$/, '');
  const y = String(b || '').toLowerCase().replace(/\.$/, '');
  return !!x && !!y && (x === y || x.endsWith('.' + y) || y.endsWith('.' + x));
}

function summarize(checks, anomalies) {
  const authChecks = checks.slice(0, 4);
  const good = authChecks.filter(x => x.state === 'good').length;
  const bad = authChecks.filter(x => x.state === 'bad').length;
  const warn = authChecks.filter(x => x.state === 'warn').length;
  let state = 'neutral';
  let title = 'Insufficient authentication evidence';
  let text = 'The headers do not contain enough positive authentication results to call the message well-authenticated.';
  if (bad > 0) {
    state = 'bad';
    title = 'Authentication warning';
    text = 'At least one reported authentication mechanism failed. Treat the message with caution and inspect the details below.';
  } else if (good >= 3 && warn === 0) {
    state = 'good';
    title = 'Strong authentication signals';
    text = 'SPF, DKIM and DMARC/related authentication results are positive in the headers. This is a good signal, not proof that the message is safe.';
  } else if (good >= 2 && bad === 0) {
    state = 'good';
    title = 'Good authentication signals';
    text = 'Multiple authentication mechanisms report success. Review the remaining warnings and identity details.';
  } else if (warn > 0 || anomalies.some(a => a.level === 'warn')) {
    state = 'warn';
    title = 'Mixed or incomplete signals';
    text = 'The headers contain useful signals, but some are missing, neutral, or deserve attention.';
  }
  return { state, title, text, good, bad, warn };
}

function stateLabel(state) {
  return state === 'good' ? 'GOOD' : state === 'bad' ? 'FAIL' : state === 'warn' ? 'CHECK' : 'N/A';
}
function statusClass(state) {
  return state === 'good' ? 'success' : state === 'bad' ? 'danger' : state === 'warn' ? 'warning' : '';
}

function statusIcon(state) {
  return state === 'good' ? '&#10003;' : state === 'bad' ? '&#10007;' : state === 'warn' ? '&#9888;' : '&#8212;';
}

function renderResult(a, raw) {
  const s = a.summary;
  const summaryHtml = `<div class="status ${statusClass(s.state)}"><strong><span aria-hidden="true" style="font-size:1.15em;margin-right:6px">${statusIcon(s.state)}</span>${escapeHtml(s.title)}</strong><br><span>${escapeHtml(s.text)}</span></div>`;
  const cards = a.checks.map(c => `
    <div class="stat">
      <span>${escapeHtml(c.label)}</span>
      <strong><span aria-hidden="true" style="margin-right:6px">${statusIcon(c.state)}</span>${escapeHtml(c.value.toUpperCase())}</strong>
      <div class="small">${escapeHtml(c.explanation)}</div>
    </div>`).join('');

  const identity = `
    <div class="grid">
      ${stat('From', a.from.address || 'Not found')}
      ${stat('Return-Path', a.returnPath.address || 'Not found')}
      ${stat('Reply-To', a.replyTo.address || 'Not found')}
      ${stat('Subject', a.subject || 'Not found')}
      ${stat('Date', a.date || 'Not found')}
      ${stat('Message-ID', a.messageId || 'Not found')}
    </div>`;

  const authRows = [
    ...a.auth.records.flatMap((r, i) => [
      ...r.spf.map(x => ['SPF', x.result, x.params, `Authentication-Results #${i + 1}`]),
      ...r.dkim.map(x => ['DKIM', x.result, x.params, `Authentication-Results #${i + 1}`]),
      ...r.dmarc.map(x => ['DMARC', x.result, x.params, `Authentication-Results #${i + 1}`]),
      ...r.arc.map(x => ['ARC', x.result, x.params, `Authentication-Results #${i + 1}`]),
      ...r.compauth.map(x => ['CompAuth', x.result, x.params, `Authentication-Results #${i + 1}`])
    ]),
    ...a.receivedSpf.map(x => ['Received-SPF', x.result, x.raw, 'Received-SPF header'])
  ];

  const receivedRows = a.received.map((v, i) => `<tr><td>${i + 1}</td><td class="mono">${escapeHtml(v)}</td></tr>`).join('');
  const allHeaderRows = a.headers.map((h, i) => `<tr><td>${i + 1}</td><td>${escapeHtml(h.originalName)}</td><td class="mono">${escapeHtml(h.value)}</td></tr>`).join('');
  const authTable = authRows.length ? `
    <div class="table-wrap"><table><thead><tr><th>Mechanism</th><th>Result</th><th>Details</th><th>Source</th></tr></thead><tbody>
      ${authRows.map(r => `<tr><td>${escapeHtml(r[0])}</td><td><strong>${escapeHtml(r[1])}</strong></td><td class="mono">${escapeHtml(r[2])}</td><td>${escapeHtml(r[3])}</td></tr>`).join('')}
    </tbody></table></div>` : `<div class="status warning">No SPF/DKIM/DMARC/ARC authentication result records were found.</div>`;

  const anomalyHtml = a.anomalies.length
    ? `<ul>${a.anomalies.map(x => `<li><strong>${escapeHtml(x.level.toUpperCase())}</strong> — ${escapeHtml(x.text)}</li>`).join('')}</ul>`
    : `<div class="status success">No basic header anomalies were detected by this local heuristic pass.</div>`;

  const providerNotes = [
    ...a.dkimSigs.map((x, i) => `DKIM-Signature #${i + 1}: ${Object.entries(x.fields).map(([k, v]) => `${k}=${v}`).join('; ')}`),
    ...a.arcSigs.map((x, i) => `ARC-Seal #${i + 1}: ${Object.entries(x.fields).map(([k, v]) => `${k}=${v}`).join('; ')}`)
  ];

  const exportPayload = sanitizeExport(a, raw);
  const packed = encodeURIComponent(JSON.stringify(exportPayload));

  return `${summaryHtml}
    <h3>Authentication at a glance</h3>
    <div class="grid">${cards}</div>

    <div class="result-actions">
      <button class="btn" id="mailExportJson">Export analysis JSON</button>
      <button class="btn" id="mailExportText">Export summary TXT</button>
    </div>

    <h3>Message identity</h3>
    ${identity}

    <h3>Authentication details</h3>
    ${authTable}

    <h3>Received path</h3>
    <p class="small">Received headers are shown in the order they appeared in the pasted message. Reading mail flow from newest to oldest requires interpreting this chain in context.</p>
    ${a.received.length ? `<div class="table-wrap"><table><thead><tr><th>#</th><th>Received</th></tr></thead><tbody>${receivedRows}</tbody></table></div>` : '<div class="status warning">No Received headers found.</div>'}

    <h3>Additional checks</h3>
    ${anomalyHtml}

    <h3>DKIM / ARC signature metadata</h3>
    ${providerNotes.length ? `<div class="table-wrap"><table><thead><tr><th>Entry</th></tr></thead><tbody>${providerNotes.map(x => `<tr><td class="mono">${escapeHtml(x)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="small">No DKIM-Signature or ARC-Seal metadata was found.</p>'}

    <h3>All headers</h3>
    <div class="table-wrap"><table><thead><tr><th>#</th><th>Header</th><th>Value</th></tr></thead><tbody>${allHeaderRows}</tbody></table></div>

    <details style="margin-top:14px"><summary>What the green checks mean</summary>
      <p class="small">Green means the header contains a positive or otherwise favorable result from the sending/receiving infrastructure. It does <strong>not</strong> mean the message itself is trustworthy. SPF, DKIM and DMARC can all pass for malicious mail sent from an authorized or compromised service.</p>
    </details>
  `;
}

function stat(label, value) {
  return `<div class="stat"><span>${escapeHtml(label)}</span><strong style="word-break:break-word">${escapeHtml(value)}</strong></div>`;
}

function sanitizeExport(a, raw) {
  return {
    note: 'Local header analysis only; no DNS, reputation, URL, or remote validation was performed.',
    summary: a.summary,
    checks: a.checks,
    identity: {
      from: a.from,
      returnPath: a.returnPath,
      replyTo: a.replyTo,
      subject: a.subject,
      date: a.date,
      messageId: a.messageId
    },
    counts: a.counts,
    anomalies: a.anomalies,
    authentication: a.auth,
    receivedSpf: a.receivedSpf,
    received: a.received,
    headers: a.headers
  };
}

function bindExports(a, raw) {
  $('#mailExportJson').onclick = () => downloadText('email-header-analysis.json', JSON.stringify(sanitizeExport(a, raw), null, 2), 'application/json;charset=utf-8');
  $('#mailExportText').onclick = () => {
    const lines = [
      `Summary: ${a.summary.title}`,
      a.summary.text,
      '',
      ...a.checks.map(c => `${c.label}: ${c.value} — ${c.explanation}`),
      '',
      `From: ${a.from.address || 'Not found'}`,
      `Return-Path: ${a.returnPath.address || 'Not found'}`,
      `Reply-To: ${a.replyTo.address || 'Not found'}`,
      `Subject: ${a.subject || 'Not found'}`,
      `Date: ${a.date || 'Not found'}`,
      `Message-ID: ${a.messageId || 'Not found'}`,
      '',
      'Warnings / notes:',
      ...(a.anomalies.length ? a.anomalies.map(x => `- ${x.level.toUpperCase()}: ${x.text}`) : ['- None detected by the local heuristic pass.']),
      '',
      'Authentication results:',
      ...a.auth.records.map((r, i) => `- Authentication-Results #${i + 1}: ${r.raw}`)
    ];
    downloadText('email-header-analysis.txt', lines.join('\n'), 'text/plain;charset=utf-8');
  };
}

async function readLocalTextFile(file) {
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return new TextDecoder('utf-16le').decode(bytes);
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return new TextDecoder('windows-1252').decode(bytes);
  }
}

function extractEmlHeaders(raw) {
  const text = String(raw || '').replace(/^\uFEFF/, '');
  const m = text.search(/\r?\n\r?\n/);
  return m >= 0 ? text.slice(0, m) : text;
}

async function parseMsgFile(file) {
  const buffer = await file.arrayBuffer();
  const cfb = parseCompoundFile(buffer);
  const props = extractMsgStringProperties(cfb.streams);
  const headers = props['007d'] || '';

  const properties = {
    subject: props['0037'] || '',
    senderName: props['0c1a'] || '',
    senderEmail: props['0c1f'] || '',
    displayTo: props['0e04'] || '',
    displayCc: props['0e03'] || '',
    displayBcc: props['0e02'] || '',
    replyTo: props['0050'] || '',
    messageId: props['1035'] || ''
  };

  if (headers) {
    return {
      headers: extractEmlHeaders(headers),
      properties,
      note: `Loaded ${file.name} locally. PR_TRANSPORT_MESSAGE_HEADERS was extracted from the Outlook MSG container.`
    };
  }

  return {
    headers: buildSyntheticHeaders(properties),
    properties,
    note: `Loaded ${file.name} locally. The MSG did not expose Internet transport headers, so only common MAPI identity fields could be shown. SPF/DKIM/DMARC results cannot be inferred from those fields.`
  };
}

function buildSyntheticHeaders(p) {
  const lines = [];
  if (p.subject) lines.push(`Subject: ${p.subject}`);
  if (p.senderEmail || p.senderName) lines.push(`From: ${p.senderName ? p.senderName + ' ' : ''}${p.senderEmail ? `<${p.senderEmail}>` : ''}`.trim());
  if (p.displayTo) lines.push(`To: ${p.displayTo}`);
  if (p.displayCc) lines.push(`Cc: ${p.displayCc}`);
  if (p.displayBcc) lines.push(`Bcc: ${p.displayBcc}`);
  if (p.replyTo) lines.push(`Reply-To: ${p.replyTo}`);
  if (p.messageId) lines.push(`Message-ID: ${p.messageId}`);
  return lines.join('\n');
}

function parseCompoundFile(buffer) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  const sig = [0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1];
  for (let i = 0; i < sig.length; i++) {
    if (bytes[i] !== sig[i]) throw new Error('The selected file is not a valid Outlook .msg / Compound File.');
  }

  const sectorShift = view.getUint16(30, true);
  const miniSectorShift = view.getUint16(32, true);
  const sectorSize = 1 << sectorShift;
  const miniSectorSize = 1 << miniSectorShift;
  const firstDirSector = view.getInt32(48, true);
  const miniCutoff = view.getUint32(56, true);
  const firstMiniFatSector = view.getInt32(60, true);
  const numMiniFatSectors = view.getUint32(64, true);
  const firstDifatSector = view.getInt32(68, true);
  const numDifatSectors = view.getUint32(72, true);

  const fatSectors = [];
  for (let i = 0; i < 109; i++) {
    const sid = view.getInt32(76 + i * 4, true);
    if (sid >= 0) fatSectors.push(sid);
  }
  let difat = firstDifatSector;
  for (let n = 0; n < numDifatSectors && difat >= 0; n++) {
    const base = 512 + difat * sectorSize;
    for (let i = 0; i < (sectorSize / 4) - 1; i++) {
      const sid = view.getInt32(base + i * 4, true);
      if (sid >= 0) fatSectors.push(sid);
    }
    difat = view.getInt32(base + sectorSize - 4, true);
  }

  const fat = [];
  for (const sid of fatSectors) {
    const base = 512 + sid * sectorSize;
    for (let i = 0; i < sectorSize / 4; i++) fat.push(view.getInt32(base + i * 4, true));
  }

  const chain = start => {
    const out = [];
    const seen = new Set();
    let cur = start;
    while (cur >= 0 && cur !== 0xfffffffe && cur !== 0xffffffff && !seen.has(cur) && out.length < 100000) {
      seen.add(cur); out.push(cur); cur = fat[cur];
    }
    return out;
  };

  const readRegular = (start, size) => {
    if (!size || start < 0) return new Uint8Array();
    const ids = chain(start);
    const out = new Uint8Array(Math.min(size, ids.length * sectorSize));
    let pos = 0;
    for (const sid of ids) {
      const base = 512 + sid * sectorSize;
      const take = Math.min(sectorSize, out.length - pos);
      if (take <= 0) break;
      out.set(bytes.subarray(base, base + take), pos);
      pos += take;
    }
    return out;
  };

  const dirIds = chain(firstDirSector);
  const dir = concatBytes(dirIds.map(s => bytes.slice(512 + s * sectorSize, 512 + (s + 1) * sectorSize)));
  const entries = [];

  for (let off = 0; off + 128 <= dir.length; off += 128) {
    const nameLen = viewAt(dir, off + 64, 2, 'u16');
    if (nameLen < 2) { entries.push(null); continue; }
    const name = decodeUtf16LE(dir.slice(off, off + nameLen - 2));
    const type = dir[off + 66];
    const left = viewAt(dir, off + 68, 4, 'i32');
    const right = viewAt(dir, off + 72, 4, 'i32');
    const child = viewAt(dir, off + 76, 4, 'i32');
    const start = viewAt(dir, off + 116, 4, 'i32');
    const sizeLow = viewAt(dir, off + 120, 4, 'u32');
    const sizeHigh = viewAt(dir, off + 124, 4, 'u32');
    const size = sizeHigh ? (sizeHigh * 0x100000000 + sizeLow) : sizeLow;
    entries.push({ name, type, left, right, child, start, size });
  }

  const root = entries.findIndex(e => e && e.type === 5);
  const rootEntry = root >= 0 ? entries[root] : null;
  const rootMiniStream = rootEntry && rootEntry.start >= 0 ? readRegular(rootEntry.start, rootEntry.size) : new Uint8Array();

  const miniFat = [];
  if (firstMiniFatSector >= 0 && numMiniFatSectors) {
    for (const sid of chain(firstMiniFatSector).slice(0, numMiniFatSectors)) {
      const base = 512 + sid * sectorSize;
      for (let i = 0; i < sectorSize / 4; i++) miniFat.push(view.getInt32(base + i * 4, true));
    }
  }

  const readMini = (start, size) => {
    if (!size || start < 0 || !miniFat.length) return new Uint8Array();
    const chunks = [];
    const seen = new Set();
    let cur = start;
    let count = 0;
    while (cur >= 0 && cur !== 0xfffffffe && cur !== 0xffffffff && !seen.has(cur) && count * miniSectorSize < size) {
      seen.add(cur);
      const base = cur * miniSectorSize;
      chunks.push(rootMiniStream.slice(base, base + miniSectorSize));
      cur = miniFat[cur];
      count++;
    }
    return concatBytes(chunks).slice(0, size);
  };

  const streams = new Map();
  const visit = (id, path) => {
    if (id < 0 || !entries[id]) return;
    const e = entries[id];
    visit(e.left, path);
    const current = path ? `${path}/${e.name}` : e.name;
    if (e.type === 1 || e.type === 5) visit(e.child, current);
    else if (e.type === 2) {
      const data = e.size < miniCutoff ? readMini(e.start, e.size) : readRegular(e.start, e.size);
      streams.set(current, data);
    }
    visit(e.right, path);
  };
  if (root >= 0) visit(entries[root].child, '');

  return { streams };
}

function extractMsgStringProperties(streams) {
  const strings = {};
  for (const [path, data] of streams) {
    const m = path.match(/__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})$/);
    if (!m) continue;
    const prop = m[1].toLowerCase();
    const type = m[2].toLowerCase();
    if (type === '001f') strings[prop] = decodeUtf16LE(data).replace(/\u0000+$/, '');
    else if (type === '001e') strings[prop] = decodeWindows1252(data).replace(/\u0000+$/, '');
  }
  return strings;
}

function viewAt(bytes, offset, size, kind) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return kind === 'u16' ? v.getUint16(offset, true) : kind === 'u32' ? v.getUint32(offset, true) : v.getInt32(offset, true);
}

function decodeUtf16LE(bytes) {
  return new TextDecoder('utf-16le').decode(bytes);
}

function decodeWindows1252(bytes) {
  try { return new TextDecoder('windows-1252').decode(bytes); }
  catch { return new TextDecoder('iso-8859-1').decode(bytes); }
}

function concatBytes(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) { out.set(c, pos); pos += c.length; }
  return out;
}
