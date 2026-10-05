import { $, escapeHtml, downloadText, enableToolDragging } from '../utils.js';

export const metadata = {
  id: 'mail-header',
  title: 'Mail-Header analyzer',
  description: 'Analyze message headers locally',
  path: '/#header'
};

const LIMITS = {
  maxHeaderBytes: 2 * 1024 * 1024,
  maxHeaderCount: 5000,
  maxReceivedCount: 500,
  maxAuthenticationResults: 100,
  maxDkimSignatures: 100,
  maxArcSeals: 100,
  maxCompoundEntries: 100000,
  maxCompoundChain: 100000,
  maxCompoundDepth: 256,
  maxCompoundFileBytes: 128 * 1024 * 1024
};

export function renderHeaderRework(app) {
  app.innerHTML = `
    <div class="tool-window" id="mailHeaderWindow">
      <div class="tool-window-header" id="mailHeaderDragHandle" title="Drag tool">
        <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
        <strong>E-mail message header analyzer</strong>
      </div>

      <section class="card">
        <h2>E-mail message header analyzer</h2>
        <p class="small">
          Paste complete message headers or load an <code>.eml</code> or Outlook <code>.msg</code> file.
          Parsing and analysis happen locally in the browser. No DNS, reputation, URL, geolocation,
          or external-service lookups are performed.
        </p>
        <textarea id="mailHeaders" spellcheck="false" placeholder="Authentication-Results: mx.example; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com\nReceived-SPF: pass (receiver: domain of sender@example.com designates 203.0.113.10 as permitted sender)\nDKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; h=from:to:subject:date:message-id; bh=...; b=...\nFrom: Sender <sender@example.com>\nTo: recipient@example.net\nSubject: Example\nDate: Thu, 20 Aug 2026 14:00:00 +0000\nMessage-ID: <example@example.com>\nReceived: from mail.example.com (mail.example.com [203.0.113.10]) by mx.example.net with ESMTPS id abc; Thu, 20 Aug 2026 14:00:00 +0000"></textarea>
        <div class="row" style="margin-top:10px;align-items:center">
          <input id="mailHeaderFile" type="file" accept=".eml,.msg,.txt,.log,message/rfc822" hidden>
          <button class="btn" id="mailHeaderPick">Load .eml / .msg file</button>
          <button class="btn primary" id="mailHeaderAnalyze">Analyze</button>
          <button class="btn" id="mailHeaderClear">Clear</button>
        </div>
        <div class="row" style="margin-top:10px;align-items:center">
          <label for="mailHeaderAnalysisMode"><strong>Analysis evidence</strong></label>
          <select id="mailHeaderAnalysisMode" aria-describedby="mailHeaderModeHelp">
            <option value="headers">Header evidence only (offline)</option>
            <option value="supplied-dns">Header + user-supplied DNS evidence (offline)</option>
          </select>
        </div>
        <div id="mailHeaderModeHelp" class="small" style="margin-top:6px">
          The default mode reads only the message. The second mode lets you paste DNS records you already have; the browser still performs no DNS/network lookups.
        </div>
        <details id="mailHeaderDnsDetails" style="margin-top:10px" hidden>
          <summary>Supply DNS evidence</summary>
          <div class="grid" style="margin-top:10px">
            <label class="stat"><span>SPF TXT record</span><input id="mailHeaderSpfRecord" type="text" spellcheck="false" placeholder="v=spf1 ip4:203.0.113.10 include:example.net -all"></label>
            <label class="stat"><span>DMARC TXT record</span><input id="mailHeaderDmarcRecord" type="text" spellcheck="false" placeholder="v=DMARC1; p=quarantine; adkim=s; aspf=r"></label>
            <label class="stat"><span>DKIM public-key TXT record</span><input id="mailHeaderDkimKeyRecord" type="text" spellcheck="false" placeholder="v=DKIM1; k=rsa; p=MIIBIjANBgkqh..."></label>
          </div>
          <p class="small">Supplied records are treated as evidence, not as automatically authoritative DNS responses. SPF evaluation is deliberately limited to locally evaluable mechanisms such as explicit ip4/ip6 terms; include/a/mx expansion is not performed offline.</p>
        </details>
        <div id="mailHeaderFileInfo" class="small" style="margin-top:10px"></div>
      </section>
      <section class="card" id="mailHeaderResult" hidden></section>
    </div>
  `;

  const fileInput = $('#mailHeaderFile');
  const dropZone = $('#mailHeaderWindow');
  const analysisMode = $('#mailHeaderAnalysisMode');
  const dnsDetails = $('#mailHeaderDnsDetails');
  analysisMode.onchange = () => { dnsDetails.hidden = analysisMode.value !== 'supplied-dns'; };

  $('#mailHeaderPick').onclick = () => fileInput.click();
  fileInput.onchange = async e => {
    const f = e.target.files?.[0];
    if (!f) return;
    await loadMailFile(f);
    fileInput.value = '';
  };

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
  });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', async e => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const f = e.dataTransfer?.files?.[0];
    if (!f) return;
    await loadMailFile(f);
  });

  async function loadMailFile(f) {
    try {
      const info = $('#mailHeaderFileInfo');
      info.textContent = `Reading ${f.name} locally…`;
      if (f.size > LIMITS.maxCompoundFileBytes) {
        throw new Error(`The selected file is larger than the local safety limit of ${formatBytes(LIMITS.maxCompoundFileBytes)}.`);
      }
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
  }

  $('#mailHeaderClear').onclick = () => {
    $('#mailHeaders').value = '';
    $('#mailHeaderResult').hidden = true;
    $('#mailHeaderResult').innerHTML = '';
    $('#mailHeaderFileInfo').textContent = '';
    $('#mailHeaderFile').value = '';
    $('#mailHeaderSpfRecord').value = '';
    $('#mailHeaderDmarcRecord').value = '';
    $('#mailHeaderDkimKeyRecord').value = '';
  };

  $('#mailHeaderAnalyze').onclick = analyze;
  $('#mailHeaders').addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyze();
  });

  enableToolDragging(
    $('#mailHeaderWindow'),
    $('#mailHeaderDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );

  function analyze() {
    const raw = $('#mailHeaders').value;
    const result = $('#mailHeaderResult');

    if (!raw.trim()) {
      result.hidden = false;
      result.innerHTML = '<div class="status warning">Paste message headers first.</div>';
      return;
    }

    try {
      const headers = parseHeaders(raw);
      const analysis = analyzeHeaders(headers, readSuppliedEvidence());
      result.hidden = false;
      result.innerHTML = renderResult(analysis, raw);
      bindExports(analysis);
    } catch (e) {
      result.hidden = false;
      result.innerHTML = `<div class="status danger">${escapeHtml(e.message || 'Header parsing failed.')}</div>`;
    }
  }
}

function readSuppliedEvidence() {
  const mode = document.querySelector('#mailHeaderAnalysisMode')?.value || 'headers';
  if (mode !== 'supplied-dns') return { mode, dns: {} };
  return {
    mode,
    dns: {
      spf: document.querySelector('#mailHeaderSpfRecord')?.value.trim() || '',
      dmarc: document.querySelector('#mailHeaderDmarcRecord')?.value.trim() || '',
      dkimKey: document.querySelector('#mailHeaderDkimKeyRecord')?.value.trim() || ''
    }
  };
}

function parseHeaders(raw) {
  const text = String(raw ?? '').replace(/^\uFEFF/, '');
  const byteLength = utf8ByteLength(text);
  if (byteLength > LIMITS.maxHeaderBytes) {
    throw new Error(`Header input exceeds the ${formatBytes(LIMITS.maxHeaderBytes)} local-analysis limit.`);
  }

  const headerPart = extractEmlHeaders(text);
  const physical = headerPart.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const unfolded = [];
  const parseWarnings = [];

  for (let i = 0; i < physical.length; i++) {
    const line = physical[i];
    if (/^[ \t]/.test(line)) {
      if (!unfolded.length) {
        parseWarnings.push(`Continuation line ${i + 1} appeared before the first header and was ignored.`);
      } else {
        unfolded[unfolded.length - 1].value += ' ' + line.trim();
        unfolded[unfolded.length - 1].physicalLines.push(i + 1);
      }
    } else if (line.trim() === '') {
      continue;
    } else {
      const idx = line.indexOf(':');
      if (idx <= 0) {
        parseWarnings.push(`Line ${i + 1} does not contain a valid header-name colon and was ignored.`);
        continue;
      }
      const rawName = line.slice(0, idx);
      const value = line.slice(idx + 1).trim();
      if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(rawName.trim())) {
        parseWarnings.push(`Line ${i + 1} contains an unusual header name: ${rawName}`);
      }
      unfolded.push({
        name: rawName.trim().toLowerCase(),
        originalName: rawName.trim(),
        value,
        physicalLines: [i + 1]
      });
    }
  }

  if (unfolded.length > LIMITS.maxHeaderCount) {
    throw new Error(`The message contains more than ${LIMITS.maxHeaderCount} parsed headers, exceeding the local safety limit.`);
  }
  if (!unfolded.length) throw new Error('No RFC-style message headers were found.');

  return unfolded.map((h, index) => ({ ...h, index: index + 1, rawValue: h.value }));
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

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function parseAuthResults(headers) {
  const ars = values(headers, 'authentication-results').slice(0, LIMITS.maxAuthenticationResults);
  const out = { records: [], spf: [], dkim: [], dmarc: [], arc: [], compauth: [], other: [] };

  for (let index = 0; index < ars.length; index++) {
    const raw = ars[index];
    const clean = normalizeHeaderWhitespace(raw);
    const parts = splitOutsideComments(clean, ';').map(s => s.trim()).filter(Boolean);
    const firstPart = parts.shift() || '';
    const firstTokens = firstPart.split(/\s+/);
    const authserv = firstTokens[0] || '';
    const version = /^\d+$/.test(firstTokens[1] || '') ? Number(firstTokens[1]) : null;
    const record = {
      index: index + 1,
      raw,
      authserv,
      version,
      methods: [],
      parserWarnings: []
    };

    for (const segment of parts) {
      const method = parseAuthenticationMethod(segment);
      if (!method) {
        record.parserWarnings.push(segment);
        continue;
      }
      method.recordIndex = record.index;
      record.methods.push(method);
      if (method.mechanism === 'spf') out.spf.push(method);
      else if (method.mechanism === 'dkim') out.dkim.push(method);
      else if (method.mechanism === 'dmarc') out.dmarc.push(method);
      else if (method.mechanism === 'arc') out.arc.push(method);
      else if (method.mechanism === 'compauth') out.compauth.push(method);
      else out.other.push(method);
    }
    out.records.push(record);
  }

  return out;
}

function parseAuthenticationMethod(segment) {
  // Authentication-Results clauses are normally: method=result [reason=...] [type.property=value ...]
  const m = segment.match(/^([a-z][a-z0-9_-]*)\s*=\s*([a-z][a-z0-9_-]*)(.*)$/i);
  if (!m) return null;

  const mechanism = m[1].toLowerCase();
  const result = m[2].toLowerCase();
  const tail = m[3] || '';
  const tokenParts = tokenizeAuthResultTail(tail);
  const properties = {};
  let reason = '';

  for (let i = 0; i < tokenParts.length; i++) {
    const token = tokenParts[i];
    const eq = token.indexOf('=');
    if (eq <= 0) continue;
    const key = token.slice(0, eq).trim().toLowerCase();
    const val = stripOuterQuotes(token.slice(eq + 1).trim());
    if (key === 'reason') reason = val;
    else properties[key] = val;
  }

  const detail = Object.entries(properties)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');

  return { mechanism, result, reason, properties, detail, raw: segment };
}

function tokenizeAuthResultTail(input) {
  const out = [];
  let current = '';
  let quote = null;
  let commentDepth = 0;

  const flush = () => {
    const v = current.trim();
    if (v) out.push(v);
    current = '';
  };

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const prev = input[i - 1];

    if (quote) {
      current += ch;
      if (ch === quote && prev !== '\\') quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === '(') {
      commentDepth++;
      current += ch;
      continue;
    }
    if (ch === ')' && commentDepth > 0) {
      commentDepth--;
      current += ch;
      continue;
    }
    if (commentDepth === 0 && /\s/.test(ch)) {
      flush();
    } else {
      current += ch;
    }
  }
  flush();
  return out;
}

function parseReceivedSpf(headers) {
  return values(headers, 'received-spf').map(raw => {
    const clean = normalizeHeaderWhitespace(raw);
    const firstWord = clean.trim().split(/[\s(]/)[0].toLowerCase();
    const props = {};
    const rawPropertyMatches = clean.matchAll(/(^|[\s;])([a-z][a-z0-9_-]*)\s*=\s*("[^"]*"|'[^']*'|[^\s;,)]+)/gi);
    for (const m of rawPropertyMatches) props[m[2].toLowerCase()] = stripOuterQuotes(m[3]);
    return { result: firstWord, props, raw };
  });
}

function parseAuthSignature(headers, name) {
  return values(headers, name).slice(0, name === 'dkim-signature' ? LIMITS.maxDkimSignatures : LIMITS.maxArcSeals).map(raw => {
    const fields = {};
    const warnings = [];

    const chunks = splitOutsideQuotes(raw, ';');
    for (const chunk of chunks) {
      const eq = chunk.indexOf('=');
      if (eq <= 0) continue;
      const key = chunk.slice(0, eq).trim().toLowerCase();
      const value = chunk.slice(eq + 1).trim();
      if (!/^[a-z][a-z0-9_-]*$/i.test(key)) continue;
      if (Object.prototype.hasOwnProperty.call(fields, key)) warnings.push(`Duplicate DKIM/ARC tag: ${key}`);
      fields[key] = value;
    }

    if (!fields.v) warnings.push('Missing v= version tag.');
    if (!fields.a && name === 'dkim-signature') warnings.push('Missing a= algorithm tag.');
    if (!fields.d && name === 'dkim-signature') warnings.push('Missing d= signing domain.');
    if (!fields.s && name === 'dkim-signature') warnings.push('Missing s= selector.');
    if (name === 'dkim-signature' && !fields.h) warnings.push('Missing h= signed-header list.');
    if (name === 'dkim-signature' && !fields.b) warnings.push('Missing b= signature data.');

    const signedHeaders = fields.h
      ? fields.h.split(':').map(x => x.trim().toLowerCase()).filter(Boolean)
      : [];

    const coveredSet = new Set(signedHeaders);
    const dkimHeaderCoverage = ['from', 'to', 'subject', 'date', 'message-id', 'reply-to'].map(header => ({
      header,
      signed: coveredSet.has(header)
    }));

    return {
      fields,
      warnings,
      raw,
      signedHeaders,
      dkimHeaderCoverage,
      expiresAt: parseEpochSeconds(fields.x),
      signedAt: parseEpochSeconds(fields.t)
    };
  });
}

function parseAddressHeader(value) {
  const raw = String(value || '').trim();
  const decoded = decodeMimeWords(raw);
  const matches = parseAddressList(decoded);
  const firstAddress = matches[0] || { name: '', address: '', domain: '' };

  return {
    ...firstAddress,
    raw,
    decoded,
    addresses: matches
  };
}

function parseAddressList(value) {
  const tokens = splitAddressList(value);
  return tokens
    .map(parseMailbox)
    .filter(x => x.address || x.name)
    .map(x => ({
      ...x,
      domain: getDomain(x.address)
    }));
}

function parseMailbox(value) {
  let s = String(value || '').trim();
  if (!s) return { name: '', address: '' };

  s = removeComments(s).trim();
  if (!s) return { name: '', address: '' };

  const groupMatch = s.match(/^([^:]+):\s*(.*);$/s);
  if (groupMatch) {
    const groupAddresses = parseAddressList(groupMatch[2]);
    return groupAddresses[0] || { name: groupMatch[1].trim(), address: '' };
  }

  const angle = s.match(/^(.*?)\s*<\s*([^<>\s]+)\s*>\s*$/s);
  if (angle) {
    return {
      name: decodeMimeWords(removeComments(angle[1].trim()).replace(/^"|"$/g, '').trim()),
      address: angle[2].trim()
    };
  }

  const simple = s.match(/([!#$%&'*+\-/=?^_`{|}~0-9A-Za-z.]+@[A-Za-z0-9.-]+)$/);
  if (simple) {
    return {
      name: '',
      address: simple[1]
    };
  }

  return {
    name: '',
    address: s.replace(/^<|>$/g, '').trim()
  };
}

function deriveAlignment(
  fromDomain,
  dmarcDomains,
  dkimDomains,
  spfDomains,
  dmarcResult,
  dmarcPolicy = null
) {
  const fromD = normalizeDomain(fromDomain);
  const dmarcD = normalizeDomain(dmarcDomains[0] || '');

  if (!fromD || !dmarcResult) {
    return {
      label: 'DMARC alignment',
      state: 'neutral',
      value: 'not established',
      mode: 'unknown',
      policy: { adkim: 'unknown', aspf: 'unknown' },
      fromDomain: fromD,
      dmarcDomain: dmarcD,
      dkim: {
        strict: false,
        relaxed: false,
        policyAligned: false,
        domain: '',
        organizationalDomain: ''
      },
      spf: {
        strict: false,
        relaxed: false,
        policyAligned: false,
        domain: '',
        organizationalDomain: ''
      },
      explanation: 'A reported DMARC result and a usable From domain are required. No DNS policy lookup was performed.'
    };
  }

  const dkim = bestAlignedDomain(fromD, dkimDomains);
  const spf = bestAlignedDomain(fromD, spfDomains);
  const policy = {
    adkim: dmarcPolicy?.adkim || 'unknown',
    aspf: dmarcPolicy?.aspf || 'unknown'
  };

  dkim.policyAligned =
    policy.adkim === 's'
      ? dkim.strict
      : policy.adkim === 'r'
        ? dkim.relaxed
        : false;

  spf.policyAligned =
    policy.aspf === 's'
      ? spf.strict
      : policy.aspf === 'r'
        ? spf.relaxed
        : false;

  const reportedPass = String(dmarcResult).toLowerCase() === 'pass';
  const observedAligned = dkim.relaxed || spf.relaxed;
  const policyKnown = policy.adkim !== 'unknown' || policy.aspf !== 'unknown';
  const policyAligned = dkim.policyAligned || spf.policyAligned;

  let state = resultState(dmarcResult, { empty: true });
  let value = String(dmarcResult).toLowerCase();
  let explanation = `From=${fromD}.`;

  if (reportedPass && policyKnown && policyAligned) {
    state = 'good';
    value = 'aligned';

    const paths = [];
    if (dkim.policyAligned) paths.push(`DKIM ${dkim.domain}`);
    if (spf.policyAligned) paths.push(`SPF ${spf.domain}`);

    explanation =
      `${paths.join(' and ')} satisfies the supplied ${`
        policy.adkim === 's' ? 'strict' : policy.adkim === 'r' ? 'relaxed' : 'unknown'
      `} DKIM / ${policy.aspf === 's' ? 'strict' : policy.aspf === 'r' ? 'relaxed' : 'unknown'}`
      + ` SPF alignment mode with From=${fromD}.`;
  } else if (reportedPass && observedAligned && !policyKnown) {
    state = 'warn';
    value = 'pass / alignment observed';
    explanation =
      `DMARC=pass was reported and at least one DKIM/SPF identifier is relaxed-aligned with From=${fromD}, `
      + 'but the DMARC alignment policy was not supplied or independently verified.';
  } else if (reportedPass && dmarcD && domainsEqual(fromD, dmarcD) && !policyKnown) {
    state = 'warn';
    value = 'pass / DMARC identity matches From';
    explanation =
      `Reported DMARC header.from domain ${dmarcD} matches From=${fromD}, `
      + 'but that alone does not independently establish an aligned DKIM/SPF identifier.';
  } else if (reportedPass && policyKnown && !policyAligned) {
    state = 'warn';
    value = 'pass / policy alignment not established';
    explanation =
      `DMARC=pass was reported, but the locally observed DKIM/SPF identifiers do not establish `
      + `the supplied DMARC alignment policy for From=${fromD}.`;
  } else if (reportedPass) {
    state = 'warn';
    value = 'pass / alignment not established locally';
    explanation =
      'DMARC=pass was reported, but locally observed DKIM/SPF identifiers did not establish '
      + 'the required alignment. Authentication-Results is not independently verified.';
  }

  if (policyKnown) {
    explanation += ` Supplied policy: adkim=${policy.adkim}; aspf=${policy.aspf}.`;
  } else {
    explanation +=
      ' DMARC policy alignment mode was not obtained from DNS, so strict-vs-relaxed policy cannot be confirmed offline.';
  }

  return {
    label: 'DMARC alignment',
    state,
    value,
    mode:
      policy.adkim === policy.aspf && policy.adkim !== 'unknown'
        ? policy.adkim === 's' ? 'strict' : 'relaxed'
        : 'mixed/unknown',
    policy,
    fromDomain: fromD,
    dmarcDomain: dmarcD,
    dkim,
    spf,
    explanation
  };
}

function bestAlignedDomain(fromDomain, domains) {
  const clean = domains.map(normalizeDomain).filter(Boolean);
  const exact = clean.find(d => d === fromDomain) || '';
  const relaxed = clean.find(d => isRelaxedAligned(fromDomain, d)) || '';

  return {
    domain: exact || relaxed,
    strict: !!exact,
    relaxed: !!relaxed,
    organizationalComparable: relaxed ? isKnownComparableOrganizationalDomain(fromDomain, relaxed) : false,
    organizationalDomain: relaxed ? getOrganizationalDomain(relaxed) : ''
  };
}

/*
 * Strictly safer than the old parent/suffix test:
 * - exact domains always align;
 * - subdomains only align when their effective registrable domain is known to match;
 * - unknown suffixes are not guessed as aligned.
 *
 * This deliberately uses a conservative built-in suffix set. If the host application already
 * has a Public Suffix List adapter, getOrganizationalDomain() can be replaced with it.
 */
const COMMON_PUBLIC_SUFFIXES = new Set([
  'com','org','net','edu','gov','mil','int','io','ai','app','dev','info','biz','name','pro','me','tv',
  'co','uk','de','fr','es','it','nl','be','ch','at','se','no','dk','fi','pl','cz','sk','hu','ro','bg',
  'gr','pt','ie','is','lu','li','ee','lv','lt','si','hr','rs','ua','ru','by','tr','il','za','in','cn',
  'jp','kr','sg','hk','tw','my','id','ph','th','vn','au','nz','br','mx','ar','cl'
]);

const KNOWN_MULTI_LABEL_PUBLIC_SUFFIXES = new Set([
  'co.uk','org.uk','ac.uk','gov.uk','com.au','net.au','org.au','edu.au',
  'co.nz','org.nz','govt.nz','co.jp','ne.jp','or.jp',
  'co.in','firm.in','net.in','org.in','gen.in','ind.in',
  'co.za','org.za','com.br','net.br','com.mx','com.tr','com.sg',
  'com.my','com.hk','com.tw','com.cn','com.ar','com.pl','com.ua',
  'com.ru','com.cy','com.gr','com.pt','com.es','com.de','co.il','co.kr'
]);

function isRelaxedAligned(a, b) {
  const x = normalizeDomain(a);
  const y = normalizeDomain(b);

  if (!x || !y) return false;
  if (x === y) return true;

  const ox = getOrganizationalDomain(x);
  const oy = getOrganizationalDomain(y);

  return !!ox && !!oy && ox === oy;
}

function isKnownComparableOrganizationalDomain(a, b) {
  return !!getOrganizationalDomain(a) && !!getOrganizationalDomain(b);
}

function getOrganizationalDomain(domain) {
  const d = normalizeDomain(domain);
  if (!d) return '';

  const labels = d.split('.');
  if (labels.length < 2) return '';

  const suffix2 = labels.slice(-2).join('.');
  if (KNOWN_MULTI_LABEL_PUBLIC_SUFFIXES.has(suffix2)) {
    return labels.length >= 3 ? labels.slice(-3).join('.') : '';
  }

  const suffix1 = labels[labels.length - 1];
  if (COMMON_PUBLIC_SUFFIXES.has(suffix1)) {
    return labels.slice(-2).join('.');
  }

  /*
   * Unknown public suffix structures are intentionally not guessed.
   * Exact-domain equality still works above; relaxed comparison stays unproven.
   */
  return '';
}

function parseAlignmentMode(value) {
  const v = String(value || '').toLowerCase();
  const match = v.match(/(?:^|[;\s])(?:adkim|aspf)\s*=\s*([sr])(?:[;\s]|$)/i);
  return match
    ? (match[1].toLowerCase() === 's' ? 'strict' : 'relaxed')
    : 'unknown';
}

function analyzeHeaders(headers, evidence = { mode: 'headers', dns: {} }) {
  const auth = parseAuthResults(headers);
  const receivedSpf = parseReceivedSpf(headers);
  const dkimSigs = parseAuthSignature(headers, 'dkim-signature');
  const arcSigs = parseAuthSignature(headers, 'arc-seal');

  const from = parseAddressHeader(first(headers, 'from'));
  const returnPath = parseAddressHeader(first(headers, 'return-path'));
  const replyTo = parseAddressHeader(first(headers, 'reply-to'));
  const sender = parseAddressHeader(first(headers, 'sender'));

  const subjectRaw = first(headers, 'subject');
  const subject = decodeMimeWords(subjectRaw);

  const messageId = normalizeMessageId(first(headers, 'message-id'));
  const dateRaw = first(headers, 'date');
  const dateParsed = parseMailDate(dateRaw);

  const received = values(headers, 'received');
  const receivedHops = parseReceivedChain(received);
  const receivedOrder = analyzeReceivedOrder(receivedHops);
  const headerDiagnostics = analyzeHeaderIntegrity(headers);

  const dkimReported = chooseBestReported(auth.dkim);
  const spfReported = chooseBestReported([
    ...auth.spf,
    ...receivedSpf.map((x, i) => ({
      mechanism: 'spf',
      result: x.result,
      properties: x.props,
      detail: formatReceivedSpfProperties(x.props),
      raw: x.raw,
      source: 'received-spf',
      recordIndex: i + 1
    }))
  ]);
  const dmarcReported = chooseBestReported(auth.dmarc);
  const arcReported = chooseBestReported(auth.arc);
  const compauthReported = chooseBestReported(auth.compauth);

  const dkimDomains = auth.dkim.flatMap(x => extractAuthDomains(x, 'dkim'));
  const spfDomains = auth.spf.flatMap(x => extractAuthDomains(x, 'spf'));
  const dmarcDomains = auth.dmarc.flatMap(x => extractAuthDomains(x, 'dmarc'));

  const suppliedDmarcPolicy = evidence?.dns?.dmarc
    ? parseDmarcRecord(evidence.dns.dmarc)
    : null;

  const dmarcPolicyMode =
    suppliedDmarcPolicy && !suppliedDmarcPolicy.recordError
      ? {
          adkim: suppliedDmarcPolicy.adkim,
          aspf: suppliedDmarcPolicy.aspf,
          source: 'user-supplied DNS evidence'
        }
      : null;

  const checks = [
    makeAuthCheck(
      'SPF',
      spfReported?.result,
      spfReported
        ? `Authentication-Results${auth.records.length ? ` #${spfReported.recordIndex}` : ''}`
        : (receivedSpf[0] ? 'Received-SPF header' : 'No SPF result found'),
      spfDomains[0] || receivedSpf[0]?.props?.sender || ''
    ),
    makeAuthCheck(
      'DKIM',
      dkimReported?.result,
      dkimReported
        ? `Authentication-Results #${dkimReported.recordIndex}`
        : (dkimSigs.length
          ? 'DKIM-Signature present, but no DKIM= result was found'
          : 'No DKIM result or signature found'),
      dkimDomains[0] || dkimSigs[0]?.fields?.d || ''
    ),
    makeAuthCheck(
      'DMARC',
      dmarcReported?.result,
      dmarcReported
        ? `Authentication-Results #${dmarcReported.recordIndex}`
        : 'No DMARC result found',
      dmarcDomains[0] || from.domain
    ),
    makeAuthCheck(
      'ARC',
      arcReported?.result,
      arcReported
        ? `Authentication-Results #${arcReported.recordIndex}`
        : (arcSigs.length
          ? 'ARC-Seal present, but no ARC= result was found'
          : 'ARC is optional and was not reported'),
      ''
    )
  ];

  if (compauthReported) {
    checks.push(
      makeAuthCheck(
        'CompAuth',
        compauthReported.result,
        `Authentication-Results #${compauthReported.recordIndex}`,
        compauthReported.properties?.[Object.keys(compauthReported.properties || {})[0]] || ''
      )
    );
  }

  const alignment = deriveAlignment(
    from.domain,
    dmarcDomains,
    dkimDomains,
    spfDomains,
    dmarcReported?.result,
    dmarcPolicyMode
  );

  checks.push(alignment);

  const authConflicts = detectAuthenticationConflicts(auth);

  const anomalies = buildAnomalies({
    headers,
    auth,
    receivedSpf,
    dkimSigs,
    arcSigs,
    from,
    returnPath,
    replyTo,
    sender,
    subjectRaw,
    messageId,
    dateRaw,
    dateParsed,
    received,
    receivedHops,
    receivedOrder,
    headerDiagnostics,
    dkimReported,
    spfReported,
    dmarcReported,
    dmarcDomains,
    dkimDomains,
    spfDomains,
    authConflicts
  });

  const verificationPreview = analyzeSuppliedDnsEvidence({
    evidence,
    from,
    dkimSigs,
    dkimReported,
    spfReported,
    dmarcReported,
    dmarcDomains,
    receivedSpf,
    receivedHops
  });

  for (const finding of verificationPreview.findings) {
    anomalies.push(finding);
  }

  const summary = summarize(checks, anomalies);
  const timestamp = deriveTransportTimeline(receivedHops, dateParsed, dkimSigs);
  const identityRelationships = deriveIdentityRelationships(
    from,
    returnPath,
    replyTo,
    sender,
    dkimDomains,
    spfDomains,
    dmarcDomains
  );

  const verification = verificationPreview;

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
    sender,
    subject,
    subjectRaw,
    messageId,
    date: dateRaw,
    dateParsed,
    received,
    receivedHops,
    receivedOrder,
    timestamp,
    anomalies,
    authConflicts,
    identityRelationships,
    dkimDomains,
    spfDomains,
    dmarcDomains,
    verification,
    counts: {
      totalHeaders: headers.length,
      uniqueNames: new Set(headers.map(h => h.name)).size,
      received: received.length,
      authResults: values(headers, 'authentication-results').length,
      dkimSignatures: dkimSigs.length,
      arcSeals: arcSigs.length,
      duplicateHeaderNames: Object.values(headerDiagnostics.duplicates).filter(n => n > 1).length
    },
    limitations: [
      'Authentication-Results, Received-SPF, SPF, DKIM and DMARC results are reported or derived from supplied headers; they were not independently verified.',
      'No DNS, public-suffix-list download, cryptographic DKIM verification, IP reputation, URL reputation, or geolocation lookup was performed.',
      'Relaxed DMARC domain comparison is exact for known/ordinary domain structures; unknown public-suffix structures are treated conservatively rather than guessed.'
    ]
  };
}

function chooseBestReported(items) {
  if (!items?.length) return null;

  const priority = new Map([
    ['pass', 10],
    ['bestguesspass', 9],
    ['neutral', 6],
    ['softfail', 5],
    ['temperror', 4],
    ['permerror', 3],
    ['fail', 1]
  ]);

  return [...items].sort(
    (a, b) => (priority.get(b.result) || 0) - (priority.get(a.result) || 0)
  )[0] || items[0];
}

function extractAuthDomains(item, mechanism) {
  if (!item) return [];

  const keys =
    mechanism === 'dkim'
      ? ['header.d', 'header.i']
      : mechanism === 'spf'
        ? ['smtp.mailfrom', 'smtp.helo']
        : mechanism === 'dmarc'
          ? ['header.from']
          : [];

  const out = [];

  for (const key of keys) {
    const v = item.properties?.[key];
    if (!v) continue;

    const candidate =
      key === 'header.i'
        ? (v.includes('@') ? v.slice(v.lastIndexOf('@') + 1) : v)
        : v;

    const d = normalizeDomain(candidate);
    if (d && !out.includes(d)) out.push(d);
  }

  return out;
}

function deriveReportedDmarcPolicyMode(items) {
  /*
   * Authentication-Results does not normally carry adkim/aspf policy.
   * Keep this hook for extended/vendor-specific header data without pretending
   * that a DNS lookup occurred.
   */
  for (const item of items || []) {
    const joined = [item.reason, item.detail, item.raw]
      .filter(Boolean)
      .join(' ');

    const mode = parseAlignmentMode(joined);
    if (mode !== 'unknown') return mode;
  }

  return '';
}

function makeAuthCheck(label, value, source, detail) {
  const state = resultState(value, { empty: true });
  const normalized = value ? String(value).toLowerCase() : '';

  let explanation = source;

  if (normalized === 'pass') {
    explanation = `${source}${detail ? ` · ${detail}` : ''}`;
  } else if (!value) {
    explanation = source;
  } else {
    explanation = `${source} · reported ${normalized}`;
  }

  return {
    label,
    state,
    value: normalized || 'not found',
    explanation
  };
}

function resultState(value, options = {}) {
  const v = String(value || '').toLowerCase();

  if (v === 'pass' || v === 'valid' || v === 'bestguesspass') return 'good';
  if (v === 'fail' || v === 'hardfail' || v === 'invalid') return 'bad';
  if (v === 'softfail' || v === 'neutral' || v === 'temperror' || v === 'permerror') return 'warn';

  return options.empty ? 'neutral' : 'unknown';
}

function summarize(checks, anomalies) {
  const primary = checks.filter(x => ['SPF', 'DKIM', 'DMARC'].includes(x.label));
  const good = primary.filter(x => x.state === 'good').length;
  const bad = primary.filter(x => x.state === 'bad').length;
  const warn = primary.filter(x => x.state === 'warn').length;

  const anomalyBad = anomalies.filter(a => a.level === 'bad').length;
  const anomalyWarn = anomalies.filter(a => a.level === 'warn').length;

  let state = 'neutral';
  let title = 'Insufficient reported authentication evidence';
  let text =
    'The headers do not contain enough positive reported SPF/DKIM/DMARC results '
    + 'to describe the message as strongly authenticated.';

  if (bad > 0 || anomalyBad > 0) {
    state = 'bad';
    title = 'Authentication or header warning';
    text =
      'At least one primary authentication result failed or a high-severity '
      + 'header anomaly was detected. Inspect the evidence below.';
  } else if (good === 3 && warn === 0) {
    state = 'good';
    title = 'Strong reported authentication signals';
    text =
      'SPF, DKIM and DMARC all report success in the supplied headers. '
      + 'This is a favorable signal, not proof that the message is safe.';
  } else if (good >= 2) {
    state = 'good';
    title = 'Good reported authentication signals';
    text =
      'Multiple primary authentication mechanisms report success. '
      + 'Review identity alignment, transport anomalies and any conflicts below.';
  } else if (warn > 0 || anomalyWarn > 0) {
    state = 'warn';
    title = 'Mixed or incomplete signals';
    text =
      'The headers contain useful signals, but some are missing, neutral, '
      + 'conflicting, or deserve attention.';
  }

  return {
    state,
    title,
    text,
    good,
    bad,
    warn,
    primaryCount: primary.length
  };
}

function buildAnomalies(ctx) {
  const a = [];
  const count = name => ctx.headers.filter(h => h.name === name).length;

  const duplicatesOfInterest = [
    'from',
    'sender',
    'to',
    'cc',
    'bcc',
    'reply-to',
    'return-path',
    'date',
    'message-id',
    'subject',
    'mime-version',
    'content-type',
    'content-transfer-encoding'
  ];

  if (!ctx.from.address) {
    a.push({
      level: 'bad',
      category: 'identity',
      text: 'No usable From address was found.'
    });
  }

  if (!ctx.dateRaw) {
    a.push({
      level: 'warn',
      category: 'structure',
      text: 'No Date header was found.'
    });
  }

  if (ctx.dateRaw && !ctx.dateParsed.valid) {
    a.push({
      level: 'warn',
      category: 'timestamps',
      text: `Date header could not be parsed as a valid message date: ${ctx.dateRaw}`
    });
  }

  if (!ctx.messageId) {
    a.push({
      level: 'warn',
      category: 'identity',
      text: 'No Message-ID header was found.'
    });
  }

  if (
    ctx.replyTo.address &&
    ctx.from.domain &&
    ctx.replyTo.domain &&
    !isRelaxedAligned(ctx.from.domain, ctx.replyTo.domain)
  ) {
    a.push({
      level: 'warn',
      category: 'identity',
      text:
        `Reply-To domain (${ctx.replyTo.domain}) does not share the same locally-derived `
        + `organizational domain as From (${ctx.from.domain}). This can be legitimate, `
        + 'but deserves attention.'
    });
  }

  if (ctx.received.length === 0) {
    a.push({
      level: 'warn',
      category: 'transport',
      text: 'No Received headers were found.'
    });
  }

  if (ctx.received.length > LIMITS.maxReceivedCount) {
    a.push({
      level: 'warn',
      category: 'transport',
      text:
        `More than ${LIMITS.maxReceivedCount} Received headers were present; analysis was capped.`
    });
  }

  for (const name of duplicatesOfInterest) {
    const n = count(name);
    if (n > 1) {
      a.push({
        level:
          name === 'return-path' ||
          name === 'from' ||
          name === 'date' ||
          name === 'message-id'
            ? 'bad'
            : 'warn',
        category: 'duplicate-header',
        text: `Multiple ${displayHeaderName(name)} headers were present (${n}).`
      });
    }
  }

  for (const d of ctx.headerDiagnostics.warnings) {
    a.push({
      level: d.level,
      category: 'header-parser',
      text: d.text
    });
  }

  for (const c of ctx.authConflicts || []) {
    a.push({
      level: 'warn',
      category: 'authentication-conflict',
      text: c.text
    });
  }

  for (const hop of ctx.receivedHops) {
    for (const issue of hop.issues) {
      a.push({
        level: issue.level,
        category: 'transport',
        text: `Received hop #${hop.appearanceIndex}: ${issue.text}`
      });
    }
  }

  if (ctx.receivedOrder.negativeDelays > 0) {
    a.push({
      level: 'bad',
      category: 'timestamps',
      text:
        `${ctx.receivedOrder.negativeDelays} Received hop interval appears negative. `
        + 'Header order and timestamps are inconsistent.'
    });
  }

  if (ctx.receivedOrder.largeDelays.length) {
    const biggest = ctx.receivedOrder.largeDelays[0];

    a.push({
      level: 'warn',
      category: 'timestamps',
      text:
        `A transport gap of ${formatDuration(biggest.ms)} was observed between `
        + `Received hops #${biggest.from} and #${biggest.to}.`
    });
  }

  if (ctx.receivedHops.length && ctx.dateParsed.valid) {
    const parseable = ctx.receivedHops
      .filter(h => h.timestamp.valid)
      .sort((x, y) => x.timestamp.date - y.timestamp.date);

    const oldest = parseable[0];

    if (oldest) {
      const delta = oldest.timestamp.date - ctx.dateParsed.date;

      if (delta < -5 * 60 * 1000) {
        a.push({
          level: 'warn',
          category: 'timestamps',
          text:
            `The oldest parseable Received timestamp is ${formatDuration(Math.abs(delta))} `
            + 'earlier than the Date header.'
        });
      } else if (delta > 24 * 60 * 60 * 1000) {
        a.push({
          level: 'warn',
          category: 'timestamps',
          text:
            `The oldest parseable Received timestamp is ${formatDuration(delta)} `
            + 'later than the Date header.'
        });
      }
    }
  }

  for (const sig of ctx.dkimSigs) {
    if (sig.signedAt && ctx.dateParsed.valid) {
      const delta =
        ctx.dateParsed.date.getTime() - sig.signedAt.getTime();

      if (Math.abs(delta) > 24 * 60 * 60 * 1000) {
        a.push({
          level: 'warn',
          category: 'timestamps',
          text:
            `A DKIM t= timestamp differs from Date by ${formatDuration(Math.abs(delta))}.`
        });
      }
    }

    if (sig.expiresAt && sig.signedAt && sig.expiresAt <= sig.signedAt) {
      a.push({
        level: 'warn',
        category: 'dkim',
        text:
          'A DKIM x= expiration timestamp is not later than its t= signing timestamp.'
      });
    }
  }

  if (ctx.dkimSigs.some(x => x.warnings.length)) {
    const total = ctx.dkimSigs.reduce((n, x) => n + x.warnings.length, 0);

    a.push({
      level: 'warn',
      category: 'dkim',
      text:
        `${total} DKIM signature metadata issue(s) were detected. `
        + 'This is metadata analysis only; the signature was not cryptographically verified.'
    });
  }

  if (
    ctx.dkimSigs.some(
      x => x.fields.h && !x.signedHeaders.includes('from')
    )
  ) {
    a.push({
      level: 'bad',
      category: 'dkim',
      text:
        'At least one DKIM signature does not list From in h=. '
        + 'DKIM verification requires the From field to be protected.'
    });
  }

  return dedupeAnomalies(a);
}

function analyzeHeaderIntegrity(headers) {
  const duplicates = {};

  for (const h of headers) {
    duplicates[h.name] = (duplicates[h.name] || 0) + 1;
  }

  const warnings = [];

  for (const h of headers) {
    if (/[^\x09\x20-\x7E]/.test(h.name)) {
      warnings.push({
        level: 'warn',
        text: `Header name "${h.originalName}" contains non-ASCII characters.`
      });
    }

    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(h.value)) {
      warnings.push({
        level: 'bad',
        text: `Header "${h.originalName}" contains control characters.`
      });
    }
  }

  return { duplicates, warnings };
}

function dedupeAnomalies(items) {
  const seen = new Set();
  const out = [];

  for (const item of items) {
    const key = `${item.level}|${item.category}|${item.text}`;
    if (seen.has(key)) continue;

    seen.add(key);
    out.push(item);
  }

  return out;
}

function detectAuthenticationConflicts(auth) {
  const out = [];

  for (const mechanism of ['spf', 'dkim', 'dmarc', 'arc', 'compauth']) {
    const items = auth[mechanism] || [];
    const results = [
      ...new Set(items.map(x => x.result).filter(Boolean))
    ];

    if (results.length > 1) {
      out.push({
        mechanism,
        results,
        text:
          `Conflicting ${mechanism.toUpperCase()} results were reported `
          + `across Authentication-Results records: ${results.join(', ')}.`
      });
    }
  }

  return out;
}

function deriveIdentityRelationships(
  from,
  returnPath,
  replyTo,
  sender,
  dkimDomains,
  spfDomains,
  dmarcDomains
) {
  return {
    fromVsReturnPath: compareDomains(from.domain, returnPath.domain),
    fromVsReplyTo: compareDomains(from.domain, replyTo.domain),
    fromVsSender: compareDomains(from.domain, sender.domain),
    fromVsDkim: compareMany(from.domain, dkimDomains),
    fromVsSpf: compareMany(from.domain, spfDomains),
    fromVsDmarc: compareMany(from.domain, dmarcDomains)
  };
}

function domainsEqual(a, b) {
  return normalizeDomain(a) === normalizeDomain(b);
}

function compareDomains(a, b) {
  const x = normalizeDomain(a);
  const y = normalizeDomain(b);

  if (!x || !y) {
    return {
      available: false,
      exact: false,
      relaxed: false,
      a: x,
      b: y
    };
  }

  return {
    available: true,
    exact: x === y,
    relaxed: isRelaxedAligned(x, y),
    a: x,
    b: y
  };
}

function compareMany(a, valuesList) {
  const candidates = valuesList
    .filter(Boolean)
    .map(v => compareDomains(a, v));

  return {
    available: candidates.some(x => x.available),
    exact: candidates.some(x => x.exact),
    relaxed: candidates.some(x => x.relaxed),
    candidates
  };
}

function parseReceivedChain(receivedValues) {
  return receivedValues
    .slice(0, LIMITS.maxReceivedCount)
    .map((raw, i) => parseReceivedHop(raw, i + 1));
}

function parseReceivedHop(raw, appearanceIndex) {
  const text = normalizeHeaderWhitespace(raw);

  const timestamp = parseReceivedTimestamp(text);
  const fromPart = extractReceivedSegment(text, 'from', 'by');
  const byPart = extractReceivedSegment(
    text,
    'by',
    'with|id|for|;|$'
  );

  const withMatch = text.match(/\bwith\s+([^\s;]+)/i);
  const idMatch = text.match(/\bid\s+([^\s;]+)/i);
  const forMatch = text.match(/\bfor\s+([^;]+)/i);

  const from = parseReceivedNode(fromPart);
  const by = parseReceivedNode(byPart);

  const protocol = withMatch?.[1] || '';
  const id = idMatch?.[1] || '';
  const forAddress = forMatch
    ? (
        parseAddressList(forMatch[1].trim())[0]?.address
        || forMatch[1].trim()
      )
    : '';

  const issues = [];

  if (!by.host && !by.ip) {
    issues.push({
      level: 'warn',
      text: 'No usable by-host was recognized.'
    });
  }

  if (from.ip && isSpecialOrPrivateIp(from.ip)) {
    issues.push({
      level: 'warn',
      text:
        `${from.ip} is a private, loopback, link-local, documentation, `
        + 'or otherwise special-use address.'
    });
  }

  if (by.ip && isSpecialOrPrivateIp(by.ip)) {
    issues.push({
      level: 'warn',
      text:
        `${by.ip} is a private, loopback, link-local, documentation, `
        + 'or otherwise special-use address.'
    });
  }

  if (
    from.host &&
    by.host &&
    normalizeHostname(from.host) === normalizeHostname(by.host)
  ) {
    issues.push({
      level: 'warn',
      text:
        'The parsed from-host and by-host are identical; this can be legitimate '
        + 'for local processing.'
    });
  }

  return {
    appearanceIndex,
    raw,
    from,
    by,
    protocol,
    id,
    forAddress,
    timestamp,
    issues
  };
}

function parseReceivedNode(segment) {
  const clean = String(segment || '').trim();

  if (!clean) {
    return {
      host: '',
      ip: '',
      helo: '',
      raw: '',
      comments: []
    };
  }

  const bracketIp = clean.match(/\[([^\]]+)\]/);
  const ip =
    bracketIp && isIpLiteral(bracketIp[1])
      ? bracketIp[1]
      : findFirstIp(clean);

  let remainder = clean;

  if (bracketIp) {
    remainder = remainder.replace(bracketIp[0], ' ');
  }

  const comments = [
    ...remainder.matchAll(/\(([^()]*)\)/g)
  ]
    .map(m => m[1].trim())
    .filter(Boolean);

  const hostCandidates = remainder
    .replace(/\([^)]*\)/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  const host =
    hostCandidates
      .find(x => looksLikeHostname(x))
      ?.replace(/[(),;]$/g, '')
    || '';

  const helo =
    comments.find(x => looksLikeHostname(x))
    || '';

  return {
    host,
    ip: ip || '',
    helo,
    raw: clean,
    comments
  };
}

function extractReceivedSegment(text, keyword, endPattern) {
  const re = new RegExp(
    `\\b${keyword}\\s+(.+?)(?=\\s+\\b(?:${endPattern})\\b|\\s*;\\s|$)`,
    'i'
  );

  const m = text.match(re);
  return m ? m[1].trim() : '';
}

function parseReceivedTimestamp(text) {
  const semicolon = text.lastIndexOf(';');

  if (semicolon < 0) {
    return {
      valid: false,
      date: null,
      raw: ''
    };
  }

  const raw = text.slice(semicolon + 1).trim();
  const date = parseMailDate(raw);

  return {
    ...date,
    raw
  };
}

function analyzeReceivedOrder(hops) {
  const chronological = hops
    .filter(h => h.timestamp.valid)
    .map(h => ({
      appearanceIndex: h.appearanceIndex,
      time: h.timestamp.date.getTime()
    }));

  const intervals = [];
  let negativeDelays = 0;
  const largeDelays = [];

  /*
   * Received fields are normally prepended by each receiving hop,
   * so appearance order is newest -> oldest.
   */
  for (let i = 0; i + 1 < chronological.length; i++) {
    const newer = chronological[i];
    const older = chronological[i + 1];

    const ms = newer.time - older.time;

    const item = {
      from: older.appearanceIndex,
      to: newer.appearanceIndex,
      ms
    };

    intervals.push(item);

    if (ms < 0) {
      negativeDelays++;
    }

    if (ms > 60 * 60 * 1000) {
      largeDelays.push(item);
    }
  }

  largeDelays.sort((a, b) => b.ms - a.ms);

  const chronologicalHops = [...chronological]
    .sort((a, b) => a.time - b.time);

  return {
    intervals,
    negativeDelays,
    largeDelays,
    chronologicalHops
  };
}

function deriveTransportTimeline(hops, dateParsed, dkimSigs) {
  const valid = hops
    .filter(h => h.timestamp.valid)
    .sort((a, b) => a.timestamp.date - b.timestamp.date);

  const firstObserved = valid[0]?.timestamp.date || null;
  const lastObserved = valid[valid.length - 1]?.timestamp.date || null;

  const transitMs =
    firstObserved && lastObserved
      ? Math.max(0, lastObserved - firstObserved)
      : null;

  const dkimSignedAt = dkimSigs
    .map(x => x.signedAt)
    .filter(Boolean)
    .map(x => new Date(x));

  const dkimExpiresAt = dkimSigs
    .map(x => x.expiresAt)
    .filter(Boolean)
    .map(x => new Date(x));

  return {
    firstObserved,
    lastObserved,
    transitMs,
    messageDate: dateParsed.valid ? dateParsed.date : null,
    dkimSignedAt,
    dkimExpiresAt
  };
}

function renderResult(a) {
  const s = a.summary;

  const summaryHtml = `<div class="status ${statusClass(s.state)}">
    <strong>
      <span aria-hidden="true" style="font-size:1.15em;margin-right:6px">
        ${statusIcon(s.state)}
      </span>
      ${escapeHtml(s.title)}
    </strong><br>
    <span>${escapeHtml(s.text)}</span>
  </div>`;

  const primaryChecks = a.checks.filter(
    x => ['SPF', 'DKIM', 'DMARC'].includes(x.label)
  );

  const supplementaryChecks = a.checks.filter(
    x => !['SPF', 'DKIM', 'DMARC', 'DMARC alignment'].includes(x.label)
  );

  const alignment = a.checks.find(
    x => x.label === 'DMARC alignment'
  );

  const evidenceCards = primaryChecks.map(c => `
    <div class="stat">
      <span>${escapeHtml(c.label)}</span>
      <strong>
        <span aria-hidden="true" style="margin-right:6px">
          ${statusIcon(c.state)}
        </span>
        ${escapeHtml(c.value.toUpperCase())}
      </strong>
      <div class="small">${escapeHtml(c.explanation)}</div>
    </div>
  `).join('');

  const supplementaryHtml = supplementaryChecks.length
    ? supplementaryChecks.map(c => `
      <div class="stat">
        <span>${escapeHtml(c.label)}</span>
        <strong>
          <span aria-hidden="true" style="margin-right:6px">
            ${statusIcon(c.state)}
          </span>
          ${escapeHtml(c.value.toUpperCase())}
        </strong>
        <div class="small">${escapeHtml(c.explanation)}</div>
      </div>
    `).join('')
    : '<p class="small">No supplementary authentication results were reported.</p>';

  const facts = [
    ['Reported primary auth', `${s.good}/${s.primaryCount} PASS`],
    ['Received hops', String(a.counts.received)],
    ['Unique headers', String(a.counts.uniqueNames)],
    ['Duplicate header names', String(a.counts.duplicateHeaderNames)],
    ['Auth-Results records', String(a.counts.authResults)],
    ['DKIM signatures', String(a.counts.dkimSignatures)],
    ['ARC seals', String(a.counts.arcSeals)]
  ];

  const identity = `
    <div class="grid">
      ${stat('From', formatAddress(a.from))}
      ${stat('Return-Path', formatAddress(a.returnPath))}
      ${stat('Reply-To', formatAddress(a.replyTo))}
      ${stat('Sender', formatAddress(a.sender))}
      ${stat('Subject', a.subject || 'Not found')}
      ${stat('Date', a.date || 'Not found')}
      ${stat('Parsed Date', a.dateParsed.valid ? a.dateParsed.date.toISOString() : 'Not parsed')}
      ${stat('Message-ID', a.messageId || 'Not found')}
    </div>`;

  const relationshipRows = [
    relationRow('From ↔ Return-Path', a.identityRelationships.fromVsReturnPath),
    relationRow('From ↔ Reply-To', a.identityRelationships.fromVsReplyTo),
    relationRow('From ↔ Sender', a.identityRelationships.fromVsSender),
    relationRow('From ↔ DKIM d=', a.identityRelationships.fromVsDkim),
    relationRow('From ↔ SPF identity', a.identityRelationships.fromVsSpf),
    relationRow('From ↔ DMARC header.from', a.identityRelationships.fromVsDmarc)
  ].join('');

  const authRows = a.auth.records.flatMap(r =>
    r.methods.map(x => ({
      mechanism: x.mechanism.toUpperCase(),
      result: x.result,
      identity: formatAuthProperties(x.properties),
      reason: x.reason || '',
      source: `Authentication-Results #${r.index}`,
      authserv: r.authserv
    }))
  );

  const authTable = authRows.length
    ? `
      <div class="table-wrap"><table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Result</th>
            <th>Identity / properties</th>
            <th>Reason</th>
            <th>Auth service</th>
          </tr>
        </thead>
        <tbody>
          ${authRows.map(r => `
            <tr>
              <td>${escapeHtml(r.mechanism)}</td>
              <td><strong>${escapeHtml(r.result)}</strong></td>
              <td class="mono">${escapeHtml(r.identity || '—')}</td>
              <td>${escapeHtml(r.reason || '—')}</td>
              <td>${escapeHtml(r.authserv || '—')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table></div>
    `
    : '<div class="status warning">No Authentication-Results method records were parsed.</div>';

  const conflictHtml = a.authConflicts.length
    ? `
      <div class="status warning">
        <strong>Conflicting reported results</strong>
        <ul>
          ${a.authConflicts.map(c => `<li>${escapeHtml(c.text)}</li>`).join('')}
        </ul>
      </div>
    `
    : `
      <div class="status success">
        No conflicting SPF/DKIM/DMARC/ARC/CompAuth result values were found across Authentication-Results records.
      </div>
    `;

  const receivedTable = renderReceivedTable(a);
  const timeline = renderTimeline(a);
  const dkimTable = renderDkimTable(a);

  const anomalyHtml = a.anomalies.length
    ? `
      <ul class="mail-findings">
        ${a.anomalies.map(x => `
          <li>
            <strong>${escapeHtml(x.level.toUpperCase())}</strong>
            · <span class="small">${escapeHtml(x.category)}</span>
            — ${escapeHtml(x.text)}
          </li>
        `).join('')}
      </ul>
    `
    : '<div class="status success">No local heuristic anomalies were detected.</div>';

  const allHeaderRows = a.headers
    .map(h => `
      <tr>
        <td>${h.index}</td>
        <td>${escapeHtml(h.originalName)}</td>
        <td class="mono">${escapeHtml(h.value)}</td>
      </tr>
    `)
    .join('');

  return `${summaryHtml}

    <h3>Evidence at a glance</h3>
    <div class="grid">
      ${facts.map(([k, v]) => stat(k, v)).join('')}
    </div>

    <h3>Primary authentication — reported values</h3>
    <div class="grid">${evidenceCards}</div>
    <p class="small">
      These are values reported by mail infrastructure in the supplied headers.
      The browser did not independently perform DNS lookups or cryptographic verification.
    </p>

    <h3>Domain relationships and DMARC alignment</h3>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Relationship</th>
            <th>Exact</th>
            <th>Relaxed</th>
            <th>Observed domains</th>
          </tr>
        </thead>
        <tbody>${relationshipRows}</tbody>
      </table>
    </div>

    <div class="stat" style="margin-top:10px">
      <span>${escapeHtml(alignment.label)}</span>
      <strong>
        <span aria-hidden="true" style="margin-right:6px">
          ${statusIcon(alignment.state)}
        </span>
        ${escapeHtml(alignment.value)}
      </strong>
      <div class="small">${escapeHtml(alignment.explanation)}</div>
    </div>

    <h3>Supplementary authentication</h3>
    <div class="grid">${supplementaryHtml}</div>

    <h3>Authentication-Results detail</h3>
    ${authTable}
    ${conflictHtml}

    <h3>Received path</h3>
    <p class="small">
      Received fields are listed in message-header appearance order (normally newest → oldest).
      The analyzer parses the locally visible host, IP, protocol, ID, recipient and timestamp
      fields without doing DNS lookups.
    </p>
    ${timeline}
    ${receivedTable}

    <h3>Message identity</h3>
    ${identity}

    <h3>Optional supplied-DNS evidence</h3>
    ${renderVerification(a.verification)}

    <h3>DKIM / ARC signature metadata</h3>
    ${dkimTable}

    <h3>Header anomalies and forensic checks</h3>
    ${anomalyHtml}

    <h3>All headers</h3>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Header</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>${allHeaderRows}</tbody>
      </table>
    </div>

    <div class="result-actions">
      <button class="btn" id="mailExportJson">Export analysis JSON</button>
      <button class="btn" id="mailExportText">Export forensic summary TXT</button>
      <button class="btn" id="mailCopyReport">Copy forensic summary</button>
    </div>

    <details style="margin-top:14px">
      <summary>Observed vs derived vs unverified</summary>
      <p class="small">
        <strong>Observed:</strong> values directly present in supplied headers,
        such as SPF=pass or a Received timestamp.
      </p>
      <p class="small">
        <strong>Derived:</strong> relationships and timings calculated locally from
        those values, such as domain alignment or a transport gap.
      </p>
      <p class="small">
        <strong>Unverified:</strong> cryptographic DKIM verification, SPF/DKIM/DMARC
        DNS policy, IP reputation, URL reputation and geolocation were not performed.
      </p>
    </details>
  `;
}

function renderReceivedTable(a) {
  if (!a.receivedHops.length) {
    return '<div class="status warning">No Received headers found.</div>';
  }

  const rows = a.receivedHops.map(h => `
    <tr>
      <td>${h.appearanceIndex}</td>
      <td>
        ${escapeHtml(h.from.host || '—')}
        ${h.from.ip ? `<div class="small mono">${escapeHtml(h.from.ip)}</div>` : ''}
        ${h.from.helo ? `<div class="small">HELO ${escapeHtml(h.from.helo)}</div>` : ''}
      </td>
      <td>
        ${escapeHtml(h.by.host || '—')}
        ${h.by.ip ? `<div class="small mono">${escapeHtml(h.by.ip)}</div>` : ''}
        ${h.by.helo ? `<div class="small">HELO ${escapeHtml(h.by.helo)}</div>` : ''}
      </td>
      <td>${escapeHtml(h.protocol || '—')}</td>
      <td>${escapeHtml(h.forAddress || '—')}</td>
      <td>${h.timestamp.valid ? escapeHtml(h.timestamp.date.toISOString()) : '—'}</td>
      <td>${h.id ? escapeHtml(h.id) : '—'}</td>
    </tr>
  `).join('');

  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>From</th>
            <th>By</th>
            <th>With</th>
            <th>For</th>
            <th>Timestamp</th>
            <th>ID</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderTimeline(a) {
  const valid = [...a.receivedHops]
    .filter(h => h.timestamp.valid)
    .sort((x, y) => x.timestamp.date - y.timestamp.date);

  if (!valid.length) {
    return `
      <div class="status warning">
        No parseable Received timestamps were found, so a transport timeline cannot be constructed.
      </div>
    `;
  }

  const messageDate = a.timestamp.messageDate;

  const cards = valid.map((hop, index) => {
    const previous = valid[index - 1];
    const gap = previous
      ? hop.timestamp.date - previous.timestamp.date
      : null;

    return `
      <div class="stat">
        <span>
          Hop ${hop.appearanceIndex} ·
          ${escapeHtml(hop.by.host || hop.by.ip || 'unknown receiver')}
        </span>

        <strong>${escapeHtml(hop.timestamp.date.toISOString())}</strong>

        <div class="small">
          ${escapeHtml(
            gap == null
              ? 'Oldest observed timestamp'
              : `+${formatDuration(gap)} from previous chronological hop`
          )}
        </div>

        ${
          hop.from.host || hop.from.ip
            ? `<div class="small mono">
                from ${escapeHtml(hop.from.host || '')}
                ${hop.from.ip ? `[${escapeHtml(hop.from.ip)}]` : ''}
              </div>`
            : ''
        }
      </div>
    `;
  }).join('');

  const comparisons = [];

  if (messageDate) {
    const oldest = valid[0].timestamp.date;
    const newest = valid[valid.length - 1].timestamp.date;

    comparisons.push(
      `Date header → oldest Received: ${formatSignedDuration(oldest - messageDate)}`
    );
    comparisons.push(
      `Date header → newest Received: ${formatSignedDuration(newest - messageDate)}`
    );
  }

  if (a.timestamp.transitMs != null) {
    comparisons.push(
      `Observed Received span: ${formatDuration(a.timestamp.transitMs)}`
    );
  }

  return `
    <div class="grid">${cards}</div>
    ${
      comparisons.length
        ? `<p class="small">${comparisons.map(escapeHtml).join(' · ')}</p>`
        : ''
    }
  `;
}

function analyzeSuppliedDnsEvidence(ctx) {
  const dns = ctx.evidence?.dns || {};
  const supplied = Boolean(dns.spf || dns.dmarc || dns.dkimKey);

  const findings = [];

  if (!supplied) {
    return {
      mode: 'headers',
      supplied: false,
      spf: null,
      dmarc: null,
      dkimKey: null,
      findings
    };
  }

  const clientIp =
    ctx.receivedSpf?.[0]?.props?.['client-ip']
    || findObservedClientIp(
      ctx.receivedSpf,
      ctx.receivedHops,
      ctx.dkimSigs
    );

  const spf = dns.spf
    ? parseSpfRecord(dns.spf, clientIp)
    : null;

  const dmarc = dns.dmarc
    ? parseDmarcRecord(dns.dmarc)
    : null;

  const dkimKey = dns.dkimKey
    ? parseDkimKeyRecord(dns.dkimKey)
    : null;

  if (spf?.unsupportedMechanisms?.length) {
    findings.push({
      level: 'warn',
      category: 'supplied-dns',
      text:
        `Supplied SPF record contains mechanisms that this offline evaluator did not expand: `
        + `${spf.unsupportedMechanisms.join(', ')}.`
    });
  }

  if (
    spf?.result &&
    ctx.spfReported?.result &&
    ['pass', 'fail', 'softfail', 'neutral'].includes(spf.result) &&
    spf.result !== ctx.spfReported.result
  ) {
    findings.push({
      level: 'warn',
      category: 'supplied-dns',
      text:
        `Supplied SPF evidence locally evaluates to ${spf.result}, `
        + `while the message reports SPF=${ctx.spfReported.result}.`
    });
  }

  if (dmarc?.recordError) {
    findings.push({
      level: 'warn',
      category: 'supplied-dns',
      text:
        `Supplied DMARC record could not be fully parsed: ${dmarc.recordError}`
    });
  }

  if (
    dmarc &&
    !dmarc.recordError &&
    ctx.dmarcReported?.result === 'pass' &&
    ctx.from?.domain
  ) {
    const fromDomain = normalizeDomain(ctx.from.domain);

    const dkimAligned = (ctx.dkimSigs || [])
      .map(sig => normalizeDomain(sig.fields?.d || ''))
      .filter(Boolean)
      .some(d =>
        dmarc.adkim === 's'
          ? d === fromDomain
          : isRelaxedAligned(d, fromDomain)
      );

    const spfAligned = (
      ctx.spfReported?.properties
        ? Object.values(ctx.spfReported.properties)
        : []
    )
      .map(v => normalizeDomain(v))
      .filter(Boolean)
      .some(d =>
        dmarc.aspf === 's'
          ? d === fromDomain
          : isRelaxedAligned(d, fromDomain)
      );

    if (!dkimAligned && !spfAligned) {
      findings.push({
        level: 'warn',
        category: 'supplied-dns',
        text:
          `Supplied DMARC policy (${dmarc.adkim}/${dmarc.aspf}) is not `
          + 'supported by a locally observable aligned DKIM/SPF identifier.'
      });
    }
  }

  if (dkimKey?.recordError) {
    findings.push({
      level: 'warn',
      category: 'supplied-dns',
      text:
        `Supplied DKIM key record has an issue: ${dkimKey.recordError}`
    });
  }

  return {
    mode: 'supplied-dns',
    supplied: true,
    spf,
    dmarc,
    dkimKey,
    findings
  };
}

function findObservedClientIp(receivedSpf, receivedHops) {
  const v = receivedSpf?.[0]?.props?.['client-ip'];

  if (v && isIpLiteral(v)) {
    return v;
  }

  const hopIp = [...(receivedHops || [])]
    .reverse()
    .find(h => h.from?.ip)
    ?.from?.ip;

  if (hopIp && isIpLiteral(hopIp)) {
    return hopIp;
  }

  return '';
}

function parseSpfRecord(record, clientIp) {
  const tokens = String(record || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  const result = {
    record,
    version: tokens[0]?.toLowerCase() === 'v=spf1' ? 'spf1' : '',
    mechanisms: [],
    unsupportedMechanisms: [],
    result: 'unknown',
    clientIp: clientIp || ''
  };

  if (result.version !== 'spf1') {
    return {
      ...result,
      result: 'invalid',
      recordError: 'Record does not begin with v=spf1.'
    };
  }

  let terminal = null;

  for (const token of tokens.slice(1)) {
    const m = token.match(
      /^([+?~-]?)([a-z][a-z0-9]*(?::[^ ]+)?)$/i
    );

    if (!m) continue;

    const qualifier = m[1] || '+';
    const body = m[2].toLowerCase();
    const base = body.split(':', 1)[0];

    result.mechanisms.push({
      qualifier,
      mechanism: base,
      value: body
    });

    if (['all', 'ip4', 'ip6'].includes(base)) {
      const local = evaluateSpfDirectMechanism(
        base,
        body,
        clientIp
      );

      if (local === true) {
        terminal = spfQualifierResult(qualifier);
        break;
      }

      if (base === 'all') {
        terminal = spfQualifierResult(qualifier);
        break;
      }
    } else {
      result.unsupportedMechanisms.push(base);
    }
  }

  result.result =
    terminal
    || (clientIp ? 'not_locally_determined' : 'no_client_ip');

  return result;
}

function evaluateSpfDirectMechanism(base, token, clientIp) {
  if (!clientIp) return false;

  if (base === 'ip4') {
    const cidr = token.slice(4);
    return isIpv4(clientIp) && ip4InCidr(clientIp, cidr);
  }

  if (base === 'ip6') {
    return isIpv6(clientIp) && ip6InCidr(clientIp, token.slice(4));
  }

  return false;
}

function spfQualifierResult(q) {
  return q === '+'
    ? 'pass'
    : q === '-'
      ? 'fail'
      : q === '~'
        ? 'softfail'
        : 'neutral';
}

function ip4InCidr(ip, cidr) {
  const [network, bitsText] = String(cidr || '').split('/');

  if (!isIpv4(network) || !isIpv4(ip)) return false;

  const bits =
    bitsText == null
      ? 32
      : Number(bitsText);

  if (!Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false;
  }

  const toInt = v =>
    v.split('.').reduce(
      (n, x) => ((n << 8) | Number(x)) >>> 0,
      0
    );

  const mask =
    bits === 0
      ? 0
      : (0xffffffff << (32 - bits)) >>> 0;

  return (
    (toInt(ip) & mask)
    ===
    (toInt(network) & mask)
  );
}

function ip6InCidr(ip, cidr) {
  const [networkText, bitsText] = String(cidr || '').split('/');
  if (!isIpv6(networkText) || !isIpv6(ip)) return false;

  const bits =
    bitsText == null
      ? 128
      : Number(bitsText);

  if (!Number.isInteger(bits) || bits < 0 || bits > 128) {
    return false;
  }

  const ipBytes = ipv6ToBytes(ip);
  const networkBytes = ipv6ToBytes(networkText);

  if (!ipBytes || !networkBytes) return false;

  const fullBytes = Math.floor(bits / 8);
  const remainingBits = bits % 8;

  for (let i = 0; i < fullBytes; i++) {
    if (ipBytes[i] !== networkBytes[i]) return false;
  }

  if (remainingBits) {
    const mask = 0xff << (8 - remainingBits);
    if (
      (ipBytes[fullBytes] & mask)
      !==
      (networkBytes[fullBytes] & mask)
    ) {
      return false;
    }
  }

  return true;
}

function ipv6ToBytes(value) {
  let v = String(value || '').toLowerCase().trim();

  if (!isIpv6(v)) return null;

  if (v.includes('::')) {
    const [left, right] = v.split('::');

    const leftParts = left ? left.split(':').filter(Boolean) : [];
    const rightParts = right ? right.split(':').filter(Boolean) : [];

    const missing = 8 - leftParts.length - rightParts.length;

    const parts = [
      ...leftParts,
      ...Array(Math.max(0, missing)).fill('0'),
      ...rightParts
    ];

    return ipv6PartsToBytes(parts);
  }

  return ipv6PartsToBytes(v.split(':'));
}

function ipv6PartsToBytes(parts) {
  if (parts.length !== 8) return null;

  const out = new Uint8Array(16);

  for (let i = 0; i < parts.length; i++) {
    const n = parseInt(parts[i] || '0', 16);

    if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
      return null;
    }

    out[i * 2] = (n >> 8) & 0xff;
    out[i * 2 + 1] = n & 0xff;
  }

  return out;
}

function parseDmarcRecord(record) {
  const tags = parseTagRecord(record);

  const out = {
    record,
    version: tags.v || '',
    p: (tags.p || '').toLowerCase(),
    sp: (tags.sp || '').toLowerCase(),
    adkim: (tags.adkim || 'r').toLowerCase(),
    aspf: (tags.aspf || 'r').toLowerCase(),
    pct: tags.pct || '100',
    rua: tags.rua || '',
    ruf: tags.ruf || '',
    tags,
    recordError: ''
  };

  if (out.version.toLowerCase() !== 'dmarc1') {
    out.recordError = 'Missing or invalid v=DMARC1.';
  }

  if (!['none', 'quarantine', 'reject'].includes(out.p)) {
    out.recordError =
      out.recordError
      || 'p= must be none, quarantine, or reject.';
  }

  if (!['r', 's'].includes(out.adkim)) {
    out.recordError =
      out.recordError
      || 'adkim= must be r or s.';
  }

  if (!['r', 's'].includes(out.aspf)) {
    out.recordError =
      out.recordError
      || 'aspf= must be r or s.';
  }

  const pct = Number(out.pct);

  if (!Number.isInteger(pct) || pct < 0 || pct > 100) {
    out.recordError =
      out.recordError
      || 'pct= must be an integer from 0 to 100.';
  }

  return out;
}

function parseDkimKeyRecord(record) {
  const tags = parseTagRecord(record);

  const out = {
    record,
    tags,
    version: tags.v || '',
    algorithm: (tags.k || 'rsa').toLowerCase(),
    publicKeyPresent: Boolean(tags.p),
    flags: tags.t || '',
    notes: tags.n || '',
    recordError: ''
  };

  if (
    out.version
    && out.version.toLowerCase() !== 'dkim1'
  ) {
    out.recordError =
      'Unexpected DKIM key version.';
  }

  if (!out.publicKeyPresent) {
    out.recordError =
      'The public-key record has no p= value.';
  }

  if (!['rsa', 'ed25519'].includes(out.algorithm)) {
    out.recordError =
      out.recordError
      || `Unsupported DKIM key algorithm for this metadata check: ${out.algorithm}.`;
  }

  if (
    out.publicKeyPresent
    && !/^[A-Za-z0-9+/=]+$/.test(out.tags.p)
  ) {
    out.recordError =
      out.recordError
      || 'p= contains characters that are not valid base64.';
  }

  return out;
}

function parseTagRecord(record) {
  const tags = {};

  for (const part of String(record || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;

    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();

    if (key) {
      tags[key] = value;
    }
  }

  return tags;
}

function renderVerification(v) {
  if (!v?.supplied) {
    return `
      <p class="small">
        No DNS evidence was supplied. Header-only analysis remains active.
      </p>
    `;
  }

  const cards = [];

  if (v.spf) {
    cards.push(
      stat(
        'Supplied SPF',
        `${v.spf.result}${v.spf.clientIp ? ` · client ${v.spf.clientIp}` : ''}`
      )
    );
  }

  if (v.dmarc) {
    cards.push(
      stat(
        'Supplied DMARC',
        `${v.dmarc.p || 'invalid'} · adkim=${v.dmarc.adkim}; aspf=${v.dmarc.aspf}`
      )
    );
  }

  if (v.dkimKey) {
    cards.push(
      stat(
        'Supplied DKIM key',
        `${v.dkimKey.algorithm}${v.dkimKey.publicKeyPresent ? ' · public key present' : ' · no public key'}`
      )
    );
  }

  const findings = v.findings?.length
    ? `
      <ul>
        ${v.findings.map(x => `
          <li>
            <strong>${escapeHtml(x.level.toUpperCase())}</strong>
            — ${escapeHtml(x.text)}
          </li>
        `).join('')}
      </ul>
    `
    : `
      <div class="status success">
        No inconsistencies were found between the supplied records and the locally evaluated evidence.
      </div>
    `;

  return `
    <div class="grid">${cards.join('')}</div>
    <p class="small">
      Supplied DNS data is user-provided evidence. It is not authenticated by the browser.
    </p>
    ${findings}
  `;
}

function renderDkimTable(a) {
  if (!a.dkimSigs.length && !a.arcSigs.length) {
    return '<p class="small">No DKIM-Signature or ARC-Seal metadata was found.</p>';
  }

  const dkimRows = a.dkimSigs.map((x, i) => `
    <tr>
      <td>DKIM #${i + 1}</td>
      <td class="mono">${escapeHtml(x.fields.d || '—')}</td>
      <td>${escapeHtml(x.fields.s || '—')}</td>
      <td>${escapeHtml(x.fields.a || '—')}</td>
      <td>${escapeHtml(x.fields.c || '—')}</td>
      <td>${escapeHtml(x.signedHeaders.join(', ') || '—')}</td>
      <td>${escapeHtml(x.warnings.join(' · ') || 'None')}</td>
    </tr>
  `).join('');

  const arcRows = a.arcSigs.map((x, i) => `
    <tr>
      <td>ARC #${i + 1}</td>
      <td class="mono">${escapeHtml(x.fields.d || '—')}</td>
      <td>${escapeHtml(x.fields.s || '—')}</td>
      <td>${escapeHtml(x.fields.a || '—')}</td>
      <td>${escapeHtml(x.fields.c || '—')}</td>
      <td>
        i=${escapeHtml(x.fields.i || '—')};
        cv=${escapeHtml(x.fields.cv || '—')}
      </td>
      <td>${escapeHtml(x.warnings.join(' · ') || 'None')}</td>
    </tr>
  `).join('');

  return `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Entry</th>
            <th>d=</th>
            <th>s=</th>
            <th>a=</th>
            <th>c=</th>
            <th>Coverage / chain</th>
            <th>Metadata checks</th>
          </tr>
        </thead>
        <tbody>${dkimRows}${arcRows}</tbody>
      </table>
    </div>
    <p class="small">
      DKIM <code>h=</code> coverage is shown from the supplied signature metadata.
      The signature itself was not cryptographically verified against a public key.
    </p>
  `;
}

function relationRow(label, rel) {
  if (!rel.available) {
    return `
      <tr>
        <td>${escapeHtml(label)}</td>
        <td>—</td>
        <td>—</td>
        <td>Not enough locally visible domain data</td>
      </tr>
    `;
  }

  const observed = rel.candidates?.length
    ? rel.candidates.map(x =>
        `${x.b} (${x.exact ? 'exact' : x.relaxed ? 'relaxed' : 'different'})`
      ).join('; ')
    : `${rel.b || ''}`;

  return `
    <tr>
      <td>${escapeHtml(label)}</td>
      <td>${rel.exact ? 'YES' : 'NO'}</td>
      <td>${rel.relaxed ? 'YES' : 'NO'}</td>
      <td class="mono">${escapeHtml(observed)}</td>
    </tr>
  `;
}

function formatAuthProperties(properties) {
  return Object.entries(properties || {})
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

function formatAddress(x) {
  if (!x?.address) return 'Not found';
  return x.name
    ? `${x.name} <${x.address}>`
    : x.address;
}

function stat(label, value) {
  return `
    <div class="stat">
      <span>${escapeHtml(label)}</span>
      <strong style="word-break:break-word">${escapeHtml(value)}</strong>
    </div>
  `;
}

function statusClass(state) {
  return state === 'good'
    ? 'success'
    : state === 'bad'
      ? 'danger'
      : state === 'warn'
        ? 'warning'
        : '';
}

function statusIcon(state) {
  return state === 'good'
    ? '&#10003;'
    : state === 'bad'
      ? '&#10007;'
      : state === 'warn'
        ? '&#9888;'
        : '&#8212;';
}

function sanitizeExport(a) {
  return {
    note:
      'Local header analysis only. No DNS, reputation, URL, geolocation, '
      + 'or remote validation was performed.',
    version: 2,
    summary: a.summary,
    checks: a.checks,

    identity: {
      from: a.from,
      returnPath: a.returnPath,
      replyTo: a.replyTo,
      sender: a.sender,
      subject: a.subject,
      date: a.date,
      dateParsed: a.dateParsed,
      messageId: a.messageId
    },

    relationships: a.identityRelationships,
    counts: a.counts,
    anomalies: a.anomalies,
    authentication: a.auth,
    authenticationConflicts: a.authConflicts,
    verification: a.verification,
    receivedSpf: a.receivedSpf,
    receivedHops: a.receivedHops,
    receivedOrder: a.receivedOrder,
    timeline: a.timestamp,
    dkimSignatures: a.dkimSigs,
    arcSeals: a.arcSigs,
    headers: a.headers,
    limitations: a.limitations
  };
}

function bindExports(a) {
  $('#mailExportJson').onclick = () => {
    downloadText(
      'email-header-analysis.json',
      JSON.stringify(sanitizeExport(a), null, 2),
      'application/json;charset=utf-8'
    );
  };

  $('#mailExportText').onclick = () => {
    downloadText(
      'email-header-analysis.txt',
      buildTextReport(a),
      'text/plain;charset=utf-8'
    );
  };

  $('#mailCopyReport').onclick = async () => {
    try {
      await navigator.clipboard.writeText(buildTextReport(a));

      const btn = $('#mailCopyReport');
      const old = btn.textContent;

      btn.textContent = 'Copied';

      setTimeout(() => {
        btn.textContent = old;
      }, 1200);
    } catch {
      $('#mailHeaderResult').insertAdjacentHTML(
        'afterbegin',
        '<div class="status warning">The browser did not allow clipboard access. Use the TXT export instead.</div>'
      );
    }
  };
}

function formatReceivedSpfProperties(props) {
  return Object.entries(props || {})
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

function buildTextReport(a) {
  const lines = [
    'Mail Header Analysis',
    '====================',
    '',
    `Summary: ${a.summary.title}`,
    a.summary.text,
    '',
    'Primary authentication:',
    ...a.checks
      .filter(c => ['SPF', 'DKIM', 'DMARC'].includes(c.label))
      .map(c => `- ${c.label}: ${c.value} — ${c.explanation}`),
    '',
    `DMARC alignment: ${a.checks.find(c => c.label === 'DMARC alignment')?.value || 'not established'}`,
    '',
    'Identity:',
    `- From: ${formatAddress(a.from)}`,
    `- Return-Path: ${formatAddress(a.returnPath)}`,
    `- Reply-To: ${formatAddress(a.replyTo)}`,
    `- Sender: ${formatAddress(a.sender)}`,
    `- Subject: ${a.subject || 'Not found'}`,
    `- Date: ${a.date || 'Not found'}`,
    `- Message-ID: ${a.messageId || 'Not found'}`,
    '',
    'Transport:',
    `- Received hops: ${a.receivedHops.length}`,
    a.timestamp.transitMs != null
      ? `- Observed Received span: ${formatDuration(a.timestamp.transitMs)}`
      : '- Observed Received span: not available',
    ...a.receivedHops.map(
      h =>
        `- Hop #${h.appearanceIndex}: from ${formatNodeText(h.from)} by ${formatNodeText(h.by)}`
        + `${h.protocol ? ` with ${h.protocol}` : ''}`
        + `${h.timestamp.valid ? ` at ${h.timestamp.date.toISOString()}` : ''}`
    ),
    '',
    'Warnings / notes:',
    ...(a.anomalies.length
      ? a.anomalies.map(
          x => `- ${x.level.toUpperCase()} [${x.category}]: ${x.text}`
        )
      : ['- None detected by the local heuristic pass.']),
    '',
    'Limitations:',
    ...a.limitations.map(x => `- ${x}`)
  ];

  return lines.join('\n');
}

function formatNodeText(node) {
  if (!node) return 'unknown';

  const base = node.host || 'unknown';

  return node.ip
    ? `${base} [${node.ip}]`
    : base;
}

async function readLocalTextFile(file) {
  if (file.size > LIMITS.maxCompoundFileBytes) {
    throw new Error(
      `The selected file is larger than ${formatBytes(LIMITS.maxCompoundFileBytes)}.`
    );
  }

  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);

  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return new TextDecoder('utf-16le').decode(bytes);
  }

  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return decodeUtf16Be(bytes);
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

  return m >= 0
    ? text.slice(0, m)
    : text;
}

async function parseMsgFile(file) {
  const buffer = await file.arrayBuffer();

  if (buffer.byteLength > LIMITS.maxCompoundFileBytes) {
    throw new Error(
      `The selected MSG file is larger than ${formatBytes(LIMITS.maxCompoundFileBytes)}.`
    );
  }

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
      note:
        `Loaded ${file.name} locally. PR_TRANSPORT_MESSAGE_HEADERS was extracted `
        + 'from the Outlook MSG container.'
    };
  }

  return {
    headers: buildSyntheticHeaders(properties),
    properties,
    note:
      `Loaded ${file.name} locally. The MSG did not expose Internet transport headers, `
      + 'so only common MAPI identity fields could be shown. SPF/DKIM/DMARC results '
      + 'cannot be inferred from those fields.'
  };
}

function buildSyntheticHeaders(p) {
  const lines = [];

  if (p.subject) {
    lines.push(`Subject: ${p.subject}`);
  }

  if (p.senderEmail || p.senderName) {
    lines.push(
      `From: ${p.senderName ? `${p.senderName} ` : ''}${p.senderEmail ? `<${p.senderEmail}>` : ''}`.trim()
    );
  }

  if (p.displayTo) lines.push(`To: ${p.displayTo}`);
  if (p.displayCc) lines.push(`Cc: ${p.displayCc}`);
  if (p.displayBcc) lines.push(`Bcc: ${p.displayBcc}`);
  if (p.replyTo) lines.push(`Reply-To: ${p.replyTo}`);
  if (p.messageId) lines.push(`Message-ID: ${p.messageId}`);

  return lines.join('\n');
}

function parseCompoundFile(buffer) {
  if (buffer.byteLength < 512) {
    throw new Error(
      'The selected Outlook MSG / Compound File is too small to contain a valid CFB header.'
    );
  }

  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  const sig = [
    0xd0, 0xcf, 0x11, 0xe0,
    0xa1, 0xb1, 0x1a, 0xe1
  ];

  for (let i = 0; i < sig.length; i++) {
    if (bytes[i] !== sig[i]) {
      throw new Error(
        'The selected file is not a valid Outlook .msg / Compound File.'
      );
    }
  }

  const sectorShift = view.getUint16(30, true);
  const miniSectorShift = view.getUint16(32, true);

  if (![9, 10, 11, 12].includes(sectorShift)) {
    throw new Error(
      `Unsupported Compound File sector size exponent: ${sectorShift}.`
    );
  }

  if (![6, 7].includes(miniSectorShift)) {
    throw new Error(
      `Unsupported Compound File mini-sector size exponent: ${miniSectorShift}.`
    );
  }

  const sectorSize = 1 << sectorShift;
  const miniSectorSize = 1 << miniSectorShift;

  const firstDirSector = view.getInt32(48, true);
  const miniCutoff = view.getUint32(56, true);
  const firstMiniFatSector = view.getInt32(60, true);
  const numMiniFatSectors = view.getUint32(64, true);
  const firstDifatSector = view.getInt32(68, true);
  const numDifatSectors = view.getUint32(72, true);

  if (
    sectorSize + 512 > bytes.length
    && bytes.length > 512
  ) {
    throw new Error(
      'Compound File sector geometry is inconsistent with the file size.'
    );
  }

  const fatSectors = [];

  for (let i = 0; i < 109; i++) {
    const sid = view.getInt32(76 + i * 4, true);
    if (sid >= 0) fatSectors.push(sid);
  }

  let difat = firstDifatSector;
  const seenDifat = new Set();

  for (
    let n = 0;
    n < Math.min(numDifatSectors, 4096) && difat >= 0;
    n++
  ) {
    if (seenDifat.has(difat)) {
      throw new Error('Compound File DIFAT contains a cycle.');
    }

    seenDifat.add(difat);

    const base = 512 + difat * sectorSize;

    if (!rangeWithin(base, sectorSize, bytes.length)) {
      throw new Error(
        'Compound File DIFAT sector is outside the file.'
      );
    }

    for (let i = 0; i < (sectorSize / 4) - 1; i++) {
      const sid = view.getInt32(base + i * 4, true);
      if (sid >= 0) fatSectors.push(sid);
    }

    difat = view.getInt32(
      base + sectorSize - 4,
      true
    );
  }

  const fat = [];

  for (const sid of fatSectors) {
    const base = 512 + sid * sectorSize;

    if (!rangeWithin(base, sectorSize, bytes.length)) {
      throw new Error(
        'Compound File FAT sector is outside the file.'
      );
    }

    for (let i = 0; i < sectorSize / 4; i++) {
      fat.push(
        view.getInt32(base + i * 4, true)
      );
    }
  }

  const chain = start => {
    const out = [];
    const seen = new Set();

    let cur = start;

    while (
      cur >= 0
      && cur !== 0xfffffffe
      && cur !== 0xffffffff
      && !seen.has(cur)
      && out.length < LIMITS.maxCompoundChain
    ) {
      if (cur >= fat.length) {
        throw new Error(
          'Compound File sector chain references a sector outside the FAT.'
        );
      }

      seen.add(cur);
      out.push(cur);
      cur = fat[cur];
    }

    if (out.length >= LIMITS.maxCompoundChain) {
      throw new Error(
        'Compound File sector chain exceeds the local safety limit.'
      );
    }

    return out;
  };

  const readRegular = (start, size) => {
    if (!size || start < 0) {
      return new Uint8Array();
    }

    if (size > LIMITS.maxCompoundFileBytes) {
      throw new Error(
        'Compound File stream exceeds the local safety limit.'
      );
    }

    const ids = chain(start);
    const out = new Uint8Array(
      Math.min(size, ids.length * sectorSize)
    );

    let pos = 0;

    for (const sid of ids) {
      const base = 512 + sid * sectorSize;
      const take = Math.min(
        sectorSize,
        out.length - pos
      );

      if (take <= 0) break;

      if (!rangeWithin(base, take, bytes.length)) {
        throw new Error(
          'Compound File stream points outside the file.'
        );
      }

      out.set(
        bytes.subarray(base, base + take),
        pos
      );

      pos += take;
    }

    return out;
  };

  const dirIds = chain(firstDirSector);

  const dirChunks = dirIds.map(s => {
    const base = 512 + s * sectorSize;

    if (!rangeWithin(base, sectorSize, bytes.length)) {
      throw new Error(
        'Compound File directory sector is outside the file.'
      );
    }

    return bytes.slice(
      base,
      base + sectorSize
    );
  });

  const dir = concatBytes(dirChunks);
  const entries = [];

  for (
    let off = 0;
    off + 128 <= dir.length;
    off += 128
  ) {
    const nameLen = viewAt(
      dir,
      off + 64,
      2,
      'u16'
    );

    if (nameLen < 2) {
      entries.push(null);
      continue;
    }

    const safeNameLen = Math.min(
      nameLen - 2,
      62
    );

    const name = decodeUtf16LE(
      dir.slice(
        off,
        off + safeNameLen
      )
    );

    const type = dir[off + 66];
    const left = viewAt(
      dir,
      off + 68,
      4,
      'i32'
    );
    const right = viewAt(
      dir,
      off + 72,
      4,
      'i32'
    );
    const child = viewAt(
      dir,
      off + 76,
      4,
      'i32'
    );
    const start = viewAt(
      dir,
      off + 116,
      4,
      'i32'
    );
    const sizeLow = viewAt(
      dir,
      off + 120,
      4,
      'u32'
    );
    const sizeHigh = viewAt(
      dir,
      off + 124,
      4,
      'u32'
    );

    const size = sizeHigh
      ? (sizeHigh * 0x100000000 + sizeLow)
      : sizeLow;

    if (size > LIMITS.maxCompoundFileBytes) {
      throw new Error(
        'Compound File directory contains an oversized stream.'
      );
    }

    entries.push({
      name,
      type,
      left,
      right,
      child,
      start,
      size
    });

    if (entries.length > LIMITS.maxCompoundEntries) {
      throw new Error(
        'Compound File directory exceeds the local safety limit.'
      );
    }
  }

  const root = entries.findIndex(
    e => e && e.type === 5
  );

  if (root < 0) {
    throw new Error(
      'Compound File root directory entry was not found.'
    );
  }

  const rootEntry = entries[root];

  const rootMiniStream =
    rootEntry && rootEntry.start >= 0
      ? readRegular(
          rootEntry.start,
          rootEntry.size
        )
      : new Uint8Array();

  const miniFat = [];

  if (firstMiniFatSector >= 0 && numMiniFatSectors) {
    for (
      const sid of chain(firstMiniFatSector)
        .slice(
          0,
          Math.min(numMiniFatSectors, 4096)
        )
    ) {
      const base = 512 + sid * sectorSize;

      if (!rangeWithin(base, sectorSize, bytes.length)) {
        throw new Error(
          'Compound File mini-FAT sector is outside the file.'
        );
      }

      for (let i = 0; i < sectorSize / 4; i++) {
        miniFat.push(
          view.getInt32(
            base + i * 4,
            true
          )
        );
      }
    }
  }

  const readMini = (start, size) => {
    if (!size || start < 0 || !miniFat.length) {
      return new Uint8Array();
    }

    const chunks = [];
    const seen = new Set();

    let cur = start;
    let count = 0;

    while (
      cur >= 0
      && cur !== 0xfffffffe
      && cur !== 0xffffffff
      && !seen.has(cur)
      && count * miniSectorSize < size
    ) {
      if (cur >= miniFat.length) {
        throw new Error(
          'Compound File mini-stream references a sector outside the mini-FAT.'
        );
      }

      seen.add(cur);

      const base = cur * miniSectorSize;

      if (base >= rootMiniStream.length) {
        throw new Error(
          'Compound File mini-stream points outside the root mini-stream.'
        );
      }

      chunks.push(
        rootMiniStream.slice(
          base,
          base + miniSectorSize
        )
      );

      cur = miniFat[cur];
      count++;

      if (count > LIMITS.maxCompoundChain) {
        throw new Error(
          'Compound File mini-stream chain exceeds the local safety limit.'
        );
      }
    }

    return concatBytes(chunks).slice(0, size);
  };

  const streams = new Map();
  const visitedNodes = new Set();

  const visit = (id, path, depth = 0) => {
    if (id < 0 || !entries[id]) return;

    if (depth > LIMITS.maxCompoundDepth) {
      throw new Error(
        'Compound File directory nesting exceeds the local safety limit.'
      );
    }

    const visitKey = `${id}|${path}`;

    if (visitedNodes.has(visitKey)) {
      return;
    }

    visitedNodes.add(visitKey);

    if (visitedNodes.size > LIMITS.maxCompoundEntries * 2) {
      throw new Error(
        'Compound File directory traversal exceeded the local safety limit.'
      );
    }

    const e = entries[id];

    visit(e.left, path, depth + 1);

    const current =
      path
        ? `${path}/${e.name}`
        : e.name;

    if (e.type === 1 || e.type === 5) {
      visit(e.child, current, depth + 1);
    } else if (e.type === 2) {
      const data =
        e.size < miniCutoff
          ? readMini(e.start, e.size)
          : readRegular(e.start, e.size);

      streams.set(current, data);
    }

    visit(e.right, path, depth + 1);
  };

  if (root >= 0) {
    visit(entries[root].child, '');
  }

  return { streams };
}

function extractMsgStringProperties(streams) {
  const strings = {};

  for (const [path, data] of streams) {
    const m = path.match(
      /__substg1\.0_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})$/
    );

    if (!m) continue;

    const prop = m[1].toLowerCase();
    const type = m[2].toLowerCase();

    if (type === '001f') {
      strings[prop] =
        decodeUtf16LE(data).replace(/\u0000+$/, '');
    } else if (type === '001e') {
      strings[prop] =
        decodeWindows1252(data).replace(/\u0000+$/, '');
    }
  }

  return strings;
}

function viewAt(bytes, offset, size, kind) {
  const v = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength
  );

  return kind === 'u16'
    ? v.getUint16(offset, true)
    : kind === 'u32'
      ? v.getUint32(offset, true)
      : v.getInt32(offset, true);
}

function concatBytes(chunks) {
  const total = chunks.reduce(
    (n, c) => n + c.length,
    0
  );

  const out = new Uint8Array(total);
  let pos = 0;

  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }

  return out;
}

function normalizeHeaderWhitespace(value) {
  return String(value || '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/[\t ]+/g, ' ')
    .trim();
}

function splitOutsideComments(input, delimiter) {
  const out = [];
  let start = 0;
  let quote = null;
  let commentDepth = 0;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const prev = input[i - 1];

    if (quote) {
      if (ch === quote && prev !== '\\') {
        quote = null;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }

    if (ch === '(') {
      commentDepth++;
      continue;
    }

    if (ch === ')' && commentDepth > 0) {
      commentDepth--;
      continue;
    }

    if (
      commentDepth === 0
      && input.startsWith(delimiter, i)
    ) {
      out.push(
        input.slice(start, i)
      );

      start =
        i + delimiter.length;

      i += delimiter.length - 1;
    }
  }

  out.push(
    input.slice(start)
  );

  return out;
}

function splitOutsideQuotes(input, delimiter) {
  return splitOutsideComments(
    input,
    delimiter
  );
}

function splitAddressList(input) {
  const out = [];
  let start = 0;
  let quote = null;
  let commentDepth = 0;
  let angleDepth = 0;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const prev = input[i - 1];

    if (quote) {
      if (ch === quote && prev !== '\\') {
        quote = null;
      }
      continue;
    }

    if (ch === '"') {
      quote = ch;
      continue;
    }

    if (ch === '(') {
      commentDepth++;
      continue;
    }

    if (ch === ')' && commentDepth > 0) {
      commentDepth--;
      continue;
    }

    if (!commentDepth && ch === '<') {
      angleDepth++;
    }

    if (
      !commentDepth
      && ch === '>'
      && angleDepth > 0
    ) {
      angleDepth--;
    }

    if (
      !commentDepth
      && angleDepth === 0
      && ch === ','
    ) {
      out.push(
        input.slice(start, i).trim()
      );

      start = i + 1;
    }
  }

  out.push(
    input.slice(start).trim()
  );

  return out.filter(Boolean);
}

function removeComments(value) {
  let input = String(value || '');
  let result = '';
  let depth = 0;
  let quote = null;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const prev = input[i - 1];

    if (quote) {
      result += ch;

      if (ch === quote && prev !== '\\') {
        quote = null;
      }

      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      result += ch;
      continue;
    }

    if (ch === '(') {
      depth++;
      continue;
    }

    if (ch === ')' && depth > 0) {
      depth--;
      continue;
    }

    if (!depth) {
      result += ch;
    }
  }

  return result;
}

function normalizeDomain(value) {
  let d = String(value || '')
    .trim()
    .toLowerCase();

  d = d
    .replace(/^.*@/, '')
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');

  d = d.replace(
    /[^a-z0-9._:-]+$/g,
    ''
  );

  return d;
}

function getDomain(address) {
  const i = String(address || '')
    .lastIndexOf('@');

  return i > -1
    ? normalizeDomain(
        address.slice(i + 1)
      )
    : '';
}

function normalizeHostname(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
}

function looksLikeHostname(value) {
  const v = String(value || '')
    .replace(
      /^[\[(]|[\]),;:]$/g,
      ''
    );

  return (
    /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(v)
    && /[A-Za-z]/.test(v)
  );
}

function isIpLiteral(value) {
  return isIpv4(value) || isIpv6(value);
}

function findFirstIp(text) {
  const ipv6 = text.match(
    /\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b/
  );

  if (ipv6 && isIpv6(ipv6[0])) {
    return ipv6[0];
  }

  const ipv4 = text.match(
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/
  );

  if (ipv4 && isIpv4(ipv4[0])) {
    return ipv4[0];
  }

  return '';
}

function isIpv4(value) {
  const parts = String(value || '').split('.');

  return (
    parts.length === 4
    && parts.every(
      x => /^\d{1,3}$/.test(x)
        && Number(x) <= 255
    )
  );
}

function isIpv6(value) {
  const v = String(value || '').trim();

  if (!v.includes(':')) return false;
  if (!/^[0-9a-f:]+$/i.test(v)) return false;

  const double = (
    v.match(/::/g) || []
  ).length;

  if (double > 1) return false;

  const parts = v.split(':');

  if (double === 0) {
    return parts.length === 8;
  }

  return (
    parts.length <= 8
    && parts.some(Boolean) === true
  );
}

function isSpecialOrPrivateIp(ip) {
  if (isIpv4(ip)) {
    const [a, b] = ip
      .split('.')
      .map(Number);

    return (
      a === 10
      || a === 127
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0)
      || (a === 198 && (b === 18 || b === 19 || b === 51))
      || (a === 203 && b === 0)
      || (a >= 224)
    );
  }

  if (isIpv6(ip)) {
    const v = ip.toLowerCase();

    return (
      v === '::1'
      || v === '::'
      || v.startsWith('fe80:')
      || v.startsWith('fc')
      || v.startsWith('fd')
    );
  }

  return false;
}

function parseMailDate(value) {
  const raw = String(value || '').trim();

  if (!raw) {
    return {
      valid: false,
      date: null,
      raw: ''
    };
  }

  const time = Date.parse(raw);

  if (Number.isNaN(time)) {
    return {
      valid: false,
      date: null,
      raw
    };
  }

  const date = new Date(time);

  return {
    valid: true,
    date,
    raw
  };
}

function parseEpochSeconds(value) {
  const n = Number(
    String(value || '').trim()
  );

  if (!Number.isFinite(n) || n <= 0) {
    return null;
  }

  return new Date(n * 1000);
}

function normalizeMessageId(value) {
  const v = String(value || '').trim();

  if (!v) return '';

  const m = v.match(/<[^<>]+>/);

  return m ? m[0] : v;
}

function stripOuterQuotes(value) {
  const v = String(value ?? '').trim();

  if (
    v.length >= 2
    && (
      (
        v[0] === '"'
        && v[v.length - 1] === '"'
      )
      || (
        v[0] === "'"
        && v[v.length - 1] === "'"
      )
    )
  ) {
    return v.slice(1, -1);
  }

  return v;
}

function decodeMimeWords(value) {
  const input = String(value || '');

  return input.replace(
    /=\?([^?\s]+)\?([bBqQ])\?([^?]*)\?=/g,
    (full, charset, encoding, payload) => {
      try {
        const bytes =
          encoding.toLowerCase() === 'b'
            ? base64ToBytes(payload)
            : latin1ToBytes(
                decodeQuotedPrintableWord(payload)
              );

        return decodeBytes(
          bytes,
          charset
        );
      } catch {
        return full;
      }
    }
  );
}

function decodeQuotedPrintableWord(value) {
  return String(value || '')
    .replace(/_/g, ' ')
    .replace(
      /=([0-9A-Fa-f]{2})/g,
      (_, hex) =>
        String.fromCharCode(
          parseInt(hex, 16)
        )
    );
}

function base64ToBytes(value) {
  const clean = String(value || '')
    .replace(/\s+/g, '');

  const bin = atob(clean);
  const out = new Uint8Array(bin.length);

  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }

  return out;
}

function latin1ToBytes(value) {
  const s = String(value || '');
  const out = new Uint8Array(s.length);

  for (let i = 0; i < out.length; i++) {
    out[i] = s.charCodeAt(i) & 0xff;
  }

  return out;
}

function decodeBytes(bytes, charset) {
  const normalized = String(
    charset || ''
  ).toLowerCase();

  const decoderCharset =
    normalized === 'iso-8859-1'
    || normalized === 'latin1'
      ? 'windows-1252'
      : normalized;

  try {
    return new TextDecoder(
      decoderCharset
    ).decode(bytes);
  } catch {
    return new TextDecoder(
      'utf-8'
    ).decode(bytes);
  }
}

function decodeUtf16Be(bytes) {
  const hasBom =
    bytes.length >= 2
    && bytes[0] === 0xfe
    && bytes[1] === 0xff;

  const start = hasBom ? 2 : 0;

  const copy = new Uint8Array(
    Math.max(
      0,
      bytes.length - start
    )
  );

  for (
    let i = start, j = 0;
    i + 1 < bytes.length;
    i += 2, j += 2
  ) {
    copy[j] = bytes[i + 1];
    copy[j + 1] = bytes[i];
  }

  return new TextDecoder(
    'utf-16le'
  ).decode(copy);
}

function utf8ByteLength(value) {
  return new TextEncoder()
    .encode(String(value || ''))
    .length;
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;

  if (n < 1024 ** 2) {
    return `${(n / 1024).toFixed(1)} KiB`;
  }

  if (n < 1024 ** 3) {
    return `${(n / 1024 ** 2).toFixed(1)} MiB`;
  }

  return `${(n / 1024 ** 3).toFixed(1)} GiB`;
}

function formatDuration(ms) {
  if (!Number.isFinite(ms)) {
    return 'unknown';
  }

  const sign = ms < 0 ? '-' : '';

  let seconds = Math.round(
    Math.abs(ms) / 1000
  );

  const days = Math.floor(
    seconds / 86400
  );

  seconds %= 86400;

  const hours = Math.floor(
    seconds / 3600
  );

  seconds %= 3600;

  const minutes = Math.floor(
    seconds / 60
  );

  seconds %= 60;

  const parts = [];

  if (days) parts.push(`${days}d`);
  if (hours) parts.push(`${hours}h`);
  if (minutes) parts.push(`${minutes}m`);

  if (seconds || !parts.length) {
    parts.push(`${seconds}s`);
  }

  return sign + parts.join(' ');
}

function formatSignedDuration(ms) {
  return ms >= 0
    ? `+${formatDuration(ms)}`
    : formatDuration(ms);
}

function displayHeaderName(name) {
  return String(name || '')
    .split('-')
    .map(
      x => x
        ? x[0].toUpperCase() + x.slice(1)
        : x
    )
    .join('-');
}

function rangeWithin(start, length, total) {
  return (
    Number.isSafeInteger(start)
    && Number.isSafeInteger(length)
    && start >= 0
    && length >= 0
    && start + length <= total
  );
}

function decodeUtf16LE(bytes) {
  return new TextDecoder('utf-16le').decode(bytes);
}

function decodeWindows1252(bytes) {
  try {
    return new TextDecoder('windows-1252').decode(bytes);
  } catch {
    return new TextDecoder('iso-8859-1').decode(bytes);
  }
}

export const headerAnalyzerInternals = {
  parseHeaders,
  parseAuthResults,
  parseReceivedChain,
  parseReceivedHop,
  parseAuthSignature,
  parseAddressHeader,
  analyzeReceivedOrder,
  analyzeHeaderIntegrity,
  detectAuthenticationConflicts,
  deriveAlignment,
  getOrganizationalDomain,
  isRelaxedAligned,
  decodeMimeWords,
  parseMailDate,
  analyzeHeaders,
  getDomain,
  analyzeSuppliedDnsEvidence,
  parseSpfRecord,
  parseDmarcRecord,
  parseDkimKeyRecord,
  parseCompoundFile
};