import { $, escapeHtml, downloadText } from './utils.js';

function badge(kind, text) {
  const cls = kind === 'good' ? 'good' : kind === 'bad' ? 'bad' : kind === 'warn' ? 'warn' : 'neutral';
  return `<span class="status ${cls}">${escapeHtml(text)}</span>`;
}

function hostInfo(hostname) {
  const lower = hostname.toLowerCase().replace(/\.$/, '');
  const isIpv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(lower);
  const isIpv6 = lower.includes(':') && /^[0-9a-f:]+$/i.test(lower);
  const labels = lower ? lower.split('.') : [];
  const suspiciousTlds = new Set(['zip','mov','click','top','xyz','work','download','stream','country','gq','tk','ml','ga','cf']);
  const punycode = labels.some(x => x.startsWith('xn--'));
  const tld = !isIpv4 && !isIpv6 && labels.length > 1 ? labels.at(-1) : '';
  const manySubdomains = labels.length >= 5;
  const longHost = lower.length > 80;
  const privateIp = isIpv4 && (() => {
    const p = lower.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31);
  })();
  return { lower, labels, isIpv4, isIpv6, punycode, tld, manySubdomains, longHost, privateIp };
}

function analyze(raw) {
  const findings = [];
  let url;
  try {
    url = new URL(raw.trim());
  } catch {
    return { valid: false, error: 'This is not a valid URL that the browser URL parser can understand.' };
  }

  const h = hostInfo(url.hostname);
  const rawLower = raw.toLowerCase();
  const host = h.lower;
  const queryParams = [...url.searchParams.keys()];
  const decodedPath = decodeURIComponentSafe(url.pathname);
  const decodedSearch = decodeURIComponentSafe(url.search);
  const entireDecoded = decodeURIComponentSafe(raw);

  const add = (severity, title, detail) => findings.push({ severity, title, detail });

  if (url.protocol !== 'https:') {
    add(url.protocol === 'http:' ? 'high' : 'medium', 'Connection is not HTTPS', 'The URL does not use HTTPS. Credentials or content could be exposed or modified in transit.');
  } else {
    add('good', 'HTTPS is used', 'The URL uses HTTPS. This protects the connection in transit, but does not prove that the website itself is trustworthy.');
  }

  if (url.username || url.password) {
    add('high', 'Embedded credentials', 'The URL contains user-info before the hostname. Attackers can abuse this to make a malicious host look like a trusted name.');
  }

  if (h.punycode) {
    add('high', 'Punycode / internationalized hostname', 'The hostname contains xn-- labels. These can be legitimate, but they are also commonly involved in look-alike / homograph attacks.');
  }

  if (h.isIpv4 || h.isIpv6) {
    add('medium', 'IP address used as host', `The destination is an IP address (${url.hostname}) rather than a normal domain name. This can be legitimate, but is common in direct malware/phishing links.`);
  }

  if (h.privateIp) add('warn', 'Private IPv4 address', 'The hostname is a private/local IPv4 address. This is generally meaningful only on an internal network and is not a normal public website destination.');
  if (h.manySubdomains) add('medium', 'Many subdomains', `The hostname has ${h.labels.length} labels. Deep nesting is not inherently malicious, but attackers often use long subdomains to hide the actual registrable domain.`);
  if (h.longHost) add('medium', 'Very long hostname', 'The hostname is unusually long and may be trying to obscure the meaningful domain or pack tracking/attack data into the host name.');
  if (h.tld && suspiciousTlds.has(h.tld)) add('medium', 'Higher-risk / frequently abused TLD', `The top-level domain .${h.tld} is frequently seen in low-cost or abused domains. TLD alone is never proof of maliciousness.`);

  const hostTokens = host.split(/[.\-_]/).filter(Boolean);
  const brandWords = ['microsoft','office365','office','outlook','google','gmail','apple','icloud','paypal','amazon','docusign','dropbox','adobe','github','linkedin','facebook','instagram','okta','salesforce','onedrive','sharepoint'];
  const brandHits = brandWords.filter(b => hostTokens.includes(b) || host.includes(`${b}-`) || host.includes(`-${b}`));
  if (brandHits.length && !['microsoftonline.com','office.com','outlook.com','google.com','gmail.com','apple.com','icloud.com','paypal.com','amazon.com','docusign.com','dropbox.com','adobe.com','github.com','linkedin.com','facebook.com','instagram.com','okta.com','salesforce.com','onedrive.com','sharepoint.com'].some(x => host === x || host.endsWith(`.${x}`))) {
    add('high', 'Brand name appears in an unverified hostname', `The hostname contains a brand-like token (${brandHits.join(', ')}), but the parser cannot establish that the domain is owned by that brand.`);
  }

  if (/%[0-9a-f]{2}/i.test(url.hostname)) add('high', 'Percent-encoded hostname content', 'Percent encoding in hostnames is unusual and can be used to disguise URL content.');

  const suspiciousPath = /(login|signin|verify|verification|secure|account|update|password|reset|invoice|payment|wallet|crypto|unlock|mfa|2fa)/i.test(decodedPath);
  if (suspiciousPath) add('medium', 'Sensitive action words in path', 'The path contains terms commonly used in credential theft, payment scams, account takeover, or fake verification pages.');

  const executable = /\.(exe|scr|msi|bat|cmd|ps1|vbs|js|jar|hta|dll|iso|img|lnk)(?:$|[?#])/i.test(decodedPath);
  if (executable) add('high', 'Potential executable download', 'The path ends in a file type commonly used to deliver executable or script content.');

  if (/https?:\/\//i.test(decodedPath)) add('high', 'Nested URL in path', 'The path itself contains another URL. This pattern is commonly used by redirectors, open redirects, and phishing links.');

  const encCount = (raw.match(/%[0-9a-f]{2}/gi) || []).length;
  if (encCount >= 5) add('medium', 'Heavy percent encoding', `The URL contains ${encCount} percent-encoded bytes. Encoding is normal in URLs, but unusually dense encoding can obscure the destination or payload.`);
  if (/\b(?:javascript|data|vbscript):/i.test(raw)) add('high', 'Script/data URL scheme detected', 'A script-oriented URL scheme is present. These should be treated as unsafe unless there is a very specific reason for them.');

  const params = queryParams.map(k => k.toLowerCase());
  const redirectKeys = params.filter(k => /^(url|uri|u|redirect|redirect_uri|return|returnurl|next|dest|destination|continue|target|link|goto|callback)$/i.test(k));
  if (redirectKeys.length) add('medium', 'Redirect-style query parameter', `The query contains redirect-like parameter(s): ${redirectKeys.join(', ')}. This can be legitimate, but is commonly abused to hide the final destination.`);

  if (/(password|passwd|pwd|token|auth|session|secret|apikey|api_key|access_token|code)=/i.test(url.search)) add('high', 'Sensitive-looking query parameter', 'The query string appears to contain credentials, tokens, authorization codes, or secrets. Avoid sharing this URL because it may expose sensitive information.');

  if (queryParams.length > 15) add('medium', 'Large query string', `The URL contains ${queryParams.length} query parameters. Large parameter sets can be normal for tracking, but can also be used to obscure the real purpose of a link.`);
  if (/utm_|gclid|fbclid|mc_cid|mc_eid/i.test(url.search)) add('info', 'Tracking parameters present', 'The URL contains common advertising/campaign tracking parameters. Tracking is not malicious by itself.');

  if (decodedPath !== url.pathname || decodedSearch !== url.search) add('info', 'Encoded characters can change how the URL appears', 'Some characters were percent-decoded for analysis. Compare the displayed URL carefully with the encoded representation.');
  if (entireDecoded !== raw) add('info', 'Percent-decoding changes the visible text', 'The URL contains encoded characters that become different characters after decoding. This can be used for obfuscation.');

  if (url.port && !['80','443'].includes(url.port)) add('medium', 'Non-standard port', `The URL explicitly uses port ${url.port}. This can be legitimate for internal applications, but deserves attention on unsolicited links.`);
  if (url.hash) add('info', 'Fragment present', 'The fragment (#...) is normally processed by the browser after the HTTP request and is often used for client-side navigation or tracking. It is not sent to the server in a standard HTTP request.');

  const high = findings.filter(x => x.severity === 'high').length;
  const medium = findings.filter(x => x.severity === 'medium').length;
  const warnings = findings.filter(x => x.severity === 'warn').length;
  const good = findings.filter(x => x.severity === 'good').length;

  let verdict = 'CHECK';
  let verdictClass = 'warn';
  if (high > 0) { verdict = 'SUSPICIOUS'; verdictClass = 'bad'; }
  else if (medium >= 2 || warnings > 0) { verdict = 'CAUTION'; verdictClass = 'warn'; }
  else if (good > 0 && medium === 0) { verdict = 'NO OBVIOUS URL RED FLAGS'; verdictClass = 'good'; }

  return {
    valid: true,
    raw,
    url,
    host: h,
    queryParams,
    decodedPath,
    decodedSearch,
    findings,
    counts: { high, medium, warnings, good },
    verdict,
    verdictClass,
  };
}

function decodeURIComponentSafe(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

function row(label, value, note='') {
  return `<tr><th>${escapeHtml(label)}</th><td class="mono">${escapeHtml(value || '—')}</td><td>${escapeHtml(note)}</td></tr>`;
}

function renderResult(result) {
  if (!result.valid) return `<div class="card"><h3>Invalid URL</h3><p>${escapeHtml(result.error)}</p></div>`;

  const findings = result.findings.map(f => {
    const icon = f.severity === 'good' ? '&#10003;' : f.severity === 'high' ? '&#10007;' : f.severity === 'medium' || f.severity === 'warn' ? '&#9888;' : '&#8505;';
    const label = f.severity === 'good' ? 'GOOD' : f.severity === 'high' ? 'HIGH RISK' : f.severity === 'medium' || f.severity === 'warn' ? 'CHECK' : 'INFO';
    return `<div class="finding ${f.severity}"><span class="finding-icon">${icon}</span><div><strong>${escapeHtml(label)} — ${escapeHtml(f.title)}</strong><div>${escapeHtml(f.detail)}</div></div></div>`;
  }).join('');

  const u = result.url;
  const h = result.host;
  const parts = [
    ['Scheme', u.protocol, 'The protocol/scheme determines how the resource is addressed. HTTPS is generally expected for public web links.'],
    ['Username', u.username, 'Credentials before @ are unusual on modern web links and can be used to disguise the real hostname.'],
    ['Password', u.password ? '••••••' : '', 'Password components in URLs should be treated as sensitive.'],
    ['Hostname', u.hostname, 'The actual network host parsed by the browser. This is the most important domain component to inspect.'],
    ['Port', u.port || '(default)', 'Explicit non-standard ports deserve extra attention.'],
    ['Path', u.pathname, 'The resource/path requested from the host.'],
    ['Query', u.search || '', 'Parameters after ?. These can contain tracking, redirects, identifiers, or sensitive data.'],
    ['Fragment', u.hash || '', 'The #fragment is normally handled by the browser and is not sent in the HTTP request.'],
  ];
  const rows = parts.map(x => row(x[0], x[1], x[2])).join('');

  const hostRows = [
    row('Normalized host', h.lower),
    row('Labels', h.labels.join(' | ')),
    row('IP address?', h.isIpv4 ? 'IPv4' : h.isIpv6 ? 'IPv6' : 'No'),
    row('Punycode?', h.punycode ? 'Yes' : 'No'),
    row('Top-level domain', h.tld || '—'),
    row('Deep subdomains?', h.manySubdomains ? 'Yes' : 'No'),
  ].join('');

  const params = result.queryParams.length ? result.queryParams.map(k => `<span class="tag mono">${escapeHtml(k)}</span>`).join(' ') : '<span class="muted">No query parameters</span>';

  return `
    <section class="card">
      <div class="verdict ${result.verdictClass}"><span class="verdict-icon">${result.verdictClass === 'good' ? '&#10003;' : result.verdictClass === 'bad' ? '&#10007;' : '&#9888;'}</span><div><strong>${escapeHtml(result.verdict)}</strong><div>Heuristic URL analysis only — this does not prove that the destination is safe or malicious.</div></div></div>
      <h3>Quick security view</h3>
      <div class="findings">${findings || '<p>No specific indicators were triggered.</p>'}</div>
    </section>

    <section class="card">
      <h3>URL parts</h3>
      <table class="data-table"><thead><tr><th>Part</th><th>Value</th><th>What it means</th></tr></thead><tbody>${rows}</tbody></table>
    </section>

    <section class="card">
      <h3>Hostname analysis</h3>
      <table class="data-table"><tbody>${hostRows}</tbody></table>
      <p><strong>Important:</strong> a subdomain such as <span class="mono">login.example.com</span> is still controlled by <span class="mono">example.com</span>, whereas <span class="mono">example.com.evil.test</span> is controlled by <span class="mono">evil.test</span>.</p>
    </section>

    <section class="card">
      <h3>Query parameters</h3>
      <div>${params}</div>
    </section>
  `;
}

export function renderUrlAnalyzer(app) {
  app.innerHTML = `
    <section class="card">
      <h2>URL Authenticity / Forensics Analyzer</h2>
      <p>Paste a URL to inspect it without visiting it. Everything is parsed and analyzed locally in this browser.</p>
      <label for="urlInput">URL</label>
      <textarea id="urlInput" rows="4" placeholder="https://example.com/path?next=https%3A%2F%2Fexample.org"></textarea>
      <div class="toolbar">
        <button class="btn primary" id="analyzeUrl">Analyze URL</button>
        <button class="btn" id="clearUrl">Clear</button>
        <button class="btn" id="copyUrlReport">Copy report</button>
        <button class="btn" id="downloadUrlReport">Download report</button>
      </div>
      <p class="muted">No DNS lookups, HTTP requests, reputation checks, redirect following, or external APIs are used.</p>
    </section>
    <div id="urlResults"></div>
  `;

  let lastResult = null;
  const input = $('#urlInput');
  const results = $('#urlResults');

  const run = () => {
    lastResult = analyze(input.value);
    results.innerHTML = renderResult(lastResult);
  };

  $('#analyzeUrl').onclick = run;
  $('#clearUrl').onclick = () => { input.value = ''; results.innerHTML = ''; lastResult = null; input.focus(); };
  $('#copyUrlReport').onclick = async () => {
    if (!lastResult) return;
    await copyText(JSON.stringify(safeExport(lastResult), null, 2));
  };
  $('#downloadUrlReport').onclick = () => {
    if (!lastResult) return;
    downloadText('url-analysis.json', JSON.stringify(safeExport(lastResult), null, 2), 'application/json');
  };
  input.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run(); });
}

function safeExport(result) {
  return {
    raw: result.raw,
    verdict: result.verdict,
    counts: result.counts,
    url: {
      href: result.url.href,
      protocol: result.url.protocol,
      usernamePresent: Boolean(result.url.username),
      passwordPresent: Boolean(result.url.password),
      hostname: result.url.hostname,
      port: result.url.port,
      pathname: result.url.pathname,
      search: result.url.search,
      hash: result.url.hash,
      queryParameters: result.queryParams,
    },
    findings: result.findings,
  };
}
