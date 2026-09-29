import { $, escapeHtml, downloadText, enableToolDragging } from '../utils.js';
async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  textarea.remove();
}
const ATTRIBUTE_KEYWORDS = [
  'domain', 'path', 'expires', 'max-age',
  'secure', 'httponly', 'samesite', 'priority', 'partitioned'
];
const SAMESITE_INFO = {
  strict:
    'Sent only with same-site requests. Never attached to cross-site subrequests or cross-site navigation, even a plain link clicked from another site. Strongest CSRF protection, but can break flows that arrive via an external link or a cross-site redirect (SSO, payment providers, etc.).',
  lax:
    'Sent with same-site requests and with top-level, "safe" cross-site navigations (plain links, GET). Not sent on cross-site subrequests such as images, iframes or fetch/XHR, or on cross-site form POSTs. Most current browsers apply this automatically when SameSite is not set at all.',
  none:
    'Sent on every request, including cross-site subrequests and third-party embeds. Requires the Secure attribute - current browsers reject a SameSite=None cookie that is not also Secure.'
};
const PRIORITY_INFO = {
  low: 'Chromium-only hint: evicted first when the browser enforces its per-domain cookie jar limits.',
  medium: 'Chromium-only hint: default eviction priority.',
  high: 'Chromium-only hint: evicted last when the browser enforces its per-domain cookie jar limits.'
};
function truthyCell(value) {
  return /^(true|yes|y|1|✓|✔)$/i.test((value || '').trim());
}
function humanizeDuration(seconds) {
  const units = [
    ['year', 31536000],
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60]
  ];
  for (const [label, secs] of units) {
    if (seconds >= secs) {
      const value = Math.round(seconds / secs);
      return `${value} ${label}${value === 1 ? '' : 's'}`;
    }
  }
  return `${seconds}s`;
}
function approxByteSize(name, value) {
  return new TextEncoder().encode(`${name || ''}=${value || ''}`).length;
}
function parseSetCookieLine(text) {
  const segments = text.split(';').map(s => s.trim()).filter(s => s !== '');
  const first = segments.shift() || '';
  const eq = first.indexOf('=');
  const name = eq === -1 ? first : first.slice(0, eq).trim();
  const value = eq === -1 ? '' : first.slice(eq + 1).trim();
  const attrs = {
    domain: null,
    path: null,
    expires: null,
    maxAge: null,
    secure: false,
    httpOnly: false,
    sameSite: null,
    priority: null,
    partitioned: false,
    unknown: []
  };
  for (const seg of segments) {
    const eqIdx = seg.indexOf('=');
    const rawKey = eqIdx === -1 ? seg : seg.slice(0, eqIdx);
    const rawVal = eqIdx === -1 ? '' : seg.slice(eqIdx + 1).trim();
    const key = rawKey.trim().toLowerCase();
    switch (key) {
      case 'domain': attrs.domain = rawVal; break;
      case 'path': attrs.path = rawVal; break;
      case 'expires': attrs.expires = rawVal; break;
      case 'max-age': attrs.maxAge = rawVal; break;
      case 'secure': attrs.secure = true; break;
      case 'httponly': attrs.httpOnly = true; break;
      case 'samesite': attrs.sameSite = rawVal; break;
      case 'priority': attrs.priority = rawVal; break;
      case 'partitioned': attrs.partitioned = true; break;
      default: attrs.unknown.push(seg);
    }
  }
  return { name, value, attrs };
}
function classifyLine(line) {
  let text = line.trim().replace(/^[<>]\s*/, '');
  if (!text) return null;
  if (/^set-cookie2?:/i.test(text)) {
    return { kind: 'response', text: text.replace(/^set-cookie2?:\s*/i, '').trim() };
  }
  const withoutCookiePrefix = text.replace(/^cookie:\s*/i, '');
  const hadCookiePrefix = withoutCookiePrefix !== text;
  const lower = withoutCookiePrefix.toLowerCase();
  const hasAttributeKeyword = ATTRIBUTE_KEYWORDS.some(keyword => {
    const re = new RegExp(`(^|;)\\s*${keyword.replace('-', '\\-')}\\s*(=|;|$)`, 'i');
    return re.test(lower);
  });
  if (!hadCookiePrefix && hasAttributeKeyword) {
    return { kind: 'response', text: withoutCookiePrefix.trim() };
  }
  return { kind: 'request', text: withoutCookiePrefix.trim() };
}
function parseCookieTable(text) {
  const lines = text
    .split('\n')
    .map(l => l.replace(/\r$/, ''))
    .filter(l => l.trim() !== '');
  if (lines.length < 2 || !lines.every(l => l.includes('\t'))) {
    return null;
  }
  const header = lines[0].split('\t').map(c => c.trim().toLowerCase());
  if (!header.includes('name') || !header.includes('value')) {
    return null;
  }
  return lines.slice(1).map(line => {
    const cells = line.split('\t');
    const row = {};
    header.forEach((h, i) => { row[h] = (cells[i] ?? '').trim(); });
    const findCol = (...keys) => {
      for (const key of keys) {
        const col = header.find(h => h === key || h.includes(key));
        if (col !== undefined && row[col] !== '') return row[col];
      }
      return '';
    };
    const expiresCell = findCol('expires', 'max-age', 'maxage');
    let expires = null;
    let maxAge = null;
    if (expiresCell && !/^session$/i.test(expiresCell)) {
      if (/^-?\d+$/.test(expiresCell)) {
        maxAge = expiresCell;
      } else if (!Number.isNaN(new Date(expiresCell).getTime())) {
        expires = expiresCell;
      }
    }
    const domainCell = findCol('domain');
    const pathCell = findCol('path');
    const sameSiteCell = findCol('samesite', 'same site');
    const priorityCell = findCol('priority');
    return {
      name: findCol('name'),
      value: findCol('value'),
      attrs: {
        domain: domainCell || null,
        path: pathCell || null,
        expires,
        maxAge,
        secure: truthyCell(findCol('secure')),
        httpOnly: truthyCell(findCol('http only', 'httponly', 'http')),
        sameSite: sameSiteCell || null,
        priority: priorityCell || null,
        partitioned: truthyCell(findCol('partition key', 'partitioned')),
        unknown: []
      }
    };
  });
}
function analyze(raw) {
  const text = raw.replace(/\r\n/g, '\n');
  if (!text.trim()) {
    return { mode: 'empty' };
  }
  const tableRows = parseCookieTable(text);
  if (tableRows) {
    return { mode: 'table', cookies: tableRows };
  }
  if (!text.includes('=')) {
    return { mode: 'unrecognized' };
  }
  const responseCookies = [];
  const requestChunks = [];
  for (const line of text.split('\n')) {
    const classified = classifyLine(line);
    if (!classified || !classified.text) continue;
    if (classified.kind === 'response') {
      responseCookies.push(parseSetCookieLine(classified.text));
    } else {
      requestChunks.push(classified.text);
    }
  }
  const requestPairs = [];
  for (const chunk of requestChunks) {
    for (const part of chunk.split(';')) {
      const p = part.trim();
      if (!p) continue;
      const eq = p.indexOf('=');
      if (eq === -1) {
        requestPairs.push({ name: p, value: '', noValue: true });
      } else {
        requestPairs.push({ name: p.slice(0, eq).trim(), value: p.slice(eq + 1).trim() });
      }
    }
  }
  return { mode: 'lines', responseCookies, requestPairs };
}
function analyzeCookie(cookie) {
  const findings = [];
  const { name, value, attrs } = cookie;
  if (!name) {
    findings.push({
      level: 'danger',
      title: 'No cookie name found',
      detail: 'The parser could not find a name=value pair before the first ";". Check the pasted text.'
    });
  } else if (/[\s,;\\"]/.test(name)) {
    findings.push({
      level: 'danger',
      title: 'Cookie name contains characters that are not allowed unencoded',
      detail: 'RFC 6265 cookie-name tokens must not contain whitespace, commas, semicolons, backslashes or quotes. Browsers may reject or mis-parse this cookie.'
    });
  }
  if (value && /[\s,;\\]/.test(value) && !(value.startsWith('"') && value.endsWith('"'))) {
    findings.push({
      level: 'warn',
      title: 'Cookie value contains characters outside the safe cookie-octet set',
      detail: 'Space, comma, semicolon and backslash are not allowed in an unquoted cookie value per RFC 6265. Some servers wrap such values in double quotes, or Base64/percent-encode them instead.'
    });
  }
  if (attrs.secure) {
    findings.push({
      level: 'ok',
      title: 'Secure is set',
      detail: 'The browser only ever sends this cookie over HTTPS, protecting it from passive network interception.'
    });
  } else {
    findings.push({
      level: 'warn',
      title: 'Secure is missing',
      detail: 'Without Secure, this cookie can also be sent over plain HTTP, where it is visible to anyone on the network path. Recommended unless this cookie is deliberately used over plain HTTP on a local/dev origin.'
    });
  }
  if (attrs.httpOnly) {
    findings.push({
      level: 'ok',
      title: 'HttpOnly is set',
      detail: 'Client-side JavaScript (document.cookie) cannot read this cookie, which limits the impact of an XSS vulnerability elsewhere on the site.'
    });
  } else {
    findings.push({
      level: 'warn',
      title: 'HttpOnly is missing',
      detail: 'Any JavaScript on the page - including code injected via XSS or a compromised third-party script - can read this cookie via document.cookie. Only omit HttpOnly if client-side script genuinely needs the value.'
    });
  }
  const sameSiteRaw = attrs.sameSite;
  const sameSiteNorm = sameSiteRaw ? sameSiteRaw.toLowerCase() : null;
  if (!sameSiteRaw) {
    findings.push({
      level: 'warn',
      title: 'SameSite is not set explicitly',
      detail: 'Most current browsers treat a missing SameSite as SameSite=Lax by default, but older or non-Chromium-based clients may not. Set it explicitly so behaviour does not depend on the visitor\u2019s browser.'
    });
  } else if (!SAMESITE_INFO[sameSiteNorm]) {
    findings.push({
      level: 'danger',
      title: `Unrecognized SameSite value "${sameSiteRaw}"`,
      detail: 'Valid values are Strict, Lax or None (case-insensitive). Browsers treat an invalid value the same as if SameSite were missing entirely.'
    });
  } else {
    findings.push({
      level: sameSiteNorm === 'none' ? 'warn' : 'ok',
      title: `SameSite=${sameSiteRaw}`,
      detail: SAMESITE_INFO[sameSiteNorm]
    });
  }
  if (sameSiteNorm === 'none' && !attrs.secure) {
    findings.push({
      level: 'danger',
      title: 'SameSite=None without Secure',
      detail: 'This combination is invalid under the current cookie spec. Chrome, Firefox and Edge reject a SameSite=None cookie that is not also marked Secure - the browser will not store it at all.'
    });
  }
  if (attrs.domain) {
    const bareDomain = attrs.domain.replace(/^\./, '');
    findings.push({
      level: 'warn',
      title: `Domain=${attrs.domain} widens the cookie's scope`,
      detail: `Explicitly setting Domain makes this a "domain" cookie instead of a host-only one: it is sent to ${bareDomain} and every subdomain of it, not only the exact host that set it. A leading "." is legacy syntax with no extra effect. Omit Domain entirely for the more restrictive, usually safer host-only default.`
    });
    if (bareDomain.split('.').filter(Boolean).length <= 1) {
      findings.push({
        level: 'danger',
        title: 'Domain looks like a bare top-level label',
        detail: 'Browsers reject attempts to set a cookie for an entire public suffix/TLD (e.g. ".com"). Double-check this value.'
      });
    }
  } else {
    findings.push({
      level: 'ok',
      title: 'No Domain attribute - host-only cookie',
      detail: 'The cookie is only sent back to the exact host that set it, not to any subdomain. This is generally the safer default.'
    });
  }
  if (attrs.path) {
    findings.push({
      level: 'ok',
      title: `Path=${attrs.path}`,
      detail: attrs.path === '/'
        ? 'The cookie is sent with every request to the host/domain, regardless of the URL path.'
        : 'The cookie is only sent for requests whose path starts with this value.'
    });
  } else {
    findings.push({
      level: 'warn',
      title: 'No Path attribute',
      detail: 'Without an explicit Path, the browser derives a default from the path of the request that set the cookie (roughly, up to the last "/") - not "/". Set Path explicitly if the cookie should apply site-wide.'
    });
  }
  if (attrs.maxAge !== null) {
    const seconds = Number(attrs.maxAge);
    if (Number.isNaN(seconds)) {
      findings.push({
        level: 'danger',
        title: `Max-Age="${attrs.maxAge}" is not a valid number`,
        detail: 'Max-Age must be an integer number of seconds. An invalid value is typically ignored by the browser.'
      });
    } else if (seconds <= 0) {
      findings.push({
        level: 'ok',
        title: 'Max-Age is zero or negative',
        detail: 'This is the standard mechanism for deleting a cookie: the browser expires it immediately.'
      });
    } else {
      findings.push({
        level: 'ok',
        title: `Max-Age=${seconds}s (~${humanizeDuration(seconds)})`,
        detail: 'Max-Age takes precedence over Expires when both are present (RFC 6265). The cookie persists across browser restarts until it expires.'
      });
    }
    if (attrs.expires) {
      findings.push({
        level: 'ok',
        title: 'Both Max-Age and Expires are present',
        detail: 'Max-Age wins in every modern browser; Expires is kept only for very old clients that predate it.'
      });
    }
  } else if (attrs.expires) {
    const parsed = new Date(attrs.expires);
    if (Number.isNaN(parsed.getTime())) {
      findings.push({
        level: 'danger',
        title: `Expires="${attrs.expires}" could not be parsed`,
        detail: 'Expires must be a valid HTTP-date, e.g. "Wed, 21 Oct 2026 07:28:00 GMT". An unparsable value is typically ignored by the browser.'
      });
    } else {
      const isPast = parsed.getTime() < Date.now();
      findings.push({
        level: isPast ? 'warn' : 'ok',
        title: `Expires=${parsed.toUTCString()}${isPast ? ' (already in the past)' : ''}`,
        detail: isPast
          ? 'A date in the past deletes the cookie immediately - this may be intentional, e.g. a logout response.'
          : 'The cookie persists across browser restarts until this date.'
      });
    }
  } else {
    findings.push({
      level: 'ok',
      title: 'No Expires/Max-Age - session cookie',
      detail: 'The cookie is kept only for the current browser session and discarded when the browser - not just the tab - closes. Note: some browsers\u2019 "continue where you left off" feature can make session cookies outlive a literal close/reopen.'
    });
  }
  if (attrs.priority) {
    const p = attrs.priority.toLowerCase();
    findings.push({
      level: 'ok',
      title: `Priority=${attrs.priority}`,
      detail: PRIORITY_INFO[p] || 'Non-standard attribute; only Chromium-based browsers act on it.'
    });
  }
  if (attrs.partitioned) {
    findings.push({
      level: attrs.secure ? 'ok' : 'danger',
      title: 'Partitioned (CHIPS)',
      detail: 'The cookie is stored per top-level site: the same cookie set from a third-party context on siteA.example and siteB.example is kept in two separate jars. Requires Secure.' +
        (attrs.secure ? '' : ' Secure is missing here, so this will likely be rejected.')
    });
  }
  if (name.startsWith('__Host-')) {
    const problems = [];
    if (!attrs.secure) problems.push('Secure is missing');
    if (attrs.path !== '/') problems.push('Path is not "/"');
    if (attrs.domain) problems.push('a Domain attribute is present');
    findings.push({
      level: problems.length ? 'danger' : 'ok',
      title: '__Host- name prefix',
      detail: problems.length
        ? `A cookie named __Host-\u2026 must have Secure, Path=/, and no Domain attribute. Browsers reject it because: ${problems.join(', ')}.`
        : 'Requirements satisfied (Secure, Path=/, no Domain). Browsers additionally lock this cookie to being ' +
          'host-only and reject it from insecure origins - one of the strongest guarantees available.'
    });
  } else if (name.startsWith('__Secure-')) {
    findings.push({
      level: attrs.secure ? 'ok' : 'danger',
      title: '__Secure- name prefix',
      detail: attrs.secure
        ? 'Requirement satisfied (Secure is set). Browsers additionally refuse to accept or overwrite this cookie from a non-HTTPS response.'
        : 'A cookie named __Secure-\u2026 must have Secure. Without it, browsers reject the cookie entirely.'
    });
  } else if (/^__host-/i.test(name)) {
    findings.push({
      level: 'warn',
      title: 'Looks like a miscased __Host- prefix',
      detail: `Cookie name prefixes are case-sensitive. "${name}" does not match "__Host-" exactly, so the browser enforces none of the __Host- guarantees - it is treated as an ordinary cookie name.`
    });
  } else if (/^__secure-/i.test(name)) {
    findings.push({
      level: 'warn',
      title: 'Looks like a miscased __Secure- prefix',
      detail: `Cookie name prefixes are case-sensitive. "${name}" does not match "__Secure-" exactly, so the browser does not enforce the __Secure- guarantee.`
    });
  }
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
    findings.push({
      level: 'warn',
      title: 'Value looks like a JWT',
      detail: 'Three dot-separated Base64URL segments - this may be a JSON Web Token. Use the JWT/JWS/JWK Decoder tool to inspect its header and claims. Treat the value as a live credential if it is a session token.'
    });
  }
  const size = approxByteSize(name, value);
  if (size > 4096) {
    findings.push({
      level: 'danger',
      title: `Cookie is ~${size} bytes`,
      detail: 'Most browsers cap an individual cookie around 4096 bytes and silently drop cookies over that limit.'
    });
  } else if (size > 3000) {
    findings.push({
      level: 'warn',
      title: `Cookie is ~${size} bytes`,
      detail: 'Getting close to the common ~4096 byte per-cookie limit enforced by most browsers.'
    });
  }
  return findings;
}
function findingBlock(f) {
  const cls = f.level === 'danger' ? 'danger' : f.level === 'warn' ? 'warn' : 'ok';
  return `
    <div class="status ${cls}">
      <strong>${escapeHtml(f.title)}</strong>
      <div class="small">${escapeHtml(f.detail)}</div>
    </div>
  `;
}
function attrRow(label, value, note) {
  return `
    <tr>
      <th>${escapeHtml(label)}</th>
      <td class="mono">${escapeHtml(value)}</td>
      <td class="small">${escapeHtml(note)}</td>
    </tr>
  `;
}
function truncate(value, max = 80) {
  if (!value) return '(empty)';
  return value.length > max ? `${value.slice(0, max)}\u2026` : value;
}
function renderCookieCard(cookie, index) {
  const findings = analyzeCookie(cookie);
  const dangerCount = findings.filter(f => f.level === 'danger').length;
  const warnCount = findings.filter(f => f.level === 'warn').length;
  const overallLabel = dangerCount
    ? `${dangerCount} issue${dangerCount > 1 ? 's' : ''}`
    : warnCount
      ? `${warnCount} to review`
      : 'looks solid';
  const a = cookie.attrs;
  const rows = [
    attrRow('Name', cookie.name || '(none)', 'Identifier sent back on every matching request.'),
    attrRow('Value', truncate(cookie.value), 'Opaque to the browser; only the server assigns meaning to it.'),
    attrRow('Domain', a.domain || '(not set \u2192 host-only)', a.domain
      ? 'Sent to this domain and all its subdomains.'
      : 'Sent only to the exact host that set it.'),
    attrRow('Path', a.path || '(not set \u2192 derived from request path)', 'Restricts which URL paths receive the cookie.'),
    attrRow('Expires', a.expires || '-', 'Legacy expiry date; ignored when Max-Age is also present.'),
    attrRow('Max-Age', a.maxAge ?? '-', 'Expiry in seconds from now; takes precedence over Expires.'),
    attrRow('Secure', a.secure ? 'Yes' : 'No', 'HTTPS-only transmission when Yes.'),
    attrRow('HttpOnly', a.httpOnly ? 'Yes' : 'No', 'Hidden from JavaScript (document.cookie) when Yes.'),
    attrRow('SameSite', a.sameSite || '(not set)', 'Controls cross-site sending behaviour.'),
    attrRow('Priority', a.priority || '-', 'Chromium-only eviction hint.'),
    attrRow('Partitioned', a.partitioned ? 'Yes' : 'No', 'CHIPS partitioned storage when Yes.')
  ].join('');
  const unknownRow = a.unknown && a.unknown.length
    ? `
      <tr>
        <th>Unrecognized</th>
        <td class="mono">${escapeHtml(a.unknown.join('; '))}</td>
        <td class="small">Not a standard attribute - vendor-specific extension or a typo.</td>
      </tr>
    `
    : '';
  return `
    <section class="card">
      <div class="row">
        <h3 style="margin:0">Cookie ${index + 1}: <span class="mono">${escapeHtml(cookie.name || '(unnamed)')}</span></h3>
        <span class="spacer"></span>
        <span class="pill">${escapeHtml(overallLabel)}</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Attribute</th><th>Value</th><th>Meaning</th></tr></thead>
          <tbody>${rows}${unknownRow}</tbody>
        </table>
      </div>
      <div class="sub-result">
        ${findings.map(findingBlock).join('')}
      </div>
    </section>
  `;
}
function renderRequestCard(pairs) {
  if (!pairs.length) return '';
  const rows = pairs
    .map(p => `
      <tr>
        <td class="mono">${escapeHtml(p.name)}</td>
        <td class="mono">${escapeHtml(p.noValue ? '(no value)' : p.value)}</td>
      </tr>
    `)
    .join('');
  const totalSize = pairs.reduce((sum, p) => sum + approxByteSize(p.name, p.value), 0);
  return `
    <section class="card">
      <h3>Request-side Cookie header (${pairs.length} ${pairs.length === 1 ? 'cookie' : 'cookies'})</h3>
      <div class="notice">
        This looks like a <span class="mono">Cookie:</span> request header - what the browser sends <em>to</em> the server. Attributes such as Domain, Path, Secure, HttpOnly, SameSite and expiry are decided by the server via <span class="mono">Set-Cookie</span> and are stripped by the browser before the request is sent, so they cannot be recovered here. Paste the response's <span class="mono">Set-Cookie</span> header(s) instead to inspect those.
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Value</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <p class="small">Approximate total size: ${totalSize} bytes.</p>
    </section>
  `;
}
function renderSummary(cookies) {
  if (!cookies.length) return '';
  let secure = 0;
  let httpOnly = 0;
  let session = 0;
  let persistent = 0;
  let dangerTotal = 0;
  for (const cookie of cookies) {
    if (cookie.attrs.secure) secure++;
    if (cookie.attrs.httpOnly) httpOnly++;
    if (cookie.attrs.maxAge !== null || cookie.attrs.expires) persistent++; else session++;
    dangerTotal += analyzeCookie(cookie).filter(f => f.level === 'danger').length;
  }
  return `
    <section class="card">
      <h3>Summary</h3>
      <div class="grid">
        <div class="stat"><span>Cookies parsed</span><strong>${cookies.length}</strong></div>
        <div class="stat"><span>Secure</span><strong>${secure}/${cookies.length}</strong></div>
        <div class="stat"><span>HttpOnly</span><strong>${httpOnly}/${cookies.length}</strong></div>
        <div class="stat"><span>Session / Persistent</span><strong>${session} / ${persistent}</strong></div>
      </div>
      ${dangerTotal
        ? `<div class="status danger" style="margin-top:12px">
             <strong>${dangerTotal} issue${dangerTotal > 1 ? 's' : ''} found</strong>
             <div class="small">See the per-cookie breakdown below.</div>
           </div>`
        : ''}
    </section>
  `;
}
function renderResult(result) {
  if (result.mode === 'empty') {
    return '';
  }
  if (result.mode === 'unrecognized') {
    return `
      <section class="card">
        <div class="status warn">
          <strong>No cookie-like data found</strong>
          <div class="small">
            Paste a Set-Cookie response header, a Cookie request header, or rows copied from the browser's DevTools cookie table (including the header row).
          </div>
        </div>
      </section>
    `;
  }
  if (result.mode === 'table') {
    return `
      <div class="notice">
        Parsed as a DevTools cookie-table paste. Column mapping is best-effort and can vary slightly between browser versions - for full accuracy, paste the raw <span class="mono">Set-Cookie</span> response header instead.
      </div>
      ${renderSummary(result.cookies)}
      ${result.cookies.map((c, i) => renderCookieCard(c, i)).join('')}
    `;
  }
  const parts = [];
  parts.push(renderSummary(result.responseCookies));
  parts.push(result.responseCookies.map((c, i) => renderCookieCard(c, i)).join(''));
  parts.push(renderRequestCard(result.requestPairs));
  if (!result.responseCookies.length && !result.requestPairs.length) {
    parts.push(`
      <section class="card">
        <div class="status warn">
          <strong>Nothing parsed</strong>
          <div class="small">Check that the pasted text contains at least one name=value pair.</div>
        </div>
      </section>
    `);
  }
  return parts.join('');
}
function safeExport(result) {
  if (result.mode === 'table' || result.mode === 'lines') {
    const cookies = result.mode === 'table' ? result.cookies : result.responseCookies;
    return {
      mode: result.mode,
      cookies: cookies.map(c => ({ ...c, findings: analyzeCookie(c) })),
      requestPairs: result.mode === 'lines' ? result.requestPairs : undefined
    };
  }
  return result;
}

export function renderCookies(app) {
  app.innerHTML = `
    <div class="tool-window" id="cookieWindow">
    <div class="tool-window-header" id="cookieDragHandle" title="Drag tool">
      <span class="tool-drag-grip" aria-hidden="true">⋮⋮</span>
      <strong>Cookie analyzer</strong>
    </div>
    <section class="card">
      <h2>Cookie analyzer</h2>
      <p class="small">
        Paste one or more <span class="mono">Set-Cookie</span> response headers, a browser <span class="mono">Cookie:</span> request header, or rows copied from DevTools' Application/Storage \u2192 Cookies table. Everything is parsed locally in this browser - the tool never reads this tab's real cookie jar (<span class="mono">document.cookie</span> is never accessed) and makes no network requests.
      </p>
      <label for="cookieInput">Cookie data</label>
      <textarea
        id="cookieInput"
        spellcheck="false"
        placeholder="sessionid=abc123; Domain=.example.com; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; Secure; SameSite=Lax __Host-csrftoken=xyz789; Path=/; Secure; SameSite=Strict Set-Cookie: cart=1a2b3c; Max-Age=3600; Path=/checkout
        One Set-Cookie value per line. A plain 'Cookie: a=1; b=2' request header and DevTools table pastes are also supported."
      ></textarea>
      <div class="row" style="margin-top:10px">
        <button class="btn primary" id="cookieAnalyze">Analyze</button>
        <button class="btn" id="cookieClear">Clear</button>
        <button class="btn" id="cookieCopy">Copy report</button>
        <button class="btn" id="cookieDownload">Download report</button>
      </div>
    </section>
    <div id="cookieResults"></div>
    </div>
  `;
  const input = $('#cookieInput');
  const results = $('#cookieResults');
  let lastResult = null;
  const run = () => {
    lastResult = analyze(input.value);
    results.innerHTML = renderResult(lastResult);
  };
  $('#cookieAnalyze').onclick = run;
  $('#cookieClear').onclick = () => {
    input.value = '';
    results.innerHTML = '';
    lastResult = null;
    input.focus();
  };
  $('#cookieCopy').onclick = async () => {
    if (!lastResult) return;
    await copyText(JSON.stringify(safeExport(lastResult), null, 2));
  };
  $('#cookieDownload').onclick = () => {
    if (!lastResult) return;
    downloadText(
      'cookie-analysis.json',
      JSON.stringify(safeExport(lastResult), null, 2),
      'application/json'
    );
  };
  input.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run();
  });

  enableToolDragging(
    $('#cookieWindow'),
    $('#cookieDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );

}