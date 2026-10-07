import { $, escapeHtml, downloadText } from '../utils.js';
const WINDOWS_EPOCH_MS = Date.UTC(1601, 0, 1);
const UNIX_EPOCH_MS = Date.UTC(1970, 0, 1);
const OLE_EPOCH_MS = Date.UTC(1899, 11, 30);
const TICKS_PER_MS = 10_000n;
const DOTNET_TO_WINDOWS_EPOCH_TICKS = 504911232000000000n;
const FILETIME_MAX_TICKS = 0xFFFFFFFFFFFFFFFFn;
const FILETIME_SENTINELS = new Map([
  [0n, 'AD sentinel: commonly means \u201cnever set\u201d (e.g. pwdLastSet, lastLogon = 0).'],
  [0x7FFFFFFFFFFFFFFFn, 'AD sentinel: commonly means \u201cnever expires\u201d (e.g. accountExpires).']
]);
const MIN_SUPPORTED_MS = WINDOWS_EPOCH_MS;
const MAX_SUPPORTED_MS = Number(FILETIME_MAX_TICKS / TICKS_PER_MS) + WINDOWS_EPOCH_MS;
const PLAUSIBLE_MIN_MS = Date.UTC(1990, 0, 1);
const PLAUSIBLE_MAX_MS = Date.UTC(2100, 0, 1);
function inRange(ms) {
  return Number.isFinite(ms) && ms >= MIN_SUPPORTED_MS && ms <= MAX_SUPPORTED_MS;
}
function isPlausible(ms) {
  return ms >= PLAUSIBLE_MIN_MS && ms <= PLAUSIBLE_MAX_MS;
}
function adjustConfidence(base, ms) {
  return isPlausible(ms) ? base : Math.max(15, base - 40);
}
function isoUtc(ms) {
  return new Date(ms).toISOString();
}
function localIso(ms) {
  const date = new Date(ms);
  const pad2 = value => String(value).padStart(2, '0');
  const milliseconds = String(date.getMilliseconds()).padStart(3, '0');
  const offsetMinutes = -date.getTimezoneOffset();
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const absoluteOffset = Math.abs(offsetMinutes);
  const offsetHours = Math.floor(absoluteOffset / 60);
  const offsetRemainder = absoluteOffset % 60;
  return (
    `${date.getFullYear()}-` +
    `${pad2(date.getMonth() + 1)}-` +
    `${pad2(date.getDate())}T` +
    `${pad2(date.getHours())}:` +
    `${pad2(date.getMinutes())}:` +
    `${pad2(date.getSeconds())}.` +
    `${milliseconds}` +
    `${sign}${pad2(offsetHours)}:${pad2(offsetRemainder)}`
  );
}
function int64(value) {
  const text = String(value).trim();
  if (!/^[+-]?\d+$/.test(text)) {
    throw new Error('Expected an integer timestamp.');
  }
  return BigInt(text);
}
function unixSec(value) {
  const ms = Number(int64(value)) * 1000;
  if (!inRange(ms)) throw new Error('Unix seconds value is outside the supported range.');
  return ms;
}
function unixMs(value) {
  const ms = Number(int64(value));
  if (!inRange(ms)) throw new Error('Unix/JavaScript milliseconds value is outside the supported range.');
  return ms;
}
function filetimeFromTicks(ticks) {
  const wholeMs = ticks / TICKS_PER_MS;
  const remainder = ticks % TICKS_PER_MS;
  const ms = Number(wholeMs) + WINDOWS_EPOCH_MS + Number(remainder) / 10_000;
  if (!inRange(ms)) throw new Error('FILETIME value is outside the supported range.');
  return ms;
}
function filetime(value) {
  return filetimeFromTicks(int64(value));
}
function filetimeSentinelNote(ticks) {
  return FILETIME_SENTINELS.get(ticks) || null;
}
function dotnetTicksFromValue(dotnetTicks) {
  return filetimeFromTicks(dotnetTicks - DOTNET_TO_WINDOWS_EPOCH_TICKS);
}
function dotnetTicks(value) {
  return dotnetTicksFromValue(int64(value));
}
function dotnetTicksFromMs(ms) {
  const windowsTicks = BigInt(Math.round((ms - WINDOWS_EPOCH_MS) * 10_000));
  return windowsTicks + DOTNET_TO_WINDOWS_EPOCH_TICKS;
}
function chromeTimestampFromMicros(micros) {
  const wholeMs = micros / 1000n;
  const remainder = micros % 1000n;
  const ms = Number(wholeMs) + WINDOWS_EPOCH_MS + Number(remainder) / 1000;
  if (!inRange(ms)) throw new Error('Chrome/WebKit timestamp value is outside the supported range.');
  return ms;
}
function chromeTimestamp(value) {
  return chromeTimestampFromMicros(int64(value));
}
function chromeTimestampFromMs(ms) {
  return BigInt(Math.round((ms - WINDOWS_EPOCH_MS) * 1000));
}
function oleAutomationDate(value) {
  const text = String(value).trim();
  const num = Number(text);
  if (!Number.isFinite(num)) throw new Error('Expected a decimal day-count (OLE Automation Date).');
  const ms = OLE_EPOCH_MS + num * 86_400_000;
  if (!inRange(ms)) throw new Error('OLE Automation Date value is outside the supported range.');
  return ms;
}
function oleAutomationDateFromMs(ms) {
  return (ms - OLE_EPOCH_MS) / 86_400_000;
}
function parseDate(value) {
  const ms = Date.parse(String(value).trim());
  if (Number.isNaN(ms) || !inRange(ms)) throw new Error('Invalid or unsupported date/time value.');
  return ms;
}
function eventLogDate(value) {
  const text = String(value).trim();
  const systemTimeMatch = text.match(/SystemTime\s*=\s*["']([^"']+)["']/i);
  const cleaned = (systemTimeMatch ? systemTimeMatch[1] : text).replace(
    /^\s*(?:TimeCreated|DateTime|Timestamp)\s*[:=]\s*/i, ''
  );
  const normalized = cleaned.replace(/(\.\d{3})\d+(?=Z|[+-]\d{2}:?\d{2}|$)/, '$1');
  return parseDate(normalized);
}
function localAmbiguousDate(value, dateStyle) {
  const text = String(value).trim();
  const m = text.match(
    /^(\d{1,2})[/-](\d{1,2})[/-](\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.(\d+))?\s*(AM|PM)?)?\s*$/i
  );
  if (!m) throw new Error('Expected a date like 01/15/2026 or 15-01-2026, optionally with a time.');
  let [, a, b, year, hh, mm, ss, frac, ampm] = m;
  a = Number(a); b = Number(b); year = Number(year);
  hh = hh !== undefined ? Number(hh) : 0;
  mm = mm !== undefined ? Number(mm) : 0;
  ss = ss !== undefined ? Number(ss) : 0;
  let month, day, autoDetected = false;
  if (a > 12 && b > 12) {
    throw new Error(`Neither ${a} nor ${b} can be a month - this isn\u2019t a valid date.`);
  } else if (a > 12) {
    day = a; month = b; autoDetected = true;
  } else if (b > 12) {
    month = a; day = b; autoDetected = true;
  } else if (dateStyle === 'dmy') {
    day = a; month = b;
  } else {
    month = a; day = b;
  }
  if (ampm) {
    const pm = ampm.toUpperCase() === 'PM';
    hh = (hh % 12) + (pm ? 12 : 0);
  }
  if (month < 1 || month > 12 || day < 1 || day > 31) {
    throw new Error('Invalid month or day value.');
  }
  const ms = new Date(
    year, month - 1, day, hh, mm, ss,
    frac ? Number(frac.slice(0, 3).padEnd(3, '0')) : 0
  ).getTime();
  if (!inRange(ms)) throw new Error('Date value is outside the supported range.');
  return { ms, autoDetected, month, day };
}
function hexBig(value) {
  const cleaned = String(value).trim().replace(/^0x/i, '').replace(/[\s:_-]/g, '');
  if (!cleaned || !/^[0-9a-f]+$/i.test(cleaned)) {
    throw new Error('Invalid hexadecimal timestamp.');
  }
  return BigInt(`0x${cleaned}`);
}
function hexCandidates(value) {
  let ticks;
  try {
    ticks = hexBig(value);
  } catch {
    return [];
  }
  const digitLen = ticks.toString(16).length;
  const candidates = [];
  const asNumber = Number(ticks);
  const unixSecondsMs = asNumber * 1000;
  if (inRange(unixSecondsMs)) {
    candidates.push({ format: 'Hex \u2192 Unix seconds', ms: unixSecondsMs, confidence: adjustConfidence(digitLen <= 10 ? 85 : 70, unixSecondsMs) });
  }
  if (inRange(asNumber)) {
    candidates.push({ format: 'Hex \u2192 Unix milliseconds', ms: asNumber, confidence: adjustConfidence(digitLen >= 10 ? 65 : 45, asNumber) });
  }
  try {
    const ms = filetimeFromTicks(ticks);
    candidates.push({ format: 'Hex \u2192 Windows FILETIME', ms, confidence: adjustConfidence(digitLen >= 14 ? 95 : 75, ms), sentinel: filetimeSentinelNote(ticks) });
  } catch { }
  try {
    const ms = chromeTimestampFromMicros(ticks);
    candidates.push({ format: 'Hex \u2192 Chrome/WebKit timestamp', ms, confidence: adjustConfidence(digitLen >= 13 ? 60 : 40, ms) });
  } catch {  }
  try {
    const ms = dotnetTicksFromValue(ticks);
    candidates.push({ format: 'Hex \u2192 .NET DateTime.Ticks', ms, confidence: adjustConfidence(digitLen >= 14 ? 55 : 35, ms) });
  } catch { /* out of range */ }
  return candidates.sort((a, b) => b.confidence - a.confidence);
}
function heuristic(value, dateStyle) {
  const text = String(value).trim();
  const candidates = [];
  if (/^\d+$/.test(text)) {
    const bi = BigInt(text);
    if (text.length <= 10) {
      try { const ms = unixSec(text); candidates.push({ format: 'Unix seconds', ms, confidence: adjustConfidence(95, ms) }); } catch { }
    }
    if (text.length >= 1 && text.length <= 6) {
      try { const ms = oleAutomationDate(text); candidates.push({ format: 'OLE Automation Date (VT_DATE)', ms, confidence: adjustConfidence(60, ms) }); } catch { }
    }
    if (text.length >= 11 && text.length <= 14) {
      try { const ms = unixMs(text); candidates.push({ format: 'Unix / JavaScript milliseconds', ms, confidence: adjustConfidence(95, ms) }); } catch { }
    }
    if (text.length >= 13 && text.length <= 17) {
      try { const ms = chromeTimestampFromMicros(bi); candidates.push({ format: 'Chrome/WebKit timestamp', ms, confidence: adjustConfidence(75, ms) }); } catch { }
    }
    if (text.length >= 15 && text.length <= 18) {
      try {
        const ms = filetime(text);
        candidates.push({ format: 'Windows FILETIME', ms, confidence: adjustConfidence(92, ms), sentinel: filetimeSentinelNote(bi) });
      } catch { }
      try { const ms = dotnetTicksFromValue(bi); candidates.push({ format: '.NET DateTime.Ticks', ms, confidence: adjustConfidence(55, ms) }); } catch { }
    }
  }
  const looksLikeHex = /^0x[0-9a-f]+$/i.test(text) || /^[0-9a-f]{8,20}$/i.test(text.replace(/[\s:_-]/g, ''));
  if (looksLikeHex) candidates.push(...hexCandidates(text));
  const looksLikeEventLog = /SystemTime\s*=/i.test(text) || /^\s*(?:TimeCreated|DateTime|Timestamp)\s*[:=]/i.test(text);
  if (looksLikeEventLog) {
    try { const ms = eventLogDate(text); candidates.push({ format: 'Windows Event Log-style timestamp', ms, confidence: adjustConfidence(99, ms) }); } catch { }
  }
  const looksLikeIsoDate = /^\d{4}-\d{2}-\d{2}[T ]/.test(text) || /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),/i.test(text) || /(Z|[+-]\d{2}:?\d{2})$/i.test(text);
  if (looksLikeIsoDate) {
    try { const ms = parseDate(text); candidates.push({ format: 'ISO-8601 / RFC 3339 / date-time', ms, confidence: adjustConfidence(96, ms) }); } catch { }
  }
  if (/^\d{1,2}[/-]\d{1,2}[/-]\d{4}/.test(text)) {
    try {
      const r = localAmbiguousDate(text, dateStyle);
      candidates.push({
        format: r.autoDetected ? 'Local date-time (day/month position auto-detected)' : `Local date-time (assumed ${dateStyle === 'dmy' ? 'D/M/Y' : 'M/D/Y'})`,
        ms: r.ms,
        confidence: adjustConfidence(r.autoDetected ? 88 : 72, r.ms)
      });
    } catch { }
  }
  return candidates.sort((a, b) => b.confidence - a.confidence);
}
function all(ms) {
  const unixSeconds = Math.floor((ms - UNIX_EPOCH_MS) / 1000);
  const unixMilliseconds = Math.round(ms - UNIX_EPOCH_MS);
  const filetimeTicks = BigInt(Math.round((ms - WINDOWS_EPOCH_MS) * 10_000));
  const filetimeHex = filetimeTicks.toString(16).padStart(16, '0').toUpperCase();
  const chromeTicks = chromeTimestampFromMs(ms);
  const dotnetTicksVal = dotnetTicksFromMs(ms);
  const oleDate = oleAutomationDateFromMs(ms);
  return {
    sec: unixSeconds,
    ums: unixMilliseconds,
    iso: isoUtc(ms),
    local: localIso(ms),
    filetime: filetimeTicks.toString(),
    filetimeHex: `0x${filetimeHex}`,
    filetimeSentinel: filetimeSentinelNote(filetimeTicks),
    chrome: chromeTicks.toString(),
    dotnetTicks: dotnetTicksVal.toString(),
    ole: Number.isFinite(oleDate) ? oleDate.toFixed(6).replace(/0+$/, '').replace(/\.$/, '') : '-',
    secHex: `0x${Math.max(0, unixSeconds).toString(16).padStart(8, '0').toUpperCase()}`,
    msHex: `0x${Math.max(0, unixMilliseconds).toString(16).padStart(8, '0').toUpperCase()}`
  };
}
export function renderTimestamp(app) {
  app.innerHTML = `
    <section class="card">
      <div class="row">
        <div>
          <h2>Timestamp / Epoch Converter</h2>
          <p class="small">
            Convert common Windows and web timestamp formats locally, or identify an unknown value heuristically.
          </p>
        </div>
        <span class="spacer"></span>
        <span class="pill">local-only, no network</span>
      </div>
      <div class="card">
        <div class="row">
          <label for="ts-input" style="margin:0">Timestamp</label>
          <span class="spacer"></span>
          <label for="ts-mode" class="small" style="margin:0">Format</label>
          <select id="ts-mode">
            <option value="heuristic">What timestamp format is this?</option>
            <option value="unix-seconds">Unix seconds</option>
            <option value="unix-ms">Unix / JavaScript milliseconds</option>
            <option value="iso">ISO-8601 / RFC 3339</option>
            <option value="eventlog">Windows Event Log (SystemTime)</option>
            <option value="localdate">Local date (M/D/Y or D/M/Y)</option>
            <option value="filetime">Windows FILETIME</option>
            <option value="ole">OLE Automation Date (VT_DATE)</option>
            <option value="chrome">Chrome/WebKit timestamp</option>
            <option value="dotnet">.NET DateTime.Ticks</option>
            <option value="hex">Hex timestamp</option>
          </select>
        </div>
        <input id="ts-input" type="text" value="1724064000" placeholder="e.g. 1724064000, 1724064000000, 0x01DB..., 2025-01-01T12:00:00Z">
        <div class="row" id="ts-datestyle-row" hidden style="margin-top:8px">
          <label for="ts-datestyle" class="small" style="margin:0">Ambiguous local dates (e.g. 05/06/2026) mean:</label>
          <select id="ts-datestyle">
            <option value="dmy">Day/Month/Year (Europe)</option>
            <option value="mdy">Month/Day/Year (US)</option>
          </select>
        </div>
        <div class="row" style="margin-top:10px">
          <button class="btn primary" type="button" id="ts-convert">Convert</button>
          <button class="btn" type="button" id="ts-now">Use current time</button>
          <button class="btn" type="button" id="ts-clear">Clear</button>
          <span class="spacer"></span>
          <button class="btn" type="button" id="ts-copy">Copy</button>
          <button class="btn" type="button" id="ts-download">Download</button>
        </div>
      </div>
      <div id="ts-message" class="status" hidden role="status"></div>
      <div class="card">
        <h3>Quick result</h3>
        <div id="ts-quick"></div>
      </div>
      <div id="ts-heuristics" class="card" hidden>
        <h3>Candidates</h3>
        <div id="ts-candidates"></div>
      </div>
      <div class="card">
        <h3>UTC / local</h3>
        <div class="grid-2">
          <div class="stat"><span>UTC</span><strong id="ts-utc">-</strong></div>
          <div class="stat"><span>Local time</span><strong id="ts-local">-</strong></div>
        </div>
      </div>
      <div class="card">
        <h3>Equivalent representations</h3>
        <div class="grid-2">
          <div class="stat"><span>Unix seconds</span><strong id="ts-sec">-</strong></div>
          <div class="stat"><span>Unix milliseconds</span><strong id="ts-ms">-</strong></div>
          <div class="stat"><span>Windows FILETIME</span><strong id="ts-ft">-</strong></div>
          <div class="stat"><span>FILETIME hex</span><strong id="ts-fth">-</strong></div>
          <div class="stat"><span>Chrome/WebKit timestamp</span><strong id="ts-chrome">-</strong></div>
          <div class="stat"><span>.NET DateTime.Ticks</span><strong id="ts-dotnet">-</strong></div>
          <div class="stat"><span>OLE Automation Date</span><strong id="ts-ole">-</strong></div>
          <div class="stat"><span>Unix seconds hex</span><strong id="ts-sech">-</strong></div>
          <div class="stat"><span>Unix milliseconds hex</span><strong id="ts-msh">-</strong></div>
        </div>
        <div id="ts-sentinel-note" hidden style="margin-top:10px"></div>
      </div>
      <div class="card">
        <h3>Reference notes</h3>
        <ul>
          <li>Unix seconds/milliseconds count from 1970-01-01 UTC.</li>
          <li>Windows FILETIME uses 100ns ticks since 1601-01-01 UTC; <span class="mono">0</span> and <span class="mono">0x7FFFFFFFFFFFFFFF</span> are common Active Directory sentinels (\u201cnever set\u201d / \u201cnever expires\u201d) and are recognized explicitly.</li>
          <li>Chrome/WebKit timestamps share the FILETIME epoch (1601) but count microseconds.</li>
          <li>.NET <span class="mono">DateTime.Ticks</span> uses 100ns ticks since <span class="mono">0001-01-01</span> - a different epoch than FILETIME, despite the same tick size.</li>
          <li>OLE Automation Date (VT_DATE, used by WMI/VBScript/Excel) counts days since 1899-12-30, with the time of day as a fraction.</li>
          <li>Timezone-less ISO/Event Viewer/local-date values are interpreted in the browser's local timezone.</li>
          <li>Ambiguous local dates (both numbers \u226412) fall back to the style you pick above; when one number is &gt;12 the day/month position is detected automatically regardless of that setting.</li>
          <li>Supported range is 1601-01-01 up to the maximum a 64-bit FILETIME can represent (year 60056) - wide enough to include legitimate extreme values like the AD sentinels, not just "plausible" dates.</li>
        </ul>
      </div>
    </section>
  `;
  const q = selector => $(selector, app);
  const input = q('#ts-input');
  const mode = q('#ts-mode');
  const dateStyleRow = q('#ts-datestyle-row');
  const dateStyleSelect = q('#ts-datestyle');
  const message = q('#ts-message');
  const candidatesEl = q('#ts-candidates');
  const heuristicsCard = q('#ts-heuristics');
  function notice(text, kind) {
    message.textContent = text || '';
    message.hidden = !text;
    message.className = `status ${kind || 'warn'}`;
  }
  function sentinelHtml(note) {
    return note ? `<div class="status ok" style="margin-top:4px"><strong>${escapeHtml(note)}</strong></div>` : '';
  }
  function render(ms, sentinel) {
    const result = all(ms);
    q('#ts-utc').textContent = result.iso;
    q('#ts-local').textContent = result.local;
    q('#ts-sec').textContent = result.sec.toLocaleString();
    q('#ts-ms').textContent = result.ums.toLocaleString();
    q('#ts-ft').textContent = result.filetime;
    q('#ts-fth').textContent = result.filetimeHex;
    q('#ts-chrome').textContent = result.chrome;
    q('#ts-dotnet').textContent = result.dotnetTicks;
    q('#ts-ole').textContent = result.ole;
    q('#ts-sech').textContent = result.secHex;
    q('#ts-msh').textContent = result.msHex;
    q('#ts-quick').innerHTML = `
      <div class="grid-2">
        <div class="stat"><span>Date (UTC)</span><strong>${escapeHtml(result.iso)}</strong></div>
        <div class="stat"><span>Date (local)</span><strong>${escapeHtml(result.local)}</strong></div>
      </div>
    `;
    const note = sentinel || result.filetimeSentinel;
    const sentinelEl = q('#ts-sentinel-note');
    sentinelEl.hidden = !note;
    sentinelEl.innerHTML = sentinelHtml(note);
  }
  function renderCandidates(list) {
    if (!list.length) {
      candidatesEl.innerHTML = '<div class="small">No confident timestamp interpretation was found.</div>';
      return;
    }
    candidatesEl.innerHTML = list.map((candidate, index) => {
      const isBest = index === 0;
      return `
        <div class="card">
          <div class="row">
            <div>
              <strong>${escapeHtml(candidate.format)}</strong>
              <div class="small">${escapeHtml(isoUtc(candidate.ms))}</div>
            </div>
            <span class="spacer"></span>
            <span class="pill">${isBest ? 'BEST MATCH' : 'POSSIBLE'} \u00b7 ${candidate.confidence}%</span>
          </div>
          <div class="small">Local: ${escapeHtml(localIso(candidate.ms))}</div>
          ${sentinelHtml(candidate.sentinel)}
        </div>
      `;
    }).join('');
  }
  function convert() {
    try {
      const text = input.value.trim();
      if (!text) throw new Error('Enter a timestamp.');
      if (mode.value === 'heuristic' || mode.value === 'hex') {
        const list = mode.value === 'hex' ? hexCandidates(text) : heuristic(text, dateStyleSelect.value);
        heuristicsCard.hidden = false;
        renderCandidates(list);
        if (!list.length) {
          q('#ts-quick').innerHTML = '<div class="small">No likely format found.</div>';
          notice(mode.value === 'hex' ? 'Could not interpret this as a hexadecimal timestamp.' : 'No strong match. Try selecting a specific format.');
          return;
        }
        render(list[0].ms, list[0].sentinel);
        notice(`Best match: ${list[0].format} (${list[0].confidence}% confidence).`, 'ok');
        return;
      }
      heuristicsCard.hidden = true;
      let ms, sentinel;
      switch (mode.value) {
        case 'unix-seconds': ms = unixSec(text); break;
        case 'unix-ms': ms = unixMs(text); break;
        case 'iso': ms = parseDate(text); break;
        case 'eventlog': ms = eventLogDate(text); break;
        case 'localdate': { const r = localAmbiguousDate(text, dateStyleSelect.value); ms = r.ms; break; }
        case 'filetime': { const ticks = int64(text); ms = filetimeFromTicks(ticks); sentinel = filetimeSentinelNote(ticks); break; }
        case 'ole': ms = oleAutomationDate(text); break;
        case 'chrome': ms = chromeTimestamp(text); break;
        case 'dotnet': ms = dotnetTicks(text); break;
        default: throw new Error('Unsupported mode.');
      }
      render(ms, sentinel);
      notice('Conversion successful.', 'ok');
    } catch (error) {
      candidatesEl.innerHTML = '<div class="small">-</div>';
      q('#ts-quick').innerHTML = '<div class="small">No result.</div>';
      notice(error?.message || 'Could not parse timestamp.', 'danger');
    }
  }
  function syncDateStyleVisibility() {
    dateStyleRow.hidden = !(mode.value === 'localdate' || mode.value === 'heuristic');
  }
  q('#ts-convert').onclick = convert;
  input.onkeydown = event => {
    if (event.key === 'Enter') { event.preventDefault(); convert(); }
  };
  q('#ts-now').onclick = () => {
    input.value = String(Date.now());
    mode.value = 'unix-ms';
    syncDateStyleVisibility();
    convert();
  };
  q('#ts-clear').onclick = () => {
    input.value = '';
    q('#ts-quick').innerHTML = '<div class="small">No result.</div>';
    ['ts-utc', 'ts-local', 'ts-sec', 'ts-ms', 'ts-ft', 'ts-fth', 'ts-chrome', 'ts-dotnet', 'ts-ole', 'ts-sech', 'ts-msh']
      .forEach(id => { q('#' + id).textContent = '-'; });
    q('#ts-sentinel-note').hidden = true;
    candidatesEl.innerHTML = '<div class="small">-</div>';
    notice('');
  };
  q('#ts-copy').onclick = async () => {
    const text = [
      `UTC: ${q('#ts-utc').textContent}`,
      `Local: ${q('#ts-local').textContent}`,
      `Unix seconds: ${q('#ts-sec').textContent}`,
      `Unix ms: ${q('#ts-ms').textContent}`,
      `FILETIME: ${q('#ts-ft').textContent} (${q('#ts-fth').textContent})`,
      `Chrome/WebKit: ${q('#ts-chrome').textContent}`,
      `.NET Ticks: ${q('#ts-dotnet').textContent}`,
      `OLE Automation Date: ${q('#ts-ole').textContent}`
    ].join('\n');
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    notice('Copied to clipboard.', 'ok');
  };
  q('#ts-download').onclick = () => {
    const payload = {
      input: input.value,
      mode: mode.value,
      utc: q('#ts-utc').textContent,
      local: q('#ts-local').textContent,
      unixSeconds: q('#ts-sec').textContent,
      unixMilliseconds: q('#ts-ms').textContent,
      filetime: q('#ts-ft').textContent,
      filetimeHex: q('#ts-fth').textContent,
      chromeWebKit: q('#ts-chrome').textContent,
      dotnetTicks: q('#ts-dotnet').textContent,
      oleAutomationDate: q('#ts-ole').textContent
    };
    downloadText('timestamp-conversion.json', JSON.stringify(payload, null, 2), 'application/json');
  };
  mode.onchange = () => { syncDateStyleVisibility(); convert(); };
  dateStyleSelect.onchange = () => convert();
  syncDateStyleVisibility();
  convert();
}