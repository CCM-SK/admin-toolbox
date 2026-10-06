import { $, escapeHtml, downloadText, dropBinder, enableToolDragging } from '../utils.js';
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
const MAX_RENDERED_ROWS = 500;
const FALLBACK_ZONES = [
  'UTC', 'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Europe/Madrid', 'Europe/Rome',
  'Europe/Moscow', 'Europe/Istanbul', 'Africa/Cairo', 'Africa/Johannesburg',
  'Asia/Jerusalem', 'Asia/Dubai', 'Asia/Karachi', 'Asia/Kolkata', 'Asia/Dhaka',
  'Asia/Bangkok', 'Asia/Shanghai', 'Asia/Hong_Kong', 'Asia/Singapore', 'Asia/Tokyo',
  'Asia/Seoul', 'Australia/Perth', 'Australia/Sydney', 'Pacific/Auckland',
  'America/Sao_Paulo', 'America/New_York', 'America/Chicago', 'America/Denver',
  'America/Los_Angeles', 'America/Anchorage', 'Pacific/Honolulu'
];
function getIanaZones() {
  try {
    if (typeof Intl.supportedValuesOf === 'function') {
      const zones = Intl.supportedValuesOf('timeZone');
      if (zones && zones.length) return ['UTC', ...zones.filter(z => z !== 'UTC')];
    }
  } catch { /* fall through to static list */ }
  return FALLBACK_ZONES;
}
function isValidZone(tz) {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}
function getTimeZoneOffsetMinutes(date, timeZone) {
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
  const parts = {};
  for (const p of dtf.formatToParts(date)) parts[p.type] = p.value;
  const asUtc = Date.UTC(
    Number(parts.year), Number(parts.month) - 1, Number(parts.day),
    Number(parts.hour) % 24, Number(parts.minute), Number(parts.second)
  );
  return (asUtc - date.getTime()) / 60000;
}
function wallClockToUtc(wall, timeZone) {
  let guess = Date.UTC(wall.y, wall.mo - 1, wall.d, wall.h, wall.mi, wall.s, wall.ms || 0);
  for (let i = 0; i < 2; i++) {
    const offsetMin = getTimeZoneOffsetMinutes(new Date(guess), timeZone);
    guess = Date.UTC(wall.y, wall.mo - 1, wall.d, wall.h, wall.mi, wall.s, wall.ms || 0) - offsetMin * 60000;
  }
  return guess;
}
function formatInZone(epochMs, timeZone, withDate) {
  if (epochMs === null || epochMs === undefined || Number.isNaN(epochMs)) return '\u2014';
  const dtf = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
  const parts = {};
  for (const p of dtf.formatToParts(new Date(epochMs))) parts[p.type] = p.value;
  const time = `${parts.hour}:${parts.minute}:${parts.second}`;
  return withDate ? `${parts.year}-${parts.month}-${parts.day} ${time}` : time;
}
function pad(n) { return String(n).padStart(2, '0'); }
function offsetStringToMinutes(s) {
  if (!s || /^Z$/i.test(s)) return 0;
  const m = s.match(/^([+-])(\d{2}):?(\d{2})$/);
  if (!m) return null;
  const sign = m[1] === '-' ? -1 : 1;
  return sign * (Number(m[2]) * 60 + Number(m[3]));
}
const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
const TIMESTAMP_PATTERNS = [
  {
    name: 'ISO 8601',
    regex: /(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?/,
    parse(m) {
      const offset = m[8] ? offsetStringToMinutes(m[8]) : null;
      return {
        wall: { y: +m[1], mo: +m[2], d: +m[3], h: +m[4], mi: +m[5], s: +m[6], ms: m[7] ? Number(('0.' + m[7]) * 1000) : 0 },
        explicitOffsetMinutes: offset
      };
    }
  },
  {
    name: 'Apache/nginx bracketed',
    regex: /\[(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]/,
    parse(m) {
      const mo = MONTHS[m[2].toLowerCase()];
      const offRaw = m[7] ? `${m[7].slice(0, 3)}:${m[7].slice(3)}` : null;
      return {
        wall: { y: +m[3], mo, d: +m[1], h: +m[4], mi: +m[5], s: +m[6], ms: 0 },
        explicitOffsetMinutes: offRaw ? offsetStringToMinutes(offRaw) : null
      };
    }
  },
  {
    name: 'US date (MM/DD/YYYY)',
    regex: /(\d{1,2})\/(\d{1,2})\/(\d{4})[, ]+(\d{1,2}):(\d{2}):(\d{2})(?:\s?(AM|PM))?/i,
    parse(m) {
      let h = +m[4];
      if (m[7]) {
        const pm = m[7].toUpperCase() === 'PM';
        h = (h % 12) + (pm ? 12 : 0);
      }
      return {
        wall: { y: +m[3], mo: +m[1], d: +m[2], h, mi: +m[5], s: +m[6], ms: 0 },
        explicitOffsetMinutes: null
      };
    }
  },
  {
    name: 'Syslog (no year)',
    regex: /\b([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b/,
    parse(m) {
      const mo = MONTHS[m[1].toLowerCase()];
      if (!mo) return null;
      return {
        wall: { y: new Date().getUTCFullYear(), mo, d: +m[2], h: +m[3], mi: +m[4], s: +m[5], ms: 0 },
        explicitOffsetMinutes: null,
        yearAssumed: true
      };
    }
  }
];
function scanLineForTimestamp(line) {
  for (const pattern of TIMESTAMP_PATTERNS) {
    const m = line.match(pattern.regex);
    if (!m) continue;
    const parsed = pattern.parse(m);
    if (!parsed) continue;
    if (parsed.wall.mo < 1 || parsed.wall.mo > 12 || parsed.wall.d < 1 || parsed.wall.d > 31) continue;
    return { ...parsed, matchText: m[0], formatName: pattern.name };
  }
  return null;
}
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const IPV6_RE = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b/;
function guessFieldsFromText(text) {
  const fields = { host: '', user: '', ip: '', process: '' };
  const ip = text.match(IPV4_RE) || text.match(IPV6_RE);
  if (ip) fields.ip = ip[0];
  const user = text.match(/\b(?:user(?:name)?|account[\s_-]?name|logon|caller)[\s:=]+["']?([A-Za-z0-9._\\@-]+)/i);
  if (user) fields.user = user[1];
  const proc = text.match(/\b([A-Za-z0-9._-]+\.exe)\b/i) || text.match(/\b(?:process(?:name)?|image)[\s:=]+["']?([A-Za-z0-9._\\-]+)/i);
  if (proc) fields.process = proc[1];
  const host = text.match(/\b(?:host(?:name)?|computer|workstation)[\s:=]+["']?([A-Za-z0-9._-]+)/i);
  if (host) fields.host = host[1];
  return fields;
}
const XML_FIELD_CATEGORY = {
  targetusername: 'user', subjectusername: 'user', accountname: 'user', user: 'user',
  samaccountname: 'user', callerusername: 'user',
  workstationname: 'host', computername: 'host', hostname: 'host',
  ipaddress: 'ip', sourceip: 'ip', sourceaddress: 'ip', destinationip: 'ip',
  destinationaddress: 'ip', clientip: 'ip',
  processname: 'process', image: 'process', newprocessname: 'process',
  parentimage: 'process', commandline: 'process'
};
let idCounter = 0;
function nextId() { return ++idCounter; }
function makeEvent(fileId, fileName, wall, explicitOffsetMinutes, message, fields, extra) {
  const epochUtcMs = explicitOffsetMinutes !== null
    ? Date.UTC(wall.y, wall.mo - 1, wall.d, wall.h, wall.mi, wall.s, wall.ms || 0) - explicitOffsetMinutes * 60000
    : null;
  return {
    id: nextId(),
    fileId, fileName,
    wall, explicitOffsetMinutes, epochUtcMs,
    message, fields: { host: '', user: '', ip: '', process: '', ...fields },
    extra: extra || ''
  };
}
function parseWindowsEventXml(text, fileId, fileName) {
  const doc = new DOMParser().parseFromString(`<root>${text}</root>`, 'application/xml');
  if (doc.querySelector('parsererror')) return null;
  const eventEls = [...doc.getElementsByTagName('Event')];
  if (!eventEls.length) return null;
  const events = [];
  for (const el of eventEls) {
    const sysTime = el.querySelector('TimeCreated')?.getAttribute('SystemTime');
    if (!sysTime) continue;
    const m = sysTime.match(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z?/);
    if (!m) continue;
    const wall = { y: +m[1], mo: +m[2], d: +m[3], h: +m[4], mi: +m[5], s: +m[6], ms: m[7] ? Number(m[7].slice(0, 3).padEnd(3, '0')) : 0 };
    const provider = el.querySelector('Provider')?.getAttribute('Name') || '';
    const eventId = el.querySelector('EventID')?.textContent?.trim() || '';
    const level = el.querySelector('Level')?.textContent?.trim() || '';
    const computer = el.querySelector('Computer')?.textContent?.trim() || '';
    const task = el.querySelector('Task')?.textContent?.trim() || '';
    const fields = { host: computer, user: '', ip: '', process: '' };
    const dataEls = [...el.querySelectorAll('EventData > Data, UserData Data')];
    const dataPairs = [];
    for (const d of dataEls) {
      const name = (d.getAttribute('Name') || '').trim();
      const value = (d.textContent || '').trim();
      if (!value) continue;
      dataPairs.push(`${name}=${value}`);
      const category = XML_FIELD_CATEGORY[name.toLowerCase()];
      if (category && !fields[category]) fields[category] = value;
    }
    const message = `${provider || 'Windows Event'} \u2014 EventID ${eventId}${task ? ` (${task})` : ''}${level ? `, Level ${level}` : ''}`;
    events.push(makeEvent(fileId, fileName, wall, 0, message, fields, dataPairs.join('; ')));
  }
  return events.length ? { events, format: 'Windows Event Log (XML)', ambiguous: false, tzNote: 'TimeCreated/SystemTime is always UTC.' } : null;
}
function splitW3cLine(line) {
  return line.trim().split(/\s+/);
}
function parseW3cExtendedLog(text, fileId, fileName) {
  const lines = text.split('\n');
  const headerLines = lines.filter(l => l.startsWith('#'));
  if (!headerLines.length) return null;
  const fieldsLine = headerLines.find(l => /^#Fields:/i.test(l));
  if (!fieldsLine) return null;
  const columns = fieldsLine.replace(/^#Fields:\s*/i, '').trim().split(/\s+/);
  const softwareLine = headerLines.find(l => /^#Software:/i.test(l)) || '';
  const timeFormatLine = headerLines.find(l => /^#Time Format:/i.test(l));
  const isIis = /Internet Information Services/i.test(softwareLine) || (columns.includes('sc-status') && columns.includes('cs-uri-stem'));
  const isFirewall = /Windows Firewall/i.test(softwareLine) || (columns.includes('action') && columns.includes('src-ip') && columns.includes('dst-ip'));
  let ambiguous;
  let tzNote;
  let impliedOffset;
  if (timeFormatLine) {
    const utc = /UTC/i.test(timeFormatLine);
    ambiguous = !utc;
    impliedOffset = utc ? 0 : null;
    tzNote = `Declared by the file itself: "${timeFormatLine.replace(/^#/, '').trim()}".`;
  } else if (isIis) {
    ambiguous = false;
    impliedOffset = 0;
    tzNote = 'IIS/W3C extended log format timestamps are always UTC by specification.';
  } else if (isFirewall) {
    ambiguous = true;
    impliedOffset = null;
    tzNote = 'Windows Firewall logs use local system time by default and do not declare a timezone.';
  } else {
    ambiguous = true;
    impliedOffset = null;
    tzNote = 'Generic W3C extended log; timezone not declared in the header.';
  }
  const dateIdx = columns.indexOf('date');
  const timeIdx = columns.indexOf('time');
  if (dateIdx === -1 || timeIdx === -1) return null;
  const events = [];
  for (const line of lines) {
    if (!line || line.startsWith('#')) continue;
    const cells = splitW3cLine(line);
    if (cells.length < columns.length) continue;
    const dm = cells[dateIdx].match(/(\d{4})-(\d{2})-(\d{2})/);
    const tm = cells[timeIdx].match(/(\d{2}):(\d{2}):(\d{2})/);
    if (!dm || !tm) continue;
    const wall = { y: +dm[1], mo: +dm[2], d: +dm[3], h: +tm[1], mi: +tm[2], s: +tm[3], ms: 0 };
    const fields = { host: '', user: '', ip: '', process: '' };
    const summary = [];
    columns.forEach((col, i) => {
      const val = cells[i];
      if (val === undefined || val === '-') return;
      if (col === 'c-ip' || col === 'src-ip' || col === 'clientip') fields.ip = fields.ip || val;
      if (col === 'cs-username' || col === 'cs-method' && false) fields.user = fields.user || val;
      if (col === 'cs-username') fields.user = val;
      if (col !== 'date' && col !== 'time') summary.push(`${col}=${val}`);
    });
    const message = isIis
      ? `${cells[columns.indexOf('cs-method')] || ''} ${cells[columns.indexOf('cs-uri-stem')] || ''} \u2192 ${cells[columns.indexOf('sc-status')] || ''}`.trim()
      : isFirewall
        ? `${cells[columns.indexOf('action')] || ''} ${cells[columns.indexOf('protocol')] || ''} ${cells[columns.indexOf('src-ip')] || ''}:${cells[columns.indexOf('src-port')] || ''} \u2192 ${cells[columns.indexOf('dst-ip')] || ''}:${cells[columns.indexOf('dst-port')] || ''}`.trim()
        : summary.slice(0, 4).join(' ');
    events.push(makeEvent(fileId, fileName, wall, impliedOffset, message, fields, summary.join('; ')));
  }
  if (!events.length) return null;
  return {
    events,
    format: isIis ? 'IIS / W3C extended log' : isFirewall ? 'Windows Firewall log' : 'W3C extended log',
    ambiguous,
    tzNote
  };
}
function parseCsv(text, fileId, fileName, chosenColumn) {
  const lines = text.split('\n').filter(l => l.trim() !== '');
  if (lines.length < 2) return null;
  const delim = lines[0].includes('\t') ? '\t' : ',';
  const header = lines[0].split(delim).map(h => h.trim());
  const tsKeywords = ['timestamp', 'time', 'date', '@timestamp', 'eventtime', 'datetime', 'occurred'];
  let guessIndex = chosenColumn !== undefined
    ? chosenColumn
    : header.findIndex(h => tsKeywords.includes(h.toLowerCase()));
  if (guessIndex === -1) guessIndex = header.findIndex(h => tsKeywords.some(k => h.toLowerCase().includes(k)));
  if (guessIndex === -1) {
    return { needsColumnPick: true, headers: header };
  }
  const events = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = lines[i].split(delim);
    if (!cells[guessIndex]) continue;
    const found = scanLineForTimestamp(cells[guessIndex]);
    if (!found) continue;
    const rowObj = {};
    header.forEach((h, idx) => { rowObj[h] = (cells[idx] || '').trim(); });
    const rowText = Object.entries(rowObj).map(([k, v]) => `${k}=${v}`).join('; ');
    const fields = guessFieldsFromText(rowText);
    const message = header
      .filter((h, idx) => idx !== guessIndex)
      .slice(0, 4)
      .map(h => rowObj[h])
      .filter(Boolean)
      .join(' \u00b7 ');
    events.push(makeEvent(fileId, fileName, found.wall, found.explicitOffsetMinutes, message || '(row)', fields, rowText));
  }
  if (!events.length) return null;
  return {
    events,
    format: 'CSV',
    ambiguous: events.some(e => e.explicitOffsetMinutes === null),
    tzNote: 'Timezone depends on how the timestamp column was written; shown per-event where detectable.',
    headers: header,
    guessIndex
  };
}
function parseGenericText(text, fileId, fileName) {
  const lines = text.split('\n');
  const events = [];
  let last = null;
  for (const line of lines) {
    if (!line.trim()) continue;
    const found = scanLineForTimestamp(line);
    if (!found) {
      if (last) last.extra += (last.extra ? '\n' : '') + line;
      continue;
    }
    const fields = guessFieldsFromText(line);
    const message = line.length > 160 ? line.slice(0, 160) + '\u2026' : line;
    const ev = makeEvent(fileId, fileName, found.wall, found.explicitOffsetMinutes, message, fields, '');
    events.push(ev);
    last = ev;
  }
  if (!events.length) return null;
  return {
    events,
    format: 'Generic text log',
    ambiguous: events.some(e => e.explicitOffsetMinutes === null),
    tzNote: 'Best-effort per-line timestamp detection; timezone shown per-event where detectable.'
  };
}
function detectAndParse(fileName, text, chosenCsvColumn) {
  const trimmed = text.trim();
  if (/^\uFEFF?<\?xml/.test(trimmed) || /<Event[\s>]/.test(trimmed.slice(0, 2000)) || /\.xml$/i.test(fileName)) {
    const result = parseWindowsEventXml(text, null, fileName);
    if (result) return result;
  }
  if (/^#Fields:/m.test(trimmed) || /^#Software:/m.test(trimmed)) {
    const result = parseW3cExtendedLog(text, null, fileName);
    if (result) return result;
  }
  if (/\.csv$/i.test(fileName) || (trimmed.split('\n')[0] || '').includes(',')) {
    const result = parseCsv(text, null, fileName, chosenCsvColumn);
    if (result) return result;
  }
  return parseGenericText(text, null, fileName) || { events: [], format: 'Unrecognized', ambiguous: false, tzNote: '' };
}
function newFileState(id, name, text, result) {
  if (result.needsColumnPick) {
    return {
      id, name, size: text.length,
      format: 'CSV', ambiguous: true, tzNote: '',
      tzValue: '', status: 'needs-column',
      events: [], included: true,
      needsColumnPick: true, headers: result.headers,
      rawText: text
    };
  }
  for (const ev of result.events) { ev.fileId = id; }
  return {
    id, name, size: text.length,
    format: result.format,
    ambiguous: result.ambiguous,
    tzNote: result.tzNote,
    tzValue: result.ambiguous ? '' : 'UTC',
    status: result.ambiguous ? 'pending' : 'ready',
    events: result.events,
    included: true,
    needsColumnPick: false,
    headers: result.headers || [],
    rawText: text
  };
}
function applyCsvColumnChoice(file, columnIndex) {
  const result = parseCsv(file.rawText, file.id, file.name, columnIndex);
  if (!result || result.needsColumnPick) {
    file.status = 'needs-column';
    file.events = [];
    return;
  }
  for (const ev of result.events) { ev.fileId = file.id; }
  file.format = result.format;
  file.ambiguous = result.ambiguous;
  file.tzNote = result.tzNote;
  file.tzValue = result.ambiguous ? '' : 'UTC';
  file.status = result.ambiguous ? 'pending' : 'ready';
  file.events = result.events;
  file.needsColumnPick = false;
}
function resolveFileTimezone(file, tz) {
  file.tzValue = tz;
  file.status = 'resolved';
  for (const ev of file.events) {
    if (ev.explicitOffsetMinutes === null) {
      ev.epochUtcMs = wallClockToUtc(ev.wall, tz);
    }
  }
}
function fileStatusBadge(file) {
  if (file.status === 'ready') return '<span class="status ok" style="display:inline-block;padding:2px 8px">auto-detected</span>';
  if (file.status === 'resolved') return '<span class="status ok" style="display:inline-block;padding:2px 8px">resolved</span>';
  if (file.status === 'needs-column') return '<span class="status warn" style="display:inline-block;padding:2px 8px">needs column</span>';
  return '<span class="status warn" style="display:inline-block;padding:2px 8px">needs timezone</span>';
}
function renderFileList(files, zones) {
  if (!files.length) return '';
  const zoneOptions = zones.map(z => `<option value="${escapeHtml(z)}">`).join('');
  const rows = files.map(file => `
    <tr data-file-id="${file.id}">
      <td><input type="checkbox" class="fileInclude" data-file-id="${file.id}" ${file.included ? 'checked' : ''}></td>
      <td class="mono">${escapeHtml(file.name)}</td>
      <td>${escapeHtml(file.format)}</td>
      <td>${file.events.length}</td>
      <td>${fileStatusBadge(file)}</td>
      <td>
        ${file.status === 'needs-column'
          ? `<select class="fileColumn" data-file-id="${file.id}">
               <option value="">\u2014 which column is the timestamp? \u2014</option>
               ${file.headers.map((h, i) => `<option value="${i}">${escapeHtml(h)}</option>`).join('')}
             </select>`
          : file.status === 'ready'
            ? `<span class="small">${escapeHtml(file.tzNote || 'UTC')}</span>`
            : `<input class="fileTz mono" list="tzListOptions" data-file-id="${file.id}" placeholder="e.g. Europe/Berlin or UTC" value="${escapeHtml(file.tzValue)}" style="width:180px">`}
      </td>
      <td><button class="btn danger fileRemove" data-file-id="${file.id}">Remove</button></td>
    </tr>
  `).join('');
  return `
    <section class="card">
      <h3>Loaded files</h3>
      <datalist id="tzListOptions">${zoneOptions}</datalist>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Include</th><th>File</th><th>Format</th><th>Events</th><th>Timezone</th><th></th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <p class="small">
        Formats with a declared or spec-implied timezone (Windows Event Log XML, IIS/W3C logs) are
        included automatically. Everything else needs an explicit timezone before its events are
        merged into the timeline \u2014 type an IANA zone name (e.g. <span class="mono">Europe/Vienna</span>)
        or <span class="mono">UTC</span>.
      </p>
    </section>
  `;
}
function renderHistogram(events, bucket, displayTz) {
  if (!events.length) return '';
  const bucketMs = bucket === 'minute' ? 60000 : bucket === 'hour' ? 3600000 : 86400000;
  const counts = new Map();
  for (const ev of events) {
    const key = Math.floor(ev.epochUtcMs / bucketMs) * bucketMs;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const keys = [...counts.keys()].sort((a, b) => a - b);
  const max = Math.max(...counts.values());
  const withDate = bucket !== 'minute' || (keys[keys.length - 1] - keys[0]) > 86400000;
  const bars = keys.map(k => {
    const count = counts.get(k);
    const pct = Math.max(2, Math.round((count / max) * 100));
    const label = formatInZone(k, displayTz, true);
    return `
      <div class="hist-row" data-bucket-start="${k}" data-bucket-end="${k + bucketMs}" style="display:flex;align-items:center;gap:8px;cursor:pointer" title="Click to zoom into this ${bucket}">
        <span class="small mono" style="width:160px;flex:none">${escapeHtml(label)}</span>
        <span style="background:var(--accent);height:10px;border-radius:4px;width:${pct}%;min-width:4px"></span>
        <span class="small" style="width:40px;flex:none;text-align:right">${count}</span>
      </div>
    `;
  }).join('');
  return `
    <section class="card">
      <div class="row">
        <h3 style="margin:0">Event density</h3>
        <span class="spacer"></span>
        <label class="small" style="margin:0">Bucket:
          <select id="histBucket">
            <option value="minute" ${bucket === 'minute' ? 'selected' : ''}>Minute</option>
            <option value="hour" ${bucket === 'hour' ? 'selected' : ''}>Hour</option>
            <option value="day" ${bucket === 'day' ? 'selected' : ''}>Day</option>
          </select>
        </label>
      </div>
      <p class="small">${keys.length} bucket${keys.length === 1 ? '' : 's'}. Click a bar to filter the timeline to that period.</p>
      <div style="display:flex;flex-direction:column;gap:4px;max-height:260px;overflow-y:auto">${bars}</div>
    </section>
  `;
}
function renderTimelineTable(events, displayTz, total) {
  const shown = events.slice(0, MAX_RENDERED_ROWS);
  const rows = shown.map(ev => `
    <tr>
      <td class="mono small">${escapeHtml(formatInZone(ev.epochUtcMs, displayTz, true))}</td>
      <td class="small">${escapeHtml(ev.fileName)}</td>
      <td class="small">${escapeHtml(ev.fields.host)}</td>
      <td class="small">${escapeHtml(ev.fields.user)}</td>
      <td class="small">${escapeHtml(ev.fields.ip)}</td>
      <td class="small">${escapeHtml(ev.fields.process)}</td>
      <td class="small">${escapeHtml(ev.message)}</td>
      <td><button class="btn around" data-event-id="${ev.id}">\u00b15 min</button></td>
    </tr>
  `).join('');
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>File</th><th>Host</th><th>User</th><th>IP</th><th>Process</th><th>Message</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="small">Showing ${shown.length} of ${total} matching events. Narrow the filters to see more, or use Export for the full filtered set.</p>
  `;
}
function renderSummary(events, displayTz) {
  if (!events.length) {
    return `<div class="status warn"><strong>No events to show</strong><div class="small">Load files and/or adjust filters.</div></div>`;
  }
  const first = events[0];
  const last = events[events.length - 1];
  const fileSet = new Set(events.map(e => e.fileName));
  return `
    <div class="grid">
      <div class="stat"><span>Events</span><strong>${events.length}</strong></div>
      <div class="stat"><span>Files</span><strong>${fileSet.size}</strong></div>
      <div class="stat"><span>Earliest</span><strong class="mono">${escapeHtml(formatInZone(first.epochUtcMs, displayTz, true))}</strong></div>
      <div class="stat"><span>Latest</span><strong class="mono">${escapeHtml(formatInZone(last.epochUtcMs, displayTz, true))}</strong></div>
    </div>
  `;
}
export function renderTimeline(app) {
  const zones = getIanaZones();
  app.innerHTML = `
    <div class="tool-window" id="timelineWindow">
    <div class="tool-window-header" id="timelineDragHandle" title="Drag tool">
      <span class="tool-drag-grip" aria-hidden="true">\u22ee\u22ee</span>
      <strong>Structured log timeline</strong>
    </div>
    <section class="card">
      <h2>Structured log timeline</h2>
      <p class="small">
        Drop several log files (Windows Event Log XML exports, IIS/W3C logs, Windows Firewall logs,
        CSV, or plain text) to merge them into one normalized, sortable timeline. Everything is parsed
        in this browser; files are never uploaded anywhere.
      </p>
      <div class="dropzone" id="timelineDrop">
        Drop files here, or <button class="btn" id="timelinePick">choose files</button>
        <input id="timelineFile" type="file" multiple hidden>
      </div>
    </section>
    <div id="timelineFiles"></div>
    <section class="card" id="timelineFilters" hidden>
      <h3>Filters</h3>
      <div class="grid-2">
        <div><label for="fHost">Host</label><input id="fHost" placeholder="substring"></div>
        <div><label for="fUser">User</label><input id="fUser" placeholder="substring"></div>
        <div><label for="fIp">IP</label><input id="fIp" placeholder="substring"></div>
        <div><label for="fProcess">Process</label><input id="fProcess" placeholder="substring"></div>
      </div>
      <div class="grid-2" style="margin-top:10px">
        <div><label for="fSearch">Free text</label><input id="fSearch" placeholder="search message/raw fields"></div>
        <div>
          <label for="displayTz">Display timezone</label>
          <input id="displayTz" class="mono" list="tzListOptionsMain" value="UTC">
          <datalist id="tzListOptionsMain">${zones.map(z => `<option value="${escapeHtml(z)}">`).join('')}</datalist>
        </div>
      </div>
      <div class="row" style="margin-top:10px">
        <div class="small">Range: <span id="rangeLabel">full range</span></div>
        <button class="btn" id="rangeClear" hidden>Clear range</button>
        <span class="spacer"></span>
        <button class="btn" id="exportCsv">Export filtered CSV</button>
        <button class="btn" id="exportJson">Export filtered JSON</button>
        <button class="btn" id="copyReport">Copy report</button>
      </div>
    </section>
    <div id="timelineHistogram"></div>
    <section class="card" id="timelineSummary" hidden></section>
    <section class="card" id="timelineTableCard" hidden>
      <h3>Timeline</h3>
      <div id="timelineTable"></div>
    </section>
    </div>
  `;
  const drop = $('#timelineDrop');
  const fileInput = $('#timelineFile');
  const filesCard = $('#timelineFiles');
  const filtersCard = $('#timelineFilters');
  const histCard = $('#timelineHistogram');
  const summaryCard = $('#timelineSummary');
  const tableCard = $('#timelineTableCard');
  const tableDiv = $('#timelineTable');
  const rangeLabel = $('#rangeLabel');
  const rangeClearBtn = $('#rangeClear');
  let files = [];
  let bucket = 'hour';
  let range = null;
  let fileIdCounter = 0;
  async function handleFiles(fileObjs) {
    for (const f of fileObjs) {
      const text = await f.text();
      const result = detectAndParse(f.name, text);
      const id = ++fileIdCounter;
      const state = newFileState(id, f.name, text, result);
      files.push(state);
    }
    rerenderAll();
  }
  $('#timelinePick').onclick = () => fileInput.click();
  fileInput.onchange = () => { if (fileInput.files.length) handleFiles([...fileInput.files]); fileInput.value = ''; };
  dropBinder(drop, list => list.length && handleFiles(list));
  function allIncludedEvents() {
    const out = [];
    for (const file of files) {
      if (!file.included) continue;
      if (file.status === 'pending') continue;
      for (const ev of file.events) {
        if (ev.epochUtcMs !== null) out.push(ev);
      }
    }
    return out.sort((a, b) => a.epochUtcMs - b.epochUtcMs);
  }
  function applyFilters(events) {
    const host = $('#fHost')?.value.trim().toLowerCase() || '';
    const user = $('#fUser')?.value.trim().toLowerCase() || '';
    const ip = $('#fIp')?.value.trim().toLowerCase() || '';
    const proc = $('#fProcess')?.value.trim().toLowerCase() || '';
    const search = $('#fSearch')?.value.trim().toLowerCase() || '';
    return events.filter(ev => {
      if (host && !ev.fields.host.toLowerCase().includes(host)) return false;
      if (user && !ev.fields.user.toLowerCase().includes(user)) return false;
      if (ip && !ev.fields.ip.toLowerCase().includes(ip)) return false;
      if (proc && !ev.fields.process.toLowerCase().includes(proc)) return false;
      if (search) {
        const hay = `${ev.message} ${ev.extra} ${ev.fileName}`.toLowerCase();
        if (!hay.includes(search)) return false;
      }
      if (range && (ev.epochUtcMs < range.startMs || ev.epochUtcMs > range.endMs)) return false;
      return true;
    });
  }
  function currentDisplayTz() {
    const val = $('#displayTz')?.value.trim() || 'UTC';
    return isValidZone(val) ? val : 'UTC';
  }
  function rerenderFiles() {
    filesCard.innerHTML = renderFileList(files, zones);
    filesCard.querySelectorAll('.fileInclude').forEach(cb => {
      cb.onchange = () => {
        const file = files.find(f => f.id === Number(cb.dataset.fileId));
        if (file) file.included = cb.checked;
        rerenderResults();
      };
    });
    filesCard.querySelectorAll('.fileColumn').forEach(sel => {
      sel.onchange = () => {
        const file = files.find(f => f.id === Number(sel.dataset.fileId));
        if (!file || sel.value === '') return;
        applyCsvColumnChoice(file, Number(sel.value));
        rerenderAll();
      };
    });
    filesCard.querySelectorAll('.fileTz').forEach(inp => {
      inp.addEventListener('change', () => {
        const file = files.find(f => f.id === Number(inp.dataset.fileId));
        if (!file) return;
        const tz = inp.value.trim();
        if (!tz || !isValidZone(tz)) {
          inp.style.borderColor = 'var(--danger, #c0392b)';
          return;
        }
        inp.style.borderColor = '';
        resolveFileTimezone(file, tz);
        rerenderAll();
      });
    });
    filesCard.querySelectorAll('.fileRemove').forEach(btn => {
      btn.onclick = () => {
        files = files.filter(f => f.id !== Number(btn.dataset.fileId));
        rerenderAll();
      };
    });
  }
  function rerenderResults() {
    const included = allIncludedEvents();
    const filtered = applyFilters(included);
    const displayTz = currentDisplayTz();
    if (!files.length) {
      filtersCard.hidden = true;
      histCard.innerHTML = '';
      summaryCard.hidden = true;
      tableCard.hidden = true;
      return;
    }
    filtersCard.hidden = false;
    histCard.innerHTML = renderHistogram(filtered, bucket, displayTz);
    summaryCard.hidden = false;
    summaryCard.innerHTML = renderSummary(filtered, displayTz);
    tableCard.hidden = false;
    tableDiv.innerHTML = renderTimelineTable(filtered, displayTz, filtered.length);
    rangeLabel.textContent = range
      ? `${formatInZone(range.startMs, displayTz, true)} \u2192 ${formatInZone(range.endMs, displayTz, true)}`
      : 'full range';
    rangeClearBtn.hidden = !range;
    const bucketSelect = $('#histBucket');
    if (bucketSelect) bucketSelect.onchange = e => { bucket = e.target.value; rerenderResults(); };
    histCard.querySelectorAll('.hist-row').forEach(row => {
      row.onclick = () => {
        range = { startMs: Number(row.dataset.bucketStart), endMs: Number(row.dataset.bucketEnd) };
        rerenderResults();
      };
    });
    tableDiv.querySelectorAll('.around').forEach(btn => {
      btn.onclick = () => {
        const ev = included.find(e => e.id === Number(btn.dataset.eventId));
        if (!ev) return;
        range = { startMs: ev.epochUtcMs - 5 * 60000, endMs: ev.epochUtcMs + 5 * 60000 };
        rerenderResults();
        tableCard.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
      };
    });
  }
  function rerenderAll() {
    rerenderFiles();
    rerenderResults();
  }
  ['fHost', 'fUser', 'fIp', 'fProcess', 'fSearch'].forEach(id => {
    $(`#${id}`).addEventListener('input', () => rerenderResults());
  });
  $('#displayTz').addEventListener('change', () => rerenderResults());
  rangeClearBtn.onclick = () => { range = null; rerenderResults(); };
  $('#exportCsv').onclick = () => {
    const filtered = applyFilters(allIncludedEvents());
    const displayTz = currentDisplayTz();
    const header = 'time,file,host,user,ip,process,message';
    const rows = filtered.map(ev => [
      formatInZone(ev.epochUtcMs, displayTz, true), ev.fileName, ev.fields.host, ev.fields.user,
      ev.fields.ip, ev.fields.process, ev.message
    ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','));
    downloadText('timeline-filtered.csv', [header, ...rows].join('\n'), 'text/csv');
  };
  $('#exportJson').onclick = () => {
    const filtered = applyFilters(allIncludedEvents());
    const displayTz = currentDisplayTz();
    const out = filtered.map(ev => ({
      time: formatInZone(ev.epochUtcMs, displayTz, true),
      epochUtcMs: ev.epochUtcMs,
      file: ev.fileName,
      ...ev.fields,
      message: ev.message
    }));
    downloadText('timeline-filtered.json', JSON.stringify(out, null, 2), 'application/json');
  };
  $('#copyReport').onclick = async () => {
    const filtered = applyFilters(allIncludedEvents());
    await copyText(JSON.stringify({ count: filtered.length, events: filtered.slice(0, 200) }, null, 2));
  };
  enableToolDragging(
    $('#timelineWindow'),
    $('#timelineDragHandle'),
    () => document.body.classList.contains('sidebar-detached')
  );
}